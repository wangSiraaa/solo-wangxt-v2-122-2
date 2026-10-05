package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

// testDatabaseURL returns the database used by integration tests. Set
// DNSZONE_TEST_DATABASE to point at it; tests skip when unreachable so
// plain `go test ./...` stays self-contained.
func testDatabaseURL() string {
	if u := os.Getenv("DNSZONE_TEST_DATABASE"); u != "" {
		return u
	}
	return "postgres://dnsadmin@127.0.0.1:55432/dnszone_test?sslmode=disable&connect_timeout=2"
}

const origin = "lab.test."

func freshStore(t *testing.T) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := New(ctx, testDatabaseURL(), origin)
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	// Clean slate for deterministic serials.
	if _, err := s.pool.Exec(ctx, `TRUNCATE zone_changes, zone_records, zone_versions`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE zone_meta SET current_serial=0, origin=$1 WHERE id=1`, origin); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func parse(t *testing.T, text string) []dns.RR {
	t.Helper()
	rrs, err := zone.Parse(strings.NewReader(text), origin,
		zone.Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatal(err)
	}
	return rrs
}

func TestPublishAndLoad(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	rrs := parse(t, `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
`)
	res, err := s.Publish(ctx, rrs, "first", zone.Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial != 1 {
		t.Fatalf("first serial = %d, want 1", res.Serial)
	}
	snap, err := s.LoadCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Serial != 1 {
		t.Fatalf("loaded serial = %d", snap.Serial)
	}
	as, found := snap.Lookup("www.lab.test.", dns.TypeA)
	if !found || len(as) != 1 {
		t.Fatalf("loaded snapshot content wrong: %v", as)
	}
	// SOA serial stored on the version must equal the snapshot serial.
	if snap.SOA().Serial != 1 {
		t.Fatal("SOA serial mismatch")
	}
}

func TestInvalidPublishIsAtomicNoOp(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1",
		zone.Limits{MinTTL: 30, MaxTTL: 86400}); err != nil {
		t.Fatal(err)
	}

	// Build RRs directly (bypassing parser validation) so that the
	// transaction's own defense rejects them and rolls everything back.
	mustRR := func(text string) dns.RR {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		return rr
	}
	soa := snapSOA(t, s, 1)
	outOfZone := []dns.RR{
		soa,
		mustRR("lab.test. 3600 IN NS ns1.lab.test."),
		mustRR("ns1.lab.test. 3600 IN A 127.0.0.10"),
		mustRR("host.other.test. 3600 IN A 1.2.3.4"),
	}
	if _, err := s.Publish(ctx, outOfZone, "bad-owner",
		zone.Limits{MinTTL: 30, MaxTTL: 86400}); err == nil {
		t.Fatal("out-of-zone publish must fail")
	}

	lowTTL := []dns.RR{
		soa,
		mustRR("lab.test. 3600 IN NS ns1.lab.test."),
		mustRR("ns1.lab.test. 5 IN A 127.0.0.10"),
	}
	if _, err := s.Publish(ctx, lowTTL, "bad-ttl",
		zone.Limits{MinTTL: 30, MaxTTL: 86400}); err == nil {
		t.Fatal("TTL below bound publish must fail")
	}

	// Nothing moved: serial still 1 and exactly one version row.
	serial, err := s.CurrentSerial(ctx)
	if err != nil || serial != 1 {
		t.Fatalf("after failed publishes serial=%d err=%v, want 1", serial, err)
	}
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM zone_versions`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("versions rows=%d err=%v, want 1 (rolled back)", n, err)
	}
}

// snapSOA returns a copy of version v's SOA RR so tests can assemble raw
// record sets for negative Publish paths.
func snapSOA(t *testing.T, s *Store, v uint32) dns.RR {
	t.Helper()
	snap, err := s.LoadSnapshot(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	return snap.SOA()
}

func TestConcurrentPublishSerializes(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()

	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Publish(ctx, parse(t, content(i)),
				fmt.Sprintf("p%d", i), zone.Limits{MinTTL: 30, MaxTTL: 86400})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent publish: %v", err)
	}

	serial, err := s.CurrentSerial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if serial != n {
		t.Fatalf("serial after %d concurrent publishes = %d (gap or loss)", n, serial)
	}

	// Each version 1..n exists and its snapshot is internally complete:
	// SOA serial always agrees with the version number.
	for v := uint32(1); v <= n; v++ {
		snap, err := s.LoadSnapshot(ctx, v)
		if err != nil {
			t.Fatalf("version %d missing: %v", v, err)
		}
		if snap.SOA().Serial != v {
			t.Fatalf("version %d snapshot SOA serial %d", v, snap.SOA().Serial)
		}
	}
}

func TestChangelogDrivesIXFRDelta(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1",
		zone.Limits{MinTTL: 30, MaxTTL: 86400}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, parse(t, content(2)), "v2",
		zone.Limits{MinTTL: 30, MaxTTL: 86400}); err != nil {
		t.Fatal(err)
	}
	changes, err := s.LoadChanges(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	var adds, dels int
	var sawSOA bool
	for _, c := range changes {
		switch c.Action {
		case "ADD":
			adds++
		case "DEL":
			dels++
		}
		if c.RR.Header().Rrtype == dns.TypeSOA {
			sawSOA = true
		}
	}
	// content(2) differs from content(0) by adding host2 only.
	if adds != 1 || dels != 0 {
		t.Fatalf("changelog adds=%d dels=%d, want 1/0", adds, dels)
	}
	if sawSOA {
		t.Fatal("SOA must not appear in record deltas")
	}
}

// content returns a zone text where variant adds `variant` extra host
// records, giving each publish a distinct-but-related RR set.
func content(variant int) string {
	base := `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
www IN A 127.0.0.21
`
	if variant == 2 {
		base += "host2 IN A 127.0.0.30\n"
	}
	return base
}

func TestRestoreRepublishesHistoricalContentWithHigherSerial(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}

	// v1 and v2 (v2 adds host2).
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1", lim); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, parse(t, content(2)), "v2-accidental", lim); err != nil {
		t.Fatal(err)
	}

	// Roll back to v1's content as a forward version.
	res, err := s.Restore(ctx, 1, "back to v1", lim)
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial != 3 {
		t.Fatalf("restored serial = %d, want 3 (must be greater than v2)", res.Serial)
	}

	// Served content is v1: host2 is gone again, www keeps both v1 records.
	cur, err := s.LoadCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Serial != 3 || cur.SOA().Serial != 3 {
		t.Fatalf("current serial %d / SOA %d, want 3/3", cur.Serial, cur.SOA().Serial)
	}
	if _, found := cur.Lookup("host2.lab.test.", dns.TypeA); found {
		t.Fatal("host2 from the misconfigured v2 must not be served after restore")
	}
	if as, found := cur.Lookup("www.lab.test.", dns.TypeA); !found || len(as) != 2 {
		t.Fatalf("www A after restore: %v found=%v", as, found)
	}

	// The new version's changelog expresses the v2 -> new-v1 delta, which
	// is exactly what drives IXFR: host2 is removed, nothing else differs.
	if len(res.Changes) != 1 || res.Changes[0].Action != "DEL" {
		t.Fatalf("restore changelog = %v, want one DEL", res.Changes)
	}
	h := res.Changes[0].RR.Header()
	if h.Name != "host2.lab.test." || h.Rrtype != dns.TypeA {
		t.Fatalf("unexpected DEL: %s", zone.CanonicalText(res.Changes[0].RR))
	}
	stored, err := s.LoadChanges(ctx, 3)
	if err != nil || len(stored) != 1 || stored[0].Action != "DEL" {
		t.Fatalf("persisted changelog for serial 3 wrong: %v err=%v", stored, err)
	}

	// Audit lineage: version 3 records it was restored from version 1, and
	// neither v1 nor the accidental v2 were deleted.
	vs, err := s.ListVersions(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 3 {
		t.Fatalf("versions after restore = %d, want 3 (history preserved)", len(vs))
	}
	if vs[0].Serial != 3 || vs[0].RestoredFrom != 1 {
		t.Fatalf("newest version = %+v, want serial 3 restored-from 1", vs[0])
	}
	for _, serial := range []uint32{1, 2, 3} {
		if snap, err := s.LoadSnapshot(ctx, serial); err != nil {
			t.Fatalf("version %d missing after restore: %v", serial, err)
		} else if serial == 2 {
			if _, found := snap.Lookup("host2.lab.test.", dns.TypeA); !found {
				t.Fatal("audit history of v2 lost: host2 should still be present")
			}
		}
	}
}

func TestRestoreMissingVersionChangesNothing(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1", lim); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, parse(t, content(2)), "v2-accidental", lim); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Restore(ctx, 99, "nope", lim); !errors.Is(err, ErrNoVersion) {
		t.Fatalf("restore of missing version: err = %v, want ErrNoVersion", err)
	}
	if serial, _ := s.CurrentSerial(ctx); serial != 2 {
		t.Fatalf("current serial = %d, want 2 (failed restore must not move service)", serial)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM zone_versions`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("version rows after failed restore = %d err=%v, want 2", n, err)
	}
	cur, err := s.LoadCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := cur.Lookup("host2.lab.test.", dns.TypeA); !found {
		t.Fatal("service must still serve v2 after a failed restore")
	}

	// Restoring when nothing has ever been published is equally a no-op.
	empty := freshStore(t)
	if _, err := empty.Restore(ctx, 1, "", lim); !errors.Is(err, ErrNoVersion) {
		t.Fatalf("restore on empty store: err = %v, want ErrNoVersion", err)
	}
	if serial, _ := empty.CurrentSerial(ctx); serial != 0 {
		t.Fatalf("empty store current serial = %d, want 0", serial)
	}
}

func TestRestoreRejectsHistoryFailingCurrentValidation(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1", lim); err != nil {
		t.Fatal(err)
	}

	// Simulate a historical version (serial 2) saved under older, looser
	// rules: a record whose TTL is below the current minimum. It exists in
	// history but would not be accepted by a publish today.
	badTTL := []string{
		"lab.test. 3600 IN SOA ns1.lab.test. admin.lab.test. 2 7200 3600 1209600 300",
		"lab.test. 3600 IN NS ns1.lab.test.",
		"ns1.lab.test. 3600 IN A 127.0.0.10",
		"www.lab.test. 5 IN A 127.0.0.20",
	}
	insertHistoricalVersion(t, ctx, s, 2, badTTL)

	if _, err := s.Restore(ctx, 2, "restore stale", lim); err == nil {
		t.Fatal("restore of a version violating current TTL bounds must fail")
	}
	if serial, _ := s.CurrentSerial(ctx); serial != 1 {
		t.Fatalf("current serial = %d, want 1 (validation failure rolled back)", serial)
	}
	if _, err := s.LoadSnapshot(ctx, 3); !errors.Is(err, ErrNoVersion) &&
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("version 3 must not exist after failed restore: %v", err)
	}

	// Same for a historical version containing a now-unsupported type.
	badType := []string{
		"lab.test. 3600 IN SOA ns1.lab.test. admin.lab.test. 2 7200 3600 1209600 300",
		"lab.test. 3600 IN NS ns1.lab.test.",
		"ns1.lab.test. 3600 IN A 127.0.0.10",
		"dnskey.lab.test. 3600 IN DNSKEY 256 3 13 YQ==",
	}
	insertHistoricalVersion(t, ctx, s, 3, badType)
	if _, err := s.Restore(ctx, 3, "restore dnskey", lim); err == nil {
		t.Fatal("restore of a version with an unsupported type must fail")
	}
	if serial, _ := s.CurrentSerial(ctx); serial != 1 {
		t.Fatalf("current serial = %d, want 1 after second failed restore", serial)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM zone_versions`).Scan(&n); err != nil || n != 3 {
		// 1 published + 2 raw-inserted history rows; the failed Restores
		// must not have added any version.
		t.Fatalf("version rows = %d err=%v, want 3", n, err)
	}
	// The currently served snapshot is untouched.
	cur, err := s.LoadCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Serial != 1 {
		t.Fatalf("served serial = %d, want 1", cur.Serial)
	}
}

func TestRestoreCurrentVersionProducesEmptyChangelog(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}
	if _, err := s.Publish(ctx, parse(t, content(2)), "v1", lim); err != nil {
		t.Fatal(err)
	}
	// Restoring the version already being served: content identical, so the
	// change log is empty but the serial still advances.
	res, err := s.Restore(ctx, 1, "no-op content", lim)
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial != 2 || len(res.Changes) != 0 {
		t.Fatalf("restore current: serial=%d changes=%v, want 2 with no changes",
			res.Serial, res.Changes)
	}
}

// insertHistoricalVersion writes a raw version row + records without
// touching the current-version pointer, to emulate history saved under
// different validation rules.
func insertHistoricalVersion(t *testing.T, ctx context.Context, s *Store, serial int64, rrTexts []string) {
	t.Helper()
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO zone_versions (serial, origin, note) VALUES ($1, $2, $3)
		 ON CONFLICT (serial) DO NOTHING`, serial, origin, "stale-history"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM zone_records WHERE serial=$1`, serial); err != nil {
		t.Fatal(err)
	}
	for i, text := range rrTexts {
		// Validate the fixture itself parses; validation under rules is
		// exactly what Restore is supposed to re-do.
		if _, err := dns.NewRR(text); err != nil {
			t.Fatalf("fixture record %q does not parse: %v", text, err)
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO zone_records (serial, position, rr_text) VALUES ($1,$2,$3)`,
			serial, i, text); err != nil {
			t.Fatal(err)
		}
	}
}
