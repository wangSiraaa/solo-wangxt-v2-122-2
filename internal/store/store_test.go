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

func TestRepublishHistoricalVersionCreatesForwardDelta(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}

	v1 := parse(t, content(0))
	if _, err := s.Publish(ctx, v1, "v1", lim); err != nil {
		t.Fatal(err)
	}
	v2 := parse(t, content(2))
	if _, err := s.Publish(ctx, v2, "v2", lim); err != nil {
		t.Fatal(err)
	}

	res, err := s.Republish(ctx, 1, "restore v1 content", lim)
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial != 3 {
		t.Fatalf("republished serial = %d, want new serial 3", res.Serial)
	}

	current, err := s.LoadCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Serial != 3 || current.SOA().Serial != 3 {
		t.Fatalf("current serial = %d (SOA %d), want 3", current.Serial, current.SOA().Serial)
	}
	source, err := s.LoadSnapshot(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := nonSOA(current), nonSOA(source); got != want {
		t.Fatalf("current content does not match serial 1:\ngot:  %s\nwant: %s", got, want)
	}
	if _, found := current.Lookup("host2.lab.test.", dns.TypeA); found {
		t.Fatal("restored current snapshot still contains v2-only host2")
	}

	// The delta is from the *currently served* v2 to the new forward
	// serial, not a serial rollback: v2's added record must be deleted.
	changes, err := s.LoadChanges(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Action != "DEL" ||
		changes[0].RR.Header().Name != "host2.lab.test." {
		t.Fatalf("serial 3 changelog = %#v, want one DEL for host2", changes)
	}

	vs, err := s.ListVersions(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 3 || vs[0].Serial != 3 || vs[0].Kind != "republish" ||
		vs[0].SourceSerial == nil || *vs[0].SourceSerial != 1 {
		t.Fatalf("version audit metadata wrong: %#v", vs)
	}
	// The mistaken v2 and source v1 records must both remain available.
	if _, err := s.LoadSnapshot(ctx, 1); err != nil {
		t.Fatalf("source v1 history removed: %v", err)
	}
	if _, err := s.LoadSnapshot(ctx, 2); err != nil {
		t.Fatalf("mistaken v2 history removed: %v", err)
	}
}

func TestRepublishMissingVersionIsNoOp(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}
	if _, err := s.Publish(ctx, parse(t, content(0)), "v1", lim); err != nil {
		t.Fatal(err)
	}

	_, err := s.Republish(ctx, 999, "missing", lim)
	if !errors.Is(err, ErrNoVersion) {
		t.Fatalf("Republish missing version error = %v, want ErrNoVersion", err)
	}
	serial, err := s.CurrentSerial(ctx)
	if err != nil || serial != 1 {
		t.Fatalf("after missing republish serial=%d err=%v, want 1", serial, err)
	}
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM zone_versions`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("versions rows=%d err=%v, want 1", n, err)
	}
	current, err := s.LoadCurrent(ctx)
	if err != nil || current.Serial != 1 {
		t.Fatalf("current snapshot changed after no-op: serial=%d err=%v", serial, err)
	}
}

func TestRepublishRejectsHistoricalDataFailingCurrentRules(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	oldLimits := zone.Limits{MinTTL: 30, MaxTTL: 86400}
	ttl30, err := zone.Parse(strings.NewReader(`$ORIGIN lab.test.
$TTL 30
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
`), origin, oldLimits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, ttl30, "short-ttl", oldLimits); err != nil {
		t.Fatal(err)
	}

	newLimits := zone.Limits{MinTTL: 60, MaxTTL: 86400}
	if _, err := s.Republish(ctx, 1, "retry with new rules", newLimits); err == nil {
		t.Fatal("historical TTL that violates current minimum must be rejected")
	}
	serial, err := s.CurrentSerial(ctx)
	if err != nil || serial != 1 {
		t.Fatalf("after invalid republish serial=%d err=%v, want 1", serial, err)
	}
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM zone_versions`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("versions rows=%d err=%v, want 1", n, err)
	}
}

func nonSOA(snap *zone.Snapshot) string {
	var lines []string
	for _, rr := range snap.RRs {
		if rr.Header().Rrtype == dns.TypeSOA {
			continue
		}
		lines = append(lines, zone.CanonicalText(rr))
	}
	return strings.Join(lines, "\n")
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
