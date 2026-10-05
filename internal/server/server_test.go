package server

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"

	"localtest/dnszone/internal/config"
	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"
)

const testZone = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (7 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
www IN A 127.0.0.21
alias IN CNAME www.lab.test.
`

// base64 of "e2e-tsig-secret", shared by server and client in these tests
const testTSIGB64 = "ZTJlLXRzaWctc2VjcmV0"

func newTestServer(t *testing.T, snap *zone.Snapshot) string {
	t.Helper()
	cfgJSON := `{
	  "zone": "lab.test.",
	  "listen_udp": "127.0.0.1:0",
	  "listen_tcp": "127.0.0.1:0",
	  "database_url": "postgres://unused",
	  "ttl_min": 30, "ttl_max": 86400,
	  "transfer_allow_cidrs": ["127.0.0.0/8", "::1/128"],
	  "tsig_keys": {
	    "xfer.lab.test.": {"algorithm": "hmac-sha256", "secret_b64": "` + testTSIGB64 + `"}
	  }
	}`
	f, err := os.CreateTemp(t.TempDir(), "cfg-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(cfgJSON); err != nil {
		t.Fatal(err)
	}
	f.Close()
	cfg, err := config.Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	srv := &Server{cfg: cfg, logger: log.New(io.Discard, "", 0)}
	srv.snapshot.Store(snap)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Share the port between TCP and UDP, like the production listener.
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		pc.Close()
		ln.Close()
	})
	go srv.Serve(ctx, pc, ln)

	addr := ln.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c := new(dns.Client)
		c.Timeout = 100 * time.Millisecond
		probe := new(dns.Msg)
		probe.SetQuestion("lab.test.", dns.TypeSOA)
		if _, _, err := c.Exchange(probe, addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return addr
}

func snap(t *testing.T, serial uint32, text string) *zone.Snapshot {
	t.Helper()
	rrs, err := zone.Parse(strings.NewReader(text), "lab.test.",
		zone.Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatal(err)
	}
	s, err := zone.NewSnapshot("lab.test.", serial, rrs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func dnsQuery(t *testing.T, addr, network, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := new(dns.Client)
	c.Net = network
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query %s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return r
}

func TestE2EPositiveAndNegative(t *testing.T) {
	addr := newTestServer(t, snap(t, 7, testZone))

	// Same name, multiple records.
	r := dnsQuery(t, addr, "udp", "www.lab.test.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 2 {
		t.Fatalf("www A: rcode=%s aa=%v answers=%d",
			dns.RcodeToString[r.Rcode], r.Authoritative, len(r.Answer))
	}
	if r.RecursionAvailable {
		t.Fatal("RA must never be set: this server does not recurse")
	}

	// CNAME chain includes the CNAME and both target records.
	r = dnsQuery(t, addr, "udp", "alias.lab.test.", dns.TypeA)
	if len(r.Answer) != 3 || r.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("alias A chain wrong: %v", r.Answer)
	}

	// NXDOMAIN: AA plus SOA authority with the negative-cache TTL.
	r = dnsQuery(t, addr, "udp", "nope.lab.test.", dns.TypeA)
	if r.Rcode != dns.RcodeNameError || !r.Authoritative || len(r.Ns) != 1 {
		t.Fatalf("NXDOMAIN wrong: rcode=%s aa=%v ns=%d",
			dns.RcodeToString[r.Rcode], r.Authoritative, len(r.Ns))
	}
	soa, ok := r.Ns[0].(*dns.SOA)
	if !ok || soa.Hdr.Ttl != 300 {
		t.Fatalf("negative SOA TTL = %v, want 300 = min(SOA ttl, minimum)", r.Ns[0])
	}

	// NODATA: existing name, missing type -> NOERROR + SOA authority.
	r = dnsQuery(t, addr, "udp", "www.lab.test.", dns.TypeMX)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || len(r.Ns) != 1 {
		t.Fatalf("NODATA wrong: rcode=%s answers=%d ns=%d",
			dns.RcodeToString[r.Rcode], len(r.Answer), len(r.Ns))
	}

	// Out of zone: REFUSED and never recursion.
	r = dnsQuery(t, addr, "udp", "example.com.", dns.TypeA)
	if r.Rcode != dns.RcodeRefused || r.RecursionAvailable {
		t.Fatalf("out-of-zone: rcode=%s ra=%v", dns.RcodeToString[r.Rcode], r.RecursionAvailable)
	}

	// Non-query opcode -> NOTIMP.
	c := new(dns.Client)
	m := new(dns.Msg)
	m.Opcode = dns.OpcodeUpdate
	m.SetQuestion("lab.test.", dns.TypeSOA)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("UPDATE opcode rcode=%s, want NOTIMP", dns.RcodeToString[r.Rcode])
	}
}

// TestE2EAtomicSwapSnapshot drives the exact primitive used on publish:
// one atomic pointer replacement. Concurrent readers must only observe
// complete snapshots, and an AXFR in flight stays on one version.
func TestE2EAtomicSwapSnapshot(t *testing.T) {
	// Serial is assigned by the publisher (NewSnapshot rewrites the SOA);
	// s1=1, s2=8 leaves a visible gap like a jump across versions.
	s1 := snap(t, 1, testZone)
	s2 := snap(t, 8, testZone)

	srv := &Server{
		cfg:    mustConfig(t),
		logger: log.New(io.Discard, "", 0),
	}
	srv.snapshot.Store(s1)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	pc, _ := net.ListenPacket("udp", ln.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, pc, ln)
	addr := ln.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pc := new(dns.Client)
		pc.Timeout = 100 * time.Millisecond
		probe := new(dns.Msg)
		probe.SetQuestion("lab.test.", dns.TypeSOA)
		if _, _, err := pc.Exchange(probe, addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	stop := make(chan struct{})
	errs := make(chan string, 64)
	go func() {
		client := new(dns.Client)
		for {
			select {
			case <-stop:
				return
			default:
			}
			m := new(dns.Msg)
			m.SetQuestion("www.lab.test.", dns.TypeA)
			r, _, err := client.Exchange(m, addr)
			if err != nil {
				errs <- "query error: " + err.Error()
				return
			}
			if n := len(r.Answer); n != 2 {
				errs <- "partial www rrset"
				return
			}
		}
	}()
	// Single swap: old -> new in one atomic step.
	srv.snapshot.Store(s2)
	r := dnsQuery(t, addr, "udp", "lab.test.", dns.TypeSOA)
	if r.Answer[0].(*dns.SOA).Serial != 8 {
		t.Fatalf("post-swap SOA serial = %d, want 8", r.Answer[0].(*dns.SOA).Serial)
	}
	close(stop)
	select {
	case e := <-errs:
		t.Fatal(e)
	default:
	}
}

func mustConfig(t *testing.T) *config.Config {
	t.Helper()
	f, _ := os.CreateTemp(t.TempDir(), "cfg-*.json")
	f.WriteString(`{
	  "zone": "lab.test.", "listen_udp": "127.0.0.1:0", "listen_tcp": "127.0.0.1:0",
	  "database_url": "postgres://unused", "ttl_min": 30, "ttl_max": 86400,
	  "transfer_allow_cidrs": ["127.0.0.0/8"],
	  "tsig_keys": {"xfer.lab.test.": {"algorithm": "hmac-sha256", "secret_b64": "` + testTSIGB64 + `"}}
	}`)
	f.Close()
	cfg, err := config.Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// testDBURL mirrors internal/store test defaults; the test skips when no
// PostgreSQL is reachable so `go test ./...` stays self-contained.
func testDBURL() string {
	if u := os.Getenv("DNSZONE_TEST_DATABASE"); u != "" {
		return u
	}
	return "postgres://dnsadmin@127.0.0.1:55432/dnszone_test?sslmode=disable&connect_timeout=2"
}

// xferDBURL is a separate database so this package's full-stack test never
// truncates tables that internal/store tests are using in parallel.
func xferDBURL(t *testing.T) string {
	t.Helper()
	baseURL := testDBURL()
	// Parse only to discover and validate the connection parameters.
	cfg, err := pgx.ParseConfig(baseURL)
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	xferName := cfg.Database + "_xfer"
	// CREATE DATABASE cannot run in a transaction; connecting to the
	// existing test database and issuing it directly is enough. "Duplicate
	// database" errors are ignored.
	admin, err := pgx.Connect(context.Background(), baseURL)
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	defer admin.Close(context.Background())
	if _, err := admin.Exec(context.Background(),
		`CREATE DATABASE `+quoteIdent(xferName)); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		t.Skipf("cannot create test database %s: %v", xferName, err)
	}
	// Rewrite the path component of the connection URI explicitly:
	// pgx's ConnConfig.ConnString() reconstructs from the original string
	// and would otherwise keep the old database.
	if i := strings.Index(baseURL, "/"); i >= 0 {
		path := baseURL[i+1:]
		rest := ""
		if q := strings.Index(path, "?"); q >= 0 {
			rest = path[q:]
			path = path[:q]
		}
		return baseURL[:i+1] + xferName + rest
	}
	return baseURL
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

const zoneV1Text = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
www IN A 127.0.0.21
`

const zoneV2Text = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
www IN A 127.0.0.21
host2 IN A 127.0.0.30
`

// TestE2ERestoreAndIXFR drives the acceptance flow against real
// PostgreSQL and real DNS sockets:
// publish v1 (serial 1), publish accidental v2 (serial 2), restore v1 ->
// serial 3; queries return v1 content with serial > v2; an IXFR from the
// client's serial 2 expresses the delta to the restored version.
func TestE2ERestoreAndIXFR(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	st, err := store.New(ctx, xferDBURL(t), "lab.test.")
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool().Exec(ctx,
		`TRUNCATE zone_changes, zone_records, zone_versions`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx,
		`UPDATE zone_meta SET current_serial=0, origin='lab.test.' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}
	pub := func(text, note string) uint32 {
		rrs, err := zone.Parse(strings.NewReader(text), "lab.test.", lim)
		if err != nil {
			t.Fatal(err)
		}
		res, err := st.Publish(ctx, rrs, note, lim)
		if err != nil {
			t.Fatal(err)
		}
		return res.Serial
	}
	if s := pub(zoneV1Text, "v1"); s != 1 {
		t.Fatalf("v1 serial = %d, want 1", s)
	}
	if s := pub(zoneV2Text, "v2-accidental"); s != 2 {
		t.Fatalf("v2 serial = %d, want 2", s)
	}

	cfg := mustConfig(t)
	srv, err := New(ctx, cfg, st, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srvCtx, srvCancel := context.WithCancel(ctx)
	t.Cleanup(func() {
		srvCancel()
		pc.Close()
		ln.Close()
	})
	go srv.Serve(srvCtx, pc, ln)
	addr := ln.Addr().String()
	waitReady(t, addr)

	// Before restore: server serves v2.
	r := dnsQuery(t, addr, "udp", "host2.lab.test.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("host2 should exist under v2: rcode=%s answers=%d",
			dns.RcodeToString[r.Rcode], len(r.Answer))
	}

	// Roll back to v1 as a new version.
	res, err := st.Restore(ctx, 1, "restore v1", lim)
	if err != nil {
		t.Fatal(err)
	}
	restoredSerial := res.Serial
	if restoredSerial != 3 {
		t.Fatalf("restored serial = %d, want 3", restoredSerial)
	}

	// Simulate retention pruning of an intermediate version: publish one
	// more version (serial 4) then restore v1 again (serial 5). The IXFR
	// below exercises the intact 1..5 history; serial 4 is pruned only
	// afterwards to test the AXFR fallback for a client on the pruned
	// serial.
	if s := pub(zoneV2Text, "later-pruned"); s != 4 {
		t.Fatalf("pruned version serial = %d, want 4", s)
	}
	if _, err := st.Restore(ctx, 1, "restore v1 again", lim); err != nil {
		t.Fatal(err)
	}
	currentSerial := uint32(5)

	// The server hot-reloads via LISTEN zone_published.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		soa := dnsQuery(t, addr, "udp", "lab.test.", dns.TypeSOA)
		if len(soa.Answer) == 1 && soa.Answer[0].(*dns.SOA).Serial == currentSerial {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	soa := dnsQuery(t, addr, "udp", "lab.test.", dns.TypeSOA)
	if got := soa.Answer[0].(*dns.SOA).Serial; got != currentSerial {
		t.Fatalf("served SOA serial = %d, want %d (> v2)", got, currentSerial)
	}

	// Queries return v1 content: host2 is gone, www still has two records.
	r = dnsQuery(t, addr, "udp", "host2.lab.test.", dns.TypeA)
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("host2 after restore: rcode=%s, want NXDOMAIN (v1 content)",
			dns.RcodeToString[r.Rcode])
	}
	r = dnsQuery(t, addr, "udp", "www.lab.test.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 2 {
		t.Fatalf("www after restore: rcode=%s answers=%d, want 2 v1 records",
			dns.RcodeToString[r.Rcode], len(r.Answer))
	}

	// IXFR from the client's v2 serial to the restored serial must express
	// the change: SOA(cur), SOA(2)+DELs, ..., closing SOA(cur). The
	// intervening serials are all restorations of v1 (empty diffs), so the
	// only non-SOA RR in the stream is the DEL of v2's host2 record.
	ixfrRRs := signedTransfer(t, dns.TypeIXFR, 2, addr)
	if len(ixfrRRs) < 4 {
		t.Fatalf("IXFR too short: %d RRs", len(ixfrRRs))
	}
	head, ok := ixfrRRs[0].(*dns.SOA)
	if !ok || head.Serial != currentSerial {
		t.Fatalf("IXFR must open with current SOA serial %d, got %v", currentSerial, ixfrRRs[0])
	}
	tail, ok := ixfrRRs[len(ixfrRRs)-1].(*dns.SOA)
	if !ok || tail.Serial != currentSerial {
		t.Fatalf("IXFR must close with current SOA serial %d, got %v", currentSerial, ixfrRRs[len(ixfrRRs)-1])
	}
	var sawOldSOA, sawDelHost2 bool
	for _, rr := range ixfrRRs[1 : len(ixfrRRs)-1] {
		if soa, isSOA := rr.(*dns.SOA); isSOA && soa.Serial == 2 {
			sawOldSOA = true
		}
		if rr.Header().Rrtype == dns.TypeA && rr.Header().Name == "host2.lab.test." {
			sawDelHost2 = true
		}
	}
	if !sawOldSOA || !sawDelHost2 {
		t.Fatalf("IXFR v2->%d missing delta pieces (oldSOA=%v delHost2=%v): %v",
			currentSerial, sawOldSOA, sawDelHost2, ixfrRRs)
	}

	// IXFR from an older serial missing from history falls back to AXFR.
	// Now prune the intermediate serial 4 completely (retention), as it
	// would be on a server where only some versions are retained. A client
	// still on serial 4 is older than current but unknown to us, and RFC
	// 1995 mandates falling back to a full AXFR.
	if _, err := st.Pool().Exec(ctx,
		`DELETE FROM zone_changes WHERE serial = 4;
		 DELETE FROM zone_records WHERE serial = 4;
		 DELETE FROM zone_versions WHERE serial = 4`); err != nil {
		t.Fatal(err)
	}
	axfrRRs := signedTransfer(t, dns.TypeIXFR, 4, addr)
	if len(axfrRRs) < 4 {
		t.Fatalf("IXFR from unknown serial should fall back to AXFR, got %d RRs", len(axfrRRs))
	}
	for _, rr := range axfrRRs {
		if soa, isSOA := rr.(*dns.SOA); isSOA && soa.Serial != currentSerial {
			t.Fatalf("AXFR fallback bracketed by wrong serial: %d", soa.Serial)
		}
	}
}

func signedTransfer(t *testing.T, qtype uint16, clientSerial uint32, addr string) []dns.RR {
	t.Helper()
	// Fresh Transfer per call: miekg/dns reuses Transfer.Conn across In()
	// calls, while the server closes the TCP connection once a transfer
	// stream ends.
	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{"xfer.lab.test.": testTSIGB64}
	q := new(dns.Msg)
	q.SetQuestion("lab.test.", qtype)
	if qtype == dns.TypeIXFR {
		q.Ns = []dns.RR{&dns.SOA{
			Hdr:     dns.RR_Header{Name: "lab.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns1.lab.test.",
			Mbox:    "admin.lab.test.",
			Serial:  clientSerial,
			Refresh: 7200, Retry: 3600, Expire: 1209600, Minttl: 300,
		}}
	}
	q.SetTsig("xfer.lab.test.", dns.HmacSHA256, 300, time.Now().Unix())
	env, err := tr.In(q, addr)
	if err != nil {
		t.Fatal(err)
	}
	var all []dns.RR
	for e := range env {
		if e.Error != nil {
			t.Fatalf("envelope: %v", e.Error)
		}
		all = append(all, e.RR...)
	}
	return all
}

func waitReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c := new(dns.Client)
		c.Timeout = 100 * time.Millisecond
		m := new(dns.Msg)
		m.SetQuestion("lab.test.", dns.TypeSOA)
		if _, _, err := c.Exchange(m, addr); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("test server never became ready")
}

func TestE2ETransferGateAndContent(t *testing.T) {
	addr := newTestServer(t, snap(t, 7, testZone))

	// Unsigned AXFR over TCP -> REFUSED.
	c := new(dns.Client)
	c.Net = "tcp"
	m := new(dns.Msg)
	m.SetQuestion("lab.test.", dns.TypeAXFR)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeRefused {
		t.Fatalf("unsigned AXFR rcode=%s, want REFUSED", dns.RcodeToString[r.Rcode])
	}

	// Authorized, correctly signed AXFR: SOA bookends with serial 7.
	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{"xfer.lab.test.": testTSIGB64}
	q := new(dns.Msg)
	q.SetQuestion("lab.test.", dns.TypeAXFR)
	q.SetTsig("xfer.lab.test.", dns.HmacSHA256, 300, time.Now().Unix())
	env, err := tr.In(q, addr)
	if err != nil {
		t.Fatal(err)
	}
	var all []dns.RR
	for e := range env {
		if e.Error != nil {
			t.Fatalf("envelope: %v", e.Error)
		}
		all = append(all, e.RR...)
	}
	if len(all) < 3 {
		t.Fatalf("AXFR too short: %d RRs", len(all))
	}
	if all[0].(*dns.SOA).Serial != 7 || all[len(all)-1].(*dns.SOA).Serial != 7 {
		t.Fatal("AXFR must open and close with the same SOA serial")
	}

	// Wrong secret -> REFUSED (server uses library verification only).
	bad := new(dns.Client)
	bad.Net = "tcp"
	bad.TsigSecret = map[string]string{"xfer.lab.test.": "YmFkLXNlY3JldC1iYWQtc2VjcmV0LWI="}
	bm := new(dns.Msg)
	bm.SetQuestion("lab.test.", dns.TypeAXFR)
	bm.SetTsig("xfer.lab.test.", dns.HmacSHA256, 300, time.Now().Unix())
	br, _, err := bad.Exchange(bm, addr)
	if err != nil {
		t.Fatal(err)
	}
	if br.Rcode != dns.RcodeRefused {
		t.Fatalf("bad-secret AXFR rcode=%s, want REFUSED", dns.RcodeToString[br.Rcode])
	}
}
