package zone

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const validZone = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
@ IN A 127.0.0.5
www IN A 127.0.0.20
www IN A 127.0.0.21
www IN TXT "hello"
alias IN CNAME www.lab.test.
*.wild IN A 127.0.0.99
`

func mustParse(t *testing.T, text string, lim Limits) []dns.RR {
	t.Helper()
	rrs, err := Parse(strings.NewReader(text), "lab.test.", lim)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return rrs
}

func TestParseValid(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, err := NewSnapshot("lab.test.", 42, rrs)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got := snap.SOA().Serial; got != 42 {
		t.Fatalf("SOA serial = %d, want 42 (publisher must rewrite it)", got)
	}
}

func TestTTLBounds(t *testing.T) {
	lim := Limits{MinTTL: 30, MaxTTL: 86400}
	cases := map[string]string{
		"below min": `low 29 IN A 127.0.0.1`,
		"above max": `high 90000 IN A 127.0.0.1`,
	}
	for name, rec := range cases {
		t.Run(name, func(t *testing.T) {
			text := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n",
				rec+"\n", 1)
			if _, err := Parse(strings.NewReader(text), "lab.test.", lim); err == nil {
				t.Fatalf("%s: expected TTL rejection", name)
			}
		})
	}
	t.Run("exact bounds accepted", func(t *testing.T) {
		text := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n",
			"lo 30 IN A 127.0.0.1\nhi 86400 IN A 127.0.0.2\n", 1)
		if _, err := Parse(strings.NewReader(text), "lab.test.", lim); err != nil {
			t.Fatalf("boundary TTLs rejected: %v", err)
		}
	})
}

func TestRejectCNAMEConflict(t *testing.T) {
	base := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n", "", 1)
	cases := map[string]string{
		"coexists with A": base + "h IN A 127.0.0.7\nh IN CNAME x.lab.test.\n",
		"two CNAMEs":      base + "h IN CNAME a.lab.test.\nh IN CNAME b.lab.test.\n",
		"CNAME at apex":   "@ IN CNAME elsewhere.example.net.\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(text), "lab.test.",
				Limits{MinTTL: 30, MaxTTL: 86400}); err == nil {
				t.Fatalf("%s: expected conflict rejection", name)
			}
		})
	}
}

func TestRejectOutOfZoneAndTypes(t *testing.T) {
	base := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n", "", 1)
	cases := map[string]string{
		"out of zone owner": base + "h.other.test. IN A 1.2.3.4\n",
		"unsupported type":  base + "h IN DNSKEY 256 3 8 AAAA\n",
		"class CH":          base + "h 3600 CH TXT \"x\"\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(text), "lab.test.",
				Limits{MinTTL: 30, MaxTTL: 86400}); err == nil {
				t.Fatalf("%s: expected rejection", name)
			}
		})
	}
}

func TestLookupMultiRecord(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	as, found := snap.Lookup("www.lab.test.", dns.TypeA)
	if !found || len(as) != 2 {
		t.Fatalf("www A: found=%v n=%d, want 2 A records", found, len(as))
	}
	txts, _ := snap.Lookup("WWW.LAB.TEST.", dns.TypeTXT)
	if len(txts) != 1 {
		t.Fatalf("case-insensitive www TXT: got %d", len(txts))
	}
	// NODATA: name exists, wrong type. found stays true but no answers.
	if any, found := snap.Lookup("www.lab.test.", dns.TypeAAAA); !found || len(any) != 0 {
		t.Fatalf("www AAAA must be NODATA (found=true, 0 answers), got found=%v n=%d", found, len(any))
	}
	// NXDOMAIN: name absent.
	if _, found := snap.Lookup("missing.lab.test.", dns.TypeA); found {
		t.Fatal("missing name must report not found")
	}
}

func TestLookupCNAMEChain(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	ans, found := snap.Lookup("alias.lab.test.", dns.TypeA)
	if !found || len(ans) != 3 {
		t.Fatalf("alias A: found=%v n=%d, want CNAME+2A", found, len(ans))
	}
	if ans[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatal("first answer must be the CNAME")
	}
	// Explicit CNAME query returns just the CNAME.
	cs, _ := snap.Lookup("alias.lab.test.", dns.TypeCNAME)
	if len(cs) != 1 {
		t.Fatalf("CNAME query returned %d", len(cs))
	}
}

func TestLookupWildcard(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	ans, found := snap.Lookup("anything.wild.lab.test.", dns.TypeA)
	if !found || len(ans) != 1 || ans[0].Header().Name != "anything.wild.lab.test." {
		t.Fatalf("wildcard expansion wrong: found=%v ans=%v", found, ans)
	}
	if ans[0].(*dns.A).A.String() != "127.0.0.99" {
		t.Fatalf("wildcard rdata = %v", ans[0])
	}
}

func TestNegativeTTL(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	if got := snap.NegativeTTL(); got != 300 {
		t.Fatalf("negative TTL = %d, want min(SOA ttl 3600, minimum 300)=300", got)
	}
}

func TestDiffExcludesSOA(t *testing.T) {
	v1 := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	s1, _ := NewSnapshot("lab.test.", 1, v1)
	v2text := strings.Replace(validZone,
		"www IN A 127.0.0.21\n",
		"www IN A 127.0.0.21\nwww IN A 127.0.0.22\n", 1)
	v2 := mustParse(t, v2text, Limits{MinTTL: 30, MaxTTL: 86400})
	s2, _ := NewSnapshot("lab.test.", 2, v2)
	changes := Diff(s1, s2)
	var n int
	for _, c := range changes {
		if c.RR.Header().Rrtype == dns.TypeSOA {
			t.Fatal("SOA must not appear in changelog deltas")
		}
		n++
	}
	if n != 1 {
		var b strings.Builder
		for _, c := range changes {
			b.WriteString(c.Action + " " + CanonicalText(c.RR) + "\n")
		}
		t.Fatalf("diff = %d changes, want 1 (only new A);\n%s", n, b.String())
	}
}

func TestAXFROrdering(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	if snap.RRs[0].Header().Rrtype != dns.TypeSOA {
		t.Fatal("AXFR must begin with SOA")
	}
	if snap.RRs[1].Header().Rrtype != dns.TypeNS {
		t.Fatalf("position 1 must be apex NS, got %v", snap.RRs[1])
	}
}
