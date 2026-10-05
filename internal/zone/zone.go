// Package zone implements the in-memory authoritative zone model:
// parsing RFC 1035 zone text, semantic validation (record-type allow-list,
// TTL bounds, CNAME conflicts, in-zone owners), immutable snapshots and
// diffing between two versions for IXFR/changelog generation.
package zone

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Record types this server explicitly supports. Anything else appearing
// in a zone file (including DNSSEC types like RRSIG/NSEC/DNSKEY) is rejected.
var allowedTypes = map[uint16]bool{
	dns.TypeSOA:   true,
	dns.TypeNS:    true,
	dns.TypeA:     true,
	dns.TypeAAAA:  true,
	dns.TypeCNAME: true,
	dns.TypeMX:    true,
	dns.TypeTXT:   true,
	dns.TypeSRV:   true,
	dns.TypePTR:   true,
	dns.TypeCAA:   true,
}

// IsAllowedType reports whether t is on the supported record-type list.
func IsAllowedType(t uint16) bool { return allowedTypes[t] }

// Limits configures the accepted TTL window for zone records.
type Limits struct {
	MinTTL uint32
	MaxTTL uint32
}

// Snapshot is an immutable point-in-time copy of a zone version.
// All lookups operate on snapshots, so a query can never observe a
// half-published version: the swap to a new snapshot is a single
// pointer assignment.
type Snapshot struct {
	Origin   string
	Serial   uint32
	RRs      []dns.RR // full canonical RRset, SOA/NS(apex) first then sorted
	byName   map[string][]dns.RR
	wildcard map[string][]dns.RR // exact wildcard label -> records ("*.lab.test.")
}

func (s *Snapshot) buildIndex() {
	s.byName = make(map[string][]dns.RR)
	s.wildcard = make(map[string][]dns.RR)
	for _, rr := range s.RRs {
		name := rr.Header().Name
		if strings.HasPrefix(name, "*.") {
			s.wildcard[name] = append(s.wildcard[name], rr)
			continue
		}
		s.byName[name] = append(s.byName[name], rr)
	}
}

// Lookup returns all records at name of the given qtype, following up to
// eight CNAME hops, along with the records in traversal order. qtype TypeANY
// returns every record at the name. Wildcards (RFC 4592) are consulted.
// The returned found flag distinguishes NXDOMAIN (name does not exist)
// from NODATA (name exists, no record of the requested type).
func (s *Snapshot) Lookup(qname string, qtype uint16) (answers []dns.RR, found bool) {
	name := strings.ToLower(qname)
	seen := map[string]bool{}
	for hops := 0; hops <= 8; hops++ {
		direct, directExists := s.lookupName(name)
		var rrs []dns.RR
		if directExists {
			rrs = direct
		} else if wc := s.matchWildcard(name); wc != nil {
			// Synthesize: wildcard owner becomes the queried name.
			for _, rr := range wc {
				cp := dns.Copy(rr)
				cp.Header().Name = name
				rrs = append(rrs, cp)
			}
		} else {
			return answers, found
		}
		found = true

		if qtype == dns.TypeANY {
			answers = append(answers, rrs...)
			return
		}
		var matched []dns.RR
		var cname *dns.CNAME
		for _, rr := range rrs {
			if rr.Header().Rrtype == qtype {
				matched = append(matched, rr)
			}
			if c, ok := rr.(*dns.CNAME); ok {
				cname = c
			}
		}
		if len(matched) > 0 {
			answers = append(answers, matched...)
			return
		}
		if qtype == dns.TypeCNAME || cname == nil || seen[name] {
			return
		}
		seen[name] = true
		answers = append(answers, cname)
		name = strings.ToLower(cname.Target)
		if !dns.IsSubDomain(s.Origin, name) {
			// Target outside the zone; the server cannot chase it.
			return
		}
	}
	return
}

func (s *Snapshot) lookupName(name string) ([]dns.RR, bool) {
	rrs, ok := s.byName[strings.ToLower(name)]
	return rrs, ok
}

// matchWildcard implements RFC 4592 source-of-synthesis lookup: find the
// closest encloser (the deepest concrete ancestor name of qname; the
// apex always counts as concrete because it holds SOA/NS), then test
// wildcard names one label below it, nearest first.
func (s *Snapshot) matchWildcard(name string) []dns.RR {
	name = strings.ToLower(name)
	if !dns.IsSubDomain(s.Origin, name) || name == s.Origin {
		return nil
	}
	labels := dns.SplitDomainName(name)
	originN := dns.CountLabel(s.Origin)
	// strip = number of qname labels removed to reach the closest
	// encloser. labels[strip:] is the encloser suffix.
	strip := 0
	for strip < len(labels)-originN {
		suffix := strings.Join(labels[strip+1:], ".") + "."
		if _, concrete := s.lookupName(suffix); concrete {
			break
		}
		strip++
	}
	// Candidate wildcard expands qname's (strip+1)th label to "*":
	// for strip=0 -> "*.<parent>"; try deeper wildcards only while no
	// concrete name blocks them. Nearest candidate first.
	for i := strip; i >= 0; i-- {
		suffix := strings.Join(labels[i+1:], ".") + "."
		if rrs, ok := s.wildcard["*."+suffix]; ok {
			return rrs
		}
	}
	return nil
}

// SOA returns the zone SOA record (a copy), or nil if absent.
func (s *Snapshot) SOA() *dns.SOA {
	for _, rr := range s.RRs {
		if soa, ok := rr.(*dns.SOA); ok {
			return dns.Copy(soa).(*dns.SOA)
		}
	}
	return nil
}

// NegativeTTL returns the TTL to put on the SOA in negative responses:
// min(SOA TTL, SOA minimum field) per RFC 2308 section 5.
func (s *Snapshot) NegativeTTL() uint32 {
	soa := s.SOA()
	if soa == nil {
		return 0
	}
	if soa.Hdr.Ttl < soa.Minttl {
		return soa.Hdr.Ttl
	}
	return soa.Minttl
}

// Parse reads an RFC 1035 master file and returns the RRs normalized to the
// given origin. TTL values are checked against lim but the serial in the
// SOA is left untouched (the caller rewrites it on publish).
func Parse(r io.Reader, origin string, lim Limits) ([]dns.RR, error) {
	zp := dns.NewZoneParser(r, dns.Fqdn(origin), "input")
	var out []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if err := validateRR(rr, dns.Fqdn(origin), lim); err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("zone parse: %w", err)
	}
	if err := Validate(out, origin, lim); err != nil {
		return nil, err
	}
	sortRRs(out, dns.Fqdn(origin))
	return out, nil
}

// Validate checks a complete RR set against the current record and TTL
// rules. It is used both when parsing a new master file and when
// republishing records loaded from historical storage.
func Validate(rrs []dns.RR, origin string, lim Limits) error {
	origin = dns.Fqdn(origin)
	for _, rr := range rrs {
		if err := validateRR(rr, origin, lim); err != nil {
			return err
		}
	}
	return validateSet(rrs, origin)
}

// NewSnapshot builds an immutable snapshot with a store-assigned serial.
func NewSnapshot(origin string, serial uint32, rrs []dns.RR) (*Snapshot, error) {
	origin = dns.Fqdn(origin)
	for _, rr := range rrs {
		if err := validateRR(rr, origin, Limits{MinTTL: 0, MaxTTL: ^uint32(0)}); err != nil {
			return nil, err
		}
	}
	if err := validateSet(rrs, origin); err != nil {
		return nil, err
	}
	cp := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		c := dns.Copy(rr)
		if soa, ok := c.(*dns.SOA); ok {
			soa.Serial = serial
		}
		cp[i] = c
	}
	sortRRs(cp, origin)
	s := &Snapshot{Origin: origin, Serial: serial, RRs: cp}
	s.buildIndex()
	return s, nil
}

func validateRR(rr dns.RR, origin string, lim Limits) error {
	h := rr.Header()
	if h.Class != dns.ClassINET {
		return fmt.Errorf("record %s %s: only class IN supported", h.Name, dns.TypeToString[h.Rrtype])
	}
	if !allowedTypes[h.Rrtype] {
		return fmt.Errorf("record %s %s: type not supported by this server", h.Name, dns.TypeToString[h.Rrtype])
	}
	if h.Ttl < lim.MinTTL {
		return fmt.Errorf("record %s %s: TTL %d below minimum %d", h.Name, dns.TypeToString[h.Rrtype], h.Ttl, lim.MinTTL)
	}
	if h.Ttl > lim.MaxTTL {
		return fmt.Errorf("record %s %s: TTL %d above maximum %d", h.Name, dns.TypeToString[h.Rrtype], h.Ttl, lim.MaxTTL)
	}
	name := strings.ToLower(h.Name)
	if !dns.IsSubDomain(origin, name) {
		return fmt.Errorf("record %s %s: owner name outside zone %s", h.Name, dns.TypeToString[h.Rrtype], origin)
	}
	if h.Rrtype == dns.TypeNS && name != origin {
		return fmt.Errorf("NS record %s: only apex NS is supported in this zone", h.Name)
	}
	return nil
}

// validateSet enforces whole-zone invariants:
// exactly one SOA at apex, apex CNAME forbidden, and the RFC 1034 CNAME
// coexistence rule (a CNAME owner may have no other record type, and a
// name with other records may not gain a CNAME).
func validateSet(rrs []dns.RR, origin string) error {
	soaCount := 0
	nsAtApex := 0
	byName := map[string]map[uint16]int{}
	for _, rr := range rrs {
		h := rr.Header()
		name := strings.ToLower(h.Name)
		if name == origin {
			switch h.Rrtype {
			case dns.TypeSOA:
				soaCount++
			case dns.TypeNS:
				nsAtApex++
			}
		}
		if _, ok := byName[name]; !ok {
			byName[name] = map[uint16]int{}
		}
		byName[name][h.Rrtype]++
	}
	if soaCount != 1 {
		return fmt.Errorf("zone must contain exactly one SOA record at apex %s, found %d", origin, soaCount)
	}
	if nsAtApex == 0 {
		return fmt.Errorf("zone must contain at least one NS record at apex %s", origin)
	}
	for name, types := range byName {
		if _, hasCNAME := types[dns.TypeCNAME]; hasCNAME {
			if name == origin {
				return errors.New("CNAME at zone apex is forbidden (apex must keep SOA and NS)")
			}
			if types[dns.TypeCNAME] > 1 {
				return fmt.Errorf("multiple CNAME records at %s", name)
			}
			if len(types) > 1 {
				return fmt.Errorf("CNAME at %s conflicts with other record type(s) at the same name (RFC 1034)", name)
			}
		}
	}
	return nil
}

// Key identifies a resource record independently of its TTL: same owner,
// type and rdata body. Used for diffs.
func rrKey(rr dns.RR) string {
	h := rr.Header()
	return strings.ToLower(h.Name) + "|" + dns.TypeToString[h.Rrtype] + "|" + canonicalRdata(rr)
}

// canonicalRdata renders rdata without the owner/TTL/class/type prefix.
func canonicalRdata(rr dns.RR) string {
	// miekg format: "name\tttl\tclass\ttype\trdata..." (5+ tab fields).
	parts := strings.Split(rr.String(), "\t")
	if len(parts) >= 5 {
		return strings.ToLower(strings.Join(parts[4:], " "))
	}
	return strings.ToLower(rr.String())
}

// Change is one removed or added record between two zone versions.
type Change struct {
	Action string // "ADD" or "DEL"
	RR     dns.RR
}

// Diff returns the changelog from old to new: deletions of records that
// disappeared followed by additions of records that appeared. Each side
// keeps TTL of the respective version so IXFR clients can update caches.
// The apex SOA is excluded: its serial changes with every version and is
// carried structurally by zone versions / the IXFR envelope.
func Diff(old, new *Snapshot) []Change {
	oldSet := map[string]dns.RR{}
	newSet := map[string]dns.RR{}
	collect := func(snap *Snapshot, dst map[string]dns.RR) {
		if snap == nil {
			return
		}
		for _, rr := range snap.RRs {
			if rr.Header().Rrtype == dns.TypeSOA {
				continue
			}
			dst[rrKey(rr)] = rr
		}
	}
	collect(old, oldSet)
	collect(new, newSet)
	var changes []Change
	for k, rr := range oldSet {
		if _, ok := newSet[k]; !ok {
			changes = append(changes, Change{Action: "DEL", RR: dns.Copy(rr)})
		}
	}
	for k, rr := range newSet {
		if _, ok := oldSet[k]; !ok {
			changes = append(changes, Change{Action: "ADD", RR: dns.Copy(rr)})
		}
	}
	sortChanges(changes)
	return changes
}

func sortChanges(ch []Change) {
	sort.SliceStable(ch, func(i, j int) bool {
		if ch[i].Action != ch[j].Action {
			return ch[i].Action == "DEL" // DEL before ADD
		}
		return rrKey(ch[i].RR) < rrKey(ch[j].RR)
	})
}

// sortRRs orders records deterministically: SOA first, apex NS next, then
// by name and type. This is the AXFR wire order clients expect.
func sortRRs(rrs []dns.RR, origin string) {
	rank := func(rr dns.RR) int {
		h := rr.Header()
		switch {
		case h.Rrtype == dns.TypeSOA && strings.EqualFold(h.Name, origin):
			return 0
		case h.Rrtype == dns.TypeNS && strings.EqualFold(h.Name, origin):
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(rrs, func(i, j int) bool {
		ri, rj := rank(rrs[i]), rank(rrs[j])
		if ri != rj {
			return ri < rj
		}
		ni := strings.ToLower(rrs[i].Header().Name)
		nj := strings.ToLower(rrs[j].Header().Name)
		if ni != nj {
			return ni < nj
		}
		if rrs[i].Header().Rrtype != rrs[j].Header().Rrtype {
			return rrs[i].Header().Rrtype < rrs[j].Header().Rrtype
		}
		return canonicalRdata(rrs[i]) < canonicalRdata(rrs[j])
	})
}

// CanonicalText serializes an RR in stable master-file form for storage.
func CanonicalText(rr dns.RR) string {
	h := rr.Header()
	return fmt.Sprintf("%s %d IN %s %s",
		strings.ToLower(h.Name),
		h.Ttl,
		dns.TypeToString[h.Rrtype],
		canonicalRdata(rr))
}
