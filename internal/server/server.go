// Package server implements the authoritative DNS server. It serves one
// zone from an immutable snapshot that is atomically swapped when a new
// version publishes. It never resolves recursively and never fetches
// anything from the network: all answers come from the local snapshot.
package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/config"
	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"
)

// Server is a read-only authoritative name server plus TSIG-gated
// AXFR/IXFR for authorized clients.
type Server struct {
	cfg    *config.Config
	store  *store.Store
	logger *log.Logger

	snapshot atomic.Pointer[zone.Snapshot]

	udp *dns.Server
	tcp *dns.Server
}

// New creates the server and loads the current snapshot (may be nil if
// no version published yet).
func New(ctx context.Context, cfg *config.Config, st *store.Store, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{cfg: cfg, store: st, logger: logger}
	snap, err := st.LoadCurrent(ctx)
	if err != nil {
		return nil, err
	}
	s.snapshot.Store(snap)
	return s, nil
}

// Run starts UDP and TCP listeners from the configured addresses and
// follows publish notifications until ctx is canceled.
func (s *Server) Run(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", s.cfg.ListenUDP)
	if err != nil {
		return fmt.Errorf("udp listen %s: %w", s.cfg.ListenUDP, err)
	}
	ln, err := net.Listen("tcp", s.cfg.ListenTCP)
	if err != nil {
		pc.Close()
		return fmt.Errorf("tcp listen %s: %w", s.cfg.ListenTCP, err)
	}
	return s.Serve(ctx, pc, ln)
}

// Serve runs the DNS handlers on already-bound listeners (used by Run and
// by tests that need ephemeral ports). Both listeners are closed when the
// context is canceled or either server terminates.
func (s *Server) Serve(ctx context.Context, pc net.PacketConn, ln net.Listener) error {
	mux := dns.NewServeMux()
	// Handle everything ourselves: out-of-zone names get REFUSED rather
	// than the mux's default behavior.
	mux.HandleFunc(".", s.handle)

	newDNSServer := func() *dns.Server {
		srv := &dns.Server{
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}
		if s.cfg.HasTransferKeys() {
			// Library-provided TSIG: the server verifies incoming signed
			// requests with HMAC (SHA1/SHA224/SHA256/SHA384/SHA512) and the
			// transfer writer auto-signs responses. No custom crypto.
			srv.TsigSecret = s.cfg.TsigSecrets()
		}
		return srv
	}

	s.udp = newDNSServer()
	s.udp.PacketConn = pc
	s.tcp = newDNSServer()
	s.tcp.Listener = ln

	errCh := make(chan error, 2)
	go func() { errCh <- s.udp.ActivateAndServe() }()
	go func() { errCh <- s.tcp.ActivateAndServe() }()
	s.logger.Printf("authoritative server for zone %s: UDP %s, TCP %s",
		s.cfg.ZoneOrigin(), pc.LocalAddr(), ln.Addr())

	go s.watchPublishes(ctx)

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.udp.ShutdownContext(shCtx)
		_ = s.tcp.ShutdownContext(shCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) watchPublishes(ctx context.Context) {
	if s.store == nil {
		// Static-snapshot mode (tests): nothing to watch.
		<-ctx.Done()
		return
	}
	ch := s.store.Subscribe(ctx)
	for serial := range ch {
		snap, err := s.store.LoadSnapshot(ctx, serial)
		if err != nil {
			s.logger.Printf("reload serial %d: %v", serial, err)
			continue
		}
		// Single atomic pointer swap: in-flight queries finish against the
		// snapshot they started with; new queries see the whole new version.
		cur := s.snapshot.Load()
		if cur != nil && serial <= cur.Serial {
			continue
		}
		s.snapshot.Store(snap)
		s.logger.Printf("loaded new zone version serial %d (%d records)", serial, len(snap.RRs))
	}
}

func (s *Server) current() *zone.Snapshot { return s.snapshot.Load() }

func clientIP(w dns.ResponseWriter) net.IP {
	if a, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		return a.IP
	}
	if a, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP
	}
	h, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		return nil
	}
	return net.ParseIP(h)
}

func refused(w dns.ResponseWriter, m *dns.Msg) {
	r := new(dns.Msg)
	r.SetRcode(m, dns.RcodeRefused)
	r.RecursionAvailable = false
	_ = w.WriteMsg(r)
}

func (s *Server) handle(w dns.ResponseWriter, m *dns.Msg) {
	// Standard query only. This server does not implement DNS UPDATE
	// (opcode UPDATE -> NOTIMP), inverse queries, or anything else.
	if m.Opcode != dns.OpcodeQuery {
		r := new(dns.Msg)
		r.SetRcode(m, dns.RcodeNotImplemented)
		_ = w.WriteMsg(r)
		return
	}
	if len(m.Question) != 1 {
		r := new(dns.Msg)
		r.SetRcode(m, dns.RcodeFormatError)
		_ = w.WriteMsg(r)
		return
	}

	// EDNS version negotiation: only version 0 understood.
	if opt := m.IsEdns0(); opt != nil && opt.Version() != 0 {
		r := new(dns.Msg)
		r.SetRcode(m, dns.RcodeBadVers)
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetVersion(0)
		r.Extra = append(r.Extra, o)
		_ = w.WriteMsg(r)
		return
	}

	q := m.Question[0]
	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		s.handleTransfer(w, m)
		return
	}
	s.handleQuery(w, m)
}

func (s *Server) handleQuery(w dns.ResponseWriter, m *dns.Msg) {
	q := m.Question[0]
	snap := s.current()
	if snap == nil {
		refused(w, m)
		return
	}
	qname := strings.ToLower(q.Name)
	if q.Qclass != dns.ClassINET {
		r := new(dns.Msg)
		r.SetRcode(m, dns.RcodeRefused)
		_ = w.WriteMsg(r)
		return
	}
	if !dns.IsSubDomain(snap.Origin, qname) {
		// Out of zone: authoritative REFUSED, and crucially no recursion
		// is attempted (RA=0). Nothing is fetched from anywhere.
		r := new(dns.Msg)
		r.SetRcode(m, dns.RcodeRefused)
		r.RecursionAvailable = false
		_ = w.WriteMsg(r)
		return
	}

	r := new(dns.Msg)
	r.SetReply(m)
	r.Authoritative = true
	r.RecursionAvailable = false

	answers, nameExists := snap.Lookup(qname, q.Qtype)
	r.Answer = answers
	if len(answers) > 0 {
		s.write(w, r)
		return
	}

	soa := snap.SOA()
	negativeSOA := dns.Copy(soa).(*dns.SOA)
	negativeSOA.Hdr.Ttl = snap.NegativeTTL()

	if !nameExists {
		// Prove NXDOMAIN with the name-error proof chain: if an ancestor of
		// qname does not exist either, it is still NXDOMAIN; the SOA in
		// authority marks it as an authoritative negative answer (RFC 2308).
		r.Rcode = dns.RcodeNameError
		r.Ns = append(r.Ns, negativeSOA)
	} else {
		// NODATA: name exists, no record of this type (also covers the
		// empty non-terminal case).
		r.Rcode = dns.RcodeSuccess
		r.Ns = append(r.Ns, negativeSOA)
	}
	s.write(w, r)
}

func (s *Server) write(w dns.ResponseWriter, resp *dns.Msg) {
	if err := w.WriteMsg(resp); err != nil {
		s.logger.Printf("write response to %s: %v", w.RemoteAddr(), err)
	}
}

// transferRequest validates ACL + TSIG for an AXFR/IXFR request.
func (s *Server) transferRequest(w dns.ResponseWriter, m *dns.Msg) (*zone.Snapshot, bool) {
	snap := s.current()
	if snap == nil {
		refused(w, m)
		return nil, false
	}
	ip := clientIP(w)
	if ip == nil || !s.cfg.TransferAllowed(ip) {
		s.logger.Printf("transfer denied by ACL: %s", w.RemoteAddr())
		refused(w, m)
		return nil, false
	}
	// Require a valid TSIG record. The library verifies the MAC using the
	// configured keys and exposes the result via TsigStatus; an unsigned
	// request or a bad/unknown key is refused.
	tsig := m.IsTsig()
	if tsig == nil {
		s.logger.Printf("transfer denied (no TSIG): %s", w.RemoteAddr())
		refused(w, m)
		return nil, false
	}
	if status := w.TsigStatus(); status != nil {
		s.logger.Printf("transfer denied (TSIG verification failed): %s: %v",
			w.RemoteAddr(), status)
		refused(w, m)
		return nil, false
	}
	q := m.Question[0]
	if !strings.EqualFold(q.Name, snap.Origin) {
		refused(w, m)
		return nil, false
	}
	return snap, true
}

func (s *Server) handleTransfer(w dns.ResponseWriter, m *dns.Msg) {
	if _, ok := w.RemoteAddr().(*net.TCPAddr); !ok {
		// Zone transfers are TCP only.
		refused(w, m)
		return
	}
	snap, ok := s.transferRequest(w, m)
	if !ok {
		return
	}
	q := m.Question[0]
	if q.Qtype == dns.TypeAXFR {
		s.serveAXFR(w, m, snap)
		return
	}

	// IXFR: RFC 1995. The client's current serial comes from the SOA in
	// authority. Same serial -> just the SOA; older serial we have deltas
	// for -> incremental response; otherwise fall back to full AXFR.
	var clientSerial uint32
	if len(m.Ns) == 0 {
		s.serveAXFR(w, m, snap)
		return
	}
	soaReq, isSOA := m.Ns[0].(*dns.SOA)
	if !isSOA {
		s.serveAXFR(w, m, snap)
		return
	}
	clientSerial = soaReq.Serial

	switch {
	case clientSerial == snap.Serial:
		// Already up to date: RFC 1995 single-SOA response.
		s.serveSOAOnly(w, m, snap)
	case clientSerial > snap.Serial:
		// Client claims a serial ahead of ours. Per RFC 1995 2.(c) the
		// server MAY answer with just the current SOA; do so.
		s.serveSOAOnly(w, m, snap)
	default:
		// We must hold the client's version to produce deltas; if we do
		// not (pruned history, serial from another master), RFC 1995
		// mandates falling back to a full AXFR.
		exists, err := s.store.VersionExists(context.Background(), clientSerial)
		if err == nil && exists {
			if err := s.serveIXFR(w, m, snap, clientSerial); err == nil {
				return
			}
			s.logger.Printf("IXFR failed, falling back to AXFR: %v", err)
		}
		s.serveAXFR(w, m, snap)
	}
}

func (s *Server) serveAXFR(w dns.ResponseWriter, m *dns.Msg, snap *zone.Snapshot) {
	ch := make(chan *dns.Envelope, 4)
	go func() {
		defer close(ch)
		soa := snap.SOA()
		// RFC 5936: the first message contains only the SOA.
		ch <- &dns.Envelope{RR: []dns.RR{dns.Copy(soa)}}
		const batch = 40
		var middle []dns.RR
		for _, rr := range snap.RRs {
			if _, isSOA := rr.(*dns.SOA); isSOA {
				continue
			}
			middle = append(middle, rr)
		}
		for i := 0; i < len(middle); i += batch {
			j := min(i+batch, len(middle))
			ch <- &dns.Envelope{RR: append([]dns.RR(nil), middle[i:j]...)}
		}
		// The final message contains only the closing SOA.
		ch <- &dns.Envelope{RR: []dns.RR{dns.Copy(soa)}}
	}()
	if err := (&dns.Transfer{}).Out(w, m, ch); err != nil {
		s.logger.Printf("AXFR to %s: %v", w.RemoteAddr(), err)
	}
}

func (s *Server) serveSOAOnly(w dns.ResponseWriter, m *dns.Msg, snap *zone.Snapshot) {
	// RFC 1995: "SOA serial == server serial" response is a single SOA.
	ch := make(chan *dns.Envelope, 1)
	ch <- &dns.Envelope{RR: []dns.RR{snap.SOA()}}
	close(ch)
	if err := (&dns.Transfer{}).Out(w, m, ch); err != nil {
		s.logger.Printf("SOA-only response to %s: %v", w.RemoteAddr(), err)
	}
}

// serveIXFR streams RFC 1995 deltas from clientSerial+1 up to current:
// SOA(new), [DEL old RRs ..., SOA(old)], [ADD new RRs ..., SOA(new)] ...
func (s *Server) serveIXFR(w dns.ResponseWriter, m *dns.Msg, current *zone.Snapshot, clientSerial uint32) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cur, err := s.store.CurrentSerial(ctx)
	if err != nil {
		return err
	}
	if cur != current.Serial {
		return errors.New("serial moved while building IXFR")
	}

	ch := make(chan *dns.Envelope, 8)
	go func() {
		defer close(ch)
		currentSOA := current.SOA()
		ch <- &dns.Envelope{RR: []dns.RR{dns.Copy(currentSOA)}}
		for serial := clientSerial + 1; serial <= cur; serial++ {
			changes, err := s.store.LoadChanges(ctx, serial)
			if err != nil {
				return
			}
			oldSOA, err := s.soaFor(ctx, serial-1)
			if err != nil {
				return
			}
			newSOA, err := s.soaFor(ctx, serial)
			if err != nil {
				return
			}
			var dels, adds []dns.RR
			for _, c := range changes {
				switch c.Action {
				case "DEL":
					dels = append(dels, c.RR)
				case "ADD":
					adds = append(adds, c.RR)
				}
			}
			ch <- &dns.Envelope{RR: append([]dns.RR{dns.Copy(oldSOA)}, dels...)}
			ch <- &dns.Envelope{RR: append([]dns.RR{dns.Copy(newSOA)}, adds...)}
		}
		ch <- &dns.Envelope{RR: []dns.RR{dns.Copy(currentSOA)}}
	}()

	t := dns.Transfer{}
	if err := t.Out(w, m, ch); err != nil {
		return fmt.Errorf("ixfr write: %w", err)
	}
	return nil
}

func (s *Server) soaFor(ctx context.Context, serial uint32) (*dns.SOA, error) {
	if serial == 0 {
		// No previous version: the first version's delta treats the old
		// SOA as equal to the new one (empty prior state).
		snap, err := s.store.LoadSnapshot(ctx, 1)
		if err != nil {
			return nil, err
		}
		return snap.SOA(), nil
	}
	snap, err := s.store.LoadSnapshot(ctx, serial)
	if err != nil {
		return nil, err
	}
	return snap.SOA(), nil
}
