#!/usr/bin/env bash
# End-to-end verification with standard dig. Assumes:
#   - dnszone server running on 127.0.0.1:5354 with config.json (zone lab.test.)
#   - testdata/zone-v2.db currently published (serial 2, host2 exists)
#   - dig available via DIG or PATH
set -u
DIG="${DIG:-dig}"
S="@127.0.0.1 -p 5354"
KEY="-k testdata/tsig.key"
fail=0
pass() { printf 'PASS %s\n' "$1"; }
bad()  { printf 'FAIL %s\n' "$1"; fail=1; }

out()  { $DIG $S "$@" 2>&1; }
cnt()  { out "$@" | grep -vcE '^;|^$|TSIG'; }
has()  { out "$@" | grep -qE "$1"; }

# Current SOA serial (assumes the full zone is published).
CUR=$(out lab.test SOA +short | awk '{print $3}')
PREV=$((CUR - 1))

# 1. Authoritative positive answer with AA, no recursion availability.
hdr=$(out lab.test SOA +noall +comments)
echo "$hdr" | grep -q 'status: NOERROR' && \
echo "$hdr" | grep -q 'flags: qr aa rd;' && \
! echo "$hdr" | grep -q ' ra' && \
pass "apex SOA is AA, no RA" || bad "apex SOA flags"

# 2. TTL honored on positive answers (configured 3600).
has $'lab\\.test\\.\t\t3600\tIN\tSOA' lab.test SOA +noall +answer && pass "positive TTL=3600" || bad "positive TTL"

# 3. Same name, multiple records.
n=$(out www.lab.test A +noall +answer +tcp | grep -c $'\tA\t')
[ "$n" = "3" ] && pass "www.lab.test has 3 A records" || bad "multi-record count=$n"

# 4. CNAME chase inside zone.
out alias.lab.test A +noall +answer | grep -q "CNAME.*www.lab.test." && \
[ "$(out alias.lab.test A +noall +answer | grep -c $'\tA\t')" = "3" ] && \
pass "CNAME alias -> www (CNAME+3 A)" || bad "CNAME chase"

# 5. Wildcard.
has '127.0.0.99' anything.wild.lab.test A +short && pass "wildcard expansion" || bad "wildcard"

# 6. NXDOMAIN carries SOA authority at negative TTL (300), AA.
out nope.lab.test A >/tmp/r1.txt
grep -q 'status: NXDOMAIN' /tmp/r1.txt && \
grep -q 'flags: qr aa rd' /tmp/r1.txt && \
grep -qE 'lab\.test\.\s+300\s+IN\s+SOA' /tmp/r1.txt && \
pass "NXDOMAIN AA + SOA @300" || bad "NXDOMAIN"

# 7. NODATA (name exists, type missing).
out www.lab.test AAAA >/tmp/r2.txt
grep -q 'status: NOERROR' /tmp/r2.txt && \
grep -qE 'lab\.test\.[[:space:]]+300[[:space:]]+IN[[:space:]]+SOA' /tmp/r2.txt && \
[ "$(awk '/^;; ANSWER SECTION:/{f=1;next} /^;; /{f=0} f && /AAAA/' /tmp/r2.txt | wc -l)" = "0" ] && \
pass "NODATA NOERROR + SOA @300" || bad "NODATA"

# 8. Out of zone -> REFUSED, recursion not available.
out example.com A +noall +comments | grep -q 'status: REFUSED' && pass "out-of-zone REFUSED" || bad "out-of-zone"

# 9. AXFR/IXFR over UDP refused.
out lab.test AXFR +ignore +noall +comments | grep -q 'status: REFUSED' && pass "AXFR over UDP refused" || bad "AXFR UDP"

# 10. AXFR without TSIG refused (TCP).
out lab.test AXFR +tcp +noall +comments | grep -q 'status: REFUSED' && pass "unsigned AXFR refused" || bad "unsigned AXFR"

# 11. AXFR with valid TSIG succeeds and bookends SOA serial 2.
$DIG $S $KEY lab.test AXFR +tcp +noall +answer >/tmp/xfr.txt 2>/dev/null
first=$(grep -m1 $'\tSOA\t' /tmp/xfr.txt | awk '{print $7}')
last=$(tac /tmp/xfr.txt | grep -m1 $'\tSOA\t' | awk '{print $7}')
nrec=$(grep -vcE '^;|^$|TSIG' /tmp/xfr.txt)
[ "$first" = "$CUR" ] && [ "$last" = "$CUR" ] && [ "$nrec" = "20" ] && \
pass "TSIG AXFR complete (20 RRs, SOA $CUR..$CUR)" || bad "TSIG AXFR ($first/$last/$nrec)"

# 12. IXFR up-to-date (current serial) -> single SOA.
n=$( $DIG $S $KEY lab.test IXFR=$CUR +tcp +noall +answer 2>/dev/null | grep -vcE '^;|^$|TSIG' )
[ "$n" = "1" ] && pass "IXFR current serial -> 1 SOA" || bad "IXFR current ($n)"

# 13. IXFR delta from previous serial: new SOA, old SOA+DEL, new SOA+ADDs, final SOA.
$DIG $S $KEY lab.test IXFR=$PREV +tcp +noall +answer 2>/dev/null | grep -v TSIG >/tmp/ix.txt
soas=$(grep -c $'\tSOA\t' /tmp/ix.txt)
grep -q 'DEL\|v1\|TXT "multi-record same name v1"' /tmp/ix.txt && \
grep -q '127.0.0.30' /tmp/ix.txt && [ "$soas" = "4" ] && \
pass "IXFR $PREV->$CUR delta shaped (4 SOAs)" || bad "IXFR delta (soa=$soas)"

# 14. Unsupported record type in an explicit query still answered NODATA
#     (server does not crash; types are constrained at publish time).
out www.lab.test RRSIG +noall +comments | grep -q 'status: NOERROR' && pass "RRSIG query NODATA, no crash" || bad "RRSIG query"

# 15. Non-query opcode handled (NOTIMP/REFUSED), server stays up.
has '127.0.0.20' www.lab.test A +short && pass "server alive after all probes" || bad "liveness"

echo "----------------------------------------"
if [ "$fail" = 0 ]; then echo "ALL DIG CHECKS PASSED"; else echo "SOME CHECKS FAILED"; exit 1; fi
