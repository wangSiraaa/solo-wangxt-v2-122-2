#!/usr/bin/env python3
"""Send malformed DNS datagrams and assert the server keeps serving.

Robustness check required by the "malformed requests must not crash the
server / must not cause it to fetch anything" rule. Sends truncated,
empty, structurally invalid and random UDP packets, then confirms a
normal query still gets a correct authoritative answer.

Usage: python3 scripts/fuzz-udp.py [host] [port] [count]
"""
import os, random, socket, struct, subprocess, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5354
COUNT = int(sys.argv[3]) if len(sys.argv) > 3 else 2000

cases = [
    b"", b"\x00", b"\x00\x00", b"\x00" * 11, b"\xff" * 4,
    b"\xab\xcd\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00",        # no question
    b"\xab\xcd\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00",        # QDCOUNT=2
    b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www", # truncated name
    b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00",
]
random.seed(1)
for _ in range(COUNT):
    cases.append(bytes(random.randrange(256) for _ in range(random.randint(0, 60))))

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)
replies = 0
for pkt in cases:
    try:
        s.sendto(pkt, (HOST, PORT))
        data, _ = s.recvfrom(4096)
        if data and struct.unpack("!H", data[2:4])[0] & 0x8000:  # QR bit
            replies += 1
    except socket.timeout:
        pass
s.close()

dig = os.environ.get("DIG", "dig")
out = subprocess.run([dig, f"@{HOST}", "-p", str(PORT), "ns1.lab.test.", "A", "+short"],
                     capture_output=True, text=True).stdout
assert out.strip() == "127.0.0.10", f"server not functional after fuzz: {out!r}"
print(f"sent {len(cases)} malformed probes, {replies} well-formed replies; service intact")
