from pwn import *

context(log_level="debug")
io = remote("node4.anna.nssctf.cn", 26810)

for i in range(101):
    io.recvuntil(b"\nWhat is ")
    express = io.recvuntil(b"?")[:-1]
    io.sendline(str(eval(express)).encode())


io.interactive()

