from pwn import *

io = process("./附件")
gdb.attach(io)
io.recvuntil(b"you want to say: ")
io.sendline(b"beaf")

io.interactive()
