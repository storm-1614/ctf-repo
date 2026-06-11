from pwn import *

# io = process("./ezcmp")

io = remote("node5.anna.nssctf.cn", 27215)

buff = (
    p64(0x144678AADC0E4072)
    + p64(0x84B6E81A4C7EB0E2)
    + p64(0xF426588ABCEE2052)
    + p64(0x0000C8CB2C5E90C2)
)

io.send(buff)
io.interactive()
