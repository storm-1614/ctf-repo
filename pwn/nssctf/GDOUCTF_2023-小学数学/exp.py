from pwn import *

context(log_level = 'debug')
io = remote("node4.anna.nssctf.cn", 29066)

io.sendline()
for i in range(1, 301):
    io.recvuntil(f"Round: {i}\n".encode())
    question = io.recvuntil(b"=")[:-2].decode()
    if '-' in question:
        answer = eval(question.replace('-', '+'))
    elif 'x' in question:
        answer = eval(question.replace('x', '-'))
    elif '//' in question:
        answer = eval(question.replace('//', '*'))
    elif '+' in question:
        answer = eval(question.replace('+', '%'))
    elif '%' in question:
        answer = eval(question.replace('%', '//'))
    
    io.sendline(str(answer).encode())
io.interactive()
