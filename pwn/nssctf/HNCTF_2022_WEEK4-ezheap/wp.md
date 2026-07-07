# [HNCTF 2022 WEEK4]ezheap wp

## 题面
压缩包：
```
Archive:  ezheap.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
  1868984  2022-10-12 22:33   libc-2.23.so
    17456  2022-10-24 00:30   ezheap
---------                     -------
  1886440                     2 files

```

带 libc   

## 分析
首先用 glibc-all-in-one 重新 patchelf。  

checksec 看保护全开。  
```
❯ pwn checksec ./ezheap
[*] '/data/project/ctf-repo/pwn/nssctf/HNCTF_2022_WEEK4-ezheap/ezheap'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

ida pro 静态分析：

### main 
``` c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+Ch] [rbp-4h]

  init_env(argc, argv, envp);
  puts("Easy Note.");
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      v3 = getnum();
      if ( v3 != 4 )
        break;
      edit();
    }
    if ( v3 > 4 )
    {
LABEL_13:
      puts("Invalid!");
    }
    else if ( v3 == 3 )
    {
      show();
    }
    else
    {
      if ( v3 > 3 )
        goto LABEL_13;
      if ( v3 == 1 )
      {
        add();
      }
      else
      {
        if ( v3 != 2 )
          goto LABEL_13;
        delete();
      }
    }
  }
}
```

简易记事本。  

### getnum()

```c
int getnum()
{
  char s[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  memset(s, 0, sizeof(s));
  read(0, s, 0x17u);
  return atoi(s);
}
```

### add()

``` c
int add()
{
  __int64 v0; // rbx
  __int64 v1; // rax
  int v3; // [rsp+0h] [rbp-20h]
  int v4; // [rsp+4h] [rbp-1Ch]

  puts("Input your idx:");
  v3 = getnum();
  puts("Size:");
  v4 = getnum();
  if ( (unsigned int)v4 > 0x100 )
  {
    LODWORD(v1) = puts("Invalid!");
  }
  else
  {
    heaplist[v3] = malloc(0x20u);
    if ( !heaplist[v3] )
    {
      puts("Malloc Error!");
      exit(1);
    }
    v0 = heaplist[v3];
    *(_QWORD *)(v0 + 16) = malloc(v4);
    *(_QWORD *)(heaplist[v3] + 32LL) = &puts;
    if ( !*(_QWORD *)(heaplist[v3] + 16LL) )
    {
      puts("Malloc Error!");
      exit(1);
    }
    sizelist[v3] = v4;
    puts("Name: ");
    if ( !(unsigned int)read(0, (void *)heaplist[v3], 0x10u) )
    {
      puts("Something error!");
      exit(1);
    }
    puts("Content:");
    if ( !(unsigned int)read(0, *(void **)(heaplist[v3] + 16LL), sizelist[v3]) )
    {
      puts("Error!");
      exit(1);
    }
    puts("Done!");
    v1 = heaplist[v3];
    *(_DWORD *)(v1 + 24) = 1;
  }
  return v1;
}
```


