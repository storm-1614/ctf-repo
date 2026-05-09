# What is the heap？

## types of memory
`ELF.text`、`ELF.plt`、`ELF.got`、`ELF.bss`、`ELF.data`、`ELF.rodata`、`stack`……  

动态内存分配：
mmap() 允许我们动态内存分配释放，但是分配大小不灵活（因为内存页），而且速度慢。  

## heap 做什么
由 ptmalloc/glibc 实现的 heap 提供两个函数：

`malloc()`  分配内存  
`free()`  释放内存  

还有一些辅助函数：  
`realloc()` 改变分配内存的大小  
`calloc()` 分配内存并置 0   

## heap 的实现
ptmalloc 不使用 mmap。  
使用数据段(data segment)  
通过 brk 和 sbrk 系统调用进行扩展。  

## strace 追溯系统调用
``` c
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char msg[] = "About to malloc()!";

int main(int argc, char *argv[])
{
    write(1, msg, strlen(msg));
    malloc(16);
    return EXIT_SUCCESS;
}
```

编译并用 strace 分析系统调用：  
```
write(1, "About to malloc()!", 18About to malloc()!)      = 18
brk(NULL)                               = 0x55fe07f30000
brk(0x55fe07f51000)                     = 0x55fe07f51000
exit_group(0)                           = ?
+++ exited with 0 +++
```

从 write 被调用之后，开始到 malloc(16) 的系统调用，显示了两次 brk 调用。  
两次调用的地址之差为 `0x2100` 也就是 21 页内存。  

 ## heap 的问题
1. 被程序员错误的使用  
忘记释放内存，忘记指向数据的内存，忘记该地址指向的内存已经被释放。  
2. 因为库的效率优化留下了一些安全问题。  

如何检查到问题：  
- valgrind 检查未被使用的堆  
- glibc 的技巧
    * `export MALLOC_CHECK = 1`
    * `export MALLOC_PERTURB = 1`
    * `export MALLOC_MMAP_THRESHOLD_ = 1`
