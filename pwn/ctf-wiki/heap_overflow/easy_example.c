/*
 * 调用 malloc 分配一块堆上的内存，之后向这个堆块中写入一个字符串，如果输入的字符串过长会导致溢出 chunk 的区域并覆盖到其后的 top chunk 之中 (实际上 puts 内部会调用 malloc 分配堆内存，覆盖到的可能并不是 top chunk)。 
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) 
{
  char *chunk;
  chunk=malloc(24);
  puts("Get input:");
  gets(chunk);
  return 0;
}

