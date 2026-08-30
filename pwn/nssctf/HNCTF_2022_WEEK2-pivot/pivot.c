// gcc -m64   -z noexecstack  -fno-stack-protector -no-pie -z lazy  -o pivot pivot.c
#include<stdio.h>
int vuln()
{
    char buf[0x100];
    read(0,buf,0x120);
    puts("G00DBYE.");
}
int main()
{
    setbuf(stdin,0);
    setbuf(stderr,0);
    setbuf(stdout,0);
    puts("Name:");
    char name[0x20];
    read(0,name,0x98);
    printf("Hello, %s\n",name);
    vuln();
    puts("Over");
    return;
}

