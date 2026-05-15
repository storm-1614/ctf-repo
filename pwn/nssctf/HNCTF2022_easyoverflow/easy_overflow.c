#include<stdio.h>
int main()
{
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);
    puts("Input something");
    char name[30];
    int number=0;
    gets(name);
    if(number!=0){
        puts("You win.");
        system("cat flag");
    }
    return 0;
}
