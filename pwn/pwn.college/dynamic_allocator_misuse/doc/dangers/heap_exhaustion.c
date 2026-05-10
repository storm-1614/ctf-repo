/*
 * =====================================================================================
 *
 *       Filename:  heap_exhaustion.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  05/10/2026 07:57:39 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  storm-1614
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    int i = 0;
    char *a = "1";
    while (a)
    {
        i++;
        a = malloc(0x00000000);
        printf("Allocated: %p\n", a);
    }
    printf("%d\n", i);
    return EXIT_SUCCESS;
}
