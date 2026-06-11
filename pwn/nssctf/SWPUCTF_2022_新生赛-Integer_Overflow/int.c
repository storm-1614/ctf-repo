/*
 * =====================================================================================
 *
 *       Filename:  int.c
 *
 *    Description: Test integer overflow. 
 *
 *        Version:  1.0
 *        Created:  06/07/2026 08:45:14 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  storm-1614
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    size_t target = -1;
    printf("%u", target);
    return EXIT_SUCCESS;
}

