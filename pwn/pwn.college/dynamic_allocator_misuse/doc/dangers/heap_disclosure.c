/*
 * =====================================================================================
 *
 *       Filename:  heap_disclosure.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  05/10/2026 08:24:29 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  strom-1614
 *   Organization:  
 *
 * =====================================================================================
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char *password = malloc(8);
    char *name = malloc(8);

    printf("Password? ");
    scanf("%7s", password);
    assert(strcmp(password, "hunter2") == 0);
    free(password);

    printf("Name? ");
    scanf("%7s", name);
    printf("Hello %s!\n", name);
    free(name);

    printf("Goodbye, %s!\n", name);
    return EXIT_SUCCESS;
}
