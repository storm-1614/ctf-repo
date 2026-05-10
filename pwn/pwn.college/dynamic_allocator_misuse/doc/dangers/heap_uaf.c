/*
 * =====================================================================================
 *
 *       Filename:  heap_uaf.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  05/10/2026 08:08:39 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  storm-1614
 *   Organization:
 *
 * =====================================================================================
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    char *user_input = malloc(8);
    printf("user_input address: %p\n", user_input);


    printf("Name?");
    scanf("%7s", user_input);
    printf("Hello %s!\n", user_input);
    free(user_input);

    long *authenticated = malloc(8);
    printf("authenticated address: %p\n", authenticated);
    *authenticated = 0;
    printf("Passwd?");
    scanf("%7s", user_input);

    if (getuid() == 0 || strcmp(user_input, "hunter2") == 0)
        *authenticated = 1;

    if (*authenticated)
        sendfile(0, open("/flag", 0), 0, 128);
    return EXIT_SUCCESS;
}
