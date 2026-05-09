/*
 * =====================================================================================
 *
 *       Filename:  heap_datasegment.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  05/09/2026 10:30:20 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  storm-1614
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sendfile.h>

char msg[] = "About to malloc()!";

int main(int argc, char *argv[])
{
    write(1, msg, strlen(msg));
    int maps = open("/proc/self/maps", O_RDONLY);
    char buf[4096];
    ssize_t n;
    while ((n = read(maps, buf, sizeof(buf))) > 0) {
        write(1, buf, n);
    }
    close(maps);
    malloc(16);
    maps = open("/proc/self/maps", O_RDONLY);
    while ((n = read(maps, buf, sizeof(buf))) > 0) {
        write(1, buf, n);
    }
    close(maps);
    malloc(0x10000);
    malloc(0x10000);
    malloc(0x10000);
    maps = open("/proc/self/maps", O_RDONLY);
    while ((n = read(maps, buf, sizeof(buf))) > 0) {
        write(1, buf, n);
    }
    close(maps);

    return EXIT_SUCCESS;
}
