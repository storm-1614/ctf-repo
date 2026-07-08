/*
 * =====================================================================================
 *
 *       Filename:  heap_size.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  06/03/2026 08:20:47 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);

    // allocate our chunks
    int size = strtoll(argv[1], 0, 0);
    unsigned long *a = malloc(size);
    unsigned long *b = malloc(size);

    free(a); // free the earlier one
    malloc(size * 2); // force the freed chunk to be actually processed
    malloc(16);

    printf("a_chunk: %#p\n", (a-2));
    printf("b_chunk: %#p\n", (b-2));
    puts("");
    printf("a_chunk->prev_size: %#llx\n", *(a-2));
    printf("a_chunk->size: %#llx\n", *(a-1));
    printf("b_chunk->prev_size: %#llx\n", *(b-2));
    printf("b_chunk->size: %#llx\n", *(b-1));

    return EXIT_SUCCESS;
}

