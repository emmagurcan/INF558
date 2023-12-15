/**************************************************************/
/* collisions.c                                               */
/* Author : Matthieu Lequesne                                 */
/* Last modification October 5, 2023                          */
/**************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include "random.h"
#include "hashtable.h"
#include "easyhash.h"
#include "collisions.h"

int find_collisions(int imax){
    hash_table H;
    buffer_t buf; // The current buffer you work on
    buffer_t *tab = malloc(imax * sizeof(buffer_t)); // A table to store buffers you treated
    int status = 1;
    H = hash_init(imax);
    buffer_init(&buf, 4);
        for (int i = 0; i < imax; i++) {
            buffer_random(&buf, 4);
            unsigned int h = easy_hash(&buf);
            hash_pair kv;
            int result = hash_get(&kv, H, h);

            if (result == HASH_NOT_FOUND) {
                hash_put(H, h, i);
            } else if (result == HASH_FOUND) {
                print_collision(&tab[kv.v], &buf);
            }
            buffer_clone(&tab[i], &buf);
        
    }
    status--;
    buffer_clear(&buf);
    hash_clear(H);
    free(tab);
    return status;
}

void print_collision(buffer_t *value1, buffer_t *value2){
    unsigned long h1 = (unsigned long) easy_hash(value1);
    unsigned long h2 = (unsigned long) easy_hash(value2);

    if (h1!=h2){
        perror("[print_collision] Hash values are not equal!");
        return;
    }

    if (buffer_equality(value1, value2) != 0){
        perror("[print_collision] Buffer values are equal!");
        return;
    }

    printf("collision found: \n");
    printf("h(");
    buffer_print_int(stdout, value1);
    printf(") = %ld\n", h1);
    printf("h(");
    buffer_print_int(stdout, value2);
    printf(") = %ld\n\n", h2);
}
