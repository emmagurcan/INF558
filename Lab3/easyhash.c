#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "buffer.h"
#include "hashtable.h"
#include "easyhash.h"

unsigned int easy_hash(buffer_t *buf){
    uchar a = 0xa0, b = 0xb1, c = 0x11, d = 0x4d;
    int i;

    for(i = 0; i < buf->length; i++){
	a ^= buf->tab[i];
	b = b ^ a ^ 0x55;
        c = b ^ 0x94;
        d = c ^ buf->tab[i] ^ 0x74;
    }
    return (((unsigned int)d) << 24) | (((unsigned int)c) << 16)
	| (((unsigned int)a) << 8) | b;
}

