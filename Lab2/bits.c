/**************************************************************/
/* bits.c                                                     */
/* Author : Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Modifications: Maxime Bombar (maxime.bombar@inria.fr)      */
/* Last modification September 29, 2022 (Maxime Bombar)       */
/**************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "buffer.h"
#include "bits.h"

void printDec(uchar* u, int length){
    int i;
    
    printf("[");
    if(length == 0){
	printf("]");
	return;
    }
    for(i  = 0; i < length - 1; i++){
	printf("%d, ", *(u++));
    }
    printf("%d]", *u);
}


void printHexa(uchar* u, int length){
    int i;
    
    printf("[");
    if(length == 0){
	printf("]");
	return;
    }
    for(i  = 0; i < length - 1; i++){
	if(*u < 0x10)
	    printf("0x0%x, ", *(u++));
	else
	    printf("0x%x, ", *(u++));
    }
    if(*u < 0x10)
	printf("0x0%x]", *(u++));
    else
	printf("0x%x]", *(u++));
}


void printBin(uchar* u, int length){
    int i, j;

    printf("[ ");
    if(length == 0){
	printf("]");
	return;
    }
    for(i  = 0; i < length - 1; i++){
	for(j = BYTE_SIZE - 1; j >= 0; j--){
	    printf("%d ", (*u >> j) & 1);
	}
	printf("| ");
	u++;
    }
    for(j = BYTE_SIZE - 1; j >= 0 ; j--){
	printf("%d ", (*u >> j) & 1);
    }
    printf("]");
}



uchar getBit(uchar t, int position){
    return (t >> position) & 1;
}

uchar setBit(uchar t, int position, uchar value){
    uchar t_cleared = t & ~(1 << position);
    return t_cleared | (value << position);
}

void buffer_flip_bit(buffer_t *out, buffer_t *in, int position){
    /* Flips the bit number position of buffer in and
       writes the result in buffer out. 
       position should be less than 8 * in->length */

    buffer_reset(out);
    if(position < 0 || position > BYTE_SIZE * in->length){
	perror("[buffer_flip_bit] : Position should be in range [0, 8 * in->length[\n");
	return;
    }
    int byte_position = position / BYTE_SIZE;
    int bit_position = position % BYTE_SIZE, i;
    uchar *cursor = in->tab;
    for(i = 0; i < in->length; i++, cursor++){
	if(i == byte_position){
	    uchar a = setBit(*cursor, bit_position,
			     getBit(*cursor, bit_position) ? 0 : 1);
	    buffer_append_uchar(out, a);
	}
	else
	    buffer_append_uchar(out, *cursor);
    }
}



int HammingWeightByte(uchar c){
    int cntr = 0;
    while (c != 0) {
        uchar b = getBit(c, 0);
        if (b == 1){
            cntr++;
        }
        c = c >> 1;
    }
    return cntr;
}


int HammingWeight(buffer_t *buf){
    int cntr = 0;
    int length = buf->length;
    uchar *tab = buf->tab;
    for (int i = 0; i < length; i++){
        cntr = cntr + HammingWeightByte(*tab);
        tab++;
    }
    return cntr;
}


void oneTimePad(buffer_t *encrypted, buffer_t *msg, buffer_t *key) {
/* to be filled in */
    buffer_reset(encrypted);

/* to be filled in */
}