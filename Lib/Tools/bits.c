
/**************************************************************/
/* bits.c                                                     */
/* Author : Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Modifications: Maxime Bombar (maxime.bombar@inria.fr)      */
/* Last modification September 29, 2022 (Maxime Bombar)       */
/**************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "gmp.h"
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
    printf("[ ");
    if(length == 0){
	printf("]");
	return;
    }
    int i, j;
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
    return 1 & (t >> position);
}


uchar setBit(uchar t, int position, uchar value){
    if(value != 0 && value !=1){
        perror("setBit error");
        return 0;
    }
    int mask = 1 << position;
    return ((t & ~mask) | (value << position));
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
    int result = 0, j;
    for(j = 0; j < BYTE_SIZE; j++){
	if((c >> j) % 2 == 1)
	    result++;
    }
    return result;
}


int HammingWeight(buffer_t *buf){
    int result = 0, i;
    uchar *cursor = buf->tab;
    for(i = 0; i < buf->length; i++, cursor++)
	result += HammingWeightByte(*cursor);
    return result;
}


int HammingDistance(buffer_t *buf, buffer_t *buf2){
    if(buf->length != buf2->length){
	perror("[HammingDistance] ERROR : buffers should have the same length\n");
	return 0;
    }
    int result = 0, i;
    uchar *cursor = buf->tab;
    uchar *cursor2 = buf2->tab;
    for(i = 0; i < buf->length; i++, cursor++, cursor2++)
	result += HammingWeightByte(*cursor ^ *cursor2);
    return result;
}



void oneTimePad(buffer_t *encrypted, buffer_t *msg, buffer_t *key) {
    buffer_reset(encrypted);

    uchar *cursor_key = key->tab;
    uchar *cursor_msg = msg->tab;
    int i;
	
    for(i = 0; i < msg->length; i++)
	buffer_append_uchar(encrypted, *(cursor_msg++) ^ *(cursor_key++));
}
