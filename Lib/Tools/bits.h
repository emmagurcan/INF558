#ifndef __FRS__BITS

/**************************************************************/
/* bits.h                                                     */
/* Author : Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Last modification September 20, 2018                       */
/**************************************************************/


/* Defintions */
#define BYTE_SIZE 8
typedef unsigned char uchar;
typedef unsigned int uint;

/* Functions */
void printDec(uchar* u, int length);
void printHexa(uchar* u, int length);
void printBin(uchar* u, int length);
uchar getBit(uchar t, int position);
uchar setBit(uchar t, int position, uchar value);
void buffer_flip_bit(buffer_t *out, buffer_t *in, int position);
int HammingWeightByte(uchar c);
int HammingWeight(buffer_t *buf);
int HammingDistance(buffer_t *buf, buffer_t *buf2);
void oneTimePad(buffer_t *encrypted, buffer_t *msg, buffer_t *key);

#define __FRS__BITS
#endif
