/**************************************************************/
/* testEx3.c                                                  */
/* Author : Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Last modification September 25, 2018                       */
/**************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "buffer.h"
#include "bits.h"
#include "LFSR.h"



void test(uchar a){
    printf("\n************ Testing exhaustive search (Bourrinate) ***************\n");
    //1. Initialise
    buffer_t IV1, trans1, stream1, searched_IV1;
    buffer_init(&IV1, 3);
    buffer_init(&trans1, 3);
    buffer_init(&stream1, 32);
    buffer_init(&searched_IV1, 3);

    // 2. Fills in registers
    // Uncomment below if you already ran succesfully this test.
    buffer_append_uchar(&IV1, a);
    buffer_append_uchar(&IV1, 129);
    buffer_append_uchar(&IV1, 223);
    buffer_append_uchar(&trans1, 221);
    buffer_append_uchar(&trans1, 50);
    buffer_append_uchar(&trans1, 237);

    // 3. Compute LFSR Stream
    LFSR(&stream1, &trans1, &IV1, 32);

    // 4. Bourrinate!!
    printf("\nBrute force search in progress. This may take some time....\n");
    bourrinate_IV(&searched_IV1, &trans1, &stream1);

    // 5. Compare
    if(buffer_equality(&IV1, &searched_IV1)){
	printf("\nIV found : ");
	printDec(searched_IV1.tab, searched_IV1.length);
	printf("\n\n[Bourrinate success, OK]\n\n");
    }
    else
	printf("\n\n[Failed, you should better bourrinate]\n\n");
	
    // 6. Free Memory
    buffer_clear(&IV1);
    buffer_clear(&trans1);
    buffer_clear(&stream1);
    buffer_clear(&searched_IV1);
}



void usage(char *s){
    fprintf(stderr, "Usage: %s <First byte of the key>\n", s);
}



int main(int argc, char *argv[]){
    if(argc == 1){
	usage(argv[0]);
	return 0;
    }
    uchar a = (uchar)atoi(argv[1]);
    test(a);
    return 0;
}
