#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gmp.h"
#include "buffer.h"
#include "bits.h"
#include "random.h"
#include "sign.h"

#define NAME_MAX_LENGTH 128
#define DEBUG 0

void keygen(char* prefix, mpz_t e, int size){
    /* Names of the files */
    char pk_name[NAME_MAX_LENGTH];
    char sk_name[NAME_MAX_LENGTH];
	
    strcpy(pk_name, prefix);
    strcpy(sk_name, prefix);
    strcat(pk_name, "_pub.txt");
    strcat(sk_name, "_sec.txt");

    /* Randomness */
    gmp_randstate_t state;
    gmp_randinit_default(state);
#if DEBUG
    gmp_randseed_ui(state, 42);
#else
    gmp_randseed_ui(state, random_seed());
#endif

    /* Key generation */
    RSA_generate_key_files(pk_name, sk_name, size, state);
}

void usage(char *s){
    fprintf(stderr, "Usage: %s <bit size> <key_prefix>", s);
    fprintf(stderr, " <e (in base 10)>\nDefault e = 3.\n\n");
}

int main(int argc, char* argv[]){
    if(argc <= 3){
	usage(argv[0]);
	return 0;
    }
    mpz_t e;
    mpz_init(e);
    
    if(argc <= 3)
	mpz_set_ui(e, 3);
    else
	mpz_set_str(e, argv[3], 10);

    keygen(argv[2], e, atoi(argv[1]));
	
    mpz_clear(e);
    return 0;
}
