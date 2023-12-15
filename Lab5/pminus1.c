#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include "gmp.h"
#include "utils.h"
#include "pminus1.h"

#define DEBUG 0

static void ReadDifFile(mpz_t p, FILE *file){
    mpz_t q;
    int dp;

    /* we have to read file while read_p <= p */
    mpz_init_set_ui(q, 1);
    while(fscanf(file, "%d", &dp) != EOF){
	mpz_add_ui(q, q, dp << 1);
	if(mpz_cmp(q, p) > 0)
	    break;
    }
    mpz_set(p, q);
    mpz_clear(q);
}

/* Starting from nextprime(p) >= p+1. 
   On unsuccessful exit, p is the smallest prime > bound1.
*/
int PollardPminus1Step1(mpz_t factor, const mpz_t N, long bound1, FILE* ficdp,
			mpz_t b, mpz_t p){
    int status=FACTOR_ERROR;
     mpz_t R, gcdResult;
    mpz_inits(R, gcdResult, NULL);

    mpz_set_ui(R, 1);
    mpz_t i;
    mpz_init(i);
    for (mpz_set_ui(i, 2); mpz_cmp_ui(i, bound1) <= 0; mpz_nextprime(i, i)) {
        mpz_mul(R, R, i);
    }

    mpz_mul(b, b, R);
    mpz_sub_ui(b, b, 1);

    mpz_gcd(gcdResult, b, N);

    if (mpz_cmp_ui(gcdResult, 1) > 0) {
        mpz_set(factor, gcdResult);
        status = FACTOR_FOUND;
    }

    mpz_set(p, i);

    mpz_clears(R, gcdResult, i, NULL);
    return status;
}

int PollardPminus1Step2(mpz_t factor, const mpz_t N, long bound2, FILE* ficdp,
			mpz_t b, mpz_t p){
    mpz_t bm1;
    unsigned long d;
    int dp, status = FACTOR_ERROR;
    int B = (int)log((double)bound2);
    B = B * B;

    mpz_init(bm1);
    ReadDifFile(p, ficdp);
    /* Precomputations */
    mpz_t* precomputations = (mpz_t*)malloc(B * sizeof(mpz_t));
    mpz_t* cursor = precomputations;
    int i;
		
    for(i = 0; i < B; i++, cursor++){
	mpz_init(*cursor);
	mpz_powm_ui(*cursor, b, i, N);
    }
#if DEBUG >= 1
    printf("# Precomputation of phase 2 done.\n");
#endif
    mpz_powm(b, b, p, N);
    while(mpz_cmp_ui(p, bound2) <= 0){
	mpz_sub_ui(bm1, b, 1);
	mpz_gcd(factor, bm1, N);
	if(mpz_cmp_ui(factor, 1) > 0){
	    status = FACTOR_FOUND;
	    break;
	}
	fscanf(ficdp, "%d", &dp);
	d = dp << 1;
	mpz_add_ui(p, p, d);		
	if(d < B){
	    mpz_mul(b, b, precomputations[d]);
	    mpz_mod(b, b, N);
	}
	else{
	    printf("Cramer's rule Failed!\n");
	    printf("WRITE A PAPER!!!\n");
	    return 1;
	}
    }			
    cursor = precomputations;
    for(i = 0; i < B; i++, cursor++){
        mpz_clear(*cursor);
    }
    free(precomputations);
    mpz_clear(bm1);
    if (status != FACTOR_FOUND) {
        status = FACTOR_NOT_FOUND;
    }
    return status;
}

int PollardPminus1(factor_t* res, int *nf, const mpz_t N,
		   long bound1, long bound2, FILE* ficdp){

}
