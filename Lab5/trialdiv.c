#include <stdlib.h>
#include <stdio.h>

#include "gmp.h"
#include "utils.h"
#include "trialdiv.h"

/* OUTPUT: 1 if factorization finished. */
int trialDivision(factor_t* factors, int *nf, mpz_t cof, const mpz_t N,
		  const long bound, uint length, FILE* ficdp){
    int status = FACTOR_NOT_FOUND;
    mpz_t bounded, i, e, temp;
    mpz_inits(bounded, i, e, temp, NULL);
    mpz_sqrt(bounded, N);
    
    mpz_set_ui(bounded, (unsigned int) bound);
    int j = 0;

    for (mpz_set_ui(i, 0); mpz_cmp(i, bounded) < 0; mpz_add_ui(i, i, 1)){
        printf("%s\n", "made it");
        mpz_mod(temp, N, i);
        if (mpz_cmp(temp, 0) == 0){
            status = FACTOR_FOUND;
            mpz_div(e, N, i);
            AddFactor(factors + j, i, mpz_get_ui(e), status);
            j++;
        }
    }
    mpz_clears(bounded, i, e, NULL);
    return status;
}
