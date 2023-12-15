#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "gmp.h"
#include "xgcd.h"

#include "crt.h"

/* Given (r0, m0) and (r1, m1), compute n such that
   n mod m0 = r0; n mod m1 = r1.  If no such n exists, then this
   function returns 0. Else returns 1.  The moduli m must all be positive.
*/
int CRT2(mpz_t n, mpz_t r0, mpz_t m0, mpz_t r1, mpz_t m1){
    int status = 1;
    int done = 0;
    mpz_t a0, a1, tmp;

    mpz_inits(a0, a1, tmp, NULL);

    /* M[0] = m1, M[1] = m0 */
    if(mpz_invert(a0, m1, m0) == 0){
		/* we want to solve r0+k*m0 = r1 mod m1; i.e.,
		   k*m0 = (r1-r0) mod m1
		*/
		mpz_sub(tmp, r1, r0);
		status = linear_equation_mod(n, m0, tmp, m1);
		if(status){
			mpz_mul(n, n, m0);
			mpz_add(n, n, r0);
		}
		done = 1;
    }
    if(!done){
		mpz_invert(a1, m0, m1);
		mpz_mul(n, a0, m1);     /* a0*M0 */
		mpz_mul(n, n, r0);      /* a0*M0*r0 */
		mpz_mul(tmp, a1, m0);   /* a1*M1 */
		mpz_addmul(n, tmp, r1);
		mpz_mul(tmp, m0, m1);
		mpz_mod(n, n, tmp);
    }
    mpz_clears(a0, a1, tmp, NULL);
    return status;
}

int CRT0(mpz_t n, mpz_t *r, mpz_t *m, int nb_pairs){
    int status = 1;
    mpz_t *M = (mpz_t *)malloc(nb_pairs * sizeof(mpz_t));
    mpz_t *a = (mpz_t *)malloc(nb_pairs * sizeof(mpz_t));
    mpz_t prod;
    int i;

    mpz_set_ui(n, 0);
    mpz_init_set(prod, m[0]);
    for(i = 1; i < nb_pairs; i++)
		mpz_mul(prod, prod, m[i]);
    for(i = 0; i < nb_pairs; i++){
	/* M[i] = prod/m[i] */
		mpz_init(M[i]);
		mpz_divexact(M[i], prod, m[i]);
	/* a[i]*M[i] = 1 mod m[i] */
		mpz_init(a[i]);
		if(mpz_invert(a[i], M[i], m[i]) == 0){
			status = 0;
			break;
		}
    }
    if(status){
		mpz_t tmp;
		mpz_init(tmp);
		for(i = 0; i < nb_pairs; i++){
			mpz_mul(tmp, a[i], M[i]);
			mpz_addmul(n, tmp, r[i]);
		}
		mpz_clear(tmp);
		mpz_mod(n, n, prod);
    }
    mpz_clear(prod);
    for(i = 0; i < nb_pairs; i++){
		mpz_clear(M[i]);
		mpz_clear(a[i]);
    }
    free(M);
    free(a);
    return status;
}

/* Given a list S of pairs (r,m), returns an integer n such that n mod
   m = r for each (r,m) in S.  If no such n exists, then this function
   returns 0. Else returns 1.  The moduli m must all be positive.
*/
int CRT(mpz_t n, mpz_t *r, mpz_t *m, int nb_pairs){
    int status = 1;
    mpz_t R0, R1, M0, M1;
    int i;

    mpz_init_set(R0, r[0]);
    mpz_init_set(M0, m[0]);
    mpz_inits(R1, M1, NULL);
    for(i = 1; i < nb_pairs; i++){
		mpz_set(R1, r[i]);
		mpz_set(M1, m[i]);
		if((status = CRT2(n, R0, M0, R1, M1)) == 0)
			break;
		/* update */
		mpz_set(R0, n);
		mpz_mul(M0, M0, m[i]);
    }
    mpz_clears(R0, R1, M0, M1, NULL);
    return status;
}
