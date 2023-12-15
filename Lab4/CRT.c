#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "gmp.h"

#include "xgcd.h"
#include "CRT.h"

/* Given (r0, m0) and (r1, m1), compute n such that
   n mod m0 = r0; n mod m1 = r1.  If no such n exists, then this
   function returns 0. Else returns 1.  The moduli m must all be positive.
*/
int CRT2(mpz_t n, mpz_t r0, mpz_t m0, mpz_t r1, mpz_t m1){
    int status = -42;
/* to be filled in */
    return status;
}

/* to be filled in */

/* Given a list S of pairs (r,m), returns an integer n such that n mod
   m = r for each (r,m) in S.  If no such n exists, then this function
   returns 0. Else returns 1.  The moduli m must all be positive.
*/
int CRT(mpz_t n, mpz_t *r, mpz_t *m, int nb_pairs){
    int status = -42;
/* to be filled in */
    return status;
}
