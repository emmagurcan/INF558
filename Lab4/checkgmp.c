#include <stdio.h>

#include "gmp.h"

int main(void){
    mpz_t a, b, p;

    printf("Hi, this is version %d of GMP\n", __GNU_MP_RELEASE);
    mpz_init(a);		 /* initialize variables */
    mpz_init(b);
    mpz_init(p);
    mpz_set_si(a, 32187690);	 /* assign variables */
    mpz_set_str(b, "383552808581", 0);
    mpz_mul(p, a, b);		 /* generate product */
    mpz_out_str(stdout, 10, p); /* print number without newline */
    puts("");			 /* print newline */
    mpz_clear(a);		 /* clear out variables */
    mpz_clear(b);
    mpz_clear(p);
    return 0;
}
