#include <stdio.h>
#include <assert.h>

#include "gmp.h"

#include "xgcd.h"

#define DEBUG 0


/* If bound == NULL: g <- gcd(a, b) and a*u+b*v = g.
   If bound != NULL, stop as soon as r_{i+1} <= bound;
   g <- r_{i+1} and a*u+b*v = g.
*/
void XGCD_aux(mpz_t g, mpz_t u, mpz_t v, mpz_t a, mpz_t b, mpz_t bound){
    mpz_t ri, rip1, u0, u1, v0, v1, r, q, tmp;
    int i;

    mpz_init_set_si(u1, 1);
    mpz_init_set_si(v1, 0);
    mpz_init_set_si(u0, 0);
    mpz_init_set_si(v0, 1);
    mpz_init_set(ri, a);   /* a = r_{-1} = u1*a+v1*b */
    mpz_init_set(rip1, b); /* b = r_0    = u0*a+v0*b */
    mpz_inits(tmp, q, r, NULL);
    i = -2;
    while(mpz_sgn(rip1) != 0){
	if((bound != NULL) && mpz_cmp(rip1, bound) <= 0)
	    /* r_{i+1} <= bound */
	    break;
	i++;
	mpz_tdiv_qr(q, r, ri, rip1);
#if DEBUG >= 1
	printf("r_{%d}:=", i); mpz_out_str(stdout, 10, ri); printf(";\n");
	printf("r%d:=", i+1); mpz_out_str(stdout, 10, rip1); printf(";\n");
	printf("q%d:=", i+2); mpz_out_str(stdout, 10, q); printf(";\n");
	printf("r%d:=", i+2); mpz_out_str(stdout, 10, r); printf(";\n");
#endif	
	/* u_{i+2} = u_i - q_{i+2} u_{i+1} */
	mpz_mul(tmp, q, u0);   /* q_{i+2} u_{i+1} */
	mpz_sub(tmp, u1, tmp); /* u_i - q_{i+2} u_{i+1} */
	mpz_swap(u1, u0);
	mpz_swap(u0, tmp);
	/* v_{i+2} = v_i - q_{i+2} v_{i+1} */
	mpz_mul(tmp, q, v0);
	mpz_sub(tmp, v1, tmp);
	mpz_swap(v1, v0);
	mpz_swap(v0, tmp);
#if DEBUG >= 1
	printf("u%d:=", i+2); mpz_out_str(stdout, 10, u0); printf(";\n");
	printf("v%d:=", i+2); mpz_out_str(stdout, 10, v0); printf(";\n");
#endif
	/* useful check: r = r_{i+2} = a*u_{i+2}+b*v_{i+2} */
	mpz_mul(tmp, u0, a);
	mpz_addmul(tmp, v0, b);
	assert(mpz_cmp(tmp, r) == 0);
	/* update */
	mpz_swap(ri, rip1);
	mpz_swap(rip1, r);
    }
    if(bound == NULL)
	mpz_set(g, ri);
    else
	mpz_set(g, rip1);
    mpz_set(u, u0);
    mpz_set(v, v0);
    /* clear variables */
    mpz_clears(u1, v1, u0, v0, NULL);
    mpz_clears(tmp, q, r, ri, rip1, NULL);
}

/* compute g, u and v s.t. a*u+b*v = g = gcd(a, b) */
void XGCD(mpz_t g, mpz_t u, mpz_t v, mpz_t a, mpz_t b){
    XGCD_aux(g, u, v, a, b, NULL);
}

/* Find s and t such that a = s/t mod m, where s, t <= sqrt(m).
   We need gcd(a, m) = 1.
   Make sure t > 0.
   Explain:
   Rewrite a*t = s mod m and use partial euclid: a*u+m*v = s.
 */
void rational_reconstruction(mpz_t s, mpz_t t, mpz_t a, mpz_t m){
    mpz_t bound, v;

    mpz_inits(v, bound, NULL);
    mpz_sqrt(bound, m);
    XGCD_aux(s, v, t, m, a, bound);
    if(mpz_sgn(t) == -1){
	mpz_neg(t, t);
	mpz_neg(s, s);
    }
    mpz_clears(v, bound, NULL);
}

/* Solve a*x=b mod m if possible. 
   Explain:
*/
int linear_equation_mod(mpz_t x, mpz_t a, mpz_t b, mpz_t m){
    int status = 1;
    mpz_t tmp;

    mpz_init(tmp);
    if(mpz_invert(tmp, a, m) != 0){
	/* normal case: a invertible mod m */
	mpz_mul(x, tmp, b);
	mpz_mod(x, x, m);
    }
    else{
	mpz_t g;

	mpz_init(g);
	mpz_gcd(g, a, m);
	/* g | a and g | m => b should be disible by g */
	mpz_mod(tmp, b, g);
	if(mpz_sgn(tmp) != 0)
	    /* no solution */
	    status = 0;
	else{
	    /* a = g*a', m = g*m', b = g*b' */
	    mpz_t aa, bb, mm;

	    mpz_inits(aa, bb, mm, NULL);
	    mpz_divexact(aa, a, g);
	    mpz_divexact(bb, b, g);
	    mpz_divexact(mm, m, g);
	    mpz_invert(tmp, aa, mm);
	    mpz_mul(x, tmp, bb);
	    mpz_mod(x, x, mm);
	    mpz_clears(aa, bb, mm, NULL);
	}
	mpz_clear(g);
    }
    mpz_clear(tmp);
    return status;
}
 
