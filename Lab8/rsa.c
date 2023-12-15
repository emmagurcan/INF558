#include <stdio.h>
#include <stdlib.h>

#include "gmp.h"
#include "rsa.h"

#define DEBUG 0

int is_valid_key(mpz_t p, mpz_t q, mpz_t e, mpz_t d, int nlen){
	if(nlen <= 200){
		perror("[is_valid_key] : nlen should be > 200.\n");
		return 0;
	}

	// p, q should be prime
	if(!mpz_probab_prime_p(p, 25) || ! mpz_probab_prime_p(q, 25)){
#if DEBUG
		printf("p, q should be prime.  ");
#endif		
		return 0;
	}

	mpz_t lambda, pm1, qm1, pmq, ed, g, bound, bound1, bound2;
	mpz_inits(lambda, pm1, qm1, pmq, ed, g, bound, bound1, bound2, NULL);

	// e should be odd
	if(mpz_divisible_ui_p(e, 2)){
#if DEBUG
		printf("e should be odd.  ");
#endif		
		return 0;
	}

	
	// e should be prime to lambda
	mpz_sub_ui(pm1, p, 1);
	mpz_sub_ui(qm1, q, 1);
	mpz_lcm(lambda, pm1, qm1);
	mpz_gcd(g, e, lambda);	
	if(mpz_cmp_ui(g, 1) != 0){
#if DEBUG
		gmp_printf("e should be prime to lambda. gcd(e, lambda) = %Zd.\n", g);
#endif		
		return 0;
	}	
	
	// Bounds on e.
	size_t size_e = mpz_sizeinbase(e, 2);
	if(size_e < 16 || size_e > 256){
		return 0;
	}
	
	
	// ed = 1 mod lambda
	mpz_mul(ed, e, d);
	mpz_mod(ed, ed, lambda);
	if(mpz_cmp_ui(ed, 1) != 0){
#if DEBUG
		printf("ed should be congruent to 1 modulo lambda.   ");
#endif		
		return 0;
	}

	
	// p, q should be large enough
	mpf_t b_f, tmp_f;
	mpf_inits(b_f, tmp_f, NULL);
	mpf_sqrt_ui(b_f, 2);
	mpf_set_ui(tmp_f, 2);
	mpf_pow_ui(tmp_f, tmp_f, nlen/2 - 1);
	mpf_mul(b_f, b_f, tmp_f);
	mpz_set_f(bound1, b_f);	
	if(mpz_cmp(p, bound1) <= 0 || mpz_cmp(q, bound1) <= 0){
#if DEBUG
		printf("p or q is too small.  ");
#endif
		return 0;
	}
		
	// p, q should not be too close to each other
	mpz_ui_pow_ui(bound2, 2, nlen/2 - 100);
	mpz_sub(pmq, p, q);
	if(mpz_cmpabs(pmq, bound2) <= 0){
#if DEBUG
		printf("p and q are too close.  ");
#endif
		return 0;
	}

	
	mpf_clears(b_f, tmp_f, NULL);
	mpz_clears(lambda, pm1, qm1, pmq, ed, g, bound, bound1, bound2, NULL);
	
	return 1;
}


void RSA_weak_generate_key(mpz_t p, mpz_t q, mpz_t e, mpz_t d, int nlen,
					  gmp_randstate_t state){
	mpz_t bound, bound1, g, lambda, pm1, qm1;
	mpz_inits(bound, bound1, g, lambda, pm1, qm1, NULL);
	mpf_t b_f, tmp_f;
	mpf_inits(b_f, tmp_f, NULL);
	mpf_sqrt_ui(b_f, 2);
	mpf_set_ui(tmp_f, 2);
	mpf_pow_ui(tmp_f, tmp_f, nlen/2 - 1);
	mpf_mul(b_f, b_f, tmp_f);
	mpz_set_f(bound, b_f);	
	
	do{
		mpz_urandomb(p, state, nlen/2);
		mpz_nextprime(p, p);
    } while(mpz_cmp(p, bound) < 0);
	mpz_sub_ui(pm1, p, 1);

	
	do{
		mpz_urandomb(q, state, nlen/2);
		mpz_nextprime(q, q);
    } while(mpz_cmp(q, bound) < 0);
	mpz_sub_ui(qm1, q, 1);
	mpz_lcm(lambda, pm1, qm1);
	
	mpz_set_ui(bound1, 1 << 16);

	do{
		do{
			mpz_urandomb(e, state, 256);
		}while(mpz_cmp(e, bound1) <= 0);
		mpz_gcd(g, e, lambda);
	}while(mpz_cmp_ui(g, 1) != 0);

	mpz_invert(d, e, lambda);
	
	mpf_clears(b_f, tmp_f, NULL);
	mpz_clears(bound, bound1, g, lambda, pm1, qm1, NULL);
}


void RSA_generate_key(mpz_t N, mpz_t p, mpz_t q, mpz_t e, mpz_t d,
					  int nlen, gmp_randstate_t state){
	do{
		RSA_weak_generate_key(p, q, e, d, nlen, state);
	}while(!is_valid_key(p, q, e, d, nlen));
	mpz_mul(N, p, q);
}



void RSA_encrypt(mpz_t cipher, mpz_t msg, mpz_t N, mpz_t e){
    mpz_powm(cipher, msg, e, N);
}

void RSA_decrypt(mpz_t msg, mpz_t cipher, mpz_t N, mpz_t d){
    mpz_powm(msg, cipher, d, N);
}



void RSA_dummy_generate_key(mpz_t N, mpz_t e, int nlen,
							gmp_randstate_t state){
	
	mpz_t g, p, q, lambda, pm1, qm1;
	mpz_inits(g, p, q, lambda, pm1, qm1, NULL);

	do{
		mpz_urandomb(p, state, nlen/2);
		mpz_nextprime(p, p);		
		do{
			mpz_urandomb(q, state, nlen/2);
			mpz_nextprime(q, q);
		}while(mpz_cmp(p, q) == 0);
		
		mpz_sub_ui(pm1, p, 1);
		mpz_sub_ui(qm1, q, 1);
		mpz_lcm(lambda, pm1, qm1);
		mpz_gcd(g, e, lambda);
		mpz_mul(N, p, q);
	
	}while(mpz_cmp_ui(g, 1) != 0 || mpz_sizeinbase(N, 2) < nlen);
#if DEBUG
	gmp_printf("[RSA_dummy_generate_key] N = %Zd, size : %ld\n",
			   N, mpz_sizeinbase(N, 2));
#endif
	
	mpz_clears(g, p, q, lambda, pm1, qm1, NULL);
}
