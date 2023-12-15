#include <stdio.h>
#include <stdlib.h>

#include "utilities.h"

#include "gmp.h"
#include "crt.h"
#include "rsa.h"

#define DEBUG 0


int is_valid_key(mpz_t p, mpz_t q, mpz_t e, mpz_t d, int nlen, int sec){
    mpz_t lambda, pm1, qm1, pmq, ed, g, bound1, bound2;
    mpz_inits(lambda, pm1, qm1, pmq, ed, g, bound1, bound2, NULL);

    mpz_sub_ui(pm1, p, 1);
    mpz_sub_ui(qm1, q, 1);
    mpz_lcm(lambda, pm1, qm1);

    int status = 1;
    // p, q should be prime
    if(!mpz_probab_prime_p(p, 25) || ! mpz_probab_prime_p(q, 25)){
#if DEBUG
      printf("[is_valid_key] : p, q should be prime.  ");
#endif
      status = 0;
      goto end_valid;
    }

    // e should be odd
    if(mpz_divisible_ui_p(e, 2)){
#if DEBUG
	  printf("[is_valid_key] : e should be odd.  ");
#endif
      status = 0;
      goto end_valid;
    }

    // e should be prime to lambda
    mpz_gcd(g, e, lambda);
    if(mpz_cmp_ui(g, 1) != 0){
#if DEBUG
      printf("[is_valid_key] : e should be prime to lambda. ");
#if DEBUG >= 2
	  gmp_printf("gcd(e, lambda) = %Zd.  ", g);
#endif
#endif
	  status = 0;
      goto end_valid;
    }
    // Bounds on e.
    size_t size_e = mpz_sizeinbase(e, 2);
    if(size_e < 16){
#if DEBUG
      printf("[is_valid_key] : e is too small.   ");
#endif
      status = 0;
      goto end_valid;
    }
    if(size_e > 256){
#if DEBUG
      printf("[is_valid_key] : e is too large.   ");
#endif
      status=0;
      goto end_valid;
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
	printf("[is_valid_key] : p or q is too small.  ");
#endif
	status = 0;
    }
    mpz_clear(bound1);
    mpf_clears(b_f, tmp_f, NULL);
    if(status == 0)
	  goto end_valid;

    // p, q should not be too close to each other
    mpz_inits(bound2, pmq, NULL);
    mpz_ui_pow_ui(bound2, 2, nlen/2 - sec);
    mpz_sub(pmq, p, q);
    if(mpz_cmpabs(pmq, bound2) <= 0){
#if DEBUG
	  printf("[is_valid_key] : p and q are too close.  ");
#endif
      status = 0;
    }
    mpz_clears(bound2, pmq, NULL);
    if(status == 0)
	  goto end_valid;

    // ed = 1 mod lambda
    mpz_mul(ed, e, d);
    mpz_mod(ed, ed, lambda);
    if(mpz_cmp_ui(ed, 1) != 0){
#if DEBUG
	  printf("[is_valid_key] : ed should be");
	  printf(" congruent to 1 modulo lambda.   ");
#endif
	  status = 0;
      goto end_valid;
    }
 end_valid:
    mpz_clears(lambda, pm1, qm1, ed, g, NULL);

    return status;
}


int RSA_weak_generate_key(mpz_t p, mpz_t q, mpz_t e, mpz_t d, int nlen,
			   gmp_randstate_t state){
    mpz_t p1, q1, N, phi, one, g, b;
    mpz_inits(p1, q1, N, phi, one, g, b, NULL);
    mpz_set_ui(one, 1);
    mpz_urandomb(q, state, nlen/2);
    mpz_nextprime(q, q);
    mpz_urandomb(p, state, nlen/2);
    mpz_nextprime(p, p);

    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);

    mpz_mul(N, p, q);
    mpz_mul(phi, p1, q1);

    while (mpz_cmp(g, one) != 0){
        mpz_urandomb(e, state, nlen/4);
        mpz_gcd(g, phi, e);
    }
    mpz_invert(d, e, phi);

    mpz_clears(p1, q1, N, phi, one, g, b, NULL);
    return 1;
}


int RSA_generate_key(mpz_t N, mpz_t p, mpz_t q, mpz_t e, mpz_t d,
		      int nlen, int sec, gmp_randstate_t state){
    while (!is_valid_key(p, q, e, d, nlen, sec)){
        RSA_weak_generate_key(p, q, e, d, nlen, state);
    }
    mpz_mul(N, p, q);
}



int RSA_encrypt(mpz_t cipher, mpz_t msg, mpz_t N, mpz_t e){
    mpz_powm(cipher, msg, e, N);
    return 1;
}

int RSA_decrypt(mpz_t msg, mpz_t cipher, mpz_t N, mpz_t d){
    mpz_powm(msg, cipher, d, N);
    return 1;
}


// /* Use CRT. */
// int RSA_decrypt_with_p_q(mpz_t msg, mpz_t cipher, mpz_t N, mpz_t d,
// 			 mpz_t p, mpz_t q){
//     // Compute ciphertext mod p and mod q
//     mpz_t cipher_p, cipher_q, d_p, d_q, result_p, result_q;
//     mpz_inits(cipher_p, cipher_q, d_p, d_q, result_p, result_q, NULL);

//     mpz_mod(cipher_p, cipher, p);
//     mpz_mod(cipher_q, cipher, q);

//     mpz_mod(d_p, d, p);
//     mpz_mod(d_q, d, q);

//     mpz_powm(result_p, cipher_p, d_p, p);
//     mpz_powm(result_q, cipher_q, d_q, q);

//     // Chinese Remainder Theorem (CRT)
//     mpz_t n1, n2, tmp, term1, term2;
//     mpz_inits(n1, n2, tmp, term1, term2, NULL);

//     mpz_invert(n1, q, p);
//     mpz_invert(n2, p, q);

//     mpz_mul(term1, result_p, q);
//     mpz_mul(term1, term1, n1);

//     mpz_mul(term2, result_q, p);
//     mpz_mul(term2, term2, n2);

//     mpz_add(tmp, term1, term2);
//     mpz_mod(msg, tmp, N);

//     mpz_clears(cipher_p, cipher_q, d_p, d_q, result_p, result_q, NULL);
//     mpz_clears(n2, n1, tmp, term1, term2, NULL);
//     return 1;
// }

int RSA_decrypt_with_p_q(mpz_t msg, mpz_t cipher, mpz_t N, mpz_t d,
			 mpz_t p, mpz_t q){

    mpz_mul(N, p, q);
    RSA_decrypt(msg, cipher, N, d);
    return 1;
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
