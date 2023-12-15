#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utilities.h"

#include "gmp.h"
#include "buffer.h"
#include "sha3.h"

#include "rsa.h"
#include "sign.h"
#include "dsa.h"
#include "attack_dsa.h"

#define DEBUG 0

int dsa_sign_dummy(buffer_t *msg, mpz_t p,
		   mpz_t q, mpz_t a, mpz_t x, mpz_t r, mpz_t s,
		   mpz_t k){
    
    size_t hash_len = hash_length(q);
    buffer_t hash;
    buffer_init(&hash, hash_len);
    buffer_hash(&hash, hash_len, msg);

    mpz_t hash_mpz;
    mpz_init(hash_mpz);
    mpz_import(hash_mpz, hash_len, 1, 1, 0, 0, hash.tab);

    mpz_set_ui(r, 0);
    mpz_set_ui(s, 0);
    mpz_t km;
    mpz_init(km);

    mpz_powm(r, a, k, p);
    mpz_mod(r, r, q);
    mpz_mul(s, x, r);
    mpz_add(s, s, hash_mpz);
    mpz_invert(km, k, q);
    mpz_mul(s, s, km);
    mpz_mod(s, s, q);
    mpz_clears(km, NULL);
    mpz_clear(hash_mpz);
    buffer_clear(&hash);

    return 1;
}

/* Solves the system with unkowns k, x:
   s1.k - r1.x = h1
   s2.k - r1.x = h2
   and fills in x
*/
int solve_system_modq(mpz_t x, mpz_t r1, mpz_t s1,
		      mpz_t r2, mpz_t s2, mpz_t h1, mpz_t h2,
		      mpz_t q){

    // printf("%s\n", "Test solving system...");
    printf("%s\n", "Linear system :");
    gmp_printf("%Zd k - %Zd x = %Zd\n", s1, r1, h1);
    gmp_printf("%Zd k - %Zd x = %Zd\n", s2, r2, h2);

    mpz_t left, right, denom, res;
    mpz_inits(left, right, denom, res, NULL);
    mpz_mul(left, s2, h1);
    mpz_mul(right, s1, h2);
    mpz_mul(denom, s2, r1);
    mpz_neg(denom, denom);
    mpz_addmul(denom, s1, r2);
    mpz_sub(res, left, right);
    mpz_mod(res, res, q);
    mpz_invert(denom, denom, q);
    mpz_mul(x, res, denom);
    mpz_mod(x, x, q);
    mpz_clears(left, right, denom, res, NULL);

    printf("\n");
    printf("%s\n", "Candidate for secret key obtained from the attack:");
    gmp_printf("x = %Zd\n", x);
    printf("\n");
    return 1;
}


int dsa_attack(mpz_t x, buffer_t *msg1, buffer_t *msg2,
	       mpz_t p, mpz_t q, mpz_t a, mpz_t r1,
	       mpz_t s1, mpz_t r2, mpz_t s2){
    mpz_t h1, h2;
    mpz_inits(h1, h2, NULL);

    mpz_import(h1, msg1->length, 1, 1, 0, 0, msg1->tab);
    mpz_import(h2, msg2->length, 1, 1, 0, 0, msg2->tab);

    int solve_status = solve_system_modq(x, r1, s1, r2, s2, h1, h2, q);

    mpz_clears(h1, h2, NULL);

    return solve_status;
}
