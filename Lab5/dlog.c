/****************************************************************/
/* dlog.c                                                       */
/* Authors: Alain Couvreur, FMorain                             */
/* alain.couvreur@lix.polytechnique.fr                          */
/* Last modification October 16, 2023                           */
/****************************************************************/

#include <stdio.h>
#include <assert.h>

#include "utilities.h"

#include "hash.h"
#include "dlog.h"
#include "gmp.h"


/* 2 is very verbose, 1 is mild */
#define DEBUG 0

/* INPUT: u <= sqrt(ord(g))
   OUTPUT: DLOG_ERROR in case of problem
           DLOG_SMALL_ORDER if order of g found
           DL_OK otherwise 
   SIDE-EFFECT: result <- ord(g) if small and DLOG_SMALL_ORDER is returned.
*/
int babySteps(mpz_t result, hash_table H, mpz_t g, mpz_t u, mpz_t p){
    mpz_t i, kz;
    mpz_inits(i, kz, NULL);
    for (mpz_set_ui(i, 0); mpz_cmp(i, u) < 0; mpz_add_ui(i, i, 1)){
        mpz_powm(kz, g, i, p);
        int addr;
        if (hash_put_mpz(H, &addr, kz, i, g, p) != HASH_OK){
            mpz_clears(i, kz, NULL);
            return DLOG_ERROR;
        }
    }
    mpz_clears(i, kz, NULL);
    return DLOG_OK;
}

int giantSteps(mpz_t result, hash_table H, mpz_t g, mpz_t ordg, mpz_t u, mpz_t p, mpz_t a)
{
    mpz_t c, cmax_plus_one, g_pow_minus_u;
    mpz_init_set_ui(c, 0);
    mpz_init(cmax_plus_one);
    mpz_init_set(g_pow_minus_u, g);

    mpz_powm(g_pow_minus_u, g_pow_minus_u, u, p);
    mpz_invert(g_pow_minus_u, g_pow_minus_u, p);

    mpz_div(cmax_plus_one, ordg, u);

    while (mpz_cmp(c, cmax_plus_one) < 0) {
        mpz_t prod, d;
        mpz_init_set(prod, g_pow_minus_u);
        mpz_powm(prod, prod, c, p);
        mpz_mul(prod, prod, a);
        mpz_mod(prod, prod, p);
        mpz_init(d);

        if (hash_get_mpz(d, H, prod, g, p) == HASH_FOUND) {
            // res = cu + d
            mpz_mul(result, c, u);
            mpz_add(result, result, d);

            mpz_clear(prod);
            mpz_clear(d);
            mpz_clear(c);
            mpz_clear(cmax_plus_one);
            mpz_clear(g_pow_minus_u);
            return DLOG_OK;
        }

        mpz_add_ui(c, c, 1);
        mpz_clear(prod);
        mpz_clear(d);
    }

    mpz_clear(c);
    mpz_clear(cmax_plus_one);
    mpz_clear(g_pow_minus_u);
    return DLOG_ERROR;
}

/* INPUT: ordg is an upper bound on ord(g).
   OUTPUT: DLOG_ERROR in case of pb
   SIDE-EFFECT: result = ord(g) if small and DLOG_SMALL_ORDER is returned.
 */int BSGS_aux(mpz_t result, mpz_t a, mpz_t g, mpz_t ordg, mpz_t p){
    mpz_t u;
    mpz_init(u);
    mpz_sqrt(u, ordg);
    hash_table H = hash_init(2 * mpz_get_ui(u));

    if (babySteps(result, H, g, u, p) == DLOG_SMALL_ORDER){
        hash_clear(H);
        mpz_clear(u);
        return DLOG_SMALL_ORDER;
    }

    if (giantSteps(result, H, g, ordg, u, p, a) == DLOG_FOUND){
        hash_clear(H);
        mpz_clear(u);
        return DLOG_OK;
    }

    else{
        hash_clear(H);
        mpz_clear(u);
        return DLOG_ERROR;
    }
}

int BSGS(mpz_t result, mpz_t a, mpz_t g, mpz_t p)
{
    mpz_t ordg;
    mpz_init(ordg);
    mpz_sub_ui(ordg, p, 1);
    
    int first_attempt = BSGS_aux(result, a, g, ordg, p);
    if (first_attempt == DLOG_SMALL_ORDER){
        gmp_printf("Resetting order of g to %Zd\n", ordg);
        if (BSGS_aux(result, a, g, result, p) == DLOG_FOUND){
            return DLOG_OK;
        }
        else {
            return DLOG_ERROR;
        }
    }
    else if (first_attempt == DLOG_OK){
        return DLOG_OK;
    }
    else {
        return DLOG_ERROR;
    }
}