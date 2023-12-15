/****************************************************************/
/* rho.c                                                        */
/* Authors: Alain Couvreur, Maxime Bombar                       */
/* alain.couvreur@lix.polytechnique.fr                          */
/* maxime.bombar@inria.fr                                       */
/* Last modification October 24, 2022                           */
/****************************************************************/

#include <stdio.h>
#include <assert.h>

#include "gmp.h"
#include "utils.h"

#include "rho.h"

long f(long x) {
    return x * x + 7;
}

int gcd(int a, int b) {
    if (b == 0) {
        return a;
    }
    return gcd(b, a % b);
}

int PollardRho_with_long(long *factor, const long N,
                         long nbOfIterations) {
    long x = 2;
    long y = 2;
    long d = 1;
    long i = 1;
    while (d == 1 && i < nbOfIterations) {
        x = f(x) % N;
        y = f(f(y)) % N;
        d = gcd(abs(x - y), N);
        i++;
    }
    if (d == 1) {
        return 0;
    } else {
        *factor = d;
        return 1;
    }
}

void f_steps(mpz_t result, mpz_t x, const mpz_t N) {
    mpz_t temp;
    mpz_init(temp);
    mpz_mul(temp, x, x);
    mpz_add_ui(temp, temp, 1);
    mpz_mod(result, temp, N);
    mpz_clear(temp);
}

int PollardRhoSteps(mpz_t factor, const mpz_t N,
                    void (*f)(mpz_t, mpz_t, const mpz_t),
                    long nbOfIterations) {
    mpz_t x, y, d;
    mpz_inits(x, y, d, NULL);
    mpz_set_ui(x, 2);
    mpz_set_ui(y, 2);
    mpz_set_ui(d, 1);

    for (long i = 1; i <= nbOfIterations; i++) {
        f_steps(x, x, N);
        f_steps(y, y, N);
        f_steps(y, y, N);
        mpz_sub(d, x, y);
        mpz_abs(d, d);
        mpz_gcd(d, d, N);
        if (mpz_cmp_ui(d, 1) != 0 && mpz_cmp(d, N) != 0) {
            mpz_set(factor, d);
            mpz_clears(x, y, d, NULL);
            return 1;
        }
    }

    mpz_clears(x, y, d, NULL);
    return 0;
}

int PollardRho(factor_t *result, int *nf, const mpz_t N,
               void (*f)(mpz_t, mpz_t, const mpz_t), long nbOfIterations) {
    mpz_t factor;
    mpz_init(factor);
    int success = PollardRhoSteps(factor, N, f, nbOfIterations);

    if (success) {
        AddFactor(result + *nf, factor, 1, success);
        (*nf)++;
        return 1;
    } else {
        return 0;
    }
}
