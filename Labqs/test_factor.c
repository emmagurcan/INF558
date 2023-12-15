/*****************************************************************/
/* test_factor.c                                                 */
/* Author : Alain Couvreur <alain.couvreur@lix.polytechnique.fr> */
/* Modifs : Maxime Bombar <maxime.bombar@inria.fr>               */
/* Last modification October 25, 2022                            */
/*****************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "gmp.h"
#include "utilities.h"

#include "utils.h"
#include "trialdiv.h"
#include "rho.h"
#include "pminus1.h"

void testTrial(mpz_t n, long bound, uint length, FILE* file){
    factor_t* factors = (factor_t*)malloc(length * sizeof(factor_t));
    int i, nFactors;
    mpz_t cof;
    mpz_init(cof);
    printf("+------------------------+\n");
    gmp_printf("Factorization of %Zd with primes less than %ld:\n\n",
	       n, bound);
    int status=trialDivision(factors, &nFactors, cof, n, bound, length, file);
    implementation_check("trialdiv", status);
    //gmp_printf("%Zd = ", n);
    factor_t* cursor = factors;
    for(i = 0; i < nFactors; i++, cursor++){
	gmp_printf("(%Zd^%d) * ", cursor->f, cursor->e);
    }
    gmp_printf("(%Zd)\n", cof);
	

    mpz_clear(cof);
    factor_clear(factors, nFactors);
    free(factors);
}


void test1(){
    printf("************** Testing Trial division **************\n");

    FILE* file;
    mpz_t n;
    long bound;
    mpz_inits(n, NULL);

    if((file = fopen("1e7.data", "r")) == NULL){
	perror("1e7.data");
	exit(-1);
    }
    /* TEST 1.1 */
    mpz_set_ui(n, 3276);
    bound = 10;
    testTrial(n, bound, 10, file);
    rewind(file);
    /* END TEST 1.1 */

    /* TEST 1.2 */
    bound = 100;
    testTrial(n, bound, 10, file);
    rewind(file);
    /* END TEST 1.2 */

    /* TEST 1.3 */
    mpz_set_str(n, "29145271819831067830349386007355751792690423602074265137925000", 10);
    testTrial(n, bound, 10, file);
    rewind(file);
    /* END TEST 1.3 */

    /* TEST 1.4 */
    mpz_set_str(n, "12652209139612535291", 10);
    bound = 10000000;
    testTrial(n, bound, 10, file);
    rewind(file);
    /* END TEST 1.4 */

    mpz_clears(n, NULL);
    fclose(file);
}



void testPollardRho_with_long(const mpz_t N, long nrOfIterations){
    mpz_t Q;

    mpz_init(Q);
    int status;
    double duration;
    clock_t start, finish;
    gmp_printf("Seeking a factor for N = %Zd\n", N);
    printf("+--------------------+\n");
    long f=1, n=mpz_get_si(N);
    start = clock();
    status= PollardRho_with_long(&f,n,100000);
    implementation_check("PollardRho_with_long", status);
    finish = clock();
    if (status == FACTOR_FOUND && mpz_divisible_ui_p(N, f)) {
        mpz_divexact_ui(Q, N, f);
        printf("[FACTOR FOUND] : ");
        if (mpz_cmp_ui(Q, f)<0) {
            gmp_printf("%Zd, %ld\n", Q, f);
        }
    else {
        gmp_printf("%ld, %Zd\n", f, Q);
    }
    }
    else if (status == FACTOR_ERROR) {
        printf("[FACTOR ERROR]\n");
    }
    else {
        printf("[FACTOR NOT FOUND]\n");
    }
    duration = (double)(finish - start)/CLOCKS_PER_SEC;
    printf("Running time: %f seconds.\n\n", duration);
    mpz_clear(Q);
}

void test2(){
    printf("************** Testing Pollard rho for longs **********************\n");
    printf("\n**************************************************\n");
    printf("* \tUsing function x |-> x^2 + 7.\t\t *\n");
    printf("**************************************************\n\n");

    mpz_t N;
    mpz_init_set_si(N,44);
    testPollardRho_with_long(N, 100000);

    mpz_set_si(N,126522);
    testPollardRho_with_long(N, 100000);

    mpz_set_si(N,448537);
    testPollardRho_with_long(N, 100000);

    mpz_clear(N);
}


void goodFunction(mpz_t out, mpz_t in, const mpz_t N){
    mpz_powm_ui(out, in, 2, N);
    mpz_add_ui(out, out, 7);
    mpz_mod(out, out, N);
}

void badFunction(mpz_t out, mpz_t in, const mpz_t N){
    mpz_powm_ui(out, in, 2, N);
    mpz_sub_ui(out, out, 3);
    mpz_mod(out, out, N);
}


void testPollardRho(mpz_t N, long nrOfIterations,
                    void (*f)(mpz_t, mpz_t, const mpz_t)){
    gmp_printf("Seeking a factor for N = %Zd\n", N);

    printf("+--------------------+\n");
    factor_t p[20];
    double duration;
    clock_t start, finish;
    int nf = 0, i, status;

    start = clock();
    status = PollardRho(p, &nf, N, f, 100000);
    implementation_check("PollardRho", status);
    finish = clock();

    if (status == FACTOR_ERROR) {
        printf("[FACTOR ERROR]\n\n");
    }

    if (status == FACTOR_NOT_FOUND) {
        printf("[FACTOR NOT FOUND]\n\n");
    }
    else {
        for(i = 0; i < nf; i++) {
            gmp_printf("[FACTOR FOUND] : p = %Zd (%d)\n",
                       p[i].f, p[i].status);
        }
    }
    duration = (double)(finish - start)/CLOCKS_PER_SEC;
    printf("Running time : %f seconds.\n\n", duration);
    factor_clear(p, nf);
}


void test3(){
    printf("************** Testing Pollard rho **********************\n\n");

    mpz_t N;
    mpz_init(N);

    printf("\n**************************************************\n");
    printf("* \tUsing function x |-> x^2 + 7.\t\t *\n");
    printf("**************************************************\n\n");

    mpz_set_str(N, "22145579", 10);
    testPollardRho(N, 100000, goodFunction);
    if(mpz_probab_prime_p(N, 25))
	printf("Petit polission\n");

    mpz_set_str(N, "12652209139612535291", 10);
    testPollardRho(N, 100000, goodFunction);

    mpz_set_str(N, "10541221091544233897", 10);
    testPollardRho(N, 100000, goodFunction);

    mpz_set_str(N, "633564754957339397639948337059", 10);
    testPollardRho(N, 1000000, goodFunction);

    mpz_set_str(N, "2035109857152735577711831203565763223283", 10);
    testPollardRho(N, 100000000000000000, goodFunction);

    mpz_set_str(N, "72963193328043133999662344352921779599583554200941", 10);
    testPollardRho(N, 100000000000000000, goodFunction);


    printf("\n**************************************************\n");
    printf("* \tUsing function x |-> x^2 - 3.\t\t *\n");
    printf("**************************************************\n\n");

    mpz_set_str(N, "12652209139612535291", 10);
    testPollardRho(N, 100000, badFunction);

    mpz_set_str(N, "10541221091544233897", 10);
    testPollardRho(N, 100000, badFunction);

    mpz_set_str(N, "633564754957339397639948337059", 10);
    testPollardRho(N, 1000000, badFunction);

    mpz_set_str(N, "2904904137951823762898116102980679156667", 10);
    testPollardRho(N, 10000000, badFunction);

    mpz_set_str(N, "72963193328043133999662344352921779599583554200941", 10);
    testPollardRho(N, 100000000, badFunction);

    mpz_clear(N);
}

void testPminus1(mpz_t N, long bound1, long bound2, FILE* file){

    factor_t p[20];
    int i, nf = 0, status = FACTOR_NOT_FOUND;
    double duration;
    clock_t start, finish;

    gmp_printf("Seeking a factor for N = %Zd\n", N);
    printf("+--------------------+\n");

    start = clock();
    status = PollardPminus1(p, &nf, N, bound1, bound2, file);
    implementation_check("PollardPminus1", status);
    finish = clock();

    if (status == FACTOR_ERROR) {
        printf("[FACTOR ERROR]\n\n");
    }

    if(status == FACTOR_NOT_FOUND && nf == 0)
	printf("[FACTOR NOT FOUND]\n\n");
    else{
	for(i = 0; i < nf; i++)
	    gmp_printf("[FACTOR FOUND] : p = %Zd (%d)\n",
		       p[i].f, p[i].status);
	duration = (double)(finish - start)/CLOCKS_PER_SEC;
	printf("Running time : %f seconds.\n\n", duration);
	factor_clear(p, nf);
    }
}


void test4(){
    printf("***************** Testing Pollard p - 1 ********************\n\n");
    printf("\n**********************************\n");
    printf("* \tPHASE 1:\t\t *\n");
    printf("**********************************\n\n");

    FILE* file = fopen("1e7.data", "r");


    mpz_t N;
    long bound1, bound2;
    mpz_inits(N, NULL);

    mpz_set_ui(N, 2993);
    bound1 = 50;
    bound2 = 0;
    testPminus1(N, bound1, bound2, file);
    rewind(file);

    mpz_set_str(N, "12652209139612535291", 10);
    testPminus1(N, 1500, bound2, file);
    rewind(file);

    mpz_set_str(N, "561988649120021", 10);
    testPminus1(N, 1000, bound2, file);
    rewind(file);

    printf("\n**********************************\n");
    printf("* \tPHASE 1&2:\t\t *\n");
    printf("**********************************\n\n");

    mpz_set_str(N, "561988649120021", 10);
    testPminus1(N, 1500, 1000000, file);
    rewind(file);

    mpz_set_str(N, "633564754957339397639948337059", 10);
    testPminus1(N, 1000000, 100000000, file);
    rewind(file);

    fclose(file);
    mpz_clears(N, NULL);
}

void usage(char *s, int ntests){
    fprintf(stderr, "Usage: %s <test_number in 1..%d>\n", s, ntests);
}

int main(int argc, char *argv[]){
    if(argc == 1){
	usage(argv[0], 4);
	return 0;
    }
    int n = atoi(argv[1]);

    
    // testgcd(15,5,3);
    switch(n){
    case 1:
	test1();
	break;
    case 2:
	test2();
	break;
    case 3:
	test3();
	break;
    case 4:
	test4();
	break;
    }
    return 0;
}
