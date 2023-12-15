/****************************************************************/
/* test_dlog.c                                                  */
/* Authors: Alain Couvreur                                      */
/* alain.couvreur@lix.polytechnique.fr                          */
/* Last modification October 16, 2023                           */
/****************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include "gmp.h"

#include "utilities.h"
#include "hash.h"
#include "dlog.h"


int elementary_verif(unsigned int k, unsigned int v, mpz_t a,
		     mpz_t vz, mpz_t verif, hash_table H, mpz_t g,
		     mpz_t p){

    mpz_set_ui(a, k);
    mpz_set_ui(verif, v);
    if(hash_get_mpz(vz, H, a, g, p) == HASH_NOT_FOUND){
	gmp_printf("[ERROR] Hash table misses the pair [%Zd; %Zd].\n",
		   a, verif);
	return 0;
    }
    else if(mpz_cmp(vz, verif) != 0){
	gmp_printf("[Error] value corresponding to key: %Zd,", a);
	gmp_printf(" should be %Zd and not %Zd.\n", verif, vz);
	return 0;
    }
    return 1;
}


void test_BS(mpz_t g, mpz_t n_baby_steps, mpz_t p){
    printf("----------- Testing the precomputation phase ----------\n");
    mpz_t sqrtordg, vz, a, verif;
    mpz_inits(sqrtordg, vz, a, verif, NULL);
    mpz_set_ui(sqrtordg, 7);
    mpz_set_ui(vz, 0);
	
    unsigned int size = mpz_get_ui(sqrtordg);
    hash_table H = hash_init(size);	

    fflush(stdout);
    int status = babySteps(vz, H, g, sqrtordg, p);
    implementation_check("babySteps", status);
	
    if(H->nb_elts != 7){
	printf("[ERROR] Hash table has not the good number of elements.\n");
	return;
    }
    else
	printf("Hash table contains the good number of elements: [OK].\n");
    if(!elementary_verif(1, 0, a, vz, verif, H, g, p))
	return;
    else
	printf("Pair [1, 0]  : [OK].\n");
    if(!elementary_verif(2, 1, a, vz, verif, H, g, p))
	return;
    else
	printf("Pair [2, 1]  : [OK].\n");
	
    if(!elementary_verif(4, 2, a, vz, verif, H, g, p))
	return;
    else
	printf("Pair [4, 2]  : [OK].\n");
   
    if(!elementary_verif(8, 3, a, vz, verif, H, g, p))
	return;
    else
	printf("Pair [8, 3]  : [OK].\n");
		
    if(!elementary_verif(16, 4, a, vz, verif, H, g, p))
	return;
    else
	printf("Pair [16, 4] : [OK].\n");
	
    if(!elementary_verif(32, 5, a, vz, verif, H, g, p))
	return;
    else
	printf("Pair [32, 5] : [OK].\n");
		
    if(!elementary_verif(27, 6, a, vz, verif, H, g, p))
	return;
    else
	printf("Pair [27, 6] : [OK].\n");
	
    printf("[SUCCESS]\n");
    mpz_clears(sqrtordg, vz, a, verif, NULL);
    hash_clear(H);
}


void test1(){
    mpz_t n_baby_steps, g, p;
    mpz_inits(n_baby_steps, g, p, NULL);
    mpz_set_ui(g, 2);	

    mpz_set_ui(n_baby_steps, 6);
    mpz_set_ui(p, 37);
    test_BS(g, n_baby_steps, p);
    mpz_clears(n_baby_steps, g, p, NULL);
}


int testBSGS(mpz_t a, mpz_t g, mpz_t p, int expected){
    mpz_t result, testResult;
    int res;

    mpz_inits(result, testResult, NULL);

    printf("---------------------------\n");
    gmp_printf("Log of %Zd in base %Zd modulo %Zd: \n", a, g, p);
    res = BSGS(result, a, g, p);
    implementation_check("BSGS", res);
    if (res == DLOG_NOT_FOUND) {
	printf("[FAILED]\n");
	mpz_clears(result, testResult, NULL);
	return (expected == 0);
    }
    else if(res == DLOG_FOUND){
	gmp_printf("Discrete Log: %Zd\n", result);
	mpz_powm(testResult, g, result, p);
	res = mpz_cmp(testResult, a);
	if(res == 0){
	    printf("[OK]\n");
	    res = (expected == 1);
	}
	else{
	    printf("[FAILED] verification\n");
	    res = (expected == 0);
	}
    }
    else{
	printf("[NYI]\n");
    }
    mpz_clears(result, testResult, NULL);
    return res;
}

void test2(){
    mpz_t a, g, p;

    mpz_inits(a, g, p, NULL);
    mpz_set_ui(g, 2);	

    int i = 1;
    mpz_set_str(a, "19", 10);
    mpz_set_str(p, "37", 10);
    if(!testBSGS(a, g, p, 1))
	i = 0;
	
    mpz_set_str(a, "705995201", 10);
    mpz_set_str(p, "813140123", 10);
    if(!testBSGS(a, g, p, 1))
	i = 0;
	
    mpz_set_str(a, "1", 10);
    mpz_set_str(p, "813140123", 10);
    if(!testBSGS(a, g, p, 1))
	i = 0;
	
    mpz_set_str(a, "16", 10);
    mpz_set_str(p, "813140123", 10);
    if(!testBSGS(a, g, p, 1))
	i = 0;
    
    mpz_set_str(p, "813140149", 10);
    mpz_set_str(g, "49781403", 10);
    mpz_set_str(a, "16", 10);
    if(!testBSGS(a, g, p, 0))
	i = 0;
    
    mpz_set_str(p, "813140149", 10);
    mpz_set_str(g, "49781403", 10);
    mpz_set_str(a, "801817871", 10);
    if(!testBSGS(a, g, p, 1))
	i = 0;
    
    mpz_set_ui(g, 2);	

    mpz_set_str(a, "26559362869", 10);
    mpz_set_str(p, "651959218259", 10);
    if(!testBSGS(a, g, p, 1))
	i = 0;

#if 0
    /* too large for VPL? */
    mpz_set_str(a, "31399422437428", 10);
    mpz_set_str(p,  "87997811728907", 10);
#else
    mpz_set_str(a, "109422437428", 10);
    mpz_set_str(p,  "117567810149", 10);
    /* u=342881, dl is 58264075294=(c=169925)*u+(d=21369) */
#endif
    if(!testBSGS(a, g, p, 1))
	i = 0;
	
    if(i)
	printf("[SUCCESS]\n");
    else
	printf("[FAILED]\n");
    mpz_clears(a, g, p, NULL);
}

void testpga(char *sp, char *sg, char *sa){
    mpz_t p, g, a;
    int i;

    mpz_init_set_str(p, sp, 10);
    mpz_init_set_str(g, sg, 10);
    mpz_init_set_str(a, sa, 10);
    if(!testBSGS(a, g, p, 1))
	i = 0;

    if(i)
        printf("[SUCCESS]\n");
    else
        printf("[FAILED]\n");
    mpz_clears(a, g, p, NULL);
}

void usage(char *s){
    fprintf(stderr, "Usage: %s <test_number>\n", s);
}


int main(int argc, char *argv[]){
    if(argc == 1){
	usage(argv[0]);
	return 0;
    }
    int n = atoi(argv[1]);

    switch(n){
    case 1:
	test1();
	break;
    case 2:
	test2();
	break;
    default:
        if (argc == 2) {
            fprintf(stderr,
                    "Usage: %s %s p g a for solving g^z = a mod p\n",
                    argv[0], argv[1]);
            return 0;
        }
        /* p, g, a for solving g^z = a mod p as in the slides */
        testpga(argv[2], argv[3], argv[4]);
    }
    return 0;
}
