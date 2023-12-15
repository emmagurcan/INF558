#include <stdio.h>
#include <stdlib.h>

#include "utilities.h"
#include "gmp.h"

#include "CRT.h"

void testCRT(mpz_t *r, mpz_t *m, int nb_pairs){
    mpz_t n;
    int i, status;
	
    mpz_init(n);
    status = CRT(n, r, m, nb_pairs);
    implementation_check("CRT", status);    
    printf("CRT([");
    for(i = 0; i < nb_pairs; i++){
	if(i > 0)
	    printf(",");
	gmp_printf("(%Zd, %Zd)", r[i], m[i]);
    }
    printf("]) = (%d, ", status);
    if(status)
	gmp_printf("%Zd)\n", n);
    else
	printf("undef)\n");
    mpz_clear(n);
}

void testCRT2(mpz_t *r, mpz_t *m){
    mpz_t n;
    int status;
    mpz_init(n);

    status = CRT2(n, r[0], m[0], r[1], m[1]);
    implementation_check("CRT2", status);    
    printf("CRT([");
    gmp_printf("(%Zd, %Zd)", r[0], m[0]);
    printf(",");
    gmp_printf("(%Zd, %Zd)", r[1], m[1]);
    printf("]) = (%d, ", status);
    if(status)
	gmp_printf("%Zd)\n", n);
    else
	printf("undef)\n");
    mpz_clear(n);
}

void test(int b){
    mpz_t *r = (mpz_t *)malloc(5 * sizeof(mpz_t));
    mpz_t *m = (mpz_t *)malloc(5 * sizeof(mpz_t));
    int i;

    for(i = 0; i < 5; i++){
	mpz_init(r[i]);
	mpz_init(m[i]);
    }

    mpz_set_ui(r[0], 1); mpz_set_ui(m[0], 7);
    mpz_set_ui(r[1], 2); mpz_set_ui(m[1], 11);
    mpz_set_ui(r[2], 3); mpz_set_ui(m[2], 13);
    mpz_set_ui(r[3], 4); mpz_set_ui(m[3], 15);
    mpz_set_ui(r[4], 5); mpz_set_ui(m[4], 17);
    testCRT2(r, m);
    if(b){
	testCRT(r, m, 2);
	testCRT(r, m, 3);
	testCRT(r, m, 5);

	mpz_set_ui(r[0], 1); mpz_set_ui(m[0], 3);
	mpz_set_ui(r[1], 2); mpz_set_ui(m[1], 6);
	testCRT(r, m, 2);

	mpz_set_ui(r[1], 4); mpz_set_ui(m[1], 6);
	testCRT(r, m, 2);
    }
	
    for(i = 0; i < 5; i++){
	mpz_clear(r[i]);
	mpz_clear(m[i]);
    }
    free(r);
    free(m);
}

void usage(char *s){
    fprintf(stderr, "Usage: %s <test_number in 1..2>\n", s);
}

int main(int argc, char *argv[]){
    if(argc == 1){
	usage(argv[0]);
	return 0;
    }
    int n = atoi(argv[1]);
	
    switch(n){
    case 1:
	test(0);
	break;
    case 2:
	test(1);
	break;
    }
    return 0;
}
