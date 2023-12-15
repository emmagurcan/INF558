/****************************************************************/
/* test_QS.c                                                    */
/* Author: F. Morain                                            */
/* morainr@lix.polytechnique.fr                                 */
/* Last modification October 15, 2023                           */
/****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "gmp.h"
#include "utils.h"
#include "QS.h"

void testQS1(int phase){
    mpz_t N, kN, g;
    int B[] = {-1, 2, 5, 17, 23};
    int cardB = 5, M = 10, nf = 0;
    factor_t tabf[2];

    mpz_inits(N, kN, g, NULL);

    mpz_set_str(N, "143", 10);
    mpz_mul_ui(kN, N, 7);
    mpz_set_ui(g, 31);
    QS_aux(tabf, &nf, N, kN, g, B, cardB, M, phase);

    mpz_clears(N, kN, g, NULL);
}

void testQS(const char *sN, int k, int cardB, int M, int phase){
    const char *ficdp = "1e7.data";
    FILE *file;
    mpz_t N;
    factor_t tabf[20];
    int nf = 0;

    if((file = fopen(ficdp, "r")) == NULL){
	perror(ficdp);
	return;
    }
    mpz_init_set_str(N, sN, 10);
    QS(tabf, &nf, N, k, cardB, M, file, 10);
    fclose(file);
}

void testQSWithBigNumbers(){
    const char *tab[] = {
	"1000000013 0 0 0",                           /* 10dd */
	"100000000021 0 0 0",                         /* 12dd */
	"10000000000049 0 0 0",                       /* 14dd */
	"1000000000000003 0 0 0",                     /* 16dd */
	"100000000000000223 0 0 6000",                /* 18dd */
	"10000000000000000049 0 150 15000",           /* 20dd */
	"1000000000000000000049 0 150 20000",         /* 22dd */
	"100000000000000000000027 0 420 70000",       /* 24dd */
	"10000000000000000000000007 0 500 120000",    /* 26dd */
	"1000000000000000000000000003 0 625 300000",  /* 28dd */
	"100000000000000000000000000039 0 700 600000",/* 30dd */
	NULL};
    char sN[100];
    int k = 0, cardB = 0, M = 0, i;

    for(i = 0; tab[i] != NULL; i++){
	sscanf(tab[i], "%s %d %d %d\n", sN, &k, &cardB, &M);
	printf("########## Factoring N%d = %s (%d %d %d)\n",
	       i+1, sN, k, cardB, M);
	testQS(sN, k, cardB, M, 0);
    }
}

void usage(char *cmd){
    fprintf(stderr, "%s [0|1|2|3|4|5] [k cardB M, N]\n", cmd);
    fprintf(stderr, "with no argument, basic test on 143\n");
    fprintf(stderr, "with 1|2|3|4|5, test for given phase\n");
    fprintf(stderr, "with 0, test some numbers below 30dd\n");
}

int main(int argc, char *argv[]){
    int k = 0, cardB = 0, M = 0, phase = 0;

    if(argc == 1)
	testQS1(1);
    else if(argc == 2){
	if(!isdigit(argv[1][0])){
	    usage(argv[0]);
	}
	else{
	    phase = atoi(argv[1]);
	    if(phase > 0)
		testQS1(phase);
	    else
		testQSWithBigNumbers();
	}
    }
    else{
	if(argc > 3){
	    k = atoi(argv[3]);
	    cardB = atoi(argv[4]);
	    M = atoi(argv[5]);
	}
	testQS(argv[2], k, cardB, M, atoi(argv[1]));
    }
    return 0;
}
