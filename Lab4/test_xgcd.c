#include <stdio.h>
#include <stdlib.h>

#include "utilities.h"
#include "gmp.h"

#include "xgcd.h"

void test_xgcd_long(long a, long b, long g){
    long u, v, gg;
    int status;

    status = XGCD_long(&gg, &u, &v, a, b);
    implementation_check("XGCD_long", status);
    if(gg == g){
	printf("[gcd: OK]\n");
	if(u*a+v*b == g)
	    printf("[xgcd: OK]\n");
	else
	    printf("[xgcd: FAILED]\n");
    }
    else
        printf("[gcd: FAILED]\n");
}

void testab(const char *sa, const char *sb, const char *sg){
    mpz_t a, b, g, u, v, gg;

    mpz_init_set_str(a, sa, 10);
    mpz_init_set_str(b, sb, 10);
    mpz_init_set_str(gg, sg, 10);
    mpz_inits(g, u, v, NULL);

    int status = XGCD(g, u, v, a, b);
    implementation_check("XGCD", status);

    if(mpz_cmp(g, gg) == 0){
	printf("[gcd: OK]\n");
	mpz_mul(gg, u, a);
	mpz_addmul(gg, v, b);
	if(mpz_cmp(g, gg) == 0)
	    printf("[xgcd: OK]\n");
	else
	    printf("[xgcd: FAILED]\n");
    }
    else
	printf("[gcd: FAILED]\n");
    mpz_clears(a, b, g, gg, u, v, NULL);
}

void testlem(const char *sa, const char *sb, const char *sm, const char *sx){
    mpz_t a, b, m, x, tmp;
    int ok = 1, status;

    mpz_init_set_str(a, sa, 10);
    mpz_init_set_str(b, sb, 10);
    mpz_init_set_str(m, sm, 10);
    mpz_init_set_str(x, sx, 10);

    mpz_init(tmp);
    status = linear_equation_mod(tmp, a, b, m);
    implementation_check("linear_equation_mod", status);

    if(status == 0)
	ok = mpz_sgn(x) == 0;
    else
	ok = mpz_cmp(tmp, x) == 0;

    mpz_clears(a, b, m, x, tmp, NULL);

    if(ok)
	printf("[OK]\n");
    else
	printf("[FAILED]\n");
}

int main(int argc, char *argv[]){
    if(argc == 1){
	fprintf(stderr, "Usage: %s <test_nb in 0..2>\n", argv[0]);
	return 0;
    }
    int n = atoi(argv[1]);

    switch(n){
    case 0:
	printf("test 0.1:      ");
	test_xgcd_long(101, 11, 1);
	printf("test 0.2:      ");
	test_xgcd_long(101, 101, 101);
	printf("test 0.3:      ");
	test_xgcd_long(101, 0, 101);
	printf("test 0.4:      ");
	test_xgcd_long(1010, 35, 5);
	break;
    case 1:
	printf("test 1.1:      ");
	testab("101", "11", "1");
	printf("test 1.2:      ");
	testab("101", "101", "101");
	printf("test 1.3:      ");
	testab("101", "0", "101");
	printf("test 1.4:      ");
	testab("1010", "35", "5");
	break;
    case 2:
	printf("test 2.1:      ");
	testlem("1", "50", "101", "50");
	printf("test 2.2:      ");
	testlem("11", "50", "101", "78");
	printf("test 2.3:      ");
	testlem("11", "50", "135", "115");
	printf("test 2.4:      ");
	testlem("10", "53", "135", "0");
	printf("test 2.5:      ");
	testlem("10", "50", "135", "5");
    }
    return 0;
}
