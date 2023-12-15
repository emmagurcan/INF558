#include <stdlib.h>
#include <stdio.h>

#include "gmp.h"

#include "base64.h"
#include "buffer.h"
#include "bits.h"
#include "certificate.h"

int main(int argc, char *argv[]){
    FILE *in = NULL;
    certificate_t C, C2;
    mpz_t N, e;
    uchar *strcert;

    if(argc != 3){
	fprintf(stderr, "Usage: %s pub_key certif\n", argv[0]);
	return 0;
    }
    if((in = fopen(argv[1], "r")) == NULL){
	perror(argv[1]);
	return -1;
    }
    mpz_inits(N, e, NULL);
    if(read_public_keys(N, e, in) == 0)
	perror("read_public_keys");
    fclose(in);
    
    if((in = fopen(argv[2], "r")) == NULL){
	perror(argv[2]);
	return -1;
    }
    init_certificate(&C);
    printf("Reading certificate from file and testing validity\n");
    extract_certificate(&C, in);
    fclose(in);
    print_certificate(&C);
    strcert = string_from_certificate(&C);
    printf("Certificate as a string:\n%s\n", strcert);
    printf("-> is_valid=%d\n", valid_certificate(&C, N, e));

    printf("Reading certificate from string and retesting validity\n");
    init_certificate(&C2);
    if(certificate_from_string(&C2, (char*)strcert) == 0)
	printf("error\n");
    else
	printf("-> is_valid=%d\n", valid_certificate(&C2, N, e));

    mpz_clears(N, e, NULL);
    free((char *)strcert);
    clear_certificate(&C);
    clear_certificate(&C2);
    return 0;
}
