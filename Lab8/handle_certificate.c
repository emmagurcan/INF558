#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gmp.h"

#include "base64.h"
#include "buffer.h"
#include "bits.h"
#include "certificate.h"

#define MAX_NAME_LENGTH 256

void Usage(char *s){
    printf("Usage: %s <args>\n", s);
    printf("where <args> can be\n");
    printf("create auth_secret_key pub_key_to_certify username issuername\n");
    printf("or\n");
    printf("verify auth_pub_key certificate\n");
}

int main(int argc, char *argv[]){
    FILE *in = NULL;
    certificate_t C;
    mpz_t N, d, e;

    if(argc <= 1){
        Usage(argv[0]);
        return 0;
    }
    if(strcmp(argv[1], "create") == 0){
	/* read secret key */
        if((in = fopen(argv[2], "r")) == NULL){
            perror(argv[2]);
            return -1;
        }
        mpz_inits(N, d, NULL);
        read_secret_keys(N, d, in);
        fclose(in);
        /* read key to sign */
        if((in = fopen(argv[3], "r")) == NULL){
            perror(argv[3]);
            return -1;
        }
        init_certificate(&C);
        create_certificate(&C, argv[4], argv[5], N, d, in);
        mpz_clears(N, d, NULL);
        fclose(in);
        print_certificate(&C);
        /* TODO: change this, not strong enough */
        char *certif_file_name = malloc(MAX_NAME_LENGTH*sizeof(char)+1);
        char suffix[17] = "_certificate.txt";
        strcpy(certif_file_name, argv[4]);
        strcat(certif_file_name, suffix);
        printf_certificate(certif_file_name, &C);
        clear_certificate(&C);
        free(certif_file_name);
    }
    else if(strcmp(argv[1], "verify") == 0){
        int valid;
        /* read public key */
        if((in = fopen(argv[2], "r")) == NULL){
            perror(argv[2]);
            return -1;
        }
        mpz_inits(N, e, NULL);
        read_public_keys(N, e, in);
        fclose(in);
        /* read certificate */
        if((in = fopen(argv[3], "r")) == NULL){
            perror(argv[3]);
            return -1;
        }
        init_certificate(&C);
        extract_certificate(&C, in);
        valid = valid_certificate(&C, N, e);
        mpz_clears(N, e, NULL);
        print_certificate(&C);
        clear_certificate(&C);
        //printf("-> %d\n", valid);
        printf("\n\n[ ");
        if(!valid)
            printf("IN");
        printf("VALID CERTIFICATE ]\n\n");
    }
    else{
        printf("Unrecognized option: %s\n", argv[1]);
    }
    return 0;
}
