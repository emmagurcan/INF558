#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gmp.h"

#include "base64.h"
#include "buffer.h"
#include "bits.h"
#include "random.h"

#include "operating_modes.h"
#include "aes.h"

#include "channel.h"

void channel_init(mpz_t p, mpz_t g){
    mpz_set_str(p, "0x8000000000000000000000000000001D", 0);
    mpz_set_ui(g, 2);
}

/* If in doesn't start with prefix, return -1 or 0; 1 otherwise. */
int msg_import_mpz(mpz_t n, char *in, const char *prefix, int base){
    if(strlen(in) < strlen(prefix))
	return -1;
    if(strncmp(in, prefix, strlen(prefix)) != 0)
	return 0;
    mpz_set_str(n, in+strlen(prefix), base);
    return 1;
}

void msg_export_mpz(char *buf, const char *prefix, mpz_t n, int base){
    if(base == 0)
	gmp_sprintf(buf, "%s%#Zx", prefix, n);
    else
	printf("msg_export_mpz: NYI");
}

/* If in doesn't start with prefix, return -1 or 0; 1 otherwise. */
int msg_import_string(char *buf, char *in, const char *prefix){
    if(strlen(in) < strlen(prefix))
	return -1;
    if(strncmp(in, prefix, strlen(prefix)) != 0)
	return 0;
    sprintf(buf, "%s", in+strlen(prefix));
    return 1;
}

void msg_export_string(char *buf, const char *prefix, const char* in){
    sprintf(buf, "%s%s", prefix, in);
}

