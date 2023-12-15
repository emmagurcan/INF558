#define _POSIX_C_SOURCE 200809L // Enable POSIX.1-2008 extension for strnlen

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <time.h>

#include "gmp.h"

#include "base64.h"
#include "buffer.h"
#include "bits.h"
#include "sign.h"
#include "certificate.h"

#define DEBUG 0
#define BUF_LENGTH 512

/* INPUT: lbuf is the total size of including '\0'.
   OUTPUT: 1 in case prefix was found, 0 otherwise. */
int parse_prefix_buffer(char *buf, size_t *lbuf, const char *prefix)
{
    size_t lprefix = strlen(prefix);

    if((*lbuf < lprefix) || strncmp(buf, prefix, lprefix) != 0)
	return 0;
    *lbuf -= lprefix+1;
    memmove(buf, buf+lprefix, *lbuf+1);
    buf[*lbuf] = '\0';
    return 1;
}

#define PARSE_BUF(buf, lbuf, prefix){ \
    do { \
	if(parse_prefix_buffer((buf), (lbuf), (prefix)) == 0) return 0;	\
    } while(0);}

/* OUTPUT: 1 in case prefix was found, 0 otherwise.
   TODO: what about eof if the last line doesn't end with a '\n'? 
*/
int read_buffer(char *buf, size_t *lbuf, const char *prefix, FILE *in){
    /* TODO: humf! */
    fgets(buf, BUF_LENGTH, in);
    *lbuf = strnlen(buf, BUF_LENGTH);
    return parse_prefix_buffer(buf, lbuf, prefix);
}

#define READ_BUF(buf, lbuf, prefix, in){ \
    do { \
	if(read_buffer((buf), (lbuf), (prefix), (in)) == 0) return 0;	\
    } while(0);}

int read_public_keys(mpz_t N, mpz_t e, FILE *in){
    char buf[BUF_LENGTH];
    size_t lbuf;
    
    READ_BUF(buf, &lbuf, "#", in);
    READ_BUF(buf, &lbuf, "N = ", in);
    mpz_set_str(N, buf, 0);
    
    READ_BUF(buf, &lbuf, "e = ", in);
    mpz_set_str(e, buf, 0);
    return 1;
}

int read_secret_keys(mpz_t N, mpz_t d, FILE *in){
    char buf[BUF_LENGTH];
    size_t lbuf;
    
    READ_BUF(buf, &lbuf, "#", in);
    READ_BUF(buf, &lbuf, "N = ", in);
    mpz_set_str(N, buf, 0);
    
    READ_BUF(buf, &lbuf, "d = ", in);
    mpz_set_str(d, buf, 0);
    return 1;
}

int init_certificate(certificate_t *C){
    C->user = NULL;
    C->issuer = NULL;
    C->valid_from = 0;
    C->valid_to = 0;
    mpz_inits(C->N, C->e, C->signature, NULL);
    return 0;
}

int clear_certificate(certificate_t *C){
    free(C->user);
    free(C->issuer);
    mpz_clears(C->N, C->e, C->signature, NULL);
    return 0;
}

uchar *string_from_certificate(certificate_t *C){
    uchar msg[1024], *tmp;
    size_t len;

    /* TODO: do better, the lenght has to be computed and '\n' removed */
    gmp_sprintf((char *)msg,
		"NAME %s\nVALID-FROM %ld\nVALID-TO %ld\nISSUER %s\n"
		"KEY %#Zx %#Zx\nSIGNATURE %#Zx\n",
		C->user, C->valid_from, C->valid_to, C->issuer,
		C->N, C->e, C->signature);
    len = strnlen((char *)msg, 1024);
    tmp = (uchar *)malloc(len+1);
    strncpy((char *)tmp, (char *)msg, len+1);
    return tmp;
}

void print_certificate(certificate_t *C){
    uchar *msg = string_from_certificate(C);
    printf("%s", (char *)msg);
    free(msg);
}


void printf_certificate(char *file_name, certificate_t *C){
    uchar *msg = string_from_certificate(C);
    FILE *out = fopen(file_name, "w");
    fprintf(out, "%s", (char *)msg);
    fclose(out);
    free(msg);
	
}

void prepare_signature(buffer_t *prep, certificate_t *C){
    uchar msg[1024];
    size_t len;

    /* TODO: there should be a unique stringification function! */
    gmp_sprintf((char *)msg, "NAME %s\nVALID-FROM %ld\nVALID-TO %ld\n"
		"ISSUER %s\nKEY %#Zx %#Zx\n",
		C->user, C->valid_from, C->valid_to, C->issuer, C->N, C->e);
    len = strnlen((char *)msg, 1024);
    buffer_from_string(prep, msg, len + 1);
}

/* in should contain a header, followed by "N = *\n", "e = *\n" */
void create_certificate(certificate_t *C, const char *user, const char *issuer,
			mpz_t N, mpz_t d, FILE *in){
    time_t tt;
    struct tm tm;
    buffer_t msg;
    buffer_init(&msg, 1024);

    C->user = (char *)malloc(strlen(user)+1);
    strncpy(C->user, user, strlen(user)+1);
    C->issuer = (char *)malloc(strlen(issuer)+1);
    strncpy(C->issuer, issuer, strlen(issuer)+1);
    read_public_keys(C->N, C->e, in);
    tt = time(NULL);
    C->valid_from = tt;
    localtime_r(&tt, &tm);

    tm.tm_year += 1;

    //    strftime(buf, sizeof(buf), "%d %b %Y %H:%M", &tm);
    C->valid_to = mktime(&tm);

    prepare_signature(&msg, C);
    RSA_sign_buffer(C->signature, &msg, N, d);
    buffer_clear(&msg);
}

/* TODO: rename to certificate_from_file */
int extract_certificate(certificate_t *C, FILE *in){
    char buf[BUF_LENGTH], *tmp1, *tmp2;
    size_t lbuf;

    READ_BUF(buf, &lbuf, "NAME ", in);
    C->user = (char *)malloc(lbuf+1);
    strncpy(C->user, buf, lbuf+1);

    READ_BUF(buf, &lbuf, "VALID-FROM ", in);
    C->valid_from = atol(buf);
    READ_BUF(buf, &lbuf, "VALID-TO ", in);
    C->valid_to = atol(buf);

    READ_BUF(buf, &lbuf, "ISSUER ", in);
    C->issuer = (char *)malloc(lbuf+1);
    strncpy(C->issuer, buf, lbuf+1);

    fgets(buf, BUF_LENGTH, in);
    for(tmp1 = buf+4; *tmp1 != ' '; tmp1++);
    *tmp1 = '\0';
    mpz_set_str(C->N, buf+4, 0);
    for(tmp2 = tmp1+1; *tmp2 != '\n'; tmp2++);
    *tmp2 = '\0';
    mpz_set_str(C->e, tmp1+1, 0);

    READ_BUF(buf, &lbuf, "SIGNATURE ", in);
    mpz_set_str(C->signature, buf, 0);
    return 1;
}

/* TODO: do as in extract_certificate... */
int certificate_from_string(certificate_t *C, char* str){
    char *tmp1, *tmp2, *tmp3, buf[BUF_LENGTH];
    size_t lbuf;

#if 1
    /* extract from "NAME Francois MORAIN\n" */
    for(tmp1 = str; *tmp1 != '\n' ; tmp1++);
    lbuf = (size_t)(tmp1-str);
    strncpy(buf, str, lbuf);
    buf[lbuf++] = '\0';
    PARSE_BUF(buf, &lbuf, "NAME ");
    C->user = (char *)malloc(lbuf+1);
    strncpy(C->user, buf, lbuf);
    C->user[lbuf] = '\0';

    /* "VALID-FROM 1511877338" */
    ++tmp1;
    for(tmp2 = tmp1; *tmp2 != '\n'; tmp2++);
    lbuf = (size_t)(tmp2-tmp1);
    strncpy(buf, tmp1, lbuf);
    buf[lbuf++] = '\0';
    PARSE_BUF(buf, &lbuf, "VALID-FROM ");
    sscanf(buf, "%ld", &C->valid_from);

    /* "VALID-TO " */
    tmp1 = ++tmp2;
    for(tmp2 = tmp1; *tmp2 != '\n'; tmp2++);
    lbuf = 1 + (size_t)(tmp2-tmp1);
    strncpy(buf, tmp1, lbuf);
    buf[lbuf++] = '\0';
    PARSE_BUF(buf, &lbuf, "VALID-TO ");
    sscanf(buf, "%ld", &C->valid_to);
    
    /* extract from "ISSUER Francois MORAIN le plus bo\n" */
    tmp1 = ++tmp2;
    for(tmp2 = tmp1; *tmp2 != '\n'; tmp2++);
    lbuf = (size_t)(tmp2-tmp1);
    strncpy(buf, tmp1, lbuf);
    buf[lbuf++] = '\0';
    PARSE_BUF(buf, &lbuf, "ISSUER ");
    C->issuer = (char *)malloc(lbuf+1);
    strncpy(C->issuer, buf, lbuf);
    C->issuer[lbuf] = '\0';

    /* "KEY ..." */
    tmp1 = ++tmp2;
    for(tmp2 = tmp1; *tmp2 != '\n'; tmp2++);
    lbuf = (size_t)(tmp2-tmp1);
    strncpy(buf, tmp1, lbuf);
    buf[lbuf++] = '\0';
    PARSE_BUF(buf, &lbuf, "KEY ");
    /* there are two numbers N and e */
    for(tmp3 = buf; *tmp3 != ' '; tmp3++);
    *tmp3 = '\0';
    mpz_set_str(C->N, buf, 0);
    ++tmp3;
    mpz_set_str(C->e, tmp3, 0);
#if DEBUG > 0
    gmp_printf("N=%#Zx\ne=%#Zx\n", C->N, C->e);
#endif
    
    /* "SIGNATURE ... */
    tmp1 = ++tmp2;
    for(tmp2 = tmp1; *tmp2 != '\n'; tmp2++);
    lbuf = (size_t)(tmp2-tmp1);
    strncpy(buf, tmp1, lbuf);
    buf[lbuf++] = '\0';
    PARSE_BUF(buf, &lbuf, "SIGNATURE ");
    mpz_set_str(C->signature, buf, 0);
#if DEBUG > 0
    gmp_printf("Signature: %#Zx\n", C->signature);
#endif
#else
    /* extract from "NAME Francois MORAIN\n" */
    for(tmp1 = str   ; *tmp1 != ' ' ; tmp1++);
    ++tmp1;
    for(tmp2 = tmp1; *tmp2 != '\n'; tmp2++);
    lbuf = tmp2-tmp1;
    C->user = (char *)malloc(lbuf+1);
    strncpy(C->user, tmp1, lbuf);
    C->user[lbuf] = '\0';

    /* "VALID-FROM 1511877338" */
    ++tmp2;
    for(tmp1 = tmp2; *tmp1 != ' ' ; tmp1++);
    ++tmp1;
    sscanf(tmp1, "%ld", &C->valid_from);
    /* "VALID-TO " */
    for( ; *tmp1 != ' ' ; tmp1++);
    ++tmp1;
    sscanf(tmp1, "%ld", &C->valid_to);

    /* extract from "ISSUER Francois MORAIN le plus bo\n" */
    /* TODO: check for "ISSUER " */
    for( ; *tmp1 != ' ' ; tmp1++); /* skip ISSUER */
    ++tmp1;
    for(tmp2 = tmp1; *tmp2 != '\n'; tmp2++);
    lbuf = tmp2-tmp1;
    C->issuer = (char *)malloc(lbuf+1);
    strncpy(C->issuer, tmp1, lbuf);
    C->issuer[lbuf] = '\0';

    /* "KEY ..." */
    tmp1 = tmp2+1; /* tmp1 ready on "KEY */
    /* SAME TODO */
    for( ; *tmp1 != ' ' ; tmp1++); /* skip KEY */
    ++tmp1;
    for(tmp2 = tmp1; *tmp2 != ' '; tmp2++);
    *tmp2 = '\0';
    mpz_set_str(C->N, tmp1, 0);
    for( ; *tmp1 != '\0' ; tmp1++);
    *tmp1 = ' '; /* put back */
    ++tmp1;
    for(tmp2 = tmp1; *tmp2 != '\n'; tmp2++);
    *tmp2 = '\0';
    mpz_set_str(C->e, tmp1, 0);
#if DEBUG > 0
    gmp_printf("N=%#Zx\ne=%#Zx\n", C->N, C->e);
#endif
    for( ; *tmp1 != '\0' ; tmp1++);
    *tmp1 = '\n'; /* put back */

    /* "SIGNATURE ... */
    for(++tmp1 ; *tmp1 != ' ' ; tmp1++);
    for(tmp2 = tmp1; *tmp2 != '\n'; tmp2++);
    *tmp2 = '\0';
    mpz_set_str(C->signature, tmp1, 0);
#if DEBUG > 0
    gmp_printf("Signature: %#Zx\n", C->signature);
#endif
    *tmp2 = '\n';
#endif
    return 1;
}

int verify_date(certificate_t *C){
    time_t tt;
    char buf[255];
    int ok;

    tt = time(NULL);
    //    printf("time is %ld\n", tt);
    ctime_r(&tt, buf); 
    ok = C->valid_from <= tt && C->valid_to >= tt;
#if DEBUG > 0
    printf("buf=%s -> valid_date = %d\n", buf, ok);
#endif
    return ok;
}

/* make it not an oracle... */
int valid_certificate(certificate_t *C, mpz_t N, mpz_t e){
    buffer_t msg;
    buffer_init(&msg, 1024);
    prepare_signature(&msg, C);
    int ok = 1;
    
    /* check date */
    ok &= verify_date(C);
#if DEBUG > 0
    printf("[valid_certificate] ok1=%d\n", ok);
    gmp_printf("N:=%Zd; e:=%Zd;\n", N, e);
    buffer_print(stdout, &msg);
#endif
    /* check signature */
    ok &= RSA_verify_signature(C->signature, &msg, N, e);
#if DEBUG > 0
    printf("[valid_certificate] ok2=%d\n", ok);
#endif

    buffer_clear(&msg);
    return ok;
}

