#ifndef __FRS__CERTIFICATE

typedef struct{
    char *user, *issuer;
    long valid_from, valid_to;
    mpz_t N, e, signature;
} certificate_t;

int read_public_keys(mpz_t N, mpz_t e, FILE *in);
int read_secret_keys(mpz_t N, mpz_t d, FILE *in);

int init_certificate(certificate_t *C);
int clear_certificate(certificate_t *C);
void print_certificate(certificate_t *C);
void printf_certificate(char *file_name, certificate_t *C);

uchar *string_from_certificate(certificate_t *C);
void create_certificate(certificate_t *C, const char *name, const char *issuer, mpz_t N, mpz_t d, FILE *in);
int extract_certificate(certificate_t *C, FILE *in);
int certificate_from_string(certificate_t *C, char* str);
int valid_certificate(certificate_t *C, mpz_t N, mpz_t e);

#define __FRS__CERTIFICATE
#endif
