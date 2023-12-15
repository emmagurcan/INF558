#ifndef __FRS__SIGN

typedef unsigned char uchar;

void RSA_generate_key_files(const char *pk_file_name,
							const char *sk_file_name,
							size_t nbits, gmp_randstate_t state);
void RSA_key_import(mpz_t N, mpz_t ed, const char *pk_file_name);
void RSA_signature_import(mpz_t S, const char* signature_file_name);
int hash_length(mpz_t N);
void RSA_sign_buffer(mpz_t sgn, buffer_t *msg,
				 mpz_t N, mpz_t d);
int RSA_verify_signature(mpz_t sgn, buffer_t *msg,
							mpz_t N, mpz_t e);
void RSA_sign(const char* file_name, const char* key_file_name,
			  const char* signature_file_name);
int RSA_verify(const char* file_name, const char* key_file_name,
			   const char* signature_file_name);

#define __FRS__SIGN
#endif
