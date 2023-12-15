#define BYTE_SIZE 8

int is_valid_key(mpz_t p, mpz_t q, mpz_t e, mpz_t d, int nlen, int sec);
void RSA_generate_key(mpz_t N, mpz_t p, mpz_t q, mpz_t e, mpz_t d,
					  int nlen, int sec, gmp_randstate_t state);
void RSA_encrypt(mpz_t cipher, mpz_t msg, mpz_t N, mpz_t e);
void RSA_decrypt(mpz_t msg, mpz_t cipher, mpz_t N, mpz_t d);
void RSA_dummy_generate_key(mpz_t N, mpz_t e, int nlen,
							gmp_randstate_t state);
