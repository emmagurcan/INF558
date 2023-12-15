int is_valid_key(mpz_t p, mpz_t q, mpz_t e, mpz_t d, int nlen, int sec);
int RSA_generate_key(mpz_t N, mpz_t p, mpz_t q, mpz_t e, mpz_t d,
		      int nlen, int sec, gmp_randstate_t state);
int RSA_encrypt(mpz_t cipher, mpz_t msg, mpz_t N, mpz_t e);
int RSA_decrypt(mpz_t msg, mpz_t cipher, mpz_t N, mpz_t d);
int RSA_decrypt_with_p_q(mpz_t msg, mpz_t cipher, mpz_t N, mpz_t d,
						  mpz_t p, mpz_t q);
void RSA_dummy_generate_key(mpz_t N, mpz_t e, int nlen,
			    gmp_randstate_t state);
