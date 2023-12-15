int dsa_sign_dummy(buffer_t *msg, mpz_t p,
		   mpz_t q, mpz_t a, mpz_t x, mpz_t r, mpz_t s,
		   mpz_t k);
int solve_system_modq(mpz_t x, mpz_t r1, mpz_t s1,
		      mpz_t r2, mpz_t s2, mpz_t h1, mpz_t h2,
		      mpz_t q);
int dsa_attack(mpz_t x, buffer_t *msg1, buffer_t *msg2,
	       mpz_t p, mpz_t q, mpz_t a, mpz_t r1,
	       mpz_t s1, mpz_t r2, mpz_t s2);
