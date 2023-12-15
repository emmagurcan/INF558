int generate_pq(mpz_t p, mpz_t q, size_t psize, size_t qsize,
		gmp_randstate_t state);
int dsa_generate_keys(mpz_t p, mpz_t q, mpz_t x, mpz_t y, mpz_t a,
		      size_t psize, size_t qsize,
		      gmp_randstate_t state);
void dsa_generate_key_files(const char* pk_file_name,
			    const char* sk_file_name,
			    size_t psize, size_t qsize,
			    gmp_randstate_t state);
void dsa_key_import(const char* key_file_name, mpz_t p, mpz_t q,
		    mpz_t a, mpz_t xy);
int dsa_sign_buffer(buffer_t *msg, mpz_t p,
		    mpz_t q, mpz_t a, mpz_t x, mpz_t r, mpz_t s,
		    gmp_randstate_t state);
void dsa_sign(const char* file_name, const char* key_file_name,
	     const char* signature_file_name,
	     gmp_randstate_t state);
int dsa_verify_buffer(buffer_t *msg, mpz_t p, mpz_t q,
		      mpz_t a, mpz_t r, mpz_t s, mpz_t y);
int dsa_verify(const char* file_name, const char* key_file_name,
	       const char* signature_file_name);
