int Hastad(mpz_t decrypted, mpz_t* cipher_texts, mpz_t* moduli, int exponent);
void parse_challenge(const char *file_name, int exponent, mpz_t *moduli,
		     mpz_t *cipher_texts);
