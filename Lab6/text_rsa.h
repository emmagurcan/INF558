int lengths(int *block_length, int *cipher_length, int *last_block_size,
	    buffer_t *msg, mpz_t N);
int RSA_text_encrypt(mpz_t *cipher, int block_length,
		     int cipher_length, int last_block_size,
		     buffer_t *msg, mpz_t N, mpz_t e);
int RSA_text_decrypt(buffer_t *decrypted, mpz_t *cipher,
		     int cipher_length, int block_length,
		     int last_block_size, mpz_t N, mpz_t d);
