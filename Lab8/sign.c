#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "gmp.h"

#include "buffer.h"
#include "sha3.h"
#include "rsa.h"
#include "sign.h"

#define DEBUG 0


void RSA_generate_key_files(const char *pk_file_name,
			    const char *sk_file_name,
			    size_t nbits, gmp_randstate_t state){
    mpz_t N, p, q, e, d;
    mpz_inits(N, p, q, e, d, NULL);

    FILE *pk = fopen(pk_file_name, "w");
    FILE *sk = fopen(sk_file_name, "w");
    fprintf(pk, "#RSA Public key (%ld bits):\nN = ", nbits);
    fprintf(sk, "#RSA Secret key (%ld bits):\nN = ", nbits);
	
    RSA_generate_key(N, p, q, d, e, nbits, state);
	
#if DEBUG > 0
    gmp_printf("N = 0x%Zx \np = 0x%Zx \nq = 0x%Zx\n", N, p, q);
#endif
	
    gmp_fprintf(pk, "%#Zx\ne = %#Zx\n", N, e);
    gmp_fprintf(sk, "%#Zx\nd = %#Zx\n", N, d);
	
    fclose(pk);
    fclose(sk);
    mpz_clears(N, p, q, e, d, NULL);
}


void RSA_key_import(mpz_t N, mpz_t ed, const char *key_file_name){
    FILE *key = fopen(key_file_name, "r");
    /* Go to second line, then move from 6 characters to the right */
    while(fgetc(key) != '\n');
    fseek(key, 6, SEEK_CUR);

    /* Scan the modulus N */
    gmp_fscanf(key, "%Zx", N);

    /* Same for e or d*/
    while(fgetc(key) != '\n');
    fseek(key, 6, SEEK_CUR);
    gmp_fscanf(key, "%Zx", ed);

    fclose(key);
}


int hash_length(mpz_t N){
    int bit_size_N = mpz_sizeinbase(N, 2);
    return (bit_size_N % BYTE_SIZE == 0) ?
	bit_size_N / BYTE_SIZE - 1 : (bit_size_N / BYTE_SIZE);
}


void RSA_sign_buffer(mpz_t sgn, buffer_t *msg,
		     mpz_t N, mpz_t d){
    // 0. Init
    int length = hash_length(N);
    buffer_t hash;
    mpz_t mpz_hash;
    buffer_init(&hash, length);
    mpz_init(mpz_hash);
	
    // 1. Hash and export as an mpz_t
    buffer_hash(&hash, length, msg);

#if DEBUG
    {
	int i;
	printf("hash length = %d\n", length);
	printf("Hash :\n");
	for(i = 0; i < length; i++){
	    if(i%10 == 0 && i > 0)
		printf("\n");
	    printf("%#x ", hash.tab[i]);
	}
	printf("\n\n");
    }
#endif
	
    mpz_import(mpz_hash, length, 1, 1, 1, 0, hash.tab);

#if DEBUG
    gmp_printf("GMP-ized hash :\n%#Zx\n\n", mpz_hash);
#endif
	
	
    // 2. Sign 
    RSA_decrypt(sgn, mpz_hash, N, d);

	
    // 3. Free Memory
    mpz_clear(mpz_hash);
    buffer_clear(&hash);
}


int RSA_verify_signature(mpz_t sgn, buffer_t *msg,
			 mpz_t N, mpz_t e){
    int length = hash_length(N);
    buffer_t hash, hash2;
    mpz_t mpz_hash;
    mpz_init(mpz_hash);
    buffer_init(&hash, length+1); // when signature is wrong, valgrind complains with invalid write by 1 byte ...
    buffer_init(&hash2, length);
	
    RSA_encrypt(mpz_hash, sgn, N, e);
#if DEBUG > 0
    gmp_printf("GMP-ized hash in verification :\n%#Zx\n\n", mpz_hash);
#endif
	
    mpz_export(hash.tab, NULL, 1, 1, 1, 0, mpz_hash);
    hash.length = length;
    buffer_hash(&hash2, length, msg);
    int verify = buffer_equality(&hash, &hash2);
	
    buffer_clear(&hash);
    buffer_clear(&hash2);
    mpz_clear(mpz_hash);
    return verify;
}


void RSA_signature_import(mpz_t S, const char* signature_file_name){
    FILE *sgn = fopen(signature_file_name, "r");
    while(fgetc(sgn) != '\n');
    fseek(sgn, 6, SEEK_CUR);
    gmp_fscanf(sgn, "%Zx", S);
    fclose(sgn);
}


void RSA_sign(const char* file_name, const char* key_file_name,
	      const char* signature_file_name){
    // 1. Initialisation
    buffer_t msg;
    mpz_t N, d, signature;
    mpz_inits(N, d, signature, NULL);
    buffer_init(&msg, 100);

    // 2. Import the message in a buffer
    buffer_from_file(&msg, file_name);
	
    // 3. Parse the secret key
    RSA_key_import(N, d, key_file_name);

    // 4. Sign the buffer
    RSA_sign_buffer(signature, &msg, N, d);

    // 5. Exports the signature in a file
    FILE* sgn = fopen(signature_file_name, "w");
    gmp_fprintf(sgn, "#RSA signature\nS = %#Zx\n", signature);
	
    // 6. Close and free
    fclose(sgn);
    mpz_clears(N, d, signature, NULL);
    buffer_clear(&msg);
}


int RSA_verify(const char* file_name, const char* key_file_name,
	       const char* signature_file_name){
    // 1. Initialisation
    buffer_t msg;
    mpz_t N, e, S;	
    buffer_init(&msg, 100);
    mpz_inits(N, e, S, NULL);	

	
    // 2. Import the message into a buffer
    buffer_from_file(&msg, file_name);

    // 3. Import the public key
    RSA_key_import(N, e, key_file_name);

    // 4. Parse the signature
    RSA_signature_import(S, signature_file_name);
	
    // 5. Verify
    int verify = RSA_verify_signature(S, &msg, N, e);
	
    // 6. Close, free and return
    mpz_clears(S, N, e, NULL);
    buffer_clear(&msg);
    return verify;
}
