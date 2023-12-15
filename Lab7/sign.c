#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "gmp.h"

#include "utilities.h"

#include "buffer.h"
#include "sha3.h"
#include "rsa.h"
#include "sign.h"

#define DEBUG 0


int RSA_generate_key_files(const char *pk_file_name,
			   const char *sk_file_name,
			   size_t nbits, int sec, gmp_randstate_t state){
    mpz_t n, e, d, p, q;
    mpz_inits(n, e, d, p, q, NULL);

    mpz_urandomb(p, state, nbits/2);
    mpz_nextprime(p, p);
    mpz_urandomb(q, state, nbits/2);
    mpz_nextprime(q, q);

    mpz_mul(n, p, q);
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, p, 1);
    mpz_mul(e, p, q);
    mpz_add_ui(e, e, 1);
    mpz_invert(d, e, n);

    FILE *fpublic = fopen(pk_file_name, "w");
    fprintf(fpublic, "#RSA Public key (%zu bits):\n", nbits);
    gmp_fprintf(fpublic, "N = %#Zx\ne = %#Zx\n", n, e);
    fclose(fpublic);

    FILE *fsecret = fopen(sk_file_name, "w");
    fprintf(fsecret, "#RSA Secret key (%zu bits):\n", nbits);
    gmp_fprintf(fsecret, "N = %#Zx\nd = %#Zx\n", n, d);
    fclose(fsecret);

    mpz_clears(n, e, d, p, q, NULL);

    return 1;
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


int RSA_sign_buffer(mpz_t sgn, buffer_t *msg,
		    mpz_t N, mpz_t d){
    size_t hash_len = hash_length(N);

    buffer_t hash;
    buffer_init(&hash, hash_len);
    buffer_hash(&hash, hash_len, msg);

    mpz_t hash_mpz;
    mpz_init(hash_mpz);
    mpz_import(hash_mpz, hash_len, 1, 1, 1, 0, hash.tab);

    mpz_powm(sgn, hash_mpz, d, N);

    buffer_clear(&hash);
    mpz_clear(hash_mpz);

    return 1;
}

int RSA_verify_signature(mpz_t sgn, buffer_t *msg,
			 mpz_t N, mpz_t e){

    size_t hash_len = hash_length(N);

    buffer_t hash;
    buffer_init(&hash, hash_len);
    buffer_hash(&hash, hash_len, msg);

    mpz_t hash_mpz;
    mpz_init(hash_mpz);
    mpz_import(hash_mpz, hash_len, 1, 1, 1, 0, hash.tab);
    mpz_powm(sgn, sgn, e, N);
    int result = mpz_cmp(sgn, hash_mpz) == 0;

    buffer_clear(&hash);
    mpz_clear(hash_mpz);
    return result;
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
    int status = RSA_sign_buffer(signature, &msg, N, d);
    implementation_check("RSA_sign_buffer", status);

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
    implementation_check("RSA_verify_signature", verify);
	
    // 6. Close, free and return
    mpz_clears(S, N, e, NULL);
    buffer_clear(&msg);
    return verify;
}
