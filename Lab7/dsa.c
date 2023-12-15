#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "gmp.h"

#include "utilities.h"

#include "buffer.h"
#include "sha3.h"

#include "rsa.h"
#include "sign.h"
#include "dsa.h"

#define DEBUG 0

void generate_probable_prime(mpz_t p, int psize,
			     gmp_randstate_t state){
    do{
	mpz_rrandomb(p, state, psize);
	mpz_nextprime(p, p);
    }while(mpz_sizeinbase(p, 2) < psize);
}

int generate_pq(mpz_t p, mpz_t q, size_t psize, size_t qsize,
		gmp_randstate_t state){
    
    mpz_urandomb(q, state, qsize);
    mpz_nextprime(q, q);

    mpz_t multiple;
    mpz_init(multiple);
    mpz_set_ui(multiple, 1);

    mpz_mul_2exp(multiple, multiple, psize - qsize);

    mpz_mul(p, multiple, q);
    mpz_add_ui(p, p, 1);

    while (!mpz_probab_prime_p(p, 50)) {
        mpz_addmul_ui(p, q, 2);
    }

    mpz_clear(multiple);
    return 0;
}

int dsa_generate_keys(mpz_t p, mpz_t q, mpz_t a, mpz_t x, mpz_t y, size_t psize, size_t qsize, gmp_randstate_t state) {
    generate_pq(p, q, psize, qsize, state);
    mpz_t h;
    mpz_init(h);
    mpz_set_ui(h, 2);

    mpz_t temp;
    mpz_init(temp);
    mpz_set(temp, p);
    mpz_sub_ui(temp, temp, 1);
    mpz_fdiv_q(temp, temp, q);

    while (mpz_cmp(h, p) < 0) {
        mpz_powm(a, h, temp, p);
        if (mpz_cmp_ui(a,1) > 0) break;
        mpz_add_ui(h,h,1);
    }

    mpz_t range;
    mpz_init(range);
    mpz_sub_ui(range, q, 2);
    mpz_sub_ui(range, range, 1);
    mpz_urandomm(x, state, range);
    mpz_add_ui(x, x, 2);
    mpz_clear(range);

    mpz_powm(y, a, x, p);

    return 1;
}

void dsa_generate_key_files(const char* pk_file_name, const char* sk_file_name,
			    size_t psize, size_t qsize,
			    gmp_randstate_t state){
    // 1. INITS
    mpz_t p, q, a, x, y;
    mpz_inits(p, q, a, x, y, NULL);
    FILE* pk = fopen(pk_file_name, "w");
    FILE* sk = fopen(sk_file_name, "w");
	
    // 2. Key generation
    dsa_generate_keys(p, q, a, x, y, psize, qsize, state);

    // 3. Printing files
    fprintf(pk, "#DSA public key (%lu bits, %lu bits):\n", psize, qsize);
    gmp_fprintf(pk, "p = %#Zx\nq = %#Zx\na = %#Zx\ny = %#Zx\n", p, q, a, y);
    fprintf(sk, "#DSA Private Key (%lu bits, %lu bits):\n", psize, qsize);
    gmp_fprintf(sk, "p = %#Zx\nq = %#Zx\na = %#Zx\nx = %#Zx\n", p, q, a, x);
	
    // 4. Cleaning
    mpz_clears(p, q, a, x, y, NULL);
    fclose(pk);
    fclose(sk);
}


void dsa_key_import(const char* key_file_name, mpz_t p, mpz_t q, mpz_t a,
		    mpz_t xy){
    FILE* key = fopen(key_file_name, "r");
	
    // Go to second line, then move from 6 characters to the right
    while(fgetc(key) != '\n');
    fseek(key, 6, SEEK_CUR);

    // Scan the modulus p
    gmp_fscanf(key, "%Zx", p);

    // Same for q
    while(fgetc(key) != '\n');
    fseek(key, 6, SEEK_CUR);
    gmp_fscanf(key, "%Zx", q);

    // Same for a
    while(fgetc(key) != '\n');
    fseek(key, 6, SEEK_CUR);
    gmp_fscanf(key, "%Zx", a);

    // Same for x or y
    while(fgetc(key) != '\n');
    fseek(key, 6, SEEK_CUR);
    gmp_fscanf(key, "%Zx", xy);

    fclose(key);
}

int dsa_sign_buffer(buffer_t *msg, mpz_t p,
		    mpz_t q, mpz_t a, mpz_t x, mpz_t r, mpz_t s,
		    gmp_randstate_t state){

    size_t hash_len = hash_length(q);
    buffer_t hash;
    buffer_init(&hash, hash_len);
    buffer_hash(&hash, hash_len, msg);

    mpz_t hash_mpz;
    mpz_init(hash_mpz);
    mpz_import(hash_mpz, hash_len, 1, 1, 0, 0, hash.tab);

    mpz_set_ui(r, 0);
    mpz_set_ui(s, 0);

    mpz_t k, km;
    mpz_inits(k, km, NULL);
    mpz_set_ui(k, 0);

    while (mpz_cmp_ui(k, 0)==0){
        mpz_urandomm(k, state, q);
    }

    mpz_powm(r, a, k, p);
    mpz_mod(r, r, q);
    mpz_mul(s, x, r);
    mpz_add(s, s, hash_mpz);
    mpz_invert(km, k, q);
    mpz_mul(s, s, km);
    mpz_mod(s, s, q);
    mpz_clears(k, km, NULL);
    mpz_clear(hash_mpz);
    buffer_clear(&hash);

    return 1;
}


void dsa_sign(const char* file_name, const char* key_file_name,
	     const char* signature_file_name,
	     gmp_randstate_t state){
    // 1. Initialisation
    mpz_t p, q, a, x, r, s;
    buffer_t msg;
    mpz_inits(r, s, p, q, a, x, NULL);
    buffer_init(&msg, 100);
	
    // 2. Import the message
    buffer_from_file(&msg, file_name);
#if DEBUG
    printf("Length of the message = %lu.\n", msg.length);
#endif

    /* 3. Parse the secret key */
    dsa_key_import(key_file_name, p, q, a, x);
#if DEBUG > 0
    gmp_printf("p = %#Zx\nq = %#Zx\n", p, q);
#endif
	
    /* 4. Sign */
    dsa_sign_buffer(&msg, p, q, a, x, r, s, state);

    /* 5. Write signature in a file */
    FILE* sgn = fopen(signature_file_name, "w");
    gmp_fprintf(sgn, "#DSA signature:\nr = %#Zx\ns = %#Zx\n", r, s);
	
    /* . Cleaning */
    mpz_clears(p, q, a, x, r, s, NULL);
    fclose(sgn);
    buffer_clear(&msg);
}


int dsa_verify_buffer(buffer_t *msg, mpz_t p, mpz_t q,
		      mpz_t a, mpz_t r, mpz_t s, mpz_t y){
    size_t hash_len = hash_length(q);

    buffer_t hash;
    buffer_init(&hash, hash_len);
    buffer_hash(&hash, hash_len, msg);

    mpz_t hash_mpz;
    mpz_init(hash_mpz);
    mpz_import(hash_mpz, hash_len, 1, 1, 0, 0, hash.tab);
 
    mpz_t w;
    mpz_init(w);
    mpz_invert(w, s, q);

    mpz_t u1;
    mpz_init(u1);
    mpz_mul(u1, hash_mpz, w);
    mpz_mod(u1, u1, q);

    mpz_t u2;
    mpz_init(u2);
    mpz_mul(u2, r, w);
    mpz_mod(u2, u2, q);

    mpz_t v, a_u1, y_u2;
    mpz_init(v);
    mpz_init(a_u1);
    mpz_init(y_u2);

    mpz_powm(a_u1, a, u1, p);
    mpz_powm(y_u2, y, u2, p);
    mpz_mul(v, a_u1, y_u2);
    mpz_mod(v, v, p);
    mpz_mod(v, v, q);

    mpz_clears(hash_mpz, w, u1, u2, v, a_u1, y_u2, NULL);

    return 1;
}


void dsa_import_signature(mpz_t r, mpz_t s, const char* signature_file_name){
    FILE* sgn = fopen(signature_file_name, "r");
    while(fgetc(sgn) != '\n');
    fseek(sgn, 6, SEEK_CUR);
    gmp_fscanf(sgn, "%Zx", r);
	
    while(fgetc(sgn) != '\n');
    fseek(sgn, 6, SEEK_CUR);
    gmp_fscanf(sgn, "%Zx", s);
	
    fclose(sgn);
}


int dsa_verify(const char* file_name, const char* key_file_name,
	       const char* signature_file_name){
    // 1. INIT
    mpz_t p, q, a, y, r, s;
    buffer_t msg;
    mpz_inits(p, q, a, y, r, s, NULL);
    buffer_init(&msg, 100);
	
    // 2. Imports the message
    buffer_from_file(&msg, file_name);
	
    // 3. Parse the public key 
    dsa_key_import(key_file_name, p, q, a, y);

#if DEBUG > 0
    gmp_printf("\n\np = %#Zx\nq = %#Zx\n\n", p, q);
#endif
	
    // 4. Parse the signature 
    dsa_import_signature(r, s, signature_file_name);
    int verify = dsa_verify_buffer(&msg, p, q, a, r, s, y);
	
    // 5. Cleaning and return
    mpz_clears(p, q, a, y, r, s, NULL);
    buffer_clear(&msg);
    return verify;
}
