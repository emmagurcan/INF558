#include <stdio.h>
#include <stdlib.h>

#include "utilities.h"

#include "gmp.h"
#include "buffer.h"
#include "rsa.h"
#include "text_rsa.h"

#define DEBUG 0

int lengths(int *block_length, int *cipher_length, int *last_block_size,
	    buffer_t *msg, mpz_t N){


    *block_length = (mpz_sizeinbase(N, 2) / 8) - 1;

    *cipher_length = msg->length / *block_length;

    *last_block_size = msg->length % *block_length;
    if (*last_block_size == 0)
        *last_block_size = *block_length;
    else
        (*cipher_length)++;

    return 1;
}

int RSA_text_encrypt(mpz_t *cipher, int block_length,
		     int cipher_length, int last_block_size,
		     buffer_t *msg, mpz_t N, mpz_t e){
    // cipher is a table of mpz_t of length cipher_length.
    // Memory allocation and initialisation of the cells is
    // already done.

    // block_length denotes the size of blocks of uchar's
    // which will partition the message.
    // last_block_size denotes the size of the last block. It may
    // be 0.

    //Import each block from the msg buffer and encrypt until last block
    mpz_t temp;
    mpz_init(temp);

    for (int i=0; i<cipher_length-1; i++){
        mpz_import(temp, block_length, 1, 1, 0, 0, (msg->tab)+i*block_length);
        RSA_encrypt(cipher[i], temp, N, e);
    }

    //Last block
    if (last_block_size == 0)
        last_block_size = block_length;

    mpz_import(temp, last_block_size, 1, 1, 0, 0, (msg->tab)+(cipher_length-1)*block_length);
    RSA_encrypt(cipher[cipher_length-1], temp, N, e);

    return 1;
}

int RSA_text_decrypt(buffer_t *decrypted, mpz_t *cipher,
		     int cipher_length, int block_length,
		     int last_block_size,
		     mpz_t N, mpz_t d){

    // buffer decrypted is supposed to be initialised.

    buffer_reset(decrypted);

    mpz_t msg;
    mpz_init(msg);

    size_t n;

    for (int i=0; i<cipher_length-1; i++){
        RSA_decrypt(msg, cipher[i], N, d);
        mpz_export((decrypted->tab)+(i*block_length), &n, 1, 1, 0, 0, msg);
        decrypted->length += n;
    }

    //Last block
    if (last_block_size == 0)
        last_block_size = block_length;

    RSA_decrypt(msg, cipher[cipher_length-1], N, d);
    mpz_export(decrypted->tab+(cipher_length-1)*block_length, &n, 1, 1, 0, 0, msg);
    decrypted->length += n;

    return 1;
}
