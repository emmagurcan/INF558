/*************************************************************
attack_RFC_2040.c
author Alain Couvreur : alain.couvreur@lix.polytechnique.fr
Last modification : October 8, 2018

**************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "buffer.h"
#include "sha3.h"
#include "aes.h"
#include "operating_modes.h"
#include "attack_RFC2040.h"

#define DEBUG 1

// Returns 1 if the cipher text is valid and had been padded with
//   RFC2040 
//   Else return 0.
//   If the cipher text has not the good length, returns -1. 
int oracle(buffer_t *encrypted, buffer_t *key){
    if(encrypted->length % BLOCK_LENGTH != 0){
	perror("[oracle] ERROR : cipher text has not a valid length.\n");
	return -1;
    }

    buffer_t decrypted;
    buffer_init(&decrypted, encrypted->length - BLOCK_LENGTH);	
    aes_raw_CBC_decrypt(&decrypted, encrypted, key);
	
    uchar *cursor = decrypted.tab + decrypted.length - 1;
    uchar a = *cursor;
    if(a == 0 || a > BLOCK_LENGTH){
	buffer_clear(&decrypted);
	return 0;
    }
    cursor--;
    int result = 1;

    for(int i = 1; i < a; i++, cursor--){
	if(*cursor != a){
	    result = 0;
	    break;
	}
    }
	
    buffer_clear(&decrypted);
    return result;
}



/* Returns the position of the first byte of padding */
/* in the last block of the encrypted_text           */
int get_padding_position(buffer_t *encrypted, buffer_t *key){
      if (encrypted->length % BLOCK_LENGTH != 0 || encrypted->length / BLOCK_LENGTH < 2) {
        perror("[get_padding_position] ERROR: cipher text has not a valid length.\n");
        return -1;
    }

    if (!oracle(encrypted, key)) {
        perror("[get_padding_position] ERROR: input is not a valid ciphertext.\n");
        return -1;
    }
    int i_init=encrypted->length-32;
    int i=0;
    buffer_t enc2;
    int length = encrypted->length;
    buffer_init(&enc2, length);
    buffer_flip_bit(&enc2, encrypted, (i_init+i)*8);
    while (oracle(&enc2, key) == 1){
        i++;
        buffer_flip_bit(&enc2, encrypted, (i_init+i)*8);
    }
    return i;
 
}


int prepare(buffer_t *corrupted, buffer_t *encrypted, buffer_t *decrypted,
	    int known_positions){
    /* encrypted has length a * BLOCK_LENGTH + 1
       decrypted has length a * BLOCK_LENGTH.
       CAUTION : encrypted has one block more than decrypted
       because of the IV that is its leftmost block

       decrypted contains the exact entries of the padded plaintext
       from position known_positions - BLOCK_LENGTH to the last one.
       Equivalently, on encrypted, bytes after position known_positions
       are known.
    */
	
    buffer_clone(corrupted, encrypted);
    int a = BLOCK_LENGTH - (known_positions % BLOCK_LENGTH);

    for (int i = 0; i < BLOCK_LENGTH; i++) {
        if (i >= (BLOCK_LENGTH - a)) {
            corrupted->tab[corrupted->length - 2 * BLOCK_LENGTH + i] =
                decrypted->tab[known_positions - BLOCK_LENGTH + i] ^ (uchar)(a + 1);
        }
        else {
            corrupted->tab[corrupted->length - 2 * BLOCK_LENGTH + i] = encrypted->tab[i];
        }
    }
    corrupted->tab[corrupted->length - 2 * BLOCK_LENGTH + (BLOCK_LENGTH - (a + 1))] ^= (uchar)(a + 1);

    return 0;

}


int find_last_byte(uchar *hack, buffer_t *corrupted, int position, buffer_t *key){
    if(corrupted->length < 2 * BLOCK_LENGTH){
        perror("[find_last_byte] ERROR : cipher_text is too short.\n");
        *hack = 0;
        return 0;
    }
    if(corrupted->length % BLOCK_LENGTH != 0){
        perror("[find_last_byte] ERROR : not a valid cipher text.\n");
        *hack = 0;
        return 0;
    }	

    uchar original_byte = corrupted->tab[position];

    for (int x = 0; x <= 255; x++) {
        corrupted->tab[position] = original_byte ^ (uchar)x;
        if (oracle(corrupted, key) == 1) {
            *hack = (uchar)x;
            return 1;
        }
    }

    perror("[find_the_last_byte] : failed to return the good byte");
    return 0;
}

int full_attack(buffer_t *decrypted, buffer_t *encrypted, buffer_t *key) {
    buffer_t corrupted;
    buffer_init(decrypted, encrypted->length);

    for (int i = encrypted->length - 1; i >= 0; i--) {
        uchar a = encrypted->length - i;
        int known_positions = encrypted->length - i;
        prepare(&corrupted, encrypted, known_positions, a);
        find_last_byte((uchar) i, &corrupted, known_positions, &key);
        buffer_clear(&corrupted);
    }

    int padding = decrypted->tab[decrypted->length - 1];
    decrypted->length -= padding;
    return 0;
}
