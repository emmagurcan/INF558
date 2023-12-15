/**************************************************************/
/* operating_modes.c                                          */
/* Author: Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Last modification October 8, 2018                          */
/**************************************************************/

#include <stdlib.h>
#include <stdio.h>

#include "gmp.h"
#include "base64.h"
#include "buffer.h"
#include "bits.h"
#include "aes.h"
#include "sha3.h"
#include "operating_modes.h"

#define DEBUG 0


void pad(buffer_t *padded, buffer_t *in, char mode){
    buffer_reset(padded);
    if(mode != 's' && mode != 'R'){
	perror("[pad] ERROR: mode should be either 's' or 'R' (''standard'' or ''RFC202'') \n");
	return;
    }

    buffer_append(padded, in);
    if(mode == 's'){
	buffer_append_uchar(padded, (1 << (BYTE_SIZE - 1)));
	int a = (int)(BLOCK_LENGTH - (in->length) % BLOCK_LENGTH), i;
	for(i = 0; i < a - 1; i++)
	    buffer_append_uchar(padded, 0);
    }
    if(mode == 'R'){
	uchar a = (uchar)(BLOCK_LENGTH - (in->length % BLOCK_LENGTH));
	int i;
	for(i = 0; i < a; i++)
	    buffer_append_uchar(padded, a);
    }
#if DEBUG
    printf("[pad]: length of padded: %d.\tLength of padded mod %d: %d\n",
	   (int)(padded->length), BLOCK_LENGTH,
	   (int)(padded->length) % BLOCK_LENGTH);
#endif
}


void extract(buffer_t *out, buffer_t *padded, char mode){
    buffer_reset(out);
    if(padded->length % BLOCK_LENGTH != 0){
	perror("[pad] The length of the padded message is inaccurate.\n");
	return;
    }

    size_t l = padded->length - 1;
    uchar *cursor = padded->tab + l;
    if(mode == 's'){
	while(*cursor != 1 << (BYTE_SIZE - 1)){
	    l--;
	    cursor--;
	}
    }
    else if(mode == 'R'){
	uchar a = *cursor;
	int i;
	l -= a-1;
	cursor--;
	for(i = 1; i < a; i++, cursor--){
	    if(*cursor != a){
		perror("[extract] ERROR: the padded message is not valid (mode RFC2040).\n");
		return;
	    }
	}
    }
    else{
	perror("[pad] ERROR: mode should be either 's' or 'R' (''standard'' or ''RFC202'') \n");
	return;
    }
    cursor = padded->tab;
    size_t i;
    for(i = 0; i < l; i++, cursor++)
	buffer_append_uchar(out, *cursor);
}

// CBC Mode, the input should have length which is a multiple of 16
int aes_raw_CBC_encrypt(buffer_t *encrypted, buffer_t *in, buffer_t *key, buffer_t *IV){
    buffer_reset(encrypted);
    if(in->length % BLOCK_LENGTH != 0){
	perror("[aes_raw_CBC_encrypt]: The input has not been padded.\n");
	return 0;
    }
    // 1. Initialisation
    buffer_t to_Xor;
    buffer_t tmp_in;
    buffer_t tmp_out;
    buffer_init(&to_Xor, BLOCK_LENGTH);
    buffer_init(&tmp_in, BLOCK_LENGTH);
    buffer_init(&tmp_out, BLOCK_LENGTH);

    // 2. Initialise to_Xor with IV and put IV on the begginning of encrypted
    buffer_append(&to_Xor, IV);
    buffer_append(encrypted, IV);

    // 3. Main Loop
    uchar *cursor = in->tab;	
    int i, j;
    for(i = 0; i < in->length / BLOCK_LENGTH; i++){
#if DEBUG
	printf("[aes_raw_CBC_encrypt] Treating block number %d.\t Length of encrypted = %d.\n",
	       i, (int)encrypted->length);	
#endif
	// 3.1. Copy plain_text in tmp_in
	for(j = 0; j < BLOCK_LENGTH; j++, cursor++)
	    buffer_append_uchar(&tmp_in, *cursor);

	// 3.2. Xor tmp_in with to_Xor
	oneTimePad(&tmp_out, &tmp_in, &to_Xor);

	// 3.3. Encrypt
	aes_block_encrypt(&to_Xor, &tmp_out, key);

	// 3.4. Prepare next loop
	buffer_reset(&tmp_in);
	buffer_append(encrypted, &to_Xor);
    }

    // 4. Free Memory
    buffer_clear(&tmp_in);
    buffer_clear(&tmp_out);
    buffer_clear(&to_Xor);
    return 1;
}


int aes_raw_CBC_decrypt(buffer_t *decrypted, buffer_t *in, buffer_t *key){
    buffer_reset(decrypted);
    if(in->length % BLOCK_LENGTH != 0){
#if DEBUG == 0
	perror("[aes_raw_CBC_decrypt]: The input is not a valid cipher text.\n");
#else
	fprintf(stderr,
		"[aes_raw_CBC_decrypt]: in->length=%lu not a multiple of %d.\n",
		in->length, BLOCK_LENGTH);
#endif
	return 0;
    }
    // 1. Initialisation
    buffer_t to_Xor;
    buffer_t tmp_in;
    buffer_t tmp_dec;
    buffer_t tmp_out;
    buffer_init(&to_Xor, BLOCK_LENGTH);
    buffer_init(&tmp_in, BLOCK_LENGTH);
    buffer_init(&tmp_dec, BLOCK_LENGTH);
    buffer_init(&tmp_out, BLOCK_LENGTH);

    // 2. Initialise the to_Xor with IV
    uchar *cursor = in->tab;
    int i, j;
    for(i = 0; i < BLOCK_LENGTH; i++, cursor++)
	buffer_append_uchar(&to_Xor, *cursor);
	
    // 3. Main loop
    for(i = 1; i < in->length / BLOCK_LENGTH; i++){
#if DEBUG
	printf("[aes_raw_CBC_decrypt] Treating block number %d.\t Length of decrypted = %d.\n",
	       i, (int)decrypted->length);	
#endif
	// 3.1 Copy encrypted in tmp_in
	for(j = 0; j < BLOCK_LENGTH; j++, cursor++)
	    buffer_append_uchar(&tmp_in, *cursor);

	// 3.2. Decrypt
	aes_block_decrypt(&tmp_dec, &tmp_in, key);

	// 3.3. Xor
	oneTimePad(&tmp_out, &tmp_dec, &to_Xor);

	// 3.4 Finish the loop
	buffer_clone(&to_Xor, &tmp_in);
	buffer_append(decrypted, &tmp_out);
	buffer_reset(&tmp_in);
    }	

    // 4. Free Memory
    buffer_clear(&tmp_in);
    buffer_clear(&tmp_dec);
    buffer_clear(&tmp_out);
    buffer_clear(&to_Xor);
    return 1;
}


int aes_CBC_encrypt(buffer_t *encrypted, buffer_t *plain, buffer_t *key,
		    buffer_t *IV, char mode){
    if(key->length != BLOCK_LENGTH || IV->length != BLOCK_LENGTH){
#if DEBUG == 0
	perror("[aes_CBC_encrypt] ERROR: Key or IV do not have the good length.\n");
#else
	if(key->length != BLOCK_LENGTH)
	    fprintf(stderr,
		    "[aes_CBC_encrypt] ERROR: Key does not have the good "
		    "length %lu instead of %d\n", key->length, BLOCK_LENGTH);
	if(IV->length != BLOCK_LENGTH)
	    fprintf(stderr,
		    "[aes_CBC_encrypt] ERROR: IV does not have the good "
		    "length %lu instead of %d\n", IV->length, BLOCK_LENGTH);
#endif
	return 0;
    }

    // 1. Initialisation
    buffer_reset(encrypted);
    buffer_t padded, raw, hash;
    buffer_init(&padded, BLOCK_LENGTH);
    buffer_init(&raw, BLOCK_LENGTH);
    buffer_init(&hash, HASH_LENGTH);

    // 2. Start
    buffer_append(encrypted, IV);

    // 3. Padding and encryption
    pad(&padded, plain, mode);
    aes_raw_CBC_encrypt(&raw, &padded, key, IV);
    buffer_append(encrypted, &raw);

    // 4. Mac
    buffer_hash(&hash, HASH_LENGTH, encrypted);
    buffer_append(encrypted, &hash);
	
    // . Free Memory
    buffer_clear(&padded);
    buffer_clear(&raw);
    buffer_clear(&hash);
    return 1;
}


int aes_CBC_decrypt(buffer_t *decrypted, buffer_t *encrypted, buffer_t *key,
		     char mode){
    if(key->length != BLOCK_LENGTH){
	perror("[aes_CBC_decrypt] ERROR: Key does not have the good length.\n");
	return 0;
    }
    if(encrypted->length % BLOCK_LENGTH != 0){
#if DEBUG == 0
	perror("[aes_CBC_decrypt] ERROR: Input is not a valid ciphertext.\n");
#else
	fprintf(stderr,
		"[aes_raw_CBC_decrypt]: enc->length=%lu "
		"not a multiple of %d.\n",
		encrypted->length, BLOCK_LENGTH);
#endif
	return 0;
    }

    // 1. Initialisation
    buffer_t IV, IV_cat_raw, raw, padded, hash, hash_test;
    buffer_init(&IV, BLOCK_LENGTH);
    buffer_init(&IV_cat_raw, BLOCK_LENGTH);
    buffer_init(&raw, BLOCK_LENGTH);
    buffer_init(&padded, BLOCK_LENGTH);
    buffer_init(&hash, HASH_LENGTH);
    buffer_init(&hash_test, HASH_LENGTH);

    // 2. Fill in buffers
    int i = 0;
    uchar *cursor = encrypted->tab;
    for(; i < BLOCK_LENGTH; i++, cursor++){
	buffer_append_uchar(&IV, *cursor);
	buffer_append_uchar(&IV_cat_raw, *cursor);
    }

    for(; i < encrypted->length - HASH_LENGTH; i++, cursor++){
	buffer_append_uchar(&raw, *cursor);
	buffer_append_uchar(&IV_cat_raw, *cursor);
    }

    for(; i < encrypted->length; i++, cursor++)
	buffer_append_uchar(&hash, *cursor);

    // 3. Verification of integrity
    buffer_hash(&hash_test, HASH_LENGTH, &IV_cat_raw);
    if(!buffer_equality(&hash_test, &hash)){
	perror("[aes_CBC_decrypt] ERROR: hash values differ.\n");
	return 0;
    }

    // 4. Decrypt
    aes_raw_CBC_decrypt(&padded, &raw, key);
    extract(decrypted, &padded, mode);		
	
    // 5. Free memory
    buffer_clear(&IV);
    buffer_clear(&raw);
    buffer_clear(&IV_cat_raw);
    buffer_clear(&padded);
    buffer_clear(&hash);
    buffer_clear(&hash_test);
    return 1;
}
