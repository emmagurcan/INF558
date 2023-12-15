/*************************************************************
testEx3.c
author Alain Couvreur : alain.couvreur@lix.polytechnique.fr
author FM
author Matthieu Lequesne
Last modification : October 05, 2023

**************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "buffer.h"
#include "random.h"
#include "sha3.h"
#include "aes.h"
#include "operating_modes.h"
#include "attack_RFC2040.h"

#define DEBUG 1

/* What a trick! */
static void implementation_check(const char *fctname, int n){
    if(n == -42){
	printf("\nWARNING: presumably, the function \"%s\" is"
	       " not programmed yet; exiting.\n", fctname);
	exit(-1);
    }
}

void test_oracle(){
    // 1. Initialisation
    buffer_t key, msg, padded, encrypted, IV;
    buffer_init(&key, BLOCK_LENGTH);
    buffer_init(&IV, BLOCK_LENGTH);
    buffer_init(&msg, BLOCK_LENGTH);
    buffer_init(&padded, BLOCK_LENGTH);
    buffer_init(&encrypted, BLOCK_LENGTH);

    // 2. Fill in buffers
    aes_key_generation(&key, BLOCK_LENGTH);
    buffer_random(&IV, BLOCK_LENGTH);
    buffer_from_string(&msg, (uchar *)"Is there a problem with Earth's gravitational pull in the future? Why is everything so heavy?", -1);
    pad(&padded, &msg, 'R');

#if DEBUG
    printf("[test_oracle | DEBUG mode] : padded :\n");
    buffer_print_int(stdout, &padded);
    printf("\n\n");
#endif

	
    // 3. Encrypt
    aes_raw_CBC_encrypt(&encrypted, &padded, &key, &IV);

    // 4. Test oracle on valid cipher
    printf("\nTest oracle on valid cipher : ");
    if(oracle(&encrypted, &key))
	printf("\t\t[OK]\n");
    else
	printf("\t\t[FAILED]\n");

    // 5. Test oracle on invalid cipher :
    encrypted.tab[encrypted.length - 1] = 1;
    printf("\nTest oracle on in-valid cipher : ");
    if(!oracle(&encrypted, &key))
	printf("\t[OK]\n\n");
    else
	printf("\t\t[FAILED]\n\n");
	
	
    // 6. Free Memory
    buffer_clear(&key);
    buffer_clear(&IV);
    buffer_clear(&msg);
    buffer_clear(&padded);
    buffer_clear(&encrypted);	
}


void test_get_padding_position(){
    // 1. Initialisation
    buffer_t plain, padded, encrypted, encrypted_2, key, IV;
    buffer_init(&plain, 3 * BLOCK_LENGTH);
    buffer_init(&padded, 3 * BLOCK_LENGTH);	
    buffer_init(&encrypted, 4 * BLOCK_LENGTH);
    buffer_init(&encrypted_2, 4 * BLOCK_LENGTH);
    buffer_init(&key, BLOCK_LENGTH);
    buffer_init(&IV, BLOCK_LENGTH);
	
    // 2. Fill in buffers
    aes_key_generation(&key, BLOCK_LENGTH);
    buffer_random(&IV, BLOCK_LENGTH);
    int pad_position;

    // 3. Loop
    for(int a = 1; a <= BLOCK_LENGTH; a++){
	buffer_random(&plain, 3 * BLOCK_LENGTH - a);
	pad(&padded, &plain, 'R');
	aes_raw_CBC_encrypt(&encrypted, &padded, &key, &IV);
	aes_raw_CBC_encrypt(&encrypted_2, &padded, &key, &IV);

#if DEBUG
	printf("-----\n[test_get_padding_position] :\nLength of plain = %ld.",
	       plain.length);
	printf("\nLength of encrypted = %ld.\n\n", encrypted.length);
#endif

	pad_position = get_padding_position(&encrypted, &key);
	implementation_check("get_padding_position", pad_position);
    printf("Output of get_padding_position: \t %d\n", pad_position);
    printf("Expected output of the function: \t %d\n\n", BLOCK_LENGTH - a);

	if(pad_position == BLOCK_LENGTH - a)
	    printf("[OK]\n");
	else
	    printf("[FAILED]\n");
	if(!buffer_equality(&encrypted, &encrypted_2)){
	    printf("\t\t[CAUTION] : your get_padding_position function\n");
	    printf("modifies your ciphertext in place!\n\n");
	}
			
    }
	
	
    // 4. Free Memory
    buffer_clear(&plain);
    buffer_clear(&padded);
    buffer_clear(&encrypted);
    buffer_clear(&encrypted_2);
    buffer_clear(&key);
    buffer_clear(&IV);	
}




void test_prepare(){
    // 1. INITIALISATION
    buffer_t plain, encrypted, key, IV, decrypted, corrupted;
    buffer_init(&plain, 3 * BLOCK_LENGTH);
    buffer_init(&encrypted, 4 * BLOCK_LENGTH);
    buffer_init(&key, BLOCK_LENGTH);
    buffer_init(&IV, BLOCK_LENGTH);
    buffer_init(&corrupted, 4 * BLOCK_LENGTH);
    buffer_init(&decrypted, 3 * BLOCK_LENGTH);
	
    // 2. Fill in buffer
    buffer_random(&plain, 3 * BLOCK_LENGTH);
    buffer_random(&IV, BLOCK_LENGTH);
    buffer_random(&key, BLOCK_LENGTH);
    aes_raw_CBC_encrypt(&encrypted, &plain, &key, &IV);

#if DEBUG
    printf("[test_mask | DEBUG] :\n");
    printf("-- Length of plain = %ld.\n", plain.length);
    printf("-- Length of cipher = %ld.\n\n", encrypted.length);	
#endif

    // 3. tests
    // i is the index of the first known entry of
    // the last block of plain.
    int success = 1;
    for(int known_positions = BLOCK_LENGTH + 1;
	known_positions < 2 * BLOCK_LENGTH + 1;
	known_positions++){
	printf("--- Known = %d:\n", known_positions);
	buffer_clone(&corrupted, &encrypted);
	success=prepare(&corrupted,&encrypted,&plain,known_positions);
	printf("\nEncrypted = ");
	buffer_print_int(stdout, &encrypted);
	printf("\n\n");
	implementation_check("prepare", success);
	printf("Corrupted = ");
	buffer_print_int(stdout, &corrupted);
	printf("\n\n");
		
	aes_raw_CBC_decrypt(&decrypted, &corrupted, &key);
	printf("Plain = ");
	buffer_print_int(stdout, &plain);
	printf("\n\n");
	printf("Decrypted = ");
	buffer_print_int(stdout, &decrypted);
	printf("\n\n");
	int position = known_positions - BLOCK_LENGTH - 1;
	int pad = BLOCK_LENGTH - (position % BLOCK_LENGTH);
	if((decrypted.tab[position] ^ plain.tab[position]) != (uchar)pad){
	    printf("[test_mask] : wrong value at the position we will guess.");
        printf("Expected value: \t%d\n", plain.tab[position]^(uchar)pad);
        printf("Decrypted value: \t%d\n\n", decrypted.tab[position]);

	    success = 0;
	}
    }
    if(success)
	printf("[OK]\n\n*****************************\n\n");

	
    // 4. Clean
    buffer_clear(&plain);
    buffer_clear(&encrypted);
    buffer_clear(&decrypted);
    buffer_clear(&key);
    buffer_clear(&IV);
    buffer_clear(&corrupted);
}



void test_find_last_byte(){
    // 1. Initialisation
    buffer_t plain, padded, encrypted, corrupted, key, IV;
    buffer_init(&plain, 3 * BLOCK_LENGTH);
    buffer_init(&padded, 3 * BLOCK_LENGTH);
    buffer_init(&encrypted, 4 * BLOCK_LENGTH);
    buffer_init(&corrupted, 4 * BLOCK_LENGTH);
    buffer_init(&key, BLOCK_LENGTH);
    buffer_init(&IV, BLOCK_LENGTH);
    uchar hack;
	
    // 2. Fill in buffers
    aes_key_generation(&key, BLOCK_LENGTH);
    buffer_random(&IV, BLOCK_LENGTH);

    // 3. Loop
    int success = 1;
    for(int j = 0; j < BLOCK_LENGTH; j++){
	printf("\n\n********** j = %d **********************\n\n", j);
	buffer_random(&plain, 3 * BLOCK_LENGTH - j);
	pad(&padded, &plain, 'R');
	
	aes_raw_CBC_encrypt(&encrypted, &padded, &key, &IV);
	int pad_position = get_padding_position(&encrypted, &key);
	implementation_check("get_padding_position", pad_position);
	pad_position += encrypted.length - BLOCK_LENGTH;
	printf("Padding position = %d.\n\n",
	       pad_position);
	success=prepare(&corrupted, &encrypted, &padded, 4 * BLOCK_LENGTH - j);
	implementation_check("prepare", success);
#if DEBUG
	printf("[test_find_the_last_byte | DEBUG ] :\n");
	printf("Padded :\n");
	buffer_print_int(stdout, &padded);
	printf("\n\nEcrypted :\n");
	buffer_print_int(stdout, &encrypted);
	printf("\n\nCorrupted :\n");
	buffer_print_int(stdout, &corrupted);
	printf("\n\n");
	buffer_t decrypted;
	buffer_init(&decrypted, 3 * BLOCK_LENGTH);
	printf("Decryption of prepared:\n");
	aes_raw_CBC_decrypt(&decrypted, &corrupted, &key);
	buffer_print_int(stdout, &decrypted);
	printf("\n\n");
	buffer_clear(&decrypted);
#endif
		
	success = find_last_byte(&hack, &corrupted, pad_position - 1, &key);
	implementation_check("find_last_byte", success);
	printf("Candidate for last byte = %u, should be = %u\t\t", hack,
	       padded.tab[pad_position - 1 - BLOCK_LENGTH]);


	if(hack != padded.tab[pad_position - 1 - BLOCK_LENGTH])
	    success = 0;
    }

    if(success)
	printf("[OK]\n\n");
    else
	printf("[FAILED]\n\n");

	
    // 4. Free Memory
    buffer_clear(&plain);
    buffer_clear(&padded);
    buffer_clear(&corrupted);
    buffer_clear(&encrypted);
    buffer_clear(&key);
    buffer_clear(&IV);	
}



void test_full_attack(){
    int success = 1;
    // 0. INIT
    buffer_t plain, encrypted, decrypted, IV, key;
    buffer_init(&plain, 64);
    buffer_init(&encrypted, 80);
    buffer_init(&decrypted, 64);
    buffer_init(&IV, BLOCK_LENGTH);
    buffer_init(&key, BLOCK_LENGTH);

    // 1. Fill in buffers
    int i = rand() % BLOCK_LENGTH + 3 * BLOCK_LENGTH;
    buffer_random(&plain, i);
    buffer_random(&IV, BLOCK_LENGTH);
    buffer_random(&key, BLOCK_LENGTH);

    // 2. Pad
    int pad = BLOCK_LENGTH - (i % BLOCK_LENGTH);
    for(int i = 0; i < pad; i++)
	buffer_append_uchar(&plain, (uchar)pad);
#if DEBUG
    printf("Plain text (with padding) :\n");
    buffer_print_int(stdout, &plain);
    printf("\n\n");
#endif
	
    // 3. Encrypt
    aes_raw_CBC_encrypt(&encrypted, &plain, &key, &IV);
	
	
    // 4. Decrypt
    printf("--- Performing full attack ---\n\n");
    fflush(stdout);
    success = full_attack(&decrypted, &encrypted, &key);
    implementation_check("full_attack", success);

    // 5. compare
    if(buffer_equality(&plain, &decrypted))
	printf("[DECRYPTED!!! You're such a great hacker!]\n\n");
    else{
	printf("\n\n[FAILED] Plain text : \n");
	buffer_print_int(stdout, &plain);
	printf("\n\nDecrypted text : \n");
	buffer_print_int(stdout, &decrypted);
	printf("\n\n");
    }
	
    // 6. Clean
    buffer_clear(&plain);
    buffer_clear(&encrypted);
    buffer_clear(&decrypted);
    buffer_clear(&key);
    buffer_clear(&IV);
}



void usage(char *s){
    fprintf(stderr, "Usage: %s <test_number>\n", s);
}


int main(int argc, char *argv[]){
    int	r = 42; /* force default */
    if(argc == 1){
	usage(argv[0]);
	return 0;
    }
    int n = atoi(argv[1]);
    if(argc > 2)
	r = atoi(argv[2]);
    srand(r);
    switch(n){
    case 1:
	test_oracle();
	break;
    case 2:
	test_get_padding_position();
	break;
    case 3:
	test_prepare();
	break;
    case 4:
	test_find_last_byte();
	break;
    case 5:
	test_full_attack();
	break;
    }
    return 0;
}
       
