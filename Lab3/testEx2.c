/**************************************************************/
/* testEx2.c                                                  */
/* Author : Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Last modification October 12, 2018                         */
/**************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "buffer.h"
#include "random.h"
#include "bits.h"
#include "aes.h"
#include "diffusion.h"

void test_aes(){
	// 1. Initialisation
	buffer_t msg, key, encrypted, decrypted;
	buffer_init(&msg, BLOCK_LENGTH);
	buffer_init(&key, BLOCK_LENGTH);
	buffer_init(&encrypted, BLOCK_LENGTH);
	buffer_init(&decrypted, BLOCK_LENGTH);

	// 2. Message generation
	uchar plain[17] = "Crypto is great!";
	buffer_from_string(&msg, plain, BLOCK_LENGTH);
	printf("Plain text : %s\n\n", plain);

	// 3. Key generation
	aes_key_generation(&key, BLOCK_LENGTH);
	printf("Key : ");
	buffer_print_int(stdout, &key);
	printf("\n\n");

	// 4. Encryption
	aes_block_encrypt(&encrypted, &msg, &key);
	uchar* str_buf1 = string_from_buffer(&encrypted);
	printf("Encrypted : %s\n\n", str_buf1);
	free(str_buf1);

	// 5. Decryption
	aes_block_decrypt(&decrypted, &encrypted, &key);
	uchar *str_buf2 = string_from_buffer(&decrypted);
	printf("Decrypted : %s\n\n", str_buf2);
	free(str_buf2);

	// 6. Verification
	if(buffer_equality(&msg, &decrypted))
		printf("[OK]\n\n");
	else
		printf("[FAILED]\n\n");

	// 7. Free memory
	buffer_clear(&msg);
	buffer_clear(&key);
	buffer_clear(&encrypted);
	buffer_clear(&decrypted);
}

void test_diffusion_for_key(){
    // 1. Initialisation
    buffer_t key;
    buffer_init(&key, BLOCK_LENGTH);
    int nr_tests = 10000;

    // 2. Key generation
    aes_key_generation(&key, BLOCK_LENGTH);
	
    // 3. Test
    printf("Diffusion tests for key (%d tries) : %f\n\n",
	   nr_tests, diffusion_test_for_key(&key, nr_tests));
	
    // 4. Free memory
    buffer_clear(&key);
}

void test_diffusion_for_msg(){
    // 1. Initialisation
    buffer_t msg;
    buffer_init(&msg, BLOCK_LENGTH);
    int nr_tests = 10000;

    // 2. Message generation
    buffer_random(&msg, BLOCK_LENGTH);
	
    // 3. Test
    printf("Diffusion tests for plain text (%d tries) : %f\n\n",
	   nr_tests, diffusion_test_for_msg(&msg, nr_tests));
	
    // 4. Free memory
    buffer_clear(&msg);
}


void test_diffusion_few_rounds(){
    // 1. Initialisation
    buffer_t msg;
    buffer_init(&msg, BLOCK_LENGTH);
    int nr_tests = 10000;

    // 2. Message generation
    buffer_random(&msg, BLOCK_LENGTH);
	
    // 3. Test
    for(int Nr = 0; Nr < 10; Nr++){
	printf("Diffusion tests for %d rounds : %f\n\n",
	       Nr, diffusion_test_nr_rounds(&msg, Nr, nr_tests));
    }
	
    // 4. Free memory
    buffer_clear(&msg);
}


void usage(char *s){
    fprintf(stderr, "Usage: %s <test_number>\n", s);
}


int main(int argc, char *argv[]){
    if(argc == 1){
	usage(argv[0]);
	return 0;
    }
    int n = atoi(argv[1]);
	
    switch(n){
    case 0:
	test_aes();
	break;
    case 1:
	test_diffusion_for_key();
	break;
    case 2:
	test_diffusion_for_msg();
	break;
    case 3:
	test_diffusion_few_rounds();
	break;
    }
	
}
