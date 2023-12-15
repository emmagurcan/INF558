#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utilities.h"

#include "gmp.h"

#include "buffer.h"
#include "random.h"
#include "rsa.h"
#include "text_rsa.h"
#include "hastad.h"

#define DEBUG 0

/* to be filled in */


void print_key(mpz_t N, mpz_t p, mpz_t q, mpz_t e, mpz_t d, int nlen){
    printf("---------------------- RSA %d ----------------------\n", nlen);
    printf("\nPublic key (N, e) : \n\n");
    gmp_printf("N = %Zd\n\n", N);
    gmp_printf("e = %Zd\n\n", e);

    printf("\n**** \n\nSecret key (d; p, q) : \n\n");
    gmp_printf("d = %Zd\n\n", d);
    gmp_printf("p = %Zd\n\n", p);
    gmp_printf("q = %Zd\n\n", q);
    printf("----------------------------------------------------\n\n");
}


void test_encrypt_decrypt(gmp_randstate_t state){
    // 1. INIT
    mpz_t e, d, N, msg, cipher, decrypted;
    mpz_inits(e, d, N, msg, cipher, decrypted, NULL);

    // 2. Generate key and message
    mpz_set_str(N, "13407807929942597093760734805309010363963172602566944802519609325224163304582998294904721413435102703248310906226491221593579560484162277805870126943177997", 10);
    mpz_set_str(e, "57222688662856409396324072171762917393157734041088050228362504607465340519645", 10);
    mpz_set_str(d, "1878997391028620372412461175918902866075227951627683808774454416890098012337711393921327334759215491874986751914100470703224252001941679727301166707073653", 10);
    mpz_urandomm(msg, state, N);
    printf("---------------------------------\n");
    gmp_printf("Plain text = %Zd\n\n", msg);
	
    // 3. Encrypt and decrypt
    int status = RSA_encrypt(cipher, msg, N, e);
    implementation_check("RSA_encrypt", status);
    gmp_printf("Cipher text = %Zd\n\n", cipher);

    RSA_encrypt(decrypted, cipher, N, d);
    gmp_printf("Decrypted text = %Zd\n\n", decrypted);

    // 4. Final verification
    if(mpz_cmp(msg, decrypted) == 0)
	printf("[OK]\n\n");
    else
	printf("[FAILED]\n\n");
	
	
    // . Clear
    mpz_clears(e, d, N, msg, cipher, decrypted, NULL);
}


void basic_test(mpz_t p, mpz_t q, mpz_t e, mpz_t d, int nlen){
    if(!is_valid_key(p, q, e, d, nlen, 100))
	printf("[OK]\n");
    else
	printf("[FAILED]\n");
}


void test_valid_key(gmp_randstate_t state){
    // 1. Initialisations

    mpz_t p, q, e, d, pm1, qm1, lambda, tmp;
    mpz_inits(p, q, e, d, pm1, qm1, lambda, tmp, NULL);

    // 2. First values for p, q, d, e
    mpz_set_str(p, "81877371507464127615356903751309751484031022336294425213947021730845873406133", 10);
    mpz_set_str(q, "115792089237316195423570985008687907853269984665640564039457584007913153127617", 10);
    mpz_set_ui(e, 3);
    mpz_set_ui(d, 17);
    int nlen = 512;

    // 3. p is not prime
    printf("Test when p is not prime...                                ");
    basic_test(p, q, e, d, nlen);

    mpz_set_str(p, "81877371507464127615356903751309751484031022336294425213947021730845873406131", 10);
    mpz_set_str(q, "115792089237316195423570985008687907853269984665640564039457584007913153127615", 10);

    // 4. q is not prime
    printf("Test when q is not prime...                                ");
    basic_test(p, q, e, d, nlen);
	
    mpz_set_str(q, "115792089237316195423570985008687907853269984665640564039457584007913153127617", 10);

    // 5. e is even
    mpz_set_ui(e, 4);
    printf("Test when e is even...                                     ");
    basic_test(p, q, e, d, nlen);

    // 6. e isn't prime to lambda
    mpz_set_ui(e, ((1<<17)+5)*5783);
    mpz_sub_ui(pm1, p, 1);
    mpz_sub_ui(qm1, q, 1);
    mpz_lcm(lambda, pm1, qm1);
    printf("Test when e is not prime to lambda...                      ");
    basic_test(p, q, e, d, nlen);

    // 7. e is too small
    mpz_set_ui(e, (1 << 12) + 3);
    printf("Test when e is too small...                                ");
    basic_test(p, q, e, d, nlen);

    // 8. e is too large
    mpz_ui_pow_ui(e, 2, 256);
    mpz_add_ui(e, e, 3);
    printf("Test when e is too large...                                ");
    basic_test(p, q, e, d, nlen);

    // 9. ed = 1 mod lambda
    mpz_set_ui(e, (1 << 17) + 5);
    printf("Test when ed is not congruent to 1 modulo lambda...        ");
    basic_test(p, q, e, d, nlen);

    // 10. p is too small
    mpz_ui_pow_ui(tmp, 2, 50);
    mpz_nextprime(p, tmp);
    mpz_sub_ui(pm1, p, 1);
    mpz_lcm(lambda, pm1, qm1);
    mpz_invert(d, e, lambda);
    printf("Test when p is too small...                                ");
    basic_test(p, q, e, d, nlen);

    // 11. q is too small
    mpz_set(tmp, q);
    mpz_set(q, p);
    mpz_set(p, tmp);
    printf("Test when q is too small...                                ");
    basic_test(p, q, e, d, nlen);

    // 12. p, q are too close.
    mpz_set_str(p, "81877371507464127615356903751309751484031022336294425213947021730845873406131", 10);
    mpz_set_str(q, "81877371507464127615356903751309751484031022336294425213947021730845874454759", 10);	
    mpz_set_ui(e, (1 << 17) + 5);
    mpz_sub_ui(pm1, p, 1);
    mpz_sub_ui(qm1, q, 1);
    mpz_lcm(lambda, pm1, qm1);
    mpz_invert(d, e, lambda);
    printf("Test when p, q are too close to each other...              ");
    basic_test(p, q, e, d, nlen);
	
    // 13. Free memory
    mpz_clears(p, q, e, d, pm1, qm1, lambda, tmp, NULL);
}

int test_key_gen_aux(mpz_t N, mpz_t p, mpz_t q, mpz_t e, mpz_t d, int nlen, int sec, int doprint) {
    if (doprint) {
        printf("\n\n== Test RSA %d ==\n\n", nlen);
    }
    int bool = 0;
    if (is_valid_key(p, q, e, d, nlen, sec)) {
        int sizeN = mpz_sizeinbase(N, 2);
        if (sizeN != nlen && doprint) {
            printf("[FAILED] Key is valid is of %d bits. It was expected a key of size %d\n", sizeN, nlen);
        }
        else {
            bool = 1;
            if (doprint) {
                printf("[OK] The generated key is valid.\n");
            }
        }
    }
    else if (doprint) {
        printf("[FAILED] Key is not valid.\n");
    }
    return bool;
}


void test_key_gen(gmp_randstate_t state){
    // 1. Initialisation
    mpz_t N, p, q, e, d;
    mpz_inits(N, p, q, e, d, NULL);

    // 2. Key generation
    int nlen, sec, doprint=1;

    nlen = 256, sec = 50;
    int status = RSA_generate_key(N, p, q, e, d, nlen, sec, state);
    implementation_check("RSA_generate_key", status);
# if DEBUG >= 1
    print_key(N, p, q, e, d, nlen);
# endif
    test_key_gen_aux(N, p, q, e, d, nlen, sec, doprint);
# if DEBUG >= 1
    printf("\n\n\n\n");
# endif
    nlen = 1024, sec = 100;
    RSA_generate_key(N, p, q, e, d, nlen, sec, state);
# if DEBUG >= 1
    print_key(N, p, q, e, d, nlen);
# endif
    test_key_gen_aux(N, p, q, e, d, nlen, sec, doprint);

    // 3. Free memory
    mpz_clears(N, p, q, e, d, NULL);
}



void test_CRT_RSA(int nlen, int sec, gmp_randstate_t state){
    // 1. Initialisation
    mpz_t p, q, N, d, e, msg, cipher, tmp, tmpCRT;
    mpz_inits(p, q, N, d, e, msg, cipher, tmp, tmpCRT, NULL);

    // 2. Key generation
    int status = RSA_generate_key(N, p, q, e, d, nlen, sec, state);
    implementation_check("RSA_generate_key", status);

    // 3. Encryption
    if (mpz_cmp_ui(N, 0)==0) {
        printf("[FAILED]\n");
        return;
    }
    mpz_urandomm(msg, state, N);
    status = RSA_encrypt(cipher, msg, N, e);
    implementation_check("RSA_encrypt", status);

    // 4. Decryption tests
    printf("\nStandard decryption test...   ");
    RSA_decrypt(tmp, cipher, N, d);
    if(mpz_cmp(tmp, msg) == 0)
        printf("[OK]\n");
    else
        printf("[FAILED]\n");
	
    printf("CRT decryption test...        ");
    status = RSA_decrypt_with_p_q(tmpCRT, cipher, N, d, p, q);
    implementation_check("RSA_decrypt_with_p_q", status);
    if(mpz_cmp(tmpCRT, msg) == 0)
        printf("[OK]\n\n");
    else
        printf("[FAILED]\n\n");

    // 5. Free memory
    mpz_clears(p, q, N, d, e, msg, cipher, tmp, tmpCRT, NULL);
}


void test_lengths(gmp_randstate_t state){
    // 1. Initialisation
    buffer_t msg;
    buffer_init(&msg, 211);
    mpz_t N, p, q, e, d;
    mpz_inits(N, p, q, e, d, NULL);
    int nlen = 256;

    // 2. Key generation
    int status = RSA_generate_key(N, p, q, e, d, nlen, 50, state);
    implementation_check("RSA_generate_key", status);

    // 3. Message generation
    const char* str = "Wait a minute. Wait a minute, Doc. Ah... Are you telling me that you built a time machine... out of a DeLorean? The way I see it, if you're gonna build a time machine into a car, why not do it with some *style?*";
    buffer_from_string(&msg, (uchar *)str, 211);

    // 4. Test
    printf("------------- Testing lengths ----------------\n\n");
    int block_length, cipher_length, last_block_size;
    status = lengths(&block_length, &cipher_length, &last_block_size, &msg, N);
    implementation_check("lengths", status);
    
    printf("Plain text : \n\n%s\n\n", str);
    printf("**********************************************\n\n");
    printf("Size of the modulus N (in bits) = %ld\n",
	   mpz_sizeinbase(N, 2));
    printf("Length of the message = %ld bytes\n", msg.length);
    printf("block length = %d bytes\n", block_length);
    printf("cipher length = %d blocks\n", cipher_length);
    printf("last block size = %d bytes\n\n", last_block_size);

    int i = block_length == 31 && cipher_length == 7 &&
	last_block_size == 25;

    if(i)
	printf("[OK]\n\n");
    else
	printf("[FAILED]\n\n");

    // 5. Additional test with full last block.
    const char* str2 = "Wait a minute. Wait a minute, Doc. Ah... Are you telling me that you built a time machine... out of a DeLorean? The way I see it, if you're gonna build a time machine into a car, why not do it with some *style?*******";
    buffer_reset(&msg);
    buffer_from_string(&msg, (uchar *)str2, 217);
    lengths(&block_length, &cipher_length, &last_block_size, &msg, N);
    lengths(&block_length, &cipher_length, &last_block_size, &msg, N);
    i = ( block_length == 31 && cipher_length == 7 &&
	  last_block_size == 31 );

    printf("**********************************************\n\n");
    printf("Second test (slightly longer plain text): \n");
    printf("Length of the message = %ld bytes\n", msg.length);
    printf("block length = %d bytes\n", block_length);
    printf("cipher length = %d blocks\n", cipher_length);
    printf("last block size = %d bytes\n\n", last_block_size);
	
    if(i)
	printf("[OK]\n\n");
    else
	printf("[FAILED]\n\n");
	
    // 6. Free memory
    mpz_clears(N, p, q, e, d, NULL);
    buffer_clear(&msg);
}


void test_text_encryption(gmp_randstate_t state){
    // 0. Printing
    printf("---------------- Test text encryption ");
    printf("----------------\n");

    // 1. Initialisation
    mpz_t p, q, N, d, e;
    mpz_t* cipher;
    buffer_t msg;
    int block_length, cipher_length, last_block_size, nlen = 256, sec = 50, doprint=0;
    int status;
    mpz_inits(p, q, N, d, e, NULL);
    buffer_init(&msg, 211);

    // 2. Message generation
    const char* str = "Wait a minute. Wait a minute, Doc. Ah... Are you telling me that you built a time machine... out of a DeLorean?\nThe way I see it, if you're gonna build a time machine into a car, why not do it with some *style?*";
    buffer_from_string(&msg, (uchar *)str, 211);

// 3. Key generation
#if CORRECTION
    printf("\nGenerating RSA key .....");
    status = RSA_generate_key(N, p, q, d, e, nlen, sec, state);
    implementation_check("RSA_generate_key", status);

    printf(" [DONE]\n");
#else
    RSA_generate_key(N, p, q, d, e, nlen, sec, state);
#endif
    if (test_key_gen_aux(N, p, q, e, d, nlen, sec, doprint) == 0) {
        printf("[WARNING] Your generated key doesn't verify the specifications.\n");
    }
#if DEBUG >= 1
    print_key(N, p, q, e, d, nlen);
#endif

// 4. Defining sizes and number of blocks for the cipher text
#if CORRECTION
    my_lengths(&block_length, &cipher_length, &last_block_size,
	    &msg, N);
#else
    lengths(&block_length, &cipher_length, &last_block_size,
	    &msg, N);
#endif

    // 4. Init target for ciphertext
    cipher = (mpz_t*)malloc(sizeof(mpz_t) * cipher_length);
    mpz_t* cursor = cipher;
    int i;
    for(i = 0; i < cipher_length; i++, cursor++)
	mpz_init(*cursor);
    // 5. Encryption
    status = RSA_text_encrypt(cipher, block_length, cipher_length,
			      last_block_size, &msg, N, e);
    implementation_check("RSA_text_encrypt", status);

#if DEBUG >= 1
    printf("Encrypted text :\n");
    cursor = cipher;
    for(i = 0; i < cipher_length; i++, cursor++)
	gmp_printf("%Zd\n", *cursor);
    printf("\n");
#endif

# if CORRECTION
    printf("Checking that the encryption is correct ....");
    buffer_t my_decryption;
    buffer_init(&my_decryption, 211);
    my_RSA_text_decrypt(&my_decryption, cipher, cipher_length, block_length, last_block_size, N, d);
    if (buffer_equality(&my_decryption, &msg)) {
        printf(".... [OK]\n\n");
    }
    else {
        printf("....[FAILED]\n\n");
    }
    buffer_clear(&my_decryption);
#endif

    // 7. Free memory
    cursor = cipher;
    for(i = 0; i < cipher_length; i++, cursor++)
	mpz_clear(*cursor);
    free(cipher);
    buffer_clear(&msg);
    mpz_clears(p, q, N, d, e, NULL);
}
	

void test_text_decryption(gmp_randstate_t state){
    // 0. Printing
    printf("---------------- Test text decryption ");
    printf("----------------\n");

    // 1. Initialisation	
    mpz_t p, q, N, d, e;
    mpz_t* cipher;
    buffer_t msg;
    int block_length, cipher_length, last_block_size, nlen = 256, sec = 50, doprint=0;
    int status;
    mpz_inits(p, q, N, d, e, NULL);
    buffer_init(&msg, 211);

    // 2. Message generation
    const char* str = "Wait a minute. Wait a minute, Doc. Ah... Are you telling me that you built a time machine... out of a DeLorean?\nThe way I see it, if you're gonna build a time machine into a car, why not do it with some *style?*";
    buffer_from_string(&msg, (uchar *)str, 211);

#if DEBUG
    printf("\nPlain text :\n%s\n\n", str);
#endif

    // 3. Key generation
#if CORRECTION
    printf("\nGenerating RSA key .....");
    status = RSA_generate_key(N, p, q, d, e, nlen, sec, state);
    implementation_check("RSA_generate_key", status);

    printf(" [DONE]\n");
#else
    RSA_generate_key(N, p, q, d, e, nlen, sec, state);
#endif
    if (test_key_gen_aux(N, p, q, e, d, nlen, sec, doprint) == 0) {
        printf("[WARNING] Your generated key doesn't verify the specifications.\n");
    }
#if DEBUG >= 1
    print_key(N, p, q, e, d, nlen);
#endif

    // 4. Defining sizes and number of blocks for the cipher text
#if CORRECTION
    my_lengths(&block_length, &cipher_length, &last_block_size,
	    &msg, N);
#else
    status = lengths(&block_length, &cipher_length, &last_block_size, &msg, N);
    implementation_check("lengths", status);
#endif

    // 4. Init target for ciphertext
    cipher = (mpz_t*)malloc(sizeof(mpz_t) * cipher_length);
    mpz_t* cursor = cipher;
    int i;
    for(i = 0; i < cipher_length; i++, cursor++)
	mpz_init(*cursor);
		

    // 5. Encryption
#if CORRECTION
    my_RSA_text_encrypt(cipher, block_length, cipher_length,
		     last_block_size, &msg, N, e);
#else
    status = RSA_text_encrypt(cipher, block_length, cipher_length,
			      last_block_size, &msg, N, e);
    implementation_check("RSA_text_encrypt", status);
#endif

#if DEBUG >= 1
    printf("Encrypted text :\n");
    cursor = cipher;
    for(i = 0; i < cipher_length; i++, cursor++)
	gmp_printf("%Zd\n", *cursor);
    printf("\n");
#endif
	uchar *foo;
	buffer_t decrypted;
	buffer_init(&decrypted, 211);
	status = RSA_text_decrypt(&decrypted, cipher, cipher_length,
				  block_length, last_block_size, N, d);
	implementation_check("RSA_text_encrypt", status);
	foo = string_from_buffer(&decrypted);
#if DEBUG >= 1
	printf("Decrypted text :\n%s\n\n", foo);
#endif
	free(foo);

#if CORRECTION
    printf("Checking that the decryption is correct ....");
#endif
	if(buffer_equality(&decrypted, &msg))
	    printf("[OK]\n\n");
	else
	    printf("[FAILED]\n\n");
	buffer_clear(&decrypted);
	
    // 7. Free memory
    cursor = cipher;
    for(i = 0; i < cipher_length; i++, cursor++)
	mpz_clear(*cursor);
    free(cipher);
    buffer_clear(&msg);
    mpz_clears(p, q, N, d, e, NULL);
}

 
 
	
void test_Hastad(int exponent, int nlen, gmp_randstate_t state){
    // 0. Definitions
    printf("------------- Test Hastad attack --------------\n\n");
    mpz_t *moduli = (mpz_t *)malloc(sizeof(mpz_t) * exponent);
    mpz_t *cipher_texts = (mpz_t *)malloc(sizeof(mpz_t) * exponent);
    mpz_t msg, N, e, decrypted, prod, g;
    int status;

    // 1. Initialisation
    mpz_inits(msg, N, e, decrypted, prod, g, NULL);
    mpz_set_ui(e, exponent);
    mpz_set_ui(prod, 1);
    mpz_t* cursor_mod = moduli;
    mpz_t* cursor_ciph = cipher_texts;
#if 0
    mpz_urandomb(msg, state, nlen - 1);
#else
    mpz_set_str(msg, "12345678", 10);
#endif

    gmp_printf("Plain text : \n%Zd\n\n", msg);
		
    // 2. Creating the pairs (moduli, cipher text)
    int i;
    for(i = 0; i < exponent; i++, cursor_mod++, cursor_ciph++){
	mpz_inits(*cursor_mod, *cursor_ciph, NULL);
	do{
	    RSA_dummy_generate_key(*cursor_mod, e, nlen, state);
	    mpz_gcd(g, *cursor_mod, prod);
	}while(mpz_cmp_ui(g, 1) != 0);
		
	status = RSA_encrypt(*cursor_ciph, msg, *cursor_mod, e);
	implementation_check("RSA_encrypt", status);

	assert(mpz_cmp(msg, *cursor_mod) < 0);
	mpz_mul(prod, prod, *cursor_mod);
#if DEBUG >= 1
	gmp_printf("%d-th encrypted = %Zd.\n\n", i,
		   *cursor_ciph);
#endif
    }
    printf("Key generation and encryption done.\n\n");
    fflush(stdout);
	
    // 3. Hastad
    status = Hastad(decrypted, cipher_texts, moduli, exponent);
    implementation_check("Hastad", status);

    if(mpz_cmp(decrypted, msg) == 0)
	printf("[TEST OK]\n\n");
    else
	printf("[TEST FAILED]\n\n");
	
	
    // 3. Free memory
    mpz_clears(msg, N, e, decrypted, prod, g, NULL);
    cursor_mod = moduli;
    cursor_ciph = cipher_texts;
    for(i = 0; i < exponent; i++, cursor_mod++, cursor_ciph++)
	mpz_clears(*cursor_mod, *cursor_ciph, NULL);
    free(moduli);
    free(cipher_texts);
}


static void usage(char *s, int ntests){
    fprintf(stderr, "Usage: %s <test_number in 1..%d>\n", s, ntests);
}

int main(int argc, char *argv[]){
    if(argc == 1){
	usage(argv[0], 6);
	return 0;
    }
    gmp_randstate_t state;
    gmp_randinit_default(state);
#if DEBUG >= 1
    gmp_randseed_ui(state, 42);
#else
    /* gmp_randseed_ui(state, random_seed()); */
    gmp_randseed_ui(state, 42);
#endif

    int n = atoi(argv[1]);
    switch(n){
    case 0:
	test_encrypt_decrypt(state);
	break;
    case 1:
	test_key_gen(state);
	break;
    case 2:
	test_CRT_RSA(512, 100, state);
	break;
    case 3:
	test_lengths(state);
	break;
    case 4:
	test_text_encryption(state);
	break;
    case 5:
	test_text_decryption(state);
	break;
    case 6:
	test_Hastad(3, 32, state);
	break;
    default:
	usage(argv[0], 6);
    }
    gmp_randclear(state);
    return 0;
}
