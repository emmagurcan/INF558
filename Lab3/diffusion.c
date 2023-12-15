/**************************************************************/
/* diffusion.c                                                */
/* Author : Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Last modification October 6, 2022 by FJM                   */
/* Last modification October 12, 2018                         */
/**************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "buffer.h"
#include "random.h"
#include "bits.h"
#include "aes.h"
#include "diffusion.h"


double diffusion_test_for_key(buffer_t *key, int nr_tests){
    int length = key->length;
    double result = 0;
    // 1. Intialisation
    buffer_t msg, key2, encrypted, encrypted2;
    buffer_init(&msg, length);
    buffer_init(&key2, length);
    buffer_init(&encrypted, length);
    buffer_init(&encrypted2, length);

    for (int i = 0; i < nr_tests; i++){
        // define a random value for the message msg using buffer_random
        buffer_random(&msg, length);

        // compute the aes encryption of the message with the key
        // and write the result in buffer encrypted
        aes_block_encrypt(&encrypted, &msg, key);

        // draw a random integer position in [0, L] where L
        // denotes the bit size of the key (8)
        int bit_size = 8;
        int rand_num = rand();
        int pos = rand_num % (length * bit_size);

        
        // flip the position-th bit of the key using the function
        // buffer_flip_bit of bits.c to yield key2
        buffer_flip_bit(&key2, key, pos);

        // compute the AES encryption of the message with the new key 
        // after this bit flipping and save the result to encrypted2
        aes_block_encrypt(&encrypted2, &msg, &key2);

        // compute the number of bits where the two cipher texts differ
        result += HammingDistance(&encrypted, &encrypted2);
    }

    // 3. Free memory
    buffer_clear(&msg);
    buffer_clear(&key2);	
    buffer_clear(&encrypted);	
    buffer_clear(&encrypted2);	
    return result / nr_tests;
}


double diffusion_test_for_msg(buffer_t *msg, int nr_tests){
   double result = 0;
    int length = msg->length;
    buffer_t msg2, key, encrypted, encrypted2;
    buffer_init(&msg2, length);
    buffer_init(&key, length);
    buffer_init(&encrypted, length);
    buffer_init(&encrypted2, length);

    for (int i = 0; i < nr_tests; i++){
        aes_key_generation(&key, length);
        aes_block_encrypt(&encrypted, msg, &key);

        int bit_size = 8;
        int rand_num = rand();
        int pos = rand_num % (length * bit_size);

        buffer_flip_bit(&msg2, msg, pos);

        aes_block_encrypt(&encrypted2, &msg2, &key);

        result += HammingDistance(&encrypted, &encrypted2);
    }

    // 3. Free memory
    buffer_clear(&key);
    buffer_clear(&msg2);	
    buffer_clear(&encrypted);	
    buffer_clear(&encrypted2);	
    return result / nr_tests;
}

// Interpretation of Results:
// The diffusion test for the key yields 63.96 on the diffusion test 
// for 10000 tries. This means that on average, after the bit flip and encryption
// take place, the ciphertext is 63.96 bit positions from the original text, so 64 bits/128 bits. 
// For the diffusion test on the plaintext, it was 63.94, it means that on average, after a bit flip
// in the plaintext and the encryption with the key, teh ciphertext diphers 63.94 bit positions
// from the original. The proximity of the two diffusion tests shows that AES is 
// a pretty good method and yields good diffusion, and a single bit change in the key leads
// to a significant change in the ciphertext.

double diffusion_test_nr_rounds(buffer_t *msg, int Nr, int nr_tests){
    double result = 0;
    int length = msg->length;
    buffer_t msg2, key, encrypted, encrypted2;
    buffer_init(&msg2, length);
    buffer_init(&key, length);
    buffer_init(&encrypted, length);
    buffer_init(&encrypted2, length);

    for (int i = 0; i < nr_tests; i++){
        aes_key_generation(&key, length);
        aes_block_encrypt_few_rounds(&encrypted, msg, &key, Nr);

        int bit_size = 8;
        int rand_num = rand();
        int pos = rand_num % (length * bit_size);

        buffer_flip_bit(&msg2, msg, pos);

        aes_block_encrypt_few_rounds(&encrypted2, &msg2, &key, Nr);

        result += HammingDistance(&encrypted, &encrypted2);
    }

    // 3. Free memory
    buffer_clear(&key);
    buffer_clear(&msg2);	
    buffer_clear(&encrypted);	
    buffer_clear(&encrypted2);	
    return result / nr_tests;
}
