#ifndef __FRS__AES

#define BLOCK_LENGTH 16

/* Possible key sizes */
#define SMALL 128
#define MEDIUM 192
#define LARGE 256
#define BYTE_SIZE 8

#ifndef uint
typedef unsigned int uint;
#endif

/* Functions */
void aes_key_generation(buffer_t *key, int byte_length);
void aes_block_encrypt_few_rounds(buffer_t *out, buffer_t *in, buffer_t *key, int Nr);
void aes_block_encrypt(buffer_t *out, buffer_t *in, buffer_t *key);
void aes_block_decrypt(buffer_t *out, buffer_t *in, buffer_t *key);

#define __FRS__AES
#endif
