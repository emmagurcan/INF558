#ifndef __FRS__BUFFER

/*! \file buffer.h
 */

/********** buffers **********/
typedef unsigned char uchar;

typedef struct{
    uchar *tab; /* tab[0..length[ */
    size_t size, length; /* 0 <= length <= size */
} buffer_t;

int buffer_init(buffer_t *buf, size_t size);
void buffer_clear(buffer_t *buf);
int buffer_print(FILE *ofile, buffer_t *buf);
int buffer_print_int(FILE *ofile, buffer_t *buf);
int buffer_resize(buffer_t *buf, size_t len);
int buffer_append(buffer_t *buf, buffer_t *next);
int buffer_append_uchar(buffer_t *buf, uchar c);
void buffer_reset(buffer_t *buf);
int buffer_equality(buffer_t *buf1, buffer_t *buf2);
void buffer_clone(buffer_t *out, buffer_t *in);

int buffer_from_string(buffer_t *buf, uchar *str, size_t len);
uchar *string_from_buffer(buffer_t *buf);
int buffer_from_file(buffer_t *buf, const char *file_name);
void buffer_random(buffer_t *out, int byte_length);

void buffer_to_base64(buffer_t *out, buffer_t *in);
void buffer_from_base64(buffer_t *out, buffer_t *in);

void buffer_from_mpz(buffer_t *buf, mpz_t n);
void buffer_to_mpz(mpz_t n, buffer_t *buf);

#define __FRS__BUFFER
#endif
