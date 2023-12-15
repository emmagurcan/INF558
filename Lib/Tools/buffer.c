/*! \file buffer.c
  \author François Morain (morain@lix.polytechnique.fr)
  \author Alain Couvreur (alain.couvreur@lix.polytechnique.fr)
  \date September 29, 2018.
  \details A buffer_t mimics an array of uchar of variable size.
  A buffer is created with a maximal \a size; each time an operation is
  performed, its size may be increased.
******************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "gmp.h"
#include "utilities.h"
#include "random.h"
#include "base64.h"
#include "buffer.h"

/*! \def DEBUG
  \brief set DEBUG to 1 to have a complete equality test 
*/
#define DEBUG 0

/*! \brief initialize \a buf as an array of maximal size \a size. */
int buffer_init(buffer_t *buf, size_t size){
    if(size == 0) size = 1;
    buf->size = size;
    buf->length = 0;
    buf->tab = (uchar *)malloc(size * sizeof(uchar));
    return buf->tab != NULL;
}

/*! \brief Clears and frees the memory occuped by the buffer */
void buffer_clear(buffer_t *buf){
    memset(buf->tab, 0, buf->size);
    free((char *)buf->tab);
    buf->tab = NULL;
    buf->size = -1;
    buf->length = 0;
}


/*! \brief Prints the content of \a buf to file descriptor \a ofile. */
int buffer_print(FILE *ofile, buffer_t *buf){
    int i;
    for(i = 0; i < buf->length; i++)
	fputc(buf->tab[i], ofile);
    return 0;
}

/*! \brief Prints the content of \a buf as integers to file descriptor
  \a ofile. */
int buffer_print_int(FILE *ofile, buffer_t *buf){
    int i;
    fprintf(ofile, "[");
    for(i = 0; i < buf->length; i++){
	if(i)
	    fprintf(ofile, ", ");
	fprintf(ofile, "%d", (int)buf->tab[i]);
    }
    fprintf(ofile, "]");
    return 0;
}

/*! \brief Reallocates \a buf->tab to size \a len. */
int buffer_resize(buffer_t *buf, size_t len){
    /* Changes the size of the table contained in buf */
    if(buf->size < len){
	if((buf->tab = realloc(buf->tab, len)) == NULL)
	    return 0;
	buf->size = len;
    }
    return 1;
}


/*! \brief Appends the contents of next at the end of the contents
  of buf. If buf is too small, it is resized. */
int buffer_append(buffer_t *buf, buffer_t *next){
    size_t len = buf->length + next->length;
    if(len > buf->size){
	size_t sz = buf->size;
	if(sz == 0)
	    sz = 1;
	while(sz < len)
	    sz = 2*sz;
	len = sz;
    }
	
    if(buffer_resize(buf, len) == 0)
	return 0;
    memcpy(buf->tab+buf->length, next->tab, next->length);
    buf->length += next->length;
    return 1;
}

/*! \brief Appends an element at the end of the buffer */
int buffer_append_uchar(buffer_t *buf, uchar c){
    size_t len = buf->length + 1;
    if(len > buf->size)
	len = 2 * buf->size;
    if(buffer_resize(buf, len) == 0)
	return 0;
    buf->tab[buf->length] = c;
    buf->length += 1;
    return 1;
}


/*! \brief Reset buffer to 0 */
void buffer_reset(buffer_t *buf){
    memset(buf->tab, 0, buf->size);
    buf->length = 0;	
}


/*! \brief Return 1 if \a buf1 == \a buf2 (same length, same content). */
int buffer_equality(buffer_t *buf1, buffer_t *buf2){
    if(buf1->length != buf2->length){
#if DEBUG
	printf("Different lengths: %d %d\n", buf1->length, buf2->length);
#endif
	return 0;
    }
#if DEBUG
    uchar *cursor1 = buf1->tab;
    uchar *cursor2 = buf2->tab;
    int i;
    for(i = 0; i < buf1->length; i++, cursor1++, cursor2++){
	if(*cursor1 != *cursor2){
	    printf("[buffer_equality] : ");
	    printf("buffers differ at position %d : %u  %u\n",
		   i, *cursor1, *cursor2);
	    return 0;
	}
    }
    return 1;
#endif
    if(memcmp(buf1->tab, buf2->tab, buf1->length) != 0)
	return 0;
    return 1;
}

/*! \brief Performs out <- in. */
void buffer_clone(buffer_t *out, buffer_t *in){
    buffer_reset(out);
    buffer_append(out, in);
}



/*! \brief A string is an array of uchar's that ends with a '\0'. 
  The '\0' is *not* put in the buffer.
  If the length is unknown give default value -1.
*/
int buffer_from_string(buffer_t *buf, uchar *str, size_t len){
    if(len == -1)
	len = strlen((char*)str);
	
    if(buffer_resize(buf, len) == 0)
	return 0;
    memcpy((char*)buf->tab, (char*)str, len);
    buf->length = len;
    return 1;
}

/*! \brief Creates a C string that contains \a buf. */
uchar *string_from_buffer(buffer_t *buf){
    uchar *tmp = (uchar *)malloc((buf->length+1) * sizeof(uchar));
    if(tmp != NULL){
	memcpy((char*)tmp, (char*)buf->tab, buf->length);
	tmp[buf->length] = '\0';
    }
    return tmp;
}

/*! \brief Fills in \a buf from \a file if exists */
int buffer_from_file(buffer_t *buf, const char *file_name){
    buffer_reset(buf);
    FILE *file = fopen(file_name, "r");
    if(file == NULL)
	return 0;
    while(1){
	char c = fgetc(file);
	if(feof(file))
	    break;
	buffer_append_uchar(buf, c);
    }
    fclose(file);
    return 1;	
}

/*! \brief Fills in a buffer with \a byte_length random bytes
  Pseudo-random generator should have been intialised before
*/
void buffer_random(buffer_t *out, int byte_length){
    int i;
    buffer_reset(out);
    for(i = 0; i < byte_length; i++)
	buffer_append_uchar(out, (uchar)rand());
}

/* out will have a length which is = 0 mod 3. */
void buffer_to_base64(buffer_t *out, buffer_t *in){
    size_t Nl = in->length, r3;

    /* make Nl = 0 mod 3 */
    if((r3 = Nl % 3) != 0)
	Nl += (3-r3);
    buffer_resize(out, 4*Nl/3);
    out->length = CodeBase64(out->tab, in->tab, in->length);
}

/* Take care to padding which might be nonexistant, or '=' or '=='.
 */
void buffer_from_base64(buffer_t *out, buffer_t *in){
    size_t Nl = 3*in->length/4, len;
	
    assert((in->length & 3) == 0);
    buffer_resize(out, Nl);
    DecodeBase64(out->tab, in->tab, in->length);
    /* do not count the padding if any */
    len = in->length;
    while(in->tab[len-1] == '='){
	len--;
	Nl--;
    }
    out->length = Nl;
}

void buffer_from_mpz(buffer_t *buf, mpz_t n){
    size_t nc, len = 1 + (mpz_sizeinbase(n, 2) / BYTE_SIZE); /* overshooting */
    buffer_resize(buf, len);
    mpz_export(buf->tab, &nc, 1, 1, 1, 0, n);
    assert(nc <= len);
    buf->length = nc;
}

void buffer_to_mpz(mpz_t n, buffer_t *buf){
    mpz_import(n, buf->length, 1, 1, 1, 0, buf->tab);
}

/* TEST
   int main(){
   buffer_t b1, b2;
   buffer_init(&b1, 5);
   buffer_init(&b2, 5);

   uchar tab1[] = {211, 52, 32, 71, 240};
   uchar tab2[] = {211, 52, 32, 71, 240};

   buffer_from_string(&b1, tab1, 5);
   buffer_from_string(&b2, tab2, 5);

   printf("\n\n%d\n\n", buffer_equality(&b1, &b2));
	
   buffer_clear(&b1);
   buffer_clear(&b2);
   }
*/
