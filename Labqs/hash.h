/**************************************************************/
/* hash.h                                                     */
/* Author : Francois Morain                                   */
/* morain@lix.polytechnique.fr                                */
/* Last modification October 12, 2017                         */
/**************************************************************/

#define HASH_TABLE_FULL           -3
#define HASH_TABLE_ALREADY_EXISTS -2
#define HASH_FOUND                 1
#define HASH_NOT_FOUND             2
#define HASH_OK                    3

#include "gmp.h"

typedef unsigned long ulong, hash_key, hash_value;

typedef struct{
    hash_key k;
    hash_value v;
} hash_pair;

typedef struct {
    int size, nb_elts;
    int modulo;
    hash_pair *table;
} hash_table_type, *hash_table;

extern hash_table hash_init(int size);
extern int hash_put(hash_table H, int *addr, hash_key k, hash_value v);
extern int hash_put_mpz(hash_table H, int *addr, mpz_t kz, mpz_t vz, mpz_t base, mpz_t p);
extern int hash_get(hash_pair *kv, hash_table H, hash_key k);
extern int hash_get_mpz(mpz_t vz, hash_table H, mpz_t kz, mpz_t base, mpz_t p);
extern void hash_clear(hash_table H);
