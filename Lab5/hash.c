/**************************************************************/
/* hash.c                                                     */
/* Author : Francois Morain                                   */
/* morain@lix.polytechnique.fr                                */
/* Last modification October 12, 2017                         */
/**************************************************************/

#include <stdlib.h>
#include <stdio.h>

#include "hash.h"
#include "gmp.h"

#define DEBUG 0

static ulong hash_find_modulo(int size){
    mpz_t s, mod;
    mpz_inits(s, mod, NULL);
    mpz_set_ui(s, size);
    mpz_nextprime(mod, s);
    unsigned long l = mpz_get_ui(mod);
    mpz_clears(s, mod, NULL);
    return l;
    //return 1048583; // 2^20 + 7 > 2^15
}

static int hash_addr(hash_table H, hash_key k){
    return (3 * k + 2) % H->modulo;
}

static int hash_incr(hash_table H, int addr){
    addr++;
    if(addr == H->modulo)
	addr = 0;
    return addr;
}

hash_table hash_init(int size){
    int addr;
    
    hash_table H = (hash_table)malloc(sizeof(hash_table_type));
    H->modulo = hash_find_modulo(1.5 * size);
    H->size = (int)H->modulo;
    H->nb_elts = 0;
    H->table = (hash_pair *)malloc(H->size * sizeof(hash_pair));
    if(H->table == NULL){
		perror("hash_init");
		return NULL;
    }
    for(addr = 0; addr < H->size; addr++)
		H->table[addr].k = -1;
    return H;
}

// OUTPUT: -1 if k already known; new addr otherwise.
int hash_put(hash_table H, int *addr, hash_key k, hash_value v){
    int cpt = 0;

    *addr = hash_addr(H, k);
    while(1){
	if(H->table[*addr].k == -1){
	    /* empty cell */
	    H->nb_elts++;
	    H->table[*addr].k = k;
	    H->table[*addr].v = v;
	    if(H->nb_elts == H->size){
			fprintf(stderr, "Hash table is full\n");
		return HASH_TABLE_FULL;
	    }
	    if(cpt > 10){
			//fprintf(stderr, "cpt: %d\n", cpt);
	    }
	    return HASH_OK;
	}
	if(H->table[*addr].k == k)
	    return HASH_TABLE_ALREADY_EXISTS;
	/* cell is occupied */
	*addr = hash_incr(H, *addr);
	cpt++;
    }
    return HASH_OK;
}

int hash_put_mpz(hash_table H, int *addr, mpz_t kz, mpz_t vz, mpz_t base, mpz_t p){
    /* vz should be less than 64 bits long */
	
    hash_value k = mpz_get_ui(kz);
    hash_value v = mpz_get_ui(vz);
    mpz_t x;
    mpz_init(x);

    int cpt = 0;
    *addr = hash_addr(H, k);
    while(1){
		if(H->table[*addr].k == -1){
			/* empty cell */
			H->nb_elts++;
			H->table[*addr].k = k;
			H->table[*addr].v = v;
			if(H->nb_elts == H->size){
				fprintf(stderr, "Hash table is full\n");
				mpz_clear(x);
				return HASH_TABLE_FULL;
			}
			if(cpt > 10){
				//fprintf(stderr, "cpt: %d\n", cpt);
			}
			return HASH_OK;
		}
		if(H->table[*addr].v == v){
			mpz_powm_ui(x, base, H->table[*addr].v, p);
			if(mpz_cmp(x, kz) == 0){
				mpz_clear(x);
				return HASH_TABLE_ALREADY_EXISTS;
			}
		}
		/* cell is occupied */
		*addr = hash_incr(H, *addr);
		cpt++;
    }
    mpz_clear(x);
    return HASH_OK;
}

int hash_get(hash_pair *kv, hash_table H, hash_key k){
    int addr = hash_addr(H, k);

    while(1){
		if(H->table[addr].k == -1)
			return HASH_NOT_FOUND;
		if(H->table[addr].k == k){
			kv->k = H->table[addr].k;
			kv->v = H->table[addr].v;
			return HASH_FOUND;
		}
		addr = hash_incr(H, addr);
    }
    return HASH_NOT_FOUND;
}


int hash_get_mpz(mpz_t vz, hash_table H, mpz_t kz, mpz_t base, mpz_t p){
    hash_value k = mpz_get_ui(kz);
    mpz_t x;
    mpz_init(x);

    int addr = hash_addr(H, k);
	while(1){
		if(H->table[addr].k == -1){
			mpz_clear(x);
			return HASH_NOT_FOUND;
		}
		if(H->table[addr].k == k){
			mpz_powm_ui(x, base, H->table[addr].v, p);
			if(mpz_cmp(kz, x) == 0){
				mpz_set_ui(vz, H->table[addr].v);
#if DEBUG >= 1
				gmp_printf("* From hash.c. vz = %Zd, v = %lu, x = %Zd.\n", vz, H->table[addr].v, x);
#endif
				mpz_clear(x);
				return HASH_FOUND;
			}
		}
		addr = hash_incr(H, addr);
    }
    mpz_clear(x);
    return HASH_NOT_FOUND;
}

void hash_clear(hash_table H){
    // TODO: destroy content too
    free(H->table);
    free(H);
}

