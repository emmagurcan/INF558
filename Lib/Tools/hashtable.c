/*! \file hashtable.c
 * \brief Using a small hash table with open addressing
 * \author Francois Morain (morain@lix.polytechnique.fr)
 * \date October 12, 2017                        
 **************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "hashtable.h"

static unsigned long hash_find_modulo(int size){
    return 1048583; // 2^20 + 7 > 2^15
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

/*! \brief allocates a hash table that should store up to \a sizemax keys. */
hash_table hash_init(int sizemax){
    int addr;
    
    hash_table H = (hash_table)malloc(sizeof(hash_table_type));
    H->modulo = hash_find_modulo(1.5 * sizemax);
    H->size = (int)H->modulo;
    H->nb_elts = 0;
    H->table = (hash_pair *)malloc(H->size * sizeof(hash_pair));
    if(H->table == NULL){
	perror("hash_init");
	return NULL;
    }
    for(addr = 0; addr < H->size; addr++)
	H->table[addr].k = ULONG_MAX;
    return H;
}

/*! \brief OUTPUT: HASH_TABLE_ALREADY_EXISTS < 0 if \a k already known;
  \brief         new addr where \a was stored otherwise.
*/
int hash_put(hash_table H, hash_key k, hash_value v){
    int addr = hash_addr(H, k), cpt = 0;

    while(1){
	if(hash_is_defined(H, addr) == 0){
	    /* empty cell */
	    H->nb_elts++;
	    H->table[addr].k = k;
	    H->table[addr].v = v;
	    if(H->nb_elts == H->size){
		fprintf(stderr, "Hash table is full\n");
		return HASH_TABLE_FULL;
	    }
	    if(cpt > 10){
		//fprintf(stderr, "cpt: %d\n", cpt);
	    }
	    return addr;
	}
	if(H->table[addr].v == v)
	    return HASH_TABLE_ALREADY_EXISTS;
	/* cell is occupied */
	addr = hash_incr(H, addr);
	cpt++;
    }
    return addr;
}

/*! \brief Fills in \a *kv with (\a k, \a v) where H[k] = v and returns
  \brief HASH_FOUND; otherwise returns HASH_NOT_FOUND.
*/
int hash_get(hash_pair *kv, hash_table H, hash_key k){
    int addr = hash_addr(H, k);

    while(1){
	if(hash_is_defined(H, addr) == 0)
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

/*! \brief clears the hash table \a H.*/
void hash_clear(hash_table H){
    // TODO: destroy content too
    free(H->table);
    free(H);
}

