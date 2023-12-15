/*! \file random.c
 *  \author Alain Couvreur
 */

#include <stdio.h>
#include <time.h>

#include "random.h"

/*! \brief returns a random seed as random as it can be. */
unsigned int random_seed(){
    FILE* f;
    f = fopen("/dev/urandom", "r");
    if(f == NULL){
	perror("Your system has no /dev/urandom file. Please find another source of physical randomness");
	return time(NULL);
    }
		
    unsigned int result = 0;
    int i = 0;
    while(i < 4){
	unsigned char c = fgetc(f);
	if(feof(f)){
	    printf("EOF : Should close and re-open /dev/urandom\n\n");
	    fclose(f);
	    f = fopen("/dev/urandom", "r");
	}
	else
	    result += ((unsigned int)c) << (8 * i++);
    }
    fclose(f);
    return result;
}
