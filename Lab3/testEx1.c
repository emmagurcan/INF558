/*********************************************************************
TestEx1.c
Author : Francois Morain, morain@lix.polytechnique.fr
Last modification October 9, 2018

*********************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include "collisions.h"

int main(int argc, char *argv[]){
    int r = 421; /* force default */
    if(argc == 1){
	fprintf(stderr, "Usage: %s <imax>\n", argv[0]);
	return 0;
    }
    if(argc > 2)
	r = atoi(argv[2]);
    srand(r);
    int status = find_collisions(atoi(argv[1]));
    if(status == -42){
	printf("Function find_collisions was not completed\n");
    }
    return 0;
}
