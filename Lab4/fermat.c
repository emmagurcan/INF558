#include <stdio.h>
#include <stdlib.h>
#include "gmp.h"



void fermat(int a0, int pmin, int pmax, int composites){
/* to be filled in */
}


void Usage(char *cmd){
    fprintf(stderr, "Usage: %s a pmin pmax [0|1]\n", cmd);
}


int main (int argc, char *argv[]){
    if(argc < 4){
	Usage(argv[0]);
	return 0;
    }
    int composites = 0;
    if(argc == 5)
	composites = atoi(argv[4]);
    fermat(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), composites);
    return 0;
}
