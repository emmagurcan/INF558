/*! \file eol.c
  \author François Morain (morain@lix.polytechnique.fr)
  \date November 29, 2020.
  \details Skipping '\r' characters from file.
******************************************************************/

#include <stdio.h>

int main(int argc, char *argv[]){
    FILE *ifile = NULL, *ofile = NULL;
    char c;
    if(argc <= 2){
	fprintf(stderr, "Usage: %s in out\n", argv[0]);
	return 0;
    }
    if((ifile = fopen(argv[1], "r")) == NULL){
	perror(argv[1]);
	return 0;
    }
    if((ofile = fopen(argv[2], "w")) == NULL){
	fclose(ifile);
	perror(argv[2]);
	return 0;
    }
    while(1){
	c = fgetc(ifile);
	if(feof(ifile))
	    break;
	if(c == '\r')
	    fprintf(stderr, "Skipping character \\r\n");
	else
	    fputc(c, ofile);
    }
    fclose(ifile);
    fclose(ofile);
    return 0;
}
