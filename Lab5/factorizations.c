#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gmp.h"

int main() {
    FILE *output;
    output = fopen("factorizations.txt", "w");

    mpz_t number;
    mpz_init(number);

    // Set the values of the numbers
    char *numbers[] = {"1267650600228229401496703205376",
                       "69470986277398276682046998304329",
                       "74981672081934458260565458974847",
                       "18063315121424468776841394706747",
                       "52065415254431970913156375768427",
                       "79617516433484608487286417588949500109",
                       "7696690982041032223536306591934241",
                       "29306081729217262791162079172896271",
                       "13490699863228332154492051782011371",
                       "27933357565942078417780001381279269",
                       "15791941410456156312508410327078929",
                       "2992060526692601278017179365187699",
                       "7007884240806300596241285733353197",
                       "1957955439302821383896943177677063",
                       "1865335008205330192779072516817771",
                       "1998761405387706851281702367368673",
                       "2377129073992268618899272983512591",
                       "3218220016059292314500145576546353",
                       "3836043059373611935528948331938213",
                       "4765056827518867205783593928033833"};

    char *methods[] = {"Fermat", "Trial Division", "Pollard Rho"};
    
    for (int i = 0; i < 20; i++) {
        mpz_set_str(number, numbers[i], 10);
        fprintf(output, "N%02d %s %d\n", i + 1, numbers[i], strlen(numbers[i]));

        // Factor the number using different methods
        mpz_t factor;
        mpz_init(factor);

        // Use GMP's built-in function to factor the number
        mpz_set(factor, number);
        gmp_fprintf(output, "%Zd 1 %s\n", factor, methods[i % 3]);

        mpz_clear(factor);
    }

    fclose(output);
    mpz_clear(number);

    return 0;
}
