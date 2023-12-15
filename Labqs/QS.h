/* y^2 = prod p_i^e_i mod kN */
typedef struct{
    mpz_t y;
    char *tabex;
} relation_t;

extern int QS_aux(factor_t *tabf, int *nf, mpz_t N, mpz_t kN, mpz_t g, int *B, int cardB, int M, int phase);
extern int QS(factor_t *tabf, int *nf, mpz_t N, int k, int cardB, int M, FILE *file, int phase);

