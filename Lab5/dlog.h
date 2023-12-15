/****************************************************************/
/* dlog.h                                                       */
/* Authors: Alain Couvreur, FMorain                             */
/* alain.couvreur@lix.polytechnique.fr,morain@lix               */
/* Last modification October 16, 2023                           */
/****************************************************************/

#define DLOG_ERROR       0
#define DLOG_OK          1
#define DLOG_FOUND       2
#define DLOG_NOT_FOUND   3
#define DLOG_SMALL_ORDER 4

int babySteps(mpz_t result, hash_table H, mpz_t g, mpz_t nBabySteps, mpz_t p);
int giantSteps(mpz_t result, hash_table H, mpz_t g, mpz_t ordg, mpz_t nBabySteps, mpz_t p, mpz_t kz);
int BSGS(mpz_t result, mpz_t a, mpz_t g, mpz_t p);
