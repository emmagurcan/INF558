int PollardRho_with_long(long *factor, const long N, long nbOfIterations);

int PollardRhoSteps(mpz_t factor, const mpz_t N,
		    void (*f)(mpz_t, mpz_t, const mpz_t),
		    long nbOfIterations);
int PollardRho(factor_t* result, int *nf, const mpz_t N,
	       void (*f)(mpz_t, mpz_t, const mpz_t),
	       long nrOfIterations);
