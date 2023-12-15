int PollardPminus1Step1(mpz_t factor, const mpz_t N, long bound1, FILE* ficdp,
			mpz_t b, mpz_t p);
int PollardPminus1Step2(mpz_t factor, const mpz_t N, long bound2, FILE* ficdp,
			mpz_t b, mpz_t p);
int PollardPminus1(factor_t* res, int *nf, const mpz_t N,
		   long bound1, long bound2, FILE* ficdp);
