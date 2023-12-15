#ifndef __FRS__CHANNEL

void channel_init(mpz_t p, mpz_t g);

int msg_import_mpz(mpz_t n, char *in, const char *prefix, int base);
void msg_export_mpz(char *buf, const char *prefix, mpz_t n, int base);
int msg_import_string(char *buf, char *in, const char* prefix);
void msg_export_string(char *buf, const char *prefix, const char* in);

#endif
