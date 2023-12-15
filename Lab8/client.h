#define DEFAULT_SERVER_PORT 31415
#define DEFAULT_PORT 1789
#define DEFAULT_HOST "localhost"
#define DEFAULT_NAME "john.smith"

void set_client_host(const char *ch);
void free_client_host();
void set_user_name(const char *ch);
void free_user_name();
void set_client_port(int p);
int get_client_port();

void handle_reply(char **from, int *portfrom, char **reply, char **packet);

void try_send(const char *host, const int port);
void try_aes();
void try_send_aes(const char *host, const int port);
void CaseDH(const char *server_host, const int server_port, gmp_randstate_t state);
void CaptureTheFlag(const char *server_host, const int server_port,
                    certificate_t *CA, mpz_t NA, mpz_t dA, mpz_t N_aut,
		    mpz_t e_aut, gmp_randstate_t state);
int CaseSTS(const char *server_host, const int server_port,
	    certificate_t *CA, mpz_t NA, mpz_t dA, mpz_t N_aut, mpz_t e_aut,
	    gmp_randstate_t state);
