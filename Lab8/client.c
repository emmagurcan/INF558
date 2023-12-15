#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>
#include <unistd.h>

#include "gmp.h"

#include "utilities.h"

#include "base64.h"
#include "buffer.h"
#include "bits.h"
#include "random.h"

#include "operating_modes.h"
#include "aes.h"

#include "version.h"

#include "network.h"
#include "dh.h"
#include "channel.h"

#include "certificate.h"
#include "client.h"

/* to be filled in */

#ifdef CORRECTION
#define DEBUG 0
#else
#define DEBUG 2
#endif

void Usage(char *s){
    fprintf(stderr, "Client for version %s\n\n", VERSION);
    fprintf(stderr, "Usage: %s\t[--sendto SERVER_HOST (default %s)] [--port SERVER_PORT (default %d)]\n", s, DEFAULT_HOST, DEFAULT_SERVER_PORT);
    /* fprintf(stderr, ""); */
    fprintf(stderr, "\t\t[--hostname CLIENT_HOST (default %s)]\n", DEFAULT_HOST);
    fprintf(stderr, "\t\t[--listen CLIENT_PORT (default %d)]\n", DEFAULT_PORT);
    fprintf(stderr, "\t\t[ try_send | try_aes | try_send_aes | try_DH | try_STS | try_CTF ]\n");
    fprintf(stderr, "\t\t[--help]");
    fprintf(stderr, " [--name NAME]\n");
    fprintf(stderr, "\t\t[ OPTIONAL FILES ]\n");

    fprintf(stderr, "\nArguments:\n");
    fprintf(stderr, "\tNAME: \t\tOf the form name.lastname, lowercase [Example: %s].\n", DEFAULT_NAME);
    fprintf(stderr, "\ttry_send: \tTry to send a basic message. Modify and play with this function.\n");
    fprintf(stderr, "\ttry_aes: \tTry to encrypt a basic message with AES. Don't send anything.\n");
    fprintf(stderr, "\ttry_send_aes: \tEncrypt and send a basic message with AES.\n");
    fprintf(stderr, "\ttry_DH: \tPerform DH key exchange and encrypt a message with the shared key.\n");
    fprintf(stderr, "\ttry_STS: \tPerform Station-To-Station protocol with the server.\n");
    fprintf(stderr, "\ttry_CTF: \tTry to retrieve the secret flag prepared for you. Needs your name.\n");

    fprintf(stderr, "\nOptional files (Required for STS and CTF):\n\n");
    fprintf(stderr, "\tclient_certificate.txt\n\tclient_sk.txt\n\tauth_pk.txt\n");
}

int main(int argc, char *argv[])
{
    int opt=0;
    char *server_host;
    int server_host_defined = 0, server_port_defined=0;
    int client_host_defined=0, client_port_defined=0;
    int user_name_defined=0;
    int sts_flag=0, capture_the_flag=0;
    int server_port;
    FILE *in;
    certificate_t CA;
    mpz_t NA, dA, N_aut, e_aut;
    char *packet, *reply, *from;
    int portfrom;
    gmp_randstate_t state;

    static int random_port_flag;

    static struct option long_options[] = {
        {"random", no_argument, &random_port_flag, 1},
        {"help", no_argument, 0, 'h'},
        {"sendto", required_argument, 0, 's'},
        {"port", required_argument, 0, 'p'},
        {"hostname", required_argument, 0, 'c'},
        {"listen", required_argument, 0, 'l'},
        {"name", required_argument, 0, 'n'},
        {NULL, 0, 0, '\0'}
    };

    int long_index = 0;
    while ((opt = getopt_long(argc, argv, "hs:p:c:l:n:",
                              long_options, &long_index )) != -1) {
        switch (opt) {
            case 0:
                break;
            case 'h':
                Usage(argv[0]);
                return 0;
            case 's':
                server_host = malloc(sizeof(char)*strlen(optarg)+1);
                strcpy(server_host, optarg);
                server_host_defined = 1;
                break;
            case 'p':
                server_port = atoi(optarg);
                server_port_defined = 1;
                break;
            case 'c':
                set_client_host(optarg);
                client_host_defined = 1;
                break;
            case 'l':
                set_client_port(atoi(optarg));
                client_port_defined = 1;
                break;
            case 'n':
                set_user_name(optarg);
                user_name_defined=1;
                break;
            case '?':
                fprintf(stderr, "Try %s --help\n", argv[0]);
                return 1;
            default:
                Usage(argv[0]);
                return 0;
        }

    }

    if (!server_host_defined) {
        server_host = malloc(sizeof(char)*(strlen(DEFAULT_HOST))+1);
        sprintf(server_host, "%s", DEFAULT_HOST);
        server_host_defined=1;
    }

    if (!server_port_defined) {
        server_port = DEFAULT_SERVER_PORT;
        server_port_defined=1;
    }

    if (!server_host_defined || !server_port_defined ) {
        Usage(argv[0]);
        return 0;
    }
    if (!client_host_defined) {
	set_client_host(DEFAULT_HOST);
    }
    if (!client_port_defined) {
        set_client_port(DEFAULT_PORT);
    }

    if (!user_name_defined) {
        set_user_name(DEFAULT_NAME);
        user_name_defined=0;
    }

    if (random_port_flag || check_port(get_client_port()) == 0) {
        client_port_defined=1;
        srand(random_seed());
        do {
            set_client_port((rand() % (65535 - 1024 + 1) + 1024));
        } while (check_port(get_client_port()) == 0);
    }

    network_init(get_client_port());
    mpz_inits(NA, dA, N_aut, e_aut, NULL);
    gmp_randinit_default(state);

    if (argc == optind) {
        Usage(argv[0]);
        goto clear;
        return 0;
    }
    else {
        printf("Client for version %s\n", VERSION);
        if (strcmp(argv[optind], "try_send") == 0){
            try_send(server_host, server_port);
            handle_reply(&from, &portfrom, &reply, &packet);
            free(from);
            free(reply);
            free(packet);
            goto clear;
        }
        if(strcmp(argv[optind], "try_send_aes") == 0){
            try_send_aes(server_host, server_port);
            handle_reply(&from, &portfrom, &reply, &packet);
            free(from);
            free(reply);
            free(packet);
            goto clear;
        }
        if(strcmp(argv[optind], "try_aes") == 0){
            try_aes();
            goto clear;
        }
        if(strcmp(argv[optind], "try_DH") == 0){
            printf("Go for DH: \n");
            CaseDH(server_host, server_port, state);
            char *packet2 = network_recv(5);
            if (packet2 != NULL) {
                char *reply2;
                parse_packet(NULL, NULL, &reply2, packet2);
                if (strcmp(reply2, "DH: OK")==0) {
                    printf("try_DH: [OK]\n");

                }
                else {
                    printf("try_DH: [FAILED]\n");
                }
                free(packet2);
                free(reply2);
            }
            else {
                printf("try_DH: [FAILED]\n");
            }
            goto clear;
        }


        if(strcmp(argv[optind], "try_STS") == 0) {
            sts_flag=1;
        }
        if(strcmp(argv[optind], "try_CTF") == 0){
            capture_the_flag=1;
        }
        if (sts_flag || capture_the_flag) {
            if (argc-optind<3) {
                fprintf(stderr, "\nWrong arguments. Try %s --help\n\n", argv[0]);
                goto clear;
            }
            if((in = fopen(argv[++optind], "r")) == NULL){ // client_certificate.txt
                perror(argv[optind]);
                return -1;
            }
            optind++;
            init_certificate(&CA);
            extract_certificate(&CA, in);
            fclose(in);
#if DEBUG > 0
            print_certificate(&CA);
#endif

            if((in = fopen(argv[optind], "r")) == NULL){ // client_secret_key
                perror(argv[optind]);
                return -1;
            }
            optind++;
            read_secret_keys(NA, dA, in);
#if DEBUG > 0
            gmp_printf("\nNA=%Zd,\ndA=%Zd\n\n", NA, dA);
#endif
            fclose(in);

            if((in = fopen(argv[optind], "r")) == NULL){ // auth_public_key
                perror(argv[optind]);
                return -1;
            }
            optind++;
            read_public_keys(N_aut, e_aut, in);
            fclose(in);
#if DEBUG > 0
            gmp_printf("\nN_aut:=%Zd;\ne_aut:=%Zd;\n\n", N_aut, e_aut);
#endif
            if (!valid_certificate(&CA, N_aut, e_aut)) {
                fprintf(stderr, "[ERROR] Client certificate is not valid!\n");
                exit(-1);
            }
#if DEBUG > 0
            printf("valid certificate for CA-client? %d\n",
                   valid_certificate(&CA, N_aut, e_aut));
#endif
            if (sts_flag) {
                printf("Go for STS: \n");
                int status = CaseSTS(server_host, server_port, &CA, NA, dA,
				     N_aut, e_aut, state);
		implementation_check("CaseSTS", status);
            }
            else if (capture_the_flag) {
                CaptureTheFlag(server_host, server_port, &CA, NA, dA, N_aut, e_aut, state);
            }
            clear_certificate(&CA);
        }
    }
    clear:
       free(server_host);
       free_client_host();
       free_user_name();
       mpz_clears(NA, dA, N_aut, e_aut, NULL);
       gmp_randclear(state);
       network_clear();
       return 0;
}
