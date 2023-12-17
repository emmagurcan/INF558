#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <getopt.h>
#include <unistd.h>

#include "gmp.h"

#include "base64.h"
#include "buffer.h"
#include "bits.h"
#include "random.h"
#include "base64.h"

#include "operating_modes.h"
#include "aes.h"

#include "version.h"

#include "network.h"
#include "dh.h"
#include "channel.h"

#include "certificate.h"

/* to be filled in */

#ifdef CORRECTION
#define DEBUG 0
#else
#define DEBUG 2
#endif

#define DEFAULT_PORT 31415

static char *server_host;
static int server_port;

/* to be filled in */
#define DEFAULT_HOST "localhost"
/* to be filled in */


void reply(const char *host, const int port){
    char *reply;
    reply = malloc((sizeof(char)* (6+strlen(host)+2)));
    sprintf(reply, "Hello %s!", host);
    network_send(host, port, server_host, server_port, reply);
    free(reply);
}


/* INPUT: mesg = "AES" */
void CaseAES(const char *client_host, const int client_port){
    char *packet = network_recv(-1);
    char *from_Alice;
    parse_packet(NULL, NULL, &from_Alice, packet); // Discard client_host and client_port
    buffer_t in;
    buffer_t z, decrypted, key;
    mpz_t gab;
    int N64 = strlen(from_Alice);

    buffer_init(&key, BLOCK_LENGTH);
    mpz_init_set_str(gab, "12345612345678907890", 10);
    AES128_key_from_number(&key, gab);

    printf("AES/RECV: %s\n", from_Alice);
    fflush(stdout);
    buffer_init(&in, N64);
    buffer_from_string(&in, (uchar *)from_Alice, N64);
    buffer_init(&z, 1);
    buffer_from_base64(&z, &in);

    buffer_init(&decrypted, 1);
    if (!aes_CBC_decrypt(&decrypted, &z, &key, 's')) {
        network_send(client_host, client_port, server_host, server_port, "AES: [FAILED]");
    }
    else {
        network_send(client_host, client_port, server_host, server_port, "AES: [OK]");
        buffer_print(stdout, &decrypted);
        printf("\n\n");
        fflush(stdout);
    }
    mpz_clear(gab);
    buffer_clear(&in);
    buffer_clear(&z);
    buffer_clear(&decrypted);
    buffer_clear(&key);
    free(packet);
    free(from_Alice);
}

/* INPUT: mesg = "DH: ALICE/BOB CONNECT1 0x..." */
void CaseDH(const char *client_host, const int client_port, char *mesg){
    gmp_randstate_t state;
    char buf[1024], *packet, *tmp;
    mpz_t p, g, gb, b, ga, gab;
    buffer_t encrypted, decrypted, key, in;
    int i;
    size_t nbits;

    mpz_inits(p, g, gb, b, ga, gab, NULL);
    channel_init(p, g);
    gmp_randinit_default(state);
#if DEBUG
    gmp_randseed_ui(state, 42);
    nbits = 4;
#else
    gmp_randseed_ui(state, random_seed());
    nbits = mpz_sizeinbase(p, 2)-1;
#endif
    buffer_init(&key, BLOCK_LENGTH);

    /* Bob <-- g^a -- Alice */
    if(msg_import_mpz(ga, mesg, "DH: ALICE/BOB CONNECT1 ", 0) <= 0)
	return;

    /* Bob -- g^b --> Alice */
    DH_init(b, state, nbits);
    mpz_powm_sec(gb, g, b, p);
    msg_export_mpz(buf, "DH: BOB/ALICE CONNECT2 ", gb, 0);
#if DEBUG > 0
    gmp_printf("ga=%Zd, gb=g^%Zd=%Zd\nbuf=%s\n", ga, b, gb, buf);
#endif
    network_send(client_host, client_port, server_host, server_port, buf);
    mpz_powm_sec(gab, ga, b, p);
    gmp_printf("gab=%#Zx\n", gab);

    /* receiving a message encrypted with AES key = gab */
    AES128_key_from_number(&key, gab);
    packet = network_recv(5); // If client doesn't reply in 5 sec then abort.
    if (parse_packet(NULL, NULL, &tmp, packet) == 0) {
        fprintf(stderr, "BAD packet received in DH\n");
        fflush(stderr);
        return;
    }
    printf("Received: %s [%d]\n", tmp, (int)strlen(tmp));
    fflush(stdout);
    if(msg_import_string(buf, tmp, "DH: ALICE/BOB CONNECT3 ") <= 0)
	return;
    free(tmp);
    buffer_init(&in, strlen(buf));
    buffer_from_string(&in, (uchar *)buf, strlen(buf));
    buffer_init(&encrypted, 1);
    buffer_from_base64(&encrypted, &in);
#if DEBUG > 1
    printf("enc="); buffer_print_int(stdout, &encrypted); printf("\n");
#endif
    buffer_init(&decrypted, 1);
    aes_CBC_decrypt(&decrypted, &encrypted, &key, 's');
    printf("check: ");
    for(i = 0; i < decrypted.length; i++)
        printf("%c", decrypted.tab[i]);
    printf("\n\n");
    // Reply OK to the client
    network_send(client_host, client_port, server_host, server_port, "DH: OK");
    fflush(stdout);
    buffer_clear(&decrypted);
    buffer_clear(&encrypted);
    buffer_clear(&in);
    buffer_clear(&key);
    mpz_clears(p, g, gb, b, ga, gab, NULL);
    gmp_randclear(state);
    free(packet);
}

/* INPUT: mesg = "STS: ALICE/BOB CONNECT1 0x..." */
int CaseSTS(const char *client_host, const int client_port, char *mesg,
	     certificate_t *CB, mpz_t NB, mpz_t dB, mpz_t N_aut, mpz_t e_aut, char *user_name){
    certificate_t CA;
    gmp_randstate_t state;
    char buf[1024], *tmp, *from_Alice, *packet;
    mpz_t p, g, gb, b, ga, gab, signB, tmpA, sigmaA;
    buffer_t encrypted, decrypted, clear, z, key, IV, in, out;
    size_t nbits;
    int retno=0;

    if (user_name == NULL) {
        fprintf(stderr, "Initiating STS protocol with %s:%d\n", client_host, client_port);
    }
    else {
        fprintf(stderr, "Initiating STS protocol with %s from %s:%d\n", user_name, client_host, client_port);
    }
    fflush(stderr);

    mpz_inits(p, g, gb, b, ga, gab, sigmaA, signB, tmpA, NULL);
    channel_init(p, g);
    gmp_randinit_default(state);
#if DEBUG
    gmp_randseed_ui(state, 42);
    nbits = 4;
#else
    gmp_randseed_ui(state, random_seed());
    nbits = mpz_sizeinbase(p, 2)-1;
#endif
    /* Bob <-- g^a -- Alice */
    if(msg_import_mpz(ga, mesg, "STS: ALICE/BOB CONNECT1 ", 0) <= 0)
        return retno;

    buffer_init(&key, BLOCK_LENGTH);
    buffer_init(&IV, BLOCK_LENGTH);
    buffer_random(&IV, BLOCK_LENGTH);

    /* Step 2 */
    /**** Step 2.1 ****/
    DH_init(b, state, nbits);
    /**** Step 2.2 ****/
    mpz_powm_sec(gb, g, b, p);
#if DEBUG > 0
    gmp_printf("ga=%Zd, gb=g^%Zd=%Zd\n", ga, b, gb);
#endif
    /**** Step 2.3: gab = k <- (g^a)^b = ga^b ****/
    mpz_powm_sec(gab, ga, b, p);
#if DEBUG > 0
    gmp_printf("gab=%#Zx\n", gab);
#endif
    AES128_key_from_number(&key, gab);
#if DEBUG > 0
    printf("\nkey="); buffer_print_int(stdout, &key); printf("\n");
#endif
    /**** Step 2.4: sigma_B <- SIGN_{SK_B}(gb, ga) ****/
    SIGNSK(signB, gb, ga, p, NB, dB);
#if DEBUG > 0
    gmp_printf("sigmaB=%Zd\n", signB);
#endif
    /**** Step 2.5:       y <- ENCRYPT_k(sigma_B) ****/
    buffer_init(&clear, 1);
    buffer_from_mpz(&clear, signB);
#if DEBUG > 1
    printf("\nclear="); buffer_print_int(stdout, &clear); printf("\n");
#endif
    buffer_init(&encrypted, 1);
    aes_CBC_encrypt(&encrypted, &clear, &key, &IV, 's');
#if DEBUG > 1
    printf("\nenc="); buffer_print_int(stdout, &encrypted); printf("\n\n");
#endif
    /**** Step 2.6: send (y, gb, certif_B) ****/
    buffer_init(&out, 10);
    buffer_to_base64(&out, &encrypted);
    tmp = (char*)string_from_buffer(&out);
#if DEBUG > 0
    printf("\nServer sending: %s\n\n", tmp);
#endif
    msg_export_string(buf, "STS: BOB/ALICE CONNECT2 ", tmp);
    free(tmp);
    network_send(client_host, client_port, server_host, server_port, buf);

    msg_export_mpz(buf, "STS: BOB/ALICE CONNECT2 ", gb, 0);
    network_send(client_host, client_port, server_host, server_port, buf);
    tmp = (char*)string_from_certificate(CB);
    msg_export_string(buf, "STS: BOB/ALICE CONNECT2 ", tmp);
    free(tmp);
    network_send(client_host, client_port, server_host, server_port, buf);

    /**** Step 4: Bob receives z and CA ****/
    packet = network_recv(-1);
    parse_packet(NULL, NULL, &from_Alice, packet);
    /* from_Alice = "STS: ALICE/BOB CONNECT3 z" */
    if(msg_import_string(buf, from_Alice, "STS: ALICE/BOB CONNECT3 ") <= 0){
        free(from_Alice);
        free(packet);
        return retno;
    }
    free(from_Alice);
    free(packet);
#if DEBUG > 0
    printf("server receives: %s\n\n", buf);
#endif
    buffer_init(&in, 1);
    buffer_from_string(&in, (uchar*)buf, strlen(buf));
    buffer_init(&z, 1);
    buffer_from_base64(&z, &in);
    packet = network_recv(-1);
    parse_packet(NULL, NULL, &from_Alice, packet);
    free(packet);
    /* from_Bob = "STS: ALICE/BOB CONNECT3 CA" */
    if(msg_import_string(buf, from_Alice, "STS: ALICE/BOB CONNECT3 ") <= 0){
        free(from_Alice);
        return retno;
    }
    free(from_Alice);
#if DEBUG > 0
    printf("server receives:\nCA=\n%s\n", buf);
#endif
    init_certificate(&CA);
    certificate_from_string(&CA, buf);
    /**** Step 4.1: verify certif_A ****/
#if DEBUG > 0
    printf("Is CA-client valid: %d\n", valid_certificate(&CA, N_aut, e_aut));
#endif
    if (!valid_certificate(&CA, N_aut, e_aut)) {
        fprintf(stderr, "Certificate of %s is invalid!\n\n", CA.user);
        fflush(stderr);
        gmp_randclear(state);
        buffer_clear(&in);
        buffer_clear(&z);
        buffer_clear(&encrypted);
        buffer_clear(&out);
        buffer_clear(&IV);
        buffer_clear(&key);
        buffer_clear(&clear);
        mpz_clears(p, g, gb, b, ga, gab, sigmaA, signB, tmpA, NULL);
        clear_certificate(&CA);
        return retno;
    }
    if (user_name != NULL && strcmp(CA.user, user_name) != 0) {
        fprintf(stderr, "[ERROR] User %s tried to cheat in CTF with certificate issued for %s!\n\n", user_name, CA.user);
        fflush(stderr);
        network_send(client_host, client_port, server_host, server_port, "[ERR] CHEATER !\n");
        gmp_randclear(state);
        buffer_clear(&in);
        buffer_clear(&z);
        buffer_clear(&encrypted);
        buffer_clear(&out);
        buffer_clear(&IV);
        buffer_clear(&key);
        buffer_clear(&clear);
        mpz_clears(p, g, gb, b, ga, gab, sigmaA, signB, tmpA, NULL);
        clear_certificate(&CA);
        return retno;
    }
    /**** Step 4.2: verify sign_A ****/
    buffer_init(&decrypted, 1);
    /* decrypted <- dec(z) should be sigmaA */
    aes_CBC_decrypt(&decrypted, &z, &key, 's');
    /* feed sigmaA = SIGN_{SK_A}(ga || gb) */
    buffer_to_mpz(sigmaA, &decrypted);
    /* we should check sigmaA^e = ga || gb */
    concatenate_gb_ga(tmpA, ga, gb, p);
    mpz_powm_sec(sigmaA, sigmaA, CA.e, CA.N);
#if DEBUG >= 1
    printf("signature z is valid? %d\n\n", 1-mpz_cmp(tmpA, sigmaA));
#endif
    if (mpz_cmp(tmpA, sigmaA) != 0) {
        fprintf(stderr, "Signature of %s is invalid !\n\n", CA.user);
        fflush(stderr);
	goto clear;
    }

    /* last message: "OK" */
    buffer_from_string(&clear, (uchar*)"OK", 2);
    aes_CBC_encrypt(&encrypted, &clear, &key, &IV, 's');
    buffer_to_base64(&out, &encrypted);
    tmp = (char*)string_from_buffer(&out);
#if DEBUG > 0
    printf("server sends: %s\n\n", tmp);
#endif
    msg_export_string(buf, "STS: BOB/ALICE CONNECT4 ", tmp);
    network_send(client_host, client_port, server_host, server_port, buf);
    free(tmp);
    retno = 1;
    fprintf(stderr, "STS was successfully run.\n");
    fflush(stderr);
 clear:
    clear_certificate(&CA);
    gmp_randclear(state);
    buffer_clear(&encrypted);
    buffer_clear(&decrypted);
    buffer_clear(&clear);
    buffer_clear(&z);
    buffer_clear(&key);
    buffer_clear(&IV);
    buffer_clear(&in);
    buffer_clear(&out);
    mpz_clears(p, g, gb, b, ga, gab, sigmaA, signB, tmpA, NULL);
#if DEBUG > 0
    printf("\n");
#endif
    return retno;
}

void CaseCTF(const char *client_host, const int client_port, char *mesg,
	     certificate_t *CB, mpz_t NB, mpz_t dB, mpz_t N_aut, mpz_t e_aut){
/* to be filled in */
#ifndef CORRECTION
    printf("Tut tut tut, ask the server !\n");
#endif
}


void Usage(char *s){
    fprintf(stderr, "Server for version %s\n\n", VERSION);
    fprintf(stderr, "Usage: %s\t[--hostname SERVER_HOST (default %s)]\n", s, DEFAULT_HOST);
    fprintf(stderr, "\t\t[--listen SERVER_PORT (default %d)]\n", DEFAULT_PORT);
    fprintf(stderr, "\t\t[ OPTIONAL FILES ]\n");

    fprintf(stderr, "\nOptional files (Required for STS):\n\n");
    fprintf(stderr, "\tserver_certificate.txt\n");
    fprintf(stderr, "\tserver_sk.txt\n");
    fprintf(stderr, "\tauth_pk.txt\n");
}


void free_memory(int signal){
    network_clear();
    free(server_host);
    exit(0);
}

int main(int argc, char *argv[])
{
    FILE *in;
    char *packet, *mesg, *client_host;
    int client_port, retno;
    certificate_t CB;
    mpz_t NB, dB, N_aut, e_aut;
    signal(SIGINT, &free_memory);  // free memory if SIGINT (=CTRL+C)

    int capture_the_flag = 0;

/* to be filled in */

    static int random_port_flag;
    int server_host_defined=0, server_port_defined=0;

    static struct option long_options[] = {
        {"random", no_argument, &random_port_flag, 1},
        {"help", no_argument, 0, 'h'},
        {"hostname", required_argument, 0, 's'},
        {"listen", required_argument, 0, 'l'},
        {NULL, 0, 0, '\0'}
    };


    int long_index = 0;
    int opt=0;

    while ((opt = getopt_long(argc, argv, "hl:",
                              long_options, &long_index )) != -1) {
        switch (opt) {
            case 0:
                break;
            case 'h':
                Usage(argv[0]);
                return 0;
            case 'l':
                server_port = atoi(optarg);
                server_port_defined = 1;
                break;
            case 's':
                server_host = malloc(sizeof(char)*strlen(optarg)+1);
                strcpy(server_host, optarg);
                server_host_defined = 1;
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
        server_host_defined=1;
        server_host = malloc(sizeof(char)*(strlen(DEFAULT_HOST)+1));
        strcpy(server_host, DEFAULT_HOST);
    }

    if (!server_port_defined) {
        server_port = DEFAULT_PORT;
    }

    if (random_port_flag || check_port(server_port) == 0) {
        server_port_defined = 1;
        srand(random_seed());
        do {
            server_port = (rand() % (65535 - 1024 + 1) + 1024);
        } while (check_port(server_port) == 0);
    }

    printf("Server for version %s\n", VERSION);
    fflush(stdout);
#if DEBUG > 0
    printf("Port = %d\n", server_port);
#endif
#ifdef CORRECTION
    write_port("port.txt", server_port);
#endif
    printf("\n");
    fflush(stdout);
    network_init(server_port);
    while(1){
        packet = network_recv(1);
        if (packet == NULL) {
#ifndef CORRECTION
            printf("Nothing arrived!\n");
            fflush(stdout);
#endif
        }
        else{
            retno = parse_packet(&client_host, &client_port, &mesg, packet);
            if (retno == 0){
                fprintf(stderr, "BAD packet received!\n");
                fflush(stderr);
                continue;
            }
            printf("RECV: %s\n", mesg);
            fflush(stdout);
            if(strlen(mesg) >= 3 && strncmp(mesg, "AES", 3) == 0){
                CaseAES(client_host, client_port);
            }
            else if(strlen(mesg) > 3 && strncmp(mesg, "DH: ", 4) == 0)
                CaseDH(client_host, client_port, mesg);
            else if(strlen(mesg) > 4 && (strncmp(mesg, "STS: ", 5) == 0 ||
                                         strncmp(mesg, "CTF: ", 5) == 0)) {
                if (strncmp(mesg, "CTF: ", 5) == 0) {
                    capture_the_flag = 1;
                    printf("Capture the flag !\n");
                    fflush(stdout);
                }
		/* TODO: this test arrives much too late */
                if(argc == optind){
                    fprintf(stderr, "Missing argument: server_certificat.txt");
                    fflush(stderr);
                    break;
                }
                if((in = fopen(argv[optind], "r")) == NULL){
                    perror(argv[optind]);
                    return -1;
                }
                init_certificate(&CB);
                extract_certificate(&CB, in);
                fclose(in);
#if DEBUG > 0
                print_certificate(&CB);
#endif
                if(argc == optind+1){
                    fprintf(stderr, "Missing argument: server_sk.txt");
                    fflush(stderr);
                    break;
                }
                if((in = fopen(argv[optind+1], "r")) == NULL){
                    perror(argv[optind+1]);
                    return -1;
                }
                mpz_inits(NB, dB, N_aut, e_aut, NULL);
                read_secret_keys(NB, dB, in);
                fclose(in);


                if(argc == optind+2){
                    fprintf(stderr, "Missing argument: auth_pk.txt");
                    fflush(stderr);
                    break;
                }

                if((in = fopen(argv[optind+2], "r")) == NULL){
                    perror(argv[optind+2]);
                    return -1;
                }
                read_public_keys(N_aut, e_aut, in);
                fclose(in);
#if DEBUG > 0
                gmp_printf("N_aut:=%Zd; e_aut:=%Zd;\n", N_aut, e_aut);
                printf("\nvalid certificate for CB-server? %d\n\n",
                       valid_certificate(&CB, N_aut, e_aut));
#endif
                if (capture_the_flag) {
                    CaseCTF(client_host, client_port, mesg, &CB,
                            NB, dB, N_aut, e_aut);
                }
                else {
                    CaseSTS(client_host, client_port, mesg, &CB,
                            NB, dB, N_aut, e_aut, NULL);
                    printf("\n");
                }
                mpz_clears(NB, dB, N_aut, e_aut, NULL);
		capture_the_flag = 0;
                clear_certificate(&CB);
            }
            else {
                reply(client_host, client_port);
            }
            free(packet);
            free(client_host);
            free(mesg);
        }
    }
    free(server_host);
    network_clear();
    return 0;
}
