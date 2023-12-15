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

static char *client_host;
static int client_port;
static char *user_name;

void set_client_host(const char *ch){
    client_host = malloc(sizeof(char)*strlen(ch)+1);
    strcpy(client_host, ch);
}

void free_client_host(){
    free(client_host);
}

void set_user_name(const char *ch){
    user_name = malloc(sizeof(char)*strlen(ch)+1);
    strcpy(user_name, ch);
}

void free_user_name(){
    free(user_name);
}

void set_client_port(int p){
    client_port = p;
}

int get_client_port(int p){
    return client_port;
}

void handle_reply(char **from, int *portfrom, char **reply, char **packet){
    *packet = network_recv(1);
    if(!parse_packet(from, portfrom, reply, *packet)){
        return;
    };
    printf("Received \"%s\" from %s:%d!\n", *reply, *from, *portfrom);
}

void try_send(const char *host, const int port){
    char *hello = malloc(sizeof(char)*(40+strlen(user_name)+strlen(client_host)+1));
    sprintf(hello, "Hello! My name is %s, calling from %s.", user_name, client_host);
    network_send(host, port, client_host, client_port, hello);
    free(hello);
    char *packet = network_recv(1);
    if (packet == NULL) {
        printf("[ERROR] %s didn't reply to me (%s)\n", host, client_host);
        return;
    }
    free(packet); // discard first reply
    network_send(host, port, client_host, client_port, "I am the client sending to the server.\n");
}

void try_aes(){
    uchar *msg = (uchar*)"It's a long way to Tipperary";
    buffer_t clear, encrypted, key, IV, decrypted;
    mpz_t gab;

    buffer_init(&clear, strlen((char*)msg));
    buffer_init(&encrypted, 1);
    buffer_init(&key, BLOCK_LENGTH);
    buffer_init(&IV, BLOCK_LENGTH);
	
    mpz_init_set_str(gab, "12345612345678907890", 10);
    AES128_key_from_number(&key, gab);
    buffer_random(&IV, BLOCK_LENGTH);
    buffer_from_string(&clear, msg, strlen((char*)msg));

    aes_CBC_encrypt(&encrypted, &clear, &key, &IV, 's');

    buffer_init(&decrypted, 1);
    aes_CBC_decrypt(&decrypted, &encrypted, &key, 's');
    buffer_print(stdout, &decrypted);
    printf("\n");
	
    buffer_clear(&clear);
    buffer_clear(&encrypted);
    buffer_clear(&decrypted);
    buffer_clear(&key);
    buffer_clear(&IV);
    mpz_clear(gab);
}

int send_with_aes(const char *host, const int port, uchar *msg, mpz_t gab){
    int status = NOT_YET_IMPLEMENTED;
/* to be filled in */
    return status;
}

void try_send_aes(const char *host, const int port){
    uchar *msg = (uchar*)"It's a long way to Tipperary";
    mpz_t gab;

    mpz_init_set_str(gab, "12345612345678907890", 10);
    int status = send_with_aes(host, port, msg, gab);
    implementation_check("send_with_aes", status);
    mpz_clear(gab);
}

void prepare_cipher(buffer_t *encrypted, buffer_t *clear, buffer_t *key){
    buffer_t IV;
    buffer_init(&IV, BLOCK_LENGTH);
    buffer_random(&IV, BLOCK_LENGTH);
    aes_CBC_encrypt(encrypted, clear, key, &IV, 's');
    buffer_clear(&IV);
}

void CaseDH(const char *server_host, const int server_port, gmp_randstate_t state){
/* to be filled in */
}

int CaseSTS(const char *server_host, const int server_port,
	    certificate_t *CA, mpz_t NA, mpz_t dA, mpz_t N_aut, mpz_t e_aut,
	    gmp_randstate_t state){
    int retno=NOT_YET_IMPLEMENTED;
/* to be filled in */
    return retno;
}

void CaptureTheFlag(const char *server_host, const int server_port,
                    certificate_t *CA, mpz_t NA, mpz_t dA, mpz_t N_aut,
		    mpz_t e_aut, gmp_randstate_t state){
    // Ask to capture the flag
    char ctf[] = "CTF: CONNECT";
    network_send(server_host, server_port, client_host, client_port, ctf);
    network_send(server_host, server_port, client_host, client_port, user_name);
    int status = CaseSTS(server_host, server_port, CA, NA, dA, 
			 N_aut, e_aut, state);
    implementation_check("CaseSTS", status);
    if (status == 0) {
        printf("[CTF] ERROR, try again.\n");
        return;
    }
    char *packet = network_recv(5);
    char *from, *msg;
    parse_packet(&from, NULL, &msg, packet);
    if (strcmp(from, server_host) != 0) {
        printf("[CTF] You've been hacked by %s!\n", from);
        free(packet);
        free(from);
        free(msg);
        return;
    }
    mpz_t secret;
    mpz_init(secret);
    printf("Message = %s\n", msg);
    if (mpz_set_str(secret, msg, 16) == 0) {
        gmp_printf("[CTF] Congratulations ! You captured your flag!\nSecret=%#Zx\n", secret);
    }
    else {
        printf("[CTF] ERROR, try again.\n");
    }
    free(packet);
    free(from);
    free(msg);
    mpz_clear(secret);
}
