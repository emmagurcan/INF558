#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "gmp.h"

#include "utilities.h"

#include "random.h"
#include "buffer.h"
#include "rsa.h"
#include "sha3.h"
#include "sign.h"
#include "dsa.h"
#include "attack_dsa.h"

#define DEBUG 0

/* to be filled in */


int basic_test(buffer_t *pub_ref, buffer_t *pub_verif,
	       buffer_t *sec_ref, buffer_t *sec_verif,
	       int line){
    int i = 1;
    if(!buffer_equality(pub_ref, pub_verif)){
	printf("[ERROR] Line %d of Public key file has not", line);
	printf(" the good format.\n");
	i = 0;
    }
    if(!buffer_equality(sec_ref, sec_verif)){
	printf("[ERROR] Line %d of Secret key file has not", line);
	printf(" the good format.\n");
	i = 0;
    }
    return i;
}


void test1(gmp_randstate_t state){
    // 1. INIT
    size_t nbits = 256;
    int sec = 50;

    // 3. Generate keys
    printf("Key generation...\n");
    const char* pub_str = "RSA_pub.txt";
    const char* sec_str = "RSA_sec.txt";
    int status = RSA_generate_key_files(pub_str, sec_str, nbits, sec, state);
    implementation_check("RSA_generate_key_files", status);
    printf("Done\n");

    // 4. Verfies the key files
    FILE *pk = fopen(pub_str, "r");
    FILE *sk = fopen(sec_str, "r");
    if(pk == NULL)
	printf("[ERROR] No public key file created.\n");	
    if(sk == NULL)
	printf("[ERROR] No secret key file created.\n");
    if(pk == NULL || sk == NULL)
	return;
		
    buffer_t pub_verif, sec_verif, pub_ref, sec_ref;
    buffer_init(&pub_verif, 30);
    buffer_init(&sec_verif, 30);
    buffer_init(&pub_ref, 30);
    buffer_init(&sec_ref, 30);

    uchar *pstr = (uchar *)"#RSA Public key (256 bits):";
    uchar *sstr = (uchar *)"#RSA Secret key (256 bits):";
    buffer_from_string(&pub_ref, pstr, 27);
    buffer_from_string(&sec_ref, sstr, 27);

    uchar c;
    while((c = fgetc(pk)) != '\n')
	buffer_append_uchar(&pub_verif, c);
    while((c = fgetc(sk)) != '\n')
	buffer_append_uchar(&sec_verif, c);
    if(!basic_test(&pub_ref, &pub_verif, &sec_ref, &sec_verif, 1))
	return;
	
    buffer_reset(&pub_verif);
    buffer_reset(&sec_verif);
    buffer_reset(&pub_ref);
    buffer_reset(&sec_ref);
    pstr = (uchar *)"N = 0x";
    buffer_from_string(&pub_ref, pstr, 6);
    buffer_from_string(&sec_ref, pstr, 6);
    for(int i = 0; i < 6; i++){
	buffer_append_uchar(&pub_verif, fgetc(pk));
	buffer_append_uchar(&sec_verif, fgetc(sk));
    }	
    if(!basic_test(&pub_ref, &pub_verif, &sec_ref, &sec_verif, 2))
	return;

    while((c = fgetc(pk)) != '\n');
    while((c = fgetc(sk)) != '\n');
	
    buffer_reset(&pub_verif);
    buffer_reset(&sec_verif);
    buffer_reset(&pub_ref);
    buffer_reset(&sec_ref);
    pstr = (uchar *)"e = 0x";
    sstr = (uchar *)"d = 0x";
    buffer_from_string(&pub_ref, pstr, 6);
    buffer_from_string(&sec_ref, sstr, 6);
    for(int i = 0; i < 6; i++){
	buffer_append_uchar(&pub_verif, fgetc(pk));
	buffer_append_uchar(&sec_verif, fgetc(sk));
    }	
    if(!basic_test(&pub_ref, &pub_verif, &sec_ref, &sec_verif, 3))
	return;

    printf("\nKey generation [OK].\n\n");
	
    // 5. Cleaning
    fclose(pk);
    fclose(sk);
    buffer_clear(&pub_verif);
    buffer_clear(&sec_verif);
    buffer_clear(&pub_ref);
    buffer_clear(&sec_ref);
}


void test2(){
    /* 1. INIT */
    mpz_t N, e, d, Nref, eref, dref;
    mpz_inits(N, e, d, Nref, eref, dref, NULL);

    /* 2. Defined references */
    mpz_set_str(Nref, "0xd5d3ffc9cbed4fe82f31e7eb0c5fd9240f5602e471c6aaba51c9b226b4675eeb", 0);
    mpz_set_str(eref, "0x6057fcff1d4a2f3bc7f562e82026a08155a255133b79ec37c8df421b5c7938a1", 0);
    mpz_set_str(dref, "0x71306deaf57708eb08ae09a8eb3c1c680b1b249e1c670f986cd55f862c3b4635", 0);
    gmp_printf("References:\nN = %#Zx\ne = %#Zx\nd = %#Zx\n\n", Nref, eref, dref);
	
    /* 3. Import */
    RSA_key_import(N, e, "./data/RSA_pub_ref.txt");
    gmp_printf("Test public key:\nN = %#Zx\ne = %#Zx.\n\n", N, e);
	
    int Np, ep, Ns, ds;
    Np = mpz_cmp(N, Nref);
    ep = mpz_cmp(e, eref);
		
    RSA_key_import(N, d, "./data/RSA_sec_ref.txt");
    gmp_printf("Test secret key:\nN = %#Zx\nd = %#Zx.\n\n", N, d);

    /* 4. Compare with references */
    Ns = mpz_cmp(N, Nref);
    ds = mpz_cmp(d, dref);

    if(Np == 0 && ep == 0 && Ns == 0 && ds == 0)
	printf("[TEST OK]\n\n");
    else{
	if(Np != 0)
	    printf("Wrong N for public key.\n");
	if(ep != 0)
	    printf("Wrong e.\n");
	if(Ns != 0)
	    printf("Wrong N for secret key.\n");
	if(ds != 0)
	    printf("Wrong d.\n");
	printf("[TEST FAILED]\n\n");
    }

    /* 5. Cleaning */
    mpz_clears(N, e, d, Nref, eref, dref, NULL);
}


void test3(){
    /* 1. INIT */
    uchar* message = (uchar *)"Fear is the path to the dark side. Fear leads to anger. Anger leads to hate. Hate leads to suffering.";
    mpz_t N, d, e, sgn;
    buffer_t msg;

#ifdef CORRECTION
    mpz_t my_sgn;
    mpz_init(my_sgn);
#endif

    mpz_inits(N, d, e, sgn, NULL);
    buffer_init(&msg, strlen((char *)message));
    /* 2. Import */
    const char* pub_str = "./data/RSA_pub_ref.txt";
    const char* sec_str = "./data/RSA_sec_ref.txt";

    RSA_key_import(N, d, sec_str);
    RSA_key_import(N, e, pub_str);
    buffer_from_string(&msg, message, strlen((char *)message));

    /* 3. Sign */
    int status = RSA_sign_buffer(sgn, &msg, N, d);
    implementation_check("RSA_sign_buffer", status);

#ifndef CORRECTION
    gmp_printf("Message : %s\n\nSignature : %#Zx\n\n", message, sgn);
#endif

#ifdef CORRECTION
    my_RSA_sign_buffer(my_sgn, &msg, N, d);
    printf("Checking signature algorithm ......... ");
    if (my_RSA_verify_signature(sgn, &msg, N, e)) {
        printf("[OK]\n");
    }
    else {
        printf("[FAILED]\n");
    }
#endif

    /* 4. Verify */
#ifdef CORRECTION
    printf("Checking verification algorithm ...... ");
    if(RSA_verify_signature(my_sgn, &msg, N, e))
#else
    int verif = RSA_verify_signature(sgn, &msg, N, e);
    implementation_check("RSA_verify_signature", status);
    
    printf("Verification:   ");
    if(verif != 0)
#endif
	printf("[OK]\n\n");
    else
	printf("[FAILED]\n\n");

    /* 5. Cleaning */
    mpz_clears(N, d, e, sgn, NULL);
    buffer_clear(&msg);
}


void read_file(const char* name){
    FILE* file = fopen(name, "r");
    char current = fgetc(file);
    while(current != EOF){
	printf("%c", current);
	current = fgetc(file);
    }
    fclose(file);
}


void test4(){
    /* 0. Define string names */
    const char* msg = "./data/Duck_salad.txt";
    const char* sec_str = "./data/RSA_sec_ref.txt";
    const char* sgn = "Duck_salad_RSA_signature.txt";
    const char* pub_str = "./data/RSA_pub_ref.txt";
	
    /* 1. Print message */
    printf("Message : \n\n");
    read_file(msg);

    /* 2. Sign and print signature */
    printf("-------------------------------------------------\n\n");
    RSA_sign(msg, sec_str, sgn);
    printf("\n-----------------------------------------------\n\n");
    read_file(sgn);
    printf("\n-----------------------------------------------\n\n");
    printf("Signature verification...\n\n");
    if(RSA_verify(msg, pub_str, sgn))
	printf("[OK]\n\n");
    else
	printf("[TEST FAILED]\n\n");
}

int dsa_check_parameters(mpz_t p, mpz_t q){
    mpz_t r;
    int ok = 1;
    
    size_t size_p = mpz_sizeinbase(p, 2);
    if(size_p < 511){
	printf("Error : p is to small : %zd bits instead of 512 bits.\n",
	       size_p);
	ok = 0;
    }
    if(!mpz_probab_prime_p(p, 50)){
	printf("Error : p should be prime");
	ok = 0;
    }
    if(!mpz_probab_prime_p(q, 50)){
	printf("Error : q should be prime");
	ok = 0;
    }
    mpz_init(r);
    mpz_sub_ui(r, p, 1);
    if(!mpz_divisible_p(r, q)){
	printf("Error : q should divide p-1");
	ok = 0;
    }
    mpz_clear(r);
    return ok;
}

void test5(gmp_randstate_t state){
    // 1. INIT
    mpz_t p, q;
    mpz_inits(p, q, NULL);

    // 3. Generate p, q
    int status = generate_pq(p, q, 512, 160, state);
    implementation_check("generate_pq", status);
    
    gmp_printf("p = %Zd\nq = %Zd\n\n", p, q);

    dsa_check_parameters(p, q);
	
    // 4. Cleaning
    mpz_clears(p, q, NULL);
}

void test6(gmp_randstate_t state){
    // 1. INIT
    mpz_t p, q, x, y, a;
    mpz_inits(p, q, a, x, y, NULL);

    // 3. Generate keys
    int status = dsa_generate_keys(p, q, a, x, y, 512, 160, state);
    implementation_check("dsa_generate_keys", status);

    dsa_check_parameters(p, q);

    // 4. Printing
    printf("#DSA public key\n");
    gmp_printf("p = %Zd\nq = %Zd\nx = %Zd\ny = %Zd\na = %Zd\n\n",
	       p, q, x, y, a);
	
    // 5. Cleaning
    mpz_clears(p, q, x, y, a, NULL);
}


void test7(gmp_randstate_t state){
    /* 1. INIT */
    mpz_t p, q, x, y, a, r, s;
    mpz_inits(p, q, x, y, a, r, s, NULL);
    buffer_t msg;
    const char* message = "When nine hundred years old you reach, look as good you will not.";
    int msg_length = strlen(message);
    printf("Message :\n%s\n\n", message);
    buffer_init(&msg, msg_length);
    buffer_from_string(&msg, (uchar *)message, msg_length);

    /* 3. Generate keys */
    int status = dsa_generate_keys(p, q, a, x, y, 512, 160, state);
    implementation_check("dsa_generate_keys", status);
    
#ifndef CORRECTION
    gmp_printf("Keys :\np = %Zd\nq = %Zd\na = %Zd\nx = %Zd\ny = %Zd\n\n",
	       p, q, a, x, y);
#endif

    /* 4. Sign */
#if DEBUG >= 1
    printf("---- Signing\n");
#endif
    status = dsa_sign_buffer(&msg, p, q, a, x, r, s, state);
    implementation_check("dsa_sign_buffer", status);

#if DEBUG >= 1
    gmp_printf("r = %Zd\ns = %Zd\n\n\n", r, s);
#endif
    /* 5. Verifies */
#ifndef CORRECTION
    printf("---- Verifying\n\n");
    status = dsa_verify_buffer(&msg, p, q, a, r, s, y);
    implementation_check("dsa_verify_buffer", status);
    if(status != 0){
#else
    printf("Checking DSA signature algorithm ......... ");
    if(my_dsa_verify_buffer(&msg, p, q, a, r, s, y)){
#endif
        printf("[OK]\n\n");
    }
    else {
        printf("[FAILED]\n\n");
    }

#ifdef CORRECTION
    printf("Checking DSA verification algorithm ...... ");
    buffer_t my_msg;
    buffer_init(&my_msg, msg_length);
    buffer_from_string(&my_msg, (uchar*)message, msg_length);
    my_dsa_sign_buffer(&my_msg, p, q, a, x, r, s, state);
    if (dsa_verify_buffer(&msg, p, q, a, r, s, y)) {
        printf("[OK]\n\n");
    }
    else{
        printf("[FAILED]\n\n");
    }
#endif

    /* 6. Cleaning */
    buffer_clear(&msg);
    mpz_clears(p, q, x, y, a, r, s, NULL);
}


void test8(gmp_randstate_t state){
    /* 1. INIT */
    size_t psize = 512;
    size_t qsize = 160;

    /* 3. Generate keys */
    const char* pub_str = "DSA_pub.txt";
    const char* sec_str = "DSA_sec.txt";
    dsa_generate_key_files(pub_str, sec_str, psize, qsize, state);
    printf("Key generation done.\n");
    printf("Please check the files %s and %s.\n\n", pub_str, sec_str);
}


void test9(gmp_randstate_t state){
    /* 0. Define string names */
    const char* msg = "./data/Declaration_dh.txt";
    const char* sec_str = "DSA_sec.txt";
    const char* sgn = "Declaration_dh_DSA_signature.txt";
    const char* pub_str = "DSA_pub.txt";

    /* 2. Sign and print signature */
    dsa_sign(msg, sec_str, sgn, state);
    
    read_file(sgn);

    /* 3. Verify signature */
    printf("\n-----------------------------------------------\n\n");
    printf("Signature verification... ");
    // TODO: make this bullet-proof!
    if(dsa_verify(msg, pub_str, sgn))
	printf("[OK]\n\n");
    else
	printf("[TEST FAILED]\n\n");
}


void test10(){
    printf("Test solving system...\n");
    mpz_t r1, s1, r2, s2, h1, h2, k, q, x;
    mpz_inits(r1, s1, r2, s2, h1, h2, k, q, x, NULL);

    mpz_set_ui(q, 11);
    mpz_set_ui(s1, 0);
    mpz_set_ui(r1, 3);
    mpz_set_ui(h1, 7);
    mpz_set_ui(s2, 8);
    mpz_set_ui(r2, 6);
    mpz_set_ui(h2, 2);

    int status = solve_system_modq(x, r1, s1, r2, s2, h1, h2, q);
    implementation_check("solve_system_modq", status);
    
    int i = mpz_cmp_ui(x, 5) != 0;
    if(i)
	printf("\n[TEST FAILED FOR FIRST SYSTEM]\n");
	
    mpz_set_ui(s1, 1);
    mpz_set_ui(s2, 3);
    mpz_set_ui(r2, 1);

    solve_system_modq(x, r1, s1, r2, s2, h1, h2, q);
    int j = mpz_cmp_ui(x, 10) != 0;
    if(j)
	printf("[TEST FAILED FOR SECOND SYSTEM]\n\n");
	
    if(!i && !j)
	printf("[OK]\n\n");
	
    mpz_clears(r1, s1, r2, s2, h1, h2, k, q,x, NULL);
}


void test11(gmp_randstate_t state){
    /* 1. INIT */
    const char* message1 = "Yes, a Jedi's strength flows from the Force. But beware of the dark side. Anger, fear, aggression; the dark side of the Force are they. Easily they flow, quick to join you in a fight. If once you start down the dark path, forever will it dominate your destiny, consume you it will, as it did Obi-Wan's apprentice.";
	
    const char* message2 = "Death is a natural part of life. Rejoice for those around you who transform into the Force. Mourn them do not. Miss them do not. Attachment leads to jealously. The shadow of greed, that is.";

    int msg1_length = strlen((char*)message1);
    int msg2_length = strlen((char*)message2);
	
    const char* sec_str = "./data/DSA_sec_ref.txt";
    const char* pub_str = "./data/DSA_pub_ref.txt";

    buffer_t msg1, msg2;
    mpz_t p, q, a, x, y, r0, r1, r2, s0, s1, s2, k, x_attack;
    mpz_inits(p, q, a, x, y, r0, r1, r2, s0, s1, s2, k, x_attack, NULL);
    buffer_init(&msg1, msg1_length);
    buffer_init(&msg2, msg2_length);
    buffer_from_string(&msg1, (uchar *)message1, msg1_length);
    buffer_from_string(&msg2, (uchar *)message2, msg2_length);
    printf("Testing then attack...\n\n");

    /* 3. Generate keys */
    dsa_key_import(sec_str, p, q, a, x);
    dsa_key_import(pub_str, p, q, a, y);
    gmp_printf("Public key :\ny = 0x%Zx\n\n", y);
    gmp_printf("Secret key :\nx = 0x%Zx\n\n", x);

    /* 4. Generate k */
    mpz_urandomm(k, state, q);

    /* 5. Sign Dummy */
#if DEBUG >= 1
    printf("Signature 1 :\n");
#endif
    int status = dsa_sign_dummy(&msg1, p, q, a, x, r1, s1, k);
    implementation_check("dsa_sign_dummy", status);

#if DEBUG >= 1
    printf("\n\nSignature 2 :\n");
#endif
    dsa_sign_dummy(&msg2, p, q, a, x, r2, s2, k);
#if DEBUG >= 1
    gmp_printf("\n\nSignature message 1:\nr1 = 0x%Zx\ns1 = 0x%Zx\n\n",
	       r1, s1);
    gmp_printf("Signature message 2:\nr2 = 0x%Zx\ns2 = 0x%Zx\n\n",
	       r2, s2);

    printf("Verification for message 1... ");
    if(dsa_verify_buffer(&msg1, p, q, a, r1, s1, y))
        printf("[OK]\n");
    else
        printf("[FAILED]\n");
    printf("\nVerification dsa_sign_dummy for message 2... ");
    if(dsa_verify_buffer(&msg2, p, q, a, r2, s2, y))
        printf("[OK]\n\n");
    else
        printf("[FAILED]\n\n");
#endif
	
    /* 6. Attack */
    status = dsa_attack(x_attack, &msg1, &msg2, p, q, a, r1, s1, r2, s2);
    implementation_check("dsa_attack", status);

    /* 7. Compare */
    if(mpz_cmp(x, x_attack) == 0)
        printf("[TEST OK]\n\n");
    else
        printf("[TEST FAILED]\n\n");
	
    /* 8. Cleaning */
    mpz_clears(p, q, a, x, y, r0, r1, r2, s0, s1, s2, k, x_attack,
	       NULL);
    buffer_clear(&msg1);
    buffer_clear(&msg2);
}



static void usage(char *s, int ntests){
    fprintf(stderr, "Usage: %s <test_number in 1..%d>\n", s, ntests);
}


int main(int argc, char *argv[]){
    gmp_randstate_t state;
    int r = random_seed();
    
    if(argc == 1){
	usage(argv[0], 11);
	return 0;
    }
    int n = atoi(argv[1]);
    if(argc > 2){
	r = atoi(argv[2]);
    }
    gmp_randinit_default(state);
    if(r == -1)
	gmp_randseed_ui(state, 42);
    else
	gmp_randseed_ui(state, r);

    printf("------------------ Test %d -----------------\n\n", n);
    switch(n){
    case 1:
	test1(state);
	break;
    case 2:
	test2();
	break;
    case 3:
	test3();
	break;
    case 4:
	test4();
	break;
    case 5:
	test5(state);
	break;
    case 6:
	test6(state);
	break;
    case 7:
	test7(state);
	break;
    case 8:
	test8(state);
	break;
    case 9:
	test9(state);
	break;
    case 10:
	test10();
	break;
    case 11:
	test11(state);
	break;
    }

    gmp_randclear(state);
    return 0;
}
