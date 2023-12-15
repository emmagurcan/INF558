/**************************************************************/
/* testEx4.c                                                  */
/* Author : Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Last modification September 29, 2022 (Maxime Bombar)       */
/**************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "buffer.h"
#include "bits.h"
#include "LFSR.h"
#include "Geffe.h"


void success(int a){
    if(a)
	printf("\n\n[OK]\n\n");
    else
	printf("\n\n[FAILED]\n\n");
}


void test1(){
    printf("\n***************** Testing Geffe cipher ********************\n");
    // 1. Init
    buffer_t IV1, trans1, IV2, trans2, IV3, trans3, stream1, stream2,
	stream3, stream, verif;
    buffer_init(&IV1, 5);
    buffer_init(&IV2, 5);
    buffer_init(&IV3, 5);
    buffer_init(&trans1, 5);
    buffer_init(&trans2, 5);
    buffer_init(&trans3, 5);
    buffer_init(&stream1, 128);
    buffer_init(&stream2, 128);
    buffer_init(&stream3, 128);
    buffer_init(&stream, 128);
    buffer_init(&verif, 128);

    // 2. Fill in buffers
    buffer_append_uchar(&IV1, 171);
    buffer_append_uchar(&trans1, 145);
	
    buffer_append_uchar(&IV2, 3);
    buffer_append_uchar(&IV2, 118);
    buffer_append_uchar(&trans2, 221);
    buffer_append_uchar(&trans2, 87);

    buffer_append_uchar(&IV3, 1);
    buffer_append_uchar(&IV3, 14);
    buffer_append_uchar(&trans3, 194);
    buffer_append_uchar(&trans3, 177);

    // 3. Compute LFSR's streams
    LFSR(&stream1, &trans1, &IV1, 128);
    LFSR(&stream2, &trans2, &IV2, 128);
    LFSR(&stream3, &trans3, &IV3, 128);

    // 4. Compute Geffe's stream
    Geffe(&stream, &stream1, &stream2, &stream3);

    // 5. Prining
    printf("\nLFSR1 output :   ");
    printBin(stream1.tab, 5);
    printf("\n");
    printf("LFSR2 output :   ");
    printBin(stream2.tab, 5);
    printf("\n");
    printf("LFSR3 output :   ");
    printBin(stream3.tab, 5);
    printf("\n");
    printf("Geffe's output : ");	
    printBin(stream.tab, 5);
    printf("\n\n");
	
    uchar s[128] = {3, 94, 142, 163, 6, 199, 206, 126, 173, 243,
		    241, 1, 108, 25, 111, 131, 223, 205, 84, 47,
		    184, 194, 54, 189, 236, 208, 73, 92, 155, 97,
		    195, 156, 111, 231, 101, 215, 23, 234, 141, 175,
		    121, 96, 127, 25, 227, 254, 63, 199, 178, 189,
		    226, 162, 50, 181, 70, 162, 64, 180, 89, 243, 154,
		    63, 94, 5, 119, 210, 52, 19, 181, 188, 26, 96, 189,
		    25, 103, 239, 93, 207, 1, 7, 1, 150, 184, 181, 8,
		    208, 228, 85, 24, 70, 143, 142, 206, 48, 131, 240,
		    146, 51, 45, 44, 242, 202, 126, 153, 83, 202, 22,
		    196, 164, 23, 93, 134, 43, 55, 249, 244, 32, 172,
		    17, 6, 41, 154, 204, 189, 1, 149, 134, 58};	
    buffer_from_string(&verif, s, 128);

    // 6. Compare with the actual output
    if(buffer_equality(&stream, &verif))
	printf("[OK]\n\n");
    else
	printf("\n\n[FAILED]\n\n");

    // 7. Free Memory
    buffer_clear(&IV1);
    buffer_clear(&IV2);
    buffer_clear(&IV3);
    buffer_clear(&trans1);
    buffer_clear(&trans2);
    buffer_clear(&trans3);
    buffer_clear(&stream1);
    buffer_clear(&stream2);
    buffer_clear(&stream3);
    buffer_clear(&stream);
    buffer_clear(&verif);
}


void test2(){
    printf("\n***************** Testing correlation ********************\n\n");
    // 1. Intialisation
    buffer_t s, s1, s2, s3, buf_IV1, buf_IV2, buf_IV3, buf_trans1,
	buf_trans2, buf_trans3;
    buffer_init(&buf_IV1, 3);
    buffer_init(&buf_IV2, 3);
    buffer_init(&buf_IV3, 3);
    buffer_init(&buf_trans1, 3);
    buffer_init(&buf_trans2, 3);
    buffer_init(&buf_trans3, 3);
    buffer_init(&s1, 1024);
    buffer_init(&s2, 1024);
    buffer_init(&s3, 1024);
    buffer_init(&s, 1024);
	
	
    // 2. Filling the registers
    uchar IV1[1] = {107};
    uchar trans1[1] = {241};
    uchar IV2[2] = {1, 118};
    uchar trans2[2] = {177, 143};
    uchar IV3[2] = {1, 14};
    uchar trans3[2] = {239, 33};
    buffer_from_string(&buf_IV1, IV1, 1);
    buffer_from_string(&buf_IV2, IV2, 2);
    buffer_from_string(&buf_IV3, IV3, 2);
    buffer_from_string(&buf_trans1, trans1, 1);
    buffer_from_string(&buf_trans2, trans2, 2);
    buffer_from_string(&buf_trans3, trans3, 2);
	
    // 3. Compute LFSR's streams
    LFSR(&s1, &buf_trans1, &buf_IV1, 1024);
    LFSR(&s2, &buf_trans2, &buf_IV2, 1024);
    LFSR(&s3, &buf_trans3, &buf_IV3, 1024);
    Geffe(&s, &s1, &s2, &s3);

    // 4. Tests correlations
    printf("Correlation with 1st LFSR = %f\n", correlation(&s, &s1));
    printf("Correlation with 2nd LFSR = %f\n", correlation(&s, &s2));
    printf("Correlation with 3rd LFSR = %f\n", correlation(&s, &s3));

    success(correlation(&s, &s1) > 0.74 && correlation(&s, &s1) < 0.78 &&
	    correlation(&s, &s2) > 0.48 && correlation(&s, &s2) < 0.52 &&
	    correlation(&s, &s3) > 0.72 && correlation(&s, &s3) < 0.76);
	
    // 5. Free memory
    buffer_clear(&buf_IV1);
    buffer_clear(&buf_IV2);
    buffer_clear(&buf_IV3);
    buffer_clear(&buf_trans1);
    buffer_clear(&buf_trans2);
    buffer_clear(&buf_trans3);
    buffer_clear(&s1);
    buffer_clear(&s2);
    buffer_clear(&s3);
    buffer_clear(&s);
}



void test3(){
    printf("\n***************** Testing searchIV ********************\n\n");
    // 1. Initialisation
    buffer_t buf_IV1, buf_IV2, buf_IV3, buf_trans1, buf_trans2,
	buf_trans3, s1, s2, s3, s, IV_candidate;
    buffer_init(&buf_IV1, 2);
    buffer_init(&buf_IV2, 2);
    buffer_init(&buf_IV3, 2);
    buffer_init(&IV_candidate, 2);
    buffer_init(&buf_trans1, 2);
    buffer_init(&buf_trans2, 2);
    buffer_init(&buf_trans3, 2);
    buffer_init(&s1, 1024);
    buffer_init(&s2, 1024);
    buffer_init(&s3, 1024);
    buffer_init(&s, 1024);
	
    // 2. Fill in buffers
    buffer_append_uchar(&buf_IV1, 127);
    buffer_append_uchar(&buf_IV1, 11);
    buffer_append_uchar(&buf_IV2, 1);
    buffer_append_uchar(&buf_IV2, 118);
    buffer_append_uchar(&buf_IV3, 1);
    buffer_append_uchar(&buf_IV3, 14);
    buffer_append_uchar(&buf_trans1, 215);
    buffer_append_uchar(&buf_trans1, 173);
    buffer_append_uchar(&buf_trans2, 234);
    buffer_append_uchar(&buf_trans2, 187);
    buffer_append_uchar(&buf_trans3, 240);
    buffer_append_uchar(&buf_trans3, 31);

    // 3. Compute streams
    LFSR(&s1, &buf_trans1, &buf_IV1, 1024);
    LFSR(&s2, &buf_trans2, &buf_IV2, 1024);
    LFSR(&s3, &buf_trans3, &buf_IV3, 1024);
    Geffe(&s, &s1, &s2, &s3);

    // 4. Perform exhaustive search  jklm
    printf("Test searchIV, 1st LFSR\n\n");
    searchIV(&IV_candidate, &s, &buf_trans1, 0.7);
    printf("%s.\n\n",
	   (buffer_equality(&buf_IV1, &IV_candidate) ? "[OK]" : "[FAILED]"));

    printf("Test searchIV, 3rd LFSR\n\n");
    searchIV(&IV_candidate, &s, &buf_trans3, 0.7);
    printf("%s.\n\n",
	   (buffer_equality(&buf_IV3, &IV_candidate)? "[OK]" : "[FAILED]"));
	
	
    // 5. Free memory
    buffer_clear(&buf_IV1);
    buffer_clear(&buf_IV2);
    buffer_clear(&buf_IV3);
    buffer_clear(&IV_candidate);
    buffer_clear(&buf_trans1);
    buffer_clear(&buf_trans2);
    buffer_clear(&buf_trans3);
    buffer_clear(&s1);
    buffer_clear(&s2);
    buffer_clear(&s3);
    buffer_clear(&s);
}


void test4(){
    printf("\n***************** Testing positions ********************\n\n");
    // 1. Initialisation
    buffer_t buf_IV1, buf_IV3, buf_trans1, buf_trans3, s1, s3, pos, verif;
    buffer_init(&buf_IV1, 1);
    buffer_init(&buf_IV3, 2);
    buffer_init(&buf_trans1, 1);
    buffer_init(&buf_trans3, 2);
    buffer_init(&s1, 7);
    buffer_init(&s3, 7);
    buffer_init(&pos, 7);
    buffer_init(&verif, 7);

    // 2. Fill in buffer
    uchar IV1[1] = {107};
    uchar trans1[1] = {131};
    uchar IV3[2] = {1, 14};
    uchar trans3[2] = {233, 187};
    uchar ver[7] = {106, 49, 3, 32, 69, 11, 80};
    buffer_from_string(&buf_IV1, IV1, 1);
    buffer_from_string(&buf_trans1, trans1, 1);
    buffer_from_string(&buf_IV3, IV3, 2);
    buffer_from_string(&buf_trans3, trans3, 2);
    buffer_from_string(&verif, ver, 7);

    // 3. Generate LFSR streams
    LFSR(&s1, &buf_trans1, &buf_IV1, 7);
    LFSR(&s3, &buf_trans3, &buf_IV3, 7);
    positions(&pos, &s1, &s3);

    // 	4. Printing
    printBin(s1.tab, 7);
    printf("\n");
    printBin(s3.tab, 7);
    printf("\n");
    printBin(pos.tab, 7);
    printf("\n");
    success(buffer_equality(&verif, &pos));

    // 5. Free Memory
    buffer_clear(&buf_IV1);
    buffer_clear(&buf_IV3);
    buffer_clear(&buf_trans1);
    buffer_clear(&buf_trans3);
    buffer_clear(&s1);
    buffer_clear(&s3);
    buffer_clear(&pos);
    buffer_clear(&verif);
}


void test5(){
    printf("\n***************** Testing matchAt ********************\n\n");
    // 1. Initialisation
    buffer_t buf_IV1, buf_IV2, buf_IV3, buf_trans1, buf_trans2, buf_trans3,
	s1, s2, s3, s, pos;
    buffer_init(&buf_IV1, 1);
    buffer_init(&buf_IV2, 2);
    buffer_init(&buf_IV3, 2);
    buffer_init(&buf_trans1, 1);
    buffer_init(&buf_trans2, 2);
    buffer_init(&buf_trans3, 2);
    buffer_init(&s1, 128);
    buffer_init(&s2, 128);
    buffer_init(&s3, 128);
    buffer_init(&s, 128);
    buffer_init(&pos, 128);

    // 2. Filling in the buffers
    uchar IV1[1] = {107};
    uchar trans1[1] = {229};
    uchar IV2[2] = {0, 118};
    uchar trans2[2] = {159, 179};
    uchar IV3[2] = {1, 14};
    uchar trans3[2] = {144, 137};
    uchar witness[128] = {106, 177, 64, 4, 35, 0, 32, 83, 66, 33, 32, 229,
			  195, 1, 68, 12, 150, 34, 66, 0, 64, 0, 8, 128,
			  24, 15, 1, 65, 118, 3, 42, 16, 168, 131, 4, 4,
			  128, 24, 17, 44, 56, 70, 136, 19, 200, 4, 20,
			  33, 4, 143, 0, 8, 88, 16, 2, 16, 0, 21, 1, 2,
			  80, 2, 168, 4, 128, 144, 16, 66, 146, 0, 65,
			  16, 130, 90, 54, 70, 128, 1, 0, 128, 38, 48,
			  32, 161, 0, 68, 138, 41, 196, 128, 12, 166,
			  64, 16, 128, 138, 78, 56, 65, 74, 73, 129, 6,
			  130, 140, 224, 112, 8, 64, 32, 2, 5, 192, 80,
			  2, 145, 131, 16, 44, 32, 27, 129, 32, 197, 0,
			  234, 6, 65};
    buffer_from_string(&buf_IV1, IV1, 1);
    buffer_from_string(&buf_IV2, IV2, 2);
    buffer_from_string(&buf_IV3, IV3, 2);
    buffer_from_string(&buf_trans1, trans1, 1);
    buffer_from_string(&buf_trans2, trans2, 2);
    buffer_from_string(&buf_trans3, trans3, 2);
    buffer_from_string(&pos, witness, 128);
	
	
    // 3. Compute the streams
    LFSR(&s1, &buf_trans1, &buf_IV1, 128);
    LFSR(&s2, &buf_trans2, &buf_IV2, 128);
    LFSR(&s3, &buf_trans3, &buf_IV3, 128);
    Geffe(&s, &s1, &s2, &s3);

	
    // 4. Printing
    printBin(s.tab, 7);
    printf("\n");
    printBin(s2.tab, 7);
    printf("\n");
    printBin(pos.tab, 7);
    printf("\n\n");

    // 5. Testing the function
    printf("Test match_at: %s\n\n", (match_at(&s, &s2, &pos) ? "[OK]" : "[FAILED]"));

    // Free Memory
    buffer_clear(&buf_IV1);
    buffer_clear(&buf_IV2);
    buffer_clear(&buf_IV3);
    buffer_clear(&buf_trans1);
    buffer_clear(&buf_trans2);
    buffer_clear(&buf_trans3);
    buffer_clear(&s1);
    buffer_clear(&s2);
    buffer_clear(&s3);
    buffer_clear(&s);
    buffer_clear(&pos);

}


void test6(){
    printf("\n***************** Testing searchWithMatch ********************\n\n");
    // 1. Initialisation
    buffer_t buf_IV1, buf_IV2, buf_IV3, IV_candidate, buf_trans1, buf_trans2,
	buf_trans3, s1, s2, s3, s, pos;
    buffer_init(&buf_IV1, 1);
    buffer_init(&buf_IV2, 2);
    buffer_init(&IV_candidate, 2);
    buffer_init(&buf_IV3, 2);
    buffer_init(&buf_trans1, 1);
    buffer_init(&buf_trans2, 2);
    buffer_init(&buf_trans3, 2);
    buffer_init(&s1, 128);
    buffer_init(&s2, 128);
    buffer_init(&s3, 128);
    buffer_init(&s, 128);
    buffer_init(&pos, 128);
	
    // 2. Fill in buffers
    uchar IV1[1] = {107};
    uchar trans1[1] = {229};
    uchar IV2[2] = {0, 118};
    uchar trans2[2] = {159, 179};
    uchar IV3[2] = {1, 14};
    uchar trans3[2] = {144, 137};
    uchar witness[128] = {106, 177, 64, 4, 35, 0, 32, 83, 66, 33, 32, 229,
			  195, 1, 68, 12, 150, 34, 66, 0, 64, 0, 8, 128,
			  24, 15, 1, 65, 118, 3, 42, 16, 168, 131, 4, 4,
			  128, 24, 17, 44, 56, 70, 136, 19, 200, 4, 20,
			  33, 4, 143, 0, 8, 88, 16, 2, 16, 0, 21, 1, 2,
			  80, 2, 168, 4, 128, 144, 16, 66, 146, 0, 65,
			  16, 130, 90, 54, 70, 128, 1, 0, 128, 38, 48,
			  32, 161, 0, 68, 138, 41, 196, 128, 12, 166,
			  64, 16, 128, 138, 78, 56, 65, 74, 73, 129, 6,
			  130, 140, 224, 112, 8, 64, 32, 2, 5, 192, 80,
			  2, 145, 131, 16, 44, 32, 27, 129, 32, 197, 0,
			  234, 6, 65};
    buffer_from_string(&buf_IV1, IV1, 1);
    buffer_from_string(&buf_IV2, IV2, 2);
    buffer_from_string(&buf_IV3, IV3, 2);
    buffer_from_string(&buf_trans1, trans1, 1);
    buffer_from_string(&buf_trans2, trans2, 2);
    buffer_from_string(&buf_trans3, trans3, 2);
    buffer_from_string(&pos, witness, 128);

    // 3. Compute streams
    LFSR(&s1, &buf_trans1, &buf_IV1, 128);
    LFSR(&s2, &buf_trans2, &buf_IV2, 128);
    LFSR(&s3, &buf_trans3, &buf_IV3, 128);
    Geffe(&s, &s1, &s2, &s3);

    // 4. Search 
    search_with_match(&IV_candidate, &s, &buf_trans2, &pos);
    printf("Test : %s\n\n",
	   buffer_equality(&buf_IV2, &IV_candidate)  ? "[OK]" : "[FAILED]");

    // 5. Free Memory
    buffer_clear(&buf_IV1);
    buffer_clear(&buf_IV2);
    buffer_clear(&IV_candidate);
    buffer_clear(&buf_IV3);
    buffer_clear(&buf_trans1);
    buffer_clear(&buf_trans2);
    buffer_clear(&buf_trans3);
    buffer_clear(&s1);
    buffer_clear(&s2);
    buffer_clear(&s3);
    buffer_clear(&s);
    buffer_clear(&pos);
}


void test7(){
    printf("\n***************** Testing attack ********************\n\n");
    // 1. Initialisation
    int stream_length = 100;
    buffer_t buf_IV1, buf_IV2, buf_IV3, IV_candidate1, IV_candidate2,
	IV_candidate3, buf_trans1, buf_trans2, buf_trans3, s1, s2, s3, s;
    buffer_init(&buf_IV1, 1);
    buffer_init(&IV_candidate1, 1);
    buffer_init(&buf_IV2, 2);
    buffer_init(&IV_candidate2, 2);
    buffer_init(&buf_IV3, 2);
    buffer_init(&IV_candidate3, 2);
    buffer_init(&buf_trans1, 1);
    buffer_init(&buf_trans2, 2);
    buffer_init(&buf_trans3, 2);
    buffer_init(&s1, stream_length);
    buffer_init(&s2, stream_length);
    buffer_init(&s3, stream_length);
    buffer_init(&s, stream_length);

    // 2. Filling the buffers	
    uchar IV1[1] = {107};
    uchar trans1[1] = {137};
    uchar IV2[2] = {0, 118};
    uchar trans2[2] = {128, 165};
    uchar IV3[2] = {1, 14};
    uchar trans3[2] = {171, 119};
    buffer_from_string(&buf_IV1, IV1, 1);
    buffer_from_string(&buf_IV2, IV2, 2);
    buffer_from_string(&buf_IV3, IV3, 2);
    buffer_from_string(&buf_trans1, trans1, 1);
    buffer_from_string(&buf_trans2, trans2, 2);
    buffer_from_string(&buf_trans3, trans3, 2);

    // 3. Compute streams
    LFSR(&s1, &buf_trans1, &buf_IV1, stream_length);
    LFSR(&s2, &buf_trans2, &buf_IV2, stream_length);
    LFSR(&s3, &buf_trans3, &buf_IV3, stream_length);
    Geffe(&s, &s1, &s2, &s3);
	
    // 4. Attack	
    printf("\nPerforms the attack....");
    attack(&IV_candidate1, &IV_candidate2, &IV_candidate3, &s,
	   &buf_trans1, &buf_trans2, &buf_trans3, 0.7);
	
    if(buffer_equality(&buf_IV1, &IV_candidate1) &&
       buffer_equality(&buf_IV2, &IV_candidate2) &&
       buffer_equality(&buf_IV3, &IV_candidate3))
	printf("\n\n[ATTACK SUCCESS!]\n\n");
    else
	printf("\n\n[FAILED]\n\n");

    // 5. Free Memory
    buffer_clear(&buf_IV1);
    buffer_clear(&IV_candidate1);
    buffer_clear(&buf_IV2);
    buffer_clear(&IV_candidate2);
    buffer_clear(&buf_IV3);
    buffer_clear(&IV_candidate3);
    buffer_clear(&buf_trans1);
    buffer_clear(&buf_trans2);
    buffer_clear(&buf_trans3);
    buffer_clear(&s1);
    buffer_clear(&s2);
    buffer_clear(&s3);
    buffer_clear(&s);
}

void test8(){
    printf("\n***************** Testing attack ********************\n\n");
    // 1. Initialisation
    int stream_length = 256;
    buffer_t buf_IV1, buf_IV2, buf_IV3, IV_candidate1, IV_candidate2,
	IV_candidate3, buf_trans1, buf_trans2, buf_trans3, s1, s2, s3, s;
    buffer_init(&buf_IV1, 3);
    buffer_init(&IV_candidate1, 3);
    buffer_init(&buf_IV2, 3);
    buffer_init(&IV_candidate2, 3);
    buffer_init(&buf_IV3, 3);
    buffer_init(&IV_candidate3, 3);
    buffer_init(&buf_trans1, 3);
    buffer_init(&buf_trans2, 3);
    buffer_init(&buf_trans3, 3);
    buffer_init(&s1, stream_length);
    buffer_init(&s2, stream_length);
    buffer_init(&s3, stream_length);
    buffer_init(&s, stream_length);

    // 2. Filling the buffers	
    uchar IV1[3] = {3, 208, 19};
    uchar trans1[3] = {166, 213, 15};
    uchar IV2[3] = {2, 11, 83};
    uchar trans2[3] = {196, 10, 89};
    uchar IV3[3] = {3, 0, 238};
    uchar trans3[3] = {232, 221, 229};
    buffer_from_string(&buf_IV1, IV1, 3);
    buffer_from_string(&buf_IV2, IV2, 3);
    buffer_from_string(&buf_IV3, IV3, 3);
    buffer_from_string(&buf_trans1, trans1, 3);
    buffer_from_string(&buf_trans2, trans2, 3);
    buffer_from_string(&buf_trans3, trans3, 3);

    // 3. Compute streams
    LFSR(&s1, &buf_trans1, &buf_IV1, stream_length);
    LFSR(&s2, &buf_trans2, &buf_IV2, stream_length);
    LFSR(&s3, &buf_trans3, &buf_IV3, stream_length);
    Geffe(&s, &s1, &s2, &s3);
	
    // 4. Attack	
    printf("\nPerforms the attack....\n");
    attack(&IV_candidate1, &IV_candidate2, &IV_candidate3, &s,
	   &buf_trans1, &buf_trans2, &buf_trans3, 0.7);
	
    if(buffer_equality(&buf_IV1, &IV_candidate1) &&
       buffer_equality(&buf_IV2, &IV_candidate2) &&
       buffer_equality(&buf_IV3, &IV_candidate3))
	printf("\n\n[ATTACK SUCCESS!]\n\n");
    else
	printf("\n\n[FAILED]\n\n");

    // 5. Free Memory
    buffer_clear(&buf_IV1);
    buffer_clear(&IV_candidate1);
    buffer_clear(&buf_IV2);
    buffer_clear(&IV_candidate2);
    buffer_clear(&buf_IV3);
    buffer_clear(&IV_candidate3);
    buffer_clear(&buf_trans1);
    buffer_clear(&buf_trans2);
    buffer_clear(&buf_trans3);
    buffer_clear(&s1);
    buffer_clear(&s2);
    buffer_clear(&s3);
    buffer_clear(&s);
}


void usage(char *s){
    fprintf(stderr, "Usage: %s <test_number in 1..8>\n", s);
}



int main(int argc, char *argv[]){
    if(argc == 1){
	usage(argv[0]);
	return 0;
    }
    int n = atoi(argv[1]);

    switch(n){
    case 1:
	test1();
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
	test5();
	break;
    case 6:
	test6();
	break;
    case 7:
	test7();
	break;
    case 8:
	test8();
    }
    return 0;
}
