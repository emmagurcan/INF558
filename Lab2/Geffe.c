/**************************************************************/
/* Geffe.c                                                    */
/* Author : Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Last modification September 24, 2018                       */
/**************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include "buffer.h"
#include "bits.h"
#include "LFSR.h"
#include "Geffe.h"
#define DEBUG 1


void Geffe(buffer_t *output, buffer_t *s1, buffer_t *s2, buffer_t *s3){
	for (size_t s = 0; s < s1->length; s++){
		uchar g = (s1->tab[s] & s2->tab[s])^(s2->tab[s] & s3->tab[s])^s3->tab[s];
		buffer_append_uchar(output, g);
	}
}


double correlation(buffer_t *s1, buffer_t *s2){
	size_t nbits = s1->length * 8;
	size_t matched = 0;
	for (size_t s = 0; s < s1->length; s++){
		for (int i = 0; i < 8; i++){
			if (((s1->tab[s] >> i) & 1) == ((s2->tab[s] >> i) & 1)){
				matched ++;
			}
		}
	}
	return (double)matched/nbits;
}


void searchIV(buffer_t *IV_candidate, buffer_t *stream, buffer_t *trans, double threshold){
	buffer_t stream_candidate;
	int i;
	
	buffer_init(&stream_candidate, trans->length);
	buffer_reset(IV_candidate);
	for(i = 0; i < trans->length; i++)
		buffer_append_uchar(IV_candidate, 0);

	while (true) {

		LFSR(&stream_candidate, trans, IV_candidate, stream->length);

		double c = correlation(&stream_candidate, stream);

		if (c >= threshold){
			break;
		}
		increment_buffer(IV_candidate);
	}
	
	buffer_clear(&stream_candidate);
}

void positions(buffer_t *output, buffer_t *s1, buffer_t *s3){
	if(s1->length != s3->length){
		perror("Input streams should have the same length.\n");
		return;
	}
	buffer_reset(output);
	for(int i = 0; i < s1->length; i++){
		uchar u = 0;
		for(int j=7; j>=0; j--){
			u *= 2;
			if (getBit(s1->tab[i], j)==1 && getBit(s3->tab[i], j)==0){
				u+=1;
			}
		}
		buffer_append_uchar(output, u);
	}
}

int match_at(buffer_t *s, buffer_t *s1, buffer_t *pos){
	if(s->length != s1->length || s->length != pos->length){
		perror("Input buffers should have the same lengths\n");
		return 0;
	} 
	for (size_t i = 0; i < s->length; i++){
		uchar pos_bit = (pos->tab[i >> 3] >> (7 - (i & 7))) & 1;

		if (pos_bit == 1){
			uchar s_bit = (s->tab[i >> 3] >> (7 - (i & 7))) & 1;
			uchar s1_bit = (s1->tab[i >> 3] >> (7 - (i & 7))) & 1;
			if (s_bit != s1_bit){
				return 0;
			}
		}
	}
	return -1;
}


void search_with_match(buffer_t *IV_candidate, buffer_t *stream,
					   buffer_t *trans, buffer_t *pos){
	buffer_t stream_candidate;
	int i;
	
	buffer_init(&stream_candidate, pos->length);
	buffer_reset(IV_candidate);
	for(i = 0; i < trans->length; i++)
		buffer_append_uchar(IV_candidate, 0);
	
		
	while (true){
		LFSR(&stream_candidate, trans, IV_candidate, pos->length);
		if(match_at(&stream_candidate, stream, pos)){
			break;
		}
		increment_buffer(IV_candidate);
	}
	buffer_clear(&stream_candidate);
}

void attack(buffer_t *IV_candidate1, buffer_t *IV_candidate2,
			   buffer_t *IV_candidate3, buffer_t *stream,
			   buffer_t *trans1, buffer_t *trans2, buffer_t *trans3,
			   double threshold){
	buffer_t pos;
	buffer_t stream1;
	buffer_t stream3;
	buffer_init(&pos, stream->length);
	buffer_init(&stream1, stream->length);
	buffer_init(&stream3, stream->length);

	searchIV(IV_candidate1, stream, trans1, threshold);
	searchIV(IV_candidate3, stream, trans3, threshold);
	LFSR(&stream1, trans1, IV_candidate1, stream->length);
	LFSR(&stream3, trans3, IV_candidate3, stream->length);
	positions(&pos, &stream1, &stream3);
	pos.length = stream->length ;
	search_with_match(IV_candidate2, stream, trans2, &pos);

}
