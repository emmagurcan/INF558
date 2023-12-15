/**************************************************************/
/* Geffe.h                                                    */
/* Author : Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Last modification September 24, 2018                       */
/**************************************************************/

void Geffe(buffer_t *output, buffer_t *s1, buffer_t *s2, buffer_t *s3);
double correlation(buffer_t *s1, buffer_t *s2);
void searchIV(buffer_t *IV_candidate, buffer_t *stream, buffer_t *trans,
			  double threshold);

void positions(buffer_t *output, buffer_t *s1, buffer_t *s3);
int match_at(buffer_t *s, buffer_t *s1, buffer_t *pos);
void search_with_match(buffer_t *IV_candidate, buffer_t *stream,
					   buffer_t *trans, buffer_t *pos);
void attack(buffer_t *IV_candidate1, buffer_t *IV_candidate2,
			buffer_t *IV_candidate3, buffer_t *stream,
			buffer_t *trans1, buffer_t *trans2, buffer_t *trans3,
			double threshold);
