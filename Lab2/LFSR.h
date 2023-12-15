/**************************************************************/
/* LFSR.h                                                     */
/* Author : Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Last modification September 24, 2018                       */
/**************************************************************/

/* Definitions*/

/* Functions*/

void LFSR(buffer_t *stream, buffer_t *trans, buffer_t *IV, int stream_length);
void LFSR_verbose(buffer_t *stream, buffer_t *trans, buffer_t *IV, int stream_length);
void increment_buffer(buffer_t *buf);
void bourrinate_IV(buffer_t *searched_IV, buffer_t *trans, buffer_t *stream);
