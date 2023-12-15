/**************************************************************/
/* diffusion.h                                                */
/* Author : Alain Couvreur                                    */
/* alain.couvreur@lix.polytechnique.fr                        */
/* Last modification October 12, 2018                         */
/**************************************************************/

double diffusion_test_for_key(buffer_t *key, int nr_tests);
double diffusion_test_for_msg(buffer_t *msg, int nr_tests);
double diffusion_test_nr_rounds(buffer_t *msg, int Nr, int nr_tests);
