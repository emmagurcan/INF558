int oracle(buffer_t *encrypted, buffer_t *key);
int get_padding_position(buffer_t *encrypted, buffer_t *key);
int prepare(buffer_t *corrupted, buffer_t *encrypted, buffer_t *decrypted,
			 int known_positions);
int find_last_byte(uchar *hack, buffer_t *corrupted, int pad_position, buffer_t *key);
int full_attack(buffer_t *decrypted, buffer_t *encrypted, buffer_t *key);
