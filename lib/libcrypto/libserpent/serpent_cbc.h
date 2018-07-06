/* Glue header */
#include "serpent.h"
int serpent_cbc_encrypt(serpent_context *ctx, const uint8_t * in,
			uint8_t * out, int ilen, const uint8_t * iv,
			int encrypt);
