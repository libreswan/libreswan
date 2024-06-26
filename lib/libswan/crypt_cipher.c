/* CIPHER helper functions, for libreswan
 *
 * Copyright (C) 2024 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "crypt_cipher.h"

#include "ike_alg.h"
#include "ike_alg_encrypt_ops.h"

void cipher_normal(const struct encrypt_desc *alg,
		   chunk_t data,
		   chunk_t iv,
		   PK11SymKey *key,
		   enum cipher_op op,
		   struct logger *logger)
{
	alg->encrypt_ops->do_crypt(alg, data, iv, key, op, logger);
}

bool cipher_aead(const struct encrypt_desc *alg,
		 shunk_t salt,
		 enum cipher_iv_source iv_source,
		 chunk_t wire_iv,
		 shunk_t aad,
		 chunk_t text_and_tag,
		 size_t text_size, size_t tag_size,
		 PK11SymKey *key,
		 enum cipher_op op,
		 struct logger *logger)
{
	return alg->encrypt_ops->do_aead(alg, salt, iv_source, wire_iv, aad,
					 text_and_tag, text_size, tag_size,
					 key, op, logger);
}
