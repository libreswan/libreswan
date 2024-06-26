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
#include "lswalloc.h"

void cipher_normal(const struct encrypt_desc *cipher,
		   chunk_t data,
		   chunk_t iv,
		   PK11SymKey *key,
		   enum cipher_op op,
		   struct logger *logger)
{
	cipher->encrypt_ops->do_crypt(cipher, data, iv, key, op, logger);
}

bool cipher_aead(const struct encrypt_desc *cipher,
		 shunk_t salt,
		 enum cipher_iv_source iv_source,
		 chunk_t wire_iv,
		 shunk_t aad,
		 chunk_t text_and_tag,
		 size_t text_size, size_t tag_size,
		 PK11SymKey *symkey,
		 enum cipher_op op,
		 struct logger *logger)
{
	struct cipher_aead *aead = cipher_aead_create(cipher, symkey, op, logger);
	if (aead == NULL) {
		/* already logged */
		return false;
	}
	bool ok = cipher_aead_op(aead, salt, iv_source, wire_iv, aad,
				 text_and_tag, text_size, tag_size,
				 logger);
	cipher_aead_destroy(&aead, logger);
	return ok;
}

struct cipher_aead {
	struct cipher_aead_context *context;
	const struct encrypt_desc *cipher;
};

struct cipher_aead *cipher_aead_create(const struct encrypt_desc *cipher,
				       PK11SymKey *key,
				       enum cipher_op op,
				       struct logger *logger)
{
	struct cipher_aead_context *context =
		cipher->encrypt_ops->aead_context_create(cipher, key, op, logger);
	if (context == NULL) {
		return NULL;
	}
	struct cipher_aead *aead = alloc_thing(struct cipher_aead, __func__);
	aead->context = context;
	aead->cipher = cipher;
	return aead;
}

bool cipher_aead_op(const struct cipher_aead *aead,
		    shunk_t salt,
		    enum cipher_iv_source iv_source,
		    chunk_t wire_iv,
		    shunk_t aad,
		    chunk_t text_and_tag,
		    size_t text_size, size_t tag_size,
		    struct logger *logger)
{
	return aead->cipher->encrypt_ops->aead_context_op(aead->cipher, aead->context,
							  salt, iv_source, wire_iv, aad,
							  text_and_tag, text_size, tag_size,
							  logger);
}

void cipher_aead_destroy(struct cipher_aead **aead,
			 struct logger *logger)
{
	const struct encrypt_desc *cipher = (*aead)->cipher;
	cipher->encrypt_ops->aead_context_destroy(&(*aead)->context, logger);
	pfreeany(*aead);
	return;
}
