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
#include "lswlog.h"

void cipher_normal(const struct encrypt_desc *cipher,
		   enum cipher_op op,
		   chunk_t data,
		   chunk_t iv,
		   PK11SymKey *key,
		   struct logger *logger)
{
	cipher->encrypt_ops->cipher_op_normal(cipher, data, iv, key, op, logger);
}

bool cipher_aead(const struct encrypt_desc *cipher,
		 enum cipher_op op,
		 enum cipher_iv_source iv_source,
		 shunk_t salt,
		 chunk_t wire_iv,
		 shunk_t aad,
		 chunk_t text_and_tag,
		 size_t text_size, size_t tag_size,
		 PK11SymKey *symkey,
		 struct logger *logger)
{
	struct cipher_context *context = cipher_context_create(cipher, op, iv_source,
							       symkey, salt, logger);
	if (context == NULL) {
		/* already logged */
		return false;
	}

	bool ok = cipher_context_op_aead(context, wire_iv, aad,
					 text_and_tag, text_size, tag_size,
					 logger);
	cipher_context_destroy(&context, logger);
	return ok;
}

struct cipher_context {
	const struct encrypt_desc *cipher;
	struct cipher_op_context *op_context;
};

struct cipher_context *cipher_context_create(const struct encrypt_desc *cipher,
					     enum cipher_op op,
					     enum cipher_iv_source iv_source,
					     PK11SymKey *key,
					     shunk_t salt,
					     struct logger *logger)
{
	struct cipher_context *cipher_context = alloc_thing(struct cipher_context, __func__);
	cipher_context->cipher = cipher;
	if (cipher->encrypt_ops->cipher_op_context_create != NULL) {
		cipher_context->op_context =
			cipher->encrypt_ops->cipher_op_context_create(cipher, op, iv_source,
								      key, salt, logger);
		PASSERT(logger, cipher_context->op_context != NULL);
	}
	return cipher_context;
}

void cipher_context_destroy(struct cipher_context **cipher_context,
			    struct logger *logger)
{
	if ((*cipher_context) == NULL) {
		/* presumably an incomplete state */
		ldbg(logger, "no cipher context to delete");
		return;
	}

	const struct encrypt_desc *cipher = (*cipher_context)->cipher;
	if (cipher->encrypt_ops->cipher_op_context_destroy != NULL) {
		PASSERT(logger, (*cipher_context)->op_context != NULL);
		cipher->encrypt_ops->cipher_op_context_destroy(&(*cipher_context)->op_context, logger);
	} else {
		PASSERT(logger, (*cipher_context)->op_context == NULL);
	}

	pfreeany(*cipher_context);
	return;
}

bool cipher_context_op_aead(const struct cipher_context *cipher_context,
			    chunk_t wire_iv,
			    shunk_t aad,
			    chunk_t text_and_tag,
			    size_t text_size, size_t tag_size,
			    struct logger *logger)
{
	return cipher_context->cipher->encrypt_ops->cipher_op_aead(cipher_context->op_context,
								   wire_iv, aad,
								   text_and_tag, text_size, tag_size,
								   logger);
}
