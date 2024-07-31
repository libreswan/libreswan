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
	struct cipher_op_context *op;
	const struct encrypt_desc *cipher;
};

struct cipher_context *cipher_context_create(const struct encrypt_desc *cipher,
					     enum cipher_op op,
					     enum cipher_iv_source iv_source,
					     PK11SymKey *key,
					     shunk_t salt,
					     struct logger *logger)
{
	if (cipher->encrypt_ops->cipher_op_context_create == NULL) {
		return NULL;
	}

	struct cipher_op_context *op_context =
		cipher->encrypt_ops->cipher_op_context_create(cipher, op, iv_source,
							      key, salt, logger);
	if (op_context == NULL) {
		return NULL;
	}
	struct cipher_context *context = alloc_thing(struct cipher_context, __func__);
	context->op = op_context;
	context->cipher = cipher;
	return context;
}

void cipher_context_destroy(struct cipher_context **context,
			    struct logger *logger)
{
	if ((*context) == NULL) {
		/* presumably an incomplete state */
		ldbg(logger, "no cipher context to delete");
		return;
	}

	const struct encrypt_desc *cipher = (*context)->cipher;
	cipher->encrypt_ops->cipher_op_context_destroy(&(*context)->op, logger);
	pfreeany(*context);
	return;
}

bool cipher_context_op_aead(const struct cipher_context *context,
			    chunk_t wire_iv,
			    shunk_t aad,
			    chunk_t text_and_tag,
			    size_t text_size, size_t tag_size,
			    struct logger *logger)
{
	return context->cipher->encrypt_ops->cipher_op_aead(context->op,
							    wire_iv, aad,
							    text_and_tag, text_size, tag_size,
							    logger);
}
