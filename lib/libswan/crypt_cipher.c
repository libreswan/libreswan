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
#include "crypt_symkey.h"
#include "crypt_mac.h"

void cipher_normal(const struct encrypt_desc *cipher,
		   enum cipher_op op,
		   enum cipher_iv_source iv_source,
		   chunk_t data,
		   struct crypt_mac *iv,
		   PK11SymKey *symkey,
		   struct logger *logger)
{
	struct cipher_context *context = cipher_context_create(cipher, op, iv_source,
							       symkey, null_shunk,
							       logger);
	chunk_t iv_chunk = HUNK_AS_CHUNK((*iv));
	chunk_t wire_iv = hunk_slice(iv_chunk, cipher->salt_size,
				     cipher->salt_size + cipher->wire_iv_size);
	cipher_context_op_normal(context, wire_iv, data, iv, logger);
	cipher_context_destroy(&context, logger);
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
	enum cipher_op op;
	enum cipher_iv_source iv_source;
	chunk_t salt;
	PK11SymKey *symkey;
	chunk_t old_wire_iv;
};

struct cipher_context *cipher_context_create(const struct encrypt_desc *cipher,
					     enum cipher_op op,
					     enum cipher_iv_source iv_source,
					     PK11SymKey *symkey,
					     shunk_t salt,
					     struct logger *logger)
{
	if (DBGP(DBG_BASE)) {
		LDBG_log(logger, "%s() %s %s %s symkey %p",
			 __func__, cipher->common.fqn,
			 str_cipher_op(op), str_cipher_iv_source(iv_source),
			 symkey);
		LDBG_hunk(logger, salt);
	}
	struct cipher_context *cipher_context = alloc_thing(struct cipher_context, __func__);
	cipher_context->cipher = cipher;
	cipher_context->op = op;
	cipher_context->iv_source = iv_source;
	cipher_context->symkey = symkey_addref(logger, __func__, symkey);
	cipher_context->salt = clone_hunk(salt, __func__);
	cipher_context->old_wire_iv = alloc_chunk(cipher->wire_iv_size, __func__);
	if (cipher->encrypt_ops->cipher_op_context_create != NULL) {
		cipher_context->op_context =
			cipher->encrypt_ops->cipher_op_context_create(cipher, op, iv_source,
								      symkey, salt, logger);
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

	symkey_delref(logger, __func__, &(*cipher_context)->symkey);
	free_chunk_content(&(*cipher_context)->salt);
	free_chunk_content(&(*cipher_context)->old_wire_iv);

	pfreeany(*cipher_context);
	return;
}

static void verify_wire_iv(const struct cipher_context *cipher_context,
			   chunk_t new_wire_iv,
			   struct logger *logger)
{
	if (cipher_context->iv_source == FILL_WIRE_IV) {
		LDBGP_JAMBUF(DBG_BASE, logger, buf) {
			jam(buf, "update %p %s wire_iv ",
			    cipher_context, cipher_context->cipher->common.fqn);
			jam_hex_hunk(buf, cipher_context->old_wire_iv);
			jam_string(buf, " -> ");
			jam_hex_hunk(buf, new_wire_iv);
		}
		PASSERT(logger, !hunk_eq(new_wire_iv, cipher_context->old_wire_iv));
		hunk_cpy(cipher_context->old_wire_iv, new_wire_iv);
	}
}

bool cipher_context_op_aead(const struct cipher_context *cipher_context,
			    chunk_t wire_iv,
			    shunk_t aad,
			    chunk_t text_and_tag,
			    size_t text_size, size_t tag_size,
			    struct logger *logger)
{
	if (!cipher_context->cipher->encrypt_ops->cipher_op_aead(cipher_context->cipher,
								 cipher_context->op_context,
								 cipher_context->op,
								 cipher_context->iv_source,
								 cipher_context->symkey,
								 HUNK_AS_SHUNK(cipher_context->salt),
								 wire_iv, aad,
								 text_and_tag, text_size, tag_size,
								 logger)) {
		return false;
	}
	verify_wire_iv(cipher_context, wire_iv, logger);
	return true;
}

void cipher_context_op_normal(const struct cipher_context *cipher_context,
			      chunk_t wire_iv,
			      chunk_t text,
			      struct crypt_mac *ikev1_iv,
			      struct logger *logger)
{
	cipher_context->cipher->encrypt_ops->cipher_op_normal(cipher_context->cipher,
							      cipher_context->op_context,
							      cipher_context->op,
							      cipher_context->iv_source,
							      cipher_context->symkey,
							      HUNK_AS_SHUNK(cipher_context->salt),
							      wire_iv, text,
							      ikev1_iv,
							      logger);
	verify_wire_iv(cipher_context, wire_iv, logger);
}
