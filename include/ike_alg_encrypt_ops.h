/* NSS AEAD, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney <cagney@gnu.org>
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

#ifndef IKE_ALG_ENCRYPT_OPS_H
#define IKE_ALG_ENCRYPT_OPS_H

#include "chunk.h"
#include "shunk.h"

struct logger;
enum cipher_op;
enum cipher_iv_source;
struct cipher_op_context;

struct encrypt_ops {
	const char *backend;

	/*
	 * Delegate responsibility for checking OPS specific fields.
	 */
	void (*const check)(const struct encrypt_desc *alg, struct logger *logger);

	/*
	 * Perform simple encryption.
	 *
	 * Presumably something else is implementing the integrity.
	 */
	void (*const do_crypt)(const struct encrypt_desc *alg,
			       chunk_t data,
			       chunk_t iv,
			       PK11SymKey *key,
			       enum cipher_op op,
			       struct logger *logger);

	/*
	 * Perform Authenticated Encryption with Associated Data
	 * (AEAD).
	 *
	 * The salt and wire-IV are concatenated to form the NONCE
	 * (aka. counter variable; IV; ...).
	 *
	 * The Additional Authentication Data (AAD) and the
	 * cipher-text are concatenated when generating/validating the
	 * tag (which is appended to the text).
	 *
	 * All sizes are in 8-bit bytes.
	 *
	 * Danger: TEXT and TAG are assumed to be contigious.
	 */

	struct cipher_op_context *(*const context_create)(const struct encrypt_desc *,
							  enum cipher_op,
							  enum cipher_iv_source,
							  PK11SymKey *key,
							  shunk_t salt,
							  struct logger *logger);
	void (*const context_destroy)(struct cipher_op_context **context,
				      struct logger *logger);

	bool (*const context_aead_op)(const struct cipher_op_context *context,
				      chunk_t wire_iv,
				      shunk_t aad,
				      chunk_t text_and_tag,
				      size_t text_size, size_t tag_size,
				      struct logger *logger);
};

extern const struct encrypt_ops ike_alg_encrypt_nss_aead_ops;
extern const struct encrypt_ops ike_alg_encrypt_nss_cbc_ops;
extern const struct encrypt_ops ike_alg_encrypt_nss_ctr_ops;
extern const struct encrypt_ops ike_alg_encrypt_null_ops;

#endif
