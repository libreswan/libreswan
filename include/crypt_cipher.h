/* Cipher algorithms, for libreswan
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

#ifndef CRYPT_CIPHER_H
#define CRYPT_CIPHER_H

#include <pk11pub.h>

#include "chunk.h"
#include "shunk.h"

struct encrypt_desc;
struct logger;
struct cipher_context;
struct crypt_mac;

enum cipher_op {
	DECRYPT = false,
	ENCRYPT = true,
};

#define str_cipher_op(OP)			\
	({					\
		enum cipher_op op_ = OP;	\
		(op_ == ENCRYPT ? "encrypt" :	\
		 op_ == DECRYPT ? "decrypt" :	\
		 "???");			\
	})

/*
 * Normally USE_IV:DECRYPT and FILL_IV:ENCRYPT each come as a pair.
 * The exception is testing where encryption can't generate its own
 * IV.
 */

enum cipher_iv_source {
	USE_WIRE_IV = 1,
	FILL_WIRE_IV,
	USE_IKEv1_IV,
};

#define str_cipher_iv_source(IV_SOURCE)				\
	({							\
		enum cipher_iv_source iv_source_ = IV_SOURCE;	\
		(iv_source_ == USE_WIRE_IV ? "use wire IV" :	\
		 iv_source_ == FILL_WIRE_IV ? "fill wire IV" :	\
		 iv_source_ == USE_IKEv1_IV ? "use IKEv1 IV" :	\
		 "???");					\
	})

/*
 * Separate cipher and integrity.
 */

void cipher_ikev1(const struct encrypt_desc *cipher,
		  enum cipher_op op,
		  chunk_t text,
		  struct crypt_mac *iv,
		  PK11SymKey *key,
		  struct logger *logger);

bool cipher_aead(const struct encrypt_desc *cipher,
		 enum cipher_op op,
		 enum cipher_iv_source iv_source,
		 shunk_t salt,
		 chunk_t wire_iv,
		 shunk_t aad,
		 chunk_t text_and_tag,
		 size_t text_size, size_t tag_size,
		 PK11SymKey *key,
		 struct logger *logger);

struct cipher_context *cipher_context_create(const struct encrypt_desc *cipher,
					     enum cipher_op op,
					     enum cipher_iv_source iv_source,
					     PK11SymKey *key,
					     shunk_t salt,
					     struct logger *logger);
void cipher_context_destroy(struct cipher_context **,
			    struct logger *logger);

void cipher_context_op_normal(const struct cipher_context *,
			      chunk_t wire_iv,
			      chunk_t text,
			      struct crypt_mac *ikev1_iv,
			      struct logger *logger);

bool cipher_context_op_aead(const struct cipher_context *,
			    chunk_t wire_iv,
			    shunk_t aad,
			    chunk_t text_and_tag,
			    size_t text_size, size_t tag_size,
			    struct logger *logger);

#endif
