/*
 * Copyright (C) 2014 Andrew Cagney <andrew.cagney@gmail.com>
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
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

#ifndef TEST_BUFFER_H
#define TEST_BUFFER_H

#include <stdbool.h>
#include <pk11pub.h>

#include "chunk.h"
#include "where.h"

struct logger;
struct encrypt_desc;

chunk_t decode_to_chunk(const char *prefix, const char *string,
			struct logger *logger, where_t where);
struct crypt_mac decode_to_mac(const char *prefix, const char *string,
			       struct logger *logger, where_t where);
PK11SymKey *decode_hex_to_symkey(const char *prefix, const char *string,
				 struct logger *logger, where_t where);

PK11SymKey *decode_to_key(const struct encrypt_desc *encrypt_desc, const char *string,
			  struct logger *logger, where_t where);

bool verify_symkey(const char *desc, const char *verifying,
		   chunk_t expected, PK11SymKey *actual,
		   struct logger *logger, where_t where);

bool verify_bytes(const char *desc, const char *verifying,
		  const void *expected, size_t expected_size,
		  const void *actual, size_t actual_size,
		  struct logger *logger, where_t where);

#define verify_hunk(DESC, VERIFYING, EXPECTED, ACTUAL, LOGGER, WHERE)	\
	({								\
		typeof(EXPECTED) expected_ = EXPECTED; /* evaluate once */ \
		typeof(ACTUAL) actual_ = ACTUAL; /* evaluate once */	\
		verify_bytes(DESC, VERIFYING,				\
			     expected_.ptr, expected_.len,		\
			     actual_.ptr, actual_.len,			\
			     LOGGER, WHERE);				\
	})

#endif
