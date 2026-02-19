/* mac result from PRF and HASH functions, for libreswan
 *
 * Copyright (C) 2019,2025 Andrew Cagney
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

#ifndef CRYPT_MAC_H
#define CRYPT_MAC_H

#include <stddef.h>	/* for size_t */
#include <stdint.h>	/* for uint8_t */

/*
 * Structure big enough for all MAC blocks and results.  See
 * hash_block_size, hash_digest_size, prf_key_size.
 *
 * See also ike_alg_init() for runtime check that the array is big
 * enough.
 *
 * XXX: the field names (notably the counter intuitive .ptr) are
 * chosen so that this structure is "hunk" like and works with hunk()
 * macros.
 */

struct crypt_mac {
	/* size of the mac in bytes */
	size_t len;
	/* XXX: see note above about why this is called .ptr */
	uint8_t ptr[128/*see ike_alg_init() for size check*/];
};

extern const struct crypt_mac empty_mac;

#endif
