/*
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#ifndef IKE_ALG_HASH_OPS_H
#define IKE_ALG_HASH_OPS_H

/*
 * Generic implementation of HASH_DESC.
 */
struct hash_context;

struct hash_ops {
	const char *backend;

	/*
	 * Delegate responsibility for checking OPS specific fields.
	 */
	void (*const check)(const struct hash_desc *alg, struct logger *logger);

	struct hash_context *(*init)(const struct hash_desc *hash_desc,
				     const char *name);
	void (*digest_symkey)(struct hash_context *hash,
			      const char *name, PK11SymKey *symkey);
	void (*digest_bytes)(struct hash_context *hash,
			     const char *name,
			     const uint8_t *bytes, size_t sizeof_bytes);
	void (*final_bytes)(struct hash_context**,
			    uint8_t *bytes, size_t sizeof_bytes);
};

extern const struct hash_ops ike_alg_hash_nss_ops;

#endif
