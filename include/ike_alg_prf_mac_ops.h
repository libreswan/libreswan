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

#ifndef IKE_ALG_PRF_MAC_OPS_H
#define IKE_ALG_PRF_MAC_OPS_H

struct logger;

struct prf_mac_ops {
	const char *backend;
	bool bespoke;

	/*
	 * Delegate responsibility for checking OPS specific fields.
	 */
	void (*const check)(const struct prf_desc *alg, struct logger *logger);

	struct prf_context *(*init_symkey)(const struct prf_desc *prf_desc,
					   const char *name,
					   const char *key_name, PK11SymKey *key,
					   struct logger *logger);
	struct prf_context *(*init_bytes)(const struct prf_desc *prf_desc,
					  const char *name,
					  const char *key_name,
					  const uint8_t *bytes, size_t sizeof_bytes,
					  struct logger *logger);
	void (*digest_symkey)(struct prf_context *prf,
			      const char *name, PK11SymKey *symkey);
	void (*digest_bytes)(struct prf_context *prf,
			     const char *name, const uint8_t *bytes, size_t sizeof_bytes);
	PK11SymKey *(*final_symkey)(struct prf_context **prf);
	void (*final_bytes)(struct prf_context **prf, uint8_t *bytes, size_t sizeof_bytes);
};

extern const struct prf_mac_ops ike_alg_prf_mac_hmac_ops;
extern const struct prf_mac_ops ike_alg_prf_mac_nss_ops;
extern const struct prf_mac_ops ike_alg_prf_mac_nss_xcbc_ops;

#endif
