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

struct logger;

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
			       uint8_t *dat,
			       size_t datasize,
			       PK11SymKey *key,
			       uint8_t *iv,
			       bool enc,
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
	 */
	bool (*const do_aead)(const struct encrypt_desc *alg,
			      uint8_t *salt, size_t salt_size,
			      uint8_t *wire_iv, size_t wire_iv_size,
			      uint8_t *aad, size_t aad_size,
			      uint8_t *text_and_tag,
			      size_t text_size, size_t tag_size,
			      PK11SymKey *key, bool enc,
			      struct logger *logger);
};

extern const struct encrypt_ops ike_alg_encrypt_nss_aead_ops;
extern const struct encrypt_ops ike_alg_encrypt_nss_cbc_ops;
extern const struct encrypt_ops ike_alg_encrypt_nss_ctr_ops;
extern const struct encrypt_ops ike_alg_encrypt_nss_gcm_ops;
extern const struct encrypt_ops ike_alg_encrypt_null_ops;

#endif
