/*
 * Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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

struct gcm_test_vector {
	const char *key;
	/*
	 * NIST provides a simple IV, while we require a separate SALT
	 * and wire-IV.  The value gets split before being passed to
	 * the do_crypt_hash method.
	 */
	const char *salted_iv;
	const char *aad;
	const char *plaintext;
	const char *ciphertext;
	const char *tag;
};

const struct gcm_test_vector *const aes_gcm_tests;

bool test_gcm_vectors(const struct encrypt_desc *encrypt_desc,
		      const struct gcm_test_vector *tests);
