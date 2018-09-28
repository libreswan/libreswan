/*
 * Copyright (C) 2014,2016 Andrew Cagney <cagney@gnu.org>
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

struct ctr_test_vector {
	/* CK_MECHANISM_TYPE cipher_mechanism; */
	/* struct encrypt_desc *encrypt_desc; */
	const char *description;
	const char *key;
	const char *cb;
	const char *plaintext;
	const char *ciphertext;
	const char *output_cb;
};

const struct ctr_test_vector *const aes_ctr_tests;

bool test_ctr_vectors(const struct encrypt_desc *encrypt_desc,
		      const struct ctr_test_vector *tests);
