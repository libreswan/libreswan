/*
 * Copyright (C) 2014,2016 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

struct cbc_test_vector {
	const char *description;
	/* mumble something about algorithm setting here. */
	const char *key;
	const char *iv;
	const char *plaintext;
	const char *ciphertext;
};

const struct cbc_test_vector *const aes_cbc_tests;
const struct cbc_test_vector *const camellia_cbc_tests;

bool test_cbc_vectors(const struct encrypt_desc *encrypt_desc,
		      const struct cbc_test_vector *tests);
