/*
 * Copyright (C) 2014,2016-2017 Andrew Cagney
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

struct prf_test_vector {
	const char *description;
	const char *key;
	unsigned key_size;
	const char *message;
	unsigned message_size;
	const char *prf_output;
};

extern const struct prf_test_vector aes_xcbc_prf_tests[];
extern const struct prf_test_vector hmac_md5_prf_tests[];

bool test_prf_vectors(const struct prf_desc *desc,
		      const struct prf_test_vector *tests,
		      struct logger *logger);

struct kdf_test_vector {
	const char *description;
	const char *ni;
	unsigned ni_size;
	const char *nr;
	unsigned nr_size;
	const char *gir;
	const char *gir_new;
	unsigned gir_size;
	const char *spii;
	const char *spir;
	const char *skeyseed;
	const char *skeyseed_rekey;
	const char *dkm;
	unsigned dkm_size;
};

extern const struct kdf_test_vector hmac_sha1_kdf_tests[];

bool test_kdf_vectors(const struct prf_desc *desc,
		      const struct kdf_test_vector *tests,
		      struct logger *logger);
