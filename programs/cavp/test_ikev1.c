/*
 * Parse IKEv1 CAVP test functions, for libreswan
 *
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

#include "test_ikev1.h"
#include "cavp_print.h"
#include "ikev1_prf.h"
#include "crypt_symkey.h"

void cavp_ikev1_skeyid_alphabet(const struct prf_desc *prf,
				PK11SymKey *g_xy,
				chunk_t cky_i, chunk_t cky_r,
				PK11SymKey *skeyid)
{
	print_symkey("SKEYID", "sKeyId", skeyid, 0);
	PK11SymKey *skeyid_d = ikev1_skeyid_d(prf, skeyid,
					      g_xy, cky_i, cky_r);
	print_symkey("SKEYID_d", "sKeyIdD", skeyid_d, 0);

	PK11SymKey *skeyid_a = ikev1_skeyid_a(prf, skeyid, skeyid_d,
					      g_xy, cky_i, cky_r);
	print_symkey("SKEYID_a", "sKeyIdA", skeyid_a, 0);

	PK11SymKey *skeyid_e = ikev1_skeyid_e(prf, skeyid, skeyid_a,
					      g_xy, cky_i, cky_r);
	print_symkey("SKEYID_e", "sKeyIdE", skeyid_e, 0);

	release_symkey(__func__, "skeyid_d", &skeyid_d);
	release_symkey(__func__, "skeyid_e", &skeyid_e);
	release_symkey(__func__, "skeyid_a", &skeyid_a);
}
