/*
 * Parse CAVP test vectors, for libreswan
 *
 * Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

#include <pk11pub.h>

#include "lswalloc.h"
#include "ike_alg.h"

#include "ikev1_prf.h"
#include "cavp.h"

void cavp_run(void)
{
	if (cavp_config.hasher == NULL) {
		printf("no hasher");
		return;
	}
	PK11SymKey *skeyid =
		ikev1_pre_shared_key_skeyid(cavp_config.hasher,
					    cavp_data.psk,
					    cavp_data.ni, cavp_data.nr,
					    cavp_data.g_xy);
	print_symkey("SKEYID", skeyid, 0);

	PK11SymKey *skeyid_d =
		ikev1_skeyid_d(cavp_config.hasher, skeyid,
			       cavp_data.g_xy, cavp_data.cky_i, cavp_data.cky_r);
	print_symkey("SKEYID_d", skeyid_d, 0);
	
	PK11SymKey *skeyid_a =
		ikev1_skeyid_a(cavp_config.hasher, skeyid, skeyid_d,
			       cavp_data.g_xy, cavp_data.cky_i, cavp_data.cky_r);
	print_symkey("SKEYID_a", skeyid_a, 0);
	
	PK11SymKey *skeyid_e =
		ikev1_skeyid_e(cavp_config.hasher, skeyid, skeyid_a,
			       cavp_data.g_xy, cavp_data.cky_i, cavp_data.cky_r);
	print_symkey("SKEYID_e", skeyid_e, 0);

	PK11_FreeSymKey(skeyid);
	PK11_FreeSymKey(skeyid_d);
	PK11_FreeSymKey(skeyid_e);
	PK11_FreeSymKey(skeyid_a);
}
