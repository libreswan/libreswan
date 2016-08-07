/*
 * Parse IKEv1 CAVP test functions, for libreswan
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
#include "crypt_symkey.h"

#include "cavp.h"
#include "cavp_print.h"
#include "cavp_ikev1.h"

static int ni_length;
static int nr_length;
static int psk_length;
static int g_xy_length;

static struct cavp_entry config_entries[] = {
	{ .key = "SHA-1", .op = hash, .value = OAKLEY_SHA1, },
	{ .key = "SHA-224", .op = hash, .value = 0, },
	{ .key = "SHA-256", .op = hash, .value = OAKLEY_SHA2_256, },
	{ .key = "SHA-384", .op = hash, .value = OAKLEY_SHA2_384, },
	{ .key = "SHA-512", .op = hash, .value = OAKLEY_SHA2_512, },
	{ .key = "Ni length", .op = number, .number = &ni_length },
	{ .key = "Nr length", .op = number, .number = &nr_length },
	{ .key = "pre-shared-key length", .op = number, .number = &psk_length },
	{ .key = "g^xy length", .op = number, .number = &g_xy_length },
	{ .key = NULL }
};

static int count;
static chunk_t psk;
static chunk_t ni;
static chunk_t nr;
static chunk_t cky_i;
static chunk_t cky_r;
static PK11SymKey *g_xy;

static struct cavp_entry data_entries[] = {
	{ .key = "COUNT", .op = number, .number = &count },
	{ .key = "g^xy", .op = symkey, .symkey = &g_xy },
	{ .key = "Ni", .op = chunk, .chunk = &ni },
	{ .key = "Nr", .op = chunk, .chunk = &nr },
	{ .key = "CKY_I", .op = chunk, .chunk = &cky_i },
	{ .key = "CKY_R", .op = chunk, .chunk = &cky_r },
	{ .key = "pre-shared-key", .op = chunk, .chunk = &psk },
	{ .key = "SKEYID", .op = ignore },
	{ .key = "SKEYID_d", .op = ignore },
	{ .key = "SKEYID_a", .op = ignore },
	{ .key = "SKEYID_e", .op = ignore },
	{ .key = "SKEYID_", .op = ignore },
	{ .op = NULL }
};

static void ikev1_skeyid_alphabet(PK11SymKey *skeyid)
{
	PK11SymKey *skeyid_d =
		ikev1_skeyid_d(hasher, skeyid,
			       g_xy, cky_i, cky_r);
	print_symkey("SKEYID_d", skeyid_d, 0);

	PK11SymKey *skeyid_a =
		ikev1_skeyid_a(hasher, skeyid, skeyid_d,
			       g_xy, cky_i, cky_r);
	print_symkey("SKEYID_a", skeyid_a, 0);

	PK11SymKey *skeyid_e =
		ikev1_skeyid_e(hasher, skeyid, skeyid_a,
			       g_xy, cky_i, cky_r);
	print_symkey("SKEYID_e", skeyid_e, 0);

	free_any_symkey("skeyid_d", &skeyid_d);
	free_any_symkey("skeyid_e", &skeyid_e);
	free_any_symkey("skeyid_a", &skeyid_a);
}

static void print_sig_config(void)
{
	config_number("g^xy length", g_xy_length);
	config_key(hasher_name);
	config_number("Ni length", ni_length);
	config_number("Nr length", nr_length);
}

static void run_sig(void)
{
	print_number("COUNT", count);
	print_chunk("CKY_I", cky_i, 0);
	print_chunk("CKY_R", cky_r, 0);
	print_chunk("Ni", ni, 0);
	print_chunk("Nr", nr, 0);
	print_symkey("g^xy", g_xy, 0);

	if (hasher == NULL) {
		print_line(hasher_name);
		return;
	}

	PK11SymKey *skeyid =
		ikev1_signature_skeyid(hasher,
				       ni, nr,
				       g_xy);
	print_symkey("SKEYID", skeyid, 0);
	ikev1_skeyid_alphabet(skeyid);
	free_any_symkey("skeyid", &skeyid);
}

struct cavp cavp_ikev1_sig = {
	.alias = "v1sig",
	.description = "IKE v1 Digital Signature Authentication",
	.print_config = print_sig_config,
	.run = run_sig,
	.config = config_entries,
	.data = data_entries,
};

static void print_psk_config(void)
{
	config_number("g^xy length", g_xy_length);
	config_key(hasher_name);
	config_number("Ni length", ni_length);
	config_number("Nr length", nr_length);
	config_number("pre-shared-key length", psk_length);
}

static void run_psk(void)
{
	print_number("COUNT", count);
	print_chunk("CKY_I", cky_i, 0);
	print_chunk("CKY_R", cky_r, 0);
	print_chunk("Ni", ni, 0);
	print_chunk("Nr", nr, 0);
	print_symkey("g^xy", g_xy, 0);
	print_chunk("pre-shared-key", psk, 0);

	if (hasher == NULL) {
		print_line(hasher_name);
		return;
	}

	PK11SymKey *skeyid =
		ikev1_pre_shared_key_skeyid(hasher,
					    psk,
					    ni, nr,
					    g_xy);
	print_symkey("SKEYID", skeyid, 0);
	ikev1_skeyid_alphabet(skeyid);
	free_any_symkey("skeyid", &skeyid);
}

struct cavp cavp_ikev1_psk = {
	.alias = "v1psk",
	.description = "IKE v1 Pre-shared Key Authentication",
	.print_config = print_psk_config,
	.run = run_psk,
	.config = config_entries,
	.data = data_entries,
};
