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

#include "lswalloc.h"
#include "ike_alg.h"
#include "ike_alg_prf.h"

#include "ikev1_prf.h"
#include "crypt_symkey.h"

#include "cavp.h"
#include "cavp_entry.h"
#include "cavp_print.h"
#include "test_ikev1.h"
#include "test_ikev1_dsa.h"
#include "acvp.h"

static long int ni_length;
static long int nr_length;
static long int g_xy_length;
static const struct cavp_entry *prf_entry;

static const struct cavp_entry config_entries[] = {
#ifdef USE_SHA1
	{ .key = "SHA-1", .op = op_entry, .entry = &prf_entry, .prf = &ike_alg_prf_sha1, },
#endif
#ifdef USE_SHA2
	{ .key = "SHA-224", .op = op_entry, .entry = &prf_entry, .prf = NULL, },
	{ .key = "SHA-256", .op = op_entry, .entry = &prf_entry, .prf = &ike_alg_prf_sha2_256, },
	{ .key = "SHA-384", .op = op_entry, .entry = &prf_entry, .prf = &ike_alg_prf_sha2_384, },
	{ .key = "SHA-512", .op = op_entry, .entry = &prf_entry, .prf = &ike_alg_prf_sha2_512, },
#endif
	{ .key = "Ni length", .op = op_signed_long, .signed_long = &ni_length, },
	{ .key = "Nr length", .op = op_signed_long, .signed_long = &nr_length, },
	{ .key = "g^xy length", .op = op_signed_long, .signed_long = &g_xy_length, },
	{ .key = NULL }
};

static long int count;
static chunk_t ni;
static chunk_t nr;
static chunk_t cky_i;
static chunk_t cky_r;
static PK11SymKey *g_xy;

static const struct cavp_entry data_entries[] = {
	{ .key = "COUNT", .opt = ACVP_TCID, .op = op_signed_long, .signed_long = &count },
	{ .key = "g^xy", .opt =  "gxy", .op = op_symkey, .symkey = &g_xy },
	{ .key = "Ni", .opt =  "nInit", .op = op_chunk, .chunk = &ni },
	{ .key = "Nr", .opt =  "nResp", .op = op_chunk, .chunk = &nr },
	{ .key = "CKY_I", .opt =  "ckyInit" , .op = op_chunk, .chunk = &cky_i },
	{ .key = "CKY_R", .opt =  "ckyResp", .op = op_chunk, .chunk = &cky_r },
	{ .key = "SKEYID", .op = op_ignore },
	{ .key = "SKEYID_d", .op = op_ignore },
	{ .key = "SKEYID_a", .op = op_ignore },
	{ .key = "SKEYID_e", .op = op_ignore },
	{ .key = "SKEYID_", .op = op_ignore },
	{ .op = NULL }
};

static void ikev1_dsa_print_config(void)
{
	config_number("g^xy length", g_xy_length);
	config_key(prf_entry->key);
	config_number("Ni length", ni_length);
	config_number("Nr length", nr_length);
}

static void ikev1_dsa_run_test(void)
{
	print_number("COUNT", ACVP_TCID, count);
	print_chunk("CKY_I", NULL, cky_i, 0);
	print_chunk("CKY_R", NULL, cky_r, 0);
	print_chunk("Ni", NULL, ni, 0);
	print_chunk("Nr", NULL, nr, 0);
	print_symkey("g^xy", NULL, g_xy, 0);
	if (prf_entry->prf == NULL) {
		/* not supported, ignore */
		fprintf(stderr, "WARNING: ignoring test with PRF %s\n", prf_entry->key);
		print_line(prf_entry->key);
		return;
	}
	const struct prf_desc *prf = prf_entry->prf;
	PK11SymKey *skeyid = ikev1_signature_skeyid(prf, ni, nr, g_xy);
	cavp_ikev1_skeyid_alphabet(prf, g_xy, cky_i, cky_r, skeyid);
	release_symkey(__func__, "skeyid", &skeyid);
}

const struct cavp test_ikev1_dsa = {
	.alias = "v1dsa",
	.description = "IKE v1 Digital Signature Authentication",
	.print_config = ikev1_dsa_print_config,
	.run_test = ikev1_dsa_run_test,
	.config = config_entries,
	.data = data_entries,
	.match = {
		"IKE v1 Digital Signature Authentication",
		NULL,
	},
};
