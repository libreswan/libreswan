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

#include "crypt_symkey.h"
#include "ikev2_prf.h"

#include "cavp.h"
#include "cavp_print.h"
#include "cavp_ikev2.h"

static int g_ir_length;
static int ni_length;
static int nr_length;
static int dkm_length;
static int child_sa_dkm_length;

static struct cavp_entry config_entries[] = {
	{ .key = "g^ir length", .op = number, .number = &g_ir_length },
	{ .key = "SHA-1", .op = hash, .value = OAKLEY_SHA1, },
	{ .key = "SHA-224", .op = hash, .value = 0, },
	{ .key = "SHA-256", .op = hash, .value = OAKLEY_SHA2_256, },
	{ .key = "SHA-384", .op = hash, .value = OAKLEY_SHA2_384, },
	{ .key = "SHA-512", .op = hash, .value = OAKLEY_SHA2_512, },
	{ .key = "Ni length", .op = number, .number = &ni_length },
	{ .key = "Nr length", .op = number, .number = &nr_length },
	{ .key = "DKM length", .op = number, .number = &dkm_length },
	{ .key = "Child SA DKM length", .op = number, .number = &child_sa_dkm_length },
	{ .key = NULL }
};

static void ikev2_config(void)
{
	config_number("g^ir length", g_ir_length);
	config_key(hasher_name);
	config_number("Ni length",ni_length);
	config_number("Nr length",nr_length);
	config_number("DKM length",dkm_length);
	config_number("Child SA DKM length",child_sa_dkm_length);
}

static int count;
static chunk_t ni;
static chunk_t nr;
static PK11SymKey *g_ir;
static PK11SymKey *g_ir_new;
static chunk_t spi_i;
static chunk_t spi_r;

static struct cavp_entry data_entries[] = {
	{ .key = "COUNT", .op = number, .number = &count },
	{ .key = "g^ir", .op = symkey, .symkey = &g_ir },
	{ .key = "g^ir (new)", .op = symkey, .symkey = &g_ir_new },
	{ .key = "Ni", .op = chunk, .chunk = &ni },
	{ .key = "Nr", .op = chunk, .chunk = &nr },
	{ .key = "SPIi", .op = chunk, .chunk = &spi_i },
	{ .key = "SPIr", .op = chunk, .chunk = &spi_r },
	{ .key = "SKEYSEED", .op = ignore },
	{ .key = "DKM", .op = ignore },
	{ .key = "DKM(Child SA)", .op = ignore },
	{ .key = "DKM(Child SA D-H)", .op = ignore },
	{ .key = "SKEYSEED(Rekey)", .op = ignore },
	{ .op = NULL }
};

static void run_ikev2(void)
{
	print_number("COUNT", count);
	print_chunk("Ni", ni, 0);
	print_chunk("Nr", nr, 0);
	print_symkey("g^ir", g_ir, 0);
	print_symkey("g^ir (new)", g_ir_new, 0);
	print_chunk("SPIi", spi_i, 0);
	print_chunk("SPIr", spi_r, 0);

	if (hasher == NULL) {
		print_line(hasher_name);
		return;
	}

	/* SKEYSEED = prf(Ni | Nr, g^ir) */
	PK11SymKey *skeyseed =
		ikev2_ike_sa_skeyseed(hasher, ni, nr, g_ir);
	print_symkey("SKEYSEED", skeyseed, 0);

	/* prf+(SKEYSEED, Ni | Nr | SPIi | SPIr) */
	PK11SymKey *dkm =
		ikev2_ike_sa_keymat(hasher, skeyseed,
				    ni, nr, spi_i, spi_r, dkm_length / 8);
	print_symkey("DKM", dkm, dkm_length / 8);

	/* prf+(SK_d, Ni | Nr) */
	PK11SymKey *SK_d = key_from_symkey_bytes(dkm, 0, hasher->hash_digest_len);
	PK11SymKey *child_sa_dkm =
		ikev2_child_sa_keymat(hasher, SK_d, NULL, ni, nr, child_sa_dkm_length / 8);
	print_symkey("DKM(Child SA)", child_sa_dkm, child_sa_dkm_length / 8);

	/* prf+(SK_d, g^ir (new) | Ni | Nr) */
	PK11SymKey *child_sa_dkm_dh =
		ikev2_child_sa_keymat(hasher, SK_d, g_ir_new, ni, nr,
				      child_sa_dkm_length / 8);
	print_symkey("DKM(Child SA D-H)", child_sa_dkm_dh, child_sa_dkm_length / 8);

	/* prf(SK_d (old), g^ir (new) | Ni | Nr) */
	PK11SymKey *skeyseed_rekey =
		ikev2_ike_sa_rekey_skeyseed(hasher, SK_d, g_ir_new, ni, nr);
	print_symkey("SKEYSEED(Rekey)", skeyseed_rekey, 0);

	free_any_symkey("skeyseed", &skeyseed);
	free_any_symkey("dkm", &dkm);
	free_any_symkey("SK_d", &SK_d);
	free_any_symkey("child_sa_dkm", &child_sa_dkm);
	free_any_symkey("child_sa_dkm_dh", &child_sa_dkm_dh);
	free_any_symkey("skeyseed_rekey", &skeyseed_rekey);
}

struct cavp cavp_ikev2 = {
	.alias = "v2",
	.description = "IKE v2",
	.print_config = ikev2_config,
	.run = run_ikev2,
	.config = config_entries,
	.data = data_entries,
};
