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

#include "crypt_symkey.h"
#include "ikev2_prf.h"

#include "cavp.h"
#include "cavp_entry.h"
#include "cavp_print.h"
#include "test_ikev2.h"
#include "acvp.h"

static void cavp_acvp_ikev2(const struct prf_desc *prf,
			    chunk_t ni, chunk_t nr,
			    PK11SymKey *g_ir, PK11SymKey *g_ir_new,
			    chunk_t spi_i, chunk_t spi_r,
			    signed long nr_ike_sa_dkm_bytes,
			    signed long nr_child_sa_dkm_bytes)
{
	/* SKEYSEED = prf(Ni | Nr, g^ir) */
	PK11SymKey *skeyseed = ikev2_ike_sa_skeyseed(prf,
						     ni, nr,
						     g_ir);
	print_symkey("SKEYSEED", "sKeySeed", skeyseed, 0);
	if (skeyseed == NULL) {
		print_line("failure in SKEYSEED = prf(Ni | Nr, g^ir)");
		exit(1);
	}

	/* prf+(SKEYSEED, Ni | Nr | SPIi | SPIr) */
	PK11SymKey *dkm = ikev2_ike_sa_keymat(prf, skeyseed,
					      ni, nr,
					      spi_i, spi_r,
					      nr_ike_sa_dkm_bytes);
	print_symkey("DKM", "derivedKeyingMaterial", dkm, nr_ike_sa_dkm_bytes);

	/* prf+(SK_d, Ni | Nr) */
	PK11SymKey *SK_d = key_from_symkey_bytes(dkm, 0, prf->prf_key_size);
	PK11SymKey *child_sa_dkm = ikev2_child_sa_keymat(prf, SK_d, NULL,
							 ni, nr, nr_child_sa_dkm_bytes);
	print_symkey("DKM(Child SA)", "derivedKeyingMaterialChild",
		     child_sa_dkm, nr_child_sa_dkm_bytes);

	/* prf+(SK_d, g^ir (new) | Ni | Nr) */
	PK11SymKey *child_sa_dkm_dh = ikev2_child_sa_keymat(prf, SK_d,
							    g_ir_new, ni, nr,
							    nr_child_sa_dkm_bytes);
	print_symkey("DKM(Child SA D-H)", "derivedKeyingMaterialDh",
		     child_sa_dkm_dh, nr_child_sa_dkm_bytes);

	/* SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr) */
	PK11SymKey *skeyseed_rekey = ikev2_ike_sa_rekey_skeyseed(prf, SK_d, g_ir_new,
								 ni, nr);
	print_symkey("SKEYSEED(Rekey)", "sKeySeedReKey",
		     skeyseed_rekey, 0);
	if (skeyseed_rekey == NULL) {
		print_line("failure in SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)");
		exit(1);
	}

	release_symkey(__func__, "skeyseed", &skeyseed);
	release_symkey(__func__, "dkm", &dkm);
	release_symkey(__func__, "SK_d", &SK_d);
	release_symkey(__func__, "child_sa_dkm", &child_sa_dkm);
	release_symkey(__func__, "child_sa_dkm_dh", &child_sa_dkm_dh);
	release_symkey(__func__, "skeyseed_rekey", &skeyseed_rekey);
}

static long int g_ir_length;
static long int ni_length;
static long int nr_length;
static signed long nr_ike_sa_dkm_bits;
static signed long nr_child_sa_dkm_bits;
static const struct cavp_entry *prf_entry;

static const struct cavp_entry config_entries[] = {
	{ .key = "g^ir length", .op = op_signed_long, .signed_long = &g_ir_length },
#ifdef USE_SHA1
	{ .key = "SHA-1", .op = op_entry, .entry = &prf_entry, .prf = &ike_alg_prf_sha1, },
#endif
#ifdef USE_SHA2
	{ .key = "SHA-224", .op = op_entry, .entry = &prf_entry, .prf = NULL, },
	{ .key = "SHA-256", .op = op_entry, .entry = &prf_entry, .prf = &ike_alg_prf_sha2_256, },
	{ .key = "SHA-384", .op = op_entry, .entry = &prf_entry, .prf = &ike_alg_prf_sha2_384, },
	{ .key = "SHA-512", .op = op_entry, .entry = &prf_entry, .prf = &ike_alg_prf_sha2_512, },
#endif
	{ .key = "Ni length", .op = op_signed_long, .signed_long = &ni_length },
	{ .key = "Nr length", .op = op_signed_long, .signed_long = &nr_length },
	{ .key = "DKM length", .opt = ACVP_DKM_OPTION, .op = op_signed_long, .signed_long = &nr_ike_sa_dkm_bits },
	{ .key = "Child SA DKM length", .op = op_signed_long, .signed_long = &nr_child_sa_dkm_bits },
	{ .key = NULL }
};

static void ikev2_print_config(void)
{
	config_number("g^ir length", g_ir_length);
	config_key(prf_entry->key);
	config_number("Ni length", ni_length);
	config_number("Nr length", nr_length);
	config_number("DKM length", nr_ike_sa_dkm_bits);
	config_number("Child SA DKM length", nr_child_sa_dkm_bits);
}

static long int count;
static chunk_t ni;
static chunk_t nr;
static PK11SymKey *g_ir;
static PK11SymKey *g_ir_new;
static chunk_t spi_i;
static chunk_t spi_r;

static const struct cavp_entry data_entries[] = {
	{ .key = "COUNT", .opt = ACVP_TCID, .op = op_signed_long, .signed_long = &count },
	{ .key = "g^ir", .opt = "gir", .op = op_symkey, .symkey = &g_ir },
	{ .key = "g^ir (new)", .opt = "girNew", .op = op_symkey, .symkey = &g_ir_new },
	{ .key = "Ni", .opt = "nInit", .op = op_chunk, .chunk = &ni },
	{ .key = "Nr", .opt = "nResp", .op = op_chunk, .chunk = &nr },
	{ .key = "SPIi", .opt = "spiInit", .op = op_chunk, .chunk = &spi_i },
	{ .key = "SPIr", .opt = "spiResp", .op = op_chunk, .chunk = &spi_r },
	{ .key = "SKEYSEED", .op = op_ignore },
	{ .key = "DKM", .op = op_ignore },
	{ .key = "DKM(Child SA)", .op = op_ignore },
	{ .key = "DKM(Child SA D-H)", .op = op_ignore },
	{ .key = "SKEYSEED(Rekey)", .op = op_ignore },
	{ .op = NULL }
};

static void ikev2_run_test(void)
{
	print_number("COUNT", ACVP_TCID, count);
	print_chunk("Ni", NULL, ni, 0);
	print_chunk("Nr", NULL, nr, 0);
	print_symkey("g^ir", NULL, g_ir, 0);
	print_symkey("g^ir (new)", NULL, g_ir_new, 0);
	print_chunk("SPIi", NULL, spi_i, 0);
	print_chunk("SPIr", NULL, spi_r, 0);

	if (prf_entry->prf == NULL) {
		fprintf(stderr, "WARNING: ignoring test with PRF %s\n", prf_entry->key);
		print_line(prf_entry->key);
		return;
	}
	cavp_acvp_ikev2(prf_entry->prf, ni, nr,
			g_ir, g_ir_new, spi_i, spi_r,
			nr_ike_sa_dkm_bits / 8,
			(nr_child_sa_dkm_bits > 0
			 ? nr_child_sa_dkm_bits
			 : nr_ike_sa_dkm_bits) / 8);
}

const struct cavp test_ikev2 = {
	.alias = "v2",
	.description = "IKE v2",
	.print_config = ikev2_print_config,
	.run_test = ikev2_run_test,
	.config = config_entries,
	.data = data_entries,
	.match = {
		"IKE v2",
		NULL,
	},
};
