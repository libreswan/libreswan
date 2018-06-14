/* CAVP algorithm, for libreswan
 *
 * Copyright (C) 2018, Andrew Cagney
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

#include <string.h>

#include "acvp.h"

#include "cavp_ikev2.h"

#include "ike_alg_sha1.h"
#include "ike_alg_sha2.h"

#include "test_buffer.h"
#include "crypt_symkey.h"

struct acvp_prf {
	const char *name;
	const struct prf_desc *prf;
};

static const struct acvp_prf acvp_prfs[] = {
	{ "2", &ike_alg_prf_sha1, },
	{ "5", &ike_alg_prf_sha2_256, },
	{ "6", &ike_alg_prf_sha2_384, },
	{ "7", &ike_alg_prf_sha2_512, },
	{ .prf = NULL, },
};

void acvp(struct acvp *p)
{
	const struct prf_desc *prf = NULL;
	for (const struct acvp_prf *acvp_prf = acvp_prfs;
	     acvp_prf->prf != NULL; acvp_prf++) {
		if (strcmp(acvp_prf->name, p->prf) == 0) {
			prf = acvp_prf->prf;
			break;
		}
	}
	chunk_t ni = decode_hex_to_chunk("ni", p->ni);
	chunk_t nr = decode_hex_to_chunk("nr", p->nr);
	PK11SymKey *g_ir = decode_hex_to_symkey("g^ir", p->g_ir);
	PK11SymKey *g_ir_new = decode_hex_to_symkey("g^ir(new)", p->g_ir_new);
	chunk_t spi_i = decode_hex_to_chunk("SPI I", p->spi_i);
	chunk_t spi_r = decode_hex_to_chunk("SPI R", p->spi_r);
	signed long nr_dkm_bytes = strtol(p->dkm_length, NULL, 10);
	cavp_acvp_ikev2(prf, ni, nr, g_ir, g_ir_new, spi_i, spi_r,
			nr_dkm_bytes, nr_dkm_bytes);
}
