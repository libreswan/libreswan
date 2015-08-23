/*
 * unit tests for cryptographic helper function - calculate KE and nonce
 *
 * Copyright (C) 2006 Michael C. Richardson <mcr@xelerance.com>
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
 *
 * This code was developed with the support of IXIA communications.
 */

#include "../../../programs/pluto/hmac.c"
#include "../../../programs/pluto/crypto.c"
#include "../../../programs/pluto/ike_alg.c"
#include "../../../programs/pluto/ike_alg_aes.c"
#include "../../../programs/pluto/crypt_utils.c"
#include "../../../programs/pluto/crypt_dh.c"
#include "../../../programs/pluto/ikev2_prfplus.c"

#include "crypto.h"

char *progname;

void exit_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];      /* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	fprintf(stderr, "FATAL ERROR: %s\n", m);
	exit(0);
}

void exit_tool(int code)
{
	exit(code);
}

extern struct encrypt_desc algo_aes;
struct encrypt_desc *tc3_encrypter = &algo_aes;
#include "../../lib/libpluto/seam_gi_sha1.c"

int main(int argc, char *argv[])
{
	struct pluto_crypto_req r;
	struct pcr_skeycalc_v2_r *skr = &r.pcr_d.dhv2;
	struct pcr_skeyid_q    *skq = &r.pcr_d.dhq;
	const char *story = NULL;

	progname = argv[0];
	cur_debugging = DBG_CRYPT;

	/* initialize list of moduli */
	init_crypto();

	INIT_WIRE_ARENA(*skq);

	skq->auth = tc3_auth;
	skq->prf_hash = tc3_hash;
	skq->integ_hash = tc3_hash;
	skq->oakley_group = tc3_oakleygroup;
	skq->init = tc3_init;
	skq->keysize = tc3_encrypter->keydeflen / BITS_PER_BYTE;

#define copydatlen(field, data, len) { \
		chunk_t tchunk;           \
		setchunk(tchunk, data, len); \
		WIRE_CLONE_CHUNK(*skq, field, tchunk); \
	}


	copydatlen(ni, tc3_ni, tc3_ni_len);
	copydatlen(nr, tc3_nr, tc3_nr_len);
	copydatlen(gi, tc3_gi, tc3_gi_len);
	copydatlen(gr, tc3_gr, tc3_gr_len);
	copydatlen(secret, tc3_secret, tc3_secret_len);
	copydatlen(icookie, tc3_icookie, tc3_icookie_len);
	copydatlen(rcookie, tc3_rcookie, tc3_rcookie_len);

#define dumpdat(field) \
	libreswan_DBG_dump(#field,      \
			   WIRE_CHUNK_PTR(*skq, field), \
			   skq->field.len);

	dumpdat(icookie);
	dumpdat(rcookie);
	dumpdat(ni);
	dumpdat(nr);
	dumpdat(gi);
	dumpdat(gr);
	dumpdat(secret);

	fflush(stdout);
	fflush(stderr);

	calc_dh_v2(&r, &story); /* ??? NSS may fail */

	printf("\noutput:\n");

	fflush(stdout);
	fflush(stderr);

#define dumpskr(FOO) { void *FOO = WIRE_CHUNK_PTR(*skr, FOO); \
		       libreswan_DBG_dump(#FOO, FOO, skr->FOO.len); \
}

	dumpskr(shared);
	dumpskr(skeyseed);
	dumpskr(skeyid_d);
	dumpskr(skeyid_ai);
	dumpskr(skeyid_ar);
	dumpskr(skeyid_ei);
	dumpskr(skeyid_er);
	dumpskr(skeyid_pi);
	dumpskr(skeyid_pr);
	exit(0);
}
