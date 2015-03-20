/*
 * while the rest of this file is covered under the GPL, the following
 * constant values, being inputs and outputs of a mathematical formula
 * are hereby placed in the public domain, including the expression of them
 * in the form of this C code.
 *
 * I.e. please rip off my test data so that the world will be a better place.
 *
 */

struct encrypt_desc *tc2_encrypter = &crypto_encrypter_3des;
#include "../../lib/libpluto/seam_gi.c"

static void perform_t2_test(void)
{
	struct pluto_crypto_req r;
	struct pcr_skeyid_r *skr = &r.pcr_d.dhr;
	struct pcr_skeyid_q *skq = &r.pcr_d.dhq;

	skq->thespace.start = 0;
	skq->thespace.len   = sizeof(skq->space);
	skq->auth = tc2_auth;
	skq->hash = tc2_hash;
	skq->oakley_group = tc2_oakleygroup;
	skq->init = tc2_init;
	skq->keysize = tc2_encrypter->keydeflen / BITS_PER_BYTE;

#define copydatlen(field, data, len) do { \
		chunk_t tchunk;           \
		setchunk(tchunk, data, len); \
		pluto_crypto_copychunk(&skq->thespace, skq->space \
				       , &skq->field, tchunk); }   \
	while (0)

	copydatlen(ni, tc2_ni, tc2_ni_len);
	copydatlen(nr, tc2_nr, tc2_nr_len);
	copydatlen(gi, tc2_gi, tc2_gi_len);
	copydatlen(gr, tc2_gr, tc2_gr_len);
	copydatlen(secret, tc2_secret, tc2_secret_len);
	copydatlen(icookie, tc2_icookie, tc2_icookie_len);
	copydatlen(rcookie, tc2_rcookie, tc2_rcookie_len);

#define dumpdat(field) \
	libreswan_DBG_dump(#field,      \
			   wire_chunk_ptr(skq, &skq->field), \
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

	calc_dh_iv(&r);

	printf("\noutput:\n");

	fflush(stdout);
	fflush(stderr);

	{
		void *shared = wire_chunk_ptr(skr, &skr->shared);

		libreswan_DBG_dump("shared", shared, skr->shared.len);
	}

}
