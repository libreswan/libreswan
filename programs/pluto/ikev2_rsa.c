/* do RSA operations for IKEv2
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "server.h"
#include "vendor.h"
#include "keys.h"
#include "secrets.h"
#include "ike_alg_sha1.h"
#include "crypt_hash.h"

static u_char der_digestinfo[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};
static int der_digestinfo_len = sizeof(der_digestinfo);

static void ikev2_calculate_sighash(struct state *st,
				    enum original_role role,
				    unsigned char *idhash,
				    chunk_t firstpacket,
				    unsigned char *sig_octets)
{
	const chunk_t *nonce;
	const char    *nonce_name;

	if (role == ORIGINAL_INITIATOR) {
		/* on initiator, we need to hash responders nonce */
		nonce = &st->st_nr;
		nonce_name = "inputs to hash2 (responder nonce)";
	} else {
		nonce = &st->st_ni;
		nonce_name = "inputs to hash2 (initiator nonce)";
	}

	DBG(DBG_CRYPT,
	    DBG_dump_chunk("inputs to hash1 (first packet)", firstpacket);
	    DBG_dump_chunk(nonce_name, *nonce);
	    DBG_dump("idhash", idhash, st->st_oakley.ta_prf->prf_output_size));

	struct crypt_hash *ctx = crypt_hash_init(&ike_alg_hash_sha1,
						 "sighash", DBG_CRYPT);
	crypt_hash_digest_chunk(ctx, "first packet", firstpacket);
	crypt_hash_digest_chunk(ctx, "nunce", *nonce);

	/* we took the PRF(SK_d,ID[ir]'), so length is prf hash length */
	crypt_hash_digest_bytes(ctx, "IDHASH", idhash,
				st->st_oakley.ta_prf->prf_output_size);
	crypt_hash_final_bytes(&ctx, sig_octets,
			       ike_alg_hash_sha1.hash_digest_len);
}

bool ikev2_calculate_rsa_sha1(struct state *st,
			      enum original_role role,
			      unsigned char *idhash,
			      pb_stream *a_pbs,
			      bool calc_no_ppk_auth,
			      chunk_t *no_ppk_auth)
{
	unsigned char signed_octets[SHA1_DIGEST_SIZE + 16];
	size_t signed_len;
	const struct connection *c = st->st_connection;
	const struct RSA_private_key *k = get_RSA_private_key(c);
	unsigned int sz;

	if (k == NULL)
		return FALSE; /* failure: no key to use */

	sz = k->pub.k;

	memcpy(signed_octets, der_digestinfo, der_digestinfo_len);

	ikev2_calculate_sighash(st, role, idhash,
				st->st_firstpacket_me,
				signed_octets + der_digestinfo_len);
	signed_len = der_digestinfo_len + SHA1_DIGEST_SIZE;

	passert(RSA_MIN_OCTETS <= sz && 4 + signed_len < sz &&
		sz <= RSA_MAX_OCTETS);

	DBG(DBG_CRYPT,
	    DBG_dump("v2rsa octets", signed_octets, signed_len));

	{
		/* now generate signature blob */
		u_char sig_val[RSA_MAX_OCTETS];
		int shr;

		shr = sign_hash(k, signed_octets, signed_len, sig_val, sz);
		if (shr == 0)
			return FALSE;
		passert(shr == (int)sz);
		if (calc_no_ppk_auth == FALSE) {
			if (!out_raw(sig_val, sz, a_pbs, "rsa signature"))
				return FALSE;
		} else {
			clonetochunk(*no_ppk_auth, sig_val, sz, "NO_PPK_AUTH chunk");
			DBG(DBG_PRIVATE, DBG_dump_chunk("NO_PPK_AUTH payload", *no_ppk_auth));
		}
	}

	return TRUE;
}

static err_t try_RSA_signature_v2(const u_char hash_val[MAX_DIGEST_LEN],
				  size_t hash_len,
				  const pb_stream *sig_pbs, struct pubkey *kr,
				  struct state *st)
{
	const u_char *sig_val = sig_pbs->cur;
	size_t sig_len = pbs_left(sig_pbs);
	const struct RSA_public_key *k = &kr->u.rsa;

	if (k == NULL)
		return "1" "no key available"; /* failure: no key to use */

	/* decrypt the signature -- reversing RSA_sign_hash */
	if (sig_len != k->k)
		return "1" "SIG length does not match public key length";

	err_t ugh = RSA_signature_verify_nss(k, hash_val, hash_len, sig_val,
					     sig_len);
	if (ugh != NULL)
		return ugh;

	unreference_key(&st->st_peer_pubkey);
	st->st_peer_pubkey = reference_key(kr);

	return NULL;
}

stf_status ikev2_verify_rsa_sha1(struct state *st,
				 enum original_role role,
				 unsigned char *idhash,
				 pb_stream *sig_pbs)
{
	unsigned char calc_hash[SHA1_DIGEST_SIZE];
	unsigned int hash_len = SHA1_DIGEST_SIZE;
	enum original_role invertrole;

	invertrole = (role == ORIGINAL_INITIATOR ? ORIGINAL_RESPONDER : ORIGINAL_INITIATOR);

	ikev2_calculate_sighash(st, invertrole, idhash, st->st_firstpacket_him,
				calc_hash);

	return RSA_check_signature_gen(st, calc_hash, hash_len,
				       sig_pbs, try_RSA_signature_v2);

}
