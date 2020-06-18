/* do PSK operations for IKEv2
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2015 Antony Antony <antony@phenome.org>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
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
#include "crypt_prf.h"
#include "crypt_symkey.h"
#include "lswfips.h"
#include "ikev2_prf.h"
#include <nss.h>
#include <pk11pub.h>

static struct crypt_mac ikev2_calculate_psk_sighash(bool verify,
						    const struct ike_sa *ike,
						    enum keyword_authby authby,
						    const struct crypt_mac *idhash,
						    const chunk_t firstpacket)
{
	const struct connection *c = ike->sa.st_connection;
	passert(authby == AUTHBY_PSK || authby == AUTHBY_NULL);

	dbg("ikev2_calculate_psk_sighash() called from %s to %s PSK with authby=%s",
	    ike->sa.st_state->name,
	    verify ? "verify" : "create",
	    enum_name(&keyword_authby_names, authby));

	/* pick nullauth_pss, nonce, and nonce_name suitable for (state, verify) */

	const chunk_t *nonce;
	const char *nonce_name;
	const chunk_t *nullauth_pss;

	switch (ike->sa.st_state->kind) {
	case STATE_PARENT_I2:
		if (!verify) {
			/* we are initiator sending PSK */
			nullauth_pss = &ike->sa.st_skey_chunk_SK_pi;
			nonce = &ike->sa.st_nr;
			nonce_name = "create: initiator inputs to hash2 (responder nonce)";
			break;
		}
		/* we are initiator verifying PSK */
		passert(verify);
		nullauth_pss = &ike->sa.st_skey_chunk_SK_pr;
		nonce = &ike->sa.st_ni;
		nonce_name = "verify: initiator inputs to hash2 (initiator nonce)";
		break;

	case STATE_PARENT_R1:
		/* we are responder verifying PSK */
		passert(verify);
		nullauth_pss = &ike->sa.st_skey_chunk_SK_pi;
		nonce = &ike->sa.st_nr;
		nonce_name = "verify: initiator inputs to hash2 (responder nonce)";
		break;

	case STATE_V2_ESTABLISHED_IKE_SA:
		/*
		 * Presumably the IKE SA's state was changed before
		 * the transition completed.
		 */
		if (verify) {
			/* we are initiator verifying PSK */
			passert(verify);
			nullauth_pss = &ike->sa.st_skey_chunk_SK_pr;
			nonce = &ike->sa.st_ni;
			nonce_name = "verify: initiator inputs to hash2 (initiator nonce)";
		} else {
			/* we are responder sending PSK */
			passert(!verify);
			nullauth_pss = &ike->sa.st_skey_chunk_SK_pr;
			nonce = &ike->sa.st_ni;
			nonce_name = "create: responder inputs to hash2 (initiator nonce)";
		}
		break;

	default:
		bad_case(ike->sa.st_state->kind);
	}

	/* pick pss */

	const chunk_t *pss;

	if (authby != AUTHBY_NULL) {
		pss = get_psk(c, ike->sa.st_logger);
		if (pss == NULL) {
			loglog(RC_LOG_SERIOUS,"No matching PSK found for connection: %s",
			      ike->sa.st_connection->name);
			return empty_mac;
		}
		DBG(DBG_PRIVATE, DBG_dump_hunk("User PSK:", *pss));
		const size_t key_size_min = crypt_prf_fips_key_size_min(ike->sa.st_oakley.ta_prf);
		if (pss->len < key_size_min) {
			if (libreswan_fipsmode()) {
				loglog(RC_LOG_SERIOUS,
				       "FIPS: connection %s PSK length of %zu bytes is too short for %s PRF in FIPS mode (%zu bytes required)",
				       ike->sa.st_connection->name,
				       pss->len,
				       ike->sa.st_oakley.ta_prf->common.fqn,
				       key_size_min);
				return empty_mac;
			} else {
				libreswan_log("WARNING: connection %s PSK length of %zu bytes is too short for %s PRF in FIPS mode (%zu bytes required)",
					      ike->sa.st_connection->name,
					      pss->len,
					      ike->sa.st_oakley.ta_prf->common.fqn,
					      key_size_min);
			}
		}
	} else {
		/*
		 * RFC-7619
		 *
		 * When using the NULL Authentication Method, the
		 * content of the AUTH payload is computed using the
		 * syntax of pre-shared secret authentication,
		 * described in Section 2.15 of [RFC7296].  The values
		 * SK_pi and SK_pr are used as shared secrets for the
		 * content of the AUTH payloads generated by the
		 * initiator and the responder respectively.
		 *
		 * We have SK_pi/SK_pr as PK11SymKey in st_skey_pi_nss
		 * and st_skey_pr_nss
		 */
		passert(ike->sa.hidden_variables.st_skeyid_calculated);

		pss = nullauth_pss;
		DBG(DBG_PRIVATE, DBG_dump_hunk("AUTH_NULL PSK:", *pss));
	}

	passert(pss->len != 0);

	DBG(DBG_CRYPT,
	    DBG_dump_hunk("inputs to hash1 (first packet)", firstpacket);
	    DBG_dump_hunk(nonce_name, *nonce);
	    DBG_dump_hunk("idhash", *idhash));

	/*
	 * RFC 4306 2.15:
	 * AUTH = prf(prf(Shared Secret, "Key Pad for IKEv2"), <msg octets>)
	 */
	passert(idhash->len == ike->sa.st_oakley.ta_prf->prf_output_size);
	return ikev2_psk_auth(ike->sa.st_oakley.ta_prf, *pss, firstpacket, *nonce, idhash);
}

bool ikev2_emit_psk_auth(enum keyword_authby authby,
			 const struct ike_sa *ike,
			 const struct crypt_mac *idhash,
			 pb_stream *a_pbs)
{
	struct crypt_mac signed_octets = ikev2_calculate_psk_sighash(FALSE, ike, authby, idhash,
								     ike->sa.st_firstpacket_me);
	if (signed_octets.len == 0) {
		return false;
	}

	DBG(DBG_CRYPT,
	    DBG_dump_hunk("PSK auth octets", signed_octets));

	bool ok = pbs_out_hunk(signed_octets, a_pbs, "PSK auth");
	return ok;
}

bool ikev2_create_psk_auth(enum keyword_authby authby,
			   const struct ike_sa *ike,
			   const struct crypt_mac *idhash,
			   chunk_t *additional_auth /* output */)
{
	*additional_auth = empty_chunk;
	struct crypt_mac signed_octets = ikev2_calculate_psk_sighash(FALSE, ike, authby, idhash,
								     ike->sa.st_firstpacket_me);
	if (signed_octets.len == 0) {
		return false;
	}

	const char *chunk_n = (authby == AUTHBY_PSK) ? "NO_PPK_AUTH chunk" : "NULL_AUTH chunk";
	*additional_auth = clone_hunk(signed_octets, chunk_n);
	DBG(DBG_CRYPT, DBG_dump_hunk(chunk_n, *additional_auth));

	return true;
}

bool ikev2_verify_psk_auth(enum keyword_authby authby,
			   const struct ike_sa *ike,
			   const struct crypt_mac *idhash,
			   pb_stream *sig_pbs)
{
	size_t hash_len = ike->sa.st_oakley.ta_prf->prf_output_size;
	shunk_t sig = pbs_in_left_as_shunk(sig_pbs);

	passert(authby == AUTHBY_PSK || authby == AUTHBY_NULL);

	if (sig.len != hash_len) {
		log_state(RC_LOG, &ike->sa,
			  "hash length in I2 packet (%zu) does not equal hash length (%zu) of negotiated PRF (%s)",
			  sig.len, hash_len, ike->sa.st_oakley.ta_prf->common.fqn);
		return false;
	}

	struct crypt_mac calc_hash = ikev2_calculate_psk_sighash(TRUE, ike, authby, idhash,
								 ike->sa.st_firstpacket_peer);
	if (calc_hash.len == 0) {
		return false;
	}

	DBG(DBG_CRYPT,
	    DBG_dump_hunk("Received PSK auth octets", sig);
	    DBG_dump_hunk("Calculated PSK auth octets", calc_hash));
	bool ok = hunk_eq(sig, calc_hash);
	if (ok) {
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "authenticated using authby=%s",
			  enum_name(&keyword_authby_names, authby));
		return true;
	} else {
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "AUTH mismatch: Received AUTH != computed AUTH");
		return false;
	}
}
