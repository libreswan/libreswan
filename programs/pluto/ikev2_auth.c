/* IKEv2 Authentication, for libreswan
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "crypt_hash.h"

#include "defs.h"
#include "ikev2_auth.h"
#include "state.h"
#include "log.h"
#include "connections.h"

struct crypt_mac v2_calculate_sighash(const struct state *st,
				      enum original_role role,
				      const struct crypt_mac *idhash,
				      const chunk_t firstpacket,
				      const struct hash_desc *hasher)
{
	const chunk_t *nonce;
	const char *nonce_name;

	if (role == ORIGINAL_INITIATOR) {
		/* on initiator, we need to hash responders nonce */
		nonce = &st->st_nr;
		nonce_name = "inputs to hash2 (responder nonce)";
	} else {
		nonce = &st->st_ni;
		nonce_name = "inputs to hash2 (initiator nonce)";
	}

	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("inputs to hash1 (first packet)", firstpacket);
		DBG_dump_hunk(nonce_name, *nonce);
		DBG_dump_hunk("idhash", *idhash);
	}

	struct crypt_hash *ctx = crypt_hash_init("sighash", hasher);
	crypt_hash_digest_hunk(ctx, "first packet", firstpacket);
	crypt_hash_digest_hunk(ctx, "nonce", *nonce);
	/* we took the PRF(SK_d,ID[ir]'), so length is prf hash length */
	passert(idhash->len == st->st_oakley.ta_prf->prf_output_size);
	crypt_hash_digest_hunk(ctx, "IDHASH", *idhash);
	return crypt_hash_final_mac(&ctx);
}

enum keyword_authby v2_auth_by(struct ike_sa *ike)
{
	const struct connection *c = ike->sa.st_connection;
	enum keyword_authby authby = c->spd.this.authby;
	if (ike->sa.st_peer_wants_null) {
		/* we allow authby=null and IDr payload told us to use it */
		authby = AUTH_NULL;
	} else if (authby == AUTH_UNSET) {
		/*
		 * Asymmetric policy unset.
		 * Pick up from symmetric policy, in order of preference!
		 */
		if ((c->policy & POLICY_ECDSA) && (c->sighash_policy != LEMPTY)) {
			authby = AUTH_ECDSA;
		} else if (c->policy & POLICY_RSASIG) {
			authby = AUTH_RSASIG;
		} else if (c->policy & POLICY_PSK) {
			authby = AUTH_PSK;
		} else if (c->policy & POLICY_AUTH_NULL) {
			authby = AUTH_NULL;
		} else {
			/* leave authby == AUTH_UNSET */
			/* ??? we will surely crash with bad_case */
		}
	}
	return authby;
}

enum ikev2_auth_method v2_auth_method(struct ike_sa *ike, enum keyword_authby authby)
{
	struct connection *c = ike->sa.st_connection;
	enum ikev2_auth_method auth_method;
	switch (authby) {
	case AUTH_RSASIG:
	{
		bool allow_legacy = LIN(POLICY_RSASIG_v1_5, c->policy);

		if (!ike->sa.st_seen_hashnotify) {
			if (allow_legacy) {
				auth_method = IKEv2_AUTH_RSA;
			} else {
				loglog(RC_LOG_SERIOUS, "legacy RSA-SHA1 is not allowed but peer supports nothing else");
				auth_method = IKEv2_AUTH_RESERVED;
			}
		} else {
			if (c->sighash_policy != LEMPTY) {
				auth_method = IKEv2_AUTH_DIGSIG;
			} else {
				if (allow_legacy) {
					auth_method = IKEv2_AUTH_RSA;
				} else {
					loglog(RC_LOG_SERIOUS, "Local policy does not allow legacy RSA-SHA1 but connection allows no other hash policy");
					auth_method = IKEv2_AUTH_RESERVED;

				}
			}
		}
		break;
	}
	case AUTH_ECDSA:
		auth_method = IKEv2_AUTH_DIGSIG;
		break;
	case AUTH_PSK:
		auth_method = IKEv2_AUTH_PSK;
		break;
	case AUTH_NULL:
		auth_method = IKEv2_AUTH_NULL;
		break;
	case AUTH_NEVER:
	default:
		bad_case(authby);
	}
	return auth_method;
}

const struct hash_desc *v2_auth_hash_desc(enum notify_payload_hash_algorithms hash_algo)
{
       const struct hash_desc *hd;
       switch (hash_algo) {
#ifdef USE_SHA1
       case IKEv2_AUTH_HASH_SHA1:
               hd = &ike_alg_hash_sha1;
               break;
#endif
#ifdef USE_SHA2
       case IKEv2_AUTH_HASH_SHA2_256:
               hd = &ike_alg_hash_sha2_256;
               break;
       case IKEv2_AUTH_HASH_SHA2_384:
               hd = &ike_alg_hash_sha2_384;
               break;
       case IKEv2_AUTH_HASH_SHA2_512:
               hd = &ike_alg_hash_sha2_512;
               break;
#endif
       default:
               return NULL;
       }
return hd;
}
