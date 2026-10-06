/* Authentication, for libreswan
 *
 * Copyright (C) 2022,2026 Andrew Cagney <cagney@gnu.org>
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

#include "authby.h"
#include "auth.h"

#include "ike_alg.h"
#include "ike_alg_hash.h"

#include "constants.h"		/* for enum keyword_auth */
#include "jambuf.h"
#include "lswlog.h"		/* for bad_case() */
#include "flags.h"

bool authby_is_set(struct authby authby)
{
	return authby_count(authby) > 0;
}

unsigned authby_count(struct authby authby)
{
	return flags_count(authby, authby);
}

struct authby authby_not(struct authby lhs)
{
	return flags_not(authby, lhs);
}

struct authby authby_and(struct authby lhs, struct authby rhs)
{
	return flags_and(authby, lhs, rhs);
}

struct authby authby_or(struct authby lhs, struct authby rhs)
{
	return flags_or(authby, lhs, rhs);
}

bool authby_eq(struct authby lhs, struct authby rhs)
{
	return flags_eq(authby, lhs, rhs);
}

bool authby_has_all(struct authby authby, struct authby all)
{
	return flags_has_all(authby, authby, all);
}

bool authby_has_any(struct authby authby, struct authby any)
{
	return flags_has_any(authby, authby, any);
}

bool authby_has_none(struct authby authby, struct authby none)
{
	return flags_has_none(authby, authby, none);
}

struct authby authby_and_hash(struct authby authby,
			      const struct hash_desc *hash)
{
	if (hash == &ike_alg_hash_sha1) {
		/* sha1 is only allowed with rsasig_v1.5 */
		return (struct authby) {
			.authby_rsasig_v1_5_sha1 = authby.authby_rsasig_v1_5_sha1,
		};
	}
	/*
	 * Allow PKCS#1 RSA v1.5 with SHA2; even though it doesn't
	 * have an explicit bit.
	 */
#define AND_HASH(HASH)						\
	if (hash == &ike_alg_hash_##HASH) {			\
		return (struct authby) {			\
			.authby_rsasig_v1_5_##HASH = authby.authby_rsasig_v1_5_##HASH, \
			.authby_rsasig_##HASH = authby.authby_rsasig_##HASH,	\
			.authby_ecdsa_##HASH = authby.authby_ecdsa_##HASH,	\
		};						\
	}
	AND_HASH(sha2_256);
	AND_HASH(sha2_384);
	AND_HASH(sha2_512);
#undef AND_HASH
	if (hash == &ike_alg_hash_identity) {
		/* only allow algs that don't need a hash */
		return (struct authby) {
			.authby_eddsa = authby.authby_eddsa,
		};
	}
	return (struct authby) {0};
}

bool authby_has_hash(struct authby authby,
		     const struct hash_desc *hash)
{
	return authby_is_set(authby_and_hash(authby, hash));
}

struct authby authby_and_auth(struct authby authby, enum auth auth)
{
	return flags_and_flag(authby, authby, auth);
}

struct authby authby_or_auth(struct authby authby, enum auth auth)
{
	return flags_or_flag(authby, authby, auth);
}

bool authby_has_auth(struct authby authby, enum auth auth)
{
	return flags_has_flag(authby, authby, auth);
}

struct authby authby_from_auth(enum auth auth)
{
	return flags_from_flag(authby, auth);
}

static size_t jam_authby_raw(struct jambuf *buf,
			     struct authby authby,
			     bool human)
{
	size_t s = 0;
	const char *sep = "";
#define JAM_STRING(N,H)					\
	{						\
		s += jam_string(buf, sep);		\
		s += jam_string(buf, (human ? #H : #N)); \
		sep = "+";				\
	}
#define JAM_AUTHBY(F, N, H)				\
	{						\
		if (authby.F) {				\
			JAM_STRING(N, H);		\
		}					\
	}
	JAM_AUTHBY(authby_psk, PSK, secret);
	if (authby_has_all(authby, (struct authby) {
				AUTHBY_RSASIG_RAW,
				AUTHBY_RSASIG_V1_5,
				AUTHBY_RSASIG_SHA2,
			})) {
		/* legacy */
		JAM_STRING(RSASIG, rsasig);
	} else if (authby_has_all(authby, (struct authby) {
				AUTHBY_RSASIG_RAW,
			}) &&
		!authby_has_any(authby, (struct authby) {
				AUTHBY_RSASIG_V1_5,
				AUTHBY_RSASIG_SHA2,
			})) {
		/* IKEv1 */
		JAM_STRING(RSASIG, rsasig);
	} else if (authby_has_all(authby, (struct authby) {
				AUTHBY_RSASIG_V1_5,
				AUTHBY_RSASIG_SHA2,
			}) &&
		!authby_has_all(authby, (struct authby) {
				AUTHBY_RSASIG_RAW,
			})) {
		/* IKEv2 */
		JAM_STRING(RSASIG, rsasig);
	} else {
		JAM_AUTHBY(authby_rsasig_raw, RSASIG, rsasig);
		if (authby_has_all(authby, (struct authby) {
					AUTHBY_RSASIG_SHA2,
				})) {
			JAM_STRING(RSASIG_SHA2, rsa-sha2);
		} else {
			JAM_AUTHBY(authby_rsasig_sha2_256, RSASIG_SHA2_256, rsa-sha2_256);
			JAM_AUTHBY(authby_rsasig_sha2_384, RSASIG_SHA2_384, rsa-sha2_384);
			JAM_AUTHBY(authby_rsasig_sha2_512, RSASIG_SHA2_512, rsa-sha2_512);
		}
		if (authby_has_all(authby, (struct authby) {
					AUTHBY_RSASIG_V1_5,
				})) {
			JAM_STRING(RSASIG_v1_5, rsa-v15);
		} else {
			JAM_AUTHBY(authby_rsasig_v1_5_sha1, RSASIG_v1_5_SHA1, rsa-sha1);
			JAM_AUTHBY(authby_rsasig_v1_5_sha2_256, RSASIG_V1_5_SHA2_256, rsa-v15-sha2_256);
			JAM_AUTHBY(authby_rsasig_v1_5_sha2_384, RSASIG_V1_5_SHA2_384, rsa-v15-sha2_384);
			JAM_AUTHBY(authby_rsasig_v1_5_sha2_512, RSASIG_V1_5_SHA2_512, rsa-v15-sha2_512);
		}
	}
	/*
	 * When AUTHBY has all the ECDSA_SHA2 bits set, use the the
	 * short-hand ECDSA.  This matches auth=ecdsa which will set
	 * all the bits below.
	 */
	if (authby_has_all(authby, (struct authby) {
				AUTHBY_ECDSA_SHA2,
			})) {
		JAM_STRING(ECDSA, ecdsa);
	} else {
		JAM_AUTHBY(authby_ecdsa_sha2_256, ECDSA_SHA2_256, ecdsa-sha2_256);
		JAM_AUTHBY(authby_ecdsa_sha2_384, ECDSA_SHA2_384, ecdsa-sha2_384);
		JAM_AUTHBY(authby_ecdsa_sha2_512, ECDSA_SHA2_512, ecdsa-sha2_512);
	}
	JAM_AUTHBY(authby_eddsa, EDDSA, eddsa);
	JAM_AUTHBY(authby_never, AUTH_NEVER, never);
	JAM_AUTHBY(authby_null, AUTH_NULL, null);
	JAM_AUTHBY(authby_eaponly, EAPONLY, eaponly);
#undef JAM_STRING
#undef JAM_AUTHBY
	if (s == 0) {
		s += jam_string(buf, "none");
	}
	return s;
}

size_t jam_authby(struct jambuf *buf, struct authby authby)
{
	return jam_authby_raw(buf, authby, /*human*/false);
}

size_t jam_authby_auth(struct jambuf *buf, struct authby authby)
{
	return jam_authby_raw(buf, authby, /*human*/true);
}

const char *str_authby(struct authby authby, authby_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_authby(&jambuf, authby);
	return buf->buf;
}

const char *str_authby_auth(struct authby authby, authby_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_authby_auth(&jambuf, authby);
	return buf->buf;
}

void jam_authby_sighash_policy(struct jambuf *buf, struct authby authby)
{
	const char *sep = NULL;
	for (const struct hash_desc **hashp = next_hash_desc(NULL);
	     hashp != NULL;
	     hashp = next_hash_desc(hashp)) {
		const struct hash_desc *hash = (*hashp);

		if (!authby_has_hash(authby, hash)) {
			continue;
		}

		if (sep != NULL) {
			jam_string(buf, sep);
		}
		sep = "+";
		jam_string(buf, hash->common.fqn);
	}
	if (sep == NULL) {
		jam_string(buf, "none");
	}
}

struct authby authby_v2AUTH_digsig_payload(void)
{
	return (struct authby) {
#ifdef USE_EDDSA
		AUTHBY_EDDSA,
#endif
		AUTHBY_RSASIG_V1_5,
		AUTHBY_RSASIG_SHA2,
		AUTHBY_ECDSA_SHA2,
	};
}

bool authby_has_v2AUTH_digsig_payload(struct authby authby)
{
	return authby_has_any(authby, authby_v2AUTH_digsig_payload());
}

struct authby authby_v2AUTH_pubkey(void)
{
	return (struct authby) {
#ifdef USE_EDDSA
		AUTHBY_EDDSA,
#endif
		AUTHBY_RSASIG_V1_5,
		AUTHBY_RSASIG_SHA2,
		AUTHBY_ECDSA_SHA2,
	};
}

bool authby_has_v2AUTH_pubkey(struct authby authby)
{
	return authby_has_any(authby, authby_v2AUTH_pubkey());
}
