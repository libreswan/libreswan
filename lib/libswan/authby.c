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
		return authby_and(authby, (struct authby) {
				AUTHBY_RSASIG_V1_5_SHA1,
			});
	}
	/*
	 * Allow PKCS#1 RSA v1.5 with SHA2; even though it doesn't
	 * have an explicit bit.
	 */
#define AND_HASH(Hash, HASH)					\
	if (hash == &ike_alg_hash_##Hash) {			\
		return authby_and(authby, (struct authby) {	\
				AUTHBY_RSASIG_V1_5_##HASH,	\
				AUTHBY_RSASIG_##HASH,/*PSS*/	\
				AUTHBY_ECDSA_##HASH,		\
			});					\
	}
	AND_HASH(sha2_256, SHA2_256);
	AND_HASH(sha2_384, SHA2_384);
	AND_HASH(sha2_512, SHA2_512);
#undef AND_HASH
	if (hash == &ike_alg_hash_identity) {
		/* only allow algs that don't need a hash */
		return authby_and(authby, (struct authby) {
				AUTHBY_EDDSA,
			});
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

struct authby authby_add(struct authby authby, enum auth auth)
{
	return flags_or_flag(authby, authby, auth);
}

bool authby_has(struct authby authby, enum auth auth)
{
	return flags_has_flag(authby, authby, auth);
}

struct authby authby_from_auth(enum auth auth)
{
	return flags_from_flag(authby, auth);
}

/*
 * Map names to authby bits.
 *
 * Note: order matters, for instance:
 *
 * - it decides the order that things are shown in POLICY, hence PSK
 *   is first
 *
 * - broader bitsets come first, so they are prefered.
 *
 * - Kind of assumes IKEv2, for instance IKEv1 "rsa" is handled
 *   separately.
 */
static const struct authby_name {
	const char *policy;
	const char *human;
	struct authby authby;
} authby_names[] = {

	{ "PSK", "secret", { AUTHBY_PSK, }, },

	/*
	 * RSASIG
	 */

	{ "RSASIG", "rsasig", {
			AUTHBY_RSASIG_IKEv2,
		},
	},
	{ "RSASIG_SHA2", "rsa-sha2", {
			AUTHBY_RSASIG_SHA2,
		},
	},
	{ "RSASIG_v1_5", "rsa-v15", {
			AUTHBY_RSASIG_V1_5,
		},
	},
	{ "RSASIG_v1_5_SHA1", "rsa-sha1", {
			AUTHBY_RSASIG_V1_5_SHA1,
		},
	},

	{ "RSASIG_SHA2_256", "rsa-sha2_256", { .authby_rsasig_sha2_256 = true, }, },
	{ "RSASIG_SHA2_384", "rsa-sha2_384", { .authby_rsasig_sha2_384 = true, }, },
	{ "RSASIG_SHA2_512", "rsa-sha2_512", { .authby_rsasig_sha2_512 = true, }, },
	{ "RSASIG_v1_5_SHA1_RAW", "rsa-sha1-raw", { .authby_rsasig_v1_5_sha1_raw = true, }, },
	{ "RSASIG_v1_5_SHA1_BLOB", "rsa-sha1-blob", { .authby_rsasig_v1_5_sha1_blob = true, }, },
	{ "RSASIG_V1_5_SHA2_256", "rsa-v15-sha2_256", { .authby_rsasig_v1_5_sha2_256 = true, }, },
	{ "RSASIG_V1_5_SHA2_384", "rsa-v15-sha2_384", { .authby_rsasig_v1_5_sha2_384 = true, }, },
	{ "RSASIG_V1_5_SHA2_512", "rsa-v15-sha2_512", { .authby_rsasig_v1_5_sha2_512 = true, }, },

	/*
	 * ECDSA
	 *
	 * When AUTHBY has all the ECDSA_SHA2 bits set, use the the
	 * short-hand ECDSA.  This matches auth=ecdsa which will set
	 * all the bits below.
	 */

	{ "ECDSA", "ecdsa", {
			AUTHBY_ECDSA,
		},
	},

	{ "ECDSA_SHA2_256", "ecdsa-sha2_256", { AUTHBY_ECDSA_SHA2_256, }, },
	{ "ECDSA_SHA2_384", "ecdsa-sha2_384", { AUTHBY_ECDSA_SHA2_384, }, },
	{ "ECDSA_SHA2_512", "ecdsa-sha2_512", { AUTHBY_ECDSA_SHA2_512, }, },

	/*
	 * EDDSA
	 */

	{ "EDDSA", "eddsa", { AUTHBY_EDDSA, }, },

	/* stragglers */

	{ "AUTH_NEVER", "never", { AUTHBY_NEVER, }, },
	{ "AUTH_NULL", "null", { AUTHBY_NULL, }, },
	{ "EAPONLY", "eaponly", { AUTHBY_EAPONLY, }, },

};

bool tto_ikev2_authby(shunk_t input, struct authby *authby)
{
	zero(authby);

	/*
	 * Keep these out of the name->authby table, so that when
	 * showing "digsig" it appears as the individual auth methods.
	 */
	if (hunk_strheq(input, "digsig") ||
	    hunk_strheq(input, "pubkey")) {
		*authby = authby_v2AUTH_pubkey();
		return true;
	}

	/*
	 * Some aliases.
	 */
	static const struct {
		const char *human;
		struct authby authby;
	} aliases[] = {
		{ "rsa", {
				AUTHBY_RSASIG_V1_5,
				AUTHBY_RSASIG_SHA2,
			},
		},
		{ "ecdsa-sha2", {
				AUTHBY_ECDSA,
			},
		},
		{ "psk", {
				AUTHBY_PSK,
			},
		},
	};
	FOR_EACH_ELEMENT(alias, aliases) {
		if (hunk_strheq(input, alias->human)) {
			*authby = alias->authby;
			return true;
		}
	}

	FOR_EACH_ELEMENT(name, authby_names) {
		if (hunk_strheq(input, name->human)) {
			*authby = name->authby;
			return true;
		}
	}

	return false;
}

void jam_authbys_auth(struct jambuf *buf)
{
	jam_string(buf, "\"digsig\"");

	struct authby jamed_authbys = {0};
	const struct authby_name *name = NULL;
	for (unsigned u = 0; u < elemsof(authby_names); u++) {
		/*
		 * Skip name when a super set has already been shown.
		 */
		if (authby_has_all(jamed_authbys, authby_names[u].authby)) {
			continue;
		}
		/* show the previous */
		if (name != NULL) {
			jam_string(buf, ", ");
			jam_string(buf, "\"");
			jam_string(buf, name->human);
			jam_string(buf, "\"");
		}
		/* save next */
		name = &authby_names[u];
		jamed_authbys = authby_or(jamed_authbys, name->authby);
	}

	if (name != NULL) {
		jam_string(buf, ", and ");
		jam_string(buf, "\"");
		jam_string(buf, name->human);
		jam_string(buf, "\"");
	}
}

static size_t jam_authby_raw(struct jambuf *buf,
			     struct authby authby,
			     bool human)
{
	size_t s = 0;
	const char *sep = "";
#define JAM_AUTHBY(N, H, ...)						\
	{								\
		const struct authby f_ = { __VA_ARGS__ };		\
		if (authby_has_all(authby, f_)) {			\
			s += jam_string(buf, sep);			\
			sep = "+";					\
			s += jam_string(buf, (human ? #H : #N));	\
			authby = authby_and(authby, authby_not(f_));	\
		}							\
	}

	/*
	 * Pure IKEv1.
	 *
	 * Keep this out of the table so string->authby can't see it.
	 */
	JAM_AUTHBY(RSASIG, rsasig, AUTHBY_RSASIG_IKEv1);

	/*
	 * scan table printing and scrubbing each bit as it matches.
	 */
	FOR_EACH_ELEMENT(name, authby_names) {
		if (authby_has_all(authby, name->authby)) {
			/* those bits are done with */
			authby = authby_and(authby, authby_not(name->authby));
			s += jam_string(buf, sep);
			sep ="+";
			s += jam_string(buf, (human ? name->human : name->policy));
		}
	}

	/*
	 * Now dump what was missed.
	 */
	for (enum auth auth = AUTH_FLOOR; auth < AUTH_ROOF; auth++) {
		if (authby.authby[auth]) {
			s += jam_string(buf, sep);
			sep = "+";
			if (human) {
				jam_name_human(buf, &auth_names, auth);
			} else {
				jam_name_short(buf, &auth_names, auth);
			}
		}
	}
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
		AUTHBY_RSASIG_V1_5_SHA1_BLOB,
		AUTHBY_RSASIG_SHA2,
		AUTHBY_ECDSA_BLOB,
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
		AUTHBY_ECDSA,
	};
}

bool authby_has_v2AUTH_pubkey(struct authby authby)
{
	return authby_has_any(authby, authby_v2AUTH_pubkey());
}
