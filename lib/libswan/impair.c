/* impair constants, for libreswan
 *
 * Copyright (C) 2017-2018 Andrew Cagney
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

#include <stddef.h>
#include <limits.h>

#include "constants.h"
#include "enum_names.h"
#include "lmod.h"
#include "keywords.h"
#include "impair.h"
#include "lswlog.h"

/*
 * Initialize both the .name and .help arrays.
 *
 * See plutomain.c why the name has an extra "\0" appended (hint it is
 * a hack for encoding what to do with flags).
 *
 * XXX: since only the --impair ... form is supported, has this all
 * become redundant.
 *
 * So that grepping for IMPAIR.<name> finds this file, the N parameter
 * is the full enum name (IMPAIR_...) and not just the truncated
 * suffix.
 */

struct double_double {
	const char *name[IMPAIR_roof_IX - IMPAIR_floor_IX];
	const char *help[IMPAIR_roof_IX - IMPAIR_floor_IX];
};

static struct double_double impair = {

#define S(N,A,H)							\
	.name[N##_IX - IMPAIR_floor_IX] = A "\0", \
	.help[N##_IX - IMPAIR_floor_IX] = H

       S(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH, "impair-add-unknown-payload-to-auth", "add a payload with an unknown type to AUTH"),
       S(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK, "impair-add-unknown-payload-to-auth-sk", "add a payload with an unknown type to AUTH's SK payload"),
       S(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_SA_INIT, "impair-add-unknown-payload-to-sa-init", "add a payload with an unknown type to SA_INIT"),
       S(IMPAIR_ALLOW_DNS_INSECURE, "impair-allow-dns-insecure", "allow IPSECKEY lookups without DNSSEC protection"),
       S(IMPAIR_ALLOW_NULL_NONE, "impair-allow-null-none", "cause pluto to allow esp=null-none and ah=none for testing"),
       S(IMPAIR_BUST_MI2, "impair-bust-mi2", "make MI2 really large"),
       S(IMPAIR_BUST_MR2, "impair-bust-mr2", "make MR2 really large"),
       S(IMPAIR_CORRUPT_ENCRYPTED, "impair-corrupt-encrypted", "corrupts the encrypted packet so that the decryption fails"),
       S(IMPAIR_DELETE_ON_RETRANSMIT, "impair-delete-on-retransmit", "causes pluto to fail on the first retransmit"),
       S(IMPAIR_DROP_I2, "impair-drop-i2", "drop second initiator packet"),
       S(IMPAIR_DROP_XAUTH_R0, "impair-drop-xauth-r0", "causes pluto to drop an XAUTH user/passwd request on IKE initiator"),
       S(IMPAIR_FORCE_FIPS, "impair-force-fips", "causes pluto to believe we are in fips mode, NSS needs its own hack"),
       S(IMPAIR_IGNORE_HASH_NOTIFY_REQUEST, "impair-ignore-hash-notify", "causes pluto to ignore incoming hash notify from IKE_SA_INIT Request"),
       S(IMPAIR_IGNORE_HASH_NOTIFY_RESPONSE, "impair-ignore-hash-notify-resp", "causes pluto to ignore incoming hash notify from IKE_SA_INIT Response"),
       S(IMPAIR_IKEv2_EXCLUDE_INTEG_NONE, "impair-ikev2-exclude-integ-none", "lets pluto exclude integrity 'none' in proposals"),
       S(IMPAIR_IKEv2_INCLUDE_INTEG_NONE, "impair-ikev2-include-integ-none", "lets pluto include integrity 'none' in proposals"),
       S(IMPAIR_JACOB_TWO_TWO, "impair-jacob-two-two", "cause pluto to send all messages twice."),
       S(IMPAIR_MAJOR_VERSION_BUMP, "impair-major-version-bump", "cause pluto to send an IKE major version that's higher then we support."),
       S(IMPAIR_MINOR_VERSION_BUMP, "impair-minor-version-bump", "cause pluto to send an IKE minor version that's higher then we support."),
       S(IMPAIR_OMIT_HASH_NOTIFY_REQUEST, "impair-omit-hash-notify", "causes pluto to omit sending hash notify in IKE_SA_INIT Request"),
       S(IMPAIR_PROPOSAL_PARSER, "impair-proposal-parser", "impair algorithm parser - what you see is what you get"),
       S(IMPAIR_REPLAY_BACKWARD, "impair-replay-backward", "replay all earlier packets new-to-old"),
       S(IMPAIR_REPLAY_DUPLICATES, "impair-replay-duplicates", "replay duplicates of each incoming packet"),
       S(IMPAIR_REPLAY_ENCRYPTED, "impair-replay-encrypted", "replay encrypted packets"),
       S(IMPAIR_REPLAY_FORWARD, "impair-replay-forward", "replay all earlier packets old-to-new"),
       S(IMPAIR_SA_CREATION, "impair-sa-creation", "fail all SA creation"),
       S(IMPAIR_SEND_BOGUS_DCOOKIE, "impair-send-bogus-dcookie", "causes pluto to send a a bogus IKEv2 DCOOKIE"),
       S(IMPAIR_SEND_BOGUS_ISAKMP_FLAG, "impair-send-bogus-isakmp-flag", "causes pluto to set a RESERVED ISAKMP flag to test ignoring/zeroing it"),
       S(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG, "impair-send-bogus-payload-flag", "causes pluto to set a RESERVED PAYLOAD flag to test ignoring/zeroing it"),

       S(IMPAIR_SEND_KEY_SIZE_CHECK, "impair-send-key-size-check", "causes pluto to omit checking configured ESP key sizes for testing"),
       S(IMPAIR_SEND_NO_DELETE, "impair-send-no-delete", "causes pluto to omit sending Notify/Delete messages"),
       S(IMPAIR_SEND_NO_IKEV2_AUTH, "impair-send-no-ikev2-auth", "causes pluto to omit sending an IKEv2 IKE_AUTH packet"),
       S(IMPAIR_SEND_NO_MAIN_R2, "impair-send-no-main-r2", "causes pluto to omit sending an last Main Mode response packet"),
       S(IMPAIR_SEND_NO_XAUTH_R0, "impair-send-no-xauth-r0", "causes pluto to omit sending an XAUTH user/passwd request"),
       S(IMPAIR_SEND_PKCS7_THINGIE, "impair-send-pkcs7-thingie", "send certificates as a PKCS7 thingie"),
       S(IMPAIR_SUPPRESS_RETRANSMITS, "impair-suppress-retransmits", "causes pluto to never send retransmits (wait the full timeout)"),
       S(IMPAIR_TIMEOUT_ON_RETRANSMIT, "impair-timeout-on-retransmit", "causes pluto to 'retry' (switch protocol) on the first retransmit"),
       S(IMPAIR_UNKNOWN_PAYLOAD_CRITICAL, "impair-unknown-payload-critical", "mark the unknown payload as critical"),

#undef S
};

const enum_names impair_names = {
	IMPAIR_floor_IX, IMPAIR_roof_IX - 1,
	ARRAY_REF(impair.name),
	"impair-",
	NULL,
};

const struct lmod_info impair_lmod_info = {
	.names = &impair_names,
	.all = IMPAIR_MASK,
	.mask = IMPAIR_MASK,
};
const struct enum_names impair_help = {
	IMPAIR_floor_IX, IMPAIR_roof_IX - 1,
	ARRAY_REF(impair.help),
	NULL, NULL,
};

static const struct keyword send_impairment_value[] = {
#define S(E, H) [SEND_##E] = { .name = #E, .value = SEND_##E, .details = H, }
	S(NORMAL, "send normal content"),
	S(OMIT, "do not send content"),
	S(EMPTY, "send zero length content"),
	S(DUPLICATE, "duplicate content"),
#undef S
};

static const struct keywords send_impairment_keywords =
	DIRECT_KEYWORDS(send_impairment_value);

struct impairment {
	const char *what;
	const char *help;
	/*
	 * If non-null; HOW is either a keyword or an (unsigned)
	 * number encoded as keywords.nr_keywords+NUMBER.
	 */
	const struct keywords *how_keynum;
	void *value;
	/* size_t offsetof_value; */
	size_t sizeof_value;
};

struct impairment impairments[] = {
	{ .what = NULL, },
#define V(V) .value = &V, .sizeof_value = sizeof(V)

	{
		.what = "emitting",
		.help = "disable correctness-checks when emitting a payload (let anything out)",
		V(impair_emitting),
	},
	{
		.what = "ke-payload",
		.help = "corrupt the outgoing KE payload",
		.how_keynum = &send_impairment_keywords,
		V(impair_ke_payload),
	},

	/*
	 * IKEv1: the key-length attribute is at the same level as
	 * other attributes such as encryption.  Just need to know if
	 * the IKE, or CHILD proposal set should be manipulated.
	 *
	 * IKEv2: the key-length attribute is nested within an
	 * encryption transform.  Hence, also need to know which
	 * transform to screw with.
	 */
	{
		.what = "ike-key-length-attribute",
		.help = "corrupt the outgoing IKE proposal's key length attribute",
		.how_keynum = &send_impairment_keywords,
		V(impair_ike_key_length_attribute),
	},
	{
		.what = "child-key-length-attribute",
		.help = "corrupt the outgoing CHILD proposal's key length attribute",
		.how_keynum = &send_impairment_keywords,
		V(impair_child_key_length_attribute),
	},
};

static void help(const char *prefix, const struct impairment *cr)
{
	LSWLOG_INFO(buf) {
		lswlogf(buf, "%s%s: %s", prefix, cr->what, cr->help);
	}
	if (cr->how_keynum != NULL) {
		const struct keywords *kw = cr->how_keynum;
		for (unsigned ki = 0; ki < kw->nr_values; ki++) {
			const struct keyword *kv = &kw->values[ki];
			if (kv->name != NULL) {
				LSWLOG_INFO(buf) {
					lswlogf(buf, "%s  %s: %s", prefix,
						kv->name, kv->details);
				}
			}
		}
		LSWLOG_INFO(buf) {
			lswlogf(buf, "%s  %s: %s", prefix,
				"<unsigned>", "use the unsigned value");
		}
	}
}

void help_impair(const char *prefix)
{
	for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
		const struct impairment *cr = &impairments[ci];
		help(prefix, cr);
	}
}

/*
 * Return the long value in STRING, but with +ve values adjusted by
 * BIAS.
 */
static bool parse_biased_unsigned(shunk_t string, unsigned *dest, unsigned bias)
{
	unsigned u;
	if (shunk_tou(string, &u, 0)) {
		if (u <= UINT_MAX - bias) {
			*dest = u + bias;
			return true;
		} else {
			return false;
		}
	} else {
		return false;
	}
}

#define IMPAIR_DISABLE (elemsof(impairments) + 0)
#define IMPAIR_LIST (elemsof(impairments) + 1)

bool parse_impair(const char *optarg,
		  struct whack_impair *whack_impair,
		  bool enable)
{
	if (streq(optarg, "help")) {
		help_impair("");
		return false;
	} else if (whack_impair->what != 0) {
		LSWLOG_ERROR(buf) {
			lswlogf(buf, "ignoring option '--impair %s'", optarg);
		}
		return true;
	} else if (enable && streq(optarg, "none")) {
		*whack_impair = (struct whack_impair) {
			.what = IMPAIR_DISABLE,
			.how = 0,
		};
		return true;
	} else if (enable && streq(optarg, "list")) {
		*whack_impair = (struct whack_impair) {
			.what = IMPAIR_LIST,
			.how = 0,
		};
		return true;
	}
	/* Break OPTARG into WHAT[=HOW] */
	shunk_t arg = shunk1(optarg);
	shunk_t what = shunk_strsep(&arg, ":=");
	shunk_t how = arg;
	/* look for WHAT */
	unsigned ci = 1;
	while (true) {
		if (ci >= elemsof(impairments)) {
			LSWLOG_ERROR(buf) {
				lswlogf(buf, "option '--impair "PRI_SHUNK"' not recognized",
					PRI_shunk(what));
			}
			return false;
		} else if (shunk_strcaseeq(what, impairments[ci].what)) {
			break;
		}
		ci++;
	}
	const struct impairment *cr = &impairments[ci];
	if (!enable) {
		if (how.len > 0) {
			LSWLOG_ERROR(buf) {
				lswlogf(buf, "option '--no-impair "PRI_SHUNK"' has unexpeced parameter '"PRI_SHUNK"'",
					PRI_shunk(what), PRI_shunk(how));
			}
			return false;
		}
		*whack_impair = (struct whack_impair) {
			.what = ci,
			.how = false,
		};
		return true;
	} else if (shunk_strcaseeq(how, "no")) {
		/* WHAT:none */
		*whack_impair = (struct whack_impair) {
			.what = ci,
			.how = false,
		};
		return true;
	} else if (cr->how_keynum != NULL) {
		/* return on fail */
		if (how.len == 0) {
			LSWLOG_ERROR(buf) {
				lswlogf(buf, "option --impair '"PRI_SHUNK"' requires a parameter",
					PRI_shunk(what));
			}
			return false;
		}
		if (shunk_strcaseeq(how, "help")) {
			help("", cr);
			return false;
		}
		/* return on success. */
		const struct keyword *kw = keyword_by_name(cr->how_keynum, how);
		if (kw != NULL) {
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = kw->value,
			};
			return true;
		}
		unsigned biased_value;
		if (parse_biased_unsigned(how, &biased_value,
					  cr->how_keynum->nr_values)) {
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = biased_value,
			};
			return true;
		}
		LSWLOG_ERROR(buf) {
			lswlogf(buf, "option '--impair "PRI_SHUNK"' parameter '"PRI_SHUNK"' invalid",
				PRI_shunk(what), PRI_shunk(how));
		}
		return false;
	} else if (how.len > 0) {
		/* XXX: ignores "WHAT:" */
		LSWLOG_ERROR(buf) {
			lswlogf(buf, "option '--impair "PRI_SHUNK"' has unexpected parameter '"PRI_SHUNK"'",
				PRI_shunk(what), PRI_shunk(how));
		}
		return false;
	} else {
		*whack_impair = (struct whack_impair) {
			.what = ci,
			.how = true,
		};
		return true;
	}
}

static void lswlog_impairment(struct lswlog *buf, const struct impairment *cr)
{
	if (cr->how_keynum != NULL) {
		passert(cr->sizeof_value == sizeof(unsigned));
		unsigned value = *(unsigned*)cr->value;
		const struct keyword *kw = keyword_by_value(cr->how_keynum, value);
		if (kw != NULL) {
			lswlogs(buf, kw->name);
		} else if (value >= cr->how_keynum->nr_values) {
			lswlogf(buf, "%zu", value - cr->how_keynum->nr_values);
		} else {
			lswlogf(buf, "?%u?", value);
		}
	} else switch (cr->sizeof_value) {
#define L(T) case sizeof(uint##T##_t): lswlogf(buf, "%"PRIu##T, *(uint##T##_t*)cr->value); break
			L(8);
			L(16);
			L(32);
			L(64);
#undef L
		default:
			bad_case(cr->sizeof_value);
	}
}

static bool non_zero(const uint8_t *value, size_t sizeof_value)
{
	for (unsigned byte = 0; byte < sizeof_value; byte++) {
		if (value[byte] != 0) {
			return true;
		}
	}
	return false;
}

void process_impair(const struct whack_impair *wc)
{
	if (wc->what == 0) {
		/* ignore; silently */
		return;
	} else if (wc->what == IMPAIR_DISABLE) {
		for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
			const struct impairment *cr = &impairments[ci];
			if (non_zero(cr->value, cr->sizeof_value)) {
				LSWDBGP(DBG_MASK, buf) {
					lswlogf(buf, "%s: ", cr->what);
					lswlogs(buf, " disabled");
				}
				memset(cr->value, 0, cr->sizeof_value);
			}
		}
		return;
	} else if (wc->what == IMPAIR_LIST) {
		for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
			const struct impairment *cr = &impairments[ci];
			if (non_zero(cr->value, cr->sizeof_value)) {
				/* XXX: should be whack log? */
				LSWLOG_INFO(buf) {
					lswlogf(buf, "%s: ", cr->what);
					lswlog_impairment(buf, cr);
				}
			}
		}
		return;
	} else if (wc->what >= elemsof(impairments)) {
		LSWLOG_ERROR(buf) {
			lswlogf(buf, "impairment %u out-of-range",
				wc->what);
		}
		return;
	}
	const struct impairment *cr = &impairments[wc->what];
	if (cr->how_keynum != NULL) {
		passert(cr->sizeof_value == sizeof(unsigned));
		*(unsigned*)cr->value = wc->how; /* do not un-bias */
	} else switch (cr->sizeof_value) {
#define L(T) case sizeof(uint##T##_t): *(uint##T##_t*)cr->value = wc->how; break;
			L(8);
			L(16);
			L(32);
			L(64);
#undef L
		default:
			bad_case(cr->sizeof_value);
	}
	LSWDBGP(DBG_MASK, buf) {
		lswlogf(buf, "%s: ", cr->what);
		lswlog_impairment(buf, cr);
	}
}

/*
 * declare these last so that all references are forced to use the
 * declaration in the header.
 */

bool impair_emitting;
enum send_impairment impair_ke_payload;
enum send_impairment impair_ike_key_length_attribute;
enum send_impairment impair_child_key_length_attribute;
