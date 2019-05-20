/*
 * impair constants, for libreswan
 *
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019-2019 Paul Wouters <pwouters@redhat.com>
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
       S(IMPAIR_IKEv1_DEL_WITH_NOTIFY, "impair-ikev1-del-with-notify", "causes pluto to send IKE Delete with additional bogus Notify payload"),
       S(IMPAIR_BAD_IKE_AUTH_XCHG, "impair-bad-ikev2-auth-xchg", "causes pluto to send IKE_AUTH replies with wrong exchange type"),

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
#define S(E, H) [SEND_##E] = { .name = "SEND_" #E, .sname = #E, .value = SEND_##E, .details = H, }
	S(NORMAL, "send normal content"),
	S(OMIT, "do not send content"),
	S(EMPTY, "send zero length content"),
	S(DUPLICATE, "duplicate content"),
#undef S
};

static const struct keywords send_impairment_keywords =
	DIRECT_KEYWORDS("send impaired content", send_impairment_value);

struct impairment {
	const char *what;
	const char *help;
	/*
	 * If non-NULL, HOW is either a keyword or an (unsigned)
	 * number encoded as keywords.nr_keywords+NUMBER.
	 *
	 * If NULL, HOW is assumed to be a boolean.
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
		.what = "revival",
		.help = "disable code that revives a connection that is supposed to stay up",
		V(impair_revival),
	},
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
						kv->sname, kv->details);
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
	/*
	 * look for both WHAT and for compatability with the old
	 * lset_t impair flags, no-WHAT.
	 */
	unsigned ci = 1;
	shunk_t nowhat = what;
	/* reject --no-impair no-... */
	bool no = enable ? shunk_strcaseeat(&nowhat, "no-") : true;
	while (true) {
		if (ci >= elemsof(impairments)) {
			LSWLOG_ERROR(buf) {
				lswlogf(buf, "ignoring unrecognized option '-%s-impair "PRI_SHUNK"'",
					enable ? "" : "-no",
					PRI_shunk(what));
			}
			return false;
		} else if (shunk_strcaseeq(nowhat, impairments[ci].what)) {
			break;
		}
		ci++;
	}
	const struct impairment *cr = &impairments[ci];

	/* --{,no-}impair WHAT:help always works */
	if (shunk_strcaseeq(how, "help")) {
		help("", cr);
		return false;
	}

	/*
	 * Ensure that --no-impair WHAT, --impair no-WHAT, --impair
         * WHAT:no, all always work.
	 */
	if (no || shunk_strcaseeq(how, "no")) {
		/* reject --no-impair WHAT:no and --impair no-WHAT:no */
		if (no && how.len > 0) {
			LSWLOG_ERROR(buf) {
				lswlogf(buf, "ignoring option '-%s-impair "PRI_SHUNK":"PRI_SHUNK"' with unexpected parameter '"PRI_SHUNK"'",
					enable ? "" : "-no",
					PRI_shunk(what), PRI_shunk(how), PRI_shunk(how));
			}
			return false;
		}
		*whack_impair = (struct whack_impair) {
			.what = ci,
			.how = 0,
		};
		return true;
	}

	if (cr->how_keynum != NULL) {
		/*
		 * parse --impair WHAT:HOW
		 */
		if (how.len == 0) {
			LSWLOG_ERROR(buf) {
				lswlogf(buf, "ignoring option '--impair "PRI_SHUNK"' with missing parameter",
					PRI_shunk(what));
			}
			return false;
		}
		/* try the keyword. */
		const struct keyword *kw = keyword_by_sname(cr->how_keynum, how);
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
			lswlogf(buf, "ignoring option '--impair "PRI_SHUNK":"PRI_SHUNK"' with unknown parameter '"PRI_SHUNK"'",
				PRI_shunk(what), PRI_shunk(how),
				PRI_shunk(how));
		}
		return false;
	} else {
		/*
		 * Only allow simple booleans for now (it could call
		 * parse_piased_unsigned).
		 *
		 * Accept some common terms, and assume an empty WHAT
		 * implies 'yes'.
		 *
		 * XXX: Yes, "no" was already handled above.  It's
		 * also here so that the two if() clauses look
		 * consistent.
		 */
		if (shunk_strcaseeq(how, "false") ||
		    shunk_strcaseeq(how, "off") ||
		    shunk_strcaseeq(how, "no") ||
		    shunk_strcaseeq(how, "0")) {
			/* --impair WHAT:nope */
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = 0,
			};
			return true;
		} else if (how.len == 0 ||
			   shunk_strcaseeq(how, "true") ||
			   shunk_strcaseeq(how, "on") ||
			   shunk_strcaseeq(how, "yes") ||
			   shunk_strcaseeq(how, "1")) {
			/* --impair WHAT:yes */
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = 1,
			};
			return true;
		} else {
			/* XXX: ignores "WHAT:" */
			LSWLOG_ERROR(buf) {
				lswlogf(buf, "ignoring option '--impair "PRI_SHUNK":"PRI_SHUNK"' with unexpected parameter '"PRI_SHUNK"'",
					PRI_shunk(what), PRI_shunk(how), PRI_shunk(how));
			}
			return false;
		}
	}
}

/*
 * Print something that can be fed back into --impair ARG.
 */

static uintmax_t value_of(const struct impairment *cr)
{
       switch (cr->sizeof_value) {
#define L(T) case sizeof(uint##T##_t): return *(uint##T##_t*)cr->value
               L(8);
               L(16);
               L(32);
               L(64);
#undef L
       default:
               bad_case(cr->sizeof_value);
       }
}

static void lswlog_impairment(struct lswlog *buf, const struct impairment *cr)
{
	if (cr->how_keynum != NULL) {
		lswlogf(buf, "%s:", cr->what);
		unsigned value = value_of(cr);
		const struct keyword *kw = keyword_by_value(cr->how_keynum, value);
		if (kw != NULL) {
			lswlogs(buf, kw->sname);
		} else if (value >= cr->how_keynum->nr_values) {
			lswlogf(buf, "%zu", value - cr->how_keynum->nr_values);
		} else {
			lswlogf(buf, "?%u?", value);
		}
	} else {
		/* only bool for now */
		if (value_of(cr) != 0) {
			lswlogs(buf, cr->what);
		} else {
			/* parser accepts this */
			lswlogf(buf, "%s:no", cr->what);
		}
	}
}

void lswlog_impairments(struct lswlog *buf, const char *prefix, const char *sep)
{
	/* is there anything enabled? */
	lset_t cur_impairing = (cur_debugging & IMPAIR_MASK);
	bool enabled = false;
	for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
		const struct impairment *cr = &impairments[ci];
		if (value_of(cr) != 0) {
			enabled = true;
			break;
		}
	}
	if (!enabled && cur_impairing == LEMPTY) {
		return;
	}
	lswlogs(buf, prefix);
	if (cur_impairing != LEMPTY) {
		/* avoid LEMPTY being printed as "none" */
		lswlog_enum_lset_short(buf, &impair_names, sep, cur_impairing);
	}
	const char *s = "";
	for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
		const struct impairment *cr = &impairments[ci];
		if (value_of(cr) != 0) {
			lswlogs(buf, s); s = sep;
			lswlog_impairment(buf, cr);
		}
	}
}

void process_impair(const struct whack_impair *wc)
{
	if (wc->what == 0) {
		/* ignore; silently */
		return;
	} else if (wc->what == IMPAIR_DISABLE) {
		for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
			const struct impairment *cr = &impairments[ci];
			if (value_of(cr) != 0) {
				LSWDBGP(DBG_BASE, buf) {
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
			if (value_of(cr) != 0) {
				/* XXX: should be whack log? */
				LSWLOG_INFO(buf) {
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
	LSWDBGP(DBG_BASE, buf) {
		lswlog_impairment(buf, cr);
	}
}

/*
 * declare these last so that all references are forced to use the
 * declaration in the header.
 */

bool impair_revival;
bool impair_emitting;
enum send_impairment impair_ke_payload;
enum send_impairment impair_ike_key_length_attribute;
enum send_impairment impair_child_key_length_attribute;
