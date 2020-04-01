/* impair constants, for libreswan
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

static const struct keyword send_impairment_value[] = {
#define S(E, H) [SEND_##E] = { .name = "SEND_" #E, .sname = #E, .value = SEND_##E, .details = H, }
	S(NORMAL, "do not modify content"),
	S(OMIT, "do not send content"),
	S(EMPTY, "send zero length content"),
	S(DUPLICATE, "duplicate content"),
#undef S
};

static const struct keywords send_impairment_keywords =
	DIRECT_KEYWORDS("send impaired content", send_impairment_value);

static const struct keyword exchange_impairment_value[] = {
#define S(E, H) [E##_EXCHANGE] = { .name = "SEND_" #E, .sname = #E, .value = E##_EXCHANGE, .details = H, }
	S(NO, "do not modify exchanges"),
	S(QUICK, "modify IKEv1 QUICK exchanges"),
	S(XAUTH, "modify IKEv1 XAUTH exchanges"),
	S(NOTIFICATION, "modify notification (informational) exchanges"),
	S(DELETE, "modify delete exchanges"),
#undef S
};

static const struct keywords exchange_impairment_keywords =
	DIRECT_KEYWORDS("impaire exchange content", exchange_impairment_value);

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
	const char *unsigned_help;
	void *value;
	/* size_t offsetof_value; */
	size_t sizeof_value;
};

struct impairment impairments[] = {
	{ .what = NULL, },
#define V(V) .value = &impair.V, .sizeof_value = sizeof(impair.V)

	{
		.what = "revival",
		.help = "disable code that revives a connection that is supposed to stay up",
		V(revival),
	},
	{
		.what = "emitting",
		.help = "disable correctness-checks when emitting a payload (let anything out)",
		V(emitting),
	},
	{
		.what = "ke-payload",
		.help = "corrupt the outgoing KE payload",
		.how_keynum = &send_impairment_keywords,
		.unsigned_help = "use <unsigned> to byte-fill the KE payload",
		V(ke_payload),
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
		.unsigned_help = "use <unsigned> as the key length",
		V(ike_key_length_attribute),
	},
	{
		.what = "child-key-length-attribute",
		.help = "corrupt the outgoing CHILD proposal's key length attribute",
		.how_keynum = &send_impairment_keywords,
		.unsigned_help = "use <unsigned> as the key length",
		V(child_key_length_attribute),
	},
	{
		.what = "log-rate-limit",
		.help = "set the per-hour(?) cap on rate-limited log messages",
		V(log_rate_limit),
	},

	/*
	 * IKEv1: hash payloads
	 */
	{
		.what = "v1-hash-check",
		.help = "disable check of incoming IKEv1 hash payload",
		V(v1_hash_check),
	},
	{
		.what = "v1-hash-payload",
		.help = "corrupt the outgoing HASH payload",
		.how_keynum = &send_impairment_keywords,
		.unsigned_help = "fill the hash payload with <unsigned> bytes",
		V(v1_hash_payload),
	},
	{
		.what = "v1-hash-exchange",
		.help = "the outgoing exchange that should contain the corrupted HASH payload",
		.how_keynum = &exchange_impairment_keywords,
		V(v1_hash_exchange),
	},

	{
		.what = "ike-initiator-spi",
		.help = "corrupt the IKE initiator SPI",
		.unsigned_help = "set SPI to <unsigned>",
		V(ike_initiator_spi),
	},
	{
		.what = "ike-responder-spi",
		.help = "corrupt the IKE responder SPI",
		.unsigned_help = "set SPI to <unsigned>",
		V(ike_responder_spi),
	},

	/* old stuff */

#define S(FIELD, WHAT, HELP) { .what = WHAT, .help = HELP, V(FIELD), }

	S(ADD_UNKNOWN_PAYLOAD_TO_AUTH, "add-unknown-payload-to-auth", "add a payload with an unknown type to AUTH"),
	S(ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK, "add-unknown-payload-to-auth-sk", "add a payload with an unknown type to AUTH's SK payload"),
	S(ADD_UNKNOWN_PAYLOAD_TO_SA_INIT, "add-unknown-payload-to-sa-init", "add a payload with an unknown type to SA_INIT"),
	S(ALLOW_DNS_INSECURE, "allow-dns-insecure", "allow IPSECKEY lookups without DNSSEC protection"),
	S(ALLOW_NULL_NONE, "allow-null-none", "cause pluto to allow esp=null-none and ah=none for testing"),
	S(BUST_MI2, "bust-mi2", "make MI2 really large"),
	S(BUST_MR2, "bust-mr2", "make MR2 really large"),
	S(CORRUPT_ENCRYPTED, "corrupt-encrypted", "corrupts the encrypted packet so that the decryption fails"),
	S(DELETE_ON_RETRANSMIT, "delete-on-retransmit", "causes pluto to fail on the first retransmit"),
	S(DROP_I2, "drop-i2", "drop second initiator packet"),
	S(DROP_XAUTH_R0, "drop-xauth-r0", "causes pluto to drop an XAUTH user/passwd request on IKE initiator"),
	S(FORCE_FIPS, "force-fips", "causes pluto to believe we are in fips mode, NSS needs its own hack"),
	S(IGNORE_HASH_NOTIFY_REQUEST, "ignore-hash-notify", "causes pluto to ignore incoming hash notify from IKE_SA_INIT Request"),
	S(IGNORE_HASH_NOTIFY_RESPONSE, "ignore-hash-notify-resp", "causes pluto to ignore incoming hash notify from IKE_SA_INIT Response"),
	S(IKEv2_EXCLUDE_INTEG_NONE, "ikev2-exclude-integ-none", "lets pluto exclude integrity 'none' in proposals"),
	S(IKEv2_INCLUDE_INTEG_NONE, "ikev2-include-integ-none", "lets pluto include integrity 'none' in proposals"),
	S(JACOB_TWO_TWO, "jacob-two-two", "cause pluto to send all messages twice."),
	S(MAJOR_VERSION_BUMP, "major-version-bump", "cause pluto to send an IKE major version that's higher then we support."),
	S(MINOR_VERSION_BUMP, "minor-version-bump", "cause pluto to send an IKE minor version that's higher then we support."),
	S(OMIT_HASH_NOTIFY_REQUEST, "omit-hash-notify", "causes pluto to omit sending hash notify in IKE_SA_INIT Request"),
	S(PROPOSAL_PARSER, "proposal-parser", "impair algorithm parser - what you see is what you get"),
	S(REPLAY_BACKWARD, "replay-backward", "replay all earlier packets new-to-old"),
	S(REPLAY_DUPLICATES, "replay-duplicates", "replay duplicates of each incoming packet"),
	S(REPLAY_ENCRYPTED, "replay-encrypted", "replay encrypted packets"),
	S(REPLAY_FORWARD, "replay-forward", "replay all earlier packets old-to-new"),
	S(SA_CREATION, "sa-creation", "fail all SA creation"),
	S(SEND_BOGUS_DCOOKIE, "send-bogus-dcookie", "causes pluto to send a a bogus IKEv2 DCOOKIE"),
	S(SEND_BOGUS_ISAKMP_FLAG, "send-bogus-isakmp-flag", "causes pluto to set a RESERVED ISAKMP flag to test ignoring/zeroing it"),
	S(SEND_BOGUS_PAYLOAD_FLAG, "send-bogus-payload-flag", "causes pluto to set a RESERVED PAYLOAD flag to test ignoring/zeroing it"),

	S(SEND_KEY_SIZE_CHECK, "send-key-size-check", "causes pluto to omit checking configured ESP key sizes for testing"),
	S(SEND_NO_DELETE, "send-no-delete", "causes pluto to omit sending Notify/Delete messages"),
	S(SEND_NO_IKEV2_AUTH, "send-no-ikev2-auth", "causes pluto to omit sending an IKEv2 IKE_AUTH packet"),
	S(SEND_NO_MAIN_R2, "send-no-main-r2", "causes pluto to omit sending an last Main Mode response packet"),
	S(SEND_NO_XAUTH_R0, "send-no-xauth-r0", "causes pluto to omit sending an XAUTH user/passwd request"),
	S(SEND_PKCS7_THINGIE, "send-pkcs7-thingie", "send certificates as a PKCS7 thingie"),
	S(SUPPRESS_RETRANSMITS, "suppress-retransmits", "causes pluto to never send retransmits (wait the full timeout)"),
	S(TIMEOUT_ON_RETRANSMIT, "timeout-on-retransmit", "causes pluto to 'retry' (switch protocol) on the first retransmit"),
	S(UNKNOWN_PAYLOAD_CRITICAL, "unknown-payload-critical", "mark the unknown payload as critical"),
	S(IKEv1_DEL_WITH_NOTIFY, "ikev1-del-with-notify", "causes pluto to send IKE Delete with additional bogus Notify payload"),
	S(BAD_IKE_AUTH_XCHG, "bad-ikev2-auth-xchg", "causes pluto to send IKE_AUTH replies with wrong exchange type"),

#undef S

};

static void help(const char *prefix, const struct impairment *cr)
{
	LSWLOG_INFO(buf) {
		jam(buf, "%s%s: %s", prefix, cr->what, cr->help);
	}
	if (cr->how_keynum != NULL) {
		const struct keywords *kw = cr->how_keynum;
		/* skip 0, always no */
		for (unsigned ki = 1; ki < kw->nr_values; ki++) {
			const struct keyword *kv = &kw->values[ki];
			if (kv->details != NULL) {
				LSWLOG_INFO(buf) {
					jam(buf, "%s  %s: %s", prefix,
					    kv->sname, kv->details);
				}
			}
		}
	}
	if (cr->unsigned_help != NULL) {
		LSWLOG_INFO(buf) {
			jam(buf, "%s  %s: %s", prefix,
			    "<unsigned>", cr->unsigned_help);
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
 * BIAS.  If the operation fails, zero is returned - bias must be
 * non-zero.
 */
static unsigned parse_biased_unsigned(shunk_t string, const struct impairment *cr)
{
	unsigned bias = cr->how_keynum != NULL ? cr->how_keynum->nr_values : 1;
	uintmax_t u;
	err_t err = shunk_to_uint(string, NULL, 0/*base*/, &u, UINTMAX_MAX - bias/*ceiling*/);
	if (err == NULL) {
		return u + bias;
	} else {
		return 0;
	}
}

#define IMPAIR_DISABLE (elemsof(impairments) + 0)
#define IMPAIR_LIST (elemsof(impairments) + 1)

bool parse_impair(const char *optarg,
		  struct whack_impair *whack_impair,
		  bool enable /* --impair ... vs --no-impair ...*/)
{
	if (streq(optarg, "help")) {
		help_impair("");
		return false;
	}

	if (whack_impair->what != 0) {
		LSWLOG_ERROR(buf) {
			lswlogf(buf, "ignoring second impair option: --%simpair %s",
				enable ? "" : "no-", optarg);
		}
		return true;
	}

	if (enable && streq(optarg, "none")) {
		*whack_impair = (struct whack_impair) {
			.what = IMPAIR_DISABLE,
			.how = 0,
		};
		return true;
	}

	if (enable && streq(optarg, "list")) {
		*whack_impair = (struct whack_impair) {
			.what = IMPAIR_LIST,
			.how = 0,
		};
		return true;
	}

	/* Break OPTARG into WHAT[=HOW] */
	shunk_t arg = shunk1(optarg);
	shunk_t what = shunk_token(&arg, NULL, ":=");
	shunk_t how = arg;

	/*
	 * look for both WHAT and for compatibility with the old
	 * lset_t impair flags, no-WHAT.
	 */

	bool what_no = shunk_strcaseeat(&what, "no-");
	unsigned ci = 1;
	const struct impairment *cr = NULL;
	for (ci = 1/*skip 0*/; ci < elemsof(impairments); ci++) {
		if (hunk_strcaseeq(what, impairments[ci].what)) {
			cr = &impairments[ci];
			break;
		}
	}
	if (cr == NULL) {
		LSWLOG_ERROR(buf) {
			jam(buf, "ignoring unrecognized impair option '"PRI_SHUNK"'",
			    pri_shunk(what));
		}
		return false;
	}

	/*
	 * no matter how negated, "help" always works
	 */
	if (hunk_strcaseeq(how, "help") ||
	    hunk_strcaseeq(how, "?")) {
		help("", cr);
		return false;
	}

	/*
	 * Reject overly negative or conflicting combinations.  For
	 * instance: --no-impair no-foo:bar.
	 */
	if ((!enable + what_no + (how.ptr != NULL)) > 1) {
		LSWLOG_ERROR(buf) {
			jam(buf, "ignoring overly negative --%simpair %s",
			    enable ? "" : "no-", optarg);
		}
		return false;
	}

	/*
	 * Always recognize "no".
	 */
	if (!enable || what_no || hunk_strcaseeq(how, "no")) {
		*whack_impair = (struct whack_impair) {
			.what = ci,
			.how = 0,
		};
		return true;
	}

	/*
	 * For WHAT:HOW, lookup the keyword HOW.
	 */
	if (cr->how_keynum != NULL) {
		/* try the keyword. */
		const struct keyword *kw = keyword_by_sname(cr->how_keynum, how);
		if (kw != NULL) {
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = kw->value,
			};
			return true;
		}
	} else {
		/*
		 * Assume boolean - use "yes" and "no" as that is what
		 * bool_str() prints.
		 *
		 * XXX: this can't use keywords as they won't
		 * interpret "" as yes.
		 */
		if (hunk_strcaseeq(how, "no")) {
			/* --impair WHAT:no */
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = false,
			};
			return true;
		}

		if (how.len == 0 || hunk_strcaseeq(how, "yes")) {
			/* --impair WHAT:yes or --impair WHAT */
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = true,
			};
			return true;
		}
	}

	if (cr->unsigned_help != NULL) {
		unsigned biased_value = parse_biased_unsigned(how, cr);
		if (biased_value > 0) {
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = biased_value,
			};
			return true;
		}
	}

	LSWLOG_ERROR(buf) {
		jam(buf, "ignoring impair option '"PRI_SHUNK"' with unrecognized parameter '"PRI_SHUNK"' (%s)",
		    pri_shunk(what), pri_shunk(how), optarg);
	}
	return false;
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

static void jam_impairment(jambuf_t *buf,
			   const struct impairment *cr)
{
	jam(buf, "%s:", cr->what);
	unsigned value = value_of(cr);
	if (cr->how_keynum != NULL) {
		const struct keyword *kw = keyword_by_value(cr->how_keynum, value);
		if (kw != NULL) {
			jam_string(buf, kw->sname);
		} else if (value >= cr->how_keynum->nr_values) {
			jam(buf, "%zu", value - cr->how_keynum->nr_values);
		} else {
			jam(buf, "?%u?", value);
		}
	} else if (cr->unsigned_help != NULL) {
		/* always one biased */
		if (value == 0) {
			jam(buf, "no");
		} else {
			jam(buf, "%u", value-1);
		}
	} else {
		switch (value) {
		case 0: jam(buf, "no"); break;
		case 1: jam(buf, "yes"); break;
		default: jam(buf, "?%u?", value);
		}
	}
}

bool have_impairments(void)
{
	/* is there anything enabled? */
	for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
		const struct impairment *cr = &impairments[ci];
		if (value_of(cr) != 0) {
			return true;
		}
	}
	return false;
}

void jam_impairments(jambuf_t *buf, const char *sep)
{
	const char *s = "";
	for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
		const struct impairment *cr = &impairments[ci];
		if (value_of(cr) != 0) {
			jam_string(buf, s); s = sep;
			jam_impairment(buf, cr);
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
					jam_impairment(buf, cr);
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
	/* do not un-bias */
	switch (cr->sizeof_value) {
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
		jam_impairment(buf, cr);
	}
}

/*
 * XXX: define these at the end of the file so that all references are
 * forced to use the extern declaration in the header (help stop code
 * referring to the wrong variable?).
 */

struct impair impair;
