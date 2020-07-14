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

static const struct keyword impair_emit_value[] = {
#define S(E, H) [IMPAIR_EMIT_##E] = {					\
		.name = "IMPAIR_EMIT_" #E,				\
		.sname = #E,						\
		.value = IMPAIR_EMIT_##E,				\
		.details = H,						\
	}
	S(OMIT, "do not emit content"),
	S(EMPTY, "emit zero length content"),
	S(DUPLICATE, "emit content twice"),
#undef S
};

static const struct keywords impair_emit_keywords =
	DIRECT_KEYWORDS("send impaired content", impair_emit_value);

static const struct keyword impair_v1_exchange_value[] = {
#define S(E, H) [IMPAIR_v1_##E##_EXCHANGE] = {		\
		.name = "IMPAIR_v1_" #E "_EXCHANGE",	\
		.sname = #E,				\
		.value = IMPAIR_v1_##E##_EXCHANGE,	\
		.details = H,				\
	}
	S(QUICK, "modify IKEv1 QUICK exchanges"),
	S(XAUTH, "modify IKEv1 XAUTH exchanges"),
	S(NOTIFICATION, "modify notification (informational) exchanges"),
	S(DELETE, "modify delete exchanges"),
#undef S
};

static const struct keywords impair_v1_exchange_keywords =
	DIRECT_KEYWORDS("impaire exchange content", impair_v1_exchange_value);

/* transform */

static const struct keyword impair_v2_transform_value[] = {
#define S(S, E, H) [IMPAIR_v2_TRANSFORM_##E] = { .name = "IMPAIR_v2_TRANSFORM_"#E, .sname = S, .value = IMPAIR_v2_TRANSFORM_##E, .details = H, }
	S("no", NO, "do not modify transform"),
	S("allow-none", ALLOW_NONE, "allow TRANSFORM=NONE when part of a proposal"),
	S("drop-none", DROP_NONE, "drop TRANSFORM=NONE even when part of a proposal"),
	S("omit", OMIT, "omit transform from proposal"),
#undef S
};

static const struct keywords impair_v2_transform_keywords =
	DIRECT_KEYWORDS("transform impaired content", impair_v2_transform_value);

/* */

struct impairment {
	const char *what;
	const char *help;
	/*
	 * If non-NULL, HOW is either a keyword or an (unsigned)
	 * number encoded as keywords.nr_keywords+NUMBER.
	 *
	 * If NULL, HOW is assumed to be a boolean.
	 */
	const struct keywords *how_keywords;
	const struct enum_names *how_enum_names;
	const char *unsigned_help;
	void *value;
	/* size_t offsetof_value; */
	size_t sizeof_value;
	enum impair_action action;
	unsigned param;
};

struct impairment impairments[] = {
	{ .what = NULL, },

#define A(WHAT, ACTION, PARAM, HELP, UNSIGNED_HELP, ...) { .what = WHAT, .action = CALL_##ACTION, .param = PARAM, .help = HELP, .unsigned_help = UNSIGNED_HELP, ##__VA_ARGS__, }
#define V(WHAT, VALUE, HELP, ...) { .what = WHAT, .action = CALL_IMPAIR_UPDATE, .value = &impair.VALUE, .help = HELP, .sizeof_value = sizeof(impair.VALUE), ##__VA_ARGS__, }

	V("allow-dns-insecure", allow_dns_insecure, "allow IPSECKEY lookups without DNSSEC protection"),
	V("allow-null-none", allow_null_none, "cause pluto to allow esp=null-none and ah=none for testing"),
	V("bad-ikev2-auth-xchg", bad_ike_auth_xchg, "causes pluto to send IKE_AUTH replies with wrong exchange type"),
	V("bust-mi2", bust_mi2, "make MI2 really large"),
	V("bust-mr2", bust_mr2, "make MR2 really large"),
	V("child-key-length-attribute", child_key_length_attribute, "corrupt the outgoing CHILD proposal's key length attribute",
	  .how_keywords = &impair_emit_keywords, .unsigned_help = "emit <unsigned> as the key length"),
	V("corrupt-encrypted", corrupt_encrypted, "corrupts the encrypted packet so that the decryption fails"),
	V("delete-on-retransmit", delete_on_retransmit, "causes pluto to fail on the first retransmit"),
	V("drop-i2", drop_i2, "drop second initiator packet"),
	V("drop-xauth-r0", drop_xauth_r0, "causes pluto to drop an XAUTH user/passwd request on IKE initiator"),
	V("emitting", emitting, "disable correctness-checks when emitting a payload (let anything out)"),
	V("force-fips", force_fips, "causes pluto to believe we are in fips mode, NSS needs its own hack"),
	V("ignore-hash-notify", ignore_hash_notify_request, "causes pluto to ignore incoming hash notify from IKE_SA_INIT Request"),
	V("ignore-hash-notify-resp", ignore_hash_notify_response, "causes pluto to ignore incoming hash notify from IKE_SA_INIT Response"),
	V("ike-initiator-spi", ike_initiator_spi, "corrupt the IKE initiator SPI", .unsigned_help = "set SPI to <unsigned>"),
	V("ike-key-length-attribute", ike_key_length_attribute, "corrupt the outgoing IKE proposal's key length attribute",
	  .how_keywords = &impair_emit_keywords, .unsigned_help = "emit <unsigned> as the key length"),
	V("ike-responder-spi", ike_responder_spi, "corrupt the IKE responder SPI", .unsigned_help = "set SPI to <unsigned>"),
	V("ikev1-del-with-notify", ikev1_del_with_notify, "causes pluto to send IKE Delete with additional bogus Notify payload"),

	V("v2-proposal-integ", v2_proposal_integ, "integrity in proposals", .how_keywords = &impair_v2_transform_keywords),
	V("v2-proposal-dh", v2_proposal_dh, "dh in proposals", .how_keywords = &impair_v2_transform_keywords),

	V("ikev2-add-ike-transform", ikev2_add_ike_transform, "add an extra (possibly bogus) transform to the first IKE proposal", .unsigned_help = "transform type+id encoded as TYPE<<16|ID"),
	V("ikev2-add-child-transform", ikev2_add_child_transform, "add an extra (possibly bogus) transform to the first CHILD proposal", .unsigned_help = "transform type+id encoded as TYPE<<16|ID"),

	V("jacob-two-two", jacob_two_two, "cause pluto to send all messages twice."),
	V("ke-payload", ke_payload, "corrupt the outgoing KE payload",
	  .how_keywords = &impair_emit_keywords, .unsigned_help = "emit the KE payload filled with <unsigned> bytes"),
	V("log-rate-limit", log_rate_limit, "set the per-hour(?) cap on rate-limited log messages"),
	V("major-version-bump", major_version_bump, "cause pluto to send an IKE major version that's higher then we support."),
	V("minor-version-bump", minor_version_bump, "cause pluto to send an IKE minor version that's higher then we support."),
	V("omit-hash-notify", omit_hash_notify_request, "causes pluto to omit sending hash notify in IKE_SA_INIT Request"),
	V("proposal-parser", proposal_parser, "impair algorithm parser - what you see is what you get"),
	V("rekey-initiate-supernet", rekey_initiate_supernet, "impair IPsec SA rekey initiator TSi and TSR to 0/0 ::0, emulate Windows client"),
	V("rekey-initiate-subnet", rekey_initiate_subnet, "impair IPsec SA rekey initiator TSi and TSR to X/32 or X/128"),
	V("rekey-respond-supernet", rekey_respond_supernet, "impair IPsec SA rekey responder TSi and TSR to 0/0 ::0"),
	V("rekey-respond-subnet", rekey_respond_subnet, "impair IPsec SA rekey responder TSi and TSR to X/32 X/128"),
	V("replay-backward", replay_backward, "replay all earlier packets new-to-old"),
	V("replay-duplicates", replay_duplicates, "replay duplicates of each incoming packet"),
	V("replay-encrypted", replay_encrypted, "replay encrypted packets"),
	V("replay-forward", replay_forward, "replay all earlier packets old-to-new"),
	V("revival", revival, "disable code that revives a connection that is supposed to stay up"),
	V("sa-creation", sa_creation, "fail all SA creation"),
	V("send-bogus-dcookie", send_bogus_dcookie, "causes pluto to send a a bogus IKEv2 DCOOKIE"),
	V("send-bogus-isakmp-flag", send_bogus_isakmp_flag, "causes pluto to set a RESERVED ISAKMP flag to test ignoring/zeroing it"),
	V("send-bogus-payload-flag", send_bogus_payload_flag, "causes pluto to set a RESERVED PAYLOAD flag to test ignoring/zeroing it"),
	V("send-key-size-check", send_key_size_check, "causes pluto to omit checking configured ESP key sizes for testing"),
	V("send-no-delete", send_no_delete, "causes pluto to omit sending Notify/Delete messages"),
	V("send-no-ikev2-auth", send_no_ikev2_auth, "causes pluto to omit sending an IKEv2 IKE_AUTH packet"),
	V("send-no-main-r2", send_no_main_r2, "causes pluto to omit sending an last Main Mode response packet"),
	V("send-no-xauth-r0", send_no_xauth_r0, "causes pluto to omit sending an XAUTH user/passwd request"),
	V("send-pkcs7-thingie", send_pkcs7_thingie, "send certificates as a PKCS7 thingie"),
	V("send-nonzero-reserved", send_nonzero_reserved, "send non-zero reserved fields in IKEv2 proposal fields"),
	V("send-nonzero-reserved-id", send_nonzero_reserved_id, "send non-zero reserved fields in IKEv2 ID payload that is part of the AUTH hash calculation"),
	V("suppress-retransmits", suppress_retransmits, "causes pluto to never send retransmits (wait the full timeout)"),
	V("timeout-on-retransmit", timeout_on_retransmit, "causes pluto to 'retry' (switch protocol) on the first retransmit"),

	V("v1-hash-check", v1_hash_check, "disable check of incoming IKEv1 hash payload"),
	V("v1-hash-exchange", v1_hash_exchange, "corrupt the HASH payload in the outgoing exchange",
	  .how_keywords = &impair_v1_exchange_keywords),
	V("v1-hash-payload", v1_hash_payload, "corrupt the emitted HASH payload",
	  .how_keywords = &impair_emit_keywords, .unsigned_help = "emit the hash payload filled with <unsigned> bytes"),

	V("tcp-use-blocking-write", tcp_use_blocking_write, "use a blocking write when sending TCP encapsulated IKE messages"),
	V("tcp-skip-setsockopt-espintcp", tcp_skip_setsockopt_espintcp, "skip the required setsockopt(\"espintcp\") call"),

	A("initiate-v2-liveness", INITIATE_v2_LIVENESS, 0, "initiate an IKEv2 liveness exchange", "IKE SA"),
	A("initiate-v2-delete", INITIATE_v2_DELETE, 0, "initiate an IKEv2 delete exchange", "SA"),
	A("initiate-v2-rekey", INITIATE_v2_REKEY, 0, "initiate an IKEv2 rekey using the CREATE_CHILD_SA exchange", "SA"),

	A("send-keepalive", SEND_KEEPALIVE, 0, "send a NAT keepalive packet", "SA"),

	V("add-unknown-v2-payload-to", add_unknown_v2_payload_to,
	  "impair the (unencrypted) part of the exchange",
	  .how_enum_names = &ikev2_exchange_names),
	V("add-unknown-v2-payload-to-sk", add_unknown_v2_payload_to_sk,
	  "impair the encrypted part of the exchange",
	  .how_enum_names = &ikev2_exchange_names),
	V("unknown-v2-payload-critical", unknown_v2_payload_critical,
	  "include the unknown payload in the encrypted SK payload"),

#undef V
#undef A

};

static void help(const char *prefix, const struct impairment *cr, FILE *file)
{
	fprintf(file, "%s%s: %s\n", prefix, cr->what, cr->help);
	if (cr->how_keywords != NULL) {
		const struct keywords *kw = cr->how_keywords;
		/* skip 0, always no */
		for (unsigned ki = 1; ki < kw->nr_values; ki++) {
			const struct keyword *kv = &kw->values[ki];
			if (kv->details != NULL) {
				fprintf(file, "%s    %s: %s\n",
					prefix, kv->sname, kv->details);
			}
		}
	}
	if (cr->how_enum_names != NULL) {
		bool first = true;
		for (long e = next_enum(cr->how_enum_names, -1); e >= 0;
		     e = next_enum(cr->how_enum_names, e)) {
			if (first) {
				fprintf(file, "%s    ", prefix);
				first = false;
			} else {
				fprintf(file, ", ");
			}
			const char *sname = enum_short_name(cr->how_enum_names, e);
			fprintf(file, "%s", sname);
		}
	}
	if (cr->unsigned_help != NULL) {
		fprintf(file, "%s  %s: %s\n",
			prefix, "<unsigned>", cr->unsigned_help);
	}
}

static void help_impair(const char *prefix, FILE *file)
{
	for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
		const struct impairment *cr = &impairments[ci];
		help(prefix, cr, file);
	}
}

/*
 * Return the long value in STRING, but with +ve values adjusted by
 * BIAS.  If the operation fails, zero is returned - bias must be
 * non-zero.
 */
static unsigned parse_biased_unsigned(shunk_t string, const struct impairment *cr)
{
	unsigned bias = cr->how_keywords != NULL ? cr->how_keywords->nr_values : 1;
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

enum impair_status parse_impair(const char *optarg,
				struct whack_impair *whack_impair,
				bool enable /* --impair ... vs --no-impair ...*/,
				const char *progname)
{
	if (streq(optarg, "help")) {
		help_impair("", stdout);
		return IMPAIR_HELP;
	}

	if (enable && streq(optarg, "none")) {
		*whack_impair = (struct whack_impair) {
			.what = IMPAIR_DISABLE,
			.how = 0,
		};
		return IMPAIR_OK;
	}

	if (enable && streq(optarg, "list")) {
		*whack_impair = (struct whack_impair) {
			.what = IMPAIR_LIST,
			.how = 0,
		};
		return IMPAIR_OK;
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
		fprintf(stderr, "%s: unrecognized impair option '"PRI_SHUNK"'\n",
			progname, pri_shunk(what));
		return IMPAIR_ERROR;
	}

	/*
	 * no matter how negated, "help" always works
	 */
	if (hunk_strcaseeq(how, "help") ||
	    hunk_strcaseeq(how, "?")) {
		help("", cr, stdout);
		return IMPAIR_HELP;
	}

	/*
	 * Reject overly negative or conflicting combinations.  For
	 * instance: --no-impair no-foo:bar.
	 */
	if ((!enable + what_no + (how.ptr != NULL)) > 1) {
		fprintf(stderr, "%s overly negative --%simpair %s",
			progname, enable ? "" : "no-", optarg);
		return IMPAIR_ERROR;
	}

	/*
	 * Always recognize "no".
	 */
	if (!enable || what_no || hunk_strcaseeq(how, "no")) {
		*whack_impair = (struct whack_impair) {
			.what = ci,
			.how = 0,
		};
		return IMPAIR_OK;
	}

	/*
	 * For WHAT:HOW, lookup the keyword HOW.
	 */
	if (cr->how_keywords != NULL) {
		/* try the keyword. */
		const struct keyword *kw = keyword_by_sname(cr->how_keywords, how);
		if (kw != NULL) {
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = kw->value,
			};
			return IMPAIR_OK;
		}
	} else if (cr->how_enum_names != NULL) {
		long e = enum_match(cr->how_enum_names, how);
		if (e >= 0) {
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = e,
			};
			return IMPAIR_OK;
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
			return IMPAIR_OK;
		}

		if (how.len == 0 || hunk_strcaseeq(how, "yes")) {
			/* --impair WHAT:yes or --impair WHAT */
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = true,
			};
			return IMPAIR_OK;
		}
	}

	if (cr->unsigned_help != NULL) {
		unsigned biased_value = parse_biased_unsigned(how, cr);
		if (biased_value > 0) {
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.how = biased_value,
			};
			return IMPAIR_OK;
		}
	}

fprintf(stderr, "%s: ignoring impair option '"PRI_SHUNK"' with unrecognized parameter '"PRI_SHUNK"' (%s)",
	progname, pri_shunk(what), pri_shunk(how), optarg);
	return IMPAIR_ERROR;
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
	if (cr->how_keywords != NULL) {
		const struct keyword *kw = keyword_by_value(cr->how_keywords, value);
		if (kw != NULL) {
			jam_string(buf, kw->sname);
		} else if (value >= cr->how_keywords->nr_values) {
			jam(buf, "%zu", value - cr->how_keywords->nr_values);
		} else {
			jam(buf, "?%u?", value);
		}
	} else if (cr->how_enum_names != NULL) {
		const char *sname = enum_short_name(cr->how_enum_names, value);
		if (sname != NULL) {
			jam_string(buf, sname);
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
		if (cr->action == CALL_IMPAIR_UPDATE &&
		    value_of(cr) != 0) {
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
		if (cr->action == CALL_IMPAIR_UPDATE &&
		    value_of(cr) != 0) {
			jam_string(buf, s); s = sep;
			jam_impairment(buf, cr);
		}
	}
}

bool process_impair(const struct whack_impair *wc,
		    void (*action)(enum impair_action, unsigned param,
				   unsigned update, bool background,
				   struct fd *whackfd),
		    bool background, struct fd *whackfd,
		    struct logger *logger)
{
	if (wc->what == 0) {
		/* ignore; silently */
		return true;
	} else if (wc->what == IMPAIR_DISABLE) {
		for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
			const struct impairment *cr = &impairments[ci];
			if (cr->action == CALL_IMPAIR_UPDATE &&
			    value_of(cr) != 0) {
				dbg("%s: disabled", cr->what);
				memset(cr->value, 0, cr->sizeof_value);
			}
		}
		return true;
	} else if (wc->what == IMPAIR_LIST) {
		for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
			const struct impairment *cr = &impairments[ci];
			if (cr->action == CALL_IMPAIR_UPDATE &&
			    value_of(cr) != 0) {
				LOG_MESSAGE(RC_COMMENT, logger, buf) {
					jam_impairment(buf, cr);
				}
			}
		}
		return true;
	} else if (wc->what >= elemsof(impairments)) {
		log_message(RC_LOG|ERROR_STREAM, logger,
			    "impairment %u out-of-range", wc->what);
		return false;
	}
	const struct impairment *cr = &impairments[wc->what];
	switch (cr->action) {
	case CALL_IMPAIR_UPDATE:
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
		/* log the update */
		LOG_MESSAGE(DEBUG_STREAM, logger, buf) {
			jam_impairment(buf, cr);
		}
		return true;
	case CALL_INITIATE_v2_DELETE:
	case CALL_INITIATE_v2_LIVENESS:
	case CALL_INITIATE_v2_REKEY:
	case CALL_SEND_KEEPALIVE:
	case CALL_GLOBAL_EVENT:
	case CALL_STATE_EVENT:
		/* how is always biased */
		if (action == NULL) {
			log_message(RC_LOG|DEBUG_STREAM, logger,
				    "no action for impairment %s", cr->what);
			return false;
		}
		action(cr->action, cr->param, wc->how, background, whackfd);
		return true;
	}
	/* not inside case */
	bad_case(cr->action);
}

/*
 * XXX: define these at the end of the file so that all references are
 * forced to use the extern declaration in the header (help stop code
 * referring to the wrong variable?).
 */

struct impair impair;
