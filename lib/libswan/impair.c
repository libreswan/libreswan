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
#include "whack.h"

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
	 * When .how_keywords is non-NULL, HOW is the unbiased value
	 * of the keyword.  It's assumed that any keyword with the
	 * value 0 disables the impairment.
	 *
	 * And when .unsigned_help is also non-NULL, HOW can be an
	 * unsigned number encoded as .keywords .nr_keywords +
	 * UNSIGNED.
	 */
	const struct keywords *how_keywords;
	/*
	 * (else)
	 *
	 * When .how_enum_names is non-NULL, HOW is the unbiased enum
	 * name's value.  It's assumed that any enum-name with the
	 * value 0 disables the impairment.
	 *
	 * And when .unsigned_help is also non-NULL, HOW can be an
	 * unsigned value which is passed unchanged (again 0 implies
	 * disabled).
	 *
	 * If 0 is ever needed then the field can be changed to
	 * impair_unsigned.
	 */
	const struct enum_names *how_enum_names;
	/*
	 * (else)
	 *
	 * When .unsigned_help is non-NULL, HOW is the unsigned value.
	 *
	 * Note: either the value is a struct impair_unsigned which as
	 * an enabled bit, or the value is being used for an event.
	 */
	const char *unsigned_help;
	/*
	 * Location of the value to update, and, optionally, the bit
	 * to set/clear.
	 */
	void *value;
	size_t sizeof_value;
	bool *enabled;		/* possibly NULL enabled bit */
	/*
	 * Operations.
	 */
	enum impair_action action;
	unsigned param;
};

struct impairment impairments[] = {
	{ .what = NULL, },

#define A(WHAT, ACTION, PARAM, HELP, UNSIGNED_HELP, ...)	\
	{							\
		.what = WHAT,					\
		.action = CALL_##ACTION,			\
		.param = PARAM,					\
		.help = HELP,					\
		.unsigned_help = UNSIGNED_HELP,			\
		##__VA_ARGS__,					\
	}
#define V(VALUE, HELP, ...)				\
	{						\
		.what = #VALUE,				\
		.action = CALL_IMPAIR_UPDATE,		\
		.value = &impair.VALUE,			\
		.help = HELP,				\
		.sizeof_value = sizeof(impair.VALUE),	\
		##__VA_ARGS__,				\
	}
#define B(VALUE, HELP)					\
	{						\
		.what = #VALUE,				\
		.action = CALL_IMPAIR_UPDATE,		\
		.help = HELP,				\
		.value = &impair.VALUE,			\
		.sizeof_value = sizeof(impair.VALUE),	\
	}
#define U(VALUE, HELP)						\
	{							\
		.what = #VALUE,					\
		.action = CALL_IMPAIR_UPDATE,			\
		.help = HELP,					\
		.value = &impair.VALUE.value,			\
		.sizeof_value = sizeof(impair.VALUE.value),	\
		.enabled = &impair.VALUE.enabled,		\
		.unsigned_help = "<unsigned>",			\
	}

	B(allow_dns_insecure, "allow IPSECKEY lookups without DNSSEC protection"),
	B(allow_null_none, "cause pluto to allow esp=null-none and ah=none for testing"),
	B(bad_ike_auth_xchg, "causes pluto to send IKE_AUTH replies with wrong exchange type"),
	B(bust_mi2, "make MI2 really large"),
	B(bust_mr2, "make MR2 really large"),
	V(child_key_length_attribute, "corrupt the outgoing CHILD proposal's key length attribute",
	  .how_keywords = &impair_emit_keywords,
	  .unsigned_help = "emit <unsigned> as the key length"),
	B(corrupt_encrypted, "corrupts the encrypted packet so that the decryption fails"),
	B(drop_i2, "drop second initiator packet"),
	B(drop_xauth_r0, "causes pluto to drop an XAUTH user/passwd request on IKE initiator"),
	B(emitting, "disable correctness-checks when emitting a payload (let anything out)"),
	B(force_fips, "causes pluto to believe we are in fips mode, NSS needs its own hack"),
	V(ike_key_length_attribute, "corrupt the outgoing IKE proposal's key length attribute",
	  .how_keywords = &impair_emit_keywords,
	  .unsigned_help = "emit <unsigned> as the key length"),

	U(ike_initiator_spi, "corrupt the IKE initiator SPI setting it to the <unsigned> value"),
	U(ike_responder_spi, "corrupt the IKE responder SPI setting it to the <unsigned> value"),

	B(ikev1_del_with_notify, "causes pluto to send IKE Delete with additional bogus Notify payload"),

	V(v2_proposal_integ, "integrity in proposals",
	  .how_keywords = &impair_v2_transform_keywords),
	V(v2_proposal_dh, "dh in proposals",
	  .how_keywords = &impair_v2_transform_keywords),

	U(ikev2_add_ike_transform, "add an extra (possibly bogus) TYPE transform with ID to the first IKE proposal (<unsigned> is encoded as TYPE<<16|ID)"),
	U(ikev2_add_child_transform, "add an extra (possibly bogus) TYPE transform with ID to the first CHILD proposal (<unsigned> is encoded as TYPE<<16|ID)"),

	B(jacob_two_two, "cause pluto to send all messages twice."),
	V(ke_payload, "corrupt the outgoing KE payload",
	  .how_keywords = &impair_emit_keywords,
	  .unsigned_help = "emit the KE payload filled with <unsigned> bytes"),
	B(log_rate_limit, "set the per-hour(?) cap on rate-limited log messages"),
	B(major_version_bump, "cause pluto to send an IKE major version that's higher then we support."),
	B(minor_version_bump, "cause pluto to send an IKE minor version that's higher then we support."),
	B(childless_ikev2_supported, "causes pluto to omit/ignore the CHILDLESS_IKEV2_SUPPORTED notify in the IKE_SA_INIT exchange"),

	B(ignore_v2N_SIGNATURE_HASH_ALGORITHMS, "causes pluto to ignore the notification SIGNATURE_HASH_ALGORITHMS in the IKE_SA_INIT exchange"),
	B(omit_v2N_SIGNATURE_HASH_ALGORITHMS, "causes pluto to omit the notification SIGNATURE_HASH_ALGORITHMS in the IKE_SA_INIT exchange"),

	B(proposal_parser, "impair algorithm parser - what you see is what you get"),
	B(rekey_initiate_supernet, "impair IPsec SA rekey initiator TSi and TSR to 0/0 ::0, emulate Windows client"),
	B(rekey_initiate_subnet, "impair IPsec SA rekey initiator TSi and TSR to X/32 or X/128"),
	B(rekey_respond_supernet, "impair IPsec SA rekey responder TSi and TSR to 0/0 ::0"),
	B(rekey_respond_subnet, "impair IPsec SA rekey responder TSi and TSR to X/32 X/128"),
	B(replay_encrypted, "replay encrypted packets"),
	B(revival, "disable code that revives a connection that is supposed to stay up"),
	B(send_bogus_dcookie, "causes pluto to send a a bogus IKEv2 DCOOKIE"),
	B(send_bogus_isakmp_flag, "causes pluto to set a RESERVED ISAKMP flag to test ignoring/zeroing it"),
	B(send_bogus_payload_flag, "causes pluto to set a RESERVED PAYLOAD flag to test ignoring/zeroing it"),
	B(send_key_size_check, "causes pluto to omit checking configured ESP key sizes for testing"),
	B(send_no_delete, "causes pluto to omit sending Notify/Delete messages"),
	B(send_no_ikev2_auth, "causes pluto to omit sending an IKEv2 IKE_AUTH packet"),
	B(send_no_main_r2, "causes pluto to omit sending an last Main Mode response packet"),
	B(send_no_xauth_r0, "causes pluto to omit sending an XAUTH user/passwd request"),
	B(send_no_idr, "causes pluto as initiator to omit sending an IDr payload"),
	B(send_pkcs7_thingie, "send certificates as a PKCS7 thingie"),
	B(send_nonzero_reserved, "send non-zero reserved fields in IKEv2 proposal fields"),
	B(send_nonzero_reserved_id, "send non-zero reserved fields in IKEv2 ID payload that is part of the AUTH hash calculation"),
	B(suppress_retransmits, "causes pluto to never send retransmits (wait the full timeout)"),
	B(timeout_on_retransmit, "causes pluto to 'retry' (switch protocol) on the first retransmit"),

	B(event_check_crls, "do not schedule the CRL check event"),

	B(v1_hash_check, "disable check of incoming IKEv1 hash payload"),
	V(v1_hash_exchange, "corrupt the HASH payload in the outgoing exchange",
	  .how_keywords = &impair_v1_exchange_keywords),
	V(v1_hash_payload, "corrupt the emitted HASH payload",
	  .how_keywords = &impair_emit_keywords,
	  .unsigned_help = "emit the hash payload filled with <unsigned> bytes"),

	B(tcp_use_blocking_write, "use a blocking write when sending TCP encapsulated IKE messages"),
	B(tcp_skip_setsockopt_espintcp, "skip the required setsockopt(\"espintcp\") call"),

	/*
	 * Impair message flow.
	 */

	A("drop_inbound", IMPAIR_MESSAGE_DROP, IMPAIR_INBOUND_MESSAGE,
	  "drop the N'th inbound message", "message number"),
	A("drop_outbound", IMPAIR_MESSAGE_DROP, IMPAIR_OUTBOUND_MESSAGE,
	  "drop the N'th outbound message", "message number"),

	A("block_inbound", IMPAIR_MESSAGE_BLOCK, IMPAIR_INBOUND_MESSAGE,
	  "block all inbound messages", NULL),
	A("block_outbound", IMPAIR_MESSAGE_BLOCK, IMPAIR_OUTBOUND_MESSAGE,
	  "block all outbound messages", NULL),

	A("drip_inbound", IMPAIR_MESSAGE_DRIP, IMPAIR_INBOUND_MESSAGE,
	  "drip N'th inbound message", "message number"),
	A("drip_outbound", IMPAIR_MESSAGE_DRIP, IMPAIR_OUTBOUND_MESSAGE,
	  "drip N'th outbound message", "message number"),

	A("duplicate_inbound", IMPAIR_MESSAGE_DUPLICATE, IMPAIR_INBOUND_MESSAGE,
	  "duplicate each inbound packet", NULL),
	A("duplicate_outbound", IMPAIR_MESSAGE_DUPLICATE, IMPAIR_OUTBOUND_MESSAGE,
	  "duplicate each outbound packet", NULL),

	A("replay_inbound", IMPAIR_MESSAGE_REPLAY, IMPAIR_INBOUND_MESSAGE,
	  "replay all inbound packets old-to-new", NULL),
	A("replay_outbound", IMPAIR_MESSAGE_REPLAY, IMPAIR_OUTBOUND_MESSAGE,
	  "replay all outbound packets old-to-new", NULL),

	/*
	 * Mangle payloads.
	 */

	V(add_unknown_v2_payload_to, "impair the (unencrypted) part of the exchange",
	  .how_enum_names = &ikev2_exchange_names),
	V(add_unknown_v2_payload_to_sk, "impair the encrypted part of the exchange",
	  .how_enum_names = &ikev2_exchange_names),
	B(unknown_v2_payload_critical, "include the unknown payload in the encrypted SK payload"),
	B(ignore_soft_expire, "ignore kernel soft expire events"),
	B(ignore_hard_expire, "ignore kernel hard expire events"),

	V(force_v2_auth_method, "force the use of the specified IKEv2 AUTH method",
	  .how_enum_names = &ikev2_auth_method_names),

	B(omit_v2_ike_auth_child, "omit, and don't expect, CHILD SA payloads in IKE_AUTH message"),
	B(ignore_v2_ike_auth_child, "ignore, but do expect, CHILD SA payloads in the IKE_AUTH message"),

	/*
	 * Trigger global event.
	 */

	A("trigger", GLOBAL_EVENT_HANDLER, 0, "trigger the global event", "EVENT",
	  .how_enum_names = &global_timer_names),

	/*
	 * Trigger state event.
	 */

	A("trigger_v2_rekey", STATE_EVENT_HANDLER, EVENT_v2_REKEY,
	  "trigger the rekey event", "#SA"),
	A("trigger_v2_liveness", STATE_EVENT_HANDLER, EVENT_v2_LIVENESS,
	  "trigger the liveness event", "#SA"),
	A("trigger_v1_replace", STATE_EVENT_HANDLER, EVENT_v1_REPLACE,
	  "trigger the IKEv1 replace event", "#SA"),
	A("trigger_v2_replace", STATE_EVENT_HANDLER, EVENT_v2_REPLACE,
	  "trigger the IKEv2 replace event", "#SA"),

	/*
	 * Trigger connection event.
	 */

	A("trigger_revival", CONNECTION_EVENT_HANDLER, CONNECTION_REVIVAL,
	  "trigger the revival event", "$CONNECTION"),

	/*
	 * Force the event (bypassing most of the should I do this
	 * logic).
	 */

	A("initiate_v2_liveness", INITIATE_v2_LIVENESS, 0,
	  "initiate an IKEv2 liveness exchange", "IKE SA"),
	A("send_keepalive", SEND_KEEPALIVE, 0,
	  "send a NAT keepalive packet", "SA"),

	B(cannot_ondemand, "force acquire to call cannot_ondemand() and fail"),

	U(number_of_TSi_selectors, "set the number of selectors in the TSi payload to the bogus <unsigned>"),
	U(number_of_TSr_selectors, "set the number of selectors in the TSr payload to the bogus <unsigned>"),

	B(lifetime, "skip any IKE/IPsec lifetime checks when adding connection"),

	B(copy_v1_notify_response_SPIs_to_retransmission, "copy SPIs in IKEv1 notify response to last sent packet and then retransmit"),

	U(v1_remote_quick_id, "set the remote quick ID to <unsigned>"),

	V(v1_isakmp_delete_payload, "corrupt outgoing ISAKMP delete payload",
	  .how_keywords = &impair_emit_keywords),

	V(v1_ipsec_delete_payload, "corrupt outgoing IPsec delete payload",
	  .how_keywords = &impair_emit_keywords),

	U(v2_delete_protoid, "corrupt the IKEv2 Delete protocol ID"),
	U(v2n_rekey_sa_protoid, "corrupt the IKEv2 REKEY CHILD notify protocol ID"),
	U(v2_proposal_protoid, "corrupt the IKEv2 proposal substructure protocol ID"),

	U(helper_thread_delay, "pause <unsigned> seconds before starting each helper thread job"),

	B(install_ipsec_sa_inbound_state, "error after installing the inbound IPsec SA state (but before policy)"),
	B(install_ipsec_sa_inbound_policy, "error after installing the inbound IPsec SA policy (and state)"),
	B(install_ipsec_sa_outbound_state, "error after installing the outbound IPsec SA state (but before policy)"),
	B(install_ipsec_sa_outbound_policy, "error after installing the outbound IPsec SA policy (and state)"),

#undef U
#undef B
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
			const char *sname = enum_name_short(cr->how_enum_names, e);
			fprintf(file, "%s", sname);
		}
		fprintf(file, "\n");
	}
	if (cr->unsigned_help != NULL) {
		fprintf(file, "%s  %s: %s\n",
			prefix, "<unsigned>", cr->unsigned_help);
	}
}

static void help_impair(const char *prefix, FILE *file)
{
	for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
		const struct impairment *impairment = &impairments[ci];
		help(prefix, impairment, file);
	}
}

/*
 * Try to bias VALUE.  When the BIAS would overflow log and fail.
 */

static bool bias_uintmax(const struct impairment *impairment,
			 unsigned bias, uintmax_t *value,
			 struct logger *logger)
{
	/*
	 * Does the result fit?
	 *
	 * Start with 0xff..ff, and then right shift it so it is the
	 * MAX of the value.
	 */
	unsigned drop = sizeof(uintmax_t) - impairment->sizeof_value;
	uintmax_t max = ((uintmax_t)UINTMAX_MAX) >> drop;
	if (*value > max - bias) {
		llog(ERROR_STREAM, logger,
		     "impair option '%s' value '%ju' overflows",
		     impairment->what, *value);
		return false;
	}

	*value += bias;
	return true;
}

/*
 * Optionally parse value as a uintmax.
 *
 * Used by keyword and enum cases when unsigned is an allowed
 * fallback.  Hence only consider the bias operation an error.
 */
static bool parse_uintmax(shunk_t string,
			  const struct impairment *impairment,
			  unsigned bias,
			  struct whack_impair *whack_impair,
			  struct logger *logger)
{
	if (impairment->unsigned_help == NULL) {
		return 0;
	}

	uintmax_t value;
	if (shunk_to_uintmax(string, NULL, 0/*base*/, &value) != NULL) {
		return 0;
	}

	if (!bias_uintmax(impairment, bias, &value, logger)) {
		/* already logged */
		return IMPAIR_ERROR;
	}

	*whack_impair = (struct whack_impair) {
		.what = impairment - impairments, /*i.e., index*/
		.value = value,
		.enable = (value > 0),
	};
	return IMPAIR_OK;
}

#define IMPAIR_NONE (elemsof(impairments) + 0)
#define IMPAIR_LIST (elemsof(impairments) + 1)

enum impair_status parse_impair(const char *optarg,
				struct whack_impair *whack_impair,
				bool enable /* --impair ... vs --no-impair ...*/,
				struct logger *logger)
{
	if (streq(optarg, "help")) {
		help_impair("", stdout);
		return IMPAIR_HELP;
	}

	if (enable && streq(optarg, "none")) {
		*whack_impair = (struct whack_impair) {
			.what = IMPAIR_NONE,
		};
		return IMPAIR_OK;
	}

	if (enable && streq(optarg, "list")) {
		*whack_impair = (struct whack_impair) {
			.what = IMPAIR_LIST,
		};
		return IMPAIR_OK;
	}

	/* Break OPTARG into WHAT[=BIASED_VALUE] */
	shunk_t arg = shunk1(optarg);
	shunk_t what = shunk_token(&arg, NULL, ":=");
	shunk_t how = arg;

	/*
	 * look for both WHAT and for compatibility with the old
	 * lset_t impair flags, no-WHAT.
	 */

	bool what_no = hunk_strcaseeat(&what, "no-");
	unsigned ci = 1;
	const struct impairment *impairment = NULL;
	for (ci = 1/*skip 0*/; ci < elemsof(impairments); ci++) {
		if (hunk_strcaseeq(what, impairments[ci].what)) {
			impairment = &impairments[ci];
			break;
		}
	}
	if (impairment == NULL) {
		llog(ERROR_STREAM, logger,
			    "unrecognized impair option '"PRI_SHUNK"'\n",
			    pri_shunk(what));
		return IMPAIR_ERROR;
	}

	/*
	 * no matter how negated, "help" always works
	 */
	if (hunk_strcaseeq(how, "help") ||
	    hunk_strcaseeq(how, "?")) {
		help("", impairment, stdout);
		return IMPAIR_HELP;
	}

	/*
	 * Reject overly negative or conflicting combinations.  For
	 * instance: --no-impair no-foo:bar.
	 */
	if ((!enable + what_no + (how.ptr != NULL)) > 1) {
		llog(ERROR_STREAM, logger,
			    "overly negative --%simpair %s",
			    enable ? "" : "no-", optarg);
		return IMPAIR_ERROR;
	}

	/*
	 * Always recognize "no".
	 */
	if (!enable || what_no || hunk_strcaseeq(how, "no")) {
		*whack_impair = (struct whack_impair) {
			.what = ci,
			.value = 0,
			.enable = false,
		};
		return IMPAIR_OK;
	}

	/*
	 * For WHAT:HOW, lookup the keyword HOW.
	 */
	if (impairment->how_keywords != NULL) {
		/* try the keyword. */
		const struct keyword *kw = keyword_by_sname(impairment->how_keywords, how);
		if (kw != NULL) {
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.value = kw->value, /* unbiased */
			};
			return IMPAIR_OK;
		}
		/* try unsigned */
		enum impair_status status = parse_uintmax(how, impairment,
							  impairment->how_keywords->nr_values,
							  whack_impair, logger);
		if (status != 0) {
			/* either saved, or error */
			return status;
		}
		/* error */
	} else if (impairment->how_enum_names != NULL) {
		long e = enum_match(impairment->how_enum_names, how);
		if (e >= 0) {
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.value = e, /* unbiased */
			};
			return IMPAIR_OK;
		}
		/* try unsigned */
		enum impair_status status = parse_uintmax(how, impairment,
							  /*no-bias*/0,
							  whack_impair,
							  logger);
		if (status != 0) {
			/* either saved, or error */
			return status;
		}
		/* error */
	} else if (impairment->unsigned_help != NULL) {
		uintmax_t value;
		err_t err = shunk_to_uintmax(how, NULL, 0/*base*/, &value);
		if (err != NULL) {
			llog(ERROR_STREAM, logger,
			     "impair option '"PRI_SHUNK"' has invalid parameter '"PRI_SHUNK"': %s",
			     pri_shunk(what), pri_shunk(how), err);
			return IMPAIR_ERROR;
		}
		/* never bias; checks for size */
		unsigned bias = 0;
		if (!bias_uintmax(impairment, bias, &value, logger)) {
			/* already logged */
			return IMPAIR_ERROR;
		}
		*whack_impair = (struct whack_impair) {
			.what = ci,
			.value = value,
			.enable = true,
		};
		return IMPAIR_OK;
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
				.value = false,
				.enable = false,
			};
			return IMPAIR_OK;
		}

		if (how.len == 0 || hunk_strcaseeq(how, "yes")) {
			/* --impair WHAT:yes or --impair WHAT */
			*whack_impair = (struct whack_impair) {
				.what = ci,
				.value = true,
				.enable = true,
			};
			return IMPAIR_OK;
		}
		/* error */
	}

	llog(ERROR_STREAM, logger,
		    "impair option '"PRI_SHUNK"' has unrecognized parameter '"PRI_SHUNK"'",
		    pri_shunk(what), pri_shunk(how));
	return IMPAIR_ERROR;
}

/*
 * Print something that can be fed back into --impair ARG.
 */

static uintmax_t value_of(const struct impairment *impairment)
{
	switch (impairment->sizeof_value) {
#define L(T) case sizeof(uint##T##_t): return *(uint##T##_t*)impairment->value
		L(8);
		L(16);
		L(32);
		L(64);
#undef L
	default:
		bad_case(impairment->sizeof_value);
	}
}

static bool impairment_enabled(const struct impairment *impairment)
{
	if (impairment->action != CALL_IMPAIR_UPDATE) {
		return false;
	}
	/* flip logic */
	if (impairment->enabled != NULL && *impairment->enabled) {
		return true;
	}
	if (value_of(impairment) != 0) {
		return true;
	}
	return false;
}


static void jam_impairment_value(struct jambuf *buf,
				 const struct impairment *impairment)
{
	uintmax_t value = value_of(impairment);
	if (impairment->how_keywords != NULL) {
		const struct keyword *kw = keyword_by_value(impairment->how_keywords, value);
		if (kw != NULL) {
			jam_string(buf, kw->sname);
		} else if (value >= impairment->how_keywords->nr_values) {
			/*unbias*/
			jam(buf, "%ju", value - impairment->how_keywords->nr_values);
		} else {
			jam(buf, "?%ju?", value);
		}
	} else if (impairment->how_enum_names != NULL) {
		const char *sname = enum_name_short(impairment->how_enum_names, value);
		if (sname != NULL) {
			jam_string(buf, sname);
		} else {
			jam(buf, "%ju", value);
		}
	} else if (impairment->unsigned_help != NULL &&
		   impairment->enabled != NULL) {
		if (*impairment->enabled) {
			jam(buf, "%ju", value);
		} else {
			jam_string(buf, "no");
		}
	} else if (impairment->unsigned_help != NULL) {
		/* should have .enabled */
		jam(buf, "?%ju?", value);
	} else {
		switch (value) {
		case 0: jam(buf, "no"); break;
		case 1: jam(buf, "yes"); break;
		default: jam(buf, "?%ju?", value);
		}
	}
}

static void jam_impairment(struct jambuf *buf,
			   const struct impairment *impairment)
{
	jam_string(buf, impairment->what);
	jam_string(buf, ":");
	jam_impairment_value(buf, impairment);
}

bool have_impairments(void)
{
	/* is there anything enabled? */
	for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
		const struct impairment *impairment = &impairments[ci];
		if (impairment_enabled(impairment)) {
			return true;
		}
	}
	return false;
}

void jam_impairments(struct jambuf *buf, const char *sep)
{
	const char *s = "";
	for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
		const struct impairment *impairment = &impairments[ci];
		if (impairment_enabled(impairment)) {
			jam_string(buf, s);
			s = sep;
			jam_impairment(buf, impairment);
		}
	}
}

static void process_impair_update(const struct impairment *impairment,
				  const struct whack_impair *wc,
				  struct logger *logger)
{
	LLOG_JAMBUF(LOG_STREAM, logger, buf) {
		/*
		 * XXX: lower case "impair:" for updates; upper case
		 * "IMPAIR:" for actions.
		 */
		jam_string(buf, "impair: ");
		jam_string(buf, impairment->what);
		jam_string(buf, ": ");
		/* old value */
		jam_impairment_value(buf, impairment);
		/* update */
		switch (impairment->sizeof_value) {
#define L(T) case sizeof(uint##T##_t):					\
			{						\
				*(uint##T##_t*)impairment->value = wc->value; \
				break;					\
			}
			L(8);
			L(16);
			L(32);
			L(64);
#undef L
		default:
			bad_case(impairment->sizeof_value);
		}
		if (impairment->enabled != NULL) {
			*impairment->enabled = wc->enable;
		}
		/* new value */
		jam_string(buf, " -> ");
		jam_impairment_value(buf, impairment);
	}
}

static void process_impair_none(struct logger *logger)
{
	for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
		const struct impairment *impairment = &impairments[ci];
		if (impairment_enabled(impairment)) {
			struct whack_impair wc = {0}; /* i.e., none */
			process_impair_update(impairment, &wc, logger);
		}
	}
}

static void process_impair_list(struct logger *logger)
{
	for (unsigned ci = 1; ci < elemsof(impairments); ci++) {
		const struct impairment *impairment = &impairments[ci];
		if (impairment_enabled(impairment)) {
			LLOG_JAMBUF(RC_COMMENT, logger, buf) {
				jam_impairment(buf, impairment);
			}
		}
	}
}

bool process_impair(const struct whack_impair *wc,
		    void (*action)(enum impair_action impairment_action,
				   unsigned impairment_param,
				   bool whack_enable,
				   unsigned whack_value,
				   bool background,
				   struct logger *logger),
		    bool background, struct logger *logger)
{
	if (wc->what == 0) {
		/* ignore; silently */
		return true;
	} else if (wc->what == IMPAIR_NONE) {
		process_impair_none(logger);
		return true;
	} else if (wc->what == IMPAIR_LIST) {
		process_impair_list(logger);
		return true;
	} else if (wc->what >= elemsof(impairments)) {
		llog(RC_LOG|ERROR_STREAM, logger,
			    "impairment %u out-of-range", wc->what);
		return false;
	}
	const struct impairment *impairment = &impairments[wc->what];
	switch (impairment->action) {
	case CALL_IMPAIR_UPDATE:
		/* log the update; but not to whack */
		process_impair_update(impairment, wc, logger);
		return true;
	case CALL_INITIATE_v2_LIVENESS:
	case CALL_SEND_KEEPALIVE:
	case CALL_GLOBAL_EVENT_HANDLER:
	case CALL_STATE_EVENT_HANDLER:
	case CALL_CONNECTION_EVENT_HANDLER:
	case CALL_IMPAIR_MESSAGE_DROP:
	case CALL_IMPAIR_MESSAGE_BLOCK:
	case CALL_IMPAIR_MESSAGE_DRIP:
	case CALL_IMPAIR_MESSAGE_DUPLICATE:
	case CALL_IMPAIR_MESSAGE_REPLAY:
		if (action == NULL) {
			llog(RC_LOG|DEBUG_STREAM, logger,
				    "no action for impairment %s", impairment->what);
			return false;
		}
		action(impairment->action, impairment->param,
		       wc->enable, wc->value,
		       background, logger);
		return true;
	}
	/* not inside case */
	bad_case(impairment->action);
}

/*
 * XXX: define these at the end of the file so that all references are
 * forced to use the extern declaration in the header (help stop code
 * referring to the wrong variable?).
 */

struct impair impair;
