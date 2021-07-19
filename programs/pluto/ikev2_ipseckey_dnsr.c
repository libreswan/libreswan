/*
 * low-level ipseckey lookup using libunbound ub_resolve_event call.
 *
 * Copyright (C) 2017-2019 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#ifndef USE_DNSSEC
# error this file should only be compiled when DNSSEC is defined
#endif

#include "ikev2_ipseckey_dnsr.h"
#include "defs.h"
#include "log.h"
#include <ldns/ldns.h>	/* from ldns-devel */
#include <ldns/rr.h>
#include <unbound.h>
#include "unbound-event.h"
#include "dnssec.h"	/* includes unbound.h */

struct p_dns_req *pluto_dns_list = NULL; /* DNS queries linked list */

void free_ipseckey_dns(struct p_dns_req *d)
{
	if (d == NULL)
		return;

	if (d->ub_async_id != 0) {
		ub_cancel(get_unbound_ctx(), d->ub_async_id);
		d->ub_async_id = 0;
	}

	/* XXX: free D, then remove D from a linked list?!?! */
	free_logger(&d->logger, HERE);
	pfreeany(d->qname);
	pfreeany(d->log_buf);

	struct p_dns_req **pp;
	struct p_dns_req *p;

	for (pp = &pluto_dns_list; (p = *pp) != NULL; pp = &p->next) {
		if (p == d) {
			*pp = p->next;	/* unlink this dns request */
			pfree(d);
			break;
		}
	}
}

static void dbg_log_dns_question(struct p_dns_req *dnsr,
		ldns_pkt *ldnspkt)
{
	ldns_buffer *output = ldns_buffer_new(dnsr->wire_len * 2);
	size_t i;

	for (i = 0; i < ldns_pkt_qdcount(ldnspkt); i++) {
		ldns_status status = ldns_rr2buffer_str_fmt(output,
				ldns_output_format_default,
				ldns_rr_list_rr(
					ldns_pkt_question(ldnspkt), i));
		if (status != LDNS_STATUS_OK) {
			llog(DEBUG_STREAM, dnsr->logger,
				    "could not parse DNS QUESTION section");
			return;
		}
	}

	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "DNS QUESTION ");
		jam_sanitized_bytes(buf, ldns_buffer_begin(output),
				    ldns_buffer_position(output));
	}
	ldns_buffer_free(output);
}

/*
 * Decode IPSECKEY RR from DNS
 *
 * See RFC 4025 "A Method for Storing IPsec Keying Material in DNS"
 * Section 3. "Presentation Formats"
 *
 * Precedence: decimal rep of 8 bits [we ignore this]
 * Gateway Type: decimal rep of 8 bits
 *	0: no gateway [we require this]
 *	1: gateway is IPv4 address
 *	2: gateway is IPv6 address
 *	3: gateway is a domain name
 * Algorithm: decimal rep of 8 bits
 *	0: no key
 *	1: DSA key (see RFC 2536)
 *	2: RSA key (see RFC 3110) [we require this]
 * Gateway: no gateway is denoted "." [we require this]
 * Public Key Block: bb64-encoded [we require this]
 *
 * Example:
 * 10 0 2 . AQPO39yuENlW ...
 * Precedence: 10
 * Gateway Type: 0 (no gateway)
 * Algorithm Type: 2 (RSA)
 * Gateway: . (no gateway)
 * Public Key Block: AQPO39yuENlW ...
 */

/*
 * next_rr_field:
 * A lot like strspn(stringp, " \t"), except that it ignores any amount
 * of whitespace before a field.  This means that empty fields are not
 * possible.
 */
static char *next_rr_field(char **stringp)
{
	for (;;) {
		char *r = strsep(stringp, " \t");
		if (r == NULL || *r != '\0')
			return r;
	}
}

extern const struct pubkey_type pubkey_type_rsa;

static bool extract_dns_pubkey(struct p_dns_req *dnsr, ldns_rdf *rdf, uint32_t ttl, struct dns_pubkey **dns_pubkeys)
{
	/* ??? would it not be easier to deal with the RDF form? */
	ldns_buffer *ldns_pkey = ldns_buffer_new((dnsr->wire_len * 8/6 + 2 + 1));
	ldns_status lerr = ldns_rdf2buffer_str_ipseckey(ldns_pkey, rdf);

	if (lerr != LDNS_STATUS_OK) {
		ldns_lookup_table *lt = ldns_lookup_by_id(ldns_error_str, lerr);
		llog(RC_LOG_SERIOUS, dnsr->logger,
			    "IPSECKEY rr parse error %s %s", lt->name, dnsr->log_buf);
		ldns_buffer_free(ldns_pkey);
		return false;
	}

	/* not const: we modify this buffer with strspn() */
	char *rrcursor = (char *)ldns_buffer_begin(ldns_pkey);

	(void) next_rr_field(&rrcursor);	/* Precedence (ignore) */
	const char *gwt = next_rr_field(&rrcursor);	/* Gateway Type */
	const char *algt = next_rr_field(&rrcursor);	/* Algorithm Type */
	const char *gw = next_rr_field(&rrcursor);	/* Gateway */
	const char *pubkey = next_rr_field(&rrcursor);	/* Public Key Block */
	const char *trailer = next_rr_field(&rrcursor);	/* whatever is left over */

	/*
	 * sanity check the fields (except for Precedence).
	 *
	 * Use the do() while(false) hack do deal with all the error
	 * exits.
	 */

	err_t ugh;

	do {
		if (pubkey == NULL) {
			ugh = "too few fields";
			break;
		}
		if (trailer != NULL) {
			ugh = "too many fields";
			break;
		}
		if (!streq(gwt + strspn(gwt, "0"), "")) {
			ugh = "Gateway Type must be 0";
			break;
		}
		if (!streq(algt + strspn(algt, "0"), "2")) {
			ugh = "Algorithm type must be 2 (RSA)";
			break;
		}
		if (!streq(gw, ".")) {
			ugh = "Gateway must be `.'";
			break;
		}

		/* over-allocate space to hold the key */
		size_t len = strlen(pubkey);
		struct dns_pubkey *dns_pubkey = alloc_bytes(sizeof(struct dns_pubkey) + len,
							    "temp pubkey bin store");
		dns_pubkey->type = &pubkey_type_rsa;
		dns_pubkey->ttl = ttl;

		char err_buf[TTODATAV_BUF];
		ugh = ttodatav(pubkey, len, 64, (char*)dns_pubkey->ptr, len, &dns_pubkey->len,
			       err_buf, sizeof(err_buf), 0);
		if (ugh != NULL) {
			pfree(dns_pubkey);
			break;
		}

		/*
		 * Sort the keys before inserting; sort key is
		 * arbitrary.
		 *
		 * This way test keys are added to pubkey DB in a
		 * predictable order.
		 *
		 * The alternative would be to keep the pubkey DB
		 * sorted.  What won't work is only sorting the keys
		 * when being listed - it turns out that the pubkey DB
		 * order is exposed when trying keys.
		 */
		while (*dns_pubkeys != NULL) {
			/* XXX: hunk_cmp()!?! */
			if (memcmp((*dns_pubkeys)->ptr, dns_pubkey->ptr,
				   min((*dns_pubkeys)->len, dns_pubkey->len)) < 0) {
				break;
			}
			if ((*dns_pubkeys)->len < dns_pubkey->len) {
				break;
			}
			dns_pubkeys = &(*dns_pubkeys)->next;
		}
		dns_pubkey->next = *dns_pubkeys;
		*dns_pubkeys = dns_pubkey;
		ugh = NULL;

	} while (false);

	if (ugh != NULL) {
		llog(RC_LOG_SERIOUS, dnsr->logger,
			    "ignoring IPSECKEY RR: %s", ugh);
	}

	ldns_buffer_free(ldns_pkey);

	return ugh == NULL;
}

static err_t parse_rr(struct p_dns_req *dnsr, ldns_pkt *ldnspkt)
{
	ldns_rr_list *answers = ldns_pkt_answer(ldnspkt);
	ldns_buffer *output = NULL;
	size_t i;

	dbg_log_dns_question(dnsr, ldnspkt);

	struct dns_pubkey *dns_pubkeys = NULL;

	for (i = 0; i < ldns_rr_list_rr_count(answers); i++) {
		ldns_rr *ans = ldns_rr_list_rr(answers, i);
		ldns_rr_type atype = ldns_rr_get_type(ans);
		ldns_rr_class qclass = ldns_rr_get_class(ans);
		ldns_lookup_table *class = ldns_lookup_by_id(ldns_rr_classes, qclass);
		ldns_lookup_table *class_e = ldns_lookup_by_id(ldns_rr_classes, dnsr->qclass);
		ldns_rdf *rdf;
		ldns_status status = LDNS_STATUS_OK;

		if (output != NULL)
			ldns_buffer_free(output);

		output = ldns_buffer_new((dnsr->wire_len * 8/6 + 2 +1) * 2);

		if (qclass != dnsr->qclass) {
			dbg("dns answer %zu qclass mismatch expect %s vs %s ignore the answer now",
			    i, class_e->name, class->name);
			/* unexpected qclass. possibly malfuctioning dns */
			continue;
		}

		rdf = ldns_rr_rdf(ans, 0);
		if (rdf == NULL) {
			dbg("dns answer %zu did not convert to rdf ignore this answer", i);
			continue;
		}

		if (ldns_rr_owner(ans)) {
			status = ldns_rdf2buffer_str_dname(output,
					ldns_rr_owner(ans));
		}
		if (status != LDNS_STATUS_OK) {
			continue;
		}
		ldns_buffer_printf(output, " %u ", ldns_rr_ttl(ans));
		status = ldns_rr_class2buffer_str(output,
				ldns_rr_get_class(ans));
		if (status != LDNS_STATUS_OK) {
			continue;
		}
		ldns_buffer_printf(output, " ");
		/* would this explod on unknown types? */
		status = ldns_rr_type2buffer_str(output, ldns_rr_get_type(ans));
		if (status != LDNS_STATUS_OK) {
			continue;
		}
		ldns_buffer_printf(output, " ");

		/* let's parse and debug log the usual RR types */
		switch (atype) {
		case LDNS_RR_TYPE_A:
			ldns_rdf2buffer_str_a(output, rdf);
			break;

		case LDNS_RR_TYPE_AAAA:
			ldns_rdf2buffer_str_aaaa(output, rdf);
			break;

		case LDNS_RR_TYPE_TXT:
			ldns_rdf2buffer_str_str(output, rdf);
			break;

		case LDNS_RR_TYPE_NS:
			ldns_rdf2buffer_str_dname(output, rdf);
			break;

		case LDNS_RR_TYPE_IPSECKEY:
			ldns_rdf2buffer_str_ipseckey(output, rdf);
			break;
		default:
			ldns_buffer_free(output);
			output = NULL;
			continue;
		}

		dbg("%s", ldns_buffer_begin(output));
		ldns_buffer_free(output);
		output = NULL;

		if (dnsr->validate_address_cb) {
			dnsr->validate_address_cb(dnsr, ldns_rdf_data(rdf));
		}

		if (dnsr->qtype == atype && atype == LDNS_RR_TYPE_IPSECKEY) {
			extract_dns_pubkey(dnsr, rdf, ldns_rr_ttl(ans), &dns_pubkeys);
		}

		if (atype != dnsr->qtype) {
			/* dns server stuffed extra rr types, ignore */
			dbg("dns answer %zu qtype mismatch expect %d vs %d ignore this answer",
			    i, dnsr->qtype, atype);
		}
	}

	if (dns_pubkeys == NULL) {
		return "nothing to add";
	}

	if (dnsr->pubkeys_cb) {
		dnsr->pubkeys_cb(dnsr, dns_pubkeys);
	}
	while (dns_pubkeys != NULL) {
		struct dns_pubkey *tbd = dns_pubkeys;
		dns_pubkeys = dns_pubkeys->next;
		pfree(tbd);
	}
	return NULL;
}

/* This is called when dns response arrives */
err_t process_dns_resp(struct p_dns_req *dnsr)
{
	if (dnsr->rcode != 0 ) {
		return dnsr->rcode_name;
	}

	ldns_pkt *ldnspkt = NULL;
	ldns_status status = ldns_wire2pkt(&ldnspkt, dnsr->wire, dnsr->wire_len);

	if (status != LDNS_STATUS_OK) {
		return "ldns could not parse response wire format";
	}

	if (ldns_rr_list_rr_count(ldns_pkt_answer(ldnspkt)) == 0) {
		return "DNS response contains no answer";
	}

	switch (dnsr->secure) {
	default:	/* treat as bogus */
	case UB_EVENT_BOGUS:
		return "unbound returned BOGUS response - ignored";

	case UB_EVENT_INSECURE:
		if (impair.allow_dns_insecure) {
			llog(RC_LOG, dnsr->logger,
				    "IMPAIR: allowing insecure DNS response");
			return parse_rr(dnsr, ldnspkt);
		}
		return "unbound returned INSECURE response - ignored";

	case UB_EVENT_SECURE:
		return parse_rr(dnsr, ldnspkt);
	}
}

void ikev2_ipseckey_log_missing_st(struct p_dns_req *dnsr)
{
	deltatime_t served_delta = realtimediff(dnsr->done_time, dnsr->start_time);
	deltatime_buf db;
	llog(RC_LOG_SERIOUS, dnsr->logger,
		    "the state is gone; %s returned %s elapsed time %s seconds",
		    dnsr->log_buf, dnsr->rcode_name,
		    str_deltatime(served_delta, &db));
}

void ipseckey_dbg_dns_resp(struct p_dns_req *dnsr)
{
	deltatime_t served_delta = realtimediff(dnsr->done_time, dnsr->start_time);
	deltatime_buf db;
	dbg("%s returned %s cache=%s elapsed time %s seconds",
	    dnsr->log_buf,
	    dnsr->rcode_name,
	    bool_str(dnsr->cache_hit),
	    str_deltatime(served_delta, &db));

	if (DBGP(DBG_BASE)) {
		const enum lswub_resolve_event_secure_kind k = dnsr->secure;

		DBG_log("DNSSEC=%s %s MSG SIZE %d bytes",
			k == UB_EVENT_SECURE ? "SECURE"
			: k == UB_EVENT_INSECURE ? "INSECURE"
			: k == UB_EVENT_BOGUS ? "BOGUS"
			: "invalid lswub_resolve_event_secure_kind",

			k == UB_EVENT_BOGUS ? dnsr->why_bogus : "",
			dnsr->wire_len);
	}
}

static void ipseckey_ub_cb(void* mydata, int rcode,
		void *wire, int wire_len, int secure, char* why_bogus
#if (UNBOUND_VERSION_MAJOR == 1 && UNBOUND_VERSION_MINOR >= 8) || UNBOUND_VERSION_MAJOR > 1
		, int was_ratelimited UNUSED
#endif
		)
{
	struct p_dns_req *dnsr = (struct p_dns_req *)mydata;
	ldns_lookup_table *rcode_txt;

	dnsr->rcode = rcode;
	/* do not free 'wire' */
	dnsr->wire = wire;
	dnsr->wire_len = wire_len;
	dnsr->secure = secure;
	dnsr->why_bogus = why_bogus;

	rcode_txt = ldns_lookup_by_id(ldns_rcodes, dnsr->rcode);
	dnsr->rcode_name = rcode_txt->name;

	dnsr->cb(dnsr);
}

stf_status dns_qry_start(struct p_dns_req *dnsr)
{
	int ub_ret;
	stf_status ret;

	passert(get_unbound_ctx() != NULL);

	llog(DEBUG_STREAM, dnsr->logger, "start %s", dnsr->log_buf);

	dnsr->start_time = realnow();

	ub_ret = ub_resolve_event(get_unbound_ctx(), dnsr->qname, dnsr->qtype,
				  dnsr->qclass, dnsr, ipseckey_ub_cb, &dnsr->ub_async_id);

	if (ub_ret != 0) {
		llog(RC_LOG_SERIOUS, dnsr->logger,
			    "unbound resolve call failed for %s", dnsr->log_buf);
		free_ipseckey_dns(dnsr);
		return STF_FAIL;
	}

	ret = dnsr->stf_status;
	if (dnsr->stf_status == STF_SUSPEND) {
		dnsr->cache_hit = FALSE;
	} else {
		free_ipseckey_dns(dnsr);
	}

	return ret;
}

