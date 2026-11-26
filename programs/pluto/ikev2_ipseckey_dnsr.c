/*
 * low-level ipseckey lookup using libunbound ub_resolve_event call.
 *
 * Copyright (C) 2017-2019 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2021 Daiki Ueno <dueno@redhat.com>
 * Copyright (C) 2021 Paul Wouters <paul.wouters@aiven.io>
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

#include "ttodata.h"

#ifndef USE_UNBOUND
# error this file should only be compiled when USE_UNBOUND is defined
#endif
#include <unbound.h>		/* rpm:unbound-devel */
#include "unbound-event.h"

#ifndef USE_LDNS
# error this file should only be compiled when USE_LDNS is defined
#endif
#include <ldns/ldns.h>		/* rpm:ldns-devel deb:libldns-dev */
#include <ldns/rr.h>

#include "defs.h"
#include "log.h"
#include "dnssec.h" 		/* includes unbound.h */
#include "demux.h"		/* for md_delref() */
#include "ikev2_ipseckey.h"	/* for dns_status */
#include "ikev2_ipseckey_dnsr.h"

struct p_dns_req *pluto_dns_list = NULL; /* DNS queries linked list */

void free_ipseckey_dns(struct p_dns_req **dd)
{
	struct p_dns_req *d = (*dd);
	(*dd) = NULL;
	if (d == NULL) {
		return;
	}

	if (d->ub_async_id != 0) {
		ub_cancel(d->ctx, d->ub_async_id);
		d->ub_async_id = 0;
	}

	while (d->pubkeys != NULL) {
		struct dns_pubkey *tbd = d->pubkeys;
		d->pubkeys = d->pubkeys->next;
		pfree(tbd);
	}

	md_delref(&d->md);
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
		ldns_status status =
			ldns_rr2buffer_str_fmt(output,
					       ldns_output_format_default,
					       ldns_rr_list_rr(ldns_pkt_question(ldnspkt), i));
		if (status != LDNS_STATUS_OK) {
			llog(RC_LOG, dnsr->logger,
			     "could not parse DNS QUESTION section");
			return;
		}
	}

	LDBGP_JAMBUF(DBG_BASE, dnsr->logger, buf) {
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
 *	1: DSA key     RFC 2536  reject
 *	2: RSA key     RFC 3110  accept
 *	3: ECDSA key   RFC 6605  accept
 *      4: PUBLIC KEY  RFC xxxx  accept
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
 *
 * A lot like strspn(stringp, " \t"), except that it ignores any
 * amount of whitespace before a field.  This means that empty fields
 * are not possible.
 *
 * Danger: strsep() is blatting STRINGP with NULs that terminating the
 * fields that it finds.
 */
static char *next_rr_field(char **stringp)
{
	for (;;) {
		char *r = strsep(stringp, " \t");
		if (r == NULL || *r != '\0')
			return r;
	}
}

static bool extract_dns_pubkey(struct p_dns_req *dnsr, ldns_rdf *rdf, uint32_t ttl, struct dns_pubkey **dns_pubkeys)
{
	/* ??? would it not be easier to deal with the RDF form? */
	ldns_buffer *ldns_pkey = ldns_buffer_new((dnsr->wire_len * 8/6 + 2 + 1));
	ldns_status lerr = ldns_rdf2buffer_str_ipseckey(ldns_pkey, rdf);

	if (lerr != LDNS_STATUS_OK) {
		ldns_lookup_table *lt = ldns_lookup_by_id(ldns_error_str, lerr);
		llog(RC_LOG, dnsr->logger,
		     "IPSECKEY rr parse error %s %s", lt->name, dnsr->log_buf);
		ldns_buffer_free(ldns_pkey);
		return false;
	}

	/* not const: we modify this buffer with strspn() */
	char *rrcursor = (char *)ldns_buffer_begin(ldns_pkey);

	(void) next_rr_field(&rrcursor);	/* Precedence (ignore) */
	const char *gwt = next_rr_field(&rrcursor);	/* Gateway Type */
	const char *algorithm_type_str = next_rr_field(&rrcursor);
	const char *gw = next_rr_field(&rrcursor);	/* Gateway */
	const char *pubkey = next_rr_field(&rrcursor);	/* Public Key Block */
	const char *trailer = next_rr_field(&rrcursor);	/* whatever is left over */

	/*
	 * sanity check the fields (except for Precedence).
	 *
	 * Use the do() while(false) hack do deal with all the error
	 * exits.
	 */

	err_t ugh = NULL;

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

		errno = 0;
		unsigned algorithm_type = strtoul(algorithm_type_str, NULL, 10);
		if (errno != 0) {
			ugh = "invalid Algorithm Type";
			break;
		}

		ldbg(dnsr->logger, "algorithm type '%s' is %d",
		     algorithm_type_str, algorithm_type);
		switch (algorithm_type) {
		case IPSECKEY_ALGORITHM_RSA:
		case IPSECKEY_ALGORITHM_ECDSA:
		case IPSECKEY_ALGORITHM_X_PUBKEY:
			break;
		default:
			ugh = "Algorithm type must be 2 (RSA) 3 (ECDSA) or 4 (PUBKEY draft)";
			break;
		}
		if (ugh != NULL) {
			break;
		}

		if (!streq(gw, ".")) {
			ugh = "Gateway must be `.'";
			break;
		}

		/*
		 * over-allocate structure so that there is space for
		 * the key.
		 */
		size_t pubkey_len = strlen(pubkey); /* over estimate; decoded is less */
		struct dns_pubkey *dns_pubkey = overalloc_thing(struct dns_pubkey, pubkey_len);
		dns_pubkey->algorithm_type = algorithm_type;
		dns_pubkey->ttl = ttl;
		/* store the pubkey after the struct */
		char *pubkey_ptr = (void*)(dns_pubkey+1);
		ugh = ttodata(shunk2(pubkey, pubkey_len), 64,
			      pubkey_ptr, pubkey_len, &pubkey_len);
		if (ugh != NULL) {
			pfree(dns_pubkey);
			break;
		}
		dns_pubkey->pubkey = shunk2(pubkey_ptr, pubkey_len);

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
			if (hunk_cmp((*dns_pubkeys)->pubkey, dns_pubkey->pubkey) < 0) {
				break;
			}
			dns_pubkeys = &(*dns_pubkeys)->next;
		}
		dns_pubkey->next = *dns_pubkeys;
		*dns_pubkeys = dns_pubkey;
		ugh = NULL;

	} while (false);

	if (ugh != NULL) {
		llog(RC_LOG, dnsr->logger,
		     "ignoring IPSECKEY RR: %s", ugh);
	}

	ldns_buffer_free(ldns_pkey);

	return ugh == NULL;
}

static void parse_rr(struct ike_sa *ike,
		     struct p_dns_req *dnsr, ldns_pkt *ldnspkt,
		     struct verbose verbose)
{
	vassert(ike != NULL);

	ldns_rr_list *answers = ldns_pkt_answer(ldnspkt);
	dbg_log_dns_question(dnsr, ldnspkt);

	unsigned level = verbose.level++;

	for (unsigned rr_nr = 0; rr_nr < ldns_rr_list_rr_count(answers); rr_nr++) {

		verbose.level = level + 1;
		ldns_rr *ans = ldns_rr_list_rr(answers, rr_nr);

		const unsigned rdf_nr = 0;
		ldns_rdf *rdf = ldns_rr_rdf(ans, rdf_nr);
		if (rdf == NULL) {
			vdbg("RR %u, RDF %u: could not extract RDF",
			     rr_nr, rdf_nr);
			continue;
		}

		if (verbose.debug) {
			ldns_buffer *output = ldns_buffer_new((dnsr->wire_len * 8/6 + 2 +1) * 2);
			ldns_status status = ldns_rdf2buffer_str(output, rdf);
			if (status == LDNS_STATUS_OK) {
				VDBG_log("RR %u, RDF %u: %s", rr_nr, rdf_nr,
					 ldns_buffer_begin(output));
			} else {
				VDBG_log("RR %u, RDF %u: invalid: %s (%d)",
					 rr_nr, rdf_nr,
					 ldns_get_errorstr_by_id(status),
					 status);
			}
			ldns_buffer_free(output);
			if (status != LDNS_STATUS_OK) {
				continue;
			}
		}

		verbose.level++;

		ldns_rr_type qtype = ldns_rr_get_type(ans);
		if (qtype != dnsr->qtype) {
			/* dns server stuffed extra rr types, ignore */
			name_buf db, qb;
			vdbg("RR %u, RDF %u: qtype mismatch expect %s vs %s ignore this answer",
			     rr_nr, rdf_nr, str_ldns_rr_type(dnsr->qtype, &db),
			     str_ldns_rr_type(qtype, &qb));
			continue;
		}

		ldns_rr_class qclass = ldns_rr_get_class(ans);
		if (qclass != dnsr->qclass) {
			ldns_lookup_table *class = ldns_lookup_by_id(ldns_rr_classes, qclass);
			ldns_lookup_table *dclass = ldns_lookup_by_id(ldns_rr_classes, dnsr->qclass);
			vdbg("RR %u, RDF %u: qclass mismatch expect %s vs %s ignore the answer now",
			     rr_nr, rdf_nr,
			     (dclass != NULL ? dclass->name : "<dclass>"),
			     (class != NULL ? class->name : "<class>"));
			/* unexpected qclass. possibly malfuctioning dns */
			continue;
		}

		switch (qtype) {
		case LDNS_RR_TYPE_A:
			if (dnsr->validate_address_cb) {
				dnsr->validate_address_cb(ike, dnsr,
							  ldns_rdf_data(rdf),
							  verbose);
			}
			break;
		case LDNS_RR_TYPE_IPSECKEY:
			extract_dns_pubkey(dnsr, rdf, ldns_rr_ttl(ans),
					   &dnsr->pubkeys);
			break;
		default:
		{
			name_buf qb;
			vlog_pexpect(HERE, "RR %u, RDF %u: unexpected type %s",
				     rr_nr, rdf_nr, str_ldns_rr_type(qtype, &qb));
			break;
		}
		}

	}
}

/* This is called when dns response arrives */
err_t process_dns_resp(struct ike_sa *ike, struct p_dns_req *dnsr)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, dnsr->logger, "IPSECKEY");
	vassert(ike != NULL);

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
			llog(IMPAIR_STREAM, dnsr->logger, "allowing insecure DNS response");
			parse_rr(ike, dnsr, ldnspkt, verbose);
			return NULL;
		}
		return "unbound returned INSECURE response - ignored";

	case UB_EVENT_SECURE:
		parse_rr(ike, dnsr, ldnspkt, verbose);
		return NULL;
	}
}

void ipseckey_dbg_dns_resp(struct p_dns_req *dnsr)
{
	struct logger *logger = dnsr->logger;

	deltatime_t served_delta = realtime_diff(dnsr->done_time, dnsr->start_time);
	deltatime_buf db;

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "%s returned %s cache=%s elapsed time %s seconds",
			 dnsr->log_buf,
			 dnsr->rcode_name,
			 bool_str(dnsr->dns_status == 0),
			 str_deltatime(served_delta, &db));

		const enum lswub_resolve_event_secure_kind k = dnsr->secure;
		LDBG_log(logger, "DNSSEC=%s %s MSG SIZE %d bytes",
			 (k == UB_EVENT_SECURE ? "SECURE" :
			  k == UB_EVENT_INSECURE ? "INSECURE" :
			  k == UB_EVENT_BOGUS ? "BOGUS" :
			  "invalid lswub_resolve_event_secure_kind"),
			 (k == UB_EVENT_BOGUS ? dnsr->why_bogus : ""),
			 dnsr->wire_len);
	}
}

static void ipseckey_ub_cb(void *mydata, int rcode,
			   void *wire, int wire_len,
			   int secure, char* why_bogus
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

	/*
	 * XXX: hack
	 *
	 * Should call ike_sa_by_serialno() and pass result into
	 * callback, but can't as exposing that declaration exposes a
	 * conflict between "asn1.h" and OpenSSL's headers.
	 *
	 * Hence callback an extra level of indirection.
	 *
	 * Danger, callee may free DNSR.
	 */
	ipseckey_request_callback(dnsr);
}

dns_status dns_qry_start(struct p_dns_req *dnsr)
{
	PASSERT(dnsr->logger, dnsr->ctx != NULL);
	ldbg(dnsr->logger, "start %s", dnsr->log_buf);

	dnsr->start_time = realnow();

	/*
	 * XXX: when there's a cache hit, this will call
	 * IPSECKEY_UB_CB before returning.  That will then update
	 * .dns_status.
	 */

	ldbg(dnsr->logger, "UB: %s submitted", dnsr->log_buf);
	dnsr->dns_status = DNS_LARVAL; /* reserved */
	int ub_ret = ub_resolve_event(dnsr->ctx, dnsr->qname, dnsr->qtype,
				      dnsr->qclass, dnsr,
				      ipseckey_ub_cb, &dnsr->ub_async_id);

	if (ub_ret != 0) {
		llog(RC_LOG, dnsr->logger,
		     "unbound resolve call failed for %s", dnsr->log_buf);
		return DNS_FATAL;
	}

	/*
	 * If the above has already called the callback (because the
	 * value was found in the cache), .dns_status will have been
	 * updated to something other than DNS_LARVAL.
	 */
	if (dnsr->dns_status == DNS_LARVAL) {
		dnsr->dns_status = DNS_SUSPEND;
	}

	dns_status ret = dnsr->dns_status;
	ldbg(dnsr->logger, "UB: %s returned %d (%s)",
	     dnsr->log_buf, ret,
	     (ret == DNS_SUSPEND ? "suspend" :
	      ret == DNS_OK ? "ok" :
	      ret == DNS_FATAL ? "fatal" :
	      "ERROR"));
	return ret;
}

/* XXX: hack for system header */
const char *str_ldns_rr_type(ldns_rr_type type, name_buf *buf)
{
	switch (type) {
#define S(T) case LDNS_RR_TYPE_##T: return #T
		S(A);
		S(AAAA);
		S(TXT);
		S(NS);
		S(IPSECKEY);
#undef S
	default:
		bad_name(type, buf);
		return buf->buf;
	}
}
