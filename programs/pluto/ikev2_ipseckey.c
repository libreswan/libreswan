/*
 * ipseckey lookup for pluto using libunbound ub_resolve_event call.
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

#include <arpa/inet.h>	/* for inet_ntop */
#include <arpa/nameser.h>
#include <ldns/ldns.h>	/* from ldns-devel */
#include <ldns/rr.h>
#include <unbound.h>
#include "unbound-event.h"
#include "defs.h"
#include "log.h"
#include "constants.h"	/* for demux.h */
#include "demux.h"	/* to get struct msg_digest */
#include "state.h"
#include "connections.h"
#include "dnssec.h"	/* includes unbound.h */
#include "id.h"
#include "ikev2.h"
#include "ikev2_ipseckey.h"
#include "keys.h"
#include "secrets.h"
#include "ip_address.h"
#include "ip_info.h"
#include "ikev2_ike_auth.h"
#include "state_db.h"

struct p_dns_req;

typedef void dnsr_cb_fn(struct p_dns_req *);

struct dns_pubkey {
	/* ID? */
	const struct pubkey_type *type;
	struct dns_pubkey *next;
	uint32_t ttl;
	/* chunk_t like */
	size_t len;
	uint8_t ptr[];
};

struct p_dns_req {
	dns_status dns_status;

	bool cache_hit;		/* libunbound hit cache/local, calledback immediately */

	so_serial_t so_serial;	/* wake up the state using callback() when query returns */
	stf_status (*callback)(struct ike_sa *ike, struct msg_digest *md, bool err);
	struct logger *logger;

	char *log_buf;

	realtime_t start_time;
	realtime_t done_time;

	char *qname;		/* DNS query to send, from ID */
	uint16_t qtype;
	uint16_t qclass;

	int ub_async_id;	/* used to track libunbound query, to cancel */

	int rcode;		/* libunbound dns query rcode */
	const char *rcode_name; /* rcode return txt defined by ldns */

	bool fwd_addr_valid;	/* additional check forward A/AAAA is valid */

	/*
	 * from unbound-event.h
	 * void *wire with packet: a buffer with DNS wireformat packet with the answer.
	 * do not inspect if rcode != 0.
	 * do not write or free the packet buffer, it is used
	 * internally in unbound (for other callbacks that want the same data).
	 */
	void *wire;	/* libunbound result wire buffer format */
	int wire_len;	/* length of the above buffer */

	int secure;	/* dnsec validiation returned by libunbound */
	char *why_bogus;	/* returned by libunbound if the security is bogus */

	dnsr_cb_fn *cb;	/* continue function for pluto, not the unbbound cb */

	struct p_dns_req *next;
};

static struct p_dns_req *pluto_dns_list = NULL; /* DNS queries linked list */

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

static void add_dns_pubkeys_to_pluto(struct p_dns_req *dnsr, struct dns_pubkey *dns_pubkeys)
{
	passert(dns_pubkeys != NULL);

	const struct state *st = state_with_serialno(dnsr->so_serial);
	const struct id *keyid = &st->st_connection->spd.that.id;

	/* algorithm is hardcoded RSA -- PUBKEY_ALG_RSA */
	/* delete only once. then multiple keys could be added */
	delete_public_keys(&pluto_pubkeys, keyid, &pubkey_type_rsa);

	realtime_t install_time = realnow();
	for (struct dns_pubkey *dns_pubkey = dns_pubkeys; dns_pubkey != NULL; dns_pubkey = dns_pubkey->next) {

		/*
		 * RETRANSMIT_TIMEOUT_DEFAULT as min ttl so pubkey
		 * does not expire while negotiating
		 */

		uint32_t ttl = dns_pubkey->ttl;
		uint32_t ttl_used = max(ttl, (uint32_t)RETRANSMIT_TIMEOUT_DEFAULT);
		char ttl_buf[ULTOT_BUF + 32]; /* 32 is arbitrary */

		if (ttl_used == ttl) {
			snprintf(ttl_buf, sizeof(ttl_buf), "ttl %u", ttl);
		} else {
			snprintf(ttl_buf, sizeof(ttl_buf), "ttl %u ttl used %u",
				 ttl, ttl_used);
		}

		enum dns_auth_level al = dnsr->secure == UB_EVNET_SECURE ?
			DNSSEC_SECURE : DNSSEC_INSECURE;

		if (keyid->kind == ID_FQDN) {
			id_buf thatidbuf;
			dbg("add IPSECKEY pluto as publickey %s %s %s",
			    str_id(&st->st_connection->spd.that.id, &thatidbuf),
			    ttl_buf, enum_name(&dns_auth_level_names, al));
		} else {
			id_buf thatidbuf;
			dbg("add IPSECKEY pluto as publickey %s dns query is %s %s %s",
			    str_id(&st->st_connection->spd.that.id, &thatidbuf),
			    dnsr->qname, ttl_buf,
			    enum_name(&dns_auth_level_names, al));
		}

		chunk_t keyval = chunk2(dns_pubkey->ptr, dns_pubkey->len);
		err_t ugh = add_public_key(keyid, /*dns_auth_level*/al,
					   &pubkey_type_rsa,
					   install_time, realtimesum(install_time, deltatime(ttl_used)),
					   ttl, &keyval, NULL/*don't-return-pubkey*/, &pluto_pubkeys);
		if (ugh != NULL) {
			id_buf thatidbuf;
			llog(RC_LOG_SERIOUS, dnsr->logger,
			     "add publickey failed %s, %s, %s", ugh,
			     str_id(&st->st_connection->spd.that.id, &thatidbuf),
			     dnsr->log_buf);
		}
	}
}

static void validate_address(struct p_dns_req *dnsr, unsigned char *addr)
{
	struct state *st = state_with_serialno(dnsr->so_serial);
	ip_address ipaddr;
	const struct ip_info *afi = endpoint_type(&st->st_remote_endpoint);

	if (dnsr->qtype != LDNS_RR_TYPE_A) {
		return;
	}

	/* XXX: this is assuming that addr has .ip_size bytes!?! */
	if (data_to_address(addr, afi->ip_size, afi, &ipaddr) != NULL)
		return;

	if (!endpoint_address_eq_address(st->st_remote_endpoint, ipaddr)) {
		endpoint_buf ra;
		address_buf rb;
		dbg(" forward address of IDi %s do not match remote address %s != %s",
		    dnsr->qname,
		    str_endpoint(&st->st_remote_endpoint, &ra),
		    str_address(&ipaddr, &rb));
		return;
	}

	dnsr->fwd_addr_valid = TRUE;
	endpoint_buf ra;
	dbg("address of IDi %s match remote address %s",
	    dnsr->qname, str_endpoint(&st->st_remote_endpoint, &ra));
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

		validate_address(dnsr, ldns_rdf_data(rdf));

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

	add_dns_pubkeys_to_pluto(dnsr, dns_pubkeys);
	while (dns_pubkeys != NULL) {
		struct dns_pubkey *tbd = dns_pubkeys;
		dns_pubkeys = dns_pubkeys->next;
		pfree(tbd);
	}
	return NULL;
}

/* This is called when dns response arrives */
static err_t process_dns_resp(struct p_dns_req *dnsr)
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

	case UB_EVNET_SECURE:
		return parse_rr(dnsr, ldnspkt);
	}
}

static void free_ipseckey_dns(struct p_dns_req *d)
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

static void ikev2_ipseckey_log_missing_st(struct p_dns_req *dnsr)
{
	deltatime_t served_delta = realtimediff(dnsr->done_time, dnsr->start_time);
	deltatime_buf db;
	llog(RC_LOG_SERIOUS, dnsr->logger,
	     "the state is gone; %s returned %s elapsed time %s seconds",
	     dnsr->log_buf, dnsr->rcode_name,
	     str_deltatime(served_delta, &db));
}

static void ikev2_ipseckey_log_dns_err(struct ike_sa *ike,
				       struct p_dns_req *dnsr,
				       const char *err)
{
	deltatime_t served_delta = realtimediff(dnsr->done_time, dnsr->start_time);
	deltatime_buf db;
	llog_sa(RC_LOG_SERIOUS, ike,
		"%s returned %s rr parse error %s elapsed time %s seconds",
		dnsr->log_buf,
		dnsr->rcode_name, err,
		str_deltatime(served_delta, &db));
}

static void ipseckey_dbg_dns_resp(struct p_dns_req *dnsr)
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
			k == UB_EVNET_SECURE ? "SECURE"
			: k == UB_EVENT_INSECURE ? "INSECURE"
			: k == UB_EVENT_BOGUS ? "BOGUS"
			: "invalid lswub_resolve_event_secure_kind",

			k == UB_EVENT_BOGUS ? dnsr->why_bogus : "",
			dnsr->wire_len);
	}
}

static void initiator_fetch_idr_ipseckey_continue(struct p_dns_req *dnsr)
{
	struct ike_sa *ike = ike_sa_by_serialno(dnsr->so_serial);
	const char *parse_err;

	dnsr->done_time = realnow();

	if (ike == NULL) {
		/* state disappeared we can't find discard the response */
		ikev2_ipseckey_log_missing_st(dnsr);
		free_ipseckey_dns(dnsr);
		return;
	}


	ipseckey_dbg_dns_resp(dnsr);
	parse_err = process_dns_resp(dnsr);

	if (parse_err != NULL) {
		ikev2_ipseckey_log_dns_err(ike, dnsr, parse_err);
	}

	if (dnsr->cache_hit) {
		if (dnsr->rcode == 0 && parse_err == NULL) {
			dnsr->dns_status = DNS_OK;
		} else {
			/* is there a better ret status ? */
			dnsr->dns_status = DNS_FATAL;
		}
		return;
	}
	dnsr->ub_async_id = 0;	/* this query is done no need to cancel it */

	ike->sa.ipseckey_dnsr = NULL;
	free_ipseckey_dns(dnsr);
}

static void idi_ipseckey_resume_ike_sa(struct ike_sa *ike, bool err,
				       stf_status(*callback)(struct ike_sa *ike,
							     struct msg_digest *md,
							     bool err))
{
	struct msg_digest *md = unsuspend_md(&ike->sa);
	complete_v2_state_transition(&ike->sa, md, callback(ike, md, err));
	release_any_md(&md);
}

static void idi_a_fetch_continue(struct p_dns_req *dnsr)
{
	struct ike_sa *ike = ike_sa_by_serialno(dnsr->so_serial);
	bool err;

	dnsr->done_time = realnow();

	if (ike == NULL) {
		/* state disappeared we can't find st, hence no md, abort*/
		ikev2_ipseckey_log_missing_st(dnsr);
		free_ipseckey_dns(dnsr);
		return;
	}

	if (!dnsr->cache_hit)
		ipseckey_dbg_dns_resp(dnsr);
	process_dns_resp(dnsr);

	if (!dnsr->fwd_addr_valid) {
		llog(RC_LOG_SERIOUS, dnsr->logger,
		     "forward address validation failed %s",
		     dnsr->log_buf);
	}

	if (dnsr->rcode == 0 && dnsr->fwd_addr_valid) {
		err = false;
	} else {
		if (ike->sa.ipseckey_dnsr != NULL) {
			free_ipseckey_dns(ike->sa.ipseckey_dnsr);
			ike->sa.ipseckey_dnsr = NULL;
		}
		err = true;
	}

	if (dnsr->cache_hit) {
		if (err) {
			/* is there a beeter ret status ? */
			dnsr->dns_status = DNS_FATAL;
		} else {
			dnsr->dns_status = DNS_OK;
		}
		return;
	}

	dnsr->ub_async_id = 0;	/* this query is done no need to cancel it */
	ike->sa.ipseckey_fwd_dnsr = NULL;

	if (ike->sa.ipseckey_dnsr != NULL) {
		dbg("wait for IPSECKEY DNS response %s", dnsr->qname);
		/* wait for additional A/AAAA dns response */
		free_ipseckey_dns(dnsr);
		return;
	}

	llog(DEBUG_STREAM, dnsr->logger, "%s() unsuspend id=%s", __func__, dnsr->qname);
	idi_ipseckey_resume_ike_sa(ike, err, dnsr->callback);
	free_ipseckey_dns(dnsr);
}

static void responder_fetch_idi_ipseckey_continue(struct p_dns_req *dnsr)
{
	struct ike_sa *ike = ike_sa_by_serialno(dnsr->so_serial);
	const char *parse_err;
	bool err;

	dnsr->done_time = realnow();

	if (ike == NULL) {
		/* state disappeared we can't find st, hence no md, abort*/
		ikev2_ipseckey_log_missing_st(dnsr);
		free_ipseckey_dns(dnsr);
		return;
	}

	if (!dnsr->cache_hit)
		ipseckey_dbg_dns_resp(dnsr);
	parse_err = process_dns_resp(dnsr);

	if (parse_err != NULL) {
		ikev2_ipseckey_log_dns_err(ike, dnsr, parse_err);
	}

	if (dnsr->rcode == 0 && parse_err == NULL) {
		err = false;
	} else {
		if (ike->sa.ipseckey_fwd_dnsr != NULL) {
			free_ipseckey_dns(ike->sa.ipseckey_fwd_dnsr);
			ike->sa.ipseckey_fwd_dnsr = NULL;
		}
		err = true;
	}

	if (dnsr->cache_hit) {
		if (err) {
			/* is there a beeter ret status ? */
			dnsr->dns_status = DNS_FATAL;
		} else {
			dnsr->dns_status = DNS_OK;
		}
		return;
	}

	dnsr->ub_async_id = 0;	/* this query is done no need to cancel it */

	ike->sa.ipseckey_dnsr = NULL;

	if (ike->sa.ipseckey_fwd_dnsr != NULL) {
		dbg("wait for additional DNS A/AAAA check %s", dnsr->qname);
		/* wait for additional A/AAAA dns response */
		free_ipseckey_dns(dnsr);
		return;
	}

	llog(DEBUG_STREAM, dnsr->logger, "%s() unsuspend id=%s", __func__, dnsr->qname);
	idi_ipseckey_resume_ike_sa(ike, err, dnsr->callback);
	free_ipseckey_dns(dnsr);
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

static err_t build_dns_name(struct jambuf *name_buf, const struct id *id)
{
	switch (id->kind) {
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		jam_address_reversed(name_buf, &id->ip_addr);
		break;

	case ID_FQDN:
	{
		/*
		 * strip any and all trailing "." characters, then add
		 * just one
		 *
		 * id.name will have an extra @ as prefix
		 * (XXX: is this still relevant?)
		 */
		unsigned len = id->name.len;
		while (len > 0 && id->name.ptr[len - 1] == '.')
			len--;
		/* stop at len, or any embedded '\0'; add the '.' */
		/* XXX: use jam_raw_bytes()? */
		jam(name_buf, "%.*s.", len, id->name.ptr);
		break;
	}

	default:
		return "can only query DNS for IPSECKEY for ID that is a FQDN, IPV4_ADDR, or IPV6_ADDR";
	}

	if (!jambuf_ok(name_buf)) {
		return "FQDN is too long for domain name";
	}
	return NULL;
}


static struct p_dns_req *qry_st_init(struct ike_sa *ike,
				     enum ldns_enum_rr_type qtype,
				     const char *qtype_name,
				     dnsr_cb_fn dnsr_cb,
				     stf_status (*callback)(struct ike_sa *ike,
							    struct msg_digest *md,
							    bool err))
{
	struct id id = ike->sa.st_connection->spd.that.id;

	char qname[SWAN_MAX_DOMAIN_LEN];
	struct jambuf qbuf = ARRAY_AS_JAMBUF(qname);
	err_t err = build_dns_name(&qbuf, &id);
	if (err != NULL) {
		/* is there qtype to name lookup function */
		llog_sa(RC_LOG_SERIOUS, ike,
			"could not build dns query name %s %d",
			err, qtype);
		return NULL;
	}

	struct p_dns_req *p = alloc_thing(struct p_dns_req, "id remote dns");
	p->so_serial = ike->sa.st_serialno;
	p->callback = callback;
	p->logger = clone_logger(ike->sa.st_logger, HERE);
	p->qname = clone_str(qname, "dns qname");

	p->log_buf = alloc_printf("IKEv2 DNS query -- %s IN %s --",
				  p->qname, qtype_name);

	p->qclass = ns_c_in;
	p->qtype = qtype;
	p->cache_hit = TRUE;
	p->dns_status = DNS_SUSPEND;
	p->cb = dnsr_cb;

	p->next = pluto_dns_list;
	pluto_dns_list = p;

	return p;
}

static struct p_dns_req *ipseckey_qry_st_init(struct ike_sa *ike, dnsr_cb_fn dnsr_cb,
					      stf_status(*callback)(struct ike_sa *ike,
								    struct msg_digest *md,
								    bool err))
{
	/* hardcoded RR type to IPSECKEY AA_2017_03 */
	return qry_st_init(ike, LDNS_RR_TYPE_IPSECKEY, "IPSECKEY", dnsr_cb, callback);
}

static dns_status dns_qry_start(struct p_dns_req *dnsr)
{
	int ub_ret;
	dns_status ret;

	passert(get_unbound_ctx() != NULL);

	llog(DEBUG_STREAM, dnsr->logger, "start %s", dnsr->log_buf);

	dnsr->start_time = realnow();

	ub_ret = ub_resolve_event(get_unbound_ctx(), dnsr->qname, dnsr->qtype,
				  dnsr->qclass, dnsr, ipseckey_ub_cb, &dnsr->ub_async_id);

	if (ub_ret != 0) {
		llog(RC_LOG_SERIOUS, dnsr->logger,
		     "unbound resolve call failed for %s", dnsr->log_buf);
		free_ipseckey_dns(dnsr);
		return DNS_FATAL;
	}

	ret = dnsr->dns_status;
	if (dnsr->dns_status == DNS_SUSPEND) {
		dnsr->cache_hit = FALSE;
	} else {
		free_ipseckey_dns(dnsr);
	}

	return ret;
}

/*
 * On initiator fetch IPSECKEY for IDr.
 * Fetch ipseckey from dns for IKEv2 initiator from the reverse zone
 *  1. leftrsasigkey=%dnsondemand
 *
 * The returned public key(s) with ip, as keyid, will overwrite the public
 * key(s) in pluto's global public key store
 *
 * If DNS returns multiple IPSECKEY RR add all of keys, with same keyid.
 *
 * Note libunbound call back quirck, if the data is local or cached
 * the call back function will be called without returning.
 */

bool initiator_fetch_idr_ipseckey(struct ike_sa *ike)
{
	struct p_dns_req *dnsr = ipseckey_qry_st_init(ike,
						      initiator_fetch_idr_ipseckey_continue,
						      NULL/*no-callback-for-ike*/);
	if (dnsr == NULL) {
		return false;
	}

	dns_status ret = dns_qry_start(dnsr);
	if (ret == DNS_SUSPEND) {
		ike->sa.ipseckey_dnsr = dnsr;
		return true;	/* while querying IDr do not suspend */
	}

	return ret == DNS_OK;
}

/*
 * On responder query IPSECKEY for IDi, it could be FQDN or IP.
 * The returned ipsec key(s) will be added to public store, with keyid IDi.
 * New key(s) will overwrite any existing one(s) with same keyid in pluto's
 * global public key store.
 *
 * If DNS returns multiple IPSECKEY RR add all of keys, with same keyid.
 *
 * Note: libunbound call back quirck, if the data is local or cached
 * the call back function will be called without returning.
 */
dns_status responder_fetch_idi_ipseckey(struct ike_sa *ike,
					stf_status (*callback)(struct ike_sa *ike,
							       struct msg_digest *md,
							       bool err))
{
	dns_status ret_idi;
	dns_status ret_a = DNS_OK;
	struct p_dns_req *dnsr_a = NULL;
	struct p_dns_req *dnsr_idi = ipseckey_qry_st_init(ike,
							  responder_fetch_idi_ipseckey_continue,
							  callback);

	if (dnsr_idi == NULL) {
		return DNS_FATAL;
	}

	ret_idi = dns_qry_start(dnsr_idi);

	if (ret_idi != DNS_SUSPEND && ret_idi != DNS_OK) {
		return ret_idi;
	}

	if (ret_idi == DNS_SUSPEND) {
		ike->sa.ipseckey_dnsr = dnsr_idi;
	}

	if (LIN(ike->sa.st_connection->policy, POLICY_DNS_MATCH_ID)) {
		struct id id = ike->sa.st_connection->spd.that.id;
		if (id.kind == ID_FQDN) {
			dnsr_a = qry_st_init(ike, LDNS_RR_TYPE_A, "A",
					     idi_a_fetch_continue,
					     callback);

			if (dnsr_a == NULL) {
				free_ipseckey_dns(dnsr_idi);
				return DNS_FATAL;
			}
			ret_a = dns_qry_start(dnsr_a);
		}
	}

	if (ret_a == DNS_SUSPEND)
		ike->sa.ipseckey_fwd_dnsr = dnsr_a;

	if (ret_a != DNS_SUSPEND && ret_a != DNS_OK) {
		free_ipseckey_dns(dnsr_idi);
	} else if (ret_idi == DNS_OK && ret_a == DNS_OK) {
		/* cache hit, call back is already called */
		return DNS_OK;
	} else if (ret_a == DNS_SUSPEND || ret_idi == DNS_SUSPEND) {
		return DNS_SUSPEND;
	}

	return DNS_FATAL;
}
