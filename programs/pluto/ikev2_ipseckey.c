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
#include "unbound-event.h"
#include "lswlog.h"
#include "defs.h"
#include "log.h"
#include "constants.h"	/* for demux.h */
#include "demux.h"	/* to get struct msg_digest */
#include "state.h"
#include "connections.h"
#include "dnssec.h"	/* includes unbound.h */
#include "id.h"
#include "pluto_crypt.h"	/* for ikev2.h */
#include "ikev2.h"
#include "ikev2_ipseckey.h"
#include "keys.h"
#include "secrets.h"
#include "ip_address.h"
#include "ip_info.h"

struct p_dns_req;

typedef void dnsr_cb_fn(struct p_dns_req *);

struct p_dns_req {
	stf_status stf_status;

	bool cache_hit;		/* libunbound hit cache/local, calledback immediately */

	so_serial_t so_serial_t;	/* wake up the state when query returns */

	char *dbg_buf;
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

	/*
	 * if TRUE, delete all existing keys, of same keyid, before adding
	 * pluto can hold multiple keys with same keyid different rsakey
	 */
	bool delete_existing_keys;

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
			dbg("could not parse DNS QUESTION section for %s", dnsr->dbg_buf);
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

static bool get_keyval_chunk(struct p_dns_req *dnsr, ldns_rdf *rdf,
				chunk_t *keyval)
{
	/* ??? would it not be easier to deal with the RDF form? */
	ldns_buffer *ldns_pkey = ldns_buffer_new((dnsr->wire_len * 8/6 + 2 + 1));
	ldns_status lerr = ldns_rdf2buffer_str_ipseckey(ldns_pkey, rdf);

	if (lerr != LDNS_STATUS_OK) {
		ldns_lookup_table *lt = ldns_lookup_by_id(ldns_error_str, lerr);
		loglog(RC_LOG_SERIOUS, "IPSECKEY rr parse error %s "
				"%s", lt->name, dnsr->log_buf);

		ldns_buffer_free(ldns_pkey);
		return FALSE;
	}

	/* not const: we modify this buffer with strspn() */
	char *rrcursor = (char *)ldns_buffer_begin(ldns_pkey);

	(void) next_rr_field(&rrcursor);	/* Precedence (ignore) */
	const char *gwt = next_rr_field(&rrcursor);	/* Gateway Type */
	const char *algt = next_rr_field(&rrcursor);	/* Algorithm Type */
	const char *gw = next_rr_field(&rrcursor);	/* Gateway */
	const char *pubkey = next_rr_field(&rrcursor);	/* Public Key Block */
	const char *trailer = next_rr_field(&rrcursor);	/* whatever is left over */

	/* sanity check the fields (except for Precedence) */

	err_t ugh = NULL;

	if (pubkey == NULL) {
		ugh = "too few fields";
	} else if (trailer != NULL) {
		ugh = "too many fields";
	} else if (!streq(gwt + strspn(gwt, "0"), "")) {
		ugh = "Gateway Type must be 0";
	} else if (!streq(algt + strspn(algt, "0"), "2")) {
		ugh = "Algorithm type must be 2 (RSA)";
	} else if (!streq(gw, ".")) {
		ugh = "Gateway must be `.'";
	} else {
		size_t len = strlen(pubkey);
		/* allocate enough space; probably too much */
		char *keyspace = alloc_things(char, len, "temp pubkey bin store");
		size_t bin_len;
		char err_buf[TTODATAV_BUF];
		ugh = ttodatav(pubkey, len, 64, keyspace, len,
				&bin_len, err_buf, sizeof(err_buf), 0);

		if (ugh == NULL) {
			/* make a copy, allocating the exact space required */
			*keyval = clone_bytes_as_chunk(keyspace, bin_len, "ipseckey from dns");
		}
		pfreeany(keyspace);
	}

	if (ugh != NULL) {
		loglog(RC_LOG_SERIOUS, "Ignoring IPSECKEY RR: %s", ugh);
	}

	ldns_buffer_free(ldns_pkey);

	return ugh == NULL;
}

static err_t add_rsa_pubkey_to_pluto(struct p_dns_req *dnsr, ldns_rdf *rdf,
				     uint32_t ttl)
{
	const struct state *st = state_with_serialno(dnsr->so_serial_t);
	const struct id *keyid = &st->st_connection->spd.that.id;

	/*
	 * RETRANSMIT_TIMEOUT_DEFAULT as min ttl so pubkey does not expire while
	 * negotiating
	 */
	uint32_t ttl_used = max(ttl, (uint32_t)RETRANSMIT_TIMEOUT_DEFAULT);
	char ttl_buf[ULTOT_BUF + 32]; /* 32 is arbitrary */

	if (ttl_used == ttl) {
		snprintf(ttl_buf, sizeof(ttl_buf), "ttl %u", ttl);
	} else {
		snprintf(ttl_buf, sizeof(ttl_buf), "ttl %u ttl used %u",
			ttl, ttl_used);
	}

	chunk_t keyval;
	if (!get_keyval_chunk(dnsr, rdf, &keyval))
		return "could not get key to add";

	/* algorithm is hardcoded RSA -- PUBKEY_ALG_RSA */
	if (dnsr->delete_existing_keys) {
		if (DBGP(DBG_BASE)) {
			id_buf thatidbuf;
			dbg("delete RSA public keys(s) from pluto id=%s",
			    str_id(&st->st_connection->spd.that.id, &thatidbuf));
		}
		/* delete only once. then multiple keys could be added */
		delete_public_keys(&pluto_pubkeys, keyid, &pubkey_type_rsa);
		dnsr->delete_existing_keys = FALSE;
	}

	enum dns_auth_level al = dnsr->secure == UB_EVNET_SECURE ?
		DNSSEC_SECURE : DNSSEC_INSECURE;

	if (DBGP(DBG_BASE)) {
		if (keyid->kind == ID_FQDN) {
			id_buf thatidbuf;
			DBG_log("add IPSECKEY pluto as publickey %s %s %s",
				str_id(&st->st_connection->spd.that.id, &thatidbuf),
				ttl_buf, enum_name(&dns_auth_level_names, al));
		} else {
			id_buf thatidbuf;
			DBG_log("add IPSECKEY pluto as publickey %s dns query is %s %s %s",
				str_id(&st->st_connection->spd.that.id, &thatidbuf),
				dnsr->qname, ttl_buf,
				enum_name(&dns_auth_level_names, al));
		}
	}

	err_t ugh = add_ipseckey(keyid, al, &pubkey_type_rsa, ttl, ttl_used,
				 &keyval, &pluto_pubkeys);
	if (ugh != NULL) {
		id_buf thatidbuf;
		loglog(RC_LOG_SERIOUS, "Add publickey failed %s, %s, %s", ugh,
		       str_id(&st->st_connection->spd.that.id, &thatidbuf),
		       dnsr->log_buf);
	}

	free_chunk_content(&keyval);
	return NULL;
}

static void validate_address(struct p_dns_req *dnsr, unsigned char *addr)
{
	struct state *st = state_with_serialno(dnsr->so_serial_t);
	ip_address ipaddr;
	const struct ip_info *afi = address_type(&st->st_remote_endpoint);

	if (dnsr->qtype != LDNS_RR_TYPE_A) {
		return;
	}

	/* XXX: this is assuming that addr has .ip_size bytes!?! */
	if (data_to_address(addr, afi->ip_size, afi, &ipaddr) != NULL)
		return;

	if (!sameaddr(&ipaddr, &st->st_remote_endpoint)) {
		address_buf ra, rb;
		dbg(" forward address of IDi %s do not match remote address %s != %s",
		    dnsr->qname,
		    str_address(&st->st_remote_endpoint, &ra),
		    str_address(&ipaddr, &rb));
		return;
	}

	dnsr->fwd_addr_valid = TRUE;
	address_buf ra;
	dbg("address of IDi %s match remote address %s",
	    dnsr->qname, str_address(&st->st_remote_endpoint, &ra));
}

static err_t parse_rr(struct p_dns_req *dnsr, ldns_pkt *ldnspkt)
{
	ldns_rr_list *answers = ldns_pkt_answer(ldnspkt);
	ldns_buffer *output = NULL;
	err_t err = "nothing to add";
	size_t i;

	dbg_log_dns_question(dnsr, ldnspkt);

	dnsr->delete_existing_keys = TRUE;	/* there could something to add */

	for (i = 0; i < ldns_rr_list_rr_count(answers); i++) {
		ldns_rr *ans = ldns_rr_list_rr(answers, i);
		ldns_rr_type atype = ldns_rr_get_type(ans);
		ldns_rr_class qclass = ldns_rr_get_class(ans);
		ldns_lookup_table *class = ldns_lookup_by_id(ldns_rr_classes,
				qclass);
		ldns_lookup_table *class_e = ldns_lookup_by_id(ldns_rr_classes,
				dnsr->qclass);
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
			continue;
		}

		dbg("%s", ldns_buffer_begin(output));
		ldns_buffer_free(output);
		output = NULL;

		validate_address(dnsr, ldns_rdf_data(rdf));

		if (dnsr->qtype == atype && atype == LDNS_RR_TYPE_IPSECKEY) {
			/* the real work done here -- add key to pluto store */
			err = add_rsa_pubkey_to_pluto(dnsr, rdf,
					ldns_rr_ttl(ans));
		}

		if (atype != dnsr->qtype) {
			/* dns server stuffed extra rr types, ignore */
			dbg("dns answer %zu qtype mismatch expect %d vs %d ignore this answer",
			    i, dnsr->qtype, atype);
		}
	}

	return err;
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
			libreswan_log("IMPAIR: allowing insecure DNS response");
			return parse_rr(dnsr, ldnspkt);
		}
		return "unbound returned INSECURE response - ignored";

	case UB_EVNET_SECURE:
		return parse_rr(dnsr, ldnspkt);
	}
}

void free_ipseckey_dns(struct p_dns_req *d)
{
	if (d == NULL)
		return;

	if (d->ub_async_id != 0)
	{
		ub_cancel(get_unbound_ctx(), d->ub_async_id);
		d->ub_async_id = 0;
	}

	pfreeany(d->qname);
	pfreeany(d->dbg_buf);
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
	log_global(RC_LOG_SERIOUS, null_fd,
		   "%s The state #%lu is gone. %s returned %s elapsed time %s seconds",
		   dnsr->dbg_buf, dnsr->so_serial_t,
		   dnsr->log_buf, dnsr->rcode_name,
		   str_deltatime(served_delta, &db));
}

static void ikev2_ipseckey_log_dns_err(struct state *st,
				       struct p_dns_req *dnsr,
				       const char *err)
{
	deltatime_t served_delta = realtimediff(dnsr->done_time, dnsr->start_time);
	deltatime_buf db;
	log_state(RC_LOG_SERIOUS, st,
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

static void idr_ipseckey_fetch_continue(struct p_dns_req *dnsr)
{
	struct state *st = state_with_serialno(dnsr->so_serial_t);
	const char *parse_err;

	dnsr->done_time = realnow();

	if (st == NULL) {
		/* state disappeared we can't find discard the response */
		ikev2_ipseckey_log_missing_st(dnsr);
		free_ipseckey_dns(dnsr);
		return;
	}

	set_cur_state(st);

	ipseckey_dbg_dns_resp(dnsr);
	parse_err = process_dns_resp(dnsr);

	if (parse_err != NULL) {
		ikev2_ipseckey_log_dns_err(st, dnsr, parse_err);
	}

	if (dnsr->cache_hit) {
		if (dnsr->rcode == 0 && parse_err == NULL) {
			dnsr->stf_status = STF_OK;
		} else {
			/* is there a better ret status ? */
			dnsr->stf_status = STF_FAIL + v2N_AUTHENTICATION_FAILED;
		}
		return;
	}
	dnsr->ub_async_id = 0;	/* this query is done no need to cancel it */

	st->ipseckey_dnsr = NULL;
	free_ipseckey_dns(dnsr);
	reset_globals();
}

static void idi_ipseckey_fetch_tail(struct state *st, bool err)
{
	struct msg_digest *md = unsuspend_md(st);
	stf_status stf;

	passert(md != NULL && (st == md->st));

	if (err) {
		stf = STF_FAIL + v2N_AUTHENTICATION_FAILED;
	} else {
		stf = ikev2_parent_inI2outR2_id_tail(md);
	}

	/* replace (*mdp)->st with st ... */
	complete_v2_state_transition(md->st, md, stf);
	release_any_md(&md);
	reset_globals();
}

static void idi_a_fetch_continue(struct p_dns_req *dnsr)
{
	struct state *st = state_with_serialno(dnsr->so_serial_t);
	bool err;

	dnsr->done_time = realnow();

	if (st == NULL) {
		/* state disappeared we can't find st, hence no md, abort*/
		ikev2_ipseckey_log_missing_st(dnsr);
		free_ipseckey_dns(dnsr);
		return;
	}

	if (!dnsr->cache_hit)
		set_cur_state(st);

	ipseckey_dbg_dns_resp(dnsr);
	process_dns_resp(dnsr);

	if (!dnsr->fwd_addr_valid) {
		loglog(RC_LOG_SERIOUS, "forward address validation failed %s",
				dnsr->log_buf);
	}

	if (dnsr->rcode == 0 && dnsr->fwd_addr_valid) {
		err = FALSE;
	} else {
		if (st->ipseckey_dnsr != NULL) {
			free_ipseckey_dns(st->ipseckey_dnsr);
			st->ipseckey_dnsr = NULL;
		}
		err = TRUE;
	}

	if (dnsr->cache_hit) {
		if (err) {
			/* is there a beeter ret status ? */
			dnsr->stf_status = STF_FAIL + v2N_AUTHENTICATION_FAILED;
		} else {
			dnsr->stf_status = STF_OK;
		}
		return;
	}

	dnsr->ub_async_id = 0;	/* this query is done no need to cancel it */
	st->ipseckey_fwd_dnsr = NULL;

	if (st->ipseckey_dnsr != NULL) {
		dbg("wait for IPSECKEY DNS response %s", dnsr->qname);
		/* wait for additional A/AAAA dns response */
		free_ipseckey_dns(dnsr);
		return;
	}

	dbg("%s unsuspend id=%s", dnsr->dbg_buf, dnsr->qname);

	free_ipseckey_dns(dnsr);

	idi_ipseckey_fetch_tail(st, err);
}

static void idi_ipseckey_fetch_continue(struct p_dns_req *dnsr)
{
	struct state *st = state_with_serialno(dnsr->so_serial_t);
	const char *parse_err;
	bool err;

	dnsr->done_time = realnow();

	if (st == NULL) {
		/* state disappeared we can't find st, hence no md, abort*/
		ikev2_ipseckey_log_missing_st(dnsr);
		free_ipseckey_dns(dnsr);
		return;
	}

	if (!dnsr->cache_hit)
		set_cur_state(st);

	ipseckey_dbg_dns_resp(dnsr);
	parse_err = process_dns_resp(dnsr);

	if (parse_err != NULL) {
		ikev2_ipseckey_log_dns_err(st, dnsr, parse_err);
	}

	if (dnsr->rcode == 0 && parse_err == NULL) {
		err = FALSE;
	} else {
		if (st->ipseckey_fwd_dnsr != NULL) {
			free_ipseckey_dns(st->ipseckey_fwd_dnsr);
			st->ipseckey_fwd_dnsr = NULL;
		}
		err = TRUE;
	}

	if (dnsr->cache_hit) {
		if (err) {
			/* is there a beeter ret status ? */
			dnsr->stf_status = STF_FAIL + v2N_AUTHENTICATION_FAILED;
		} else {
			dnsr->stf_status = STF_OK;
		}
		return;
	}

	dnsr->ub_async_id = 0;	/* this query is done no need to cancel it */

	st->ipseckey_dnsr = NULL;

	if (st->ipseckey_fwd_dnsr != NULL) {
		dbg("wait for additional DNS A/AAAA check %s", dnsr->qname);
		/* wait for additional A/AAAA dns response */
		free_ipseckey_dns(dnsr);
		return;
	} else {
		dbg("%s unsuspend id=%s", dnsr->dbg_buf, dnsr->qname);
		free_ipseckey_dns(dnsr);
		idi_ipseckey_fetch_tail(st, err);
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

static err_t build_dns_name(jambuf_t *name_buf, const struct id *id)
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


static struct p_dns_req *qry_st_init(struct state *st,
					enum ldns_enum_rr_type qtype,
					const char *qtype_name,
					dnsr_cb_fn dnsr_cb)
{
	struct id id = st->st_connection->spd.that.id;
	char b[CONN_INST_BUF];
	char dbg_buf[512] ;	/* Arbitrary length. It is local */
	struct p_dns_req *p;
	char log_buf[SWAN_MAX_DOMAIN_LEN * 2];	/* this is local */


	char qname[SWAN_MAX_DOMAIN_LEN];
	jambuf_t qbuf = ARRAY_AS_JAMBUF(qname);
	err_t err = build_dns_name(&qbuf, &id);
	if (err != NULL) {
		/* is there qtype to name lookup function */
		loglog(RC_LOG_SERIOUS, "could not build dns query name %s %d",
				err, qtype);
		return NULL;
	}

	p = alloc_thing(struct p_dns_req, "id remote dns");
	p->so_serial_t = st->st_serialno;
	p->qname = clone_str(qname, "dns qname");

	fmt_conn_instance(st->st_connection, b);
	snprintf(dbg_buf, sizeof(dbg_buf), "\"%s\"%s #%lu ",
			st->st_connection->name, b, st->st_serialno);

	snprintf(log_buf, sizeof(log_buf), "IKEv2 DNS query -- %s IN %s --",
			p->qname, qtype_name);

	p->dbg_buf = clone_str(dbg_buf, "dns debug name");
	p->log_buf = clone_str(log_buf, "dns log name");

	p->qclass = ns_c_in;
	p->qtype = qtype;
	p->cache_hit = TRUE;
	p->stf_status = STF_SUSPEND;
	p->cb = dnsr_cb;

	p->next = pluto_dns_list;
	pluto_dns_list = p;

	return p;
}

static struct p_dns_req *ipseckey_qry_st_init(struct state *st,
		dnsr_cb_fn dnsr_cb)
{
	/* hardcoded RR type to IPSECKEY AA_2017_03 */
	return qry_st_init(st, LDNS_RR_TYPE_IPSECKEY, "IPSECKEY", dnsr_cb);
}

static stf_status dns_qry_start(struct p_dns_req *dnsr)
{
	int ub_ret;
	stf_status ret;

	passert(get_unbound_ctx() != NULL);

	dbg("%s start %s", dnsr->dbg_buf, dnsr->log_buf);

	dnsr->start_time = realnow();

	ub_ret = ub_resolve_event(get_unbound_ctx(), dnsr->qname, dnsr->qtype,
			dnsr->qclass, dnsr, ipseckey_ub_cb, &dnsr->ub_async_id);

	if (ub_ret != 0) {
		loglog(RC_LOG_SERIOUS, "unbound resolve call failed for %s",
				dnsr->log_buf);
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
stf_status idr_ipseckey_fetch(struct state *st)
{
	stf_status ret;
	struct p_dns_req *dnsr = ipseckey_qry_st_init(st,
			idr_ipseckey_fetch_continue);

	if (dnsr == NULL) {
		return STF_FAIL;
	}

	ret = dns_qry_start(dnsr);

	if (ret == STF_SUSPEND) {
		st->ipseckey_dnsr = dnsr;
		ret = STF_OK;	/* while querying IDr do not suspend */
	}

	return ret;
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
stf_status idi_ipseckey_fetch(struct msg_digest *md)
{
	stf_status ret_idi;
	stf_status ret_a = STF_OK;
	struct state *st = md->st;
	struct p_dns_req *dnsr_a = NULL;
	struct p_dns_req *dnsr_idi = ipseckey_qry_st_init(st,
			idi_ipseckey_fetch_continue);

	if (dnsr_idi == NULL) {
		return STF_FAIL;
	}

	ret_idi = dns_qry_start(dnsr_idi);

	if (ret_idi != STF_SUSPEND && ret_idi != STF_OK) {
		return ret_idi;
	} else if (ret_idi == STF_SUSPEND) {
		st->ipseckey_dnsr = dnsr_idi;
	}

	if (LIN(st->st_connection->policy, POLICY_DNS_MATCH_ID)) {
		struct id id = st->st_connection->spd.that.id;
		if (id.kind == ID_FQDN) {
			dnsr_a = qry_st_init(st, LDNS_RR_TYPE_A, "A", idi_a_fetch_continue);

			if (dnsr_a == NULL) {
				free_ipseckey_dns(dnsr_idi);
				return STF_FAIL;
			}
			ret_a = dns_qry_start(dnsr_a);
		}
	}

	if (ret_a == STF_SUSPEND)
		st->ipseckey_fwd_dnsr = dnsr_a;

	if (ret_a != STF_SUSPEND && ret_a != STF_OK) {
		free_ipseckey_dns(dnsr_idi);
	} else if (ret_idi == STF_OK && ret_a == STF_OK) {
		/* cache hit, call back is already called */
		return STF_OK;
	} else if (ret_a == STF_SUSPEND || ret_idi == STF_SUSPEND) {
		return STF_SUSPEND;
	}

	return STF_FAIL;
}
