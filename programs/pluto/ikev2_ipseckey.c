/*
 * ipseckey lookup for pluto using libunbound ub_resolve_event call.
 *
 * Copyright (C) 2017 Antony Antony
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

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h> /* for inet_ntop */
#include <arpa/nameser.h>
#include <ldns/ldns.h>	/* from ldns-devel */
#include <ldns/rr.h>
#include "unbound-event.h"
#include "libreswan.h"
#include "lswlog.h"
#include "defs.h"
#include "log.h"
#include "constants.h" /* for demux.h */
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

struct p_dns_req;

typedef void dnsr_cb_fn(struct p_dns_req *);

struct p_dns_req {
	stf_status stf_status;

	bool cache_hit;  /* libunbound hit cache/local, calledback immediately */

	so_serial_t so_serial_t; /* wake up the state when query returns */

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
	void *wire;	 /* libunbound result wire buffer format */
	int wire_len;	 /* length of the above buffer */

	int secure;	 /* dnsec validiation returned by libunbound */
	char *why_bogus; /* returned by libunbound if the security is bogus */

	/*
	 * if TRUE, delete all existing keys, of same keyid, before adding
	 * pluto can hold multiple keys with same keyid different rsakey
	 */
	bool delete_exisiting_keys;

	dnsr_cb_fn *cb; /* continue function for pluto, not the unbbound cb */

	struct p_dns_req *next;
};

static struct p_dns_req *pluto_dns_list; /* DNS queries linked list */

static void dbg_log_dns_question(struct p_dns_req *dnsr,
		ldns_pkt *ldnspkt)
{
	ldns_buffer *output = ldns_buffer_new(dnsr->wire_len * 2);
	size_t i;

	for (i = 0; i < ldns_pkt_qdcount(ldnspkt); i++) {
		ldns_status  status = ldns_rr2buffer_str_fmt(output,
				ldns_output_format_default,
				ldns_rr_list_rr(
					ldns_pkt_question(ldnspkt), i));
		if (status != LDNS_STATUS_OK) {
			DBG(DBG_DNS, DBG_log("could not parse DNS QUESTION section for %s", dnsr->dbg_buf));
			return;
		}
	}

	DBG(DBG_DNS, DBG_log("DNS QUESTION %s", ldns_buffer_begin(output)));
	ldns_buffer_free(output);
}

static bool get_keyval_chunk(struct p_dns_req *dnsr, ldns_rdf *rdf,
				chunk_t *keyval)
{
	ldns_buffer *ldns_pkey = NULL;
	char *pubkey_start;
	size_t len;
	size_t bin_len;
	char err_buf[TTODATAV_BUF];
	char *keyspace;
	int alg;
	ldns_status lerr;
	err_t ugh;
	bool ret = TRUE;

	ldns_pkey = ldns_buffer_new((dnsr->wire_len * 8/6 + 2 +1));
	lerr = ldns_rdf2buffer_str_ipseckey(ldns_pkey, rdf);

	if (lerr != LDNS_STATUS_OK)
	{
		ldns_lookup_table *lt;
		lt = ldns_lookup_by_id(ldns_error_str, lerr);
		loglog(RC_LOG_SERIOUS, "IPSECKEY rr parse error %s "
				"%s", lt->name, dnsr->log_buf);

		ldns_buffer_free(ldns_pkey);
		return FALSE;
	}

	/* 10 0 2 . AQPO39yuENlW ... is an example */
	pubkey_start = (char *)ldns_buffer_begin(ldns_pkey); /* precedence */
	strsep(&pubkey_start, " "); /* gateway type */
	strsep(&pubkey_start, " "); /* algorithm */

	/* RFC 4025 #2.4 only accept RSA Algorithm */
	alg = atoi(pubkey_start);
	if (alg != PUBKEY_ALG_RSA) {
		/* game over */
		loglog(RC_LOG_SERIOUS, "Unsupported Algorithm in IPSECKEY %d. "
				"Expected %d(%s) query was %s", alg,
				PUBKEY_ALG_RSA,
				"PUBKEY_ALG_RSA", dnsr->qname);
		ldns_buffer_free(ldns_pkey);
		return FALSE;
	}

	strsep(&pubkey_start, " "); /* gateway */
	strsep(&pubkey_start, " "); /* bb64 encoded key */

	len = strlen(pubkey_start);
	keyspace = alloc_things(char, len, "temp pubkey bin store");
	ugh =  ttodatav(pubkey_start, len, 64, keyspace, len,
			&bin_len, err_buf, sizeof(err_buf), 0);

	if (ugh != NULL) {
		loglog(RC_LOG_SERIOUS, "converting base64 pubkey to binary failed %s", ugh);
		ret = FALSE;
	}

	ldns_buffer_free(ldns_pkey);
	if (ret)
		clonetochunk(*keyval, keyspace, bin_len,  "ipseckey from dns");

	pfreeany(keyspace);

	return ret;
}

static err_t add_rsa_pubkey_to_pluto(struct p_dns_req *dnsr, ldns_rdf *rdf,
		uint32_t ttl)
{
	struct state *st = state_with_serialno(dnsr->so_serial_t);
	struct id keyid = st->st_connection->spd.that.id;
	chunk_t keyval = empty_chunk;
	err_t ugh = NULL;
	char thatidbuf[IDTOA_BUF];
	char ttl_buf[ULTOT_BUF + 32]; /* 32 is aribitary */
	uint32_t ttl_used;

	/*
	 * RETRANSMIT_TIMEOUT_DEFAULT as min ttl so pubkey does not expire while
	 * negotiating
	 */
	ttl_used = max(ttl,  (uint32_t)RETRANSMIT_TIMEOUT_DEFAULT);

	if (ttl_used == ttl) {
		snprintf(ttl_buf, sizeof(ttl_buf), "ttl %u", ttl);
	} else {
		snprintf(ttl_buf, sizeof(ttl_buf), "ttl %u ttl used %u", ttl,
				ttl_used);
	}

	if (!get_keyval_chunk(dnsr, rdf, &keyval))
		return "could not get key to add";

	idtoa(&st->st_connection->spd.that.id, thatidbuf, sizeof(thatidbuf));
	/* algorithm is hardcoded RSA -- PUBKEY_ALG_RSA */
	if (dnsr->delete_exisiting_keys)  {
		DBG(DBG_DNS,
			DBG_log("delete RSA public keys(s) from pluto id=%s",
				thatidbuf));
		/* delete only once. then multiple keys could be added */
		delete_public_keys(&pluto_pubkeys, &keyid, PUBKEY_ALG_RSA);
		dnsr->delete_exisiting_keys = FALSE;
	}

	enum dns_auth_level al = dnsr->secure == UB_EVNET_SECURE ?
		DNSSEC_SECURE : DNSSEC_INSECURE;

	if (keyid.kind == ID_FQDN) {
		DBG(DBG_DNS, DBG_log("add IPSECKEY pluto as publickey %s %s %s",
					thatidbuf, ttl_buf,
					enum_name(&dns_auth_level_names, al)));
	} else {
		DBG(DBG_DNS,
			DBG_log("add IPSECKEY pluto as publickey %s dns query is %s %s %s",
				thatidbuf,
				dnsr->qname, ttl_buf,
				enum_name(&dns_auth_level_names, al)));
	}

	ugh = add_ipseckey(&keyid, al, PUBKEY_ALG_RSA, ttl, ttl_used,
			&keyval, &pluto_pubkeys);
	if (ugh != NULL)
		loglog(RC_LOG_SERIOUS, "Add  publickey failed %s, %s, %s", ugh,
				thatidbuf, dnsr->log_buf);

	freeanychunk(keyval);
	return NULL;
}

static void validate_address(struct p_dns_req *dnsr, unsigned char *addr)
{
	struct state *st = state_with_serialno(dnsr->so_serial_t);
	ip_address ipaddr;
	ipstr_buf ra;
	ipstr_buf rb;
	unsigned short af = addrtypeof(&st->st_remoteaddr);
	size_t addr_len = af == AF_INET ? 4 : 16;

	if (dnsr->qtype != LDNS_RR_TYPE_A) {
		return;
	}

	if (initaddr(addr, addr_len, af, &ipaddr) !=  NULL)
		return;

	if (!sameaddr(&ipaddr, &st->st_remoteaddr)) {
		DBG(DBG_DNS,
			DBG_log(" forward address of IDi %s do not match remote address %s != %s",
				dnsr->qname,
				ipstr(&st->st_remoteaddr, &ra),
				ipstr(&ipaddr, &rb)));
		return;
	}

	dnsr->fwd_addr_valid = TRUE;
	DBG(DBG_DNS, DBG_log("address of IDi %s match remote address %s",
				dnsr->qname,
				ipstr(&st->st_remoteaddr, &ra)));
}

static err_t parse_rr(struct p_dns_req *dnsr, ldns_pkt *ldnspkt)
{
	ldns_rr_list *answers = ldns_pkt_answer(ldnspkt);
	ldns_buffer *output = NULL;
	err_t err = "nothing to add";
	size_t i;

	dbg_log_dns_question(dnsr, ldnspkt);

	dnsr->delete_exisiting_keys = TRUE; /* there could something to add */

	for (i = 0; i < ldns_rr_list_rr_count(answers); i++) {
		ldns_rr *ans = ldns_rr_list_rr(answers, i);
		ldns_rr_type atype = ldns_rr_get_type(ans);
		ldns_rr_class qclass = ldns_rr_get_class(ans);
		ldns_lookup_table *class = ldns_lookup_by_id(ldns_rr_classes,
				qclass);
		ldns_lookup_table *class_e = ldns_lookup_by_id(ldns_rr_classes,
				dnsr->qclass);
		ldns_rdf *rdf;
		ldns_status  status = LDNS_STATUS_OK;

		if (output != NULL)
			ldns_buffer_free(output);

		output = ldns_buffer_new((dnsr->wire_len * 8/6 + 2 +1) * 2);

		if (qclass != dnsr->qclass) {
			DBG(DBG_DNS,
				DBG_log("dns answer %zu qclass mismatch expect %s vs %s ignore the answer now",
					i, class_e->name, class->name));
			/* unexpected qclass. possibly malfuctioning dns */
			continue;
		}

		rdf = ldns_rr_rdf(ans, 0);
		if (rdf == NULL) {
			DBG(DBG_DNS,
				DBG_log("dns answer %zu did not convert to rdf ignore this answer",
					i));
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

		DBG(DBG_DNS, DBG_log("%s", ldns_buffer_begin(output)));
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
			DBG(DBG_DNS,
				DBG_log("dns answer %zu qtype mismatch expect %d vs %d ignore this answer",
					i,  dnsr->qtype, atype));
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
		if (IMPAIR(ALLOW_DNS_INSECURE)) {
			DBG(DBG_DNS, DBG_log("Allowing insecure DNS response due to impair"));
			return parse_rr(dnsr, ldnspkt);
		}
		return "unbound returned INSECURE response - ignored";

	case UB_EVNET_SECURE:
		return parse_rr(dnsr, ldnspkt);
	}
}

void  free_ipseckey_dns(struct p_dns_req *d)
{
	struct p_dns_req **pp;
	struct p_dns_req *p;

	if (d == NULL)
		return;

	if (d->ub_async_id !=  0)
	{
		ub_cancel(get_unbound_ctx(), d->ub_async_id);
		d->ub_async_id = 0;
	}

	pfreeany(d->qname);
	pfreeany(d->dbg_buf);
	pfreeany(d->log_buf);

	for (pp = &pluto_dns_list; (p = *pp) != NULL; pp = &p->next) {
		if (p == d) {
			*pp = p->next;  /* unlink this dns request */
			pfree(d);
			return;
		}
	}
}

static void ikev2_ipseckey_log_missing_st(struct p_dns_req *dnsr)
{
	deltatime_t served_delta = realtimediff(dnsr->done_time, dnsr->start_time);
	LSWLOG_RC(RC_LOG_SERIOUS, buf) {
		lswlogf(buf, "%s The state #%lu is gone. %s returned %s elapsed time  ",
			dnsr->dbg_buf, dnsr->so_serial_t,
			dnsr->log_buf,  dnsr->rcode_name);
		lswlog_deltatime(buf, served_delta);
	}
}

static void ikev2_ipseckey_log_dns_err(struct p_dns_req *dnsr,
		const char *err)
{
	deltatime_t served_delta = realtimediff(dnsr->done_time, dnsr->start_time);
	LSWLOG_RC(RC_LOG_SERIOUS, buf) {
		lswlogf(buf, "%s returned %s rr parse error %s elapsed time ",
			dnsr->log_buf,
			dnsr->rcode_name, err);
		lswlog_deltatime(buf, served_delta);
	}
}

static void ipseckey_dbg_dns_resp(struct p_dns_req *dnsr)
{
	deltatime_t served_delta = realtimediff(dnsr->done_time, dnsr->start_time);
	LSWDBGP(DBG_CONTROL, buf) {
		lswlogf(buf, "%s returned %s cache=%s elapsed time ",
			dnsr->log_buf,
			dnsr->rcode_name,
			bool_str(dnsr->cache_hit));
		lswlog_deltatime(buf, served_delta);
	}

	DBG(DBG_DNS, {
		const enum lswub_resolve_event_secure_kind k = dnsr->secure;

		DBG_log("DNSSEC=%s %s MSG SIZE %d bytes",
			k == UB_EVNET_SECURE ? "SECURE"
			: k == UB_EVENT_INSECURE ? "INSECURE"
			: k == UB_EVENT_BOGUS ? "BOGUS"
			: "invalid lswub_resolve_event_secure_kind",

			k == UB_EVENT_BOGUS ? dnsr->why_bogus : "",
			dnsr->wire_len);
	});
}

static void idr_ipseckey_fetch_continue(struct p_dns_req *dnsr)
{
	struct state *st = state_with_serialno(dnsr->so_serial_t);
	const char *parse_err;

	dnsr->done_time = realnow();

	if (st == NULL) {
		/* state disappeared we can't find  discard the response */
		ikev2_ipseckey_log_missing_st(dnsr);
		free_ipseckey_dns(dnsr);
		return;
	}

	set_cur_state(st);

	ipseckey_dbg_dns_resp(dnsr);
	parse_err = process_dns_resp(dnsr);

	if (parse_err != NULL) {
		ikev2_ipseckey_log_dns_err(dnsr, parse_err);
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
	dnsr->ub_async_id = 0; /* this query is done no need to cancel it */

	st->ipseckey_dnsr = NULL;
	free_ipseckey_dns(dnsr);
	reset_globals();
}

static void idi_ipseckey_fetch_tail(struct state *st, bool err)
{
	struct msg_digest *md = unsuspend_md(st);
	stf_status stf;

	passert(md !=  NULL && (st == md->st));

	if (err) {
		stf = STF_FAIL + v2N_AUTHENTICATION_FAILED;
	} else {
		stf = ikev2_parent_inI2outR2_id_tail(md);
	}

	complete_v2_state_transition(&md, stf);
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

	dnsr->ub_async_id = 0; /* this query is done no need to cancel it */
	st->ipseckey_fwd_dnsr = NULL;

	if (st->ipseckey_dnsr != NULL) {
		DBG(DBG_CONTROL, DBG_log("wait for IPSECKEY DNS response %s",
					dnsr->qname));
		/* wait for additional A/AAAA dns response */
		free_ipseckey_dns(dnsr);
		return;
	}

	DBG(DBG_CONTROL, DBG_log("%s unsuspend id=%s", dnsr->dbg_buf,
				dnsr->qname));

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
		ikev2_ipseckey_log_dns_err(dnsr, parse_err);
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

	dnsr->ub_async_id = 0; /* this query is done no need to cancel it */

	st->ipseckey_dnsr = NULL;

	if (st->ipseckey_fwd_dnsr != NULL) {
		DBG(DBG_CONTROL, DBG_log("wait for additional DNS A/AAAA check %s",
					dnsr->qname));
		/* wait for additional A/AAAA dns response */
		free_ipseckey_dns(dnsr);
		return;
	} else {
		DBG(DBG_CONTROL, DBG_log("%s unsuspend id=%s", dnsr->dbg_buf,
					dnsr->qname));
		free_ipseckey_dns(dnsr);
		idi_ipseckey_fetch_tail(st, err);
	}
}

static void ipseckey_ub_cb(void* mydata, int rcode,
		void *wire, int wire_len, int secure, char* why_bogus)
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

static err_t build_dns_name(char *name_buf, /* len SWAN_MAX_DOMAIN_LEN */
		const struct id *id)
{
	/* note: all end in "." to suppress relative searches */

	if (id->name.len >= SWAN_MAX_DOMAIN_LEN)
		return "ID is too long >= SWAN_MAX_DOMAIN_LEN";

	switch (id->kind) {
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		addrtot(&id->ip_addr, 'r', name_buf, SWAN_MAX_DOMAIN_LEN);
		break;

	case ID_FQDN:
		{
			/* expected len of name_buf */
			size_t buf_len = SWAN_MAX_DOMAIN_LEN;
			size_t il;

			/* idtoa() will have an extra @ as prefix */

			il = snprintf(name_buf, buf_len, "%.*s", (int)id->name.len, id->name.ptr);

			/* strip trailing "." characters, then add one */
			while (il > 0 && name_buf[il - 1] == '.')
				il--;

			if (il > SWAN_MAX_DOMAIN_LEN)
				return "FQDN is too long for domain name";

			add_str(name_buf, buf_len, (name_buf + il), ".");
		}
		break;

	default:
		return "can only query DNS for IPSECKEY for ID that is a FQDN, IPV4_ADDR, or IPV6_ADDR";
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
	char dbg_buf[512] ;  /* Arbitrary length. It is local */
	struct p_dns_req *p;
	char log_buf[SWAN_MAX_DOMAIN_LEN * 2]; /* this is local */
	char qname[SWAN_MAX_DOMAIN_LEN];
	err_t err;


	err = build_dns_name(qname, &id);
	if (err !=  NULL) {
		/* is there qtype to name lookup function  */
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
	return qry_st_init(st, LDNS_RR_TYPE_IPSECKEY,  "IPSECKEY", dnsr_cb);
}

static stf_status dns_qry_start(struct p_dns_req *dnsr)
{
	int ub_ret;
	stf_status ret;

	passert(get_unbound_ctx() != NULL);

	DBG(DBG_CONTROL, DBG_log("%s start %s", dnsr->dbg_buf, dnsr->log_buf));

	dnsr->start_time = realnow();

	ub_ret = ub_resolve_event(get_unbound_ctx(), dnsr->qname, dnsr->qtype,
			dnsr->qclass, dnsr, ipseckey_ub_cb, &dnsr->ub_async_id);

	if (ub_ret !=  0) {
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
 * the call back function  will be called without returning.
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
		ret = STF_OK; /* while querying IDr do not suspend */
	}

	return ret;
}

/*
 * On responder query IPSECKEY for IDi, it could be FQDN or IP.
 * The returned ipsec key(s) will be added to public store, with keyid IDi.
 * New key(s) will overwrite any exisitng one(s) with same keyid in pluto's
 * global public key store.
 *
 * If DNS returns multiple IPSECKEY RR add all of keys, with same keyid.
 *
 * Note: libunbound call back quirck, if the data is local or cached
 * the call back function  will be called without returning.
 */
stf_status idi_ipseckey_fetch(struct msg_digest *md)
{
	stf_status ret_idi;
	stf_status ret_a = STF_OK;
	stf_status ret = STF_FAIL;
	struct state *st = md->st;
	struct p_dns_req *dnsr_a = NULL;
	struct p_dns_req *dnsr_idi = ipseckey_qry_st_init(st,
			idi_ipseckey_fetch_continue);

	if (dnsr_idi == NULL) {
		return ret;
	}

	ret_idi = dns_qry_start(dnsr_idi);

	if (ret_idi != STF_SUSPEND  && ret_idi != STF_OK) {
		return ret_idi;
	}

	if (LIN(st->st_connection->policy, POLICY_DNS_MATCH_ID)) {
		struct id id = st->st_connection->spd.that.id;
		if (id.kind == ID_FQDN) {
			dnsr_a = qry_st_init(st, LDNS_RR_TYPE_A, "A", idi_a_fetch_continue);

			if (dnsr_a == NULL) {
				free_ipseckey_dns(dnsr_idi);
				return ret;
			}

			ret_a = dns_qry_start(dnsr_a);
		}
	}

	if (ret_a != STF_SUSPEND && ret_a != STF_OK) {
		free_ipseckey_dns(dnsr_idi);
	} else if (ret_a == STF_SUSPEND || ret_idi == STF_SUSPEND) {
		/* all success */
		st->ipseckey_dnsr = dnsr_idi;
		st->ipseckey_fwd_dnsr = dnsr_a;
		ret = STF_SUSPEND;
	}

	return ret;
}
