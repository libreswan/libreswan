/*
 * ipseckey lookup for pluto.
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
#include "defs.h"
#include "log.h"
#include "constants.h"	/* for demux.h */
#include "demux.h"	/* to get struct msg_digest */
#include "state.h"
#include "connections.h"
#include "dnssec.h"	/* for lswub_resolve_event_secure_kind */
#include "id.h"
#include "ikev2.h"
#include "ikev2_ipseckey.h"
#include "ikev2_ipseckey_dnsr.h"
#include "keys.h"
#include "secrets.h"
#include "ip_address.h"
#include "ip_info.h"
#include "ikev2_ike_auth.h"

#define LDNS_RR_TYPE_A 1
#define LDNS_RR_TYPE_IPSECKEY 45

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

		enum dns_auth_level al = dnsr->secure == UB_EVENT_SECURE ?
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

static void idr_ipseckey_fetch_continue(struct p_dns_req *dnsr)
{
	struct state *st = state_with_serialno(dnsr->so_serial);
	const char *parse_err;

	dnsr->done_time = realnow();

	if (st == NULL) {
		/* state disappeared we can't find discard the response */
		ikev2_ipseckey_log_missing_st(dnsr);
		free_ipseckey_dns(dnsr);
		return;
	}


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
}

static void idi_ipseckey_fetch_tail(struct state *st, bool err)
{
	struct msg_digest *md = unsuspend_md(st);
	stf_status stf;

	passert(md != NULL && (st == md->v1_st));

	if (err) {
		stf = STF_FAIL + v2N_AUTHENTICATION_FAILED;
	} else {
		stf = ikev2_in_IKE_AUTH_I_out_IKE_AUTH_R_id_tail(md);
	}

	/* replace (*mdp)->st with st ... */
	complete_v2_state_transition(md->v1_st, md, stf);
	release_any_md(&md);
}

static void idi_a_fetch_continue(struct p_dns_req *dnsr)
{
	struct state *st = state_with_serialno(dnsr->so_serial);
	bool err;

	dnsr->done_time = realnow();

	if (st == NULL) {
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

	llog(DEBUG_STREAM, dnsr->logger, "unsuspend id=%s", dnsr->qname);
	free_ipseckey_dns(dnsr);

	idi_ipseckey_fetch_tail(st, err);
}

static void idi_ipseckey_fetch_continue(struct p_dns_req *dnsr)
{
	struct state *st = state_with_serialno(dnsr->so_serial);
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
		llog(DEBUG_STREAM, dnsr->logger, "unsuspend id=%s", dnsr->qname);
		free_ipseckey_dns(dnsr);
		idi_ipseckey_fetch_tail(st, err);
	}
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
				     int qtype,
				     const char *qtype_name,
				     dnsr_cb_fn dnsr_cb)
{
	struct id id = ike->sa.st_connection->spd.that.id;

	char qname[SWAN_MAX_DOMAIN_LEN];
	struct jambuf qbuf = ARRAY_AS_JAMBUF(qname);
	err_t err = build_dns_name(&qbuf, &id);
	if (err != NULL) {
		/* is there qtype to name lookup function */
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "could not build dns query name %s %d",
			  err, qtype);
		return NULL;
	}

	struct p_dns_req *p = alloc_thing(struct p_dns_req, "id remote dns");
	p->so_serial = ike->sa.st_serialno;
	p->logger = clone_logger(ike->sa.st_logger, HERE);
	p->qname = clone_str(qname, "dns qname");

	p->log_buf = alloc_printf("IKEv2 DNS query -- %s IN %s --",
				  p->qname, qtype_name);

	p->qclass = ns_c_in;
	p->qtype = qtype;
	p->cache_hit = TRUE;
	p->stf_status = STF_SUSPEND;
	p->cb = dnsr_cb;

	p->next = pluto_dns_list;
	pluto_dns_list = p;

	return p;
}

static struct p_dns_req *ipseckey_qry_st_init(struct ike_sa *ike, dnsr_cb_fn dnsr_cb)
{
	/* hardcoded RR type to IPSECKEY AA_2017_03 */
	struct p_dns_req *p = qry_st_init(ike, LDNS_RR_TYPE_IPSECKEY, "IPSECKEY", dnsr_cb);
	p->pubkeys_cb = add_dns_pubkeys_to_pluto;
	return p;
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
stf_status idr_ipseckey_fetch(struct ike_sa *ike)
{
	stf_status ret;
	struct p_dns_req *dnsr = ipseckey_qry_st_init(ike, idr_ipseckey_fetch_continue);

	if (dnsr == NULL) {
		return STF_FAIL;
	}

	ret = dns_qry_start(dnsr);

	if (ret == STF_SUSPEND) {
		ike->sa.ipseckey_dnsr = dnsr;
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
stf_status idi_ipseckey_fetch(struct ike_sa *ike)
{
	stf_status ret_idi;
	stf_status ret_a = STF_OK;
	struct p_dns_req *dnsr_a = NULL;
	struct p_dns_req *dnsr_idi = ipseckey_qry_st_init(ike, idi_ipseckey_fetch_continue);

	if (dnsr_idi == NULL) {
		return STF_FAIL;
	}

	ret_idi = dns_qry_start(dnsr_idi);

	if (ret_idi != STF_SUSPEND && ret_idi != STF_OK) {
		return ret_idi;
	}

	if (ret_idi == STF_SUSPEND) {
		ike->sa.ipseckey_dnsr = dnsr_idi;
	}

	if (LIN(ike->sa.st_connection->policy, POLICY_DNS_MATCH_ID)) {
		struct id id = ike->sa.st_connection->spd.that.id;
		if (id.kind == ID_FQDN) {
			dnsr_a = qry_st_init(ike, LDNS_RR_TYPE_A, "A", idi_a_fetch_continue);
			dnsr_a->validate_address_cb = validate_address;

			if (dnsr_a == NULL) {
				free_ipseckey_dns(dnsr_idi);
				return STF_FAIL;
			}
			ret_a = dns_qry_start(dnsr_a);
		}
	}

	if (ret_a == STF_SUSPEND)
		ike->sa.ipseckey_fwd_dnsr = dnsr_a;

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
