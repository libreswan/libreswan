/* IKEv2 Redirect Mechanism (RFC 5685) related functions, for libreswan
 *
 * Copyright (C) 2018 - 2020 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2020 Paul Wouters <pwouters@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <unistd.h>


#include "constants.h"
#include "defs.h"

#include "id.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "demux.h"
#include "ip_address.h"
#include "ipsec_doi.h"
#include "ikev2.h"
#include "ikev2_send.h"
#include "ip_info.h"
#include "ikev2_redirect.h"
#include "initiate.h"
#include "log.h"
#include "pending.h"
#include "pluto_stats.h"

static callback_cb initiate_redirect;

enum allow_global_redirect global_redirect = GLOBAL_REDIRECT_NO;

struct redirect_dests {
	char *whole;
	const char *next;	/* points into whole */
};

static struct redirect_dests global_dests = { NULL, NULL };

const char *global_redirect_to(void)
{
	if (global_dests.whole == NULL)
		return ""; /* allows caller to strlen() */
	return global_dests.whole;
}

static void free_redirect_dests(struct redirect_dests *dests)
{
	pfreeany(dests->whole);
	dests->next = NULL;
}

void free_global_redirect_dests(void)
{
	free_redirect_dests(&global_dests);
}

static void set_redirect_dests(const char *rd_str, struct redirect_dests *dests)
{
	free_redirect_dests(dests);

	/* strip any leading delimiters */
	const char *c = rd_str == NULL ? "" : rd_str + strspn(rd_str, ", \t");
	dests->whole = clone_str(c, "redirect dests");
	dests->next = dests->whole;
}

void set_global_redirect_dests(const char *grd_str)
{
	set_redirect_dests(grd_str, &global_dests);
}

/*
 * Returns a string (shunk) destination to be shipped in REDIRECT payload.
 *
 * @param rl struct containing redirect destinations
 * @return shunk_t string to be shipped.
 */

static shunk_t next_redirect_dest(struct redirect_dests *rl)
{
	const char *r = *rl->next == '\0' ? rl->whole : rl->next;
	size_t len = strcspn(r, ", \t");
	rl->next = r + len + strspn(r + len, ", \t");
	return (shunk_t) { .ptr = r, .len = len };
}

/*
 * Structure of REDIRECT Notify payload from RFC 5685.
 * The second part (Notification data) is interesting to us.
 * GW Ident Type: Type of Identity of new gateway
 * GW Ident Len:  Length of the New Responder GW Identity field
 *
 * Nonce Data is sent only if Redirect is happening during
 * IKE_SA_INIT exchange.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Next Payload  |C|  RESERVED   |         Payload Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Protocol ID(=0)| SPI Size (=0) |      Notify Message Type      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | GW Ident Type |  GW Ident Len |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               ~
 * ~                   New Responder GW Identity                   ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * ~                        Nonce Data                             ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Routines to build a notification data for REDIRECT (or REDIRECTED_FROM)
 * payload from the given string or ip.
 */

static shunk_t build_redirect_notification_data_common(enum gw_identity_type gwit,
						       shunk_t id,
						       const shunk_t *nonce, /* optional */
						       uint8_t *buf, size_t sizeof_buf,
						       struct logger *logger)
{
	if (id.len > 0xFF) {
		llog(RC_LOG_SERIOUS, logger,
		     "redirect destination longer than 255 octets; ignoring");
		return empty_shunk;
	}

	struct ikev2_redirect_part gwi = {
		/* note: struct has no holes */
		.gw_identity_type = gwit,
		.gw_identity_len = id.len
	};

	/*
	 * Create a free-standing PBS in which to build notification data.
	 */
	struct pbs_out gwid_pbs = open_pbs_out("gwid_pbs",
					       buf, sizeof_buf,
					       logger);
	if (!out_struct(&gwi, &ikev2_redirect_desc, &gwid_pbs, NULL)) {
		return empty_shunk;
	}
	if (!pbs_out_hunk(&gwid_pbs, id, "redirect ID")) {
		/* already logged */
		return empty_shunk;
	}
	if (nonce == NULL || out_hunk(*nonce, &gwid_pbs, "nonce in redirect notify"))
	{
		close_output_pbs(&gwid_pbs);
		return pbs_out_all(&gwid_pbs);
	}

	return empty_shunk;
}

static shunk_t build_redirect_notification_data_ip(const ip_address *dest_ip,
						   const shunk_t *nonce, /* optional */
						   uint8_t *buf, size_t sizeof_buf,
						   struct logger *logger)
{
	enum gw_identity_type gwit;

	const struct ip_info *afi = address_type(dest_ip);
	passert(afi != NULL);
	switch (afi->af) {
	case AF_INET:
		gwit = GW_IPV4;
		break;
	case AF_INET6:
		gwit = GW_IPV6;
		break;
	default:
		bad_case(afi->af);
	}

	return build_redirect_notification_data_common(gwit, address_as_shunk(dest_ip), nonce,
						       buf, sizeof_buf, logger);
}

/* function caller should ensure dest is non-empty string */
static shunk_t build_redirect_notification_data_str(const shunk_t dest,
						    const shunk_t *nonce, /* optional */
						    uint8_t *buf, size_t sizeof_buf,
						    struct logger *logger)
{
	ip_address ip_addr;
	err_t ugh = ttoaddress_num(dest, NULL/*UNSPEC*/, &ip_addr);

	if (ugh != NULL) {
		/*
		* ttoaddr_num failed: just ship dest_str as a FQDN
		* ??? it may be a bogus string
		*/
		return build_redirect_notification_data_common(GW_FQDN, dest, nonce,
							       buf, sizeof_buf, logger);
	} else {
		return build_redirect_notification_data_ip(&ip_addr, nonce,
							   buf, sizeof_buf, logger);
	}
}

bool redirect_global(struct msg_digest *md)
{
	struct logger *logger = md->md_logger;

	/* if we don't support global redirection, no need to continue */
	if (global_redirect == GLOBAL_REDIRECT_NO ||
	    (global_redirect == GLOBAL_REDIRECT_AUTO && !require_ddos_cookies()))
		return false;

	/*
	 * From this point on we know that redirection is a must, and return
	 * value will be true. The only thing that we need to note is whether
	 * we redirect or not, and that difference will be marked with a
	 * log message.
	 */

	if (md->chain[ISAKMP_NEXT_v2Ni] == NULL) {
		/* Ni is used as cookie to protect REDIRECT in IKE_SA_INIT */
		dbg("Ni payload required for REDIRECT is missing");
		pstats_ikev2_redirect_failed++;
		return true;
	}

	if (md->pd[PD_v2N_REDIRECTED_FROM] == NULL &&
	    md->pd[PD_v2N_REDIRECT_SUPPORTED] == NULL) {
		dbg("peer didn't indicate support for redirection");
		pstats_ikev2_redirect_failed++;
		return true;
	}

	shunk_t Ni = pbs_in_left(&md->chain[ISAKMP_NEXT_v2Ni]->pbs);
	if (Ni.len == 0) {
		dbg("Initiator nonce should not be zero length");
		pstats_ikev2_redirect_failed++;
		return true;
	}

	shunk_t dest = next_redirect_dest(&global_dests);
	if (dest.len == 0) {
		dbg("no (meaningful) destination for global redirection has been specified");
		pstats_ikev2_redirect_failed++;
		return true;
	}

	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	shunk_t data = build_redirect_notification_data_str(dest, &Ni,
							    buf, sizeof(buf),
							    logger);

	if (data.len == 0) {
		llog(RC_LOG_SERIOUS, logger,
			    "failed to construct REDIRECT notification data");
		pstats_ikev2_redirect_failed++;
		return true;
	}

	send_v2N_response_from_md(md, v2N_REDIRECT, &data);
	pstats_ikev2_redirect_completed++;
	return true;
}

bool emit_redirect_notification(const shunk_t dest_str, struct pbs_out *outs)
{
	passert(dest_str.ptr != NULL);

	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	shunk_t data = build_redirect_notification_data_str(dest_str, NULL,
							    buf, sizeof(buf),
							    outs->outs_logger);

	return data.len > 0 && emit_v2N_hunk(v2N_REDIRECT, data, outs);
}

bool emit_redirected_from_notification(const ip_address *ip_addr, struct pbs_out *outs)
{
	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	shunk_t data = build_redirect_notification_data_ip(ip_addr, NULL,
							   buf, sizeof(buf),
							   outs->outs_logger);

	return data.len > 0 && emit_v2N_hunk(v2N_REDIRECTED_FROM, data, outs);
}

/*
 * Iterate through the allowed_targets_list, and if none of the
 * specified addresses matches the one from REDIRECT
 * payload, return FALSE
 */
static bool allow_to_be_redirected(const char *allowed_targets_list, ip_address *dest_ip)
{
	if (allowed_targets_list == NULL || streq(allowed_targets_list, "%any"))
		return true;

	for (const char *t = allowed_targets_list;; ) {
		t += strspn(t, ", ");	/* skip leading separator */
		int len = (int) strcspn(t, ", ");	/* length of name */
		if (len == 0)
			break;	/* no more */

		ip_address ip_addr;
		err_t ugh = ttoaddress_num(shunk2(t, len), NULL/*UNSPEC*/, &ip_addr);

		if (ugh != NULL) {
			dbg("address %.*s isn't a valid address", len, t);
		} else if (sameaddr(dest_ip, &ip_addr)) {
			dbg("address %.*s is a match to received GW identity", len, t);
			return true;
		} else {
			dbg("address %.*s is not a match to received GW identity", len, t);
		}
		t += len;	/* skip name */
	}
	dbg("we did not find suitable address in the list specified by accept-redirect-to option");
	return false;
}

/*
 * Extract needed information from IKEv2 Notify Redirect
 * notification.
 *
 * @param data that was transferred in v2_REDIRECT Notify
 * @param char* list of addresses we accept being redirected
 * 	  to, specified with conn option accept-redirect-to
 * @param nonce that was send in IKE_SA_INIT request,
 * 	  we need to compare it with nonce data sent
 * 	  in Notify data. We do all that only if
 * 	  nonce isn't NULL.
 * @param redirect_ip ip address we need to redirect to
 * @return err_t NULL if everything went right,
 * 		 otherwise (non-NULL) what went wrong
 *
 * XXX: this logs and returns err_t; sometimes.
 */

static err_t parse_redirect_payload(const struct pbs_in *notify_pbs,
				    const char *allowed_targets_list,
				    const chunk_t *nonce,
				    ip_address *redirect_ip /* result */,
				    struct logger *logger)
{
	struct pbs_in input_pbs = *notify_pbs;
	struct ikev2_redirect_part gw_info;

	diag_t d = pbs_in_struct(&input_pbs, &ikev2_redirect_desc,
				 &gw_info, sizeof(gw_info), NULL);
	if (d != NULL) {
		llog_diag(RC_LOG_SERIOUS, logger, &d, "%s", "");
		return "received malformed REDIRECT payload";
	}

	const struct ip_info *af;

	switch (gw_info.gw_identity_type) {
	case GW_IPV4:
		af = &ipv4_info;
		break;
	case GW_IPV6:
		af = &ipv6_info;
		break;
	case GW_FQDN:
		af = NULL;
		break;
	default:
		return "bad GW Ident Type";
	}

	/* extract actual GW Identity */
	if (af == NULL) {
		/*
		 * The FQDN string isn't NUL-terminated.
		 *
		 * The length is stored in a byte so it cannot be
		 * larger than 0xFF.
		 * Some helpful compilers moan about this test being always true
		 * so I eliminated it:
		 *	passert(gw_info.gw_identity_len <= 0xFF);
		 */
		shunk_t gw_str;
		diag_t d = pbs_in_shunk(&input_pbs, gw_info.gw_identity_len, &gw_str, "GW Identity");
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, logger, &d, "%s", "");
			return "error while extracting GW Identity from variable part of IKEv2_REDIRECT Notify payload";
		}

		err_t ugh = ttoaddress_dns(gw_str, NULL/*UNSPEC*/, redirect_ip);
		if (ugh != NULL)
			return ugh;
	} else {
		if (gw_info.gw_identity_len < af->ip_size) {
			return "transferred GW Identity Length is too small for an IP address";
		}
		diag_t d = pbs_in_address(&input_pbs, redirect_ip, af, "REDIRECT address");
		if (d != NULL) {
			llog_diag(RC_LOG, logger, &d, "%s", "");
			return "variable part of payload does not match transferred GW Identity Length";
		}
		address_buf b;
		dbg("   GW Identity IP: %s", ipstr(redirect_ip, &b));
	}

	/*
	 * now check the list of allowed targets to
	 * see if parsed address matches any in the list
	 */
	if (!allow_to_be_redirected(allowed_targets_list, redirect_ip))
		return "received GW Identity is not listed in accept-redirect-to conn option";

	size_t len = pbs_left(&input_pbs);

	if (nonce == NULL) {
		if (len > 0)
			return "unexpected extra bytes in Notify data after GW data - nonce should have been omitted";
	} else if (nonce->len != len || !memeq(nonce->ptr, input_pbs.cur, len)) {
		if (DBGP(DBG_BASE)) {
			DBG_dump_hunk("expected nonce", *nonce);
			DBG_dump("received nonce", input_pbs.cur, len);
		}
		return "received nonce does not match our expected nonce Ni (spoofed packet?)";
	}

	return NULL;
}

bool redirect_ike_auth(struct ike_sa *ike, struct msg_digest *md, stf_status *redirect_status)
{
	if (md->pd[PD_v2N_REDIRECT] == NULL) {
		dbg("redirect: no redirect payload in IKE_AUTH reply");
		return false;
	}

	dbg("redirect: received v2N_REDIRECT in authenticated IKE_AUTH reply");
	if (!LIN(POLICY_ACCEPT_REDIRECT_YES, ike->sa.st_connection->policy)) {
		dbg("ignoring v2N_REDIRECT, we don't accept being redirected");
		return false;
	}

	ip_address redirect_ip;
	err_t err = parse_redirect_payload(&md->pd[PD_v2N_REDIRECT]->pbs,
					   ike->sa.st_connection->config->redirect.accept,
					   NULL,
					   &redirect_ip,
					   ike->sa.st_logger);
	if (err != NULL) {
		dbg("redirect: warning: parsing of v2N_REDIRECT payload failed: %s", err);
		return false;
	}

	/*
	 * MAGIC: the IKE SA is put into limbo (STF_SUSPEND), and then
	 * the initiate_redirect() callback initiates a new SA with
	 * the new IP, and then deletes the old in-limbo IKE SA.
	 */

	/* will use this when initiating in a callback */
	ike->sa.st_connection->temp_vars.redirect_ip = redirect_ip;
	schedule_callback("IKE_AUTH redirect", ike->sa.st_serialno,
			  initiate_redirect, NULL);
	*redirect_status = STF_SUSPEND;
	return true;
}

/*
 * Initiate via initiate_connection new IKE_SA_INIT exchange.
 */

static void initiate_redirect(const char *story, struct state *ike_sa, void *context UNUSED)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	struct connection *c = ike->sa.st_connection;
	ip_address redirect_ip = c->temp_vars.redirect_ip;
	realtime_t now = realnow();

	/*
	 * Schedule event to wipe this SA family and do it first.
	 * Remember, it won't run until after this function returns,
	 * however, it will run before any connections have had a
	 * chance to initiate vis:
	 *
	 * - code below queues up pending connections
	 * - IKE SA is expired (skips revival as connections are pending)
	 * - connections initiate
	 *
	 * This event also deletes any larval children.
	 */
	event_force(EVENT_SA_EXPIRE, &ike->sa);

	/* stuff for loop detection */

	if (c->temp_vars.num_redirects >= MAX_REDIRECTS) {
		if (deltatime_cmp(realtimediff(c->temp_vars.first_redirect_time, now),
				  <,
				  deltatime(REDIRECT_LOOP_DETECT_PERIOD))) {
			llog_sa(RC_LOG_SERIOUS, ike,
				"%s loop, stop initiating IKEv2 exchanges",
				story);
			return;
		}

		/* restart count */
		c->temp_vars.num_redirects = 0;
	}

	if (c->temp_vars.num_redirects == 0) {
		  c->temp_vars.first_redirect_time = now;
	}
	c->temp_vars.num_redirects++;

	/* save old address for REDIRECTED_FROM notify */
	c->temp_vars.old_gw_address = c->remote->host.addr;
	/* update host_addr of other end, port stays the same */
	c->remote->host.addr = redirect_ip;

	address_buf b;
	llog_sa(RC_LOG, ike,
		"initiating %s to new gateway (address: %s)",
		story, str_address_sensitive(&redirect_ip, &b));

	/* XXX: only makes sense when IKE_SA_INIT / IKE_AUTH redirect? */
	flush_pending_by_state(ike);

	initiate_connection(c, /*remote-host-name*/NULL,
			    /*background*/false /* try to keep it in the foreground */,
			    ike->sa.st_logger);
}

/* helper function for send_v2_informational_request() */

static bool add_redirect_payload(struct state *st, struct pbs_out *pbs)
{
	return emit_redirect_notification(HUNK_AS_SHUNK(st->st_active_redirect_gw), pbs);
}

static stf_status send_v2_redirect_ike_request(struct ike_sa *ike,
					       struct child_sa *child UNUSED,
					       struct msg_digest *null_md UNUSED)
{
	return record_v2_informational_request("active REDIRECT informational request",
					       ike, &ike->sa, add_redirect_payload);
}

static const struct v2_state_transition v2_redirect_ike_transition = {
	.story = "redirect IKE SA",
	.state = STATE_V2_ESTABLISHED_IKE_SA,
	.next_state = STATE_V2_ESTABLISHED_IKE_SA,
	.exchange = ISAKMP_v2_INFORMATIONAL,
	.send_role = MESSAGE_REQUEST,
	.processor = send_v2_redirect_ike_request,
	.llog_success = ldbg_v2_success,
	.timeout_event =  EVENT_RETAIN,
};

void find_and_active_redirect_states(const char *conn_name,
				     const char *active_redirect_dests,
				     struct logger *logger)
{
	passert(active_redirect_dests != NULL);
	struct redirect_dests active_dests = { NULL, NULL };
	set_redirect_dests(active_redirect_dests, &active_dests);

	int cnt = 0;

	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;
		if (IS_IKE_SA_ESTABLISHED(st) &&
		    (conn_name == NULL || streq(conn_name, st->st_connection->name))) {
			struct ike_sa *ike = pexpect_ike_sa(st);
			/* cycle through the list of redirects */
			shunk_t active_dest = next_redirect_dest(&active_dests);
			/* not whack; there could be thousands? */
			llog_sa(RC_LOG|LOG_STREAM, ike, "redirecting to: "PRI_SHUNK,
				pri_shunk(active_dest));
			free_chunk_content(&ike->sa.st_active_redirect_gw);
			ike->sa.st_active_redirect_gw = clone_hunk(active_dest, "redirect");
			cnt++;
			pexpect(v2_redirect_ike_transition.exchange == ISAKMP_v2_INFORMATIONAL);
			v2_msgid_queue_initiator(ike, NULL, &v2_redirect_ike_transition);
		}
	}

	if (cnt == 0) {
		LLOG_JAMBUF(RC_INFORMATIONAL, logger, buf) {
			jam(buf, "no active tunnels found");
			if (conn_name != NULL) {
				jam(buf, " for connection \"%s\"", conn_name);
			}
		}
	} else {
		LLOG_JAMBUF(RC_INFORMATIONAL, logger, buf) {
			jam(buf, "redirections sent for %d tunnels", cnt);
			if (conn_name != NULL) {
				jam(buf, " of connection \"%s\"", conn_name);
			}
		}
	}
	free_redirect_dests(&active_dests);
}

stf_status process_v2_IKE_SA_INIT_response_v2N_REDIRECT(struct ike_sa *ike,
							struct child_sa *child,
							struct msg_digest *md)
{
	struct connection *c = ike->sa.st_connection;
	pexpect(child == NULL);
	if (!pexpect(md->pd[PD_v2N_REDIRECT] != NULL)) {
		return STF_INTERNAL_ERROR;
	}
	struct pbs_in redirect_pbs = md->pd[PD_v2N_REDIRECT]->pbs;

	if (!LIN(POLICY_ACCEPT_REDIRECT_YES, ike->sa.st_connection->policy)) {
		llog_sa(RC_LOG, ike,
			  "ignoring v2N_REDIRECT, we don't accept being redirected");
		return STF_IGNORE;
	}

	ip_address redirect_ip;
	err_t err = parse_redirect_payload(&redirect_pbs,
					   c->config->redirect.accept,
					   &ike->sa.st_ni,
					   &redirect_ip,
					   ike->sa.st_logger);
	if (err != NULL) {
		llog_sa(RC_LOG_SERIOUS, ike,
			  "warning: parsing of v2N_REDIRECT payload failed: %s", err);
		return STF_IGNORE;
	}

	/*
	 * MAGIC: the IKE SA is put into limbo (STF_SUSPEND), and then
	 * the initiate_redirect() callback initiates a new SA with
	 * the new IP, and then deletes the old in-limbo IKE SA.
	 *
	 * XXX: could this, like for COOKIE and INVALID_KE_PAYLOAD,
	 * use schedule_reinitiate_v2_ike_sa_init() and continue with
	 * the current state?
	 */

	/* will use this when initiating in a callback */
	ike->sa.st_connection->temp_vars.redirect_ip = redirect_ip;
	schedule_callback("IKE_SA_INIT redirect", ike->sa.st_serialno,
			  initiate_redirect, NULL);
	return STF_SUSPEND;
}

void process_v2_INFORMATIONAL_request_v2N_REDIRECT(struct ike_sa *ike, struct msg_digest *md)
{
	struct pbs_in pbs = md->pd[PD_v2N_REDIRECT]->pbs;
	dbg("received v2N_REDIRECT in informational");
	ip_address redirect_to;
	err_t e = parse_redirect_payload(&pbs, ike->sa.st_connection->config->redirect.accept,
					 NULL, &redirect_to, ike->sa.st_logger);
	if (e != NULL) {
		/* XXX: parse_redirect_payload() also often logs! */
		llog_sa(RC_LOG_SERIOUS, ike,
			"warning: parsing of v2N_REDIRECT payload failed: %s", e);
		return;
	}

	/*
	 * MAGIC: the initiate_redirect() callback initiates a new SA
	 * with the new IP, and then deletes the old IKE SA.
	 */
	ike->sa.st_connection->temp_vars.redirect_ip = redirect_to;
	schedule_callback("active session redirect", ike->sa.st_serialno,
			  initiate_redirect, NULL);
}
