/* Openswan NAT-Traversal
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
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
 *
 * RCSID $Id: nat_traversal.c,v 1.26.2.5 2005/11/24 05:30:37 ken Exp $
 */

#ifdef NAT_TRAVERSAL

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>     /* used only if MSG_NOSIGNAL not defined */
#include <sys/queue.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include <pfkeyv2.h>
#include <pfkey.h>

#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "log.h"
#include "server.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"
#include "packet.h"
#include "demux.h"
#include "kernel.h"
#include "whack.h"
#include "timer.h"
#include "ike_alg.h"

#include "cookie.h"
#include "sha1.h"
#include "md5.h"
#include "crypto.h"
#include "vendor.h"

#include "natt_defines.h"
#include "nat_traversal.h"

#define NAT_D_DEBUG
#define NAT_T_SUPPORT_LAST_DRAFTS

#define DEFAULT_KEEP_ALIVE_PERIOD  20

bool nat_traversal_enabled = FALSE;
bool nat_traversal_support_non_ike = FALSE;
bool nat_traversal_support_port_floating = FALSE;

static unsigned int _kap = 0;
static unsigned int _ka_evt = 0;
static bool _force_ka = 0;

static const char *natt_version = "0.6c";

void init_nat_traversal (bool activate, unsigned int keep_alive_period,
	bool fka, bool spf)
{
	nat_traversal_enabled = activate;
	nat_traversal_support_non_ike = activate;
#ifdef NAT_T_SUPPORT_LAST_DRAFTS
	nat_traversal_support_port_floating = activate ? spf : FALSE;
	openswan_log("Setting NAT-Traversal port-4500 floating to %s"
		     , nat_traversal_support_port_floating ? "on" : "off");
	openswan_log("   port floating activation criteria nat_t=%d/port_fload=%d"
		     , activate, spf);
#endif
        {
          FILE *f = fopen("/proc/net/ipsec/natt", "r");
          char n;
          if(f != NULL) {
            n=getc(f);
            if(n=='0') {
              nat_traversal_enabled = FALSE;
              nat_traversal_support_non_ike=FALSE;
              nat_traversal_support_port_floating=FALSE;
              openswan_log("  KLIPS does not have NAT-Traversal built in (see /proc/net/ipsec/natt)\n");
            }
            fclose(f);
          }
        }

	_force_ka = fka;
	_kap = keep_alive_period ? keep_alive_period : DEFAULT_KEEP_ALIVE_PERIOD;
	plog("  including NAT-Traversal patch (Version %s)%s%s%s",
		natt_version, activate ? "" : " [disabled]",
		activate & fka ? " [Force KeepAlive]" : "",
		activate & !spf ? " [Port Floating disabled]" : "");
}

static void disable_nat_traversal(int type)
{
	if (type == ESPINUDP_WITH_NON_IKE)
		nat_traversal_support_non_ike = FALSE;
	else {
	  openswan_log("NAT-Traversal port floating turned off");
	  nat_traversal_support_port_floating = FALSE;
	}

	if (!nat_traversal_support_non_ike &&
	    !nat_traversal_support_port_floating) {
	    openswan_log("NAT-Traversal is turned OFF due to lack of KERNEL support: %d/%d"
			 , nat_traversal_support_non_ike
			 , nat_traversal_support_port_floating);
	    nat_traversal_enabled = FALSE;
	}
}

static void _natd_hash(const struct hash_desc *hasher, char *hash,
	u_int8_t *icookie, u_int8_t *rcookie,
	const ip_address *ip, u_int16_t port /* network order */)
{
	union hash_ctx ctx;

	if (is_zero_cookie(icookie))
		DBG_log("_natd_hash: Warning, icookie is zero !!");
	if (is_zero_cookie(rcookie))
		DBG_log("_natd_hash: Warning, rcookie is zero !!");

	/**
	 * draft-ietf-ipsec-nat-t-ike-01.txt
	 *
	 *   HASH = HASH(CKY-I | CKY-R | IP | Port)
	 *
	 * All values in network order
	 */
	hasher->hash_init(&ctx);
	hasher->hash_update(&ctx, icookie, COOKIE_SIZE);
	hasher->hash_update(&ctx, rcookie, COOKIE_SIZE);
	switch (addrtypeof(ip)) {
		case AF_INET:
			hasher->hash_update(&ctx,
				(const u_char *)&ip->u.v4.sin_addr.s_addr,
				sizeof(ip->u.v4.sin_addr.s_addr));
			break;
		case AF_INET6:
			hasher->hash_update(&ctx,
				(const u_char *)&ip->u.v6.sin6_addr.s6_addr,
				sizeof(ip->u.v6.sin6_addr.s6_addr));
			break;
	}
	hasher->hash_update(&ctx, (const u_char *)&port, sizeof(u_int16_t));
	hasher->hash_final(hash, &ctx);
#ifdef NAT_D_DEBUG
	DBG(DBG_NATT,
		DBG_log("_natd_hash: hasher=%p(%d)", hasher, (int)hasher->hash_digest_len);
		DBG_dump("_natd_hash: icookie=", icookie, COOKIE_SIZE);
		DBG_dump("_natd_hash: rcookie=", rcookie, COOKIE_SIZE);
		switch (addrtypeof(ip)) {
			case AF_INET:
				DBG_dump("_natd_hash: ip=", &ip->u.v4.sin_addr.s_addr,
					sizeof(ip->u.v4.sin_addr.s_addr));
				break;
		}
		DBG_log("_natd_hash: port=%d", ntohs(port));
		DBG_dump("_natd_hash: hash=", hash, hasher->hash_digest_len);
	);
#endif
}

/**
 * Add NAT-Traversal VIDs (supported ones)
 *
 * Used when we're Initiator
 */
bool nat_traversal_add_vid(u_int8_t np, pb_stream *outs)
{
	bool r = TRUE;
	DBG(DBG_NATT
	    , DBG_log("nat add vid. port: %d nonike: %d"
		      , nat_traversal_support_port_floating
		      , nat_traversal_support_non_ike));
		      
	if (nat_traversal_support_port_floating) {
		if (r) r = out_vendorid(np, outs, VID_NATT_RFC);
		if (r) r = out_vendorid(np, outs, VID_NATT_IETF_03);
		if (r) r = out_vendorid(np, outs, VID_NATT_IETF_02);
	}
	if (nat_traversal_support_non_ike) {
		if (r) r = out_vendorid(np, outs, VID_NATT_IETF_00);
	}
	return r;
}

u_int32_t nat_traversal_vid_to_method(unsigned short nat_t_vid)
{
	switch (nat_t_vid) {
		case VID_NATT_IETF_00:
			return LELEM(NAT_TRAVERSAL_IETF_00_01);
			break;
		case VID_NATT_IETF_02:
		case VID_NATT_IETF_02_N:
		case VID_NATT_IETF_03:
			return LELEM(NAT_TRAVERSAL_IETF_02_03);
			break;
		case VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE:
			return LELEM(NAT_TRAVERSAL_OSX);
			break;
		case VID_NATT_RFC:
			return LELEM(NAT_TRAVERSAL_RFC);
			break;
	}
	return 0;
}


void nat_traversal_natd_lookup(struct msg_digest *md)
{
	unsigned char hash_me[MAX_DIGEST_LEN];
	unsigned char hash_him[MAX_DIGEST_LEN];
	struct payload_digest *p;
	struct state *st = md->st;
	bool found_me = FALSE;
	bool found_him= FALSE;
	int i;

	if (!st || !md->iface || !st->st_oakley.hasher) {
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: assert failed %s:%d",
			__FILE__, __LINE__);
		return;
	}

	/** Count NAT-D **/
	for (p = md->chain[ISAKMP_NEXT_NATD_RFC], i=0;
	     p != NULL;
	     p = p->next, i++);

	/**
	 * We need at least 2 NAT-D (1 for us, many for peer)
	 */
	if (i < 2) {
		loglog(RC_LOG_SERIOUS,
		"NAT-Traversal: Only %d NAT-D - Aborting NAT-Traversal negotiation", i);
		st->hidden_variables.st_nat_traversal = 0;
		return;
	}

	/**
	 * First one with my IP & port
	 */
	_natd_hash(st->st_oakley.hasher, hash_me
		   , st->st_icookie, st->st_rcookie
		   , &(md->iface->ip_addr)
		   , ntohs(md->iface->port));

	/**
	 * The others with sender IP & port
	 */
	_natd_hash(st->st_oakley.hasher, hash_him
		   , st->st_icookie, st->st_rcookie
		   , &(md->sender), ntohs(md->sender_port));

	for (p = md->chain[ISAKMP_NEXT_NATD_RFC], i=0;
	     p != NULL && (!found_me || !found_him);
	     p = p->next)
	  {
#ifdef NAT_D_DEBUG
	    DBG(DBG_NATT,
		DBG_log("NAT_TRAVERSAL hash=%d (me:%d) (him:%d)"
			, i, found_me, found_him);
		DBG_dump("expected NAT-D(me):", hash_me,
			 st->st_oakley.hasher->hash_digest_len);
		DBG_dump("expected NAT-D(him):", hash_him,
			 st->st_oakley.hasher->hash_digest_len);
		DBG_dump("received NAT-D:", p->pbs.cur, pbs_left(&p->pbs));
		);
#endif
	    if ( (pbs_left(&p->pbs) == st->st_oakley.hasher->hash_digest_len)
		 && (memcmp(p->pbs.cur, hash_me
			    , st->st_oakley.hasher->hash_digest_len)==0))
	      {
		found_me = TRUE;
	      } 
	    
	    if ( (pbs_left(&p->pbs) == st->st_oakley.hasher->hash_digest_len)
		 && (memcmp(p->pbs.cur, hash_him
			    , st->st_oakley.hasher->hash_digest_len)==0))
	      {
		found_him = TRUE;
	      } 
	    
	    i++;
	  }
	
	DBG(DBG_NATT,
	    DBG_log("NAT_TRAVERSAL hash=%d (me:%d) (him:%d)"
		    , i, found_me, found_him));
	    
	if(!found_me) {
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_ME);
	}

	if(!found_him) {
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_PEER);
	    st->hidden_variables.st_natd = md->sender;
	}

	if(st->st_connection->forceencaps) {
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_PEER);
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_ME);
	}
}


bool nat_traversal_add_natd(u_int8_t np, pb_stream *outs,
	struct msg_digest *md)
{
	char hash[MAX_DIGEST_LEN];
	struct state *st = md->st;
	unsigned int nat_np;

	if (!st || !st->st_oakley.hasher) {
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: assert failed %s:%d",
			__FILE__, __LINE__);
		return FALSE;
	}

	DBG(DBG_EMITTING, DBG_log("sending NATD payloads"));

	nat_np = (st->hidden_variables.st_nat_traversal & NAT_T_WITH_RFC_VALUES
	      ? ISAKMP_NEXT_NATD_RFC
	      : (st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATD_BADDRAFT_VALUES
	      ? ISAKMP_NEXT_NATD_BADDRAFTS : ISAKMP_NEXT_NATD_DRAFTS));
	if (!out_modify_previous_np(nat_np, outs)) {
		return FALSE;
	}

	/**
	 * First one with sender IP & port
	 */
	if(st->st_connection->forceencaps) {
	    _natd_hash(st->st_oakley.hasher
		       , hash, st->st_icookie
		       , is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie : st->st_rcookie
		       , &(md->sender)
		       , 0);
	} else {
	    _natd_hash(st->st_oakley.hasher, hash, st->st_icookie
		       , is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie : st->st_rcookie
		       , &(md->sender)
		       , htons(md->sender_port));
	}

	if (!out_generic_raw(nat_np, &isakmp_nat_d, outs
			     , hash
			     , st->st_oakley.hasher->hash_digest_len
			     , "NAT-D")) {
	    return FALSE;
	}

	/**
	 * Second one with my IP & port
	 */
	if(st->st_connection->forceencaps) {
	    _natd_hash(st->st_oakley.hasher, hash
		       , st->st_icookie
		       , is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie : st->st_rcookie
		       , &(md->iface->ip_addr),0);
	} else {
	    _natd_hash(st->st_oakley.hasher, hash
		       , st->st_icookie
		       , is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie : st->st_rcookie
		       , &(md->iface->ip_addr)
		       , htons(md->iface->port));
	}
	return (out_generic_raw(np, &isakmp_nat_d, outs,
		hash, st->st_oakley.hasher->hash_digest_len, "NAT-D"));
}

/**
 * nat_traversal_natoa_lookup()
 * 
 * Look for NAT-OA in message
 */
void nat_traversal_natoa_lookup(struct msg_digest *md)
{
	struct payload_digest *p;
	struct state *st = md->st;
	int i;
	ip_address ip;

	if (!st || !md->iface) {
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: assert failed %s:%d",
			__FILE__, __LINE__);
		return;
	}

	/** Initialize NAT-OA */
	anyaddr(AF_INET, &st->hidden_variables.st_nat_oa);

	/** Count NAT-OA **/
	for (p = md->chain[ISAKMP_NEXT_NATOA_RFC], i=0;
	     p != NULL;
	     p = p->next, i++);

	DBG(DBG_NATT,
		DBG_log("NAT-Traversal: received %d NAT-OA.", i);
	);

	if (i==0) {
		return;
	}
	else if (!(st->hidden_variables.st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_PEER))) {
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: received %d NAT-OA. "
			"ignored because peer is not NATed", i);
		return;
	}
	else if (i>1) {
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: received %d NAT-OA. "
			"using first, ignoring others", i);
	}

	/** Take first **/
	p = md->chain[ISAKMP_NEXT_NATOA_RFC];

	DBG(DBG_PARSING,
		DBG_dump("NAT-OA:", p->pbs.start, pbs_room(&p->pbs));
	);

	switch (p->payload.nat_oa.isanoa_idtype) {
		case ID_IPV4_ADDR:
			if (pbs_left(&p->pbs) == sizeof(struct in_addr)) {
				initaddr(p->pbs.cur, pbs_left(&p->pbs)
					 , AF_INET, &ip);
			}
			else {
				loglog(RC_LOG_SERIOUS
				       , "NAT-Traversal: received IPv4 NAT-OA "
				       "with invalid IP size (%d)"
				       , (int)pbs_left(&p->pbs));
				return;
			}
			break;

		case ID_IPV6_ADDR:
			if (pbs_left(&p->pbs) == sizeof(struct in6_addr)) {
				initaddr(p->pbs.cur, pbs_left(&p->pbs)
					 , AF_INET6, &ip);
			}
			else {
				loglog(RC_LOG_SERIOUS
				       , "NAT-Traversal: received IPv6 NAT-OA "
				       "with invalid IP size (%d)"
				       , (int)pbs_left(&p->pbs));
				return;
			}
			break;
		default:
			loglog(RC_LOG_SERIOUS, "NAT-Traversal: "
				"invalid ID Type (%d) in NAT-OA - ignored",
				p->payload.nat_oa.isanoa_idtype);
			return;
			break;
	}

	DBG(DBG_NATT,
		{
			char ip_t[ADDRTOT_BUF];
			addrtot(&ip, 0, ip_t, sizeof(ip_t));
			DBG_log("received NAT-OA: %s", ip_t);
		}
	);

	if (isanyaddr(&ip)) {
		loglog(RC_LOG_SERIOUS
		       , "NAT-Traversal: received %%any NAT-OA...");
	}
	else {
		st->hidden_variables.st_nat_oa = ip;
	}
}

bool nat_traversal_add_natoa(u_int8_t np, pb_stream *outs,
	struct state *st)
{
	struct isakmp_nat_oa natoa;
	pb_stream pbs;
	unsigned char ip_val[sizeof(struct in6_addr)];
	size_t ip_len = 0;
	ip_address *ip;
	unsigned int nat_np;

	if ((!st) || (!st->st_connection)) {
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: assert failed %s:%d",
			__FILE__, __LINE__);
		return FALSE;
	}
	ip = &(st->st_localaddr);

	nat_np = (st->hidden_variables.st_nat_traversal & NAT_T_WITH_RFC_VALUES
		  ? ISAKMP_NEXT_NATOA_RFC : ISAKMP_NEXT_NATOA_DRAFTS);
	if (!out_modify_previous_np(nat_np, outs)) {
		return FALSE;
	}

	memset(&natoa, 0, sizeof(natoa));
	natoa.isanoa_np = np;

	switch (addrtypeof(ip)) {
		case AF_INET:
			ip_len = sizeof(ip->u.v4.sin_addr.s_addr);
			memcpy(ip_val, &ip->u.v4.sin_addr.s_addr, ip_len);
			natoa.isanoa_idtype = ID_IPV4_ADDR;
			break;
		case AF_INET6:
			ip_len = sizeof(ip->u.v6.sin6_addr.s6_addr);
			memcpy(ip_val, &ip->u.v6.sin6_addr.s6_addr, ip_len);
			natoa.isanoa_idtype = ID_IPV6_ADDR;
			break;
		default:
			loglog(RC_LOG_SERIOUS, "NAT-Traversal: "
				"invalid addrtypeof()=%d", addrtypeof(ip));
			return FALSE;
	}

	if (!out_struct(&natoa, &isakmp_nat_oa, outs, &pbs))
		return FALSE;

	if (!out_raw(ip_val, ip_len, &pbs, "NAT-OA"))
		return FALSE;

	DBG(DBG_NATT,
		DBG_dump("NAT-OA (S):", ip_val, ip_len);
	);

	close_output_pbs(&pbs);
	return TRUE;
}

void nat_traversal_show_result (u_int32_t nt, u_int16_t sport)
{
	const char *mth = NULL, *rslt = NULL;
	switch (nt & NAT_TRAVERSAL_METHOD) {
	case LELEM(NAT_TRAVERSAL_IETF_00_01):
	    mth = natt_type_bitnames[0];
	    break;
	case LELEM(NAT_TRAVERSAL_IETF_02_03):
	    mth = natt_type_bitnames[1];
	    break;
	case LELEM(NAT_TRAVERSAL_OSX):
	    mth = natt_type_bitnames[2];
	    break;
	case LELEM(NAT_TRAVERSAL_RFC):
	    mth = natt_type_bitnames[3];
	    break;
	}
	switch (nt & NAT_T_DETECTED) {
		case 0:
			rslt = "no NAT detected";
			break;
		case LELEM(NAT_TRAVERSAL_NAT_BHND_ME):
			rslt = "i am NATed";
			break;
		case LELEM(NAT_TRAVERSAL_NAT_BHND_PEER):
			rslt = "peer is NATed";
			break;
		case LELEM(NAT_TRAVERSAL_NAT_BHND_ME) | LELEM(NAT_TRAVERSAL_NAT_BHND_PEER):
			rslt = "both are NATed";
			break;
	}
	loglog(RC_LOG_SERIOUS,
		"NAT-Traversal: Result using %s: %s",
		mth ? mth : "unknown method",
		rslt ? rslt : "unknown result"
		);
	if ((nt & LELEM(NAT_TRAVERSAL_NAT_BHND_PEER)) &&
		(sport == IKE_UDP_PORT) &&
		((nt & NAT_T_WITH_PORT_FLOATING)==0)) {
		loglog(RC_LOG_SERIOUS,
			"Warning: peer is NATed but source port is still udp/%d. "
			"IPsec-passthrough NAT device suspected -- NAT-T may not work.",
			IKE_UDP_PORT
		);
	}
}

int nat_traversal_espinudp_socket (int sk, const char *fam, u_int32_t type)
{
	int r;
	r = setsockopt(sk, SOL_UDP, UDP_ESPINUDP, &type, sizeof(type));
	if ((r<0) && (errno == ENOPROTOOPT)) {
		loglog(RC_LOG_SERIOUS,
		       "NAT-Traversal: ESPINUDP(%d) not supported by kernel for family %s"
		       , type, fam);
		disable_nat_traversal(type);
	}
	return r;
}

void nat_traversal_new_ka_event (void)
{
	if (_ka_evt) return;  /* Event already schedule */
	event_schedule(EVENT_NAT_T_KEEPALIVE, _kap, NULL);
	_ka_evt = 1;
}

static void nat_traversal_send_ka (struct state *st)
{
	static unsigned char ka_payload = 0xff;
	chunk_t sav;

	DBG(DBG_NATT|DBG_DPD,
		DBG_log("ka_event: send NAT-KA to %s:%d (state=#%lu)"
			, ip_str(&st->st_remoteaddr)
			, st->st_remoteport
			, st->st_serialno);
	);

	/** save state chunk */
	setchunk(sav, st->st_tpacket.ptr, st->st_tpacket.len);

	/** send keep alive */
	setchunk(st->st_tpacket, &ka_payload, 1);
	send_packet(st, "NAT-T Keep Alive", FALSE);

	/** restore state chunk */
	setchunk(st->st_tpacket, sav.ptr, sav.len);
}

/**
 * Find ISAKMP States with NAT-T and send keep-alive
 */
static void nat_traversal_ka_event_state (struct state *st, void *data)
{
	unsigned int *_kap_st = (unsigned int *)data;
	const struct connection *c = st->st_connection;
	if (!c) return;
	if ( ((st->st_state == STATE_MAIN_R3)
	      || (st->st_state == STATE_MAIN_I4)
	      || (st->st_state == STATE_AGGR_R2)
	      || (st->st_state == STATE_AGGR_I2))
	     &&	(st->hidden_variables.st_nat_traversal & NAT_T_DETECTED)
	     &&	((st->hidden_variables.st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME))
		 || (_force_ka)))
	{
	    /**
	     * - ISAKMP established
	     * - NAT-Traversal detected
	     * - NAT-KeepAlive needed (we are NATed)
	     */
	    if (c->newest_isakmp_sa != st->st_serialno) {
		/** 
		 * if newest is also valid, ignore this one, we will only use
		 * newest. 
		 */
		struct state *st_newest;
		st_newest = state_with_serialno(c->newest_isakmp_sa);
		if ((st_newest)
		    && ((st_newest->st_state==STATE_MAIN_R3)
			|| (st_newest->st_state==STATE_MAIN_I4))
		    && (st_newest->hidden_variables.st_nat_traversal & NAT_T_DETECTED)
		    && ((st_newest->hidden_variables.st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME))
			|| (_force_ka)))
		{
		    return;
		}
	    }
	    set_cur_state(st);
	    nat_traversal_send_ka(st);
	    reset_cur_state();
	    (*_kap_st)++;
	}
}

void nat_traversal_ka_event (void)
{
	unsigned int _kap_st = 0;

	_ka_evt = 0;  /* ready to be reschedule */

	for_each_state((void *)nat_traversal_ka_event_state, &_kap_st);

	if (_kap_st) {
	    /**
	     * If there are still states who needs Keep-Alive, schedule new event
	     */
	    nat_traversal_new_ka_event();
	}
}

struct _new_mapp_nfo {
	ip_address addr;
	u_int16_t sport, dport;
};

static void nat_traversal_find_new_mapp_state (struct state *st, void *data)
{
	struct connection *c = st->st_connection;
	struct _new_mapp_nfo *nfo = (struct _new_mapp_nfo *)data;

	if ((c)
	    && sameaddr(&st->st_remoteaddr, &(nfo->addr)) &&
	    (st->st_remoteport == nfo->sport))
	{

	    /**
	     * Change host port
	     */
	    st->st_remoteport = nfo->dport;

	    if (IS_IPSEC_SA_ESTABLISHED(st->st_state) ||
		IS_ONLY_INBOUND_IPSEC_SA_ESTABLISHED(st->st_state)) {
		if (!update_ipsec_sa(st)) {
		    /**
		     * If ipsec update failed, restore old port or we'll
		     * not be able to update anymore.
		     */
		    st->st_remoteport = nfo->sport;
		}
	    }
	}
}

static int nat_traversal_new_mapping(const ip_address *src, u_int16_t sport,
	const ip_address *dst, u_int16_t dport)
{
	char srca[ADDRTOT_BUF], dsta[ADDRTOT_BUF];
	struct _new_mapp_nfo nfo;

	addrtot(src, 0, srca, ADDRTOT_BUF);
	addrtot(dst, 0, dsta, ADDRTOT_BUF);

	if (!sameaddr(src, dst)) {
		loglog(RC_LOG_SERIOUS, "nat_traversal_new_mapping: "
			"address change currently not supported [%s:%d,%s:%d]",
			srca, sport, dsta, dport);
		return -1;
	}

	if (sport == dport) {
		/* no change */
		return 0;
	}

	DBG_log("NAT-T: new mapping %s:%d/%d)", srca, sport, dport);

	nfo.addr = *src;
	nfo.sport = sport;
	nfo.dport = dport;

	for_each_state((void *)nat_traversal_find_new_mapp_state, &nfo);

	return 0;
}

void nat_traversal_change_port_lookup(struct msg_digest *md, struct state *st)
{
	struct iface_port *i = NULL;

	if (st == NULL) {
		return;
	}

	if (md) {
		/**
		 * If source port has changed, update (including other
		 * states and established kernel SA)
		 */
		if (st->st_remoteport != md->sender_port) {
		    nat_traversal_new_mapping(&st->st_remoteaddr
					      , st->st_remoteport
					      , &st->st_remoteaddr
					      , md->sender_port);
		}
		/**
		 * If interface type has changed, update local port (500/4500)
		 */
		if (md->iface->port != st->st_localport)
		{
		    st->st_localport = md->iface->port;
		    DBG(DBG_NATT,
			DBG_log("NAT-T: updating local port to %d"
				, st->st_localport));
		}
	}

	/**
	 * If we're initiator and NAT-T (with port floating) is detected, we
	 * need to change port (MAIN_I3 or QUICK_I1)
	 */
	if (((st->st_state == STATE_MAIN_I3)
	     || (st->st_state == STATE_QUICK_I1))
	    && (st->hidden_variables.st_nat_traversal & NAT_T_WITH_PORT_FLOATING)
	    && (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED)
	    && (st->st_localport != NAT_T_IKE_FLOAT_PORT))
	{
	    DBG(DBG_NATT
		, DBG_log("NAT-T: floating to port %d", NAT_T_IKE_FLOAT_PORT));
	    
	    st->st_localport  = NAT_T_IKE_FLOAT_PORT;
	    st->st_remoteport = NAT_T_IKE_FLOAT_PORT;
	    
	    /*
	     * Also update pending connections or they will be deleted if
	     * uniqueids option is set.
	     * THIS does NOTHING as, both arguments are "st"!
	     */
	    update_pending(st, st);
	}

	/**
	 * Find valid interface according to local port (500/4500)
	 */
	if (!(sameaddr(&st->st_localaddr, &st->st_interface->ip_addr)
	      && st->st_localport == st->st_interface->port))
	    
	{
	    char b1[ADDRTOT_BUF], b2[ADDRTOT_BUF];

	    DBG(DBG_NATT,
		DBG_log("NAT-T connection has wrong interface definition %s:%u vs %s:%u"
			, (addrtot(&st->st_localaddr, 0, b1, sizeof(b1)),b1)
			, st->st_localport
			, (addrtot(&st->st_interface->ip_addr, 0, b2, sizeof(b2)),b2)
			, st->st_interface->port));

	    for (i = interfaces; i !=  NULL; i = i->next) {
		if ((sameaddr(&st->st_localaddr, &i->ip_addr))
		    && (st->st_localport == i->port))
		{
		    DBG(DBG_NATT,
			DBG_log("NAT-T: using interface %s:%d"
				, i->ip_dev->id_rname
				, i->port));
		    st->st_interface = i;
		    break;
		}
	    }
	}
}

struct _new_klips_mapp_nfo {
	struct sadb_sa *sa;
	ip_address src, dst;
	u_int16_t sport, dport;
};

static void nat_t_new_klips_mapp (struct state *st, void *data)
{
	struct connection *c = st->st_connection;
	struct _new_klips_mapp_nfo *nfo = (struct _new_klips_mapp_nfo *)data;

	if ((c)
	    && (st->st_esp.present)
	    && sameaddr(&st->st_remoteaddr, &(nfo->src))
	    && (st->st_esp.our_spi == nfo->sa->sadb_sa_spi))
	{
	    nat_traversal_new_mapping(&st->st_remoteaddr
				      , st->st_remoteport
				      , &(nfo->dst), nfo->dport);
	}
}

void process_pfkey_nat_t_new_mapping(
	struct sadb_msg *msg __attribute__ ((unused)),
	struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
	struct _new_klips_mapp_nfo nfo;
	struct sadb_address *srcx = (void *) extensions[SADB_EXT_ADDRESS_SRC];
	struct sadb_address *dstx = (void *) extensions[SADB_EXT_ADDRESS_DST];
	struct sockaddr *srca, *dsta;
	err_t ugh = NULL;

	nfo.sa = (void *) extensions[SADB_EXT_SA];

	if ((!nfo.sa) || (!srcx) || (!dstx)) {
		openswan_log("SADB_X_NAT_T_NEW_MAPPING message from KLIPS malformed: "
			"got NULL params");
		return;
	}

	srca = ((struct sockaddr *)(void *)&srcx[1]);
	dsta = ((struct sockaddr *)(void *)&dstx[1]);

	if ((srca->sa_family != AF_INET) || (dsta->sa_family != AF_INET)) {
		ugh = "only AF_INET supported";
	}
	else {
		char text_said[SATOT_BUF];
		char _srca[ADDRTOT_BUF], _dsta[ADDRTOT_BUF];
		ip_said said;

		initaddr((const void *) &((const struct sockaddr_in *)srca)->sin_addr,
			sizeof(((const struct sockaddr_in *)srca)->sin_addr),
			srca->sa_family, &(nfo.src));
		nfo.sport = ntohs(((const struct sockaddr_in *)srca)->sin_port);
		initaddr((const void *) &((const struct sockaddr_in *)dsta)->sin_addr,
			sizeof(((const struct sockaddr_in *)dsta)->sin_addr),
			dsta->sa_family, &(nfo.dst));
		nfo.dport = ntohs(((const struct sockaddr_in *)dsta)->sin_port);

		DBG(DBG_NATT,
			initsaid(&nfo.src, nfo.sa->sadb_sa_spi, SA_ESP, &said);
			satot(&said, 0, text_said, SATOT_BUF);
			addrtot(&nfo.src, 0, _srca, ADDRTOT_BUF);
			addrtot(&nfo.dst, 0, _dsta, ADDRTOT_BUF);
			DBG_log("new klips mapping %s %s:%d %s:%d",
				text_said, _srca, nfo.sport, _dsta, nfo.dport);
		);

		for_each_state((void *)nat_t_new_klips_mapp, &nfo);
	}

	if (ugh != NULL)
		openswan_log("SADB_X_NAT_T_NEW_MAPPING message from KLIPS malformed: %s", ugh);
}

#endif

/*
 * $Log: nat_traversal.c,v $
 * Revision 1.26.2.5  2005/11/24 05:30:37  ken
 * MCR's refactored natd_lookup function for multi-NAT-D Hash
 *
 * Revision 1.26.2.4  2005/09/27 04:30:20  paul
 * Backport of HEAD's patch, adopted from Peter Van der Beken's
 * (peterv@propagandism.org) MacOSX interop patch.
 *
 * Reported to Apple Developer Center (ADC) by Paul Wouters (paul@xelerance.com):
 * Problem ID: 4274347
 * Title: IPsec NAT-T implementation is broken, breaking L2TP VPN's to non-apple servers
 * Created Date: 26-Sep-2005 06:36 PM
 *
 * Revision 1.26.2.3  2005/09/07 00:41:12  paul
 * Pull up mcr's nat-t detection for klips.
 *
 * Revision 1.26.2.2  2005/07/26 02:11:23  ken
 * Pullin from HEAD:
 * Split Aggressive mode into ikev1_aggr.c
 * Fix NAT-T that we broke in dr7
 * Move dpd/pgp vendor id's to vendor.[ch]
 *
 * Revision 1.26.2.1  2005/07/26 01:20:14  ken
 * Pull in st -> c changes from HEAD
 *
 * Revision 1.27  2005/07/26 01:14:58  mcr
 * 	switch from i->interface to st->st_interface.
 * 	cleaned up some diagnostic, and canonicalized to "NAT-Traversal"
 *
 * Revision 1.26  2005/06/14 22:38:06  mcr
 * 	changed definition of interface such that we can now compare if
 * 	a NAT vs non-NAT interface are considered the "same"
 *
 * Revision 1.25  2005/05/08 13:25:48  paul
 * fixed typo
 *
 * Revision 1.24  2005/04/21 21:58:06  mcr
 * 	log correct address/port for NAT-KA.
 *
 * Revision 1.23  2005/04/20 15:30:28  mcr
 * 	additional debugging of NAT-KA and DPD messages.
 *
 * Revision 1.22  2005/04/08 18:29:52  mcr
 * 	use natt_defines.h to get definitions.
 *
 * Revision 1.21  2005/04/06 17:56:04  mcr
 * 	log where/who the DPD R_U_THERE sent to.
 *
 * Revision 1.20  2005/03/20 23:16:16  mcr
 * 	fixed typo in case.
 *
 * Revision 1.19  2005/02/14 18:27:27  mcr
 * 	additional debugging of when NAT-T is enabled, and when the
 * 	VID is actually being sent.
 *
 * Revision 1.18  2005/01/28 06:22:52  mcr
 * 	additional debugging of whether or not NAT-T vendor
 * 	IDs are inserted.
 *
 * Revision 1.17  2005/01/24 03:35:22  mcr
 * 	fixed selection of interface for various states
 * 	of NAT "floating"
 *
 * Revision 1.16  2005/01/23 19:16:15  mcr
 * 	moved nat varibales to "hidden_variables"
 * 	added for RFC3947 NAT code.
 *
 * Revision 1.15  2004/11/30 02:31:14  mcr
 * 	oops, function didn't match prototype.
 *
 * Revision 1.14  2004/11/30 02:26:59  mcr
 * 	additional debugging of port-floating enabling/disabling.
 *
 * Revision 1.13  2004/11/05 00:14:50  mcr
 * 	added log info.
 *
 *
 * $Id: nat_traversal.c,v 1.26.2.5 2005/11/24 05:30:37 ken Exp $
 *
 */
