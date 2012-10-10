/* Libreswan NAT-Traversal
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2005 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2006 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Gilles Espinasse <g.esp@free.fr>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Shinichi Furuso <Shinichi.Furuso@jp.sony.com>
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
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>
#include <libreswan/ipsec_tunnel.h>
#include <libreswan/ipsec_param.h>

#include "sysdep.h"
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
#ifdef XAUTH_HAVE_PAM
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

#define DEFAULT_KEEP_ALIVE_PERIOD  20

bool nat_traversal_enabled = FALSE;
bool nat_traversal_support_non_ike = FALSE;
bool nat_traversal_support_port_floating = FALSE;

static unsigned int _kap = 0;
static unsigned int _ka_evt = 0;
static bool _force_ka = 0;

void init_nat_traversal (bool activate, unsigned int keep_alive_period,
	bool fka, bool spf)
{
	nat_traversal_enabled = activate;
	nat_traversal_support_non_ike = activate;
	nat_traversal_support_port_floating = activate ? spf : FALSE;
	libreswan_log("Setting NAT-Traversal port-4500 floating to %s"
		     , nat_traversal_support_port_floating ? "on" : "off");
	libreswan_log("   port floating activation criteria nat_t=%d/port_float=%d"
		     , activate, spf);
	{ 
	  FILE *f = fopen("/proc/net/ipsec/natt", "r");
	  char n;
	  if(f != NULL) {
	    n=getc(f);
	    if(n=='0') {
	      nat_traversal_enabled = FALSE;
	      nat_traversal_support_non_ike=FALSE;
	      nat_traversal_support_port_floating=FALSE;
	      libreswan_log("  KLIPS does not have NAT-Traversal built in (see /proc/net/ipsec/natt)\n");
	    }
	    fclose(f);
	  }
	}

	_force_ka = fka;
	_kap = keep_alive_period ? keep_alive_period : DEFAULT_KEEP_ALIVE_PERIOD;
	plog("   NAT-Traversal support %s%s%s",
	     activate ? " [enabled]" : " [disabled]",
	     activate & fka ? " [Force KeepAlive]" : "",
	     activate & !spf ? " [Port Floating disabled]" : "");

}

static void disable_nat_traversal(int type)
{
	if (type == ESPINUDP_WITH_NON_IKE)
		nat_traversal_support_non_ike = FALSE;
	else {
	  libreswan_log("NAT-Traversal port floating turned off");
	  nat_traversal_support_port_floating = FALSE;
	}

	if (!nat_traversal_support_non_ike &&
	    !nat_traversal_support_port_floating) {
	    libreswan_log("NAT-Traversal is turned OFF due to lack of KERNEL support: %d/%d"
			 , nat_traversal_support_non_ike
			 , nat_traversal_support_port_floating);
	    nat_traversal_enabled = FALSE;
	}
}

static void _natd_hash(const struct hash_desc *hasher, unsigned char *hash
		       , u_int8_t *icookie, u_int8_t *rcookie
		       , const ip_address *ip, u_int16_t port)
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
}

/**
 * Add NAT-Traversal VIDs (supported ones)
 *
 * Used when we're Initiator
 */
bool nat_traversal_insert_vid(u_int8_t np, pb_stream *outs, struct state *st)
{
	bool r = TRUE;
	DBG(DBG_NATT
	    , DBG_log("nat add vid. port: %d nonike: %d"
		      , nat_traversal_support_port_floating
		      , nat_traversal_support_non_ike));
		      
	if (nat_traversal_support_port_floating) {
	    if (st->st_connection->remotepeertype == CISCO) {
		if (r) r = out_vid(np, outs, VID_NATT_RFC);
	    } else {
		if (r) r = out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_RFC);
		if (r) r = out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_IETF_03);
		if (r) r = out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_IETF_02_N);
		if (r)
		r = out_vid(nat_traversal_support_non_ike ? ISAKMP_NEXT_VID : np,
			outs, VID_NATT_IETF_02);
	    }
	}
	if (nat_traversal_support_non_ike && st->st_connection->remotepeertype != CISCO) {
		if (r) r = out_vid(np, outs, VID_NATT_IETF_00);
	}
	return r;
}

u_int32_t nat_traversal_vid_to_method(unsigned short nat_t_vid)
{
	switch (nat_t_vid) {
		case VID_NATT_IETF_00:
			DBG(DBG_NATT, DBG_log("returning NATT method NAT_TRAVERSAL_METHOD_IETF_00_01"));
			return NAT_TRAVERSAL_METHOD_IETF_00_01;

		case VID_NATT_IETF_02:
		case VID_NATT_IETF_02_N:
		case VID_NATT_IETF_03:
			DBG(DBG_NATT, DBG_log("returning NATT method NAT_TRAVERSAL_METHOD_IETF_02_03"));
			return NAT_TRAVERSAL_METHOD_IETF_02_03;

		case VID_NATT_IETF_04:
		case VID_NATT_IETF_05:
		case VID_NATT_IETF_06:
		case VID_NATT_IETF_07:
		case VID_NATT_IETF_08:
		case VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE:
			DBG(DBG_NATT, DBG_log("VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE assumed as VID_NATT_RFC"));
		case VID_NATT_RFC:
			DBG(DBG_NATT, DBG_log("returning NATT method NAT_TRAVERSAL_METHOD_IETF_RFC"));
			return NAT_TRAVERSAL_METHOD_IETF_RFC;
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

	passert(st);
	passert(md->iface);
	passert(st->st_oakley.prf_hasher);

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
	_natd_hash(st->st_oakley.prf_hasher, hash_me
		   , st->st_icookie, st->st_rcookie
		   , &(md->iface->ip_addr)
		   , ntohs(md->iface->port));

	/**
	 * The others with sender IP & port
	 */
	_natd_hash(st->st_oakley.prf_hasher, hash_him
		   , st->st_icookie, st->st_rcookie
		   , &(md->sender), ntohs(md->sender_port));

	for (p = md->chain[ISAKMP_NEXT_NATD_RFC], i=0;
	     p != NULL && (!found_me || !found_him);
	     p = p->next)
	  {
	    DBG(DBG_NATT,
		DBG_log("NAT_TRAVERSAL hash=%d (me:%d) (him:%d)"
			, i, found_me, found_him);
		DBG_dump("expected NAT-D(me):", hash_me,
			 st->st_oakley.prf_hasher->hash_digest_len);
		DBG_dump("expected NAT-D(him):", hash_him,
			 st->st_oakley.prf_hasher->hash_digest_len);
		DBG_dump("received NAT-D:", p->pbs.cur, pbs_left(&p->pbs));
		);

	    if ( (pbs_left(&p->pbs) == st->st_oakley.prf_hasher->hash_digest_len)
		 && (memcmp(p->pbs.cur, hash_me
			    , st->st_oakley.prf_hasher->hash_digest_len)==0))
	      {
		found_me = TRUE;
	      } 
	    
	    if ( (pbs_left(&p->pbs) == st->st_oakley.prf_hasher->hash_digest_len)
		 && (memcmp(p->pbs.cur, hash_him
			    , st->st_oakley.prf_hasher->hash_digest_len)==0))
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
	    st->hidden_variables.st_natd = md->sender;
	}

        memset(&st->hidden_variables.st_natd,0,sizeof(st->hidden_variables.st_natd));
	anyaddr(AF_INET, &st->hidden_variables.st_natd);

	if(!found_him) {
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_PEER);
	    st->hidden_variables.st_natd = md->sender;
	}
	

	if(st->st_connection->forceencaps) {
	    DBG(DBG_NATT,
		DBG_log("NAT_TRAVERSAL forceencaps enabled"));
	    
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_PEER);
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_ME);
	    st->hidden_variables.st_natd = md->sender;
	}
}

bool nat_traversal_add_natd(u_int8_t np, pb_stream *outs,
			    struct msg_digest *md)
{
	unsigned char hash[MAX_DIGEST_LEN];
	struct state *st = md->st;
	unsigned int nat_np;
	const ip_address *first, *second;
	unsigned short firstport, secondport;

	passert(st->st_oakley.prf_hasher);

	DBG(DBG_EMITTING|DBG_NATT, DBG_log("sending NAT-D payloads"));

	nat_np = (st->hidden_variables.st_nat_traversal & NAT_T_WITH_RFC_VALUES
		  ? ISAKMP_NEXT_NATD_RFC : ISAKMP_NEXT_NATD_DRAFTS);
	if (!out_modify_previous_np(nat_np, outs)) {
		return FALSE;
	}

	first      = &(md->sender);
	firstport  = ntohs(st->st_remoteport);
	second     = &(md->iface->ip_addr);
	secondport = ntohs(st->st_localport);

	if(0) {
		const ip_address *t;
		unsigned short p;

		t=first;
		first=second;
		second=t;

		p=firstport;
		firstport=secondport;
		secondport=p;
	}


	if(st->st_connection->forceencaps) {
		DBG(DBG_NATT, DBG_log("NAT-T: forceencaps=yes, so mangling hash to force NAT-T detection"));
		firstport=secondport=0;
	}

	/**
	 * First one with sender IP & port
	 */
        _natd_hash(st->st_oakley.prf_hasher, hash, st->st_icookie
		       , is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie : st->st_rcookie
		       , first, firstport);

	if (!out_generic_raw(nat_np, &isakmp_nat_d, outs
			     , hash
			     , st->st_oakley.prf_hasher->hash_digest_len
			     , "NAT-D")) {
	    return FALSE;
	}

	/**
	 * Second one with my IP & port
	 */
        _natd_hash(st->st_oakley.prf_hasher, hash
		       , st->st_icookie
		       , is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie : st->st_rcookie
		       , second, secondport);
	return (out_generic_raw(np, &isakmp_nat_d, outs,
		hash, st->st_oakley.prf_hasher->hash_digest_len, "NAT-D"));
}

/**
 * nat_traversal_natoa_lookup()
 * 
 * Look for NAT-OA in message
 */
void nat_traversal_natoa_lookup(struct msg_digest *md, struct hidden_variables *hv)
{
	struct payload_digest *p;
	int i;
	ip_address ip;

	passert(md->iface != NULL);

	/** Initialize NAT-OA */
	anyaddr(AF_INET, &hv->st_nat_oa);

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
	else if (!(hv->st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_PEER))) {
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
		       , "NAT-Traversal: received 0.0.0.0 NAT-OA...");
	}
	else {
		hv->st_nat_oa = ip;
	}
}

bool nat_traversal_add_natoa(u_int8_t np, pb_stream *outs,
			     struct state *st, bool initiator)
{
	struct isakmp_nat_oa natoa;
	unsigned char ip_val[sizeof(struct in6_addr)];
	size_t ip_len = 0;
	ip_address *ipinit, *ipresp;
	unsigned int nat_np;

	if(initiator) {
		ipinit = &(st->st_localaddr);
		ipresp = &(st->st_remoteaddr);
	} else {
		ipresp = &(st->st_localaddr);
		ipinit = &(st->st_remoteaddr);
	}

	passert(st->st_connection);

	nat_np = (st->hidden_variables.st_nat_traversal & NAT_T_WITH_RFC_VALUES
		  ? ISAKMP_NEXT_NATOA_RFC : ISAKMP_NEXT_NATOA_DRAFTS);
	if (!out_modify_previous_np(nat_np, outs)) {
		return FALSE;
	}

	memset(&natoa, 0, sizeof(natoa));
	natoa.isanoa_np = nat_np;

	switch (addrtypeof(ipinit)) {
		case AF_INET:
			ip_len = sizeof(ipinit->u.v4.sin_addr.s_addr);
			memcpy(ip_val, &ipinit->u.v4.sin_addr.s_addr, ip_len);
			natoa.isanoa_idtype = ID_IPV4_ADDR;
			break;
		case AF_INET6:
			ip_len = sizeof(ipinit->u.v6.sin6_addr.s6_addr);
			memcpy(ip_val, &ipinit->u.v6.sin6_addr.s6_addr, ip_len);
			natoa.isanoa_idtype = ID_IPV6_ADDR;
			break;
		default:
			loglog(RC_LOG_SERIOUS, "NAT-Traversal: "
				"invalid addrtypeof()=%d", addrtypeof(ipinit));
			return FALSE;
	}

	{
		pb_stream pbs;
		if (!out_struct(&natoa, &isakmp_nat_oa, outs, &pbs))
			return FALSE;
		
		if (!out_raw(ip_val, ip_len, &pbs, "NAT-OAi"))
			return FALSE;
		
		DBG(DBG_NATT,
		    DBG_dump("NAT-OAi (S):", ip_val, ip_len);
			);
		close_output_pbs(&pbs);
	}

	
	/* output second NAT-OA */
	memset(&natoa, 0, sizeof(natoa));
	natoa.isanoa_np = np;

	switch (addrtypeof(ipresp)) {
		case AF_INET:
			ip_len = sizeof(ipresp->u.v4.sin_addr.s_addr);
			memcpy(ip_val, &ipresp->u.v4.sin_addr.s_addr, ip_len);
			natoa.isanoa_idtype = ID_IPV4_ADDR;
			break;
		case AF_INET6:
			ip_len = sizeof(ipresp->u.v6.sin6_addr.s6_addr);
			memcpy(ip_val, &ipresp->u.v6.sin6_addr.s6_addr, ip_len);
			natoa.isanoa_idtype = ID_IPV6_ADDR;
			break;
		default:
			loglog(RC_LOG_SERIOUS, "NAT-Traversal: "
				"invalid addrtypeof()=%d", addrtypeof(ipresp));
			return FALSE;
	}

	{
		pb_stream pbs;
		if (!out_struct(&natoa, &isakmp_nat_oa, outs, &pbs))
			return FALSE;
		
		if (!out_raw(ip_val, ip_len, &pbs, "NAT-OAr"))
			return FALSE;
		
		DBG(DBG_NATT,
		    DBG_dump("NAT-OAr (S):", ip_val, ip_len);
			);
		
		close_output_pbs(&pbs);
	}
	return TRUE;
}

void nat_traversal_show_result (u_int32_t nt, u_int16_t sport)
{
	const char *rslt = NULL;
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
			LHAS(nt, NAT_TRAVERSAL_METHOD_IETF_RFC) ? enum_name(&natt_method_names, NAT_TRAVERSAL_METHOD_IETF_RFC) :
			     LHAS(nt, NAT_TRAVERSAL_METHOD_IETF_05) ? enum_name(&natt_method_names, NAT_TRAVERSAL_METHOD_IETF_05) :
				LHAS(nt, NAT_TRAVERSAL_METHOD_IETF_02_03) ? enum_name(&natt_method_names, NAT_TRAVERSAL_METHOD_IETF_02_03) :
				   LHAS(nt, NAT_TRAVERSAL_METHOD_IETF_00_01) ? enum_name(&natt_method_names, NAT_TRAVERSAL_METHOD_IETF_00_01) :
				     "unknown method",
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
	int r = -1;
	struct ifreq ifr;
	int *fdp = (int *) &ifr.ifr_data;

	DBG(DBG_NATT, DBG_log("NAT-Traversal: Trying new style NAT-T"));
	memset(&ifr, 0, sizeof(ifr));
	switch(kern_interface) {
		case USE_MASTKLIPS:
			strcpy(ifr.ifr_name, "ipsec0"); /* using mast0 will break it! */
			break;
		case USE_KLIPS:
			strcpy(ifr.ifr_name, "ipsec0");
			break;
		case USE_NETKEY:
			/* Let's hope we have at least one ethernet device */
			strcpy(ifr.ifr_name, "eth0");
			break;
		case USE_BSDKAME:
			/* Let's hope we have at least one ethernet device */
			strcpy(ifr.ifr_name, "en0");
			break;
		default:
			/* We have nothing , really prob just abort and return -1 */
			strcpy(ifr.ifr_name, "eth0");
			break;
	}
	fdp[0] = sk;
	fdp[1] = type;
	r = ioctl(sk, IPSEC_UDP_ENCAP_CONVERT, &ifr);
	if (r == -1) { 
		DBG(DBG_NATT, DBG_log("NAT-Traversal: ESPINUDP(%d) setup failed for "
			   "new style NAT-T family %s (errno=%d)"
			   , type, fam, errno));
	} else {
		DBG(DBG_NATT, DBG_log("NAT-Traversal: ESPINUDP(%d) setup succeeded for "
			   "new style NAT-T family %s" , type, fam));
		return r;
	}

#if defined(KLIPS)
	DBG(DBG_NATT, DBG_log("NAT-Traversal: Trying old style NAT-T"));
	r = setsockopt(sk, SOL_UDP, UDP_ESPINUDP, &type, sizeof(type));
	if (r == -1) {
		DBG(DBG_NATT, DBG_log("NAT-Traversal: ESPINUDP(%d) setup failed for "
			   "old style NAT-T family %s (errno=%d)"
			   , type, fam, errno));
	}
	else {
		DBG(DBG_NATT, DBG_log("NAT-Traversal: ESPINUDP(%d) setup succeeded for "
			   "new style NAT-T family %s" , type, fam));
		return r;
	}
# else
	DBG(DBG_NATT, DBG_log("NAT-Traversal: ESPINUDP() setup for old style NAT-T family not available - KLIPS support not compiled in"));
# endif

	loglog(RC_LOG_SERIOUS,
	       "NAT-Traversal: ESPINUDP(%d) not supported by kernel for family %s"
	       , type, fam);
	disable_nat_traversal(type);
	return -1;
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
	if ( IS_ISAKMP_SA_ESTABLISHED(st->st_state)
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
		    && IS_ISAKMP_SA_ESTABLISHED(st->st_state)
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

	if ( ((st->st_state == STATE_QUICK_R2)
	      || (st->st_state == STATE_QUICK_I2))
	     &&	(st->hidden_variables.st_nat_traversal & NAT_T_DETECTED)
	     &&	((st->hidden_variables.st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME))
		 || (_force_ka)))
	{
	    /**
	     * - IPSEC SA established
	     * - NAT-Traversal detected
	     * - NAT-KeepAlive needed (we are NATed)
	     */
	    if (c->newest_ipsec_sa != st->st_serialno) {
		/** 
		 * if newest is also valid, ignore this one, we will only use
		 * newest. 
		 */
		struct state *st_newest;
		st_newest = state_with_serialno(c->newest_ipsec_sa);
		if ((st_newest)
		    && ((st_newest->st_state==STATE_QUICK_R2)
			|| (st_newest->st_state == STATE_QUICK_I2))
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
	struct state *st;
	ip_address    addr;
	u_int16_t     port;
};


static void nat_traversal_find_new_mapp_state (struct state *st, void *data)
{
	struct _new_mapp_nfo *nfo = (struct _new_mapp_nfo *)data;

	if((nfo->st->st_clonedfrom &&
	    (st->st_serialno == nfo->st->st_clonedfrom ||
	     st->st_clonedfrom == nfo->st->st_clonedfrom)) ||
	   st->st_serialno == nfo->st->st_serialno) {
		char b1[ADDRTOT_BUF];
		char b2[ADDRTOT_BUF];
		struct connection *c = st->st_connection;

		addrtot(&st->st_remoteaddr, 0, b1, ADDRTOT_BUF);
		addrtot(&nfo->addr,         0, b2, ADDRTOT_BUF);

		libreswan_log("new NAT mapping for #%u, was %s:%d, now %s:%d"
			     , (unsigned int)st->st_serialno
			     , b1, st->st_remoteport
			     , b2, nfo->port);
		
		/* update it */
		st->st_remoteaddr = nfo->addr;
		st->st_remoteport = nfo->port;
		st->hidden_variables.st_natd = nfo->addr;

		if(c->kind == CK_INSTANCE) {
			c->spd.that.host_addr = nfo->addr;
		}
	}
}


static int nat_traversal_new_mapping(struct state *st
				     , const ip_address *nsrc
				     , u_int16_t nsrcport)
{
	struct _new_mapp_nfo nfo;
	char ba[ADDRTOT_BUF];
	
	addrtot(nsrc, 0, ba, ADDRTOT_BUF);

	DBG(DBG_CONTROLMORE, DBG_log("state #%u NAT-T: new mapping %s:%d"
		, (unsigned int)st->st_serialno
		, ba, nsrcport));

#if 0
	if (!sameaddr(src, dst)) {
		char srca[ADDRTOT_BUF];
		char srcb[ADDRTOT_BUF];
		addrtot(src, 0, srca, ADDRTOT_BUF);
		addrtot(dst, 0, dsta, ADDRTOT_BUF);

		loglog(RC_LOG_SERIOUS, "nat_traversal_new_mapping: "
			"address change currently not supported [%s:%d,%s:%d]",
			srca, sport, dsta, dport);
		return -1;
	}

	if (sport == dport) {
		/* no change */
		return 0;
	}
#endif

	nfo.st    = st;
	nfo.addr  = *nsrc;
	nfo.port  = nsrcport;

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
		 * If source port/address has changed, update (including other
		 * states and established kernel SA)
		 */
		if (st->st_remoteport != md->sender_port ||
		    !sameaddr(&st->st_remoteaddr, &md->sender)) {

			nat_traversal_new_mapping(st
						  , &md->sender
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
	 * need to change port (MAIN_I3, QUICK_I1 or AGGR_I2)
	 */
	if ( ((st->st_state == STATE_MAIN_I3)
	     || (st->st_state == STATE_QUICK_I1) 
	     || (st->st_state == STATE_AGGR_I2))
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

	    DBG(DBG_NATT,
	        char b1[ADDRTOT_BUF];
	        char b2[ADDRTOT_BUF];
		DBG_log("NAT-T connection has wrong interface definition %s:%u vs %s:%u"
			, (addrtot(&st->st_localaddr, 0, b1, sizeof(b1)),b1)
			, st->st_localport
			, (addrtot(&st->st_interface->ip_addr, 0, b2, sizeof(b2)),b2)
			, st->st_interface->port)
	    );

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
	struct k_sadb_sa *sa;
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
		nat_traversal_new_mapping(st, &(nfo->dst), nfo->dport);
	}
}

void process_pfkey_nat_t_new_mapping(
	struct sadb_msg *msg __attribute__ ((unused)),
	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1])
{
	struct _new_klips_mapp_nfo nfo;
	struct sadb_address *srcx = (void *) extensions[K_SADB_EXT_ADDRESS_SRC];
	struct sadb_address *dstx = (void *) extensions[K_SADB_EXT_ADDRESS_DST];
	struct sockaddr *srca, *dsta;
	err_t ugh = NULL;

	nfo.sa = (void *) extensions[K_SADB_EXT_SA];

	if ((!nfo.sa) || (!srcx) || (!dstx)) {
		libreswan_log("K_SADB_X_NAT_T_NEW_MAPPING message from KLIPS malformed: "
			"got NULL params");
		return;
	}

	srca = ((struct sockaddr *)(void *)&srcx[1]);
	dsta = ((struct sockaddr *)(void *)&dstx[1]);

	if ((srca->sa_family != AF_INET) || (dsta->sa_family != AF_INET)) {
		ugh = "only AF_INET supported";
	}
	else {
		initaddr((const void *) &((const struct sockaddr_in *)srca)->sin_addr,
			sizeof(((const struct sockaddr_in *)srca)->sin_addr),
			srca->sa_family, &(nfo.src));
		nfo.sport = ntohs(((const struct sockaddr_in *)srca)->sin_port);
		initaddr((const void *) &((const struct sockaddr_in *)dsta)->sin_addr,
			sizeof(((const struct sockaddr_in *)dsta)->sin_addr),
			dsta->sa_family, &(nfo.dst));
		nfo.dport = ntohs(((const struct sockaddr_in *)dsta)->sin_port);

		DBG(DBG_NATT,
			char text_said[SATOT_BUF];
			char _srca[ADDRTOT_BUF];
			char _dsta[ADDRTOT_BUF];
			ip_said said;

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
		libreswan_log("K_SADB_X_NAT_T_NEW_MAPPING message from KLIPS malformed: %s", ugh);
}

#endif

