/* XAUTH related functions
 *
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003 Sean Mathews - Nu Tech Software Solutions, inc.
 * Copyright (C) 2003-2004 Xelerance Corporation
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
 * RCSID $Id: xauth.c,v 1.41.4.3 2005/07/26 02:11:23 ken Exp $
 *
 * This code originally written by Colubris Networks, Inc.
 * Extraction of patch and porting to 1.99 codebases by Xelerance Corporation
 * Porting to 2.x by Sean Mathews
 */

//#ifdef XAUTH

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <crypt.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "kernel.h"
#include "log.h"
#include "cookie.h"
#include "server.h"
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "whack.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "paths.h"
#include "ike_alg.h"

#include "xauth.h"
#include "virtual.h"

#ifdef HAVE_THREADS
#include <pthread.h>
#endif

static stf_status
modecfg_inI2(struct msg_digest *md);

struct paththing pwdfile;

extern bool encrypt_message(pb_stream *pbs, struct state *st); /* forward declaration */

struct thread_arg
{
    struct state *st;
    chunk_t	name;
    chunk_t	password;
    chunk_t     connname;
};

/**
* Addresses assigned (usually via MODE_CONFIG) to the Initiator
*/
struct internal_addr
{
    ip_address    ipaddr;
    ip_address    dns[2];
    ip_address    wins[2];  
};


#ifdef XAUTH_USEPAM
static
int xauth_pam_conv(int num_msg, const struct pam_message **msgm,
              struct pam_response **response, void *appdata_ptr);

static 
struct pam_conv conv = {
	xauth_pam_conv,
	NULL  };

/**
 * Get IP address from a PAM environment variable
 * 
 * @param pamh An open PAM filehandle
 * @param var Environment Variable to get the IP address from.  Usually IPADDR, DNS[12], WINS[12]
 * @param addr Pointer to var where you want IP address stored
 * @return int Return code
 */
static
int get_addr(pam_handle_t *pamh,const char *var,ip_address *addr)
{
	const char *c;
	int retval;
	
	c = pam_getenv(pamh,var);
	if(c == NULL)
	{
		c="0.0.0.0";
	}
	retval = inet_pton(AF_INET,c,(void*) &addr->u.v4.sin_addr.s_addr);
	addr->u.v4.sin_family = AF_INET;
	return (retval > 0);
}
#endif

oakley_auth_t xauth_calcbaseauth(oakley_auth_t baseauth)
{
  switch(baseauth) {
  case HybridInitRSA:
  case HybridRespRSA: 
  case XAUTHInitRSA:      
  case XAUTHRespRSA:      
    baseauth = OAKLEY_RSA_SIG;
    break;
    
  case XAUTHInitDSS:      
  case XAUTHRespDSS:      
  case HybridInitDSS: 
  case HybridRespDSS: 
    baseauth = OAKLEY_DSS_SIG;
    break;
    
  case XAUTHInitPreShared:
  case XAUTHRespPreShared:
    baseauth = OAKLEY_PRESHARED_KEY;
    break;
    
  case XAUTHInitRSAEncryption:                     
  case XAUTHRespRSAEncryption:
    baseauth = OAKLEY_RSA_ENC;
    break;
    
  case XAUTHInitRSARevisedEncryption:             
  case XAUTHRespRSARevisedEncryption:
    baseauth = OAKLEY_RSA_ENC_REV;
    break;
  }
  
  return baseauth;
}
      


/**
 * Get inside IP address for a connection
 * 
 * @param con A currently active connection struct
 * @param ia internal_addr struct
 * @return int Return Code
 */
static
int get_internal_addresses(struct connection *con,struct internal_addr *ia)
{
#ifdef XAUTH_USEPAM
    int retval;
    char str[IDTOA_BUF+sizeof("ID=")+2];
#endif

#ifdef NAT_TRAVERSAL /* only NAT-T code lets us do virtual ends */
    if (!isanyaddr(&con->spd.that.client.addr))
    {
	/** assumes IPv4, and also that the mask is ignored */
	ia->ipaddr = con->spd.that.client.addr;

    }
    else
#endif
    {
#ifdef XAUTH_USEPAM
	    if(con->pamh == NULL)
	    {
		    /** Start PAM session, using 'pluto' as our PAM name */
		    retval = pam_start("pluto", "user", &conv, &con->pamh);
		    memset(ia,0,sizeof(*ia));
		    if(retval == PAM_SUCCESS)
		    {
		            char buf[IDTOA_BUF];

			    idtoa(&con->spd.that.id, buf, sizeof(buf));
			    if (con->spd.that.id.kind == ID_DER_ASN1_DN)
			    {
				    /** Keep only the common name, if one exists */
				    char *c1, *c2;
				    c1 = strstr(buf, "CN=");
				    if (c1) {
					    c2 = strstr(c1, ", ");
					    if (c2) *c2 = '\0';
					    memmove(buf, c1+3, strlen(c1) + 1 - 3);
				    }
			    }
			    snprintf(str, sizeof(str), "ID=%s", buf);
			    pam_putenv(con->pamh,str);
			    pam_open_session(con->pamh,0);
		    }
	    }
	    if(con->pamh != NULL)
	    {
		    /** Put IP addresses from various variables into our
                     *  internal address struct */
		    get_addr(con->pamh,"IPADDR",&ia->ipaddr);
		    get_addr(con->pamh,"DNS1",&ia->dns[0]);
		    get_addr(con->pamh,"DNS2",&ia->dns[1]);
		    get_addr(con->pamh,"WINS1",&ia->wins[0]);
		    get_addr(con->pamh,"WINS2",&ia->wins[1]);
	    }
#endif
    }
    return 0;
} 

/**
 * Compute HASH of Mode Config.
 *
 * @param dest 
 * @param start
 * @param roof
 * @param st State structure
 * @return size_t Length of the HASH
 */
size_t
xauth_mode_cfg_hash(u_char *dest
		    , const u_char *start
		    , const u_char *roof
		    , const struct state *st)
{
    struct hmac_ctx ctx;

    hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_a);
    hmac_update(&ctx, (const u_char *) &st->st_msgid_phase15
		, sizeof(st->st_msgid_phase15));
    hmac_update(&ctx, start, roof-start);
    hmac_final(dest, &ctx);

    DBG(DBG_CRYPT,
	DBG_log("XAUTH: HASH computed:");
 	DBG_dump("", dest, ctx.hmac_digest_len)); 
    return ctx.hmac_digest_len;
}



/**
 * Mode Config Reply
 *
 * Generates a reply stream containing Mode Config information (eg: IP, DNS, WINS)
 *
 * @param st State structure
 * @param resp Type of reply (int)
 * @param rbody Body of the reply (stream)
 * @param ap_id ISAMA Identifier 
 * @return stf_status STF_OK or STF_INTERNAL_ERROR
 */
stf_status modecfg_resp(struct state *st
			,unsigned int resp
			,pb_stream *rbody
			,u_int16_t replytype
			,bool hackthat
			,u_int16_t ap_id)
{
    unsigned char *r_hash_start,*r_hashval;

    /* START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_ATTR); */

    {
      pb_stream hash_pbs; 
      int np = ISAKMP_NEXT_ATTR;

      if (!out_generic(np, &isakmp_hash_desc, rbody, &hash_pbs)) 
	return STF_INTERNAL_ERROR; 
      r_hashval = hash_pbs.cur;	/* remember where to plant value */ 
      if (!out_zero(st->st_oakley.hasher->hash_digest_len, &hash_pbs, "HASH")) 
	return STF_INTERNAL_ERROR; 
      close_output_pbs(&hash_pbs); 
      r_hash_start = (rbody)->cur;	/* hash from after HASH payload */ 
    }

    /* ATTR out */
    {
	struct  isakmp_mode_attr attrh;
	struct isakmp_attribute attr;
	pb_stream strattr,attrval;
	int attr_type;
	struct internal_addr ia;
	int dns_idx, wins_idx;
	bool dont_advance;

	attrh.isama_np = ISAKMP_NEXT_NONE;
	attrh.isama_type = replytype;

	attrh.isama_identifier = ap_id;
	if(!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
	    return STF_INTERNAL_ERROR;
	
	zero(&ia);
	get_internal_addresses(st->st_connection, &ia);

	if(!isanyaddr(&ia.dns[0]))	/* We got DNS addresses, answer with those */
		resp |= LELEM(INTERNAL_IP4_DNS);
	else
		resp &= ~LELEM(INTERNAL_IP4_DNS);

	if(!isanyaddr(&ia.wins[0]))	/* We got WINS addresses, answer with those */
		resp |= LELEM(INTERNAL_IP4_NBNS);
	else
		resp &= ~LELEM(INTERNAL_IP4_NBNS);

	if(hackthat) {
	    if(memcmp(&st->st_connection->spd.that.client.addr
		      ,&ia.ipaddr
		      ,sizeof(ia.ipaddr)) != 0)
		{
		    /* Make the Internal IP address and Netmask as
		     * that client address */
		    st->st_connection->spd.that.client.addr = ia.ipaddr;
		    st->st_connection->spd.that.client.maskbits = 32;
		    st->st_connection->spd.that.has_client = TRUE;
		}
	}

	attr_type = 0;
	dns_idx = 0;
	wins_idx = 0;
	while(resp != 0)
	{
	    dont_advance = FALSE;
	    if(resp & 1)
	    {	
		const unsigned char *byte_ptr;
		unsigned int len;

		/* ISAKMP attr out */
		attr.isaat_af_type = attr_type | ISAKMP_ATTR_AF_TLV;
		out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr, &attrval);
		switch(attr_type)
		{
		        case INTERNAL_IP4_ADDRESS:
		                len = addrbytesptr(&ia.ipaddr, &byte_ptr);
 				out_raw(byte_ptr,len,&attrval,"IP4_addr");
 				break;

			case INTERNAL_IP4_NETMASK:
			    {
 				    unsigned int  mask;
#if 0
				char mask[4],bits[8]={0x00,0x80,0xc0,0xe0,0xf0,0xf8,0xfc,0xfe};
				int t,m=st->st_connection->that.host_addr.maskbit;
				for(t=0;t<4;t++)
				{
				    if(m < 8) 
					mask[t] = bits[m];
				    else
					mask[t] = 0xff;
				    m -= 8;
				}
#endif				    
 				if (st->st_connection->spd.this.client.maskbits == 0)
 					mask = 0;
 				else
 					mask = 0xffffffff * 1;
				out_raw(&mask,4,&attrval,"IP4_mask");
			    }
			    break;

			case INTERNAL_IP4_SUBNET:
			    {
				char mask[4],bits[8]={0x00,0x80,0xc0,0xe0,0xf0,0xf8,0xfc,0xfe};
				int t,m=st->st_connection->spd.this.client.maskbits;
				for(t=0;t<4;t++)
				{
				    if(m < 8) 
					mask[t] = bits[m];
				    else
					mask[t] = 0xff;
				    m -= 8;
				    if(m < 0) m=0;
				}
				len = addrbytesptr(&st->st_connection->spd.this.client.addr, &byte_ptr);
				out_raw(byte_ptr,len,&attrval,"IP4_subnet");
				out_raw(mask,sizeof(mask),&attrval,"IP4_submsk"); 
				    
			    }
			    break;
		    
			case INTERNAL_IP4_DNS:
 				len = addrbytesptr(&ia.dns[dns_idx++], &byte_ptr);
 				out_raw(byte_ptr,len,&attrval,"IP4_dns");
				if(dns_idx < 2 && !isanyaddr(&ia.dns[dns_idx]))
				{
					dont_advance = TRUE;
				}
 				break;

			case INTERNAL_IP4_NBNS:
 				len = addrbytesptr(&ia.wins[wins_idx++], &byte_ptr);
 				out_raw(byte_ptr,len,&attrval,"IP4_wins");
				if(wins_idx < 2 && !isanyaddr(&ia.wins[wins_idx]))
				{
					dont_advance = TRUE;
				}
 				break;

		default:
		    openswan_log("attempt to send unsupported mode cfg attribute %s."
			 , enum_show(&modecfg_attr_names, attr_type));
		    break;
		}
		close_output_pbs(&attrval);

	    }
	    if (!dont_advance) {
		    attr_type++;
		    resp >>= 1;
	    }
	}

	close_message(&strattr);
    }

    xauth_mode_cfg_hash(r_hashval,r_hash_start,rbody->cur,st);
    
    close_message(rbody);

    encrypt_message(rbody, st);

    return STF_OK;
}

/** Set MODE_CONFIG data to client.  Pack IP Addresses, DNS, etc... and ship
 * 
 * @param st State Structure
 * @return stf_status
 */
stf_status modecfg_send_set(struct state *st)
{
	pb_stream reply,rbody;
	char buf[256];

	/* set up reply */
	init_pbs(&reply, buf, sizeof(buf), "ModecfgR1");

	st->st_state = STATE_MODE_CFG_R1;
	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* default to 0 */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
		hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_msgid = st->st_msgid_phase15;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
		{
			return STF_INTERNAL_ERROR;
		}
	}

#define MODECFG_SET_ITEM ( LELEM(INTERNAL_IP4_ADDRESS) | LELEM(INTERNAL_IP4_SUBNET) | LELEM(INTERNAL_IP4_NBNS) | LELEM(INTERNAL_IP4_DNS) )

	modecfg_resp(st
		     ,MODECFG_SET_ITEM
		     ,&rbody
 		     ,ISAKMP_CFG_SET
		     ,TRUE
		     ,0/* XXX ID */);
#undef MODECFG_SET_ITEM

	clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply)
			, "ModeCfg set");

	/* Transmit */
	send_packet(st, "ModeCfg set", TRUE);

	/* RETRANSMIT if Main, SA_REPLACE if Aggressive */
	if(st->st_event->ev_type != EVENT_RETRANSMIT
	   && st->st_event->ev_type != EVENT_NULL)
	{	
		delete_event(st);
		event_schedule(EVENT_RETRANSMIT,EVENT_RETRANSMIT_DELAY_0,st);
	}

	return STF_OK;
}

/** Set MODE_CONFIG data to client.  Pack IP Addresses, DNS, etc... and ship
 * 
 * @param st State Structure
 * @return stf_status
 */
stf_status modecfg_start_set(struct state *st)
{
    if(st->st_msgid_phase15 == 0) {
	/* pick a new message id */
	st->st_msgid_phase15 = generate_msgid(st);
    }
    st->hidden_variables.st_modecfg_vars_set = TRUE;

    return modecfg_send_set(st);
}

/** Send XAUTH credential request (username + password request)
 * @param st State
 * @return stf_status
 */
stf_status xauth_send_request(struct state *st)
{
    pb_stream reply;
    pb_stream rbody;
    char buf[256];
    u_char *r_hash_start,*r_hashval;

    /* set up reply */
    init_pbs(&reply, buf, sizeof(buf), "xauth_buf");

    openswan_log("XAUTH: Sending Username/Password request (XAUTH_R0)");


    /* this is the beginning of a new exchange */
    st->st_msgid_phase15 = generate_msgid(st);
    st->st_state = STATE_XAUTH_R0;

    /* HDR out */
    {
	struct isakmp_hdr hdr;

	zero(&hdr);	/* default to 0 */
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_HASH;
	hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
	hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	hdr.isa_msgid = st->st_msgid_phase15;

	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
	{
	    return STF_INTERNAL_ERROR;
	}
    }

    START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_ATTR);

    /* ATTR out */
    {
	struct  isakmp_mode_attr attrh;
	struct isakmp_attribute attr;
	pb_stream strattr;

	attrh.isama_np = ISAKMP_NEXT_NONE;
	attrh.isama_type = ISAKMP_CFG_REQUEST;
	attrh.isama_identifier = 0;
	if(!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr))
	    return STF_INTERNAL_ERROR;
	/* ISAKMP attr out (name) */
	attr.isaat_af_type = XAUTH_USER_NAME;
	attr.isaat_lv = 0;
	out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr, NULL);
	
	/* ISAKMP attr out (password) */
	attr.isaat_af_type = XAUTH_USER_PASSWORD;
	attr.isaat_lv = 0;
	out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr, NULL);

	close_message(&strattr);
    }

    xauth_mode_cfg_hash(r_hashval,r_hash_start,rbody.cur,st);
    
    close_message(&rbody);
    close_output_pbs(&reply);

    init_phase2_iv(st, &st->st_msgid_phase15);
    encrypt_message(&rbody, st);

    clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply)
	, "XAUTH: req");

    /* Transmit */

    send_packet(st, "XAUTH: req", TRUE);

    /* RETRANSMIT if Main, SA_REPLACE if Aggressive */
    if(st->st_event->ev_type != EVENT_RETRANSMIT)
    {	
	delete_event(st);
	event_schedule(EVENT_RETRANSMIT,EVENT_RETRANSMIT_DELAY_0 * 3,st);
    }

    return STF_OK;
}

/** Send modecfg IP address request (IP4 address)
 * @param st State
 * @return stf_status
 */
stf_status modecfg_send_request(struct state *st)
{
    pb_stream reply;
    pb_stream rbody;
    char buf[256];
    u_char *r_hash_start,*r_hashval;

    /* set up reply */
    init_pbs(&reply, buf, sizeof(buf), "xauth_buf");

    openswan_log("modecfg: Sending IP request (MODECFG_I1)");

    /* this is the beginning of a new exchange */
    st->st_msgid_phase15 = generate_msgid(st);
    st->st_state = STATE_MODE_CFG_I1;

    /* HDR out */
    {
	struct isakmp_hdr hdr;

	zero(&hdr);	/* default to 0 */
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_HASH;
	hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
	hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	hdr.isa_msgid = st->st_msgid_phase15;

	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
	{
	    return STF_INTERNAL_ERROR;
	}
    }

    START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_ATTR);

    /* ATTR out */
    {
	struct  isakmp_mode_attr attrh;
	struct isakmp_attribute attr;
	pb_stream strattr;

	attrh.isama_np = ISAKMP_NEXT_NONE;
	attrh.isama_type = ISAKMP_CFG_REQUEST;
	attrh.isama_identifier = 0;
	if(!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr))
	    return STF_INTERNAL_ERROR;
	/* ISAKMP attr out (ipv4) */
	attr.isaat_af_type = INTERNAL_IP4_ADDRESS;
	attr.isaat_lv = 0;
	out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr, NULL);
	
	/* ISAKMP attr out (netmask) */
	attr.isaat_af_type = INTERNAL_IP4_NETMASK;
	attr.isaat_lv = 0;
	out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr, NULL);

	close_message(&strattr);
    }

    xauth_mode_cfg_hash(r_hashval,r_hash_start,rbody.cur,st);
    
    close_message(&rbody);
    close_output_pbs(&reply);

    init_phase2_iv(st, &st->st_msgid_phase15);
    encrypt_message(&rbody, st);

    clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply)
	, "modecfg: req");

    /* Transmit */

    send_packet(st, "modecfg: req", TRUE);

    /* RETRANSMIT if Main, SA_REPLACE if Aggressive */
    if(st->st_event->ev_type != EVENT_RETRANSMIT)
    {	
	delete_event(st);
	event_schedule(EVENT_RETRANSMIT,EVENT_RETRANSMIT_DELAY_0 * 3,st);
    }
    st->hidden_variables.st_modecfg_started = TRUE;

    return STF_OK;
}

/** Send XAUTH status to client
 *
 * @param st State
 * @param status Status code
 * @return stf_status
 */
stf_status xauth_send_status(struct state *st, int status)
{
    pb_stream reply;
    pb_stream rbody;
    char buf[256];
    u_char *r_hash_start,*r_hashval;

    /* set up reply */
    init_pbs(&reply, buf, sizeof(buf), "xauth_buf");

    /* pick a new message id */
    st->st_msgid_phase15 = generate_msgid(st);

    /* HDR out */
    {
	struct isakmp_hdr hdr;

	zero(&hdr);	/* default to 0 */
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_HASH;
	hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
	hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	hdr.isa_msgid = st->st_msgid_phase15;

	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
	{
	    return STF_INTERNAL_ERROR;
	}
    }

    START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_ATTR);

    /* ATTR out */
    {
	struct  isakmp_mode_attr attrh;
	struct isakmp_attribute attr;
	pb_stream strattr;

	attrh.isama_np = ISAKMP_NEXT_NONE;
	attrh.isama_type = ISAKMP_CFG_SET;
	attrh.isama_identifier = 0;
	if(!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr))
	    return STF_INTERNAL_ERROR;
	/* ISAKMP attr out (status) */
#if 1
	attr.isaat_af_type = XAUTH_STATUS | ISAKMP_ATTR_AF_TV;
	attr.isaat_lv = status;
	out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr, NULL);
#else
	attr.isaat_af_type = XAUTH_STATUS | ISAKMP_ATTR_AF_TLV;
	out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr, &val);
	status = htonl(status);
	out_raw(&status,4,&val,"Status");
	close_output_pbs(&val);
#endif
	close_message(&strattr);
    }

    xauth_mode_cfg_hash(r_hashval,r_hash_start,rbody.cur,st);
    
    close_message(&rbody);
    close_output_pbs(&reply);

    init_phase2_iv(st, &st->st_msgid_phase15);
    encrypt_message(&rbody, st);

    /* free previous transmit packet */
    freeanychunk(st->st_tpacket);

    clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply)
	, "XAUTH: status");

    /* Set up a retransmission event, half a minute henceforth */
    /* Schedule retransmit before sending, to avoid race with master thread */
    delete_event(st);
    event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);


    /* Transmit */

    send_packet(st, "XAUTH: status", TRUE);

    st->st_state = STATE_XAUTH_R1;

    return STF_OK;
}

#ifdef XAUTH_USEPAM
/** XAUTH PAM conversation
 *
 * @param num_msg Int.
 * @param msgm Pam Message Struct
 * @param response Where PAM will put the results
 * @param appdata_ptr Pointer to data struct (as we are using threads)
 * @return int Return Code
 */
static
int xauth_pam_conv(int num_msg, const struct pam_message **msgm,
	       struct pam_response **response, void *appdata_ptr)
{
    struct thread_arg *arg = appdata_ptr;
    int count=0;
    struct pam_response *reply;

    if (num_msg <= 0)
        return PAM_CONV_ERR;

    reply = (struct pam_response *) calloc(num_msg,
                                           sizeof(struct pam_response));
    if (reply == NULL) {
        return PAM_CONV_ERR;
    }

    for (count=0; count < num_msg; ++count) {
        char *string=NULL;

        switch (msgm[count]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
	    string = malloc(arg->password.len+1);
	    strcpy(string,arg->password.ptr);
            break;
        case PAM_PROMPT_ECHO_ON:
	    string = malloc(arg->name.len+1);
	    strcpy(string,arg->name.ptr);
            break;
        }
	
        if (string) { /* must add to reply array */
           /* add string to list of responses */

            reply[count].resp_retcode = 0;
            reply[count].resp = string;
            string = NULL;
        }
    }

    *response = reply;
    reply = NULL;
    return PAM_SUCCESS;
}
#endif


#ifdef XAUTH_USEPAM
/** Do authentication via PAM (Plugable Authentication Modules)
 *
 * We open a PAM session via pam_start, and try to authenticate the user
 *
 * @return int Return Code
 */
static
int do_pam_authentication(void *varg)
{
    struct thread_arg	*arg = varg;
    pam_handle_t *pamh=NULL;
    int retval;

    conv.appdata_ptr = varg;

    retval = pam_start("pluto", arg->name.ptr, &conv, &pamh);

    /*  Two factor authentication - Check that the user is valid, 
	and then check if they are permitted access */
    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, PAM_SILENT);    /* is user really user? */
    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */

    pam_end(pamh, PAM_SUCCESS);

    if(retval == PAM_SUCCESS)
      return TRUE;
    else
      return FALSE;
}
#else /* XAUTH_USEPAM */

/** Do authentication via /etc/ipsec.d/passwd file using MD5 passwords
 *
 * password file structure does not compensate for
 * extra garbage so don't leave any! we do allows for #'s
 * as first char for comments just because I hate conf
 * files like .htaccess that don't support it
 *
 * /etc/ipsec.d/passwd
 * username:md5sum:connectioname\n
 *
 * can be made with, htpasswd:
 *
 * htpasswd -c -m -b /etc/ipsec.d/passwd road roadpass
 *
 * @return int Return Code
 */
static
int do_md5_authentication(void *varg)
{
    struct thread_arg	*arg = varg;
    int len;
    char szline[1024]; /* more than enough */
    FILE *fp;
    char *szuser;
    char *szpass;
    char *szconnid;
    char *sztemp;
    int loc = 0;
    size_t pwlen = strlen(ipsec_dir) + sizeof("/passwd") + 1;

    verify_path_space(&pwdfile, pwlen, "xauth passwd file path");

    snprintf(pwdfile.path, pwdfile.path_space, "%s/passwd", ipsec_dir);

    fp = fopen(pwdfile.path, "r");
    if( fp == (FILE *)0)
    {
        /* unable to open the password file */
        openswan_log("XAUTH: unable to open password file (%s) for verification", pwdfile.path);
        return FALSE;
    }

    openswan_log("XAUTH: password file (%s) open.", pwdfile.path);
    /** simple stuff read in a line then go through positioning
     * szuser ,szpass and szconnid at the begining of each of the
     * memory locations of our real data and replace the ':' with '\0'
     */

    while( fgets( szline, sizeof(szline), fp) != (char *)0)
    {
        len = strlen( szline );
        loc = 0; /* reset our index */
        if(szline[0] == '#') /* comment line move on */
           continue;

        /* get userid */
        sztemp = strchr(szline, ':');
        if (sztemp == (char *)0 )
          continue; /* we found no tokens bad line so just skip it */

        *sztemp++ = '\0'; /* put a null where the ':' was */
        szuser = &szline[loc]; /* szline now contains our null terminated data */
        loc+=strlen(szuser)+1; /* move past null into next section */

        /* get password */        
        sztemp = strchr(&szline[loc], ':');
        if (sztemp == (char *)0 )
          continue; /* we found no tokens bad line so just skip it */

        *sztemp++ = '\0'; /* put a null where the ':' was */
        szpass = &szline[loc]; /* szline now contains our null terminated data */
        loc+=strlen(szpass)+1; /* move past null into next section */

        /* get connection id */        
        sztemp = strchr(&szline[loc], '\n'); /* last \n */        
        if (sztemp == (char *)0 )
          continue; /* we found no tokens bad line so just skip it */

        *sztemp++ = '\0'; /* put a null where the ':' was */        
        szconnid = &szline[loc]; /* szline now contains our null terminated data */        
        
        /* it is possible that szconnid will be null so don't bother
         * checking it. If it is null then this is to say it applies
         * to all connection classes
         */
        DBG(DBG_CONTROL,
	    DBG_log("XAUTH: found user(%s/%s) pass(%s) connid(%s/%s)"
		    , szuser, arg->name.ptr
		    , szpass, szconnid, arg->connname.ptr));

        if ( strcasecmp(szconnid, arg->connname.ptr) == 0
	     && strcmp( szuser, arg->name.ptr ) == 0 ) /* user correct ?*/
        {
	    char *cp;

	    cp = crypt( arg->password.ptr, szpass);

	    if(DBGP(DBG_CRYPT))
	    {
		DBG_log("XAUTH: checking user(%s:%s) pass %s vs %s" , szuser, szconnid, cp, szpass);
	    }
	    else
	    {
		openswan_log("XAUTH: checking user(%s:%s) " , szuser, szconnid);
	    }

           /* Ok then now password check */
           if ( strcmp(cp, szpass ) == 0 )  
           {
             /* we have a winner */
             fclose( fp );
             return TRUE;
           }
	   openswan_log("XAUTH: nope");
        }
    }
    fclose( fp );
    
    return FALSE;
}
#endif

/** Main authentication routine will then call the actual compiled in 
 *  method to verify the user/password
 */
static void * do_authentication(void *varg)
{
    struct thread_arg	*arg = varg;
    struct state *st = arg->st;
    int results=FALSE;
    openswan_log("XAUTH: User %s: Attempting to login" , arg->name.ptr);
    
    

#ifdef XAUTH_USEPAM
    openswan_log("XAUTH: pam authentication being called to authenticate user %s",arg->name.ptr);
    results=do_pam_authentication(varg);
#else
    openswan_log("XAUTH: md5 authentication being called to authenticate user %s",arg->name.ptr);
    results=do_md5_authentication(varg);
#endif
    if(results)
    {
        openswan_log("XAUTH: User %s: Authentication Successful", arg->name.ptr);
        xauth_send_status(st,1);

        if(st->quirks.xauth_ack_msgid) {
	  st->st_msgid_phase15 = 0;
	}
	pfreeany(st->st_xauth_username);
	st->st_xauth_username = clone_str(arg->name.ptr,"XAUTH Username");
    } else
    {
	/** Login attempt failed, display error, send XAUTH status to client
         *  and reset state to XAUTH_R0 */
        openswan_log("XAUTH: User %s: Authentication Failed: Incorrect Username or Password", arg->name.ptr);
        xauth_send_status(st,0);	
        st->st_state = STATE_XAUTH_R0;        
    }   
    
    freeanychunk(arg->password);
    freeanychunk(arg->name);
    freeanychunk(arg->connname);
    pfree(varg);
    
    return NULL;
}


/** Launch an authenication prompt
 *
 * @param st State Structure
 * @param name Usernamd
 * @param password password
 * @param connname conn name, from ipsec.conf
 * @return int Return Code - always 0.
 */
int xauth_launch_authent(struct state *st
			 , chunk_t name
			 , chunk_t password
			 , chunk_t connname)
{
#ifdef HAVE_THREADS
    pthread_attr_t pattr;
    pthread_t tid;
#endif
    struct thread_arg	*arg;
    arg = alloc_thing(struct thread_arg,"ThreadArg");
    arg->st = st;
    arg->password = password;
    arg->name = name;
    arg->connname = connname;
#ifdef HAVE_THREADS
    pthread_attr_init(&pattr);
    pthread_attr_setdetachstate(&pattr,PTHREAD_CREATE_DETACHED);
    pthread_create(&tid,&pattr,do_authentication, (void*) arg);
    pthread_attr_destroy(&pattr);
#else
    do_authentication(arg);
#endif
    return 0;
}

/** STATE_XAUTH_R0:
 *  First REQUEST sent, expect for REPLY
 *  HDR*, HASH, ATTR(REPLY,PASSWORD) --> HDR*, HASH, ATTR(STATUS)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status
xauth_inR0(struct msg_digest *md)
{
    pb_stream *attrs = &md->chain[ISAKMP_NEXT_ATTR]->pbs;
    struct state *const st = md->st;
    chunk_t name, password, connname;
    bool gotname, gotpassword;

    gotname = gotpassword = FALSE;

    CHECK_QUICK_HASH(md,xauth_mode_cfg_hash(hash_val,hash_pbs->roof, md->message_pbs.roof, st)
	, "XAUTH-HASH", "XAUTH R0");

    {
        struct isakmp_attribute attr;
        pb_stream strattr;

	if (md->chain[ISAKMP_NEXT_ATTR]->payload.attribute.isama_type != ISAKMP_CFG_REPLY)
	{
	    openswan_log("Expecting MODE_CFG_REPLY, got %s instead."
		 , enum_name(&attr_msg_type_names, md->chain[ISAKMP_NEXT_ATTR]->payload.attribute.isama_type));
	    return STF_IGNORE;
	}

	while(pbs_left(attrs) > sizeof(struct isakmp_attribute))
	{
	    u_int16_t val;
	    int len;

            if (!in_struct(&attr, &isakmp_xauth_attribute_desc, attrs, &strattr))
	    {
		/* Skip unknown */
		if (attr.isaat_af_type & 0x8000)
		{
		    len = 4;
		    val = attr.isaat_lv;
		} else {
		    len = attr.isaat_lv;
		    val = ntohs(*(u_int16_t *)strattr.cur);
		}

		if(len < 4)
		{
		    openswan_log("Attribute was too short: %d", len);
		    return STF_FAIL;
		}

		attrs->cur += len;
		continue;
	    }

	    if (attr.isaat_af_type & 0x8000)
	    {
		len = 4;
		val = attr.isaat_lv;
	    } else {
		len = attr.isaat_lv;
		val = ntohs(*(u_int16_t *)strattr.cur);
	    }

	    switch(attr.isaat_af_type)
	    {
	    case XAUTH_TYPE:
		if(val != 0)
		    return NO_PROPOSAL_CHOSEN;
		break;

	    case XAUTH_USER_NAME:
		clonetochunk(name,strattr.cur,attr.isaat_lv+1,"username");
		name.ptr[name.len-1] = 0;	/* Pass NULL terminated strings */
		gotname = TRUE;
		break;
		
	    case XAUTH_USER_PASSWORD:
		clonetochunk(password,strattr.cur,attr.isaat_lv+1,"password");
		password.ptr[password.len-1] = 0;
		gotpassword = TRUE;
		break;
		
	    default:
		openswan_log("XAUTH:  Unsupported XAUTH parameter %s received."
		     , enum_show(&modecfg_attr_names, attr.isaat_af_type));
		break;
	    }
	}
    }

    /** we must get a username and a password value */
    if(!gotname || !gotpassword) {
      openswan_log("Expected MODE_CFG_REPLY did not contain %s%s%s attribute"
	   , (!gotname ? "username" : "")
	   , ((!gotname && !gotpassword) ? " or " : "")
	   , (!gotpassword ? "password" : ""));
      if(st->hidden_variables.st_xauth_client_attempt++ < XAUTH_PROMPT_TRIES)
      {
	  stf_status stat = xauth_send_request(st);

	  openswan_log("XAUTH: User %s: Authentication Failed (retry %d)"
	       , (!gotname ? "<unknown>" : (char *)name.ptr)
	       , st->hidden_variables.st_xauth_client_attempt);
	  /**
	   * STF_OK means that we transmitted again okay, but actually
	   * the state transition failed, as we are prompting again.
	   */
	  if(stat == STF_OK)
	  {
	      return STF_IGNORE;
	  } else {
	      return stat;
	  }
      } else {
	  stf_status stat = xauth_send_status(st, FALSE);

	  openswan_log("XAUTH: User %s: Authentication Failed (Retried %d times)"
	       , (!gotname ? "<unknown>" : (char *)name.ptr)
	       , st->hidden_variables.st_xauth_client_attempt);

	  if(stat == STF_OK)
	  {
	      return STF_FAIL;
	  } else {
	      return stat;
	  }
      }
    } else {
	clonetochunk(connname
		     , st->st_connection->name
		     , strlen(st->st_connection->name)+1
		     ,"connname");
	
	connname.ptr[connname.len-1] = 0; /* Pass NULL terminated strings */
	
	xauth_launch_authent(st,name,password,connname);
    }
    return STF_IGNORE;
}


/** STATE_XAUTH_R1:
 *  STATUS sent, expect for ACK
 *  HDR*, ATTR(STATUS), HASH --> Done
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status
xauth_inR1(struct msg_digest *md)
{
    struct state *const st = md->st;
    openswan_log("XAUTH: xauth_inR1(STF_OK)");
    /* Back to where we were */ 
    st->st_oakley.xauth = 0;

    if(!st->st_connection->spd.this.modecfg_server) {
	DBG(DBG_CONTROL
	    , DBG_log("Not server, starting new exchange"));
	st->st_msgid_phase15 = 0;
    }

    if(st->st_connection->spd.this.modecfg_server 
       && st->hidden_variables.st_modecfg_vars_set) {
	DBG(DBG_CONTROL
	    , DBG_log("modecfg server, vars are set. Starting new exchange."));
	st->st_msgid_phase15 = 0;
    }

    if(st->st_connection->spd.this.modecfg_server 
       && st->st_connection->policy & POLICY_MODECFG_PULL) {
	DBG(DBG_CONTROL
	    , DBG_log("modecfg server, pull mode. Starting new exchange."));
	st->st_msgid_phase15 = 0;
    }
    return STF_OK;
}

/* *
 * STATE_MODE_CFG_R0:
 *  HDR*, HASH, ATTR(REQ=IP) --> HDR*, HASH, ATTR(REPLY=IP)
 *
 * This state occurs both in the responder and in the initiator.
 *
 * In the responding server, it occurs when the client *asks* for an IP
 * address or other information. 
 *
 * Otherwise, it occurs in the initiator when the server sends a challenge
 * a set, or has a reply to our request.
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status
modecfg_inR0(struct msg_digest *md)
{
    struct state *const st = md->st;
    struct payload_digest *p;
    pb_stream *attrs;
    stf_status stat;

    DBG(DBG_CONTROLMORE, DBG_log("arrived in modecfg_inR0"));

    st->st_msgid_phase15 = md->hdr.isa_msgid;
    CHECK_QUICK_HASH(md
		     ,xauth_mode_cfg_hash(hash_val
					  ,hash_pbs->roof
					  , md->message_pbs.roof, st)
		     , "MODECFG-HASH", "MODE R0");

    /* process the MODECFG payloads therein */
    for(p = md->chain[ISAKMP_NEXT_ATTR]; p != NULL; p = p->next)
    {
        struct isakmp_attribute attr;
        pb_stream strattr;
	unsigned int resp = LEMPTY;

	attrs = &p->pbs;

	switch(p->payload.attribute.isama_type)
	{
	default:
	    openswan_log("Expecting ISAKMP_CFG_REQUEST, got %s instead (ignored)."
			 , enum_name(&attr_msg_type_names
				     , p->payload.attribute.isama_type));

	    while(pbs_left(attrs) > sizeof(struct isakmp_attribute))
	    {
		if (!in_struct(&attr, &isakmp_xauth_attribute_desc, attrs, &strattr))
		{
		    /* Skip unknown */
		    int len;
		    if (attr.isaat_af_type & 0x8000)
			len = 4;
		    else
			len = attr.isaat_lv;
		    
		    if(len < 4)
		    {
			openswan_log("Attribute was too short: %d", len);
			return STF_FAIL;
		    }
		    
		    attrs->cur += len;
		}
		
		openswan_log("ignored mode cfg attribute %s."
		     , enum_show(&modecfg_attr_names
				 , (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )));
	    }
	    break;

	case ISAKMP_CFG_REQUEST:
	    while(pbs_left(attrs) > sizeof(struct isakmp_attribute))
	    {
		if (!in_struct(&attr, &isakmp_xauth_attribute_desc, attrs, &strattr))
		{
		    /* Skip unknown */
		    int len;
		    if (attr.isaat_af_type & 0x8000)
			len = 4;
		    else
			len = attr.isaat_lv;
		    
		    if(len < 4)
		    {
			openswan_log("Attribute was too short: %d", len);
			return STF_FAIL;
		    }
		    
		    attrs->cur += len;
		}
		switch(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )
		{
		case INTERNAL_IP4_ADDRESS:
		case INTERNAL_IP4_NETMASK:
		case INTERNAL_IP4_DNS:
		case INTERNAL_IP4_SUBNET:
		case INTERNAL_IP4_NBNS:
		    resp |= LELEM(attr.isaat_af_type);
		    break;

		default:
		    openswan_log("unsupported mode cfg attribute %s received."
			 , enum_show(&modecfg_attr_names
				     , (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )));
		    break;
		}
	    }
	    
	    stat = modecfg_resp(st, resp
				,&md->rbody
				,ISAKMP_CFG_REPLY
				,TRUE
				,p->payload.attribute.isama_identifier);
	    
	    if(stat != STF_OK) {
		/* notification payload - not exactly the right choice, but okay */
		md->note = CERTIFICATE_UNAVAILABLE;
		return stat;
	    }

	    /* they asked us, we reponsed, msgid is done */
	    st->st_msgid_phase15 = 0;
	}
    }

    openswan_log("modecfg_inR0(STF_OK)");
    return STF_OK;
}

/** STATE_MODE_CFG_R2:
 *  HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * used in server push mode, on the client (initiator).
 *	    
 * @param md Message Digest
 * @return stf_status
 */
static stf_status
modecfg_inI2(struct msg_digest *md)
{
    struct state *const st = md->st;
    pb_stream *attrs = &md->chain[ISAKMP_NEXT_ATTR]->pbs;
    int resp = LEMPTY;
    stf_status stat;
    struct payload_digest *p;
    u_int16_t isama_id = 0;

    DBG(DBG_CONTROL, DBG_log("modecfg_inI2"));

    st->st_msgid_phase15 = md->hdr.isa_msgid;
    CHECK_QUICK_HASH(md
		     , xauth_mode_cfg_hash(hash_val
					  ,hash_pbs->roof
					  , md->message_pbs.roof
					  , st)
		     , "MODECFG-HASH", "MODE R1");

    for(p = md->chain[ISAKMP_NEXT_ATTR]; p != NULL; p = p->next)
    {
        struct isakmp_attribute attr;
        pb_stream strattr;

	isama_id = p->payload.attribute.isama_identifier;

	if (p->payload.attribute.isama_type != ISAKMP_CFG_SET)
	{
	    openswan_log("Expecting MODE_CFG_SET, got %x instead."
			 ,md->chain[ISAKMP_NEXT_ATTR]->payload.attribute.isama_type);
	    return STF_IGNORE;
	}

	/* CHECK that SET has been received. */

	while(pbs_left(attrs) > sizeof(struct isakmp_attribute))
	{
            if (!in_struct(&attr, &isakmp_xauth_attribute_desc
			   , attrs, &strattr))
	    {
		/* Skip unknown */
		int len;
		if (attr.isaat_af_type & 0x8000)
		    len = 4;
		else
		    len = attr.isaat_lv;

		if(len < 4)
		{
		    openswan_log("Attribute was too short: %d", len);
		    return STF_FAIL;
		}

		attrs->cur += len;
	    }

	    switch(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )
	    {
		case INTERNAL_IP4_ADDRESS:
		    {
			struct connection *c = st->st_connection;
			ip_address a;
			char caddr[SUBNETTOT_BUF];

			u_int32_t *ap = (u_int32_t *)(strattr.cur);
			a.u.v4.sin_family = AF_INET;
			memcpy(&a.u.v4.sin_addr.s_addr, ap
			       , sizeof(a.u.v4.sin_addr.s_addr));
			addrtosubnet(&a, &c->spd.this.client);

			/* make sure that the port info is zeroed */
			setportof(0, &c->spd.this.client.addr);

			c->spd.this.has_client = TRUE;
			subnettot(&c->spd.this.client, 0
				  , caddr, sizeof(caddr));
			openswan_log("setting client address to %s", caddr);
			
			if(addrbytesptr(&c->spd.this.host_srcip, NULL) == 0
			   || isanyaddr(&c->spd.this.host_srcip)) {
			  openswan_log("setting ip source address to %s"
				       , caddr);
			  c->spd.this.host_srcip = a;
			}
		    }
		    resp |= LELEM(attr.isaat_af_type);
		    break;

		case INTERNAL_IP4_NETMASK:
		case INTERNAL_IP4_DNS:
		case INTERNAL_IP4_SUBNET:
		case INTERNAL_IP4_NBNS:
		    resp |= LELEM(attr.isaat_af_type);
		    break;
		default:
		    openswan_log("unsupported mode cfg attribute %s received."
				 , enum_show(&modecfg_attr_names, (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )));
		    break;
	    }
	}
	/* loglog(LOG_DEBUG,"ModeCfg ACK: %x",resp); */
    }

    /* ack things */
    stat = modecfg_resp(st, resp
			,&md->rbody
			,ISAKMP_CFG_ACK
			,FALSE
			,isama_id);

    if(stat != STF_OK) {
	/* notification payload - not exactly the right choice, but okay */
	md->note = CERTIFICATE_UNAVAILABLE;
	return stat;
    }

    /*
     * we are done with this exchange, clear things so
     * that we can start phase 2 properly
     */
    st->st_msgid_phase15 = 0;
    if(resp) {
	st->hidden_variables.st_modecfg_vars_set = TRUE;
    }

    DBG(DBG_CONTROL, DBG_log("modecfg_inI2(STF_OK)"));
    return STF_OK;
}

/** STATE_MODE_CFG_R1:
 *  HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *	    
 * @param md Message Digest
 * @return stf_status
 */
stf_status
modecfg_inR1(struct msg_digest *md)
{
    struct state *const st = md->st;
    pb_stream *attrs = &md->chain[ISAKMP_NEXT_ATTR]->pbs;
    int resp = LEMPTY;
    struct payload_digest *p;

    DBG(DBG_CONTROL, DBG_log("modecfg_inR1"));
    openswan_log("received mode cfg reply");

    st->st_msgid_phase15 = md->hdr.isa_msgid;
    CHECK_QUICK_HASH(md,xauth_mode_cfg_hash(hash_val,hash_pbs->roof, md->message_pbs.roof, st)
	, "MODECFG-HASH", "MODE R1");


    /* process the MODECFG payloads therein */
    for(p = md->chain[ISAKMP_NEXT_ATTR]; p != NULL; p = p->next)
    {
        struct isakmp_attribute attr;
        pb_stream strattr;
	
	attrs = &p->pbs;
	
	switch(p->payload.attribute.isama_type)
	{
	default:
	{
	    openswan_log("Expecting MODE_CFG_ACK, got %x instead.",md->chain[ISAKMP_NEXT_ATTR]->payload.attribute.isama_type);
	    return STF_IGNORE;
	}
	break;
	
	case ISAKMP_CFG_ACK:
	    
	    /* CHECK that ACK has been received. */
	    while(pbs_left(attrs) > sizeof(struct isakmp_attribute))
	    {
		if (!in_struct(&attr, &isakmp_xauth_attribute_desc
			       , attrs, &strattr))
		{
		    /* Skip unknown */
		    int len;
		    if (attr.isaat_af_type & 0x8000)
			len = 4;
		    else
			len = attr.isaat_lv;
		    
		    if(len < 4)
		    {
			openswan_log("Attribute was too short: %d", len);
			return STF_FAIL;
		    }
		    
		    attrs->cur += len;
		}
		
		switch(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )
		{
		case INTERNAL_IP4_ADDRESS:
		case INTERNAL_IP4_NETMASK:
		case INTERNAL_IP4_DNS:
		case INTERNAL_IP4_SUBNET:
		case INTERNAL_IP4_NBNS:
		    resp |= LELEM(attr.isaat_af_type);
		    break;
		default:
		    openswan_log("unsupported mode cfg attribute %s received."
				 , enum_show(&modecfg_attr_names, (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )));
		    break;
		}
	    }
	    break;
	    
	case ISAKMP_CFG_REPLY:
	    while(pbs_left(attrs) > sizeof(struct isakmp_attribute))
	    {
		if (!in_struct(&attr, &isakmp_xauth_attribute_desc
			       , attrs, &strattr))
		{
		    /* Skip unknown */
		    int len;
		    if (attr.isaat_af_type & 0x8000)
			len = 4;
		    else
			len = attr.isaat_lv;
		    
		    if(len < 4)
		    {
			openswan_log("Attribute was too short: %d", len);
			return STF_FAIL;
		    }
		    
		    attrs->cur += len;
		}
		
		switch(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )
		{
		case INTERNAL_IP4_ADDRESS:
		{
		    struct connection *c = st->st_connection;
		    ip_address a;
		    char caddr[SUBNETTOT_BUF];
		    
		    u_int32_t *ap = (u_int32_t *)(strattr.cur);
		    a.u.v4.sin_family = AF_INET;
		    memcpy(&a.u.v4.sin_addr.s_addr, ap
			   , sizeof(a.u.v4.sin_addr.s_addr));
		    addrtosubnet(&a, &c->spd.this.client);

		    /* make sure that the port info is zeroed */
		    setportof(0, &c->spd.this.client.addr);

		    c->spd.this.has_client = TRUE;
		    subnettot(&c->spd.this.client, 0
			      , caddr, sizeof(caddr));
		    openswan_log("setting client address to %s"
				 , caddr);
		    
		    if(addrbytesptr(&c->spd.this.host_srcip, NULL) == 0
		       || isanyaddr(&c->spd.this.host_srcip)) {
			openswan_log("setting ip source address to %s"
				     , caddr);
			c->spd.this.host_srcip = a;
		    }
		}
		resp |= LELEM(attr.isaat_af_type);
		break;
		
		case INTERNAL_IP4_NETMASK:
		case INTERNAL_IP4_DNS:
		case INTERNAL_IP4_SUBNET:
		case INTERNAL_IP4_NBNS:
		    resp |= LELEM(attr.isaat_af_type);
		    break;
		default:
		    openswan_log("unsupported mode cfg attribute %s received."
				 , enum_show(&modecfg_attr_names, (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )));
		    break;
		}
	    }
	    /* loglog(LOG_DEBUG,"ModeCfg ACK: %x",resp); */
	    break;
	    /* loglog(LOG_DEBUG,"ModeCfg ACK: %x",resp); */
	}
    }

    /* we are done with this exchange, clear things so that we can start phase 2 properly */
    st->st_msgid_phase15 = 0;
    if(resp) {
	st->hidden_variables.st_modecfg_vars_set = TRUE;
    }

    DBG(DBG_CONTROL, DBG_log("modecfg_inR1(STF_OK)"));
    return STF_OK;
}

/** XAUTH client code - response to challenge.  May open filehandle to console
 * in order to prompt user for password
 *
 * @param st State
 * @param xauth_resp XAUTH Reponse
 * @param rbody Reply Body
 * @param ap_id
 * @return stf_status
 */
stf_status xauth_client_resp(struct state *st
			     ,unsigned int xauth_resp
			     ,pb_stream *rbody
			     ,u_int16_t ap_id)
{
    unsigned char *r_hash_start,*r_hashval;
    char xauth_username[64], xauth_password[64];
    struct connection *c = st->st_connection;
    

    /* START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_ATTR); */

    {
      pb_stream hash_pbs; 
      int np = ISAKMP_NEXT_ATTR;

      if (!out_generic(np, &isakmp_hash_desc, rbody, &hash_pbs)) 
	return STF_INTERNAL_ERROR; 
      r_hashval = hash_pbs.cur;	/* remember where to plant value */ 
      if (!out_zero(st->st_oakley.hasher->hash_digest_len, &hash_pbs, "HASH")) 
	return STF_INTERNAL_ERROR; 
      close_output_pbs(&hash_pbs); 
      r_hash_start = (rbody)->cur;	/* hash from after HASH payload */ 
    }

    /* ATTR out */
    {
	struct  isakmp_mode_attr attrh;
	struct isakmp_attribute attr;
	pb_stream strattr,attrval;
	int attr_type;
	int dns_idx, wins_idx;
	bool dont_advance;

	attrh.isama_np = ISAKMP_NEXT_NONE;
	attrh.isama_type = ISAKMP_CFG_REPLY;

	attrh.isama_identifier = ap_id;
	if(!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
	    return STF_INTERNAL_ERROR;
	
	dns_idx = 0;
	wins_idx = 0;
	attr_type = XAUTH_TYPE;

	while(xauth_resp != 0)
	{
	    dont_advance = FALSE;
	    if(xauth_resp & 1)
	    {
		/* ISAKMP attr out */
		switch(attr_type)
		{
		case XAUTH_TYPE:
		    attr.isaat_af_type = attr_type | ISAKMP_ATTR_AF_TV;
		    attr.isaat_lv = XAUTH_TYPE_GENERIC;
		    out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr, NULL);
		    break;
		    
		case XAUTH_USER_NAME:
		    attr.isaat_af_type = attr_type | ISAKMP_ATTR_AF_TLV;
		    out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr, &attrval);
		    if(st->st_whack_sock == -1)
		    {
			loglog(RC_LOG_SERIOUS, "XAUTH username requested, but no file descriptor available for prompt");
			return STF_FAIL;
		    }
		    
		    if(!whack_prompt_for(st->st_whack_sock
					 , c->name, "Username", TRUE
					 , xauth_username
					 , sizeof(xauth_username)))
		    {
			loglog(RC_LOG_SERIOUS, "XAUTH username prompt failed.");
			return STF_FAIL;
		    }
		    /* trip any trailing white space */
		    {
		      char *u = xauth_username;
		      strsep(&u, " \n\t");
		    }
		    out_raw(xauth_username, strlen(xauth_username)
			    ,&attrval, "XAUTH username");
		    close_output_pbs(&attrval);

		    break;
		    
		case XAUTH_USER_PASSWORD:
		    attr.isaat_af_type = attr_type | ISAKMP_ATTR_AF_TLV;
		    out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr, &attrval);
		    if(st->st_whack_sock == -1)
		    {
			loglog(RC_LOG_SERIOUS, "XAUTH password requested, but no file descriptor available for prompt");
			return STF_FAIL;
		    }
		    
		    if(!whack_prompt_for(st->st_whack_sock
					 , c->name, "Password", FALSE
					 , xauth_password
					 , sizeof(xauth_password)))
		    {
			loglog(RC_LOG_SERIOUS, "XAUTH password prompt failed.");
			return STF_FAIL;
		    }

		    /* trip any trailing white space */
		    {
		      char *u = xauth_password;

		      strsep(&u, " \n\t");
		    }
		    out_raw(xauth_password, strlen(xauth_password)
			    ,&attrval, "XAUTH password");
		    close_output_pbs(&attrval);
		    break;
		    
		default:
		    openswan_log("trying to send XAUTH reply, sending %s instead."
			 , enum_show(&modecfg_attr_names, attr_type));
		    break;
		}
	    }
	    
	    if (!dont_advance) {
		attr_type++;
		xauth_resp >>= 1;
	    }
	}
	
	/* do not PAD here, */
	close_output_pbs(&strattr);
    }

    openswan_log("XAUTH: Answering XAUTH challenge with user='%s'"
		 , xauth_username);

    xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody->cur, st);
    
    close_message(rbody);

    encrypt_message(rbody, st);

    return STF_OK;
}

/** 
 * STATE_XAUTH_I0
 *  HDR*, HASH, ATTR(REQ=IP) --> HDR*, HASH, ATTR(REPLY=IP)
 *
 * This state occurs in initiator.
 *
 * In the initating client, it occurs in XAUTH, when the responding server
 * demands a password, and we have to supply it.
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status
xauth_inI0(struct msg_digest *md)
{
    struct state *const st = md->st;
    struct payload_digest *p;
    pb_stream *attrs;
    char msgbuf[81];
    int len;
    unsigned type;
    char *dat;
    int status = 0;
    unsigned val;
    stf_status stat;
    bool gotrequest = FALSE;
    bool gotset = FALSE;
    bool got_status = FALSE;

    if(st->hidden_variables.st_xauth_client_done) {
	return modecfg_inI2(md);
    }

    DBG(DBG_CONTROLMORE, DBG_log("arrived in xauth_inI0"));

    st->st_msgid_phase15 = md->hdr.isa_msgid;
    CHECK_QUICK_HASH(md, xauth_mode_cfg_hash(hash_val
					     ,hash_pbs->roof
					     , md->message_pbs.roof, st)
		     , "MODECFG-HASH", "XAUTH I0");

    stat = STF_FAIL;

    /* process the MODECFG payloads therein */
    for(p = md->chain[ISAKMP_NEXT_ATTR]; p != NULL; p = p->next)
    {
        struct isakmp_attribute attr;
        pb_stream strattr;
	unsigned int xauth_resp = LEMPTY;

#define XAUTHLELEM(x) (LELEM(x - XAUTH_TYPE))

	attrs = &p->pbs;

	switch(p->payload.attribute.isama_type)
	{
	default:
	    openswan_log("Expecting ISAKMP_CFG_REQUEST, got %s instead (ignored)."
			 , enum_name(&attr_msg_type_names
				     , p->payload.attribute.isama_type));
	case ISAKMP_CFG_SET:
	    gotset = TRUE;
	    break;

	case ISAKMP_CFG_REQUEST:
	    gotrequest = TRUE;
	    break;
	}

	while(attrs->cur < attrs->roof)
	{
	    memset(&attr, 0, sizeof(attr));
	    
	    if (!in_struct(&attr, &isakmp_xauth_attribute_desc
			   , attrs, &strattr))
	    {
		/* Skip unknown */
		int len;
		if (attr.isaat_af_type & 0x8000)
		    len = 4;
		else
		    len = attr.isaat_lv;
		
		if(len < 4)
		{
		    openswan_log("Attribute was too short: %d", len);
		    return STF_FAIL;
		}
		
		attrs->cur += len;
		continue;
	    }
	    
	    if (attr.isaat_af_type & 0x8000)
	    {
		len = 4;
		val = attr.isaat_lv;
		dat = NULL;
	    } else {
		len = attr.isaat_lv;
		val = ntohs(*(u_int16_t *)strattr.cur);
		dat = strattr.cur;
	    }
	    
	    switch(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )
	    {
	    case XAUTH_STATUS:
		got_status = TRUE;
		status = attr.isaat_lv;
		break;
		
	    case XAUTH_MESSAGE:
		if(len > 80) len=80;
		memcpy(msgbuf, dat, len);
		msgbuf[len]='\0';
		loglog(RC_LOG_SERIOUS, "XAUTH: Bad Message: %s", msgbuf);
		break;
		
	    case XAUTH_TYPE:
		type = val;
		if(type != XAUTH_TYPE_GENERIC)
		{
		    openswan_log("XAUTH: Unsupported type: %d", type);
		    return STF_IGNORE;
		}
		xauth_resp |= XAUTHLELEM(attr.isaat_af_type);
		break;

	    case XAUTH_USER_NAME:
	    case XAUTH_USER_PASSWORD:
		xauth_resp |= XAUTHLELEM(attr.isaat_af_type);
		break;
		
	    case INTERNAL_IP4_ADDRESS:
	    case INTERNAL_IP4_NETMASK:
	    case INTERNAL_IP4_DNS:
	    case INTERNAL_IP4_SUBNET:
	    case INTERNAL_IP4_NBNS:
		xauth_resp |= LELEM(attr.isaat_af_type);
		break;

	    default:
		openswan_log("XAUTH: Unsupported attribute: %s"
		     , enum_show(&modecfg_attr_names, (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK)));
		break;
	    }
	}

	if(gotset && got_status)
	{
	    /* ACK whatever it was that we got */
	    stat = xauth_client_ackstatus(st, &md->rbody
					  ,md->chain[ISAKMP_NEXT_ATTR]->payload.attribute.isama_identifier);

	    /* must have gotten a status */
	    if(status && stat == STF_OK)
	    {
		st->hidden_variables.st_xauth_client_done = TRUE;
		openswan_log("XAUTH: Successfully Authenticated");
		st->st_oakley.xauth = 0;

		return STF_OK;
	    }
	    else
	    {
		return STF_FATAL;
	    }
	}
	    
	if(gotrequest)
	{
	    if(xauth_resp & (XAUTHLELEM(XAUTH_USER_NAME)|XAUTHLELEM(XAUTH_USER_PASSWORD))) {
		DBG(DBG_CONTROL, DBG_log("XAUTH: Username/password request received"));
	    }
	    
	    /* sanitize what we were asked to reply to */
	    if(st->st_connection->spd.this.xauth_client
	       && (xauth_resp &( XAUTHLELEM(XAUTH_USER_NAME)
				 | XAUTHLELEM(XAUTH_USER_PASSWORD)))==0)
	    {
		openswan_log("XAUTH: No username/password request was received.");
		return STF_IGNORE;
	    }

	    /* now, opposite */
	    if(!st->st_connection->spd.this.xauth_client
	       && (xauth_resp & (XAUTHLELEM(XAUTH_USER_NAME)
				 |XAUTHLELEM(XAUTH_USER_PASSWORD)))!=0)
	    {
		openswan_log("XAUTH: Username/password request was received, but XAUTH client mode not enabled.");
		return STF_IGNORE;
	    }
	    
	    stat = xauth_client_resp(st, xauth_resp
				     , &md->rbody
				     ,md->chain[ISAKMP_NEXT_ATTR]->payload.attribute.isama_identifier);
	}

	if(stat != STF_OK) {
	    /* notification payload - not exactly the right choice, but okay */
	    md->note = CERTIFICATE_UNAVAILABLE;
	    return stat;
	}
    }

    /* reset the message ID */
    st->st_msgid_phase15b = st->st_msgid_phase15;
    st->st_msgid_phase15 = 0;

    DBG(DBG_CONTROLMORE, DBG_log("xauth_inI0(STF_OK)"));
    return STF_OK;
}

/** XAUTH client code - Acknowledge status 
 *
 * @param st State
 * @param rbody Response Body
 * @param ap_id
 * @return stf_status
 */
stf_status xauth_client_ackstatus(struct state *st
				  ,pb_stream *rbody
				  ,u_int16_t ap_id)
{
    unsigned char *r_hash_start,*r_hashval;
    

    /* START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_ATTR); */

    {
      pb_stream hash_pbs; 
      int np = ISAKMP_NEXT_ATTR;

      if (!out_generic(np, &isakmp_hash_desc, rbody, &hash_pbs)) 
	return STF_INTERNAL_ERROR; 
      r_hashval = hash_pbs.cur;	/* remember where to plant value */ 
      if (!out_zero(st->st_oakley.hasher->hash_digest_len, &hash_pbs, "HASH")) 
	return STF_INTERNAL_ERROR; 
      close_output_pbs(&hash_pbs); 
      r_hash_start = (rbody)->cur;	/* hash from after HASH payload */ 
    }

    /* ATTR out */
    {
	struct  isakmp_mode_attr attrh;
	struct isakmp_attribute attr;
	pb_stream strattr,attrval;
	int attr_type;
	int dns_idx, wins_idx;

	attrh.isama_np = ISAKMP_NEXT_NONE;
	attrh.isama_type = ISAKMP_CFG_ACK;

	attrh.isama_identifier = ap_id;
	if(!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
	    return STF_INTERNAL_ERROR;
	
	dns_idx = 0;
	wins_idx = 0;
	attr_type = XAUTH_TYPE;

	/* ISAKMP attr out */
	attr.isaat_af_type = XAUTH_STATUS | ISAKMP_ATTR_AF_TV;
	attr.isaat_lv = 1;
	out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr, &attrval);
	close_output_pbs(&attrval);
	close_message(&strattr);
    }

    xauth_mode_cfg_hash(r_hashval,r_hash_start,rbody->cur,st);
    
    close_message(rbody);

    encrypt_message(rbody, st);

    return STF_OK;
}

/** STATE_XAUTH_I1
 *  HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *	    
 * @param md Message Digest
 * @return stf_status
 */
stf_status
xauth_inI1(struct msg_digest *md)
{
    struct state *const st = md->st;
    pb_stream *attrs = &md->chain[ISAKMP_NEXT_ATTR]->pbs;
    bool got_status, status;
    stf_status stat;
    struct payload_digest *p;
    unsigned int xauth_resp = LEMPTY;

    if(st->hidden_variables.st_xauth_client_done) {
	return modecfg_inI2(md);
    }

    DBG(DBG_CONTROLMORE, DBG_log("xauth_inI1"));

    st->st_msgid_phase15 = md->hdr.isa_msgid;
    CHECK_QUICK_HASH(md
		     , xauth_mode_cfg_hash(hash_val
					   ,hash_pbs->roof
					   , md->message_pbs.roof, st)
		     , "MODECFG-HASH", "XAUTH I1");

    got_status = FALSE;
    status = FALSE;

    for(p = md->chain[ISAKMP_NEXT_ATTR]; p != NULL; p = p->next)
    {
        struct isakmp_attribute attr;
        pb_stream strattr;
	
	attrs = &p->pbs;
	
	switch(p->payload.attribute.isama_type)	{
	default:
	    openswan_log("Expecting MODE_CFG_SET, got %x instead."
			 , p->payload.attribute.isama_type);
	    return STF_IGNORE;
	    
	case ISAKMP_CFG_SET:
	    /* CHECK that SET has been received. */
	    while(attrs->cur < attrs->roof)
	    {
		memset(&attr, 0, sizeof(attr));
		
		if (!in_struct(&attr, &isakmp_xauth_attribute_desc
			       , attrs, &strattr))
		{
		    /* Skip unknown */
		    int len;
		    if (attr.isaat_af_type & 0x8000)
			len = 4;
		    else
			len = attr.isaat_lv;
		    
		    if(len < 4)
		    {
			openswan_log("Attribute was too short: %d", len);
			return STF_FAIL;
		    }
		    
		    attrs->cur += len;
		}
		
		switch(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )
		{
		case XAUTH_STATUS:
		    xauth_resp |= XAUTHLELEM(attr.isaat_af_type);
		    got_status = TRUE;
		    status = attr.isaat_lv;
		    break;
		    
		default:
		    openswan_log("while waiting for XAUTH_STATUS, got %s instead."
			 , enum_show(&modecfg_attr_names, (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK)));
		    break;
		}
	    }
	    break;
	}
    }

    /* first check if we might be done! */
    if(!got_status || status==FALSE)
    {
	/* oops, something seriously wrong */
	openswan_log("did not get status attribute in xauth_inI1, looking for new challenge.");
	st->st_state = STATE_XAUTH_I0;
	return xauth_inI0(md);
    }

    /* ACK whatever it was that we got */
    stat = xauth_client_ackstatus(st, &md->rbody
				  ,md->chain[ISAKMP_NEXT_ATTR]->payload.attribute.isama_identifier);

    /* must have gotten a status */
    if(status && stat == STF_OK)
    {
	st->hidden_variables.st_xauth_client_done = TRUE;
	openswan_log("successfully logged in");
	st->st_oakley.xauth = 0;

	return STF_OK;
    }

    /* what? */
    return stat;
}


/*
 * $Id: xauth.c,v 1.41.4.3 2005/07/26 02:11:23 ken Exp $
 *
 * $Log: xauth.c,v $
 * Revision 1.41.4.3  2005/07/26 02:11:23  ken
 * Pullin from HEAD:
 * Split Aggressive mode into ikev1_aggr.c
 * Fix NAT-T that we broke in dr7
 * Move dpd/pgp vendor id's to vendor.[ch]
 *
 * Revision 1.41.4.2  2005/07/25 19:26:34  ken
 * Pullin fixes for NAT-T from HEAD
 * Includes IMPAIR_JACOB_TWO_TWO impairment from HEAD
 * change from c->interface to st->st_interface for sending packets
 *
 * Revision 1.43  2005/07/22 14:05:51  mcr
 * 	fixes for -Werror warnings.
 *
 * Revision 1.42  2005/07/22 14:00:19  mcr
 * 	fixes for -Werror warnings.
 *
 * Revision 1.41  2005/02/16 17:27:41  mcr
 * 	moved recording of xauth username to after the username
 * 	has actually been authenticated.
 * 	Do not record username on client -- I don't think that this
 * 	makes any sense. If it is important, it should be recorded
 * 	(and expressed in do_command()) in a different way.
 *
 * Revision 1.40  2005/02/14 05:58:46  ken
 * Add support for saving the XAUTH username, and then passing it to _updown as PLUTO_XAUTH_USERNAME environment variable
 *
 * Revision 1.39  2005/01/26 07:01:55  mcr
 * 	use phase1.5 msgid instead of msgid.
 *
 *
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
