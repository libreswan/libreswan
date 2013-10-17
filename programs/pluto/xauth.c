/* XAUTH related functions
 *
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003 Sean Mathews - Nu Tech Software Solutions, inc.
 * Copyright (C) 2003-2004 Xelerance Corporation
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
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
 * This code originally written by Colubris Networks, Inc.
 * Extraction of patch and porting to 1.99 codebases by Xelerance Corporation
 * Porting to 2.x by Sean Mathews
 */

#include <pthread.h>    /* Must be the first include file */

/* #ifdef XAUTH */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <signal.h>
#include <setjmp.h>

#if defined(linux)
/* is supposed to be in unistd.h, but it isn't on linux */
#include <crypt.h>
#endif

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>

#include "lswalloc.h"

#include "sysdep.h"
#include "lswconf.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#ifdef XAUTH_HAVE_PAM
# include <security/pam_appl.h>
#endif
#include "connections.h"        /* needs id.h */
#include "packet.h"
#include "demux.h"              /* needs packet.h */
#include "log.h"
#include "timer.h"
#include "keys.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"

#include "xauth.h"
#include "virtual.h"	/* needs connections.h */
#include "addresspool.h"

/* forward declarations */
static stf_status modecfg_inI2(struct msg_digest *md);
static stf_status xauth_client_ackstatus(struct state *st,
				  pb_stream *rbody,
				  u_int16_t ap_id);

static char pwdfile[PATH_MAX];

/* We use crypt_mutex lock because not all systems have crypt_r() */
pthread_mutex_t crypt_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
	bool in_use;
	struct state *st;
	sigjmp_buf jbuf;
} st_jbuf_t;

struct thread_arg {
	struct state *st;
	chunk_t name;
	chunk_t password;
	chunk_t connname;
#ifdef XAUTH_HAVE_PAM
	st_jbuf_t *ptr;
#endif
};

#ifdef XAUTH_HAVE_PAM
static int xauth_pam_conv(int num_msg, const struct pam_message **msgm,
		   struct pam_response **response, void *appdata_ptr);

static struct pam_conv conv = {
	xauth_pam_conv,
	NULL
};
#endif

/* pointer to an array of st_jbuf_t elements.
 * The last element has .st==NULL (and !.in_use).
 * Unused ones (not the last) have some meaningless non-NULL value in .st.  Yuck!
 * All manipulations must be protected via st_jbuf_mutex.
 * If no entries are in use, the array must be freed:
 * two tests in do_authentication depend on this.
 */
static st_jbuf_t *st_jbuf_mem = NULL;

static pthread_mutex_t st_jbuf_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Note: caller must have locked st_jbuf_mutex */
static void dealloc_st_jbuf(st_jbuf_t *ptr)
{
	st_jbuf_t *p;

	ptr->in_use = FALSE;

	for (p = st_jbuf_mem; p->st != NULL; p++) {
		if (p->in_use) {
			/* there is still an entry in use: don't free array */
			return;
		}
	}

	/* no remaining entries in use: free array */
	free(st_jbuf_mem);
	st_jbuf_mem = NULL;
}

/* Note: caller must have locked st_jbuf_mutex */
static st_jbuf_t *get_ptr_matching_tid(void)
{
	st_jbuf_t *p;

	for (p = st_jbuf_mem; p->st != NULL; p++) {
		if (p->in_use && p->st->xauth_tid == pthread_self())
			return p;
	}
	return NULL;
}

/* Find or create a free slot in the st_jbuf_mem array.
 * Note: after return, caller MUST set the .st field of the result to a
 * non-NULL value or bad things happen. The only caller does this.
 * The caller must not have locked st_jbuf_mutex: we will.
 */
static st_jbuf_t *alloc_st_jbuf(void)
{
	st_jbuf_t *ptr;

	pthread_mutex_lock(&st_jbuf_mutex);
	if (st_jbuf_mem == NULL) {
		/* no array: allocate one slot plus endmarker
		 * calloc ensures that the endmarker has .st == NULL
		 */
		st_jbuf_mem = calloc(2, sizeof(st_jbuf_t));
		if (st_jbuf_mem == NULL)
			lsw_abort();

		ptr = st_jbuf_mem;
		/* new entry is going in first slot in our new array */
	} else {
		for (ptr = st_jbuf_mem; ptr->st != NULL; ptr++) {
			if (ptr->st == NULL) {
				/* ptr points at endmarker:
				 * there is no room in the existing array.
				 * Add another slot.
				 */
				ptrdiff_t n = ptr - st_jbuf_mem;	/* number of entries, excluding end marker */

				/* allocate n entries, plus one new entry, plus new endmarker */
				st_jbuf_mem = realloc(st_jbuf_mem, sizeof(st_jbuf_t) * (n + 2));
				if (st_jbuf_mem == NULL)
					lsw_abort();

				ptr = st_jbuf_mem + n;

				/* caller MUST ensure that ptr->st is non-NULL */

				ptr[1].in_use = FALSE;	/* initialize new endmarker */
				ptr[1].st = NULL;
				/* new entry is the former endmarker slot */
				break;
			}
			if (!ptr->in_use) {
				/* we found a free slot in our existing array */
				break;
			}
		}
	}

	ptr->in_use = TRUE;
	pthread_mutex_unlock(&st_jbuf_mutex);
	return ptr;
}

/* sigIntHandler.
 * The only expected source of SIGINTs is state_deletion_xauth_cleanup
 * so the meaning is: shut down this thread, the state is disappearing.
 * ??? what if a SIGINT comes from somewhere else?
 * Note: this function locks st_jbuf_mutex
 * The longjump handler must unlock it.
 */
static void sigIntHandler(int sig)
{
	if (sig == SIGINT) {
		st_jbuf_t *ptr;

		pthread_mutex_lock(&st_jbuf_mutex);
		ptr = get_ptr_matching_tid();
		if (ptr == NULL) {
			pthread_mutex_unlock(&st_jbuf_mutex);
			lsw_abort();
		}
		/* note: st_jbuf_mutex is locked */
		siglongjmp(ptr->jbuf, 1);
	}
}

/* state_deletion_xauth_cleanup:
 * If there is still an authentication thread alive, kill it.
 * This is called by delete_state() to fix up any dangling xauth thread.
 */
void state_deletion_xauth_cleanup(struct state *st)
{
	/* ??? In POSIX pthreads, pthread_t is opaque and the following test is not legitimate  */
	if (st->xauth_tid) {
		pthread_kill(st->xauth_tid, SIGINT);
		/* The pthread_mutex_lock ensures that the do_authentication
		 * thread completes when pthread_kill'ed
		 */
		pthread_mutex_lock(&st->xauth_mutex);
		pthread_mutex_unlock(&st->xauth_mutex);
	}
	/* ??? what if the mutex hasn't been created?  Is destroying OK? */
	pthread_mutex_destroy(&st->xauth_mutex);
}

#ifdef XAUTH_HAVE_PAM

/**
 * Get IP address from a PAM environment variable
 *
 * @param pamh An open PAM filehandle
 * @param var Environment Variable to get the IP address from.  Usually IPADDR, DNS[12], WINS[12]
 * @param addr Pointer to var where you want IP address stored
 * @return int Return code
 */
static int get_addr(pam_handle_t *pamh, const char *var, ip_address *addr)
{
	const char *c;
	int retval;

	c = pam_getenv(pamh, var);
	if (c == NULL)
		c = "0.0.0.0";
	retval = inet_pton(AF_INET, c, (void*) &addr->u.v4.sin_addr.s_addr);
	addr->u.v4.sin_family = AF_INET;
	return retval > 0;
}
#endif

oakley_auth_t xauth_calcbaseauth(oakley_auth_t baseauth)
{
	switch (baseauth) {
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
static int get_internal_addresses(struct state *st, struct internal_addr *ia)
{
#ifdef XAUTH_HAVE_PAM
	int retval;
	char str[IDTOA_BUF + sizeof("ID=") + 2];
#endif
	struct connection *c = st->st_connection;

	if (!isanyaddr(&c->spd.that.client.addr)) {
		/** assumes IPv4, and also that the mask is ignored */

		if (c->pool)
			get_addr_lease(c, ia);
		else
			ia->ipaddr = c->spd.that.client.addr;

		if (!isanyaddr(&c->modecfg_dns1))
			ia->dns[0] = c->modecfg_dns1;
		if (!isanyaddr(&c->modecfg_dns2))
			ia->dns[1] = c->modecfg_dns2;
	} else

	{
#ifdef XAUTH_HAVE_PAM
		if (c->xauthby == XAUTHBY_PAM) {
			if (c->pamh == NULL) {
				/** Start PAM session, using 'pluto' as our PAM name */
				retval = pam_start("pluto", "user", &conv,
						   &c->pamh);
				memset(ia, 0, sizeof(*ia));
				if (retval == PAM_SUCCESS) {
					char buf[IDTOA_BUF];

					idtoa(&c->spd.that.id, buf,
					      sizeof(buf));
					if (c->spd.that.id.kind ==
					    ID_DER_ASN1_DN) {
						/** Keep only the common name, if one exists */
						char *c1, *c2;
						c1 = strstr(buf, "CN=");
						if (c1) {
							c2 = strstr(c1, ", ");
							if (c2)
								*c2 = '\0';
							memmove(buf, c1 + 3, strlen(
									c1) + 1 -
								3);
						}
					}
					snprintf(str, sizeof(str), "ID=%s",
						 buf);
					pam_putenv(c->pamh, str);
					pam_open_session(c->pamh, 0);
				}
			}
			if (c->pamh != NULL) {
				/* Paul: Could pam give these to us? */
				/** Put IP addresses from various variables into our
				 *  internal address struct */
				get_addr(c->pamh, "IPADDR", &ia->ipaddr);
				get_addr(c->pamh, "DNS1", &ia->dns[0]);
				get_addr(c->pamh, "DNS2", &ia->dns[1]);
			}
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
static size_t xauth_mode_cfg_hash(u_char *dest,
			   const u_char *start,
			   const u_char *roof,
			   const struct state *st)
{
	struct hmac_ctx ctx;

	hmac_init_chunk(&ctx, st->st_oakley.prf_hasher, st->st_skeyid_a);
	hmac_update(&ctx, (const u_char *) &st->st_msgid_phase15,
		    sizeof(st->st_msgid_phase15));
	hmac_update(&ctx, start, roof - start);
	hmac_final(dest, &ctx);

	DBG(DBG_CRYPT, {
		    DBG_log("XAUTH: HASH computed:");
		    DBG_dump("", dest, ctx.hmac_digest_len);
	    });
	return ctx.hmac_digest_len;
}

/**
 * Mode Config Reply
 *
 * Generates a reply stream containing Mode Config information (eg: IP, DNS, WINS)
 *
 * @param st State structure
 * @param resp Type of reply (lset_t)  ??? why singular -- this is a set?
 * @param pb_stream rbody Body of the reply (stream)
 * @param replytype int
 * @param use_modecfg_addr_as_client_addr bool
 *         True means force the IP assigned by Mode Config to be the
 *         spd.that.addr.  Useful when you know the client will change his IP
 *         to be what was assigned immediatly after authentication.
 * @param ap_id ISAMA Identifier
 * @return stf_status STF_OK or STF_INTERNAL_ERROR
 */
static stf_status modecfg_resp(struct state *st,
			lset_t resp,
			pb_stream *rbody,
			u_int16_t replytype,
			bool use_modecfg_addr_as_client_addr,
			u_int16_t ap_id)
{
	unsigned char *r_hash_start, *r_hashval;

	/* START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_MCFG_ATTR); */

	{
		pb_stream hash_pbs;

		if (!out_generic(ISAKMP_NEXT_MCFG_ATTR, &isakmp_hash_desc, rbody, &hash_pbs))
			return STF_INTERNAL_ERROR;

		r_hashval = hash_pbs.cur; /* remember where to plant value */
		if (!out_zero(st->st_oakley.prf_hasher->hash_digest_len,
			      &hash_pbs, "HASH"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&hash_pbs);
		r_hash_start = rbody->cur; /* hash from after HASH payload */
	}

	/* ATTR out */
	{
		pb_stream strattr;
		int attr_type;
		struct internal_addr ia;
		int dns_idx;

		{
			struct  isakmp_mode_attr attrh;

			attrh.isama_np = ISAKMP_NEXT_NONE;
			attrh.isama_type = replytype;
			attrh.isama_identifier = ap_id;
			if (!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
				return STF_INTERNAL_ERROR;
		}

		zero(&ia);
		get_internal_addresses(st, &ia);

		if (!isanyaddr(&ia.dns[0])) /* We got DNS addresses, answer with those */
			resp |= LELEM(INTERNAL_IP4_DNS);
		else
			resp &= ~LELEM(INTERNAL_IP4_DNS);

		if (use_modecfg_addr_as_client_addr) {
			if (memcmp(&st->st_connection->spd.that.client.addr,
				   &ia.ipaddr,
				   sizeof(ia.ipaddr)) != 0) {
				/* Make the Internal IP address and Netmask as
				 * that client address
				 */
				st->st_connection->spd.that.client.addr =
					ia.ipaddr;
				st->st_connection->spd.that.client.maskbits =
					32;
				st->st_connection->spd.that.has_client = TRUE;
			}
		}

		attr_type = 0;
		dns_idx = 0;
		while (resp != LEMPTY) {
			bool dont_advance = FALSE;

			if (resp & 1) {
				pb_stream attrval;
				unsigned char *byte_ptr;
				unsigned int len;

				/* ISAKMP attr out */
				{
					struct isakmp_attribute attr;

					attr.isaat_af_type = attr_type |
							     ISAKMP_ATTR_AF_TLV;
					if (!out_struct(&attr,
							&isakmp_xauth_attribute_desc,
							&strattr,
							&attrval))
						return STF_INTERNAL_ERROR;
				}

				switch (attr_type) {
				case INTERNAL_IP4_ADDRESS:
					len = addrbytesptr(&ia.ipaddr,
							   &byte_ptr);
					if (!out_raw(byte_ptr, len, &attrval,
						     "IP4_addr"))
						return STF_INTERNAL_ERROR;

					break;

				case INTERNAL_IP4_SUBNET:
					len = addrbytesptr(
						&st->st_connection->spd.this.client.addr,
						&byte_ptr);
					if (!out_raw(byte_ptr, len, &attrval,
						     "IP4_subnet"))
						return STF_INTERNAL_ERROR;
					/* FALL THROUGH  */
				case INTERNAL_IP4_NETMASK:
				{
					int m =
						st->st_connection->spd.this.client.maskbits;
					u_int32_t mask = htonl(~(m == 32 ? (u_int32_t)0 : ~(u_int32_t)0 >> m));


					if (!out_raw(&mask, sizeof(mask),
						     &attrval, "IP4_submsk"))
						return STF_INTERNAL_ERROR;
					break;
				}

				case INTERNAL_IP4_DNS:
					len = addrbytesptr(&ia.dns[dns_idx++],
							   &byte_ptr);
					if (!out_raw(byte_ptr, len, &attrval,
						     "IP4_dns"))
						return STF_INTERNAL_ERROR;

					if (dns_idx < 2 &&
					    !isanyaddr(&ia.dns[dns_idx]))
						dont_advance = TRUE;
					break;

				case MODECFG_DOMAIN:
				{
					if(st->st_connection->modecfg_domain) {
						DBG_log("We are sending '%s' as ModeCFG domain",
							st->st_connection->modecfg_domain);
						if (!out_raw(st->st_connection->modecfg_domain,
					   	     	     strlen(st->st_connection->modecfg_domain),
						     	     &attrval, "ModeCFG_domain")) {
							return STF_INTERNAL_ERROR;
						}
					} else {
						DBG_log("We are not sending a ModeCFG domain");
					}

				}

				case MODECFG_BANNER:
				{
					if(st->st_connection->modecfg_banner) {
						DBG_log("We are sending '%s' as ModeCFG banner",
							st->st_connection->modecfg_banner);
						if (!out_raw(st->st_connection->modecfg_banner,
					   	     	     strlen(st->st_connection->modecfg_banner),
						     	     &attrval, "ModeCFG_banner")) {
							return STF_INTERNAL_ERROR;
						}
					} else {
						DBG_log("We are not sending a ModeCFG banner");
					}

				}

				/* XXX: not sending if our end is 0.0.0.0/0 equals previous  previous behaviour */
				case CISCO_SPLIT_INC:
				{
				/* example payload
				 *  70 04      00 0e      0a 00 00 00 ff 00 00 00 00 00 00 00 00 00 
				 *   \/          \/        \ \  /  /   \ \  / /   \  \  \ /  /  /
				 *  28676        14        10.0.0.0    255.0.0.0  
				 *
				 *  SPLIT_INC  Length       IP addr      mask     proto?,sport?,dport?,proto?,sport?,dport?
				 */

					/* If we don't need split tunneling, just omit the payload */
					if (isanyaddr(&st->st_connection->spd.this.client.addr)) {
						DBG_log("We are 0.0.0.0/0 so not sending CISCO_SPLIT_INC");
						break;
					}
					DBG_log("We are sending our subnet as CISCO_SPLIT_INC");
					unsigned char si[14];	/* 14 is magic */
					memset(si, 0, sizeof(si));
					memcpy(si, &st->st_connection->spd.this.client.addr.u.v4.sin_addr.s_addr, 4);
					struct in_addr splitmask = bitstomask(st->st_connection->spd.this.client.maskbits);
					memcpy(si + 4, &splitmask, 4);
					if (!out_raw(si, sizeof(si), &attrval, "CISCO_SPLIT_INC"))
						return STF_INTERNAL_ERROR;
					break;
				}
				default:
					libreswan_log(
						"attempt to send unsupported mode cfg attribute %s.",
						enum_show(&modecfg_attr_names,
							  attr_type));
					break;
				}
				close_output_pbs(&attrval);

			}
			if (!dont_advance) {
				attr_type++;
				resp >>= 1;
			}
		}

		close_message(&strattr, st);
	}

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody->cur, st);

	close_message(rbody, st);

	encrypt_message(rbody, st);

	return STF_OK;
}

/** Set MODE_CONFIG data to client.  Pack IP Addresses, DNS, etc... and ship
 *
 * @param st State Structure
 * @return stf_status
 */
static stf_status modecfg_send_set(struct state *st)
{
	pb_stream reply, rbody;
	unsigned char buf[256];

	/* set up reply */
	init_pbs(&reply, buf, sizeof(buf), "ModecfgR1");

	change_state(st, STATE_MODE_CFG_R1);
	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);     /* default to 0 */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
		hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_msgid = st->st_msgid_phase15;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

#ifdef SOFTREMOTE_CLIENT_WORKAROUND
	/* see: http://popoludnica.pl/?id=10100110 */
	/* should become a conn option */
	/* client-side is not yet implemented for this - only works with SoftRemote clients */
	/* SoftRemote takes the IV for XAUTH from phase2, where Libreswan takes it from phase1 */
	init_phase2_iv(st, &st->st_msgid_phase15);
#endif

/* XXX This does not include IPv6 at this point */
#define MODECFG_SET_ITEM ( LELEM(INTERNAL_IP4_ADDRESS) | \
			   LELEM(INTERNAL_IP4_SUBNET) | \
			   LELEM(INTERNAL_IP4_DNS))

	modecfg_resp(st,
		     MODECFG_SET_ITEM,
		     &rbody,
		     ISAKMP_CFG_SET,
		     TRUE,
		     0 /* XXX ID */);
#undef MODECFG_SET_ITEM

	clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply),
		     "ModeCfg set");

	/* Transmit */
	send_ike_msg(st, "ModeCfg set");

	/* RETRANSMIT if Main, SA_REPLACE if Aggressive */
	if (st->st_event->ev_type != EVENT_RETRANSMIT &&
	    st->st_event->ev_type != EVENT_NULL) {
		delete_event(st);
		event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);
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
	if (st->st_msgid_phase15 == 0) {
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
	unsigned char buf[256];
	u_char *r_hash_start, *r_hashval;

	/* set up reply */
	init_pbs(&reply, buf, sizeof(buf), "xauth_buf");

	libreswan_log("XAUTH: Sending Username/Password request (XAUTH_R0)");

	/* this is the beginning of a new exchange */
	st->st_msgid_phase15 = generate_msgid(st);
	change_state(st, STATE_XAUTH_R0);

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr); /* default to 0 */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
		hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_msgid = st->st_msgid_phase15;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

	START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_MCFG_ATTR);

	/* ATTR out */
	{
		struct  isakmp_mode_attr attrh;
		struct isakmp_attribute attr;
		pb_stream strattr;

		attrh.isama_np = ISAKMP_NEXT_NONE;
		attrh.isama_type = ISAKMP_CFG_REQUEST;
		attrh.isama_identifier = 0;
		if (!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr))
			return STF_INTERNAL_ERROR;

		/* ISAKMP attr out (name) */
		attr.isaat_af_type = XAUTH_USER_NAME;
		attr.isaat_lv = 0;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				NULL))
			return STF_INTERNAL_ERROR;

		/* ISAKMP attr out (password) */
		attr.isaat_af_type = XAUTH_USER_PASSWORD;
		attr.isaat_lv = 0;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				NULL))
			return STF_INTERNAL_ERROR;

		close_message(&strattr, st);
	}

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody.cur, st);

	close_message(&rbody, st);
	close_output_pbs(&reply);

	init_phase2_iv(st, &st->st_msgid_phase15);
	encrypt_message(&rbody, st);

	clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply),
		     "XAUTH: req");

	/* Transmit */

	send_ike_msg(st, "XAUTH: req");

	/* RETRANSMIT if Main, SA_REPLACE if Aggressive */
	if (st->st_event->ev_type != EVENT_RETRANSMIT) {
		delete_event(st);
		event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0 * 3,
			       st);
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
	unsigned char buf[256];
	u_char *r_hash_start, *r_hashval;

	/* set up reply */
	init_pbs(&reply, buf, sizeof(buf), "xauth_buf");

	libreswan_log("modecfg: Sending IP request (MODECFG_I1)");

	/* this is the beginning of a new exchange */
	st->st_msgid_phase15 = generate_msgid(st);
	change_state(st, STATE_MODE_CFG_I1);

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr); /* default to 0 */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
		hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_msgid = st->st_msgid_phase15;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

	START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_MCFG_ATTR);

	/* ATTR out */
	{
		struct  isakmp_mode_attr attrh;
		struct isakmp_attribute attr;
		pb_stream strattr;

		attrh.isama_np = ISAKMP_NEXT_NONE;
		attrh.isama_type = ISAKMP_CFG_REQUEST;
		attrh.isama_identifier = 0;
		if (!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr))
			return STF_INTERNAL_ERROR;

		/* ISAKMP attr out (ipv4) */
		attr.isaat_af_type = INTERNAL_IP4_ADDRESS;
		attr.isaat_lv = 0;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				NULL))
			return STF_INTERNAL_ERROR;

		/* ISAKMP attr out (netmask) */
		attr.isaat_af_type = INTERNAL_IP4_NETMASK;
		attr.isaat_lv = 0;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				NULL))
			return STF_INTERNAL_ERROR;

		/* ISAKMP attr out (INTERNAL_IP4_DNS) */
		attr.isaat_af_type = INTERNAL_IP4_DNS;
		attr.isaat_lv = 0;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc,
				&strattr, NULL))
			return STF_INTERNAL_ERROR;

		/* ISAKMP attr out (MODECFG_BANNER) */
		attr.isaat_af_type = MODECFG_BANNER;
		attr.isaat_lv = 0;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc,
				&strattr, NULL))
			return STF_INTERNAL_ERROR;

		/* ISAKMP attr out (MODECFG_DOMAIN) */
		attr.isaat_af_type = MODECFG_DOMAIN;
		attr.isaat_lv = 0;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc,
				&strattr, NULL))
			return STF_INTERNAL_ERROR;

		/* ISAKMP attr out (CISCO_SPLIT_INC) */
		attr.isaat_af_type = CISCO_SPLIT_INC;
		attr.isaat_lv = 0;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc,
				&strattr, NULL))
			return STF_INTERNAL_ERROR;

		close_message(&strattr, st);
	}

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody.cur, st);

	close_message(&rbody, st);
	close_output_pbs(&reply);

	init_phase2_iv(st, &st->st_msgid_phase15);
	encrypt_message(&rbody, st);

	clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply),
		     "modecfg: req");

	/* Transmit */

	send_ike_msg(st, "modecfg: req");

	/* RETRANSMIT if Main, SA_REPLACE if Aggressive */
	if (st->st_event->ev_type != EVENT_RETRANSMIT) {
		delete_event(st);
		event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0 * 3,
			       st);
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
static stf_status xauth_send_status(struct state *st, int status)
{
	pb_stream reply;
	pb_stream rbody;
	unsigned char buf[256];
	u_char *r_hash_start, *r_hashval;

	/* set up reply */
	init_pbs(&reply, buf, sizeof(buf), "xauth_buf");

	/* pick a new message id */
	st->st_msgid_phase15 = generate_msgid(st);

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr); /* default to 0 */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
		hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_msgid = st->st_msgid_phase15;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

	START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_MCFG_ATTR);

	/* ATTR out */
	{
		struct  isakmp_mode_attr attrh;
		struct isakmp_attribute attr;
		pb_stream strattr;

		attrh.isama_np = ISAKMP_NEXT_NONE;
		attrh.isama_type = ISAKMP_CFG_SET;
		attrh.isama_identifier = 0;
		if (!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr))
			return STF_INTERNAL_ERROR;

		/* ISAKMP attr out (status) */
		attr.isaat_af_type = XAUTH_STATUS | ISAKMP_ATTR_AF_TV;
		attr.isaat_lv = status;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				NULL))
			return STF_INTERNAL_ERROR;
		close_message(&strattr, st);
	}

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody.cur, st);

	close_message(&rbody, st);
	close_output_pbs(&reply);

	init_phase2_iv(st, &st->st_msgid_phase15);
	encrypt_message(&rbody, st);

	/* free previous transmit packet */
	freeanychunk(st->st_tpacket);

	clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply),
		     "XAUTH: status");

	/* Set up a retransmission event, half a minute henceforth */
	/* Schedule retransmit before sending, to avoid race with master thread */
	delete_event(st);
	event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

	/* Transmit */

	send_ike_msg(st, "XAUTH: status");

	if (status)
		change_state(st, STATE_XAUTH_R1);

	return STF_OK;
}

#ifdef XAUTH_HAVE_PAM
/** XAUTH PAM conversation
 *
 * @param num_msg Int.
 * @param msgm Pam Message Struct
 * @param response Where PAM will put the results
 * @param appdata_ptr Pointer to data struct (as we are using threads)
 * @return int Return Code
 */
static int xauth_pam_conv(int num_msg, const struct pam_message **msgm,
		   struct pam_response **response, void *appdata_ptr)
{
	struct thread_arg *arg = appdata_ptr;
	int count = 0;
	struct pam_response *reply;

	if (num_msg <= 0)
		return PAM_CONV_ERR;

	reply =
		(struct pam_response *) alloc_bytes(
			num_msg * sizeof(struct pam_response), "pam_response");
	if (reply == NULL)
		return PAM_CONV_ERR;

	for (count = 0; count < num_msg; ++count) {
		char *string = NULL;

		switch (msgm[count]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			string = alloc_bytes(arg->password.len + 1,
					     "pam_echo_off");
			strcpy(string, (const char *)arg->password.ptr);
			break;
		case PAM_PROMPT_ECHO_ON:
			string = alloc_bytes(arg->name.len + 1, "pam_echo_on");
			strcpy(string, (const char *)arg->name.ptr);
			break;
		}

		if (string) { /* must add to reply array */
			/* add string to list of responses */

			reply[count].resp_retcode = 0;
			reply[count].resp = string;
		}
	}

	*response = reply;
	return PAM_SUCCESS;
}

/** Do authentication via PAM (Plugable Authentication Modules)
 *
 * We open a PAM session via pam_start, and try to authenticate the user
 *
 * @return int Return Code
 */
static int do_pam_authentication(void *varg)
{
	struct thread_arg   *arg = varg;
	int retval;
	pam_handle_t *pamh = NULL;
	struct pam_conv conv;

	conv.conv = xauth_pam_conv;
	conv.appdata_ptr = varg;

	retval = pam_start("pluto", (const char *)arg->name.ptr, &conv, &pamh);

	/* Send the remote host address to PAM */
	if (retval == PAM_SUCCESS) {
		DBG(DBG_CONTROL, DBG_log("pam_start SUCCESS"));
		retval =
			pam_set_item(pamh, PAM_RHOST, pluto_ip_str(
					     &arg->st->st_remoteaddr));
	} else {
		DBG(DBG_CONTROL,
		    DBG_log("pam_start failed with '%d'", retval));
	}
	/*  Two factor authentication - Check that the user is valid,
	    and then check if they are permitted access */
	if (retval == PAM_SUCCESS) {
		DBG(DBG_CONTROL, DBG_log("pam_set_item SUCCESS"));
		retval = pam_authenticate(pamh, PAM_SILENT); /* is user really user? */
	} else {
		DBG(DBG_CONTROL,
		    DBG_log("pam_set_item failed with '%d'", retval));
	}
	if (retval == PAM_SUCCESS) {
		DBG(DBG_CONTROL, DBG_log("pam_authenticate SUCCESS"));
		retval = pam_acct_mgmt(pamh, 0); /* permitted access? */
	} else {
		DBG(DBG_CONTROL,
		    DBG_log("pam_authenticate failed with '%d'", retval));
	}

	pam_end(pamh, PAM_SUCCESS);

	if (retval == PAM_SUCCESS) {
		libreswan_log("XAUTH: PAM_SUCCESS");
		return TRUE;
	} else {
		libreswan_log("XAUTH: PAM auth chain failed with '%d'",
			      retval);
		return FALSE;
	}

}
#endif /* XAUTH_HAVE_PAM */

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
 * htpasswd -c -m -b /etc/ipsec.d/passwd road roadpass (for crypt)
 * htpasswd -c -d -b /etc/ipsec.d/passwd road roadpass (for des)
 *                   (des is the old format used in /etc/passwd)
 * you can optionally add ":<connection name>\n" to the file.
 *
 * @return int Return Code
 */
static int do_file_authentication(void *varg)
{
	struct thread_arg   *arg = varg;
	char szline[1024]; /* more than enough */
	FILE *fp;
	char *szuser;
	char *szpass;
	char *szconnid;
	char *sztemp;
	int loc = 0;
	const struct lsw_conf_options *oco = lsw_init_options();

	snprintf(pwdfile, sizeof(pwdfile), "%s/passwd", oco->confddir);

	fp = fopen(pwdfile, "r");
	if ( fp == (FILE *)0) {
		/* unable to open the password file */
		libreswan_log(
			"XAUTH: unable to open password file (%s) for verification",
			pwdfile);
		return FALSE;
	}

	libreswan_log("XAUTH: password file (%s) open.", pwdfile);
	/** simple stuff read in a line then go through positioning
	 * szuser ,szpass and szconnid at the begining of each of the
	 * memory locations of our real data and replace the ':' with '\0'
	 */

	while (fgets(szline, sizeof(szline), fp) != NULL) {
		loc = 0;                /* reset our index */
		if (szline[0] == '#')   /* comment line move on */
			continue;

		/* get userid */
		sztemp = strchr(szline, ':');
		if (sztemp == (char *)0 )
			continue;               /* we found no tokens bad line so just skip it */

		*sztemp++ = '\0';               /* put a null where the ':' was */
		szuser = &szline[loc];          /* szline now contains our null terminated data */
		loc += strlen(szuser) + 1;      /* move past null into next section */

		/* get password */
		sztemp = strchr(&szline[loc], ':');
		if (sztemp == (char *)0 )
			continue;               /* we found no tokens bad line so just skip it */

		*sztemp++ = '\0';               /* put a null where the ':' was */
		szpass = &szline[loc];          /* szline now contains our null terminated data */
		loc += strlen(szpass) + 1;      /* move past null into next section */

		/* get connection id */
		sztemp = strchr(&szline[loc], '\n');    /* last \n */
		if (sztemp == (char *)0 )
			continue;                       /* we found no tokens bad line so just skip it */

		*sztemp++ = '\0';                       /* put a null where the ':' was */
		szconnid = &szline[loc];                /* szline now contains our null terminated data */

		/* it is possible that szconnid will be null so don't bother
		 * checking it. If it is null then this is to say it applies
		 * to all connection classes
		 */
		DBG(DBG_CONTROL,
		    DBG_log("XAUTH: found user(%s/%s) pass(%s) connid(%s/%s)",
			    szuser, arg->name.ptr,
			    szpass, szconnid, arg->connname.ptr));

		if ( streq(szconnid, (char *)arg->connname.ptr) &&
		     streq( szuser, (char *)arg->name.ptr ) ) { /* user correct ?*/
			char *cp;

			pthread_mutex_lock(&crypt_mutex);
#if defined(__CYGWIN32__)
			/* password is in the clear! */
			cp = (char *)arg->password.ptr;
#else
			/* keep the passwords using whatever utilities we have */
			cp = crypt( (char *)arg->password.ptr, szpass);
#endif

			if (DBGP(DBG_CRYPT)) {
				DBG_log(
					"XAUTH: checking user(%s:%s) pass %s vs %s", szuser, szconnid, cp,
					szpass);
			} else {
				libreswan_log("XAUTH: checking user(%s:%s) ",
					      szuser, szconnid);
			}

			/* Ok then now password check - note crypt() can return NULL */
			if ( cp && streq(cp, szpass ) ) {
				/* we have a winner */
				fclose( fp );
				pthread_mutex_unlock(&crypt_mutex);
				return TRUE;
			}
			libreswan_log("XAUTH: nope");
		}
	}
	fclose( fp );
	pthread_mutex_unlock(&crypt_mutex);
	return FALSE;
}

/** Main authentication routine will then call the actual compiled-in
 *  method to verify the user/password
 */
static void *do_authentication(void *varg)
{
	struct thread_arg   *arg = varg;
	struct state *st = arg->st;
	int results = FALSE;

	struct sigaction sa;
	struct sigaction oldsa;
	st_jbuf_t *ptr = arg->ptr;

	if (ptr == NULL) {
		freeanychunk(arg->password);
		freeanychunk(arg->name);
		freeanychunk(arg->connname);
		pfree(varg);
		pthread_mutex_unlock(&st->xauth_mutex);
		st->xauth_tid = 0;	/* ??? Not well defined for POSIX threads!!! */
		return NULL;
	}
	/* Note: this is the only sigsetjmp.
	 * The only siglongjmp sets 1 as the return value.
	 */
	pthread_mutex_lock(&st_jbuf_mutex);
	if (sigsetjmp(ptr->jbuf, 1) != 0) {
		/* we got here via siglongjmp in sigIntHandler
		 * st_jbuf_mutex is locked.
		 */

		dealloc_st_jbuf(ptr);

		/* Still one PAM thread? */
		/* ??? how do we know that there is no more than one thread? */
		/* ??? how do we know which thread was supposed to get this SIGINT if the signal handler setting is global? */
		if (st_jbuf_mem != NULL) {
			/* Yes, restart the one shot SIGINT handler */
			sigprocmask(SIG_BLOCK, NULL, &sa.sa_mask);
			sa.sa_handler = sigIntHandler;
			sa.sa_flags = SA_RESETHAND | SA_NODEFER | SA_ONSTACK; /* One shot handler */
			sigaddset(&sa.sa_mask, SIGINT);
			sigaction(SIGINT, &sa, NULL);
		} else {
			/* no */
			sigaction(SIGINT, &oldsa, NULL);
		}
		pthread_mutex_unlock(&st_jbuf_mutex);
		freeanychunk(arg->password);
		freeanychunk(arg->name);
		freeanychunk(arg->connname);
		pfree(varg);
		pthread_mutex_unlock(&st->xauth_mutex);
		st->xauth_tid = 0;	/* ??? not valid for POSIX pthreads */
		return NULL;
	}

	/* original flow (i.e. not due to siglongjmp) */
	pthread_mutex_unlock(&st_jbuf_mutex);
	sigprocmask(SIG_BLOCK, NULL, &sa.sa_mask);
	pthread_sigmask(SIG_BLOCK, &sa.sa_mask, NULL);
	sa.sa_handler = sigIntHandler;
	sa.sa_flags = SA_RESETHAND | SA_NODEFER | SA_ONSTACK; /* One shot handler */
	sigaddset(&sa.sa_mask, SIGINT);
	sigaction(SIGINT, &sa, &oldsa);
	libreswan_log("XAUTH: User %s: Attempting to login", arg->name.ptr);

	switch (st->st_connection->xauthby) {
#ifdef XAUTH_HAVE_PAM
	case XAUTHBY_PAM:
		libreswan_log(
			"XAUTH: pam authentication being called to authenticate user %s",
			arg->name.ptr);
		results = do_pam_authentication(varg);
		break;
#endif
	case XAUTHBY_FILE:
		libreswan_log(
			"XAUTH: passwd file authentication being called to authenticate user %s",
			arg->name.ptr);
		results = do_file_authentication(varg);
		break;
	case XAUTHBY_ALWAYSOK:
		libreswan_log(
			"XAUTH: authentication method 'always ok' requested to authenticate user %s",
			arg->name.ptr);
		results = TRUE;
		break;
	default:
		libreswan_log(
			"XAUTH: unknown authentication method requested to authenticate user %s",
			arg->name.ptr);
		bad_case(st->st_connection->xauthby);
	}

	/*
	 * If XAUTH authentication failed, should we soft fail or hard fail?
	 * The soft fail mode is used to bring up the SA in a walled garden.
	 * This can be detected in the updown script by the env variable XAUTH_FAILED=1
	 */
	if (!results && st->st_connection->xauthfail == XAUTHFAIL_SOFT) {
		libreswan_log(
			"XAUTH: authentication for %s failed, but policy is set to soft fail",
			arg->name.ptr);
		st->st_xauth_soft = TRUE; /* passed to updown for notification */
		results = TRUE;
	}

	if (results) {
		libreswan_log("XAUTH: User %s: Authentication Successful",
			      arg->name.ptr);
		xauth_send_status(st, XAUTH_STATUS_OK);

		if (st->quirks.xauth_ack_msgid)
			st->st_msgid_phase15 = 0;

		/* ??? is this strncpy correct? */
		strncpy(st->st_xauth_username, (char *)arg->name.ptr,
			sizeof(st->st_xauth_username));
	} else {
		/*
		 * Login attempt failed, display error, send XAUTH status to client
		 * and reset state to XAUTH_R0
		 */
		libreswan_log(
			"XAUTH: User %s: Authentication Failed: Incorrect Username or Password",
			arg->name.ptr);
		xauth_send_status(st, XAUTH_STATUS_FAIL);
	}

	pthread_mutex_lock(&st_jbuf_mutex);
	dealloc_st_jbuf(ptr);
	if (st_jbuf_mem == NULL)
		sigaction(SIGINT, &oldsa, NULL);
	pthread_mutex_unlock(&st_jbuf_mutex);
	pthread_mutex_unlock(&st->xauth_mutex);
	st->xauth_tid = 0;	/* ??? this is not valid in POSIX pthreads */

	freeanychunk(arg->password);
	freeanychunk(arg->name);
	freeanychunk(arg->connname);
	pfree(varg);

	return NULL;
}

/** Launch an authentication prompt
 *
 * @param st State Structure
 * @param name Usernamd
 * @param password password
 * @param connname conn name, from ipsec.conf
 * @return int Return Code - always 0.
 */
static int xauth_launch_authent(struct state *st,
			 chunk_t name,
			 chunk_t password,
			 chunk_t connname)
{
	pthread_attr_t pattr;
	st_jbuf_t *ptr;
	struct thread_arg   *arg;

	if (st->xauth_tid)	/* ??? this is not valid in POSIX pthreads */
		return 0;

	arg = alloc_thing(struct thread_arg, "ThreadArg");
	arg->st = st;
	arg->password = password;
	arg->name = name;
	arg->connname = connname;
	/*
	 * Start any kind of authentication in a thread. This includes file
	 * authentication as the /etc/ipsec.d/passwd file may reside on a SAN,
	 * a NAS or an NFS disk
	 */
	ptr = alloc_st_jbuf();
	ptr->st = st;
	arg->ptr = ptr;
	pthread_mutex_init(&st->xauth_mutex, NULL);
	pthread_mutex_lock(&st->xauth_mutex);
	pthread_attr_init(&pattr);
	pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);
	pthread_create(&st->xauth_tid, &pattr, do_authentication, (void*) arg);
	pthread_attr_destroy(&pattr);
	return 0;
}

/* log a nice description of an unsupported attribute */
static void log_bad_attr(const char *kind, enum_names *ed, unsigned val)
{
	libreswan_log("Unsupported %s %s attribute %s received.",
		kind,
		(val & ISAKMP_ATTR_AF_MASK) == ISAKMP_ATTR_AF_TV ? "basic" : "long",
		enum_show(ed, val & ISAKMP_ATTR_RTYPE_MASK));
}

/** STATE_XAUTH_R0:
 *  First REQUEST sent, expect for REPLY
 *  HDR*, HASH, ATTR(REPLY,PASSWORD) --> HDR*, HASH, ATTR(STATUS)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inR0(struct msg_digest *md)
{
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
	struct state *const st = md->st;
	chunk_t name, password, connname;
	bool gotname, gotpassword;

	gotname = gotpassword = FALSE;

	name = empty_chunk;
	password = empty_chunk;
	connname = empty_chunk;

	CHECK_QUICK_HASH(md,
			 xauth_mode_cfg_hash(hash_val, hash_pbs->roof,
					     md->message_pbs.roof,
					     st),
			 "XAUTH-HASH", "XAUTH R0");

	{
		struct isakmp_attribute attr;

		/* XXX This needs checking with the proper RFC's - ISAKMP_CFG_ACK got added for Cisco interop */
		if ( (md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute.isama_type
		      !=
		      ISAKMP_CFG_REPLY) &&
		     (md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute.isama_type
		      !=
		      ISAKMP_CFG_ACK) ) {
			libreswan_log(
				"Expecting MODE_CFG_REPLY, got %s instead.",
				enum_name(&attr_msg_type_names,
					  md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.
					  mode_attribute.isama_type));
			return STF_IGNORE;
		}

		while (pbs_left(attrs) > 0) {
			pb_stream strattr;

			if (!in_struct(&attr, &isakmp_xauth_attribute_desc,
				       attrs, &strattr)) {
				/* Skip malformed */
				return STF_FAIL;
			}

			switch (attr.isaat_af_type) {
			case XAUTH_TYPE | ISAKMP_ATTR_AF_TV:
				/* since we only accept XAUTH_TYPE_GENERIC we don't need to record this attribute */
				if (attr.isaat_lv != XAUTH_TYPE_GENERIC) {
					libreswan_log(
						"unsupported XAUTH_TYPE value %s received",
						enum_show(&xauth_type_names,
							  attr.isaat_lv));
					return NO_PROPOSAL_CHOSEN;
				}
				break;

			case XAUTH_USER_NAME | ISAKMP_ATTR_AF_TLV:
				/* ??? what happens if attribute contains NUL character? */
				clonetochunk(name, strattr.cur,
					     pbs_left(&strattr) + 1, "username");
				name.ptr[name.len - 1] = '\0'; /* Pass NULL terminated strings */
				gotname = TRUE;
				break;

			case XAUTH_USER_PASSWORD | ISAKMP_ATTR_AF_TLV:
				/* ??? what happens if attribute contains NUL character? */
				clonetochunk(password, strattr.cur,
					     pbs_left(&strattr) + 1, "password");
				password.ptr[password.len - 1] = '\0';
				gotpassword = TRUE;
				break;

			default:
				log_bad_attr("XAUTH", &xauth_attr_names, attr.isaat_af_type);
				break;
			}
		}
	}

	/** we must get a username and a password value */
	if (!gotname || !gotpassword) {
		libreswan_log(
			"Expected MODE_CFG_REPLY did not contain %s%s%s attribute",
			(!gotname ? "username" : ""),
			((!gotname && !gotpassword) ? " or " : ""),
			(!gotpassword ? "password" : ""));
		if (st->hidden_variables.st_xauth_client_attempt++ <
		    XAUTH_PROMPT_TRIES) {
			stf_status stat = xauth_send_request(st);

			libreswan_log(
				"XAUTH: User %s: Authentication Failed (retry %d)",
				(!gotname ? "<unknown>" : (char *)name.
				 ptr),
				st->hidden_variables.st_xauth_client_attempt);
			/**
			 * STF_OK means that we transmitted again okay, but actually
			 * the state transition failed, as we are prompting again.
			 */
			if (stat == STF_OK)
				return STF_IGNORE;
			else
				return stat;
		} else {
			stf_status stat = xauth_send_status(st, XAUTH_STATUS_FAIL);

			libreswan_log(
				"XAUTH: User %s: Authentication Failed (Retried %d times)",
				(!gotname ? "<unknown>" : (char *)name.
				 ptr),
				st->hidden_variables.st_xauth_client_attempt);

			if (stat == STF_OK)
				return STF_FAIL;
			else
				return stat;
		}
	} else {
		clonetochunk(connname,
			     st->st_connection->name,
			     strlen(st->st_connection->name) + 1,
			     "connname");

		connname.ptr[connname.len - 1] = 0; /* Pass NULL terminated strings */

		xauth_launch_authent(st, name, password, connname);
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
stf_status xauth_inR1(struct msg_digest *md)
{
	struct state *const st = md->st;

	libreswan_log("XAUTH: xauth_inR1(STF_OK)");
	/* Back to where we were */
	st->st_oakley.xauth = 0;

	if (!st->st_connection->spd.this.modecfg_server) {
		DBG(DBG_CONTROL,
		    DBG_log("Not server, starting new exchange"));
		st->st_msgid_phase15 = 0;
	}

	if (st->st_connection->spd.this.modecfg_server &&
	    st->hidden_variables.st_modecfg_vars_set) {
		DBG(DBG_CONTROL,
		    DBG_log(
			    "modecfg server, vars are set. Starting new exchange."));
		st->st_msgid_phase15 = 0;
	}

	if (st->st_connection->spd.this.modecfg_server &&
	    st->st_connection->policy & POLICY_MODECFG_PULL) {
		DBG(DBG_CONTROL,
		    DBG_log(
			    "modecfg server, pull mode. Starting new exchange."));
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
stf_status modecfg_inR0(struct msg_digest *md)
{
	struct state *const st = md->st;
	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute;
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
	lset_t resp = LEMPTY;

	DBG(DBG_CONTROLMORE, DBG_log("arrived in modecfg_inR0"));

	st->st_msgid_phase15 = md->hdr.isa_msgid;
	CHECK_QUICK_HASH(md,
			 xauth_mode_cfg_hash(hash_val,
					     hash_pbs->roof,
					     md->message_pbs.roof, st),
			 "MODECFG-HASH", "MODE R0");

	switch (ma->isama_type) {
	default:
		libreswan_log(
			"Expecting ISAKMP_CFG_REQUEST, got %s instead (ignored).",
			enum_name(&attr_msg_type_names,
				  ma->isama_type));
		/* ??? what should we do here?  Pretend all is well? */
		break;

	case ISAKMP_CFG_REQUEST:
		while (pbs_left(attrs) > 0) {
			/* ??? this looks kind of fishy:
			 * - what happens if attributes are repeated (resp cannot record that)?
			 * - who actually parses the subattributes to see if they are OK?
			 */
			struct isakmp_attribute attr;
			pb_stream strattr;

			if (!in_struct(&attr,
				       &isakmp_xauth_attribute_desc,
				       attrs,
				       &strattr)) {
				/* reject malformed */
				return STF_FAIL;
			}
			switch (attr.isaat_af_type) {
			case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TLV:
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
				/* ignore */
				break;

			default:
				log_bad_attr("modecfg", &modecfg_attr_names, attr.isaat_af_type);
				break;
			}
		}

		{
			stf_status stat = modecfg_resp(st, resp,
					    &md->rbody,
					    ISAKMP_CFG_REPLY,
					    TRUE,
					    ma->isama_identifier);

			if (stat != STF_OK) {
				/* notification payload - not exactly the right choice, but okay */
				md->note = CERTIFICATE_UNAVAILABLE;
				return stat;
			}
		}

		/* they asked us, we reponded, msgid is done */
		st->st_msgid_phase15 = 0;
	}

	libreswan_log("modecfg_inR0(STF_OK)");
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
static stf_status modecfg_inI2(struct msg_digest *md)
{
	struct state *const st = md->st;
	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute;
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
	u_int16_t isama_id = ma->isama_identifier;
	lset_t resp = LEMPTY;

	DBG(DBG_CONTROL, DBG_log("modecfg_inI2"));

	st->st_msgid_phase15 = md->hdr.isa_msgid;
	CHECK_QUICK_HASH(md,
			 xauth_mode_cfg_hash(hash_val,
					     hash_pbs->roof,
					     md->message_pbs.roof,
					     st),
			 "MODECFG-HASH", "MODE R1");

	/* CHECK that SET has been received. */

	if (ma->isama_type != ISAKMP_CFG_SET) {
		libreswan_log(
			"Expecting MODE_CFG_SET, got %x instead.",
			ma->isama_type);
		return STF_IGNORE;
	}

	while (pbs_left(attrs) > 0) {
		struct isakmp_attribute attr;
		pb_stream strattr;

		if (!in_struct(&attr, &isakmp_xauth_attribute_desc,
			       attrs, &strattr)) {
			/* reject malformed */
			return STF_FAIL;
		}

		switch (attr.isaat_af_type) {
		case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
		{
			struct connection *c = st->st_connection;
			ip_address a;
			char caddr[SUBNETTOT_BUF];

			u_int32_t *ap = (u_int32_t *)(strattr.cur);
			a.u.v4.sin_family = AF_INET;
			memcpy(&a.u.v4.sin_addr.s_addr, ap,
			       sizeof(a.u.v4.sin_addr.s_addr));
			addrtosubnet(&a, &c->spd.this.client);

			/* make sure that the port info is zeroed */
			setportof(0, &c->spd.this.client.addr);

			c->spd.this.has_client = TRUE;
			subnettot(&c->spd.this.client, 0,
				  caddr, sizeof(caddr));
			loglog(RC_LOG_SERIOUS,"Received IP address %s",
				      caddr);

			if (addrbytesptr(&c->spd.this.host_srcip,
					 NULL) == 0 ||
			    isanyaddr(&c->spd.this.host_srcip)) {
				libreswan_log(
					"setting ip source address to %s",
					caddr);
				c->spd.this.host_srcip = a;
			}
		}
			resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
			break;

		case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
		case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
		case INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TLV:
			resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
			break;
		case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
			/* ignore */
			break;
		default:
			log_bad_attr("modecfg", &modecfg_attr_names, attr.isaat_af_type);
			break;
		}
	}
	/* loglog(LOG_DEBUG,"ModeCfg ACK: 0x%" PRIxLSET, resp); */

	/* ack things */
	{
		stf_status stat = modecfg_resp(st, resp,
			    &md->rbody,
			    ISAKMP_CFG_ACK,
			    FALSE,
			    isama_id);

		if (stat != STF_OK) {
			/* notification payload - not exactly the right choice, but okay */
			md->note = CERTIFICATE_UNAVAILABLE;
			return stat;
		}
	}

	/*
	 * we are done with this exchange, clear things so
	 * that we can start phase 2 properly
	 */
	st->st_msgid_phase15 = 0;
	if (resp != LEMPTY)
		st->hidden_variables.st_modecfg_vars_set = TRUE;

	DBG(DBG_CONTROL, DBG_log("modecfg_inI2(STF_OK)"));
	return STF_OK;
}

/* Auxillary function for modecfg_inR1() */
static char *cisco_stringify(pb_stream *pbs, const char *attr_name)
{
	char strbuf[500]; /* Cisco maximum unknown - arbitrary choice */
	size_t len = pbs_left(pbs);

	if (len > sizeof(strbuf) - 1)
		len = sizeof(strbuf) - 1;

	memcpy(strbuf, pbs->cur, len);
	strbuf[len] = '\0';
	/* ' is poison to the way this string will be used
	 * in system() and hence shell.  Remove any.
	 */
	{
		char *s = strbuf;

		for (;; ) {
			s = strchr(s, '\'');
			if (s == NULL)
				break;
			*s = '?';
		}
	}
	(void)sanitize_string(strbuf, sizeof(strbuf));
	libreswan_log("Received Cisco %s: %s", attr_name, strbuf);
	return clone_str(strbuf, attr_name);
}

/** STATE_MODE_CFG_R1:
 *  HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status modecfg_inR1(struct msg_digest *md)
{
	struct state *const st = md->st;
	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute;
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
	lset_t resp = LEMPTY;

	DBG(DBG_CONTROL, DBG_log("modecfg_inR1"));
	libreswan_log("received mode cfg reply");

	st->st_msgid_phase15 = md->hdr.isa_msgid;
	CHECK_QUICK_HASH(md,
			 xauth_mode_cfg_hash(hash_val, hash_pbs->roof,
					     md->message_pbs.roof,
					     st),
			 "MODECFG-HASH", "MODE R1");

	switch (ma->isama_type) {
	default:
	{
		libreswan_log(
			"Expecting ISAKMP_CFG_ACK or ISAKMP_CFG_REPLY, got %x instead.",
			ma->isama_type);
		return STF_IGNORE;
		break;
	}

	case ISAKMP_CFG_ACK:
		/* CHECK that ACK has been received. */
		while (pbs_left(attrs) > 0) {
			struct isakmp_attribute attr;

			if (!in_struct(&attr,
				       &isakmp_xauth_attribute_desc,
				       attrs, NULL)) {
				/* reject malformed */
				return STF_FAIL;
			}

			switch (attr.isaat_af_type) {
			case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TLV:
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;

			case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
				/* ignore */
				break;

			default:
				log_bad_attr("modecfg", &modecfg_attr_names, attr.isaat_af_type);
				break;
			}
		}
		break;

	case ISAKMP_CFG_REPLY:
		while (pbs_left(attrs) > 0) {
			struct isakmp_attribute attr;
			pb_stream strattr;

			if (!in_struct(&attr,
				       &isakmp_xauth_attribute_desc,
				       attrs, &strattr)) {
				/* reject malformed */
				return STF_FAIL;
			}

			switch (attr.isaat_af_type) {

			case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			{
				struct connection *c = st->st_connection;
				ip_address a;
				char caddr[SUBNETTOT_BUF];

				u_int32_t *ap =
					(u_int32_t *)(strattr.cur);
				a.u.v4.sin_family = AF_INET;
				memcpy(&a.u.v4.sin_addr.s_addr, ap,
				       sizeof(a.u.v4.sin_addr.s_addr));
				addrtosubnet(&a, &c->spd.this.client);

				/* make sure that the port info is zeroed */
				setportof(0, &c->spd.this.client.addr);

				c->spd.this.has_client = TRUE;
				subnettot(&c->spd.this.client, 0,
					  caddr, sizeof(caddr));
				loglog(RC_LOG_SERIOUS,
					"Received IPv4 address: %s",
					caddr);

				if (addrbytesptr(&c->spd.this.host_srcip,
						 NULL) == 0 ||
				    isanyaddr(&c->spd.this.host_srcip))
				{
					libreswan_log(
						"setting ip source address to %s",
						caddr);
					c->spd.this.host_srcip = a;
				}
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
			{
				ip_address a;
				char caddr[SUBNETTOT_BUF];

				u_int32_t *ap =
					(u_int32_t *)(strattr.cur);
				a.u.v4.sin_family = AF_INET;
				memcpy(&a.u.v4.sin_addr.s_addr, ap,
				       sizeof(a.u.v4.sin_addr.s_addr));

				addrtot(&a, 0, caddr, sizeof(caddr));
				loglog(RC_LOG_SERIOUS,
					"Received IP4 NETMASK %s",
					caddr);
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			{
				ip_address a;
				char caddr[SUBNETTOT_BUF];

				u_int32_t *ap =
					(u_int32_t *)(strattr.cur);
				a.u.v4.sin_family = AF_INET;
				memcpy(&a.u.v4.sin_addr.s_addr, ap,
				       sizeof(a.u.v4.sin_addr.s_addr));

				addrtot(&a, 0, caddr, sizeof(caddr));
				loglog(RC_LOG_SERIOUS,"Received DNS %s",
					      caddr);

				{
					struct connection *c =
						st->st_connection;
					char *old = c->cisco_dns_info;

					if (old == NULL) {
						c->cisco_dns_info =
							clone_str(
								caddr,
								"cisco_dns_info");
					} else {
						/*
						 * concatenate new IP address string on end of
						 * existing string, separated by ' '.
						 */
						size_t sz_old = strlen(
							old);
						size_t sz_added =
							strlen(caddr) +
							1;
						char *new =
							alloc_bytes(
								sz_old + 1 + sz_added,
								"cisco_dns_info+");

						memcpy(new, old,
						       sz_old);
						*(new + sz_old) = ' ';
						memcpy(
							new + sz_old + 1, caddr,
							sz_added);
						c->cisco_dns_info =
							new;
						pfree(old);
					}
				}

				DBG_log("ModeCFG DNS info: %s, len=%zd",
					st->st_connection->cisco_dns_info,
					strlen(st->st_connection->cisco_dns_info));

				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			case MODECFG_DOMAIN | ISAKMP_ATTR_AF_TLV:
			{
				st->st_connection->modecfg_domain =
					cisco_stringify(&strattr,
							"ModeCFG Domain");
				loglog(RC_LOG_SERIOUS, "Received Domain: %s",
				       st->st_connection->modecfg_domain);
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			case MODECFG_BANNER | ISAKMP_ATTR_AF_TLV:
			{
				st->st_connection->modecfg_banner =
					cisco_stringify(&strattr,
							"ModeCFG Banner");
				loglog(RC_LOG_SERIOUS, "Received Banner: %s",
				       st->st_connection->modecfg_banner);
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
			{
				struct spd_route *tmp_spd;
				ip_address a;
				char caddr[SUBNETTOT_BUF];
				size_t len = pbs_left(&strattr);
				struct connection *c = st->st_connection;
				struct spd_route *tmp_spd2 = &c->spd;

				DBG_log("Received Cisco Split tunnel route(s)");
				if ( FALSE ==
				     tmp_spd2->that.has_client ) {
					ttosubnet("0.0.0.0/0.0.0.0", 0,
						  AF_INET,
						  &tmp_spd2->that.client);
					tmp_spd2->that.has_client =
						TRUE;
					tmp_spd2->that.
					has_client_wildcard =
						FALSE;
				}

				while (len > 0) {
					u_int32_t *ap;
					tmp_spd = clone_thing(c->spd,
							      "remote subnets policies");

					tmp_spd->this.id.name.ptr =
						NULL;
					tmp_spd->this.id.name.len = 0;
					tmp_spd->that.id.name.ptr =
						NULL;
					tmp_spd->that.id.name.len = 0;

					tmp_spd->this.host_addr_name =
						NULL;
					tmp_spd->that.host_addr_name =
						NULL;

					ap =
						(u_int32_t *)(strattr.
							      cur);
					a.u.v4.sin_family = AF_INET;
					memcpy(&a.u.v4.sin_addr.s_addr,
					       ap,
					       sizeof(a.u.v4.sin_addr.
						      s_addr));

					addrtosubnet(&a,
						     &tmp_spd->that.client);

					len -=
						sizeof(a.u.v4.sin_addr.
						       s_addr);
					strattr.cur +=
						sizeof(a.u.v4.sin_addr.
						       s_addr);

					ap =
						(u_int32_t *)(strattr.
							      cur);
					a.u.v4.sin_family = AF_INET;
					memcpy(&a.u.v4.sin_addr.s_addr,
					       ap,
					       sizeof(a.u.v4.sin_addr.
						      s_addr));

					tmp_spd->that.client.maskbits =
						masktocount(&a);
					len -=
						sizeof(a.u.v4.sin_addr.
						       s_addr);
					strattr.cur +=
						sizeof(a.u.v4.sin_addr.
						       s_addr);

					setportof(0,
						  &tmp_spd->that.client.addr);

					len -= 6;
					strattr.cur += 6;

					subnettot(
						&tmp_spd->that.client,
						0,
						caddr,
						sizeof(caddr));

					loglog(RC_LOG_SERIOUS,
						"Received subnet %s, maskbits %d", caddr,
						tmp_spd->that.client.maskbits);

					tmp_spd->this.updown =
						clone_str(
							tmp_spd->this.updown,
							"updown");
					tmp_spd->that.updown =
						clone_str(
							tmp_spd->that.updown,
							"updown");

					tmp_spd->this.cert_filename =
						NULL;
					tmp_spd->that.cert_filename =
						NULL;

					tmp_spd->this.cert.type = 0;
					tmp_spd->that.cert.type = 0;

					tmp_spd->this.ca.ptr = NULL;
					tmp_spd->that.ca.ptr = NULL;

					tmp_spd->this.groups = NULL;
					tmp_spd->that.groups = NULL;

					tmp_spd->this.virt = NULL;
					tmp_spd->that.virt = NULL;

					tmp_spd->next = NULL;
					tmp_spd2->next = tmp_spd;
					tmp_spd2 = tmp_spd;
				}
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP6_NBNS | ISAKMP_ATTR_AF_TLV:
			{
				DBG_log("Received and ignored obsoleted Cisco NetBEUI NS info");
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			default:
			{
				log_bad_attr("modecfg", &modecfg_attr_names, attr.isaat_af_type);
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			}
		}
		break;
	}

	/* we are done with this exchange, clear things so that we can start phase 2 properly */
	st->st_msgid_phase15 = 0;
	if (resp != LEMPTY)
		st->hidden_variables.st_modecfg_vars_set = TRUE;

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
static stf_status xauth_client_resp(struct state *st,
			     lset_t xauth_resp,
			     pb_stream *rbody,
			     u_int16_t ap_id)
{
	unsigned char *r_hash_start, *r_hashval;
	char xauth_username[XAUTH_USERNAME_LEN];
	struct connection *c = st->st_connection;

	/* START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_MCFG_ATTR); */

	{
		pb_stream hash_pbs;
		int np = ISAKMP_NEXT_MCFG_ATTR;

		if (!out_generic(np, &isakmp_hash_desc, rbody, &hash_pbs))
			return STF_INTERNAL_ERROR;

		r_hashval = hash_pbs.cur; /* remember where to plant value */
		if (!out_zero(st->st_oakley.prf_hasher->hash_digest_len,
			      &hash_pbs, "HASH"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&hash_pbs);
		r_hash_start = (rbody)->cur; /* hash from after HASH payload */
	}

	/* MCFG_ATTR out */
	{
		pb_stream strattr;
		int attr_type;

		{
			struct  isakmp_mode_attr attrh;

			attrh.isama_np = ISAKMP_NEXT_NONE;
			attrh.isama_type = ISAKMP_CFG_REPLY;

			attrh.isama_identifier = ap_id;
			if (!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
				return STF_INTERNAL_ERROR;
		}

		attr_type = XAUTH_TYPE;

		while (xauth_resp != LEMPTY) {
			bool dont_advance = FALSE;

			if (xauth_resp & 1) {
				/* ISAKMP attr out */
				bool password_read_from_prompt = FALSE;
				struct isakmp_attribute attr;
				pb_stream attrval;

				switch (attr_type) {
				case XAUTH_TYPE:
					attr.isaat_af_type = attr_type |
							     ISAKMP_ATTR_AF_TV;
					attr.isaat_lv = XAUTH_TYPE_GENERIC;
					if (!out_struct(&attr,
							&isakmp_xauth_attribute_desc,
							&strattr,
							NULL))
						return STF_INTERNAL_ERROR;

					break;

				case XAUTH_USER_NAME:
					attr.isaat_af_type = attr_type |
							     ISAKMP_ATTR_AF_TLV;
					if (!out_struct(&attr,
							&
							isakmp_xauth_attribute_desc,
							&strattr,
							&attrval))
						return STF_INTERNAL_ERROR;

					if (st->st_xauth_username[0] == '\0') {
						if (st->st_whack_sock == -1) {
							loglog(RC_LOG_SERIOUS,
							       "XAUTH username requested, but no file descriptor available for prompt");
							return STF_FAIL;
						}

						if (!whack_prompt_for(st->
								      st_whack_sock,
								      c->name,
								      "Username",
								      TRUE,
								      xauth_username,
								      sizeof(
									      xauth_username)))
						{
							loglog(RC_LOG_SERIOUS,
							       "XAUTH username prompt failed.");
							return STF_FAIL;
						}
						/* replace the first newline character with a string-terminating \0. */
						{
							char* cptr = memchr(
								xauth_username,
								'\n',
								sizeof(
									xauth_username));
							if (cptr)
								*cptr = '\0';
						}
						/* ??? is this strncpy correct? */
						strncpy(st->st_xauth_username,
							xauth_username,
							sizeof(st->
							       st_xauth_username));
					}

					if (!out_raw(st->st_xauth_username,
						     strlen(st->
							    st_xauth_username),
						     &attrval,
						     "XAUTH username"))
						return STF_INTERNAL_ERROR;

					close_output_pbs(&attrval);

					break;

				case XAUTH_USER_PASSWORD:
					attr.isaat_af_type = attr_type |
							     ISAKMP_ATTR_AF_TLV;
					if (!out_struct(&attr,
							&
							isakmp_xauth_attribute_desc,
							&strattr,
							&attrval))
						return STF_INTERNAL_ERROR;

					if (st->st_xauth_password.ptr ==
					    NULL) {
						struct secret *s;

						s = lsw_get_xauthsecret(
							st->st_connection,
							st->st_xauth_username);
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "looked up username=%s, got=%p",
							    st->
							    st_xauth_username,
							    s));
						if (s) {
							struct
							private_key_stuff *pks
								=
									lsw_get_pks(
										s);

							clonetochunk(
								st->st_xauth_password,
								pks->u.preshared_secret.ptr,
								pks->u.preshared_secret.len,
								"savedxauth password");
						}
					}

					if (st->st_xauth_password.ptr ==
					    NULL) {
						char xauth_password[64];

						if (st->st_whack_sock == -1) {
							loglog(RC_LOG_SERIOUS,
							       "XAUTH password requested, but no file descriptor available for prompt");
							return STF_FAIL;
						}

						if (!whack_prompt_for(st->
								      st_whack_sock,
								      c->name,
								      "Password",
								      FALSE,
								      xauth_password,
								      sizeof(
									      xauth_password)))
						{
							loglog(RC_LOG_SERIOUS,
							       "XAUTH password prompt failed.");
							return STF_FAIL;
						}

						/* replace the first newline character with a string-terminating \0. */
						{
							char* cptr = memchr(
								xauth_password,
								'\n',
								sizeof(
									xauth_password));
							if (cptr)
								cptr = '\0';
						}
						clonereplacechunk(
							st->st_xauth_password,
							xauth_password,
							strlen(
								xauth_password),
							"XAUTH password");
						password_read_from_prompt =
							TRUE;
					}

					if (!out_raw(st->st_xauth_password.ptr,
						     st->st_xauth_password.len,
						     &attrval,
						     "XAUTH password"))
						return STF_INTERNAL_ERROR;

					/*
					 * Do not store the password read from the prompt. The password
					 * could have been read from a one-time token device (like SecureID)
					 * or the password could have been entereted wrong,
					 */
					if (password_read_from_prompt) {
						freeanychunk(
							st->st_xauth_password);
						st->st_xauth_password.len = 0;
						password_read_from_prompt =
							FALSE;
					}
					close_output_pbs(&attrval);
					break;

				default:
					libreswan_log(
						"trying to send XAUTH reply, sending %s instead.",
						enum_show(&modecfg_attr_names,
							  attr_type));
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

	libreswan_log("XAUTH: Answering XAUTH challenge with user='%s'",
		      st->st_xauth_username);

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody->cur, st);

	close_message(rbody, st);

	encrypt_message(rbody, st);

	return STF_OK;
}

#define XAUTHLELEM(x) (LELEM((x & ISAKMP_ATTR_RTYPE_MASK)  - XAUTH_TYPE))

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
stf_status xauth_inI0(struct msg_digest *md)
{
	struct state *const st = md->st;
	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute;
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
	lset_t xauth_resp = LEMPTY;
	lset_t mcfg_resp = LEMPTY;	/* ??? value never used */

	int status = 0;
	stf_status stat = STF_FAIL;
	bool gotrequest = FALSE;
	bool gotset = FALSE;
	bool got_status = FALSE;

	if (st->hidden_variables.st_xauth_client_done)
		return modecfg_inI2(md);

	DBG(DBG_CONTROLMORE, DBG_log("arrived in xauth_inI0"));

	st->st_msgid_phase15 = md->hdr.isa_msgid;
	CHECK_QUICK_HASH(md, xauth_mode_cfg_hash(hash_val,
						 hash_pbs->roof,
						 md->message_pbs.roof, st),
			 "MODECFG-HASH", "XAUTH I0");

	switch (ma->isama_type) {
	default:
		libreswan_log(
			"Expecting ISAKMP_CFG_REQUEST or ISAKMP_CFG_SET, got %s instead (ignored).",
			enum_name(&attr_msg_type_names,
				  ma->isama_type));
		/* ??? what are we supposed to do here?  Original code fell through to next case! */
		return STF_FAIL;

	case ISAKMP_CFG_SET:
		gotset = TRUE;
		break;

	case ISAKMP_CFG_REQUEST:
		gotrequest = TRUE;
		break;
	}

	while (pbs_left(attrs) > 0) {
		struct isakmp_attribute attr;
		pb_stream strattr;

		if (!in_struct(&attr, &isakmp_xauth_attribute_desc,
			       attrs, &strattr)) {
			/* reject malformed */
			return STF_FAIL;
		}

		switch (attr.isaat_af_type) {
		case XAUTH_STATUS | ISAKMP_ATTR_AF_TV:
			DBG_log("Received Cisco XAUTH status");
			got_status = TRUE;
			switch (attr.isaat_lv) {
			case XAUTH_STATUS_FAIL:
			case XAUTH_STATUS_OK:
				status = attr.isaat_lv;
				break;
			default:
				/* ??? treat as fail?  Should we abort negotiation? */
				libreswan_log("invalid XAUTH_STATUS value %u", attr.isaat_lv);
				status = XAUTH_STATUS_FAIL;
				break;
			}
			break;

		case XAUTH_MESSAGE | ISAKMP_ATTR_AF_TLV:
		{
			/* ??? should the message be sanitized before logging? */
			/* XXX check RFC for max length? */
			size_t len = attr.isaat_lv;
			char msgbuf[81];

			DBG_log("Received Cisco XAUTH message");
			if (len >= sizeof(msgbuf) )
				len = sizeof(msgbuf) - 1;
			memcpy(msgbuf, strattr.cur, len);
			msgbuf[len] = '\0';
			loglog(RC_LOG_SERIOUS,
			       "XAUTH Message: %s", msgbuf);
			break;
		}

		case XAUTH_TYPE | ISAKMP_ATTR_AF_TV:
			if (attr.isaat_lv != XAUTH_TYPE_GENERIC) {
				libreswan_log(
					"XAUTH: Unsupported type: %d",
					attr.isaat_lv);
				return STF_IGNORE;
			}
			DBG_log("Received Cisco XAUTH type: Generic");
			xauth_resp |= XAUTHLELEM(attr.isaat_af_type);
			break;

		case XAUTH_USER_NAME | ISAKMP_ATTR_AF_TLV:
			DBG_log("Received Cisco XAUTH username");
			xauth_resp |= XAUTHLELEM(attr.isaat_af_type);
			break;

		case XAUTH_USER_PASSWORD | ISAKMP_ATTR_AF_TLV:
			DBG_log("Received Cisco XAUTH password");
			xauth_resp |= XAUTHLELEM(attr.isaat_af_type);
			break;

		case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			DBG_log("Received Cisco Internal IPv4 address");
			mcfg_resp |= LELEM(attr.isaat_af_type);
			break;

		case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
			DBG_log("Received Cisco Internal IPv4 netmask");
			mcfg_resp |= LELEM(attr.isaat_af_type);
			break;

		case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			DBG_log("Received Cisco IPv4 DNS info");
			mcfg_resp |= LELEM(attr.isaat_af_type);
			break;

		case INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TV:
			DBG_log("Received Cisco IPv4 Subnet info");
			mcfg_resp |= LELEM(attr.isaat_af_type);
			break;

		case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TV:
			DBG_log("Received Cisco NetBEUI NS info");
			mcfg_resp |= LELEM(attr.isaat_af_type);
			break;

		default:
			log_bad_attr("XAUTH", &modecfg_attr_names, attr.isaat_af_type);
			break;
		}
	}

	if (gotset && got_status) {
		/* ACK whatever it was that we got */
		stat = xauth_client_ackstatus(st, &md->rbody,
					      md->chain[
						      ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute.isama_identifier);

		/* must have gotten a status */
		if (status && stat == STF_OK) {
			st->hidden_variables.st_xauth_client_done =
				TRUE;
			libreswan_log(
				"XAUTH: Successfully Authenticated");
			st->st_oakley.xauth = 0;

			return STF_OK;
		} else {
			return STF_FATAL;
		}
	}

	if (gotrequest) {
		DBG(DBG_CONTROL, {
			if (xauth_resp &
			    (XAUTHLELEM(XAUTH_USER_NAME) |
			     XAUTHLELEM(XAUTH_USER_PASSWORD)))
				DBG_log("XAUTH: Username or password request received");
		});

		/* sanitize what we were asked to reply to */
		if (LDISJOINT(xauth_resp, XAUTHLELEM(XAUTH_USER_NAME) |
				    XAUTHLELEM(XAUTH_USER_PASSWORD)))
		{
			if (st->st_connection->spd.this.xauth_client) {
				libreswan_log(
					"XAUTH: No username or password request was received.");
				return STF_IGNORE;
			}			    
		} else {
			if (!st->st_connection->spd.this.xauth_client) {
				libreswan_log(
					"XAUTH: Username or password request was received, but XAUTH client mode not enabled.");
				return STF_IGNORE;
			}
		}

		stat = xauth_client_resp(st, xauth_resp,
					 &md->rbody,
					 md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute.isama_identifier);
	}

	if (stat != STF_OK) {
		/* notification payload - not exactly the right choice, but okay */
		md->note = CERTIFICATE_UNAVAILABLE;
		return stat;
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
static stf_status xauth_client_ackstatus(struct state *st,
				  pb_stream *rbody,
				  u_int16_t ap_id)
{
	unsigned char *r_hash_start, *r_hashval;

	/* START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_MCFG_ATTR); */

	{
		pb_stream hash_pbs;
		int np = ISAKMP_NEXT_MCFG_ATTR;

		if (!out_generic(np, &isakmp_hash_desc, rbody, &hash_pbs))
			return STF_INTERNAL_ERROR;

		r_hashval = hash_pbs.cur; /* remember where to plant value */
		if (!out_zero(st->st_oakley.prf_hasher->hash_digest_len,
			      &hash_pbs, "HASH"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&hash_pbs);
		r_hash_start = (rbody)->cur; /* hash from after HASH payload */
	}

	/* ATTR out */
	{
		struct  isakmp_mode_attr attrh;
		struct isakmp_attribute attr;
		pb_stream strattr, attrval;

		attrh.isama_np = ISAKMP_NEXT_NONE;
		attrh.isama_type = ISAKMP_CFG_ACK;

		attrh.isama_identifier = ap_id;
		if (!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
			return STF_INTERNAL_ERROR;

		/* ISAKMP attr out */
		attr.isaat_af_type = XAUTH_STATUS | ISAKMP_ATTR_AF_TV;
		attr.isaat_lv = XAUTH_STATUS_OK;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				&attrval))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&attrval);
		close_message(&strattr, st);
	}

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody->cur, st);

	close_message(rbody, st);

	encrypt_message(rbody, st);

	return STF_OK;
}

/** STATE_XAUTH_I1
 *  HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inI1(struct msg_digest *md)
{
	struct state *const st = md->st;
	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute;
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
	bool got_status = FALSE;
	unsigned int status = XAUTH_STATUS_FAIL;
	stf_status stat;
	lset_t xauth_resp = LEMPTY;	/* ??? value never used */

	if (st->hidden_variables.st_xauth_client_done)
		return modecfg_inI2(md);

	DBG(DBG_CONTROLMORE, DBG_log("xauth_inI1"));

	st->st_msgid_phase15 = md->hdr.isa_msgid;
	CHECK_QUICK_HASH(md,
			 xauth_mode_cfg_hash(hash_val,
					     hash_pbs->roof,
					     md->message_pbs.roof, st),
			 "MODECFG-HASH", "XAUTH I1");

	switch (ma->isama_type) {
	default:
		libreswan_log(
			"Expecting MODE_CFG_SET, got %x instead.",
			ma->isama_type);
		return STF_IGNORE;

	case ISAKMP_CFG_SET:
		/* CHECK that SET has been received. */
		while (pbs_left(attrs) > 0) {
			struct isakmp_attribute attr;
			pb_stream strattr;

			if (!in_struct(&attr,
				       &isakmp_xauth_attribute_desc,
				       attrs, &strattr)) {
				/* reject malformed */
				return STF_FAIL;
			}

			switch (attr.isaat_af_type) {
			case XAUTH_STATUS | ISAKMP_ATTR_AF_TV:
				xauth_resp |= XAUTHLELEM(XAUTH_STATUS);
				got_status = TRUE;
				switch (attr.isaat_lv) {
				case XAUTH_STATUS_FAIL:
				case XAUTH_STATUS_OK:
					status = attr.isaat_lv;
					break;
				default:
					/* ??? treat as fail?  Should we abort negotiation? */
					libreswan_log("invalid XAUTH_STATUS value %u", attr.isaat_lv);
					status = XAUTH_STATUS_FAIL;
					break;
				}
				break;

			default:
				libreswan_log(
					"while waiting for XAUTH_STATUS, got %s %s instead.",
					(attr.isaat_af_type & ISAKMP_ATTR_AF_MASK) == ISAKMP_ATTR_AF_TV ? "basic" : "long",
					enum_show(&modecfg_attr_names,
						  attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK));
				break;
			}
		}
		break;
	}

	/* first check if we might be done! */
	if (!got_status || status == XAUTH_STATUS_FAIL) {
		/* oops, something seriously wrong */
		libreswan_log(
			"did not get status attribute in xauth_inI1, looking for new challenge.");
		change_state(st, STATE_XAUTH_I0);
		return xauth_inI0(md);
	}

	/* ACK whatever it was that we got */
	stat = xauth_client_ackstatus(st, &md->rbody,
				      md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute.isama_identifier);

	/* must have gotten a status */
	if (status && stat == STF_OK) {
		st->hidden_variables.st_xauth_client_done = TRUE;
		libreswan_log("successfully logged in");
		st->st_oakley.xauth = 0;

		return STF_OK;
	}

	/* what? */
	return stat;
}
