/* XAUTH related functions
 *
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003 Sean Mathews - Nu Tech Software Solutions, inc.
 * Copyright (C) 2003-2004 Xelerance Corporation
 * Copyright (C) 2009 Ken Wilson <Ken_Wilson@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2013 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
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

#include <pthread.h>	/* Must be the first include file */

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

#include "lswalloc.h"

#include "sysdep.h"
#include "lswconf.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "state.h"
#include "ikev1_msgid.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"	/* needs id.h */
#include "packet.h"
#include "demux.h"		/* needs packet.h */
#include "log.h"
#include "timer.h"
#include "keys.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "secrets.h"

#include "ikev1_xauth.h"
#include "virtual.h"	/* needs connections.h */
#include "addresspool.h"
#include "pam_conv.h"

/* forward declarations */
static stf_status xauth_client_ackstatus(struct state *st,
					 pb_stream *rbody,
					 u_int16_t ap_id);

/* BEWARE: This code is multi-threaded.
 *
 * Any static object is likely shared and probably has to be protected by
 * a lock.
 * Any other shared object needs to be protected.
 * Beware of calling functions that are not thread-safe.
 *
 * Static or shared objects:
 * - locks (duh)
 * - st_jbuf_mem and the structure it points to
 * - ??? field pamh in struct connection.
 *
 * Non-thread-safe functions:
 * - crypt(3) used by do_file_authentication()
 * - ??? pam_*?
 */

typedef struct {
	bool in_use;
	struct state *st;
	sigjmp_buf jbuf;
} st_jbuf_t;

struct xauth_thread_arg {
	struct state *st;
	/* the memory for these is allocated and freed by our thread management */
	char *name;
	char *password;
	char *connname;
	char *ipaddr;
	st_jbuf_t *ptr;
};

/*
 * pointer to an array of st_jbuf_t elements.
 * The last element has .st==NULL (and !.in_use).
 * Unused ones (not the last) have some meaningless non-NULL value in .st.  Yuck!
 * All manipulations must be protected via st_jbuf_mutex.
 * If no entries are in use, the array must be freed:
 * two tests in do_authentication depend on this.
 * Note: managed by calloc/realloc/free
 */
static st_jbuf_t *st_jbuf_mem = NULL;

static pthread_mutex_t st_jbuf_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Note: caller must have locked st_jbuf_mutex */
/* IN AN AUTH THREAD */
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
	free(st_jbuf_mem);	/* was calloc()ed or realloc()ed */
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

/*
 * Find or create a free slot in the st_jbuf_mem array.
 * Note: after return, caller MUST set the .st field of the result to a
 * non-NULL value or bad things happen. The only caller does this.
 * The caller must not have locked st_jbuf_mutex: we will.
 */
static st_jbuf_t *alloc_st_jbuf(void)
{
	st_jbuf_t *ptr;

	pthread_mutex_lock(&st_jbuf_mutex);
	if (st_jbuf_mem == NULL) {
		/* no array: allocate one slot plus endmarker */
		st_jbuf_mem = calloc(2, sizeof(st_jbuf_t));
		if (st_jbuf_mem == NULL)
			lsw_abort();

		/*
		 * Initialize end marker.
		 * calloc(3) does not guarantee that pointer .st is
		 * initialized to NULL but it will set .in_use to FALSE.
		 */
		st_jbuf_mem[1].st = NULL;

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
				/* ??? why are we using reealloc instead of Pluto's functions? */
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
	/* ??? In POSIX pthreads, pthread_t is opaque and the following test is not legitimate */
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

	/* Not implemented */
	case XAUTHInitRSARevisedEncryption:
	case XAUTHRespRSARevisedEncryption:
		baseauth = OAKLEY_RSA_REVISED_MODE;
		break;
	}

	return baseauth;
}

/*
 * Get an inside IP address, INTERNAL_IP4_ADDRESS and DNS if any for a connection
 *
 * @param con A currently active connection struct
 * @param ia internal_addr struct
 */
static bool get_internal_addresses(struct state *st, struct internal_addr *ia,
		bool *got_lease)
{
	struct connection *c = st->st_connection;

	*got_lease = FALSE;
	/** assumes IPv4, and also that the mask is ignored */

	if (c->pool != NULL) {
		err_t e = lease_an_address(c, &ia->ipaddr);

		if (e != NULL) {
			libreswan_log("lease_an_address failure %s", e);
			return FALSE;
		}
		*got_lease = TRUE;
	} else {
		passert(!isanyaddr(&c->spd.that.client.addr));
		ia->ipaddr = c->spd.that.client.addr;
	}

	if (!isanyaddr(&c->modecfg_dns1))
		ia->dns[0] = c->modecfg_dns1;
	if (!isanyaddr(&c->modecfg_dns2))
		ia->dns[1] = c->modecfg_dns2;

	return TRUE;
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

	hmac_init(&ctx, st->st_oakley.prf_hasher, st->st_skeyid_a_nss);
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
 * Add ISAKMP attribute
 *
 * Add a given Mode Config attribute to the reply stream.
 *
 * @param pb_stream strattr the reply stream (stream)
 * @param attr_type int the attribute type
 * @param ia internal_addr the IP information for the connection
 * @param st State structure
 * @return stf_status STF_OK or STF_INTERNAL_ERROR
 */
static stf_status isakmp_add_attr (pb_stream *strattr,
				   const int attr_type,
				   const struct internal_addr *ia,
				   const struct state *st)
{
	pb_stream attrval;
	unsigned char *byte_ptr;
	unsigned int len;
	bool dont_advance;
	int dns_idx = 0;

	do {
		dont_advance = FALSE;

		/* ISAKMP attr out */
		{
			struct isakmp_attribute attr;

			attr.isaat_af_type = attr_type |
					     ISAKMP_ATTR_AF_TLV;
			if (!out_struct(&attr,
					&isakmp_xauth_attribute_desc,
					strattr,
					&attrval))
				return STF_INTERNAL_ERROR;
		}

		switch (attr_type) {
		case INTERNAL_IP4_ADDRESS:
			len = addrbytesptr(&ia->ipaddr,
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
			/* FALL THROUGH */
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
			len = addrbytesptr(&ia->dns[dns_idx++],
					   &byte_ptr);
			if (!out_raw(byte_ptr, len, &attrval,
				     "IP4_dns"))
				return STF_INTERNAL_ERROR;

			if (dns_idx < 2 &&
			    !isanyaddr(&ia->dns[dns_idx]))
				dont_advance = TRUE;
			break;

		case MODECFG_DOMAIN:
			if (!out_raw(st->st_connection->modecfg_domain,
				     strlen(st->st_connection->modecfg_domain),
				     &attrval, "")) {
				return STF_INTERNAL_ERROR;
			}
			break;

		case MODECFG_BANNER:
			if (!out_raw(st->st_connection->modecfg_banner,
				     strlen(st->st_connection->modecfg_banner),
				     &attrval, "")) {
				return STF_INTERNAL_ERROR;
			}
			break;

		/* XXX: not sending if our end is 0.0.0.0/0 equals previous previous behaviour */
		case CISCO_SPLIT_INC:
		{
		/* example payload
		 *  70 04      00 0e      0a 00 00 00 ff 00 00 00 00 00 00 00 00 00
		 *   \/          \/        \ \  /  /   \ \  / /   \  \  \ /  /  /
		 *  28676        14        10.0.0.0    255.0.0.0
		 *
		 *  SPLIT_INC  Length       IP addr      mask     proto?,sport?,dport?,proto?,sport?,dport?
		 */
			/*
			 * ??? this really should use
			 * packet emitting routines
			 */

			unsigned char si[14];	/* 14 is magic */

			zero(&si);	/* OK: no pointer fields */
			memcpy(si, &st->st_connection->spd.this.client.addr.u.v4.sin_addr.s_addr, 4);	/* 4 is magic */
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
	} while (dont_advance);

	return STF_OK;
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
 *	True means force the IP assigned by Mode Config to be the
 *	spd.that.addr.  Useful when you know the client will change his IP
 *	to be what was assigned immediatly after authentication.
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

		if (!ikev1_out_generic(ISAKMP_NEXT_MCFG_ATTR, &isakmp_hash_desc, rbody, &hash_pbs))
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
		bool has_lease;

		{
			struct isakmp_mode_attr attrh;

			attrh.isama_np = ISAKMP_NEXT_NONE;
			attrh.isama_type = replytype;
			attrh.isama_identifier = ap_id;
			if (!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
				return STF_INTERNAL_ERROR;
		}

		zero(&ia);	/* OK: no pointer fields */
		if (!get_internal_addresses(st, &ia, &has_lease))
			return STF_INTERNAL_ERROR;

		/* If we got DNS addresses, answer with those */
		if (!isanyaddr(&ia.dns[0]))
			resp |= LELEM(INTERNAL_IP4_DNS);
		else
			resp &= ~LELEM(INTERNAL_IP4_DNS);

		if (use_modecfg_addr_as_client_addr) {
			if (!sameaddr(&st->st_connection->spd.that.client.addr,
				&ia.ipaddr)) {
				/* Make the Internal IP address and Netmask as
				 * that client address
				 */
				st->st_connection->spd.that.client.addr =
					ia.ipaddr;
				st->st_connection->spd.that.client.maskbits =
					32;
				st->st_connection->spd.that.has_client = TRUE;
				if (has_lease)
					st->st_connection->spd.that.has_lease = TRUE;
			}
		}

		/* Send the attributes requested by the client. */
		attr_type = 0;
		while (resp != LEMPTY) {
			if (resp & 1) {
				stf_status ret = isakmp_add_attr (&strattr, attr_type, &ia, st);
				if (ret != STF_OK)
					return ret;
			}
			attr_type++;
			resp >>= 1;
		}

		/* Send these even if the client didn't request them. Due
		 * to and unwise use of a bitmask the limited range of lset_t
		 * causes us to loose track of whether the client requested
		 * them. No biggie, the MODECFG draft allows us to send
		 * attributes that the client didn't request and if we set
		 * MODECFG_DOMAIN and MODECFG_BANNER in connection
		 * configuration we probably want the client to see them
		 * anyway. */
		if (st->st_connection->modecfg_domain != NULL) {
			DBG_log("We are sending '%s' as domain",
				st->st_connection->modecfg_domain);
			isakmp_add_attr (&strattr, MODECFG_DOMAIN, &ia, st);
		} else {
			DBG_log("We are not sending a domain");
		}
		if (st->st_connection->modecfg_banner != NULL) {
			DBG_log("We are sending '%s' as banner",
				st->st_connection->modecfg_banner);
			isakmp_add_attr (&strattr, MODECFG_BANNER, &ia, st);
		} else {
			DBG_log("We are not sending a banner");
		}
		if (isanyaddr(&st->st_connection->spd.this.client.addr)) {
			DBG_log("We are 0.0.0.0/0 so not sending CISCO_SPLIT_INC");
		} else {
			DBG_log("We are sending our subnet as CISCO_SPLIT_INC");
			isakmp_add_attr (&strattr, CISCO_SPLIT_INC, &ia, st);
		}

		if (!close_message(&strattr, st))
			return STF_INTERNAL_ERROR;
	}

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody->cur, st);

	if (!close_message(rbody, st) ||
	    !encrypt_message(rbody, st))
		return STF_INTERNAL_ERROR;

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
	init_out_pbs(&reply, buf, sizeof(buf), "ModecfgR1");

	change_state(st, STATE_MODE_CFG_R1);
	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* OK: no pointer fields */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
		hdr.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

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
#define MODECFG_SET_ITEM (LELEM(INTERNAL_IP4_ADDRESS) | \
			  LELEM(INTERNAL_IP4_SUBNET) | \
			  LELEM(INTERNAL_IP4_DNS))

	modecfg_resp(st,
		     MODECFG_SET_ITEM,
		     &rbody,
		     ISAKMP_CFG_SET,
		     TRUE,
		     0 /* XXX ID */);
#undef MODECFG_SET_ITEM

	/* Transmit */
	record_and_send_ike_msg(st, &reply, "ModeCfg set");

	/* RETRANSMIT if Main, SA_REPLACE if Aggressive */
	if (st->st_event->ev_type != EVENT_v1_RETRANSMIT &&
	    st->st_event->ev_type != EVENT_NULL) {
		delete_event(st);
		event_schedule_ms(EVENT_v1_RETRANSMIT, st->st_connection->r_interval, st);
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
	if (st->st_msgid_phase15 == v1_MAINMODE_MSGID) {
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
	init_out_pbs(&reply, buf, sizeof(buf), "xauth_buf");

	libreswan_log("XAUTH: Sending Username/Password request (XAUTH_R0)");

	/* this is the beginning of a new exchange */
	st->st_msgid_phase15 = generate_msgid(st);
	change_state(st, STATE_XAUTH_R0);

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* OK: no pointer fields */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
		hdr.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_msgid = st->st_msgid_phase15;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

	START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_MCFG_ATTR);

	/* ATTR out */
	{
		struct isakmp_mode_attr attrh;
		struct isakmp_attribute attr;
		pb_stream strattr;

		attrh.isama_np = ISAKMP_NEXT_NONE;
		attrh.isama_type = ISAKMP_CFG_REQUEST;
		attrh.isama_identifier = 0;
		if (!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr))
			return STF_INTERNAL_ERROR;

		/* Empty name atribute */
		attr.isaat_af_type = XAUTH_USER_NAME;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				NULL))
			return STF_INTERNAL_ERROR;

		/* Empty password attribute */
		attr.isaat_af_type = XAUTH_USER_PASSWORD;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				NULL))
			return STF_INTERNAL_ERROR;

		if (!close_message(&strattr, st))
			return STF_INTERNAL_ERROR;
	}

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody.cur, st);

	if (!close_message(&rbody, st))
			return STF_INTERNAL_ERROR;

	close_output_pbs(&reply);

	init_phase2_iv(st, &st->st_msgid_phase15);

	if (!encrypt_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	/* Transmit */
	record_and_send_ike_msg(st, &reply, "XAUTH: req");

	/* RETRANSMIT if Main, SA_REPLACE if Aggressive */
	if (st->st_event->ev_type != EVENT_v1_RETRANSMIT) {
		delete_event(st);
		event_schedule_ms(EVENT_v1_RETRANSMIT,
				st->st_connection->r_interval, st);
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
	init_out_pbs(&reply, buf, sizeof(buf), "xauth_buf");

	libreswan_log("modecfg: Sending IP request (MODECFG_I1)");

	/* this is the beginning of a new exchange */
	st->st_msgid_phase15 = generate_msgid(st);
	change_state(st, STATE_MODE_CFG_I1);

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* OK: no pointer fields */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
		hdr.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_msgid = st->st_msgid_phase15;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

	START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_MCFG_ATTR);

	/* ATTR out */
	{
		struct isakmp_mode_attr attrh;
		struct isakmp_attribute attr;
		pb_stream strattr;

		attrh.isama_np = ISAKMP_NEXT_NONE;
		attrh.isama_type = ISAKMP_CFG_REQUEST;
		attrh.isama_identifier = 0;
		if (!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr))
			return STF_INTERNAL_ERROR;

		/* Empty IPv4 address */
		attr.isaat_af_type = INTERNAL_IP4_ADDRESS;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				NULL))
			return STF_INTERNAL_ERROR;

		/* Empty IPv4 netmask */
		attr.isaat_af_type = INTERNAL_IP4_NETMASK;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				NULL))
			return STF_INTERNAL_ERROR;

		/* Empty INTERNAL_IP4_DNS */
		attr.isaat_af_type = INTERNAL_IP4_DNS;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc,
				&strattr, NULL))
			return STF_INTERNAL_ERROR;

		/* Empty banner */
		attr.isaat_af_type = MODECFG_BANNER;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc,
				&strattr, NULL))
			return STF_INTERNAL_ERROR;

		/* Empty domain */
		attr.isaat_af_type = MODECFG_DOMAIN;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc,
				&strattr, NULL))
			return STF_INTERNAL_ERROR;

		/* Empty Cisco split */
		attr.isaat_af_type = CISCO_SPLIT_INC;
		if (!out_struct(&attr, &isakmp_xauth_attribute_desc,
				&strattr, NULL))
			return STF_INTERNAL_ERROR;

		if (!close_message(&strattr, st))
			return STF_INTERNAL_ERROR;
	}

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody.cur, st);

	if (!close_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&reply);

	init_phase2_iv(st, &st->st_msgid_phase15);

	if (!encrypt_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	/* Transmit */
	record_and_send_ike_msg(st, &reply, "modecfg: req");

	/* RETRANSMIT if Main, SA_REPLACE if Aggressive */
	if (st->st_event->ev_type != EVENT_v1_RETRANSMIT) {
		delete_event(st);
		event_schedule_ms(EVENT_v1_RETRANSMIT, st->st_connection->r_interval, st);
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
/* IN AN AUTH THREAD */
static stf_status xauth_send_status(struct state *st, int status)
{
	pb_stream reply;
	pb_stream rbody;
	unsigned char buf[256];
	u_char *r_hash_start, *r_hashval;

	/* set up reply */
	init_out_pbs(&reply, buf, sizeof(buf), "xauth_buf");

	/* pick a new message id */
	st->st_msgid_phase15 = generate_msgid(st);

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* OK: no pointer fields */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
		hdr.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_msgid = st->st_msgid_phase15;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

	START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_MCFG_ATTR);

	/* ATTR out */
	{
		struct isakmp_mode_attr attrh;
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
		if (!close_message(&strattr, st))
			return STF_INTERNAL_ERROR;
	}

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody.cur, st);

	if (!close_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&reply);

	init_phase2_iv(st, &st->st_msgid_phase15);

	if (!encrypt_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	/* Set up a retransmission event, half a minute hence */
	/* Schedule retransmit before sending, to avoid race with master thread */
	delete_event(st);
	event_schedule_ms(EVENT_v1_RETRANSMIT, st->st_connection->r_interval, st);

	/* Transmit */
	record_and_send_ike_msg(st, &reply, "XAUTH: status");

	if (status != 0)
		change_state(st, STATE_XAUTH_R1);

	return STF_OK;
}

/** Do authentication via /etc/ipsec.d/passwd file using MD5 passwords
 *
 * Structure is one entry per line.
 * Each line has fields separated by colons.
 * Empty lines and lines starting with # are ignored.
 *
 * There are two forms:
 *	username:passwdhash
 *	username:passwdhash:connectioname
 *
 * The first form (as produced by htpasswd) authorizes any connection.
 * The second is is restricted to the named connection.
 *
 * Example creation of file with two entries (without connectionname):
 *	htpasswd -c -b /etc/ipsec.d/passwd road roadpass
 *	htpasswd -b /etc/ipsec.d/passwd home homepass
 *
 * NOTE: htpasswd on your system may create a crypt() incompatible hash
 * by default (i.e. a type id of $apr1$). To create a crypt() compatible
 * hash with htpasswd use the -d option.
 *
 * @return bool success
 */
/* IN AN AUTH THREAD */
static bool do_file_authentication(void *varg)
{
	struct xauth_thread_arg *arg = varg;
	char pwdfile[PATH_MAX];
	char line[1024]; /* we hope that this is more than enough */
	int lineno = 0;
	FILE *fp;
	bool win = FALSE;

	snprintf(pwdfile, sizeof(pwdfile), "%s/passwd", lsw_init_options()->confddir);

	fp = fopen(pwdfile, "r");
	if (fp == NULL) {
		/* unable to open the password file */
		libreswan_log(
			"XAUTH: unable to open password file (%s) for verification",
			pwdfile);
		return FALSE;
	}

	libreswan_log("XAUTH: password file (%s) open.", pwdfile);

	/** simple stuff read in a line then go through positioning
	 * userid, passwd and conniectionname at the begining of each of the
	 * memory locations of our real data and replace the ':' with '\0'
	 */

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *p;	/* current position */
		char *userid;
		char *passwdhash;
		char *connectionname = NULL;
		char *addresspool = NULL;
		struct connection *c = arg->st->st_connection;
		ip_range *pool_range;

		lineno++;

		/* strip final \n (optional: we accept a partial last line) */
		p = strchr(line, '\n');
		if (p != NULL)
			*p = '\0';

		/* ignore empty or comment line */
		if (*line == '\0' || *line == '#')
			continue;

		/* get userid */
		userid = line;
		p = strchr(userid, ':');	/* find end */
		if (p == NULL) {
			/* no end: skip line */
			libreswan_log("XAUTH: %s:%d missing password hash field", pwdfile, lineno);
			continue;
		}

		*p++ ='\0'; /* terminate string by overwriting : */

		/* get password hash */
		passwdhash = p;
		p = strchr(passwdhash, ':'); /* find end */
		if (p != NULL) {
			/* optional connectionname */
			*p++='\0';     /* terminate string by overwriting : */
			connectionname = p;
			p = strchr(connectionname, ':'); /* find end */
		}

		if (p != NULL) {
			/* optional addresspool */
			*p++ ='\0'; /* terminate connectionname string by overwriting : */
			addresspool = p;
		}
		/* set connectionname to NULL if empty */
		if (connectionname != NULL && strlen(connectionname) == 0)
			connectionname = NULL;
		/* If connectionname is null, it applies
		 * to all connections
		 */
		DBG(DBG_CONTROL,
			DBG_log("XAUTH: found user(%s/%s) pass(%s) connid(%s/%s) addresspool(%s)",
				userid, arg->name,
				passwdhash,
				connectionname == NULL? "" : connectionname, arg->connname,
				addresspool == NULL? "" : addresspool));

		if (streq(userid, arg->name) &&
		    (connectionname == NULL || streq(connectionname, arg->connname)))
		{
			char *cp;

			/* We use crypt_mutex lock because not all systems have crypt_r() */
			static pthread_mutex_t crypt_mutex = PTHREAD_MUTEX_INITIALIZER;

			pthread_mutex_lock(&crypt_mutex);
#if defined(__CYGWIN32__)
			/* password is in the clear! */
			cp = arg->password;
#else
			/* keep the passwords using whatever utilities we have */
			cp = crypt(arg->password, passwdhash);
#endif
			win = cp != NULL && streq(cp, passwdhash);
			pthread_mutex_unlock(&crypt_mutex);

			/* ??? DBG and real-world code mixed */
			if (DBGP(DBG_CRYPT)) {
				DBG_log("XAUTH: checking user(%s:%s) pass %s vs %s", userid, connectionname, cp,
					passwdhash);
			} else {
				libreswan_log("XAUTH: checking user(%s:%s) ",
					      userid, connectionname);
			}

			if (win) {

				if (addresspool != NULL && strlen(addresspool)>0) {
					/* set user defined ip address or pool */
					char *temp;
					char single_addresspool[128];
					pool_range = alloc_thing(ip_range, "pool_range");
					if (pool_range != NULL){
						temp = strchr(addresspool, '-');
						if (temp == NULL ) {
							/* convert single ip address to addresspool */
							sprintf(single_addresspool, "%s-%s", addresspool, addresspool);
							DBG(DBG_CONTROLMORE,
								DBG_log("XAUTH: adding single ip addresspool entry %s for the conn %s ",
								single_addresspool, c->name));
							ttorange(single_addresspool, 0, AF_INET, pool_range, TRUE);
						} else {
							DBG(DBG_CONTROLMORE,
								DBG_log("XAUTH: adding addresspool entry %s for the conn %s ",
								addresspool, c->name));
							ttorange(addresspool, 0, AF_INET, pool_range, TRUE);
						}
						/* if valid install new addresspool */
						if (pool_range->start.u.v4.sin_addr.s_addr){
						    /* delete existing pool if exits */
							if (c->pool)
								unreference_addresspool(c);
							c->pool = install_addresspool(pool_range);
						}
						pfree(pool_range);
					}
				}
				break;
			}
			libreswan_log("XAUTH: nope");
		}
	}

	fclose(fp);
	return win;
}

#ifdef XAUTH_HAVE_PAM
/* IN AN AUTH THREAD */
static bool ikev1_do_pam_authentication(const struct xauth_thread_arg *arg)
{
	struct state *st = arg->st;
	libreswan_log("XAUTH: pam authentication being called to authenticate user %s",
			arg->name);
	struct pam_thread_arg parg;
	ipstr_buf ra;
	struct timeval start_time;
	struct timeval served_time;
	struct timeval served_delta;
	bool results = FALSE;

	parg.name = arg->name;
	parg.password =  arg->password;
	parg.c_name = arg->connname;
	parg.ra = clone_str(ipstr(&st->st_remoteaddr, &ra), "st remote address");
	parg.st_serialno = st->st_serialno;
	parg.c_instance_serial = st->st_connection->instance_serial;
	parg.atype = "XAUTH";
	gettimeofday(&start_time, NULL);
	results = do_pam_authentication(&parg);
	gettimeofday(&served_time, NULL);
	timersub(&served_time, &start_time, &served_delta);
	DBG(DBG_CONTROL,
		DBG_log("XAUTH PAM helper thread call state #%lu, %s[%lu] user=%s %s. elapsed time %lu.%06lu",
			parg.st_serialno, parg.c_name,
			parg.c_instance_serial, parg.name,
			results ? "SUCCESS" : "FAIL",
			(unsigned long)served_delta.tv_sec,
			(unsigned long)(served_delta.tv_usec * 1000000)));

	pfreeany(parg.ra);
	return results;
}
#endif

/*
 * Main authentication routine will then call the actual compiled-in
 * method to verify the user/password
 */

/* IN AN AUTH THREAD */
static void *do_authentication(void *varg)
{
	struct xauth_thread_arg *arg = varg;
	struct state *st = arg->st;
	bool results = FALSE;

	struct sigaction sa;
	struct sigaction oldsa;
	st_jbuf_t *ptr = arg->ptr;

	if (ptr == NULL) {
		pfree(arg->password);
		pfree(arg->name);
		pfree(arg->connname);
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
		/* We got here via siglongjmp in sigIntHandler.
		 * st_jbuf_mutex is locked.
		 * The idea is to shut down the PAM dialogue.
		 */

		dealloc_st_jbuf(ptr);

		/* Still one PAM thread? */
		/* ??? how do we know that there is no more than one thread? */
		/* ??? how do we know which thread was supposed to get this SIGINT if the signal handler setting is global? */
		if (st_jbuf_mem != NULL) {
			/* Yes, restart the one-shot SIGINT handler */
			sigprocmask(SIG_BLOCK, NULL, &sa.sa_mask);
			sa.sa_handler = sigIntHandler;
			sa.sa_flags = SA_RESETHAND | SA_NODEFER | SA_ONSTACK; /* One-shot handler */
			sigaddset(&sa.sa_mask, SIGINT);
			sigaction(SIGINT, &sa, NULL);
		} else {
			/* no */
			sigaction(SIGINT, &oldsa, NULL);
		}
		pthread_mutex_unlock(&st_jbuf_mutex);
		pfree(arg->password);
		pfree(arg->name);
		pfree(arg->connname);
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
	libreswan_log("XAUTH: User %s: Attempting to login", arg->name);

	switch (st->st_connection->xauthby) {
#ifdef XAUTH_HAVE_PAM
	case XAUTHBY_PAM:
		results = ikev1_do_pam_authentication(arg);
		break;
#endif
	case XAUTHBY_FILE:
		libreswan_log(
			"XAUTH: passwd file authentication being called to authenticate user %s",
			arg->name);
		results = do_file_authentication(varg);
		break;
	case XAUTHBY_ALWAYSOK:
		libreswan_log(
			"XAUTH: authentication method 'always ok' requested to authenticate user %s",
			arg->name);
		results = TRUE;
		break;
	default:
		libreswan_log(
			"XAUTH: unknown authentication method requested to authenticate user %s",
			arg->name);
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
			arg->name);
		st->st_xauth_soft = TRUE; /* passed to updown for notification */
		results = TRUE;
	}

	if (results) {
		libreswan_log("XAUTH: User %s: Authentication Successful",
			      arg->name);
		xauth_send_status(st, XAUTH_STATUS_OK);

		if (st->quirks.xauth_ack_msgid)
			st->st_msgid_phase15 = v1_MAINMODE_MSGID;

		jam_str(st->st_username, sizeof(st->st_username), arg->name);
	} else {
		/*
		 * Login attempt failed, display error, send XAUTH status to client
		 * and reset state to XAUTH_R0
		 */
		libreswan_log(
			"XAUTH: User %s: Authentication Failed: Incorrect Username or Password",
			arg->name);
		xauth_send_status(st, XAUTH_STATUS_FAIL);
	}

	pthread_mutex_lock(&st_jbuf_mutex);
	dealloc_st_jbuf(ptr);
	if (st_jbuf_mem == NULL)
		sigaction(SIGINT, &oldsa, NULL);
	pthread_mutex_unlock(&st_jbuf_mutex);
	pthread_mutex_unlock(&st->xauth_mutex);
	st->xauth_tid = 0;	/* ??? this is not valid in POSIX pthreads */

	pfree(arg->password);
	pfree(arg->name);
	pfree(arg->connname);
	pfree(varg);

	return NULL;
}

/** Launch an authentication prompt
 *
 * @param st State Structure
 * @param name Username
 * @param password Password
 * @param connname connnection name, from ipsec.conf
 * @return int Return Code - always 0.
 */
static int xauth_launch_authent(struct state *st,
			chunk_t *name,
			chunk_t *password,
			const char *connname)
{
	pthread_attr_t pattr;
	st_jbuf_t *ptr;
	struct xauth_thread_arg *arg;

	if (st->xauth_tid)	/* ??? this is not valid in POSIX pthreads */
		return 0;

	/* build arg, the context that a thread gets on creation */

	arg = alloc_thing(struct xauth_thread_arg, "XAUTH ThreadArg");
	arg->st = st;

	/*
	 * Clone these so they persist as long as we need them.
	 * Each chunk contains no NUL; we must add one to terminate a string.
	 * alloc_bytes zeros the memory it returns (so the NUL is free).
	 */
	arg->password = alloc_bytes(password->len + 1, "XAUTH Password");
	memcpy(arg->password, password->ptr, password->len);

	arg->name = alloc_bytes(name->len + 1, "XAUTH Name");
	memcpy(arg->name, name->ptr, name->len);

	arg->connname = clone_str(connname, "XAUTH connection name");

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

/*
 * STATE_XAUTH_R0:
 * First REQUEST sent, expect for REPLY
 * HDR*, HASH, ATTR(REPLY,PASSWORD) --> HDR*, HASH, ATTR(STATUS)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inR0(struct msg_digest *md)
{
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;

	struct state *const st = md->st;

	/*
	 * There are many ways out of this routine
	 * so we don't want an obligation to free anything.
	 * We manage this by making these chunks just
	 * references to parts of the input packet.
	 */
	static unsigned char unknown[] = "<unknown>";	/* never written to */
	chunk_t name,
		password = empty_chunk;
	bool gotname = FALSE,
		gotpassword = FALSE;

	CHECK_QUICK_HASH(md,
			 xauth_mode_cfg_hash(hash_val, hash_pbs->roof,
					     md->message_pbs.roof,
					     st),
			 "XAUTH-HASH", "XAUTH R0");

	setchunk(name, unknown, sizeof(unknown) - 1);	/* to make diagnostics easier */

	/* XXX This needs checking with the proper RFC's - ISAKMP_CFG_ACK got added for Cisco interop */
	switch (md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute.isama_type) {
	case ISAKMP_CFG_REPLY:
	case ISAKMP_CFG_ACK:
		break;	/* OK */
	default:
		libreswan_log(
			"Expecting MODE_CFG_REPLY; got %s instead.",
			enum_name(&attr_msg_type_names,
				  md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.
				  mode_attribute.isama_type));
		return STF_IGNORE;
	}

	while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
		struct isakmp_attribute attr;
		pb_stream strattr;
		size_t sz;

		if (!in_struct(&attr, &isakmp_xauth_attribute_desc,
			       attrs, &strattr)) {
			/* fail if malformed */
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
				return STF_FAIL + NO_PROPOSAL_CHOSEN;
			}
			break;

		case XAUTH_USER_NAME | ISAKMP_ATTR_AF_TLV:
			if (gotname) {
				libreswan_log(
					"XAUTH: two User Names!  Rejected");
				return STF_FAIL + NO_PROPOSAL_CHOSEN;
			}
			sz = pbs_left(&strattr);
			if (strnlen((const char *)strattr.cur, sz) != sz) {
				libreswan_log(
					"XAUTH User Name contains NUL character: rejected");
				return STF_FAIL + NO_PROPOSAL_CHOSEN;
			}
			setchunk(name, strattr.cur, sz);
			gotname = TRUE;
			break;

		case XAUTH_USER_PASSWORD | ISAKMP_ATTR_AF_TLV:
			if (gotpassword) {
				libreswan_log(
					"XAUTH: two User Passwords!  Rejected");
				return STF_FAIL + NO_PROPOSAL_CHOSEN;
			}
			sz = pbs_left(&strattr);
			if (sz > 0 && strattr.cur[sz-1] == '\0') {
				libreswan_log(
					"Ignoring NUL at end of XAUTH User Password (Android Issue 36879?)");
				sz--;
			}
			if (strnlen((const char *)strattr.cur, sz) != sz) {
				libreswan_log(
					"XAUTH User Password contains NUL character: rejected");
				return STF_FAIL + NO_PROPOSAL_CHOSEN;
			}
			setchunk(password, strattr.cur, sz);
			gotpassword = TRUE;
			break;

		default:
			log_bad_attr("XAUTH", &xauth_attr_names, attr.isaat_af_type);
			break;
		}
	}

	/** we must get a username and a password value */
	if (!gotname || !gotpassword) {
		libreswan_log(
			"Expected MODE_CFG_REPLY is missing %s%s%s attribute",
			!gotname ? "username" : "",
			!gotname && !gotpassword ? " and " : "",
			!gotpassword ? "password" : "");
		if (st->hidden_variables.st_xauth_client_attempt++ <
		    XAUTH_PROMPT_TRIES) {
			stf_status stat = xauth_send_request(st);

			libreswan_log(
				"XAUTH: User %.*s: Authentication Failed (retry %d)",
				(int)name.len, name.ptr,
				st->hidden_variables.st_xauth_client_attempt);
			/**
			 * STF_OK means that we transmitted again okay, but actually
			 * the state transition failed, as we are prompting again.
			 */
			return stat == STF_OK ? STF_IGNORE : stat;
		} else {
			stf_status stat = xauth_send_status(st, XAUTH_STATUS_FAIL);

			libreswan_log(
				"XAUTH: User %.*s: Authentication Failed (Retried %d times)",
				(int)name.len, name.ptr,
				st->hidden_variables.st_xauth_client_attempt);

			return stat == STF_OK ? STF_FAIL : stat;
		}
	} else {
		xauth_launch_authent(st, &name, &password, st->st_connection->name);
	}
	return STF_IGNORE;
}

/*
 * STATE_XAUTH_R1:
 * STATUS sent, expect for ACK
 * HDR*, ATTR(STATUS), HASH --> Done
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inR1(struct msg_digest *md)
{
	struct state *const st = md->st;

	libreswan_log("XAUTH: xauth_inR1(STF_OK)");
	/* Back to where we were */
	st->st_oakley.doing_xauth = FALSE;

	if (!st->st_connection->spd.this.modecfg_server) {
		DBG(DBG_CONTROL,
		    DBG_log("Not server, starting new exchange"));
		st->st_msgid_phase15 = v1_MAINMODE_MSGID;
	}

	if (st->st_connection->spd.this.modecfg_server &&
	    st->hidden_variables.st_modecfg_vars_set) {
		DBG(DBG_CONTROL,
		    DBG_log("modecfg server, vars are set. Starting new exchange."));
		st->st_msgid_phase15 = v1_MAINMODE_MSGID;
	}

	if (st->st_connection->spd.this.modecfg_server &&
	    st->st_connection->policy & POLICY_MODECFG_PULL) {
		DBG(DBG_CONTROL,
		    DBG_log("modecfg server, pull mode. Starting new exchange."));
		st->st_msgid_phase15 = v1_MAINMODE_MSGID;
	}
	return STF_OK;
}

/*
 * STATE_MODE_CFG_R0:
 * HDR*, HASH, ATTR(REQ=IP) --> HDR*, HASH, ATTR(REPLY=IP)
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
		while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
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
		st->st_msgid_phase15 = v1_MAINMODE_MSGID;
	}

	libreswan_log("modecfg_inR0(STF_OK)");
	return STF_OK;
}

/*
 * STATE_MODE_CFG_R2:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
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

	while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
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
			loglog(RC_LOG,"Received IP address %s",
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
		case MODECFG_DOMAIN | ISAKMP_ATTR_AF_TLV:
		case MODECFG_BANNER | ISAKMP_ATTR_AF_TLV:
		case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
			/* ignore - we will always send/receive these */
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
	st->st_msgid_phase15 = v1_MAINMODE_MSGID;
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
	sanitize_string(strbuf, sizeof(strbuf));
	loglog(RC_INFORMATIONAL, "Received %s: %s", attr_name, strbuf);
	return clone_str(strbuf, attr_name);
}

/*
 * STATE_MODE_CFG_R1:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
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

	DBG(DBG_CONTROL, DBG_log("modecfg_inR1: received mode cfg reply"));

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
		while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
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
			case MODECFG_DOMAIN | ISAKMP_ATTR_AF_TLV:
			case MODECFG_BANNER | ISAKMP_ATTR_AF_TLV:
			case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
				/* ignore - we will always send/receive these */
				break;

			default:
				log_bad_attr("modecfg", &modecfg_attr_names, attr.isaat_af_type);
				break;
			}
		}
		break;

	case ISAKMP_CFG_REPLY:
		while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
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
				loglog(RC_INFORMATIONAL,
					"Received IPv4 address: %s",
					caddr);

				if (addrbytesptr(&c->spd.this.host_srcip,
						 NULL) == 0 ||
				    isanyaddr(&c->spd.this.host_srcip))
				{
					DBG(DBG_CONTROL, DBG_log(
						"setting ip source address to %s",
						caddr));
					c->spd.this.host_srcip = a;
				}
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
			{
				ip_address a;
				ipstr_buf b;
				u_int32_t *ap = (u_int32_t *)(strattr.cur);

				a.u.v4.sin_family = AF_INET;
				memcpy(&a.u.v4.sin_addr.s_addr, ap,
				       sizeof(a.u.v4.sin_addr.s_addr));

				DBG(DBG_CONTROL, DBG_log("Received IP4 NETMASK %s",
					ipstr(&a, &b)));
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
				loglog(RC_INFORMATIONAL, "Received DNS server %s",
					caddr);

				{
					struct connection *c =
						st->st_connection;
					char *old = c->cisco_dns_info;

					if (old == NULL) {
						c->cisco_dns_info =
							clone_str(caddr,
								"cisco_dns_info");
					} else {
						/*
						 * concatenate new IP address
						 * string on end of existing
						 * string, separated by ' '.
						 */
						size_t sz_old = strlen(old);
						size_t sz_added =
							strlen(caddr) + 1;
						char *new =
							alloc_bytes(
								sz_old + 1 + sz_added,
								"cisco_dns_info+");

						memcpy(new, old, sz_old);
						*(new + sz_old) = ' ';
						memcpy(new + sz_old + 1, caddr,
							sz_added);
						c->cisco_dns_info = new;
						pfree(old);
					}
				}

				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			case MODECFG_DOMAIN | ISAKMP_ATTR_AF_TLV:
			{
				/* this is always done - irrespective of CFG request */
				st->st_connection->modecfg_domain =
					cisco_stringify(&strattr,
							"Domain");
				break;
			}

			case MODECFG_BANNER | ISAKMP_ATTR_AF_TLV:
			{
				/* this is always done - irrespective of CFG request */
				st->st_connection->modecfg_banner =
					cisco_stringify(&strattr,
							"Banner");
				break;
			}

			case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
			{
				/*
				 * ??? this really should be parsed by packet
				 * routines
				 */
				size_t len = pbs_left(&strattr);
				struct connection *c = st->st_connection;
				struct spd_route *last_spd = &c->spd;

				DBG(DBG_CONTROL, DBG_log("Received Cisco Split tunnel route(s)"));
				if (!last_spd->that.has_client) {
					ip_address any;

					passert(last_spd->spd_next == NULL);
					anyaddr(AF_INET, &any);
					initsubnet(&any, 0, '0',
						&last_spd->that.client);
					last_spd->that.has_client = TRUE;
					last_spd->that.has_client_wildcard =
						FALSE;
				}

				while (last_spd->spd_next != NULL) {
					/* ??? we should print out spd */
					last_spd = last_spd->spd_next;
				}

				/*
				 * See diagram in modecfg_resp's
				 * case CISCO_SPLIT_INC.
				 * The 14 is explained there.
				 */
				while (len >= 14) {
					u_int32_t *ap =
						(u_int32_t *)(strattr.cur);
					struct spd_route *tmp_spd =
						clone_thing(c->spd,
							    "remote subnets policies");
					ip_address a;
					char caddr[SUBNETTOT_BUF];

					tmp_spd->this.id.name = empty_chunk;
					tmp_spd->that.id.name = empty_chunk;

					tmp_spd->this.host_addr_name = NULL;
					tmp_spd->that.host_addr_name = NULL;

					/* grab 4 octet IP address */
					a.u.v4.sin_family = AF_INET;
					memcpy(&a.u.v4.sin_addr.s_addr,
					       ap,
					       sizeof(a.u.v4.sin_addr.
						      s_addr));

					addrtosubnet(&a, &tmp_spd->that.client);

					len -= sizeof(a.u.v4.sin_addr.s_addr);
					strattr.cur +=
						sizeof(a.u.v4.sin_addr.s_addr);

					/* grab 4 octet address mask */
					ap = (u_int32_t *)(strattr.cur);
					a.u.v4.sin_family = AF_INET;
					memcpy(&a.u.v4.sin_addr.s_addr,
					       ap,
					       sizeof(a.u.v4.sin_addr.s_addr));

					tmp_spd->that.client.maskbits =
						masktocount(&a);
					len -= sizeof(a.u.v4.sin_addr.s_addr);
					strattr.cur +=
						sizeof(a.u.v4.sin_addr.s_addr);

					/* set port to 0 (??? surely default) */
					setportof(0,
						  &tmp_spd->that.client.addr);

					/* throw away 6 octets of who knows what */
					len -= 6;
					strattr.cur += 6;

					subnettot(
						&tmp_spd->that.client,
						0,
						caddr,
						sizeof(caddr));

					loglog(RC_INFORMATIONAL,
						"Received subnet %s",
						caddr);

					tmp_spd->this.cert.ty = CERT_NONE;
					tmp_spd->that.cert.ty = CERT_NONE;

					tmp_spd->this.ca.ptr = NULL;
					tmp_spd->that.ca.ptr = NULL;

					tmp_spd->this.virt = NULL;
					tmp_spd->that.virt = NULL;

					unshare_connection_end(&tmp_spd->this);
					unshare_connection_end(&tmp_spd->that);

					tmp_spd->spd_next = NULL;
					last_spd->spd_next = tmp_spd;
					last_spd = tmp_spd;
				}
				if (len != 0) {
					libreswan_log("ignoring %d unexpected octets at end of CISCO_SPLIT_INC attribute",
						(int)len);
				}
				/*
				 * ??? this won't work because CISCO_SPLIT_INC is way bigger than LELEM_ROOF
				 * resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				 */
				break;
			}

			case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP6_NBNS | ISAKMP_ATTR_AF_TLV:
			{
				libreswan_log("Received and ignored obsoleted Cisco NetBEUI NS info");
				break;
			}

			default:
			{
				log_bad_attr("modecfg", &modecfg_attr_names, attr.isaat_af_type);
				break;
			}

			}
		}
		break;
	}

	/* we are done with this exchange, clear things so that we can start phase 2 properly */
	st->st_msgid_phase15 = v1_MAINMODE_MSGID;
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
	char xauth_username[MAX_USERNAME_LEN];
	struct connection *c = st->st_connection;

	/* START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_MCFG_ATTR); */

	{
		pb_stream hash_pbs;
		int np = ISAKMP_NEXT_MCFG_ATTR;

		if (!ikev1_out_generic(np, &isakmp_hash_desc, rbody, &hash_pbs))
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
			struct isakmp_mode_attr attrh;

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

					if (st->st_username[0] == '\0') {
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
								      sizeof(xauth_username)))
						{
							loglog(RC_LOG_SERIOUS,
							       "XAUTH username prompt failed.");
							return STF_FAIL;
						}
						/* replace the first newline character with a string-terminating \0. */
						{
							char *cptr = memchr(
								xauth_username,
								'\n',
								sizeof(xauth_username));
							if (cptr != NULL)
								*cptr = '\0';
						}
						jam_str(st->st_username,
							sizeof(st->st_username),
							xauth_username);
					}

					if (!out_raw(st->st_username,
						     strlen(st->
							    st_username),
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
						struct secret *s =
							lsw_get_xauthsecret(
								st->st_connection,
								st->st_username);

						DBG(DBG_CONTROLMORE,
						    DBG_log("looked up username=%s, got=%p",
							    st->st_username,
							    s));
						if (s != NULL) {
							struct private_key_stuff
								*pks = lsw_get_pks(s);

							clonetochunk(
								st->st_xauth_password,
								pks->u.preshared_secret.ptr,
								pks->u.preshared_secret.len,
								"savedxauth password");
						}
					}

					if (st->st_xauth_password.ptr == NULL) {
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
								      sizeof(xauth_password)))
						{
							loglog(RC_LOG_SERIOUS,
							       "XAUTH password prompt failed.");
							return STF_FAIL;
						}

						/* replace the first newline character with a string-terminating \0. */
						{
							char *cptr = memchr(xauth_password,
								'\n',
								sizeof(xauth_password));
							if (cptr != NULL)
								*cptr = '\0';
						}
						clonereplacechunk(
							st->st_xauth_password,
							xauth_password,
							strlen(xauth_password),
							"XAUTH password");
						password_read_from_prompt =
							TRUE;
					}

					if (!out_chunk(st->st_xauth_password,
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
							FALSE;	/* ??? never used? */
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
		      st->st_username);

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody->cur, st);

	if (!close_message(rbody, st) ||
	    !encrypt_message(rbody, st))
		return STF_INTERNAL_ERROR;

	return STF_OK;
}

#define XAUTHLELEM(x) (LELEM((x & ISAKMP_ATTR_RTYPE_MASK) - XAUTH_TYPE))

/*
 * STATE_XAUTH_I0:
 * HDR*, HASH, ATTR(REQ=IP) --> HDR*, HASH, ATTR(REPLY=IP)
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

	while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
		struct isakmp_attribute attr;
		pb_stream strattr;

		if (!in_struct(&attr, &isakmp_xauth_attribute_desc,
			       attrs, &strattr)) {
			/* reject malformed */
			return STF_FAIL;
		}

		switch (attr.isaat_af_type) {
		case XAUTH_STATUS | ISAKMP_ATTR_AF_TV:
			got_status = TRUE;
			switch (attr.isaat_lv) {
			case XAUTH_STATUS_FAIL:
				libreswan_log("Received Cisco XAUTH status: FAIL");
				status = attr.isaat_lv;
				break;
			case XAUTH_STATUS_OK:
				DBG(DBG_CONTROLMORE, DBG_log("Received Cisco XAUTH status: OK"));
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
			xauth_resp |= XAUTHLELEM(XAUTH_TYPE);
			break;

		case XAUTH_USER_NAME | ISAKMP_ATTR_AF_TLV:
			DBG_log("Received Cisco XAUTH username");
			xauth_resp |= XAUTHLELEM(XAUTH_USER_NAME);
			break;

		case XAUTH_USER_PASSWORD | ISAKMP_ATTR_AF_TLV:
			DBG_log("Received Cisco XAUTH password");
			xauth_resp |= XAUTHLELEM(XAUTH_USER_PASSWORD);
			break;

		case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			DBG_log("Received Cisco Internal IPv4 address");
			break;

		case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
			DBG_log("Received Cisco Internal IPv4 netmask");
			break;

		case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			DBG_log("Received Cisco IPv4 DNS info");
			break;

		case INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TV:
			DBG_log("Received Cisco IPv4 Subnet info");
			break;

		case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TV:
			DBG_log("Received Cisco NetBEUI NS info");
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
			loglog(RC_LOG,"XAUTH: Successfully Authenticated");
			st->st_oakley.doing_xauth = FALSE;

			return STF_OK;
		} else {
			libreswan_log("xauth: xauth_client_ackstatus() returned %s",
				enum_name(&stfstatus_name, stat));
			libreswan_log("XAUTH: aborting entire IKE Exchange");
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
		if (LDISJOINT(xauth_resp,
			XAUTHLELEM(XAUTH_USER_NAME) |
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
	st->st_msgid_phase15 = v1_MAINMODE_MSGID;

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

		if (!ikev1_out_generic(np, &isakmp_hash_desc, rbody, &hash_pbs))
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
		struct isakmp_mode_attr attrh;
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

		if (!close_message(&strattr, st))
			return STF_INTERNAL_ERROR;
	}

	xauth_mode_cfg_hash(r_hashval, r_hash_start, rbody->cur, st);

	if (!close_message(rbody, st) ||
	    !encrypt_message(rbody, st))
		return STF_INTERNAL_ERROR;

	return STF_OK;
}

/*
 * STATE_XAUTH_I1:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
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
		while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
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
		st->st_oakley.doing_xauth = FALSE;

		return STF_OK;
	}

	/* what? */
	return stat;
}
