/*
 * IPsec IKEv1 DOI Quick Mode functions.
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2005  Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: ikev1_quick.c,v 1.9 2005/10/13 03:27:56 mcr Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */
#include <sys/time.h>		/* for gettimeofday */

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
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
#include "keys.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "cookie.h"
#include "server.h"
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "whack.h"
#include "fetch.h"
#include "pkcs.h"
#include "asn1.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"

#include "pluto_crypt.h"
#include "ikev1.h"
#include "ikev1_quick.h"
#include "ikev1_continuations.h"

#ifdef XAUTH
#include "xauth.h"
#endif
#include "vendor.h"
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif
#ifdef VIRTUAL_IP
#include "virtual.h"
#endif
#include "dpd.h"
#include "x509more.h"
#include "tpm/tpm.h"

/* accept_PFS_KE
 *
 * Check and accept optional Quick Mode KE payload for PFS.
 * Extends ACCEPT_PFS to check whether KE is allowed or required.
 */
static notification_t
accept_PFS_KE(struct msg_digest *md, chunk_t *dest
, const char *val_name, const char *msg_name)
{
    struct state *st = md->st;
    struct payload_digest *const ke_pd = md->chain[ISAKMP_NEXT_KE];

    if (ke_pd == NULL)
    {
	if (st->st_pfs_group != NULL)
	{
	    loglog(RC_LOG_SERIOUS, "missing KE payload in %s message", msg_name);
	    return INVALID_KEY_INFORMATION;
	}
    }
    else
    {
	if (st->st_pfs_group == NULL)
	{
	    loglog(RC_LOG_SERIOUS, "%s message KE payload requires a GROUP_DESCRIPTION attribute in SA"
		, msg_name);
	    return INVALID_KEY_INFORMATION;
	}
	if (ke_pd->next != NULL)
	{
	    loglog(RC_LOG_SERIOUS, "%s message contains several KE payloads; we accept at most one", msg_name);
	    return INVALID_KEY_INFORMATION;	/* ??? */
	}
	return accept_KE(dest, val_name, st->st_pfs_group, &ke_pd->pbs);
    }
    return NOTHING_WRONG;
}

/* Initiate quick mode.
 * --> HDR*, HASH(1), SA, Nr [, KE ] [, IDci, IDcr ]
 * (see RFC 2409 "IKE" 5.5)
 * Note: this is not called from demux.c
 */

static bool
emit_subnet_id(ip_subnet *net
	       , u_int8_t np
	       , u_int8_t protoid
	       , u_int16_t port
	       , pb_stream *outs)
{
    struct isakmp_ipsec_id id;
    pb_stream id_pbs;
    ip_address ta;
    const unsigned char *tbp;
    size_t tal;
    const struct af_info *ai;
    bool usehost = FALSE;
    int masklen;

    ai = aftoinfo(subnettypeof(net));

    passert(ai != NULL);

    maskof(net, &ta);
    masklen = masktocount(&ta);
#if 1
    if(masklen == ai->mask_cnt)
    {
	usehost = TRUE;
    }
#endif

    id.isaiid_np = np;
    id.isaiid_idtype = (usehost ? ai->id_addr : ai->id_subnet);
    id.isaiid_protoid = protoid;
    id.isaiid_port = port;

    if (!out_struct(&id, &isakmp_ipsec_identification_desc, outs, &id_pbs))
	return FALSE;

    networkof(net, &ta);
    tal = addrbytesptr(&ta, &tbp);
    if (!out_raw(tbp, tal, &id_pbs, "client network"))
	return FALSE;

    if(!usehost)
    {
	maskof(net, &ta);
	tal = addrbytesptr(&ta, &tbp);
	if (!out_raw(tbp, tal, &id_pbs, "client mask"))
	    return FALSE;
    }

    close_output_pbs(&id_pbs);
    return TRUE;
}

/*
 * Produce the new key material of Quick Mode.
 * RFC 2409 "IKE" section 5.5
 * specifies how this is to be done.
 */
static void
compute_proto_keymat(struct state *st
, u_int8_t protoid
, struct ipsec_proto_info *pi)
{
    size_t needed_len; /* bytes of keying material needed */

    /* Add up the requirements for keying material
     * (It probably doesn't matter if we produce too much!)
     */
    switch (protoid)
    {
    case PROTO_IPSEC_ESP:
	    switch (pi->attrs.transid)
	    {
	    case ESP_NULL:
		needed_len = 0;
		break;
	    case ESP_DES:
		needed_len = DES_CBC_BLOCK_SIZE;
		break;
	    case ESP_3DES:
		needed_len = DES_CBC_BLOCK_SIZE * 3;
		break;
	    case ESP_AES:
		needed_len = AES_CBC_BLOCK_SIZE;

		/* if an attribute is set, then use that! */
		if(st->st_esp.attrs.key_len) {
		    needed_len = st->st_esp.attrs.key_len/8;
		}
		break;

	    default:
#ifdef KERNEL_ALG
		if((needed_len=kernel_alg_esp_enc_keylen(pi->attrs.transid))>0) {
			/* XXX: check key_len "coupling with kernel.c's */
			if (pi->attrs.key_len) {
				needed_len=pi->attrs.key_len/8;
				DBG(DBG_PARSING, DBG_log("compute_proto_keymat:"
						"key_len=%d from peer",
						(int)needed_len));
			}
			break;
		}
#endif
		bad_case(pi->attrs.transid);
	    }
	    DBG(DBG_PARSING, DBG_log("compute_proto_keymat:"
				     "needed_len (after ESP enc)=%d",
				     (int)needed_len));

	    switch (pi->attrs.auth)
	    {
	    case AUTH_ALGORITHM_NONE:
		break;
	    case AUTH_ALGORITHM_HMAC_MD5:
		needed_len += HMAC_MD5_KEY_LEN;
		break;
	    case AUTH_ALGORITHM_HMAC_SHA1:
		needed_len += HMAC_SHA1_KEY_LEN;
		break;
	    default:
#ifdef KERNEL_ALG
	      if (kernel_alg_esp_auth_ok(pi->attrs.auth, NULL)) {
		needed_len += kernel_alg_esp_auth_keylen(pi->attrs.auth);
		break;
	      } 
#endif
	    case AUTH_ALGORITHM_DES_MAC:
		bad_case(pi->attrs.auth);
		break;
	      
	    }
	    DBG(DBG_PARSING, DBG_log("compute_proto_keymat:"
				    "needed_len (after ESP auth)=%d",
				    (int)needed_len));
	    break;

    case PROTO_IPSEC_AH:
	    switch (pi->attrs.transid)
	    {
	    case AH_MD5:
		needed_len = HMAC_MD5_KEY_LEN;
		break;
	    case AH_SHA:
		needed_len = HMAC_SHA1_KEY_LEN;
		break;
	    default:
		bad_case(pi->attrs.transid);
	    }
	    break;

    default:
	bad_case(protoid);
    }

    pi->keymat_len = needed_len;

    /* Allocate space for the keying material.
     * Although only needed_len bytes are desired, we
     * must round up to a multiple of ctx.hmac_digest_len
     * so that our buffer isn't overrun.
     */
    {
	struct hmac_ctx ctx_me, ctx_peer;
	size_t needed_space;	/* space needed for keying material (rounded up) */
	size_t i;

	hmac_init_chunk(&ctx_me, st->st_oakley.hasher, st->st_skeyid_d);
	ctx_peer = ctx_me;	/* duplicate initial conditions */

	needed_space = needed_len + pad_up(needed_len, ctx_me.hmac_digest_len);
	replace(pi->our_keymat, alloc_bytes(needed_space, "keymat in compute_keymat()"));
	replace(pi->peer_keymat, alloc_bytes(needed_space, "peer_keymat in quick_inI1_outR1()"));

	for (i = 0;; )
	{
	    if (st->st_shared.ptr != NULL)
	    {
		/* PFS: include the g^xy */
		hmac_update_chunk(&ctx_me, st->st_shared);
		hmac_update_chunk(&ctx_peer, st->st_shared);
	    }
	    hmac_update(&ctx_me, &protoid, sizeof(protoid));
	    hmac_update(&ctx_peer, &protoid, sizeof(protoid));

	    hmac_update(&ctx_me, (u_char *)&pi->our_spi, sizeof(pi->our_spi));
	    hmac_update(&ctx_peer, (u_char *)&pi->attrs.spi, sizeof(pi->attrs.spi));

	    hmac_update_chunk(&ctx_me, st->st_ni);
	    hmac_update_chunk(&ctx_peer, st->st_ni);

	    hmac_update_chunk(&ctx_me, st->st_nr);
	    hmac_update_chunk(&ctx_peer, st->st_nr);

	    hmac_final(pi->our_keymat + i, &ctx_me);
	    hmac_final(pi->peer_keymat + i, &ctx_peer);

	    i += ctx_me.hmac_digest_len;
	    if (i >= needed_space)
		break;

	    /* more keying material needed: prepare to go around again */

	    hmac_reinit(&ctx_me);
	    hmac_reinit(&ctx_peer);

	    hmac_update(&ctx_me, pi->our_keymat + i - ctx_me.hmac_digest_len
		, ctx_me.hmac_digest_len);
	    hmac_update(&ctx_peer, pi->peer_keymat + i - ctx_peer.hmac_digest_len
		, ctx_peer.hmac_digest_len);
	}
    }

    DBG(DBG_CRYPT,
	DBG_dump("KEYMAT computed:\n", pi->our_keymat, pi->keymat_len);
	DBG_dump("Peer KEYMAT computed:\n", pi->peer_keymat, pi->keymat_len));
}

static void
compute_keymats(struct state *st)
{
    if (st->st_ah.present)
	compute_proto_keymat(st, PROTO_IPSEC_AH, &st->st_ah);
    if (st->st_esp.present)
	compute_proto_keymat(st, PROTO_IPSEC_ESP, &st->st_esp);
}

/* Decode the variable part of an ID packet (during Quick Mode).
 * This is designed for packets that identify clients, not peers.
 * Rejects 0.0.0.0/32 or IPv6 equivalent because
 * (1) it is wrong and (2) we use this value for inband signalling.
 */
static bool
decode_net_id(struct isakmp_ipsec_id *id
, pb_stream *id_pbs
, ip_subnet *net
, const char *which)
{
    const struct af_info *afi = NULL;

    /* Note: the following may be a pointer into static memory
     * that may be recycled, but only if the type is not known.
     * That case is disposed of very early -- in the first switch.
     */
    const char *idtypename = enum_show(&ident_names, id->isaiid_idtype);

    switch (id->isaiid_idtype)
    {
	case ID_IPV4_ADDR:
	case ID_IPV4_ADDR_SUBNET:
	case ID_IPV4_ADDR_RANGE:
	    afi = &af_inet4_info;
	    break;
	case ID_IPV6_ADDR:
	case ID_IPV6_ADDR_SUBNET:
	case ID_IPV6_ADDR_RANGE:
	    afi = &af_inet6_info;
	    break;
	case ID_FQDN:
	    loglog(RC_COMMENT, "%s type is FQDN", which);
	    return TRUE;

	default:
	    /* XXX support more */
	    loglog(RC_LOG_SERIOUS, "unsupported ID type %s"
		, idtypename);
	    /* XXX Could send notification back */
	    return FALSE;
    }

    switch (id->isaiid_idtype)
    {
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
	{
	    ip_address temp_address;
	    err_t ugh;

	    ugh = initaddr(id_pbs->cur, pbs_left(id_pbs), afi->af, &temp_address);

	    if (ugh != NULL)
	    {
		loglog(RC_LOG_SERIOUS, "%s ID payload %s has wrong length in Quick I1 (%s)"
		    , which, idtypename, ugh);
		/* XXX Could send notification back */
		return FALSE;
	    }
	    if (isanyaddr(&temp_address))
	    {
		loglog(RC_LOG_SERIOUS, "%s ID payload %s is invalid (%s) in Quick I1"
		    , which, idtypename, ip_str(&temp_address));
		/* XXX Could send notification back */
		return FALSE;
	    }
	    happy(addrtosubnet(&temp_address, net));
	    DBG(DBG_PARSING | DBG_CONTROL
		, DBG_log("%s is %s", which, ip_str(&temp_address)));
	    break;
	}

	case ID_IPV4_ADDR_SUBNET:
	case ID_IPV6_ADDR_SUBNET:
	{
	    ip_address temp_address, temp_mask;
	    err_t ugh;

	    if (pbs_left(id_pbs) != 2 * afi->ia_sz)
	    {
		loglog(RC_LOG_SERIOUS, "%s ID payload %s wrong length in Quick I1"
		    , which, idtypename);
		/* XXX Could send notification back */
		return FALSE;
	    }
	    ugh = initaddr(id_pbs->cur
		, afi->ia_sz, afi->af, &temp_address);
	    if (ugh == NULL)
		ugh = initaddr(id_pbs->cur + afi->ia_sz
		    , afi->ia_sz, afi->af, &temp_mask);
	    if (ugh == NULL)
		ugh = initsubnet(&temp_address, masktocount(&temp_mask)
		    , '0', net);
	    if (ugh == NULL && subnetisnone(net))
		ugh = "contains only anyaddr";
	    if (ugh != NULL)
	    {
		loglog(RC_LOG_SERIOUS, "%s ID payload %s bad subnet in Quick I1 (%s)"
		    , which, idtypename, ugh);
		/* XXX Could send notification back */
		return FALSE;
	    }
	    DBG(DBG_PARSING | DBG_CONTROL,
		{
		    char temp_buff[SUBNETTOT_BUF];

		    subnettot(net, 0, temp_buff, sizeof(temp_buff));
		    DBG_log("%s is subnet %s", which, temp_buff);
		});
	    break;
	}

	case ID_IPV4_ADDR_RANGE:
	case ID_IPV6_ADDR_RANGE:
	{
	    ip_address temp_address_from, temp_address_to;
	    err_t ugh;

	    if (pbs_left(id_pbs) != 2 * afi->ia_sz)
	    {
		loglog(RC_LOG_SERIOUS, "%s ID payload %s wrong length in Quick I1"
		    , which, idtypename);
		/* XXX Could send notification back */
		return FALSE;
	    }
	    ugh = initaddr(id_pbs->cur, afi->ia_sz, afi->af, &temp_address_from);
	    if (ugh == NULL)
		ugh = initaddr(id_pbs->cur + afi->ia_sz
		    , afi->ia_sz, afi->af, &temp_address_to);
	    if (ugh != NULL)
	    {
		loglog(RC_LOG_SERIOUS, "%s ID payload %s malformed (%s) in Quick I1"
		    , which, idtypename, ugh);
		/* XXX Could send notification back */
		return FALSE;
	    }

	    ugh = rangetosubnet(&temp_address_from, &temp_address_to, net);
	    if (ugh == NULL && subnetisnone(net))
		ugh = "contains only anyaddr";
	    if (ugh != NULL)
	    {
		char temp_buff1[ADDRTOT_BUF], temp_buff2[ADDRTOT_BUF];

		addrtot(&temp_address_from, 0, temp_buff1, sizeof(temp_buff1));
		addrtot(&temp_address_to, 0, temp_buff2, sizeof(temp_buff2));
		loglog(RC_LOG_SERIOUS, "%s ID payload in Quick I1, %s"
		    " %s - %s unacceptable: %s"
		    , which, idtypename, temp_buff1, temp_buff2, ugh);
		return FALSE;
	    }
	    DBG(DBG_PARSING | DBG_CONTROL,
		{
		    char temp_buff[SUBNETTOT_BUF];

		    subnettot(net, 0, temp_buff, sizeof(temp_buff));
		    DBG_log("%s is subnet %s (received as range)"
			, which, temp_buff);
		});
	    break;
	}
    }

    /* set the port selector */
    setportof(htons(id->isaiid_port), &net->addr);

    DBG(DBG_PARSING | DBG_CONTROL,
        DBG_log("%s protocol/port is %d/%d", which, id->isaiid_protoid, id->isaiid_port)
    )

    return TRUE;
}


/* like decode, but checks that what is received matches what was sent */
static bool
check_net_id(struct isakmp_ipsec_id *id
, pb_stream *id_pbs
, u_int8_t *protoid
, u_int16_t *port
, ip_subnet *net
, const char *which)
{
    ip_subnet net_temp;

    if (!decode_net_id(id, id_pbs, &net_temp, which))
	return FALSE;

    if (!samesubnet(net, &net_temp)
    || *protoid != id->isaiid_protoid || *port != id->isaiid_port)
    {
	loglog(RC_LOG_SERIOUS, "%s ID returned doesn't match my proposal", which);
	return FALSE;
    }
    return TRUE;
}


/* Compute HASH(1), HASH(2) of Quick Mode.
 * HASH(1) is part of Quick I1 message.
 * HASH(2) is part of Quick R1 message.
 * Used by: quick_outI1, quick_inI1_outR1 (twice), quick_inR1_outI2
 * (see RFC 2409 "IKE" 5.5, pg. 18 or draft-ietf-ipsec-ike-01.txt 6.2 pg 25)
 */
static size_t
quick_mode_hash12(u_char *dest, const u_char *start, const u_char *roof
, const struct state *st, const msgid_t *msgid, bool hash2)
{
    struct hmac_ctx ctx;

#if 0	/* if desperate to debug hashing */
#   define hmac_update(ctx, ptr, len) { \
	DBG_dump("hash input", (ptr), (len)); \
	(hmac_update)((ctx), (ptr), (len)); \
    }
    DBG_dump("hash key", st->st_skeyid_a.ptr, st->st_skeyid_a.len);
#endif
    hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_a);
    hmac_update(&ctx, (const void *) msgid, sizeof(msgid_t));
    if (hash2)
	hmac_update_chunk(&ctx, st->st_ni);	/* include Ni_b in the hash */
    hmac_update(&ctx, start, roof-start);
    hmac_final(dest, &ctx);

    DBG(DBG_CRYPT,
	DBG_log("HASH(%d) computed:", hash2 + 1);
	DBG_dump("", dest, ctx.hmac_digest_len));
    return ctx.hmac_digest_len;
#   undef hmac_update
}

/* Compute HASH(3) in Quick Mode (part of Quick I2 message).
 * Used by: quick_inR1_outI2, quick_inI2
 * See RFC2409 "The Internet Key Exchange (IKE)" 5.5.
 * NOTE: this hash (unlike HASH(1) and HASH(2)) ONLY covers the
 * Message ID and Nonces.  This is a mistake.
 */
static size_t
quick_mode_hash3(u_char *dest, struct state *st)
{
    struct hmac_ctx ctx;

    hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_a);
    hmac_update(&ctx, (const u_char *)"\0", 1);
    hmac_update(&ctx, (u_char *) &st->st_msgid, sizeof(st->st_msgid));
    hmac_update_chunk(&ctx, st->st_ni);
    hmac_update_chunk(&ctx, st->st_nr);
    hmac_final(dest, &ctx);
    DBG_cond_dump(DBG_CRYPT, "HASH(3) computed:", dest, ctx.hmac_digest_len);
    return ctx.hmac_digest_len;
}

/* Compute Phase 2 IV.
 * Uses Phase 1 IV from st_iv; puts result in st_new_iv.
 */
void
init_phase2_iv(struct state *st, const msgid_t *msgid)
{
    const struct hash_desc *h = st->st_oakley.hasher;
    union hash_ctx ctx;

    DBG_cond_dump(DBG_CRYPT, "last Phase 1 IV:"
		  , st->st_ph1_iv, st->st_ph1_iv_len);

    st->st_new_iv_len = h->hash_digest_len;
    passert(st->st_new_iv_len <= sizeof(st->st_new_iv));

    DBG_cond_dump(DBG_CRYPT, "current Phase 1 IV:"
		  , st->st_iv, st->st_iv_len);

    h->hash_init(&ctx);
    h->hash_update(&ctx, st->st_ph1_iv, st->st_ph1_iv_len);
    passert(*msgid != 0);
    h->hash_update(&ctx, (const u_char *)msgid, sizeof(*msgid));
    h->hash_final(st->st_new_iv, &ctx);

    DBG_cond_dump(DBG_CRYPT, "computed Phase 2 IV:"
	, st->st_new_iv, st->st_new_iv_len);
}

static stf_status
quick_outI1_tail(struct pluto_crypto_req_cont *pcrc
		 , struct pluto_crypto_req *r);

static void
quick_outI1_continue(struct pluto_crypto_req_cont *pcrc
		     , struct pluto_crypto_req *r
		     , err_t ugh)
{
    struct qke_continuation *qke = (struct qke_continuation *)pcrc;
    struct state *const st = qke->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
	, DBG_log("quick outI1: calculated ke+nonce, sending I1"));

    st->st_calculating = FALSE;

    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    set_cur_state(st);	/* we must reset before exit */
    set_suspended(st, NULL);
    e = quick_outI1_tail(pcrc, r);

    reset_globals();
}

stf_status
quick_outI1(int whack_sock
	    , struct state *isakmp_sa
	    , struct connection *c
	    , lset_t policy
	    , unsigned long try
	    , so_serial_t replacing)
{
    struct state *st = duplicate_state(isakmp_sa);
    struct qke_continuation *qke = alloc_thing(struct qke_continuation
					       , "quick_outI1 KE");
    stf_status e;

    st->st_whack_sock = whack_sock;
    st->st_connection = c;
    passert(c != NULL);

    if(st->st_calculating) {
	return STF_IGNORE;
    }

    set_cur_state(st);	/* we must reset before exit */
    st->st_policy = policy;
    st->st_try = try;

    st->st_myuserprotoid = c->spd.this.protocol;
    st->st_peeruserprotoid = c->spd.that.protocol;
    st->st_myuserport = c->spd.this.port;
    st->st_peeruserport = c->spd.that.port;

    st->st_msgid = generate_msgid(isakmp_sa);
    st->st_state = STATE_QUICK_I1;

    insert_state(st);	/* needs cookies, connection, and msgid */

    if (replacing == SOS_NOBODY)
	openswan_log("initiating Quick Mode %s {using isakmp#%lu}"
		     , prettypolicy(policy)
		     , isakmp_sa->st_serialno);
    else
	openswan_log("initiating Quick Mode %s to replace #%lu {using isakmp#%lu}"
		     , prettypolicy(policy)
		     , replacing
		     , isakmp_sa->st_serialno);

    /* 
     * See if pfs_group has been specified for this conn,
     * if not, fallback to old use-same-as-P1 behaviour
     */
#ifdef IKE_ALG
    if (st->st_connection)
	    st->st_pfs_group = ike_alg_pfsgroup(st->st_connection
						, st->st_policy);
    if (!st->st_pfs_group)
#endif
    /* If PFS specified, use the same group as during Phase 1:
     * since no negotiation is possible, we pick one that is
     * very likely supported.
     */
	    st->st_pfs_group = policy & POLICY_PFS? isakmp_sa->st_oakley.group : NULL;

    qke->st = st;
    qke->isakmp_sa = isakmp_sa;
    qke->replacing = replacing;
    qke->qke_pcrc.pcrc_func = quick_outI1_continue;
    
    if(policy & POLICY_PFS) {
	e=build_ke(&qke->qke_pcrc, st, st->st_pfs_group, st->st_import);
    } else {
	e=build_nonce(&qke->qke_pcrc, st, st->st_import);
    }

    reset_globals();

    return e;
}
    
static stf_status
quick_outI1_tail(struct pluto_crypto_req_cont *pcrc
		 , struct pluto_crypto_req *r)
{
    struct qke_continuation *qke = (struct qke_continuation *)pcrc;
    struct state *st = qke->st;
    struct connection *c = st->st_connection;
    struct state *isakmp_sa = qke->isakmp_sa;
    pb_stream reply;	/* not really a reply */
    pb_stream rbody;
    u_char	/* set by START_HASH_PAYLOAD: */
	*r_hashval,	/* where in reply to jam hash value */
	*r_hash_start;	/* start of what is to be hashed */
    bool has_client = c->spd.this.has_client || c->spd.that.has_client ||
		      c->spd.this.protocol || c->spd.that.protocol ||
		      c->spd.this.port || c->spd.that.port;

    st->st_connection = c;

#ifdef NAT_TRAVERSAL
    if (isakmp_sa->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
       /* Duplicate nat_traversal status in new state */
       st->hidden_variables.st_nat_traversal = isakmp_sa->hidden_variables.st_nat_traversal;
       if (isakmp_sa->hidden_variables.st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME)) { 
 	  has_client = TRUE;
       }
       nat_traversal_change_port_lookup(NULL, st);
    }
    else {
       st->hidden_variables.st_nat_traversal = 0;
    }
#endif

    /* set up reply */
    init_pbs(&reply, reply_buffer, sizeof(reply_buffer), "reply packet");

    /* HDR* out */
    {
	struct isakmp_hdr hdr;

	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_HASH;
	hdr.isa_xchg = ISAKMP_XCHG_QUICK;
	hdr.isa_msgid = st->st_msgid;
	hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
	{
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }

    /* HASH(1) -- create and note space to be filled later */
    START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_SA);

    /* SA out */

    /* Emit SA payload based on a subset of the policy bits.
     * POLICY_COMPRESS is considered iff we can do IPcomp.
     */
    {
	lset_t pm = POLICY_ENCRYPT | POLICY_AUTHENTICATE;

	if (can_do_IPcomp)
	    pm |= POLICY_COMPRESS;

	if (!out_sa(&rbody
		    , &ipsec_sadb[(st->st_policy & pm) >> POLICY_IPSEC_SHIFT]
		    , st, FALSE, FALSE, ISAKMP_NEXT_NONCE))
	{
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }

    {
	int np;

	if(st->st_policy & POLICY_PFS) {
	    np = ISAKMP_NEXT_KE;
	} else {
	    if(has_client) {
		np = ISAKMP_NEXT_ID;
	    } else {
		np = ISAKMP_NEXT_NONE;
	    }
	}

	/* Ni out */
	if (!ship_nonce(&st->st_ni, r, &rbody
			, np
			, "Ni"))
	    {
		reset_cur_state();
		return STF_INTERNAL_ERROR;
	    }
    }

    /* [ KE ] out (for PFS) */
    if (st->st_pfs_group != NULL)
    {
	if (!ship_KE(st, r, &st->st_gi
		     , &rbody
		     , has_client? ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE))
	{
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }

    /* [ IDci, IDcr ] out */
    if (has_client)
    {
	/* IDci (we are initiator), then IDcr (peer is responder) */
	if (!emit_subnet_id(&c->spd.this.client
			    , ISAKMP_NEXT_ID
			    , st->st_myuserprotoid
			    , st->st_myuserport, &rbody)
	    || !emit_subnet_id(&c->spd.that.client
			       , ISAKMP_NEXT_NONE
			       , st->st_peeruserprotoid
			       , st->st_peeruserport, &rbody))
	{
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }

#ifdef NAT_TRAVERSAL
    if ((st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA)
	&& (!(st->st_policy & POLICY_TUNNEL))
	&& (st->hidden_variables.st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME))) {
	/** Send NAT-OA if our address is NATed */
	if (!nat_traversal_add_natoa(ISAKMP_NEXT_NONE, &rbody, st, TRUE /* initiator */)) {
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }
#endif

#ifdef TPM
    {
	pb_stream *pbs = &rbody;
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	TCLCALLOUT_crypt("preHash",st,pbs,sizeof(struct isakmp_hdr),enc_len);
	r_hashval = tpm_relocateHash(pbs);
    }
#endif

    /* finish computing  HASH(1), inserting it in output */
    (void) quick_mode_hash12(r_hashval, r_hash_start, rbody.cur
	, st, &st->st_msgid, FALSE);

    /* encrypt message, except for fixed part of header */

    init_phase2_iv(isakmp_sa, &st->st_msgid);
    st->st_new_iv_len = isakmp_sa->st_new_iv_len;
    set_new_iv(st, isakmp_sa->st_new_iv);

    if (!encrypt_message(&rbody, st))
    {
	reset_cur_state();
	return STF_INTERNAL_ERROR;
    }

    /* save packet, now that we know its size */
    clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply)
	, "reply packet from quick_outI1");

    /* send the packet */

    send_packet(st, "quick_outI1", TRUE);

    delete_event(st);
    event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    if (qke->replacing == SOS_NOBODY)
	whack_log(RC_NEW_STATE + STATE_QUICK_I1
	    , "%s: initiate"
	    , enum_name(&state_names, st->st_state));
    else
	whack_log(RC_NEW_STATE + STATE_QUICK_I1
	    , "%s: initiate to replace #%lu"
	    , enum_name(&state_names, st->st_state)
	    , qke->replacing);

    return STF_OK;
}

/* Handle first message of Phase 2 -- Quick Mode.
 * HDR*, HASH(1), SA, Ni [, KE ] [, IDci, IDcr ] -->
 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ]
 * (see RFC 2409 "IKE" 5.5)
 * Installs inbound IPsec SAs.
 * Although this seems early, we know enough to do so, and
 * this way we know that it is soon enough to catch all
 * packets that other side could send using this IPsec SA.
 *
 * Broken into parts to allow asynchronous DNS for TXT records:
 *
 * - quick_inI1_outR1 starts the ball rolling.
 *   It checks and parses enough to learn the Phase 2 IDs
 *
 * - quick_inI1_outR1_authtail does the rest of the job
 *   unless DNS must be consulted.  In that case,
 *   it starts a DNS query, salts away what is needed
 *   to continue, and suspends.  Calls
 *   + quick_inI1_outR1_start_query
 *   + quick_inI1_outR1_process_answer
 *
 * - quick_inI1_outR1_continue will restart quick_inI1_outR1_authtail
 *   when DNS comes back with an answer.
 *
 * A big chunk of quick_inI1_outR1_authtail is executed twice.
 * This is necessary because the set of connections
 * might change while we are awaiting DNS.
 * When first called, gateways_from_dns == NULL.  If DNS is
 * consulted asynchronously, gateways_from_dns != NULL the second time.
 * Remember that our state object might disappear too!
 *
 * At the end of authtail, we have all the info we need, but we
 * haven't done any nonce generation or DH that we might need
 * to do, so that are two crypto continuations that do this work,
 * they are:
 *    quick_inI1_outR1_cryptocontinue1 -- called after NONCE/KE
 *    quick_inI1_outR1_cryptocontinue2 -- called after DH (if PFS)
 *
 * we have to call nonce/ke and DH if we are doing PFS.
 *
 *
 * If the connection is opportunistic, we must verify delegation.
 *
 * 1. Check that we are authorized to be SG for
 *    our client.  We look for the TXT record that
 *    delegates us.  We also check that the public
 *    key (if present) matches the private key we used.
 *    Eventually, we should probably require DNSsec
 *    authentication for our side.
 *
 * 2. If our client TXT record did not include a
 *    public key, check the KEY record indicated
 *    by the identity in the TXT record.
 *
 * 3. If the peer's client is the peer itself, we
 *    consider it authenticated.  Otherwise, we check
 *    the TXT record for the client to see that
 *    the identity of the SG matches the peer and
 *    that some public key (if present in the TXT)
 *    matches.  We need not check the public key if
 *    it isn't in the TXT record.
 *
 * Since p isn't yet instantiated, we need to look
 * in c for description of peer.
 *
 * We cannot afford to block waiting for a DNS query.
 * The code here is structured as two halves:
 * - process the result of just completed
 *   DNS query (if any)
 * - if another query is needed, initiate the next
 *   DNS query and suspend
 */

enum verify_oppo_step {
    vos_fail,
    vos_start,
    vos_our_client,
    vos_our_txt,
#ifdef USE_KEYRR
    vos_our_key,
#endif /* USE_KEYRR */
    vos_his_client,
    vos_done
};

static const char *const verify_step_name[] = {
  "vos_fail",
  "vos_start",
  "vos_our_client",
  "vos_our_txt",
#ifdef USE_KEYRR
  "vos_our_key",
#endif /* USE_KEYRR */
  "vos_his_client",
  "vos_done"
};

/* hold anything we can handle of a Phase 2 ID */
struct p2id {
    ip_subnet net;
    u_int8_t proto;
    u_int16_t port;
};

struct verify_oppo_bundle {
    enum verify_oppo_step step;
    bool failure_ok;      /* if true, quick_inI1_outR1_continue will try
			   * other things on DNS failure */
    struct msg_digest *md;
    struct p2id my, his;
    unsigned int new_iv_len;	/* p1st's might change */
    u_char new_iv[MAX_DIGEST_LEN];
    /* int whackfd; */	/* not needed because we are Responder */
};

struct verify_oppo_continuation {
    struct adns_continuation ac;	/* common prefix */
    struct verify_oppo_bundle b;
};

static stf_status quick_inI1_outR1_authtail(struct verify_oppo_bundle *b
    , struct adns_continuation *ac);

stf_status
quick_inI1_outR1(struct msg_digest *md)
{
    const struct state *const p1st = md->st;
    struct connection *c = p1st->st_connection;
    struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];
    struct verify_oppo_bundle b;

    /* HASH(1) in */
    CHECK_QUICK_HASH(md
	, quick_mode_hash12(hash_val, hash_pbs->roof, md->message_pbs.roof
	    , p1st, &md->hdr.isa_msgid, FALSE)
	, "HASH(1)", "Quick I1");

    /* [ IDci, IDcr ] in
     * We do this now (probably out of physical order) because
     * we wish to select the correct connection before we consult
     * it for policy.
     */

    if (id_pd != NULL)
    {
	struct payload_digest *IDci = id_pd->next;

	/* ??? we are assuming IPSEC_DOI */

	/* IDci (initiator is peer) */

	if (!decode_net_id(&id_pd->payload.ipsec_id, &id_pd->pbs
			   , &b.his.net, "peer client"))
	    return STF_FAIL + INVALID_ID_INFORMATION;

        /* Hack for MS 818043 NAT-T Update */
        if (id_pd->payload.ipsec_id.isaiid_idtype == ID_FQDN) {
	    loglog(RC_LOG_SERIOUS, "Applying workaround for MS-818043 NAT-T bug");
	    memset(&b.his.net, 0, sizeof(ip_subnet));
	    happy(addrtosubnet(&c->spd.that.host_addr, &b.his.net));
	}
	/* End Hack for MS 818043 NAT-T Update */

	b.his.proto = id_pd->payload.ipsec_id.isaiid_protoid;
	b.his.port = id_pd->payload.ipsec_id.isaiid_port;
	b.his.net.addr.u.v4.sin_port = htons(b.his.port);

	/* IDcr (we are responder) */

	if (!decode_net_id(&IDci->payload.ipsec_id, &IDci->pbs
			   , &b.my.net, "our client"))
	    return STF_FAIL + INVALID_ID_INFORMATION;

	b.my.proto = IDci->payload.ipsec_id.isaiid_protoid;
	b.my.port = IDci->payload.ipsec_id.isaiid_port;
	b.my.net.addr.u.v4.sin_port = htons(b.my.port);

#ifdef NAT_TRAVERSAL
	/*
	 * if there is a NATOA payload, then use it as
	 *    &st->st_connection->spd.that.client, if the type
	 * of the ID was FQDN
	 *
	 * we actually do NATOA calculation again later on,
	 * but we need the info here, and we don't have a state
	 * to store it in until after we've done the authorization steps.
	 */
	if ((p1st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
	    (p1st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA) &&
	    (id_pd->payload.ipsec_id.isaiid_idtype == ID_FQDN)) {
	    struct hidden_variables hv; 
	    char idfqdn[32], subnet_buf[SUBNETTOT_BUF]; 
	    int  idlen = pbs_room(&IDci->pbs);

	    if(idlen > 31) idlen=31;
	    memcpy(idfqdn, IDci->pbs.cur, idlen);
	    idfqdn[idlen]='\0';

	    hv = p1st->hidden_variables; 
	    nat_traversal_natoa_lookup(md, &hv); 
	    
	    addrtosubnet(&hv.st_nat_oa,&b.his.net);
	    subnettot(&b.his.net, 0, subnet_buf, sizeof(subnet_buf));

	    loglog(RC_LOG_SERIOUS, "IDci was FQDN: %s, using NAT_OA=%s as IDci"
		   , idfqdn, subnet_buf);
	}
#endif
    }
    else
    {
	/* implicit IDci and IDcr: peer and self */
	if (!sameaddrtype(&c->spd.this.host_addr, &c->spd.that.host_addr))
	    return STF_FAIL;

	happy(addrtosubnet(&c->spd.this.host_addr, &b.my.net));
	happy(addrtosubnet(&c->spd.that.host_addr, &b.his.net));
	b.his.proto = b.my.proto = 0;
	b.his.port = b.my.port = 0;
    }
    b.step = vos_start;
    b.md = md;
    b.new_iv_len = p1st->st_new_iv_len;
    save_new_iv(p1st, b.new_iv);
    return quick_inI1_outR1_authtail(&b, NULL);
}

static void
report_verify_failure(struct verify_oppo_bundle *b, err_t ugh)
{
    struct state *st = b->md->st;
    char fgwb[ADDRTOT_BUF]
	, cb[ADDRTOT_BUF];
    ip_address client;
    err_t which;

    switch (b->step)
    {
    case vos_our_client:
    case vos_our_txt:
#ifdef USE_KEYRR
    case vos_our_key:
#endif /* USE_KEYRR */
	which = "our";
	networkof(&b->my.net, &client);
	break;

    case vos_his_client:
	which = "his";
	networkof(&b->his.net, &client);
	break;

    case vos_start:
    case vos_done:
    case vos_fail:
    default:
	bad_case(b->step);
    }

    addrtot(&st->st_connection->spd.that.host_addr, 0, fgwb, sizeof(fgwb));
    addrtot(&client, 0, cb, sizeof(cb));
    loglog(RC_OPPOFAILURE
	, "gateway %s wants connection with %s as %s client, but DNS fails to confirm delegation: %s {msgid:%08x}"
	   , fgwb, cb, which, ugh, st->st_msgid);
}

static void
quick_inI1_outR1_continue(struct adns_continuation *cr, err_t ugh)
{
    stf_status r;
    struct verify_oppo_continuation *vc = (void *)cr;
    struct verify_oppo_bundle *b = &vc->b;
    struct state *st = b->md->st;

    DBG(DBG_CONTROLMORE
	, DBG_log("quick inI1_outR1: adns continuation: %s", ugh));

    passert(cur_state == NULL);
    /* if st == NULL, our state has been deleted -- just clean up */
    if (st != NULL)
    {
	passert(st->st_suspended_md == b->md);
	set_suspended(st, NULL);	/* no longer connected or suspended */
	cur_state = st;
	if (!b->failure_ok && ugh != NULL)
	{
	    report_verify_failure(b, ugh);
	    r = STF_FAIL + INVALID_ID_INFORMATION;
	}
	else
	{
	    r = quick_inI1_outR1_authtail(b, cr);
	}
	complete_state_transition(&b->md, r);
    }
    if (b->md != NULL)
	release_md(b->md);
    cur_state = NULL;
}

static stf_status
quick_inI1_outR1_start_query(struct verify_oppo_bundle *b
, enum verify_oppo_step next_step)
{
    struct msg_digest *md = b->md;
    struct state *p1st = md->st;
    struct connection *c = p1st->st_connection;
    struct verify_oppo_continuation *vc
	= alloc_thing(struct verify_oppo_continuation, "verify continuation");
    const struct id *our_id;
    struct id id	/* subject of query */
	, our_id_space;	/* ephemeral: no need for unshare_id_content */
    ip_address client;
    err_t ugh;

    /* Record that state is used by a suspended md */
    b->step = next_step;    /* not just vc->b.step */
    vc->b = *b;
    passert(p1st->st_suspended_md == NULL);
    set_suspended(p1st, b->md);

    DBG(DBG_CONTROL,
	{
	    char ours[SUBNETTOT_BUF];
	    char his[SUBNETTOT_BUF];

	    subnettot(&c->spd.this.client, 0, ours, sizeof(ours));
	    subnettot(&c->spd.that.client, 0, his, sizeof(his));

	    DBG_log("responding with DNS query - from %s to %s new state: %s"
		    , ours, his, verify_step_name[b->step]);
	});

    /* Resolve %myid in a cheesy way.
     * We have to do the resolution because start_adns_query
     * et al have insufficient information to do so.
     * If %myid is already known, we'll use that value
     * (XXX this may be a mistake: it could be stale).
     * If %myid is unknown, we should check to see if
     * there are credentials for the IP address or the FQDN.
     * Instead, we'll just assume the IP address since we are
     * acting as the responder and only the IP address would
     * have gotten it to us.
     * We don't even try to do this for the other side:
     * %myid makes no sense for the other side (but it is syntactically
     * legal).
     */
    our_id = resolve_myid(&c->spd.this.id);
    if (our_id->kind == ID_NONE)
    {
	iptoid(&c->spd.this.host_addr, &our_id_space);
	our_id = &our_id_space;
    }

    switch (next_step)
    {
    case vos_our_client:
	networkof(&b->my.net, &client);
	iptoid(&client, &id);
	vc->b.failure_ok = b->failure_ok = FALSE;
	ugh = start_adns_query(&id
	    , our_id
	    , ns_t_txt
	    , quick_inI1_outR1_continue
	    , &vc->ac);
	break;

    case vos_our_txt:
	vc->b.failure_ok = b->failure_ok = TRUE;
	ugh = start_adns_query(our_id
	    , our_id	/* self as SG */
	    , ns_t_txt
	    , quick_inI1_outR1_continue
	    , &vc->ac);
	break;

#ifdef USE_KEYRR
    case vos_our_key:
	vc->b.failure_ok = b->failure_ok = FALSE;
	ugh = start_adns_query(our_id
	    , NULL
	    , ns_t_key
	    , quick_inI1_outR1_continue
	    , &vc->ac);
	break;
#endif

    case vos_his_client:
	networkof(&b->his.net, &client);
	iptoid(&client, &id);
	vc->b.failure_ok = b->failure_ok = FALSE;
	ugh = start_adns_query(&id
	    , &c->spd.that.id
	    , ns_t_txt
	    , quick_inI1_outR1_continue
	    , &vc->ac);
	break;

    default:
	bad_case(next_step);
    }

    if (ugh != NULL)
    {
	/* note: we'd like to use vc->b but vc has been freed
	 * (it got freed by start_adns_query->release_adns_continuation,
	 *  noting that &vc->ac == vc)
	 * so we have to use b.  This is why we plunked next_state
	 * into b, not just vc->b.
	 */
	report_verify_failure(b, ugh);
	set_suspended(p1st,  NULL);
	return STF_FAIL + INVALID_ID_INFORMATION;
    }
    else
    {
	return STF_SUSPEND;
    }
}

static enum verify_oppo_step
quick_inI1_outR1_process_answer(struct verify_oppo_bundle *b
, struct adns_continuation *ac
, struct state *p1st)
{
    struct connection *c = p1st->st_connection;
    enum verify_oppo_step next_step;
    err_t ugh = NULL;

    DBG(DBG_CONTROL,
	{
	    char ours[SUBNETTOT_BUF];
	    char his[SUBNETTOT_BUF];

	    subnettot(&c->spd.this.client, 0, ours, sizeof(ours));
	    subnettot(&c->spd.that.client, 0, his, sizeof(his));
	    DBG_log("responding on demand from %s to %s state: %s"
		    , ours, his, verify_step_name[b->step]);
	});

    /* process just completed DNS query (if any) */
    switch (b->step)
    {
    case vos_start:
	/* no query to digest */
	next_step = vos_our_client;
	break;

    case vos_our_client:
	next_step = vos_his_client;
	{
	    const struct RSA_private_key *pri = get_RSA_private_key(c);
	    struct gw_info *gwp;

	    if (pri == NULL)
	    {
		ugh = "we don't know our own key";
		break;
	    }
	    ugh = "our client does not delegate us as its Security Gateway";
	    for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
	    {
		ugh = "our client delegates us as its Security Gateway but with the wrong public key";
		/* If there is no key in the TXT record,
		 * we count it as a win, but we will have
		 * to separately fetch and check the KEY record.
		 * If there is a key from the TXT record,
		 * we count it as a win if we match the key.
		 */
		if (!gwp->gw_key_present)
		{
		    next_step = vos_our_txt;
		    ugh = NULL;	/* good! */
		    break;
		}
		else if (same_RSA_public_key(&pri->pub, &gwp->key->u.rsa))
		{
		    ugh = NULL;	/* good! */
		    break;
		}
	    }
	}
	break;

    case vos_our_txt:
	next_step = vos_his_client;
	{
	    const struct RSA_private_key *pri = get_RSA_private_key(c);

	    if (pri == NULL)
	    {
		ugh = "we don't know our own key";
		break;
	    }
	    {
		struct gw_info *gwp;

		for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
		{
#ifdef USE_KEYRR
		    /* not an error yet, because we have to check KEY RR as well */
		    ugh = NULL;
#else
		    ugh = "our client delegation depends on our " RRNAME " record, but it has the wrong public key";
#endif
		    if (gwp->gw_key_present
		    && same_RSA_public_key(&pri->pub, &gwp->key->u.rsa))
		    {
			ugh = NULL;	/* good! */
			break;
		    }
#ifdef USE_KEYRR
		    next_step = vos_our_key;
#endif
		}
	    }
	}
	break;

#ifdef USE_KEYRR
    case vos_our_key:
	next_step = vos_his_client;
	{
	    const struct RSA_private_key *pri = get_RSA_private_key(c);

	    if (pri == NULL)
	    {
		ugh = "we don't know our own key";
		break;
	    }
	    {
		struct pubkey_list *kp;

		ugh = "our client delegation depends on our missing " RRNAME " record";
		for (kp = ac->keys_from_dns; kp != NULL; kp = kp->next)
		{
		    ugh = "our client delegation depends on our " RRNAME " record, but it has the wrong public key";
		    if (same_RSA_public_key(&pri->pub, &kp->key->u.rsa))
		    {
			/* do this only once a day */
			if (!logged_txt_warning)
			{
			    loglog(RC_LOG_SERIOUS, "found KEY RR but not TXT RR. See http://www.freeswan.org/err/txt-change.html.");
			    logged_txt_warning = TRUE;
			}
			ugh = NULL;	/* good! */
			break;
		    }
		}
	    }
	}
	break;
#endif /* USE_KEYRR */

    case vos_his_client:
	next_step = vos_done;
	{
	    struct gw_info *gwp;

	    /* check that the public key that authenticated
	     * the ISAKMP SA (p1st) will do for this gateway.
	     */

	    ugh = "peer's client does not delegate to peer";
	    for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
	    {
		ugh = "peer and its client disagree about public key";
		/* If there is a key from the TXT record,
		 * we count it as a win if we match the key.
		 * If there was no key, we claim a match since
		 * it implies fetching a KEY from the same
		 * place we must have gotten it.
		 */
		if (!gwp->gw_key_present
		|| same_RSA_public_key(&p1st->st_peer_pubkey->u.rsa
		, &gwp->key->u.rsa))
		{
		    ugh = NULL;	/* good! */
		    break;
		}
	    }
	}
	break;

    default:
	bad_case(b->step);
    }

    if (ugh != NULL)
    {
	report_verify_failure(b, ugh);
	next_step = vos_fail;
    }
    return next_step;
}

/* forward definitions */
static stf_status
quick_inI1_outR1_cryptotail(struct dh_continuation *dh
			    , struct pluto_crypto_req *r);

static void
quick_inI1_outR1_cryptocontinue2(struct pluto_crypto_req_cont *pcrc
			      , struct pluto_crypto_req *r
				 , err_t ugh);

static void
quick_inI1_outR1_cryptocontinue1(struct pluto_crypto_req_cont *pcrc
				 , struct pluto_crypto_req *r
				 , err_t ugh);

static stf_status
quick_inI1_outR1_authtail(struct verify_oppo_bundle *b
		      , struct adns_continuation *ac)
{
    struct msg_digest *md = b->md;
    struct state *const p1st = md->st;
    struct connection *c = p1st->st_connection;
    ip_subnet *our_net = &b->my.net
	, *his_net = &b->his.net;
    struct hidden_variables hv;

    /* Now that we have identities of client subnets, we must look for
     * a suitable connection (our current one only matches for hosts).
     */
    {
	struct connection *p = find_client_connection(c
	    , our_net, his_net, b->my.proto, b->my.port, b->his.proto, b->his.port);

	if (p == NULL)
	{
	    /* This message occurs in very puzzling circumstances
	     * so we must add as much information and beauty as we can.
	     */
	    struct end
		me = c->spd.this,
		he = c->spd.that;
	    char buf[2*SUBNETTOT_BUF + 2*ADDRTOT_BUF + 2*IDTOA_BUF + 2*ADDRTOT_BUF + 12]; /* + 12 for separating */
	    size_t l;

	    me.client = *our_net;
	    me.has_client = !subnetisaddr(our_net, &me.host_addr);
	    me.protocol = b->my.proto;
	    me.port = b->my.port;

	    he.client = *his_net;
	    he.has_client = !subnetisaddr(his_net, &he.host_addr);
	    he.protocol = b->his.proto;
	    he.port = b->his.port;

	    l = format_end(buf, sizeof(buf), &me, NULL, TRUE, LEMPTY);
	    l += snprintf(buf + l, sizeof(buf) - l, "...");
	    (void)format_end(buf + l, sizeof(buf) - l, &he, NULL, FALSE, LEMPTY);
	    openswan_log("cannot respond to IPsec SA request"
		" because no connection is known for %s"
		, buf);
	    return STF_FAIL + INVALID_ID_INFORMATION;
	}
	else if (p != c)
	{
	    /* We've got a better connection: it can support the
	     * specified clients.  But it may need instantiation.
	     */
	    if (p->kind == CK_TEMPLATE)
	    {
		/* Yup, it needs instantiation.  How much?
		 * Is it a Road Warrior connection (simple)
		 * or is it an Opportunistic connection (needing gw validation)?
		 */
		if (p->policy & POLICY_OPPO)
		{
		    /* Opportunistic case: delegation must be verified.
		     * Here be dragons.
		     */
		    enum verify_oppo_step next_step;
		    ip_address our_client, his_client;

		    passert(subnetishost(our_net) && subnetishost(his_net));
		    networkof(our_net, &our_client);
		    networkof(his_net, &his_client);

		    next_step = quick_inI1_outR1_process_answer(b, ac, p1st);
		    if (next_step == vos_fail)
			return STF_FAIL + INVALID_ID_INFORMATION;

		    /* short circuit: if peer's client is self,
		     * accept that we've verified delegation in Phase 1
		     */
		    if (next_step == vos_his_client
		    && sameaddr(&c->spd.that.host_addr, &his_client))
			next_step = vos_done;

		    /* the second chunk: initiate the next DNS query (if any) */
		    DBG(DBG_CONTROL,
			{
			    char ours[SUBNETTOT_BUF];
			    char his[SUBNETTOT_BUF];

			    subnettot(&c->spd.this.client, 0, ours, sizeof(ours));
			    subnettot(&c->spd.that.client, 0, his, sizeof(his));

			    DBG_log("responding on demand from %s to %s new state: %s"
				    , ours, his, verify_step_name[next_step]);
			});

		    /* start next DNS query and suspend (if necessary) */
		    if (next_step != vos_done)
			return quick_inI1_outR1_start_query(b, next_step);

		    /* Instantiate inbound Opportunistic connection,
		     * carrying over authenticated peer ID
		     * and filling in a few more details.
		     * We used to include gateways_from_dns, but that
		     * seems pointless at this stage of negotiation.
		     * We should record DNS sec use, if any -- belongs in
		     * state during perhaps.
		     */
		    p = oppo_instantiate(p, &c->spd.that.host_addr, &c->spd.that.id
			, NULL, &our_client, &his_client);
		}
		else
		{
		    /* Plain Road Warrior:
		     * instantiate, carrying over authenticated peer ID
		     */
		    p = rw_instantiate(p, &c->spd.that.host_addr,
				       his_net, 
				       &c->spd.that.id);
		}
	    }
#ifdef DEBUG
	    /* temporarily bump up cur_debugging to get "using..." message
	     * printed if we'd want it with new connection.
	     */
	    {
		lset_t old_cur_debugging = cur_debugging;

		set_debugging(cur_debugging | p->extra_debugging);
		DBG(DBG_CONTROL, DBG_log("using connection \"%s\"", p->name));
		set_debugging(old_cur_debugging);
	    }
#endif
	    c = p;
	}
	/* fill in the client's true ip address/subnet */
	if (p->spd.that.has_client_wildcard)
	{
	    p->spd.that.client = *his_net;
	    p->spd.that.has_client_wildcard = FALSE;
	}

        /* fill in the client's true port */
        if (p->spd.that.has_port_wildcard)
        {
            int port = htons(b->his.port);
 
            setportof(port, &p->spd.that.host_addr);
            setportof(port, &p->spd.that.client.addr);
 
            p->spd.that.port = b->his.port;
            p->spd.that.has_port_wildcard = FALSE;
        }



#ifdef VIRTUAL_IP
	else if (is_virtual_connection(c))
	{
	    c->spd.that.client = *his_net;
	    c->spd.that.virt = NULL;
	    if (subnetishost(his_net) && addrinsubnet(&c->spd.that.host_addr, his_net))
		c->spd.that.has_client = FALSE;
	}
#endif
    }
    passert((p1st->st_policy & POLICY_PFS)==0 || p1st->st_pfs_group != NULL );

    /* now that we are sure of our connection, create our new state, and
     * do any asynchronous cryptographic operations that we may need to
     * make it all work.
     */

    if ((p1st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
	(p1st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA)) {

	hv = p1st->hidden_variables;
	nat_traversal_natoa_lookup(md, &hv);
    }

    /* now that we are sure of our connection, create our new state */
    {
	struct state *const st = duplicate_state(p1st);

	/* first: fill in missing bits of our new state object
	 * note: we don't copy over st_peer_pubkey, the public key
	 * that authenticated the ISAKMP SA.  We only need it in this
	 * routine, so we can "reach back" to p1st to get it.
	 */
	if (st->st_connection != c)
	{
	    struct connection *t = st->st_connection;

	    st->st_connection = c;
	    set_cur_connection(c);
	    connection_discard(t);
	}

	st->st_try = 0;	/* not our job to try again from start */

	st->st_msgid = md->hdr.isa_msgid;

	st->st_new_iv_len = b->new_iv_len;
	set_new_iv(st, b->new_iv);

	set_cur_state(st);	/* (caller will reset) */
	md->st = st;	        /* feed back new state */

	st->st_peeruserprotoid = b->his.proto;
	st->st_peeruserport = b->his.port;
	st->st_myuserprotoid = b->my.proto;
	st->st_myuserport = b->my.port;

	st->st_state = STATE_QUICK_R0;

	insert_state(st);	/* needs cookies, connection, and msgid */

	/* copy hidden variables (possibly with changes */
	st->hidden_variables = hv;

	/* copy the connection's
	 * IPSEC policy into our state.  The ISAKMP policy is water under
	 * the bridge, I think.  It will reflect the ISAKMP SA that we
	 * are using.
	 */
	st->st_policy = (p1st->st_policy & POLICY_ID_AUTH_MASK)
	    | (c->policy & ~POLICY_ID_AUTH_MASK);

#ifdef NAT_TRAVERSAL
	if (p1st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
	    st->hidden_variables.st_nat_traversal = p1st->hidden_variables.st_nat_traversal;
	    nat_traversal_change_port_lookup(md, md->st);
	}
	else {
	    st->hidden_variables.st_nat_traversal = 0;
	}
#endif

	passert(st->st_connection != NULL);
	passert(st->st_connection == c);

	/* process SA in */
	{
	    struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];
	    pb_stream in_pbs = sapd->pbs;
	    
	    /* parse and accept body, setting variables, but not forming
	     * our reply. We'll make up the reply later on.
	     *
	     * note that we process the copy of the pbs, so that
	     * we can process it again in the cryptotail().
	     */
	    st->st_pfs_group = &unset_group;
	    RETURN_STF_FAILURE(parse_ipsec_sa_body(&in_pbs
						   , &sapd->payload.sa
						   , NULL
						   , FALSE, st));
	}

	/* Ni in */
	RETURN_STF_FAILURE(accept_nonce(md, &st->st_ni, "Ni"));

	/* [ KE ] in (for PFS) */
	RETURN_STF_FAILURE(accept_PFS_KE(md, &st->st_gi
					 , "Gi", "Quick Mode I1"));

	passert(st->st_pfs_group != &unset_group);

	passert(st->st_connection != NULL);

	{
	    struct qke_continuation *qke = alloc_thing(struct qke_continuation
						      , "quick_outI1 KE");

	    stf_status e;
	    enum crypto_importance ci;

	    ci = pcim_ongoing_crypto;
	    if(ci < st->st_import) ci = st->st_import;

	    qke->st = st;
	    qke->isakmp_sa = p1st;
	    qke->md = md;
	    qke->qke_pcrc.pcrc_func = quick_inI1_outR1_cryptocontinue1;

	    if (st->st_pfs_group != NULL) {
		e = build_ke(&qke->qke_pcrc, st, st->st_pfs_group, ci);
	    } else {
		e = build_nonce(&qke->qke_pcrc, st, ci);
	    }
	
	    passert(st->st_connection != NULL);

	    return e;
	}
    }
}

static void
quick_inI1_outR1_cryptocontinue1(struct pluto_crypto_req_cont *pcrc
				 , struct pluto_crypto_req *r
				 , err_t ugh)
{
    struct qke_continuation *qke = (struct qke_continuation *)pcrc;
    struct msg_digest *md = qke->md;
    struct state *const st = qke->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
	, DBG_log("quick inI1_outR1: calculated ke+nonce, calculating DH"));

    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    passert(st->st_connection != NULL);

    set_cur_state(st);	/* we must reset before exit */
    st->st_calculating=FALSE;
    set_suspended(st, NULL);

    /* we always calcualte a nonce */
    unpack_nonce(&st->st_nr, r);

    if (st->st_pfs_group != NULL) {
	struct dh_continuation *dh = alloc_thing(struct dh_continuation
						 , "quick outR1 DH");

	unpack_KE(st, r, &st->st_gr);
    
	/* set up second calculation */
	dh->md = md;
	set_suspended(st, md);
	dh->dh_pcrc.pcrc_func = quick_inI1_outR1_cryptocontinue2;
	e = start_dh_secret(&dh->dh_pcrc, st
			    , st->st_import
			    , RESPONDER
			    , st->st_oakley.group->group);
	
	if(e != STF_SUSPEND) {
	    if(dh->md != NULL) {
		complete_state_transition(&qke->md, e);
		if(dh->md) release_md(qke->md);
	    }
	}
	
    } else {
	/* but if PFS is off, we don't do a second DH, so
	 * just call the continuation after making something up.
	 */
	struct dh_continuation dh;

	dh.md=md;

	e = quick_inI1_outR1_cryptotail(&dh, NULL);

	if(dh.md != NULL) {
	    /* note: use qke-> pointer */
	    complete_state_transition(&qke->md, e);
	    if(dh.md) release_md(qke->md);
	}
    }
    reset_cur_state();
	
}

static void
quick_inI1_outR1_cryptocontinue2(struct pluto_crypto_req_cont *pcrc
			      , struct pluto_crypto_req *r
			      , err_t ugh)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *const st = md->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
	, DBG_log("quick inI1_outR1: calculated DH, sending R1"));

    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    passert(st->st_connection != NULL);

    set_cur_state(st);	/* we must reset before exit */
    st->st_calculating=FALSE;
    set_suspended(st, NULL);

    e = quick_inI1_outR1_cryptotail(dh, r);

    if(dh->md != NULL) {
	complete_state_transition(&dh->md, e);
	if(dh->md) release_md(dh->md);
    }

    reset_cur_state();
}

static stf_status
quick_inI1_outR1_cryptotail(struct dh_continuation *dh
			   , struct pluto_crypto_req *r)
{
    struct msg_digest *md = dh->md;
    struct state *st = md->st;
    struct connection *c = st->st_connection;
    struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];
    struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];
    struct isakmp_sa sa = sapd->payload.sa;
    pb_stream r_sa_pbs;
    u_char	/* set by START_HASH_PAYLOAD: */
	*r_hashval,	/* where in reply to jam hash value */
	*r_hash_start;	/* from where to start hashing */

    /* Start the output packet.
     *
     * proccess_packet() would automatically generate the HDR*
     * payload if smc->first_out_payload is not ISAKMP_NEXT_NONE.
     * We don't do this because we wish there to be no partially
     * built output packet if we need to suspend for asynch DNS.
     *
     * We build the reply packet as we parse the message since
     * the parse_ipsec_sa_body emits the reply SA
     */
    
    /* HDR* out */
    echo_hdr(md, TRUE, ISAKMP_NEXT_HASH);
    
    /* HASH(2) out -- first pass */
    START_HASH_PAYLOAD(md->rbody, ISAKMP_NEXT_SA);

    passert(st->st_connection == c);
    passert(st->st_connection != NULL);

    /* sa header is unchanged -- except for np */
    sa.isasa_np = ISAKMP_NEXT_NONCE;
    if (!out_struct(&sa, &isakmp_sa_desc, &md->rbody, &r_sa_pbs))
	return STF_INTERNAL_ERROR;

    /* parse and accept body, this time recording our reply */
    RETURN_STF_FAILURE(parse_ipsec_sa_body(&sapd->pbs
					   , &sapd->payload.sa
					   , &r_sa_pbs
					   , FALSE, st));

    passert(st->st_pfs_group != &unset_group);

    if ((st->st_policy & POLICY_PFS) && st->st_pfs_group == NULL) {
	loglog(RC_LOG_SERIOUS, "we require PFS but Quick I1 SA specifies no GROUP_DESCRIPTION");
	return STF_FAIL + NO_PROPOSAL_CHOSEN;	/* ??? */
    }
    
    openswan_log("responding to Quick Mode {msgid:%08x}", st->st_msgid);

    /**** finish reply packet: Nr [, KE ] [, IDci, IDcr ] ****/
    
    {
	int np;

	if(st->st_pfs_group != NULL) {
	    np = ISAKMP_NEXT_KE;
	} else if(id_pd != NULL) {
	    np = ISAKMP_NEXT_ID;
	} else {
	    np = ISAKMP_NEXT_NONE;
	}

	/* Nr out */
	if (!justship_nonce(&st->st_nr, &md->rbody, np, "Nr"))
	    return STF_INTERNAL_ERROR;
    }
    
    /* [ KE ] out (for PFS) */
    if (st->st_pfs_group != NULL && r!=NULL) {
	if (!justship_KE(&st->st_gr
			 , &md->rbody
			 , id_pd != NULL? ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE))
	    return STF_INTERNAL_ERROR;

	finish_dh_secret(st, r);
	
    }
    
    /* [ IDci, IDcr ] out */
    if  (id_pd != NULL)	{
	struct isakmp_ipsec_id *p = (void *)md->rbody.cur;	/* UGH! */
	    
	if (!out_raw(id_pd->pbs.start, pbs_room(&id_pd->pbs), &md->rbody, "IDci"))
	    return STF_INTERNAL_ERROR;
	p->isaiid_np = ISAKMP_NEXT_ID;
	
	p = (void *)md->rbody.cur;	/* UGH! */
	
	if (!out_raw(id_pd->next->pbs.start, pbs_room(&id_pd->next->pbs), &md->rbody, "IDcr"))
	    return STF_INTERNAL_ERROR;
	p->isaiid_np = ISAKMP_NEXT_NONE;
    }

#ifdef NAT_TRAVERSAL
#if 0
    DBG_log("NAT-OA: %d tunnel: %d \n"
		,(st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA)
    		,(st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TRANSPORT));
    if ((st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA) &&
	(st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TRANSPORT)) {
	/** Send NAT-OA if our address is NATed and if we use Transport Mode */
	if (!nat_traversal_add_natoa(ISAKMP_NEXT_NONE, &md->rbody, md->st, FALSE)) {
	    return STF_INTERNAL_ERROR;
	}
    }
#endif
#endif

#ifdef TPM
    {
	pb_stream *pbs = &md->rbody;
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	TCLCALLOUT_crypt("preHash", st,pbs,sizeof(struct isakmp_hdr),enc_len);
	r_hashval = tpm_relocateHash(pbs);	
    }
#endif

    /* Compute reply HASH(2) and insert in output */
    (void)quick_mode_hash12(r_hashval, r_hash_start, md->rbody.cur
			    , st, &st->st_msgid, TRUE);

    /* Derive new keying material */
    compute_keymats(st);

    /* Tell the kernel to establish the new inbound SA
     * (unless the commit bit is set -- which we don't support).
     * We do this before any state updating so that
     * failure won't look like success.
     */
    if (!install_inbound_ipsec_sa(st))
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */
    
    /* encrypt message, except for fixed part of header */
    
    if (!encrypt_message(&md->rbody, st))
    {
	delete_ipsec_sa(st, TRUE);
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */
    }

    DBG(DBG_CONTROLMORE, DBG_log("finished processing quick inI1"));
    return STF_OK;
}

/* Handle (the single) message from Responder in Quick Mode.
 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ] -->
 * HDR*, HASH(3)
 * (see RFC 2409 "IKE" 5.5)
 * Installs inbound and outbound IPsec SAs, routing, etc.
 */
static stf_status
quick_inR1_outI2_cryptotail(struct dh_continuation *dh
			    , struct pluto_crypto_req *r);
static void
quick_inR1_outI2_continue(struct pluto_crypto_req_cont *pcrc
			  , struct pluto_crypto_req *r
			  , err_t ugh);

stf_status
quick_inR1_outI2(struct msg_digest *md)
{
    struct state *const st = md->st;

    /* HASH(2) in */
    CHECK_QUICK_HASH(md
	, quick_mode_hash12(hash_val, hash_pbs->roof, md->message_pbs.roof
	    , st, &st->st_msgid, TRUE)
	, "HASH(2)", "Quick R1");

    /* SA in */
    {
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];

	RETURN_STF_FAILURE(parse_ipsec_sa_body(&sa_pd->pbs
	    , &sa_pd->payload.sa, NULL, TRUE, st));
    }

    /* Nr in */
    RETURN_STF_FAILURE(accept_nonce(md, &st->st_nr, "Nr"));

    /* [ KE ] in (for PFS) */
    RETURN_STF_FAILURE(accept_PFS_KE(md, &st->st_gr, "Gr", "Quick Mode R1"));

    if(st->st_pfs_group) {
	struct dh_continuation *dh = alloc_thing(struct dh_continuation
						 , "quick outI2 DH");

	/* set up DH calculation */
	dh->md = md;
	set_suspended(st, md);
	dh->dh_pcrc.pcrc_func = quick_inR1_outI2_continue;
	return start_dh_secret(&dh->dh_pcrc, st
			       , st->st_import
			       , INITIATOR
			       , st->st_oakley.group->group);
    } else {
	/* just call the tail function */
	struct dh_continuation dh;

	dh.md=md;
	return quick_inR1_outI2_cryptotail(&dh, NULL);
    }
}

static void
quick_inR1_outI2_continue(struct pluto_crypto_req_cont *pcrc
			  , struct pluto_crypto_req *r
			  , err_t ugh)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *const st = md->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
	, DBG_log("quick inI1_outR1: calculated ke+nonce, calculating DH"));

    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    passert(st->st_connection != NULL);

    set_cur_state(st);	/* we must reset before exit */
    st->st_calculating=FALSE;

    e = quick_inR1_outI2_cryptotail(dh, r);

    if(dh->md != NULL) {
	complete_state_transition(&dh->md, e);
	if(dh->md) release_md(dh->md);
    }
    reset_cur_state();
}

stf_status
quick_inR1_outI2_cryptotail(struct dh_continuation *dh
			    , struct pluto_crypto_req *r)
{
    struct msg_digest *md = dh->md;
    struct state *st = md->st;
    struct connection *c = st->st_connection;

    if (st->st_pfs_group != NULL && r!=NULL) {
	finish_dh_secret(st, r);
    }

#ifdef NAT_TRAVERSAL
    if ((st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
	(st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA)) {
	nat_traversal_natoa_lookup(md, &st->hidden_variables);
    }
#endif

    /* [ IDci, IDcr ] in; these must match what we sent */

    {
	struct payload_digest *const IDci = md->chain[ISAKMP_NEXT_ID];
	struct payload_digest *IDcr;

	if (IDci != NULL)
	{
	    /* ??? we are assuming IPSEC_DOI */

	    /* IDci (we are initiator) */

	    if (!check_net_id(&IDci->payload.ipsec_id, &IDci->pbs
	    , &st->st_myuserprotoid, &st->st_myuserport
	    , &st->st_connection->spd.this.client
	    , "our client"))
		return STF_FAIL + INVALID_ID_INFORMATION;

	    /* we checked elsewhere that we got two of them */
	    IDcr = IDci->next;
	    passert(IDcr != NULL);

	    /* IDcr (responder is peer) */

	    if (!check_net_id(&IDcr->payload.ipsec_id, &IDcr->pbs
	    , &st->st_peeruserprotoid, &st->st_peeruserport
	    , &st->st_connection->spd.that.client
	    , "peer client"))
		return STF_FAIL + INVALID_ID_INFORMATION;

	    /*
	     * if there is a NATOA payload, then use it as
	     *    &st->st_connection->spd.that.client, if the type
	     * of the ID was FQDN
	     */
#ifdef NAT_TRAVERSAL
	    if ((st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
		(st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA) &&
		(IDcr->payload.ipsec_id.isaiid_idtype == ID_FQDN)) {
		
		char idfqdn[32], subnet_buf[SUBNETTOT_BUF];
		int  idlen = pbs_room(&IDcr->pbs);
		if(idlen > 31) idlen=31;
		memcpy(idfqdn, IDcr->pbs.cur, idlen);
		idfqdn[idlen]='\0';

		addrtosubnet(&st->hidden_variables.st_nat_oa,
			     &st->st_connection->spd.that.client);

		subnettot(&st->st_connection->spd.that.client
			  , 0, subnet_buf, sizeof(subnet_buf));
		loglog(RC_LOG_SERIOUS, "IDcr was FQDN: %s, using NAT_OA=%s as IDcr"
		       , idfqdn, subnet_buf);
	    }
#endif

	}
	else
	{
	    /* no IDci, IDcr: we must check that the defaults match our proposal */
	    if (!subnetisaddr(&c->spd.this.client, &c->spd.this.host_addr)
		|| !subnetisaddr(&c->spd.that.client, &c->spd.that.host_addr))
	    {
		loglog(RC_LOG_SERIOUS, "IDci, IDcr payloads missing in message"
		    " but default does not match proposal");
		return STF_FAIL + INVALID_ID_INFORMATION;
	    }
	}
    }
    
    /* ??? We used to copy the accepted proposal into the state, but it was
     * never used.  From sa_pd->pbs.start, length pbs_room(&sa_pd->pbs).
     */

    /**************** build reply packet HDR*, HASH(3) ****************/

    /* HDR* out done */

    /* HASH(3) out -- since this is the only content, no passes needed */
    {
	u_char	/* set by START_HASH_PAYLOAD: */
	    *r_hashval,	/* where in reply to jam hash value */
	    *r_hash_start;	/* start of what is to be hashed */

	START_HASH_PAYLOAD(md->rbody, ISAKMP_NEXT_NONE);

#ifdef TPM
	{
	    pb_stream *pbs = &md->rbody;
	    size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);
	    
	    TCLCALLOUT_crypt("preHash", st,pbs,sizeof(struct isakmp_hdr),enc_len);
	    r_hashval = tpm_relocateHash(pbs);	
	}
#endif
	(void)quick_mode_hash3(r_hashval, st);
    }

   /* Derive new keying material */
    compute_keymats(st);

    /* Tell the kernel to establish the inbound, outbound, and routing part
     * of the new SA (unless the commit bit is set -- which we don't support).
     * We do this before any state updating so that
     * failure won't look like success.
     */
    if (!install_ipsec_sa(st, TRUE))
	return STF_INTERNAL_ERROR;

    /* encrypt message, except for fixed part of header */

    if (!encrypt_message(&md->rbody, st))
    {
	delete_ipsec_sa(st, FALSE);
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */
    }

    {
      DBG(DBG_CONTROLMORE, DBG_log("inR1_outI2: instance %s[%ld], setting newest_ipsec_sa to #%ld (was #%ld) (spd.eroute=#%ld)"
			       , st->st_connection->name
			       , st->st_connection->instance_serial
			       , st->st_serialno
			       , st->st_connection->newest_ipsec_sa
			       , st->st_connection->spd.eroute_owner));
    }
    
    st->st_connection->newest_ipsec_sa = st->st_serialno;

    /* note (presumed) success */
    if (c->gw_info != NULL)
	c->gw_info->key->last_worked_time = now();

    /* If we have dpd delay and dpdtimeout set, then we are doing DPD
	on this conn, so initialize it */
    if (st->st_connection->dpd_delay && st->st_connection->dpd_timeout) {
	if(dpd_init(st) != STF_OK) {
	    delete_ipsec_sa(st, FALSE);
	    return STF_FAIL;
	}
    }

    return STF_OK;
}

/* Handle last message of Quick Mode.
 * HDR*, HASH(3) -> done
 * (see RFC 2409 "IKE" 5.5)
 * Installs outbound IPsec SAs, routing, etc.
 */
stf_status
quick_inI2(struct msg_digest *md)
{
    struct state *const st = md->st;

    /* HASH(3) in */
    CHECK_QUICK_HASH(md, quick_mode_hash3(hash_val, st)
	, "HASH(3)", "Quick I2");

    /* Tell the kernel to establish the outbound and routing part of the new SA
     * (the previous state established inbound)
     * (unless the commit bit is set -- which we don't support).
     * We do this before any state updating so that
     * failure won't look like success.
     */
    if (!install_ipsec_sa(st, FALSE))
	return STF_INTERNAL_ERROR;

    {
      DBG(DBG_CONTROLMORE, DBG_log("inI2: instance %s[%ld], setting newest_ipsec_sa to #%ld (was #%ld) (spd.eroute=#%ld)"
			       , st->st_connection->name
			       , st->st_connection->instance_serial
			       , st->st_serialno
			       , st->st_connection->newest_ipsec_sa
			       , st->st_connection->spd.eroute_owner));
    }
    
    st->st_connection->newest_ipsec_sa = st->st_serialno;

    update_iv(st);	/* not actually used, but tidy */

    /* note (presumed) success */
    {
	struct gw_info *gw = st->st_connection->gw_info;

	if (gw != NULL)
	    gw->key->last_worked_time = now();
    }

    /* If we have dpd delay and dpdtimeout set, then we are doing DPD
	on this conn, so initialize it */
    if(st->st_connection->dpd_delay && st->st_connection->dpd_timeout) {
	if(dpd_init(st) != STF_OK) {
	    delete_ipsec_sa(st, FALSE);
	    return STF_FAIL;
	}
    }

    return STF_OK;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
