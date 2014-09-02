/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2010-2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2006  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2011 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
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

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>           /* for gettimeofday */
#include <gmp.h>
#include <resolv.h>

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "packet.h"
#include "keys.h"
#include "demux.h"      /* needs packet.h */
#include "adns.h"       /* needs <resolv.h> */
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "cookie.h"
#include "server.h"
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "ikev1_quick.h"
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
#include "ikev1_continuations.h"
#include "ikev2.h"

#include "xauth.h"

#include "vendor.h"
#include "nat_traversal.h"
#include "virtual.h"	/* needs connections.h */
#include "ikev1_dpd.h"
#include "x509more.h"

/* MAGIC: perform f, a function that returns notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
/* ??? why are there so many copies of this routine (ikev2.h, ikev1_continuations.h, ipsec_doi.c).
 * Sometimes more than one copy is defined!
 */
#define RETURN_STF_FAILURE(f) { \
	notification_t res = (f); \
	if (res != NOTHING_WRONG) { \
		  return STF_FAIL + res; \
	} \
}

/* create output HDR as replica of input HDR */
void echo_hdr(struct msg_digest *md, bool enc, u_int8_t np)
{
	struct isakmp_hdr r_hdr = md->hdr; /* mostly same as incoming header */

	/* make sure we start with a clean buffer */
	zero(&reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	r_hdr.isa_flags &= ~ISAKMP_FLAG_COMMIT; /* we won't ever turn on this bit */
	if (enc)
		r_hdr.isa_flags |= ISAKMP_FLAG_ENCRYPTION;
	/* some day, we may have to set r_hdr.isa_version */
	r_hdr.isa_np = np;
	if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody))
		impossible(); /* surely must have room and be well-formed */
}

/*
 * Processing FOR KE values.
 */
void unpack_KE(struct state *st,
	       const struct pluto_crypto_req *r,
	       chunk_t *g)
{
	const struct pcr_kenonce *kn = &r->pcr_d.kn;

	if (!st->st_sec_in_use) {
		st->st_sec_in_use = TRUE;
		freeanychunk(*g); /* happens in odd error cases */

		clonetochunk(*g, WIRE_CHUNK_PTR(*kn, gi),
			     kn->gi.len, "saved gi value");
		DBG(DBG_CRYPT,
		    DBG_log("saving DH priv (local secret) and pub key into state struct"));
		st->st_sec_nss = kn->secret;
		st->st_pubk_nss = kn->pubk;
	}
}

/* accept_ke
 *
 * Check and accept DH public value (Gi or Gr) from peer's message.
 * According to RFC2409 "The Internet key exchange (IKE)" 5:
 *  The Diffie-Hellman public value passed in a KE payload, in either
 *  a phase 1 or phase 2 exchange, MUST be the length of the negotiated
 *  Diffie-Hellman group enforced, if necessary, by pre-pending the
 *  value with zeros.
 */
notification_t accept_KE(chunk_t *dest, const char *val_name,
			 const struct oakley_group_desc *gr,
			 pb_stream *pbs)
{
	/* To figure out which function calls us without a pbs */
	passert(pbs != NULL);

	if (pbs_left(pbs) != gr->bytes) {
		loglog(RC_LOG_SERIOUS,
		       "KE has %u byte DH public value; %u required",
		       (unsigned) pbs_left(pbs), (unsigned) gr->bytes);
		/* XXX Could send notification back */
		return INVALID_KEY_INFORMATION;
	}
	clonereplacechunk(*dest, pbs->cur, pbs_left(pbs), val_name);
	DBG_cond_dump_chunk(DBG_CRYPT, "DH public value received:\n", *dest);
	return NOTHING_WRONG;
}

void unpack_nonce(chunk_t *n, const struct pluto_crypto_req *r)
{
	const struct pcr_kenonce *kn = &r->pcr_d.kn;

	freeanychunk(*n);
	clonetochunk(*n, WIRE_CHUNK_PTR(*kn, n),
		     DEFAULT_NONCE_SIZE, "initiator nonce");
}

bool justship_nonce(chunk_t *n, pb_stream *outs, u_int8_t np,
		    const char *name)
{
	return out_generic_chunk(np, &isakmp_nonce_desc, outs, *n, name);
}

bool ship_nonce(chunk_t *n, struct pluto_crypto_req *r,
		pb_stream *outs, u_int8_t np,
		const char *name)
{
	unpack_nonce(n, r);
	return justship_nonce(n, outs, np, name);
}

/** The whole message must be a multiple of 4 octets.
 * I'm not sure where this is spelled out, but look at
 * rfc2408 3.6 Transform Payload.
 * Note: it talks about 4 BYTE boundaries!
 *
 * @param pbs PB Stream
 */
bool close_message(pb_stream *pbs, struct state *st)
{
	size_t padding =  pad_up(pbs_offset(pbs), 4);

	/* Workaround for overzealous Checkpoint firewall */
	if (padding != 0 && st && st->st_connection != NULL &&
	    (st->st_connection->policy & POLICY_NO_IKEPAD)) {
		DBG(DBG_CONTROLMORE, DBG_log("IKE message padding of %zu bytes skipped by policy",
			padding));
	} else if (padding != 0) {
		DBG(DBG_CONTROLMORE, DBG_log("padding IKE message with %zu bytes", padding));
		if (!out_zero(padding, pbs, "message padding"))
			return FALSE;
	} else {
		DBG(DBG_CONTROLMORE, DBG_log("no IKE message padding required"));
	}

	close_output_pbs(pbs);
	return TRUE;
}

static initiator_function *pick_initiator(struct connection *c UNUSED,
					  lset_t policy)
{
	if ((policy & POLICY_IKEV1_DISABLE) == LEMPTY &&
	    (c->failed_ikev2 || ((policy & POLICY_IKEV2_PROPOSE) == LEMPTY))) {
		if (policy & POLICY_AGGRESSIVE) {
			return aggr_outI1;
		} else {
			return main_outI1;
		}
	} else if ((policy & POLICY_IKEV2_PROPOSE) ||
		   (c->policy & (POLICY_IKEV1_DISABLE | POLICY_IKEV2_PROPOSE)))	{
		return ikev2parent_outI1;
	} else {
		libreswan_log("Neither IKEv1 nor IKEv2 allowed");
		/*
		 * tried IKEv2, if allowed, and failed,
		 * and tried IKEv1, if allowed, and got nowhere.
		 */
		return NULL;
	}
}

void ipsecdoi_initiate(int whack_sock,
		       struct connection *c,
		       lset_t policy,
		       unsigned long try,
		       so_serial_t replacing,
		       enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
		       , struct xfrm_user_sec_ctx_ike * uctx
#endif
		       )
{
	/* If there's already an ISAKMP SA established, use that and
	 * go directly to Quick Mode.  We are even willing to use one
	 * that is still being negotiated, but only if we are the Initiator
	 * (thus we can be sure that the IDs are not going to change;
	 * other issues around intent might matter).
	 * Note: there is no way to initiate with a Road Warrior.
	 */
	struct state *st = find_phase1_state(c,
					     ISAKMP_SA_ESTABLISHED_STATES |
					     PHASE1_INITIATOR_STATES);

	if (st == NULL) {
		initiator_function *initiator = pick_initiator(c, policy);

		if (initiator != NULL) {
			(void) initiator(whack_sock, c, NULL, policy, try, importance
#ifdef HAVE_LABELED_IPSEC
					 , uctx
#endif
					 );
		} else {
			/* fizzle: whack_sock will be unused */
			close_any(whack_sock);
		}
	} else if (HAS_IPSEC_POLICY(policy)) {

		/* boost priority if necessary */
		if (st->st_import < importance)
			st->st_import = importance;

		if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
			/* leave our Phase 2 negotiation pending */
			add_pending(whack_sock, st, c, policy, try,
				    replacing
#ifdef HAVE_LABELED_IPSEC
				    , uctx
#endif
				    );
		} else {
			/* ??? we assume that peer_nexthop_sin isn't important:
			 * we already have it from when we negotiated the ISAKMP SA!
			 * It isn't clear what to do with the error return.
			 */
			(void) quick_outI1(whack_sock, st, c, policy, try,
					   replacing
#ifdef HAVE_LABELED_IPSEC
					   , uctx
#endif
					   );
		}
	}
}

/* Replace SA with a fresh one that is similar
 *
 * Shares some logic with ipsecdoi_initiate, but not the same!
 * - we must not reuse the ISAKMP SA if we are trying to replace it!
 * - if trying to replace IPSEC SA, use ipsecdoi_initiate to build
 *   ISAKMP SA if needed.
 * - duplicate whack fd, if live.
 * Does not delete the old state -- someone else will do that.
 */
void ipsecdoi_replace(struct state *st,
		      lset_t policy_add, lset_t policy_del,
		      unsigned long try)
{
	initiator_function *initiator;
	int whack_sock = dup_any(st->st_whack_sock);
	lset_t policy = st->st_policy;

	/*
	 * this is an improvement when an initiator does not get R2.
	 * when we support CREATE_CHILD_SA revisit this code.
	 */
	if (IS_IKE_SA(st) || !HAS_IPSEC_POLICY(policy)) {
		struct connection *c = st->st_connection;

		policy = (c->policy & ~POLICY_IPSEC_MASK & ~policy_del) |
			policy_add;

		initiator = pick_initiator(c, policy);
		passert(!HAS_IPSEC_POLICY(policy));
		if (initiator != NULL) {
			(void) initiator(whack_sock, st->st_connection, st,
					 policy,
					 try, st->st_import
#ifdef HAVE_LABELED_IPSEC
					 , st->sec_ctx
#endif
					 );
		} else {
			/* fizzle: whack_sock will be unused */
			close_any(whack_sock);
		}
	} else {
		/* Add features of actual old state to policy.  This ensures
		 * that rekeying doesn't downgrade security.  I admit that
		 * this doesn't capture everything.
		 */
		if (st->st_pfs_group != NULL)
			policy |= POLICY_PFS;
		if (st->st_ah.present) {
			policy |= POLICY_AUTHENTICATE;
			if (st->st_ah.attrs.encapsulation ==
			    ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}
		if (st->st_esp.present &&
		    st->st_esp.attrs.transattrs.encrypt != ESP_NULL) {
			policy |= POLICY_ENCRYPT;
			if (st->st_esp.attrs.encapsulation ==
			    ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}
		if (st->st_ipcomp.present) {
			policy |= POLICY_COMPRESS;
			if (st->st_ipcomp.attrs.encapsulation ==
			    ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}

		passert(HAS_IPSEC_POLICY(policy));
		ipsecdoi_initiate(whack_sock, st->st_connection, policy, try,
				  st->st_serialno, st->st_import
#ifdef HAVE_LABELED_IPSEC
				  , st->sec_ctx
#endif
				  );
	}
}

/*
 * look for the existence of a non-expiring preloaded public key
 */
bool has_preloaded_public_key(struct state *st)
{
	struct connection *c = st->st_connection;

	/* do not consider rw connections since
	 * the peer's identity must be known
	 */
	if (c->kind == CK_PERMANENT) {
		struct pubkey_list *p;

		/* look for a matching RSA public key */
		for (p = pluto_pubkeys; p != NULL; p = p->next) {
			struct pubkey *key = p->key;

			if (key->alg == PUBKEY_ALG_RSA &&
			    same_id(&c->spd.that.id, &key->id) &&
			    isundefinedrealtime(key->until_time)) {
				/* found a preloaded public key */
				return TRUE;
			}
		}
	}
	return FALSE;
}

/* Decode the ID payload of Phase 1 (main_inI3_outR3 and main_inR3)
 * Note: we may change connections as a result.
 * We must be called before SIG or HASH are decoded since we
 * may change the peer's RSA key or ID.
 */

bool extract_peer_id(struct id *peer, const pb_stream *id_pbs)
{
	switch (peer->kind) {
	/* ident types mostly match between IKEv1 and IKEv2 */
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		/* failure mode for initaddr is probably inappropriate address length */
	{
		err_t ugh = initaddr(id_pbs->cur, pbs_left(id_pbs),
				peer->kind == ID_IPV4_ADDR ? AF_INET : AF_INET6,
				&peer->ip_addr);

		if (ugh != NULL) {
			loglog(RC_LOG_SERIOUS,
				"improper %s identification payload: %s",
				enum_show(&ike_idtype_names, peer->kind),
				ugh);
			/* XXX Could send notification back */
			return FALSE;
		}
	}
	break;

	case ID_USER_FQDN:
		if (memchr(id_pbs->cur, '@', pbs_left(id_pbs)) == NULL) {
			loglog(RC_LOG_SERIOUS,
				"peer's ID_USER_FQDN contains no @: %.*s",
				(int) pbs_left(id_pbs),
				id_pbs->cur);
			/* return FALSE; */
		}
	/* FALLTHROUGH */
	case ID_FQDN:
		if (memchr(id_pbs->cur, '\0', pbs_left(id_pbs)) != NULL) {
			loglog(RC_LOG_SERIOUS,
				"Phase 1 (Parent)ID Payload of type %s contains a NUL",
				enum_show(&ike_idtype_names, peer->kind));
			return FALSE;
		}

		/* ??? ought to do some more sanity check, but what? */

		setchunk(peer->name, id_pbs->cur, pbs_left(id_pbs));
		break;

	case ID_KEY_ID:
		setchunk(peer->name, id_pbs->cur, pbs_left(id_pbs));
		DBG(DBG_PARSING,
		    DBG_dump_chunk("KEY ID:", peer->name));
		break;

	case ID_DER_ASN1_DN:
		setchunk(peer->name, id_pbs->cur, pbs_left(id_pbs));
		DBG(DBG_PARSING,
		    DBG_dump_chunk("DER ASN1 DN:", peer->name));
		break;

	default:
		/* XXX Could send notification back */
		loglog(RC_LOG_SERIOUS,
			"Unsupported identity type (%s) in Phase 1 (Parent) ID Payload",
			enum_show(&ike_idtype_names, peer->kind));
		return FALSE;
	}

	return TRUE;
}

void initialize_new_state(struct state *st,
			  struct connection *c,
			  lset_t policy,
			  int try,
			  int whack_sock,
			  enum crypto_importance importance)
{
	struct spd_route *sr;

	st->st_connection = c;

	set_state_ike_endpoints(st, c);

	set_cur_state(st);                                      /* we must reset before exit */
	st->st_policy = policy & ~POLICY_IPSEC_MASK;        /* clear bits */
	st->st_whack_sock = whack_sock;
	st->st_try = try;

	st->st_import = importance;

	for (sr = &c->spd; sr != NULL; sr = sr->next) {
		if (sr->this.xauth_client) {
			if (sr->this.xauth_name != NULL) {
				jam_str(st->st_xauth_username, sizeof(st->st_xauth_username), sr->this.xauth_name);
				break;
			}
		}
	}

	insert_state(st); /* needs cookies, connection */

	extra_debugging(c);
}

void send_delete(struct state *st)
{
	if (st->st_ikev2)
		ikev2_delete_out(st);
	else
		ikev1_delete_out(st);
}

void fmt_ipsec_sa_established(struct state *st, char *sadetails, size_t sad_len)
{
	struct connection *const c = st->st_connection;
	char *b;
	const char *ini = " {";
	ipstr_buf ipb;

	b = jam_str(sadetails, sad_len,
	       c->policy & POLICY_TUNNEL ?
		" tunnel mode" : " transport mode");

	if (st->st_esp.present) {
		char esb[ENUM_SHOW_BUF_LEN];

		if ( (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) ||
			c->forceencaps) {
			DBG(DBG_NATT, DBG_log("NAT-T: their IKE port is '%d'",
				    c->spd.that.host_port));
			DBG(DBG_NATT, DBG_log("NAT-T: forceencaps is '%s'",
				    c->forceencaps ? "enabled" : "disabled"));
		}

		snprintf(b, sad_len - (b - sadetails),
			 "%sESP%s=>0x%08lx <0x%08lx xfrm=%s_%d-%s",
			 ini,
			 (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) ? "/NAT" : "",
			 (unsigned long)ntohl(st->st_esp.attrs.spi),
			 (unsigned long)ntohl(st->st_esp.our_spi),
			 strip_prefix(enum_showb(&esp_transformid_names,
				   st->st_esp.attrs.transattrs.encrypt, esb, sizeof(esb)), "ESP_"),
			 st->st_esp.attrs.transattrs.enckeylen,
			 strip_prefix(enum_show(&auth_alg_names,
				   st->st_esp.attrs.transattrs.integ_hash), "AUTH_ALGORITHM_"));

		/* advance b to end of string */
		b = b + strlen(b);

		ini = " ";
	}

	if (st->st_ah.present) {
		snprintf(b, sad_len - (b - sadetails),
			 "%sAH=>0x%08lx <0x%08lx",
			 ini,
			 (unsigned long)ntohl(st->st_ah.attrs.spi),
			 (unsigned long)ntohl(st->st_ah.our_spi));

		/* advance b to end of string */
		b = b + strlen(b);

		ini = " ";
	}

	if (st->st_ipcomp.present) {
		snprintf(b, sad_len - (b - sadetails),
			 "%sIPCOMP=>0x%08lx <0x%08lx",
			 ini,
			 (unsigned long)ntohl(st->st_ipcomp.attrs.spi),
			 (unsigned long)ntohl(st->st_ipcomp.our_spi));

		/* advance b to end of string */
		b = b + strlen(b);

		ini = " ";
	}

	b = add_str(sadetails, sad_len, b, ini);
	b = add_str(sadetails, sad_len, b, "NATOA=");
	b = add_str(sadetails, sad_len, b,
		isanyaddr(&st->hidden_variables.st_nat_oa) ? "none" :
			ipstr(&st->hidden_variables.st_nat_oa, &ipb));

	b = add_str(sadetails, sad_len, b, " NATD=");

	if (isanyaddr(&st->hidden_variables.st_natd)) {
		b = add_str(sadetails, sad_len, b, "none");
	} else {
		char oa[ADDRTOT_BUF + sizeof(":00000")];

		snprintf(oa, sizeof(oa),
			 "%s:%d",
			 ipstr(&st->hidden_variables.st_natd, &ipb),
			 st->st_remoteport);
		b = add_str(sadetails, sad_len, b, oa);
	}

	b = add_str(sadetails, sad_len, b,
		dpd_active_locally(st) ? " DPD=active" : " DPD=passive");

	if (st->st_xauth_username[0] != '\0') {
		b = add_str(sadetails, sad_len, b, " XAUTHuser=");
		b = add_str(sadetails, sad_len, b, st->st_xauth_username);
	}

	add_str(sadetails, sad_len, b, "}");
}

void fmt_isakmp_sa_established(struct state *st, char *sadetails, size_t sad_len)
{

	/* document ISAKMP SA details for admin's pleasure */
	char *b = sadetails;
	const char *authname, *prfname;
	const char *integstr, *integname;
	char integname_tmp[20];

	passert(st->st_oakley.encrypter != NULL);
	passert(st->st_oakley.prf_hasher != NULL);
	passert(st->st_oakley.group != NULL);

	if (st->st_ikev2) {
		authname = "IKEv2";
		integstr = " integ=";
		prfname = "prf=";
		snprintf(integname_tmp, sizeof(integname_tmp), "%s_%zu",
			 st->st_oakley.integ_hasher->common.officname,
			 st->st_oakley.integ_hasher->hash_integ_len *
			 BITS_PER_BYTE);
		integname = (const char*)integname_tmp;
	} else {
		authname = enum_show(&oakley_auth_names, st->st_oakley.auth);
		integstr = "";
		integname = "";
		prfname = "integ=";
	}

	snprintf(b, sad_len - (b - sadetails) - 1,
		 " {auth=%s cipher=%s_%d%s%s %s%s group=%s}",
		 strip_prefix(authname,"OAKLEY_"),
		 st->st_oakley.encrypter->common.name,
		 st->st_oakley.enckeylen,
		 integstr, integname,
		 prfname,
		 strip_prefix(st->st_oakley.prf_hasher->common.name,"oakley_"),
		 strip_prefix(enum_name(&oakley_group_names, st->st_oakley.group->group), "OAKLEY_GROUP_"));
	st->hidden_variables.st_logged_p1algos = TRUE;
}
