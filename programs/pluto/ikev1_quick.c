/*
 * IPsec IKEv1 DOI Quick Mode functions.
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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
#include <resolv.h>


#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "ikev1_msgid.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "keys.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "server.h"
#include "ikev1_spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "whack.h"
#include "fetch.h"
#include "asn1.h"
#include "ikev1_send.h"
#include "crypto.h"
#include "secrets.h"
#include "ikev1_prf.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "crypt_symkey.h"
#include "pluto_crypt.h"
#include "crypt_prf.h"
#include "crypt_hash.h"
#include "ikev1.h"
#include "ikev1_quick.h"
#include "ikev1_continuations.h"

#include "ikev1_xauth.h"

#include "vendor.h"
#include "nat_traversal.h"
#include "virtual_ip.h"
#include "ikev1_dpd.h"
#include "pluto_x509.h"
#include "ip_address.h"
#include "ip_info.h"
#include "ikev1_hash.h"
#include "ikev1_message.h"
#include "crypt_ke.h"
#include <blapit.h>
#include "crypt_dh.h"
#include "unpack.h"

#ifdef USE_XFRM_INTERFACE
# include "kernel_xfrm_interface.h"
#endif

const struct dh_desc *ikev1_quick_pfs(const struct child_proposals proposals)
{
	if (proposals.p == NULL) {
		return NULL;
	}
	struct proposal *proposal = next_proposal(proposals.p, NULL);
	struct algorithm *dh = next_algorithm(proposal, PROPOSAL_dh, NULL);
	if (dh == NULL) {
		return NULL;
	}
	return dh_desc(dh->desc);
}

/* accept_PFS_KE
 *
 * Check and accept optional Quick Mode KE payload for PFS.
 * Extends ACCEPT_PFS to check whether KE is allowed or required.
 */
static notification_t accept_PFS_KE(struct state *st, struct msg_digest *md,
				    chunk_t *dest, const char *val_name, const char *msg_name)
{
	struct payload_digest *const ke_pd = md->chain[ISAKMP_NEXT_KE];

	if (ke_pd == NULL) {
		if (st->st_pfs_group != NULL) {
			log_state(RC_LOG_SERIOUS, st,
				  "missing KE payload in %s message", msg_name);
			return INVALID_KEY_INFORMATION;
		}
		return NOTHING_WRONG;
	} else {
		if (st->st_pfs_group == NULL) {
			log_state(RC_LOG_SERIOUS, st,
				  "%s message KE payload requires a GROUP_DESCRIPTION attribute in SA",
				  msg_name);
			return INVALID_KEY_INFORMATION;
		}
		if (ke_pd->next != NULL) {
			log_state(RC_LOG_SERIOUS, st,
				  "%s message contains several KE payloads; we accept at most one",
				  msg_name);
			return INVALID_KEY_INFORMATION; /* ??? */
		}
		if (!unpack_KE(dest, val_name, st->st_pfs_group,
			       ke_pd, st->st_logger)) {
			return INVALID_KEY_INFORMATION;
		}
		return NOTHING_WRONG;
	}
}

/* Initiate quick mode.
 * --> HDR*, HASH(1), SA, Nr [, KE ] [, IDci, IDcr ]
 * (see RFC 2409 "IKE" 5.5)
 * Note: this is not called from demux.c
 */

static bool emit_subnet_id(const ip_subnet *net,
			   uint8_t protoid,
			   uint16_t port,
			   pb_stream *outs)
{
	const struct ip_info *ai = subnet_type(net);
	const bool usehost = net->maskbits == ai->mask_cnt;
	pb_stream id_pbs;

	struct isakmp_ipsec_id id = {
		.isaiid_idtype = usehost ? ai->id_addr : ai->id_subnet,
		.isaiid_protoid = protoid,
		.isaiid_port = port,
	};

	if (!out_struct(&id, &isakmp_ipsec_identification_desc, outs, &id_pbs))
		return FALSE;

	ip_address tp = subnet_prefix(net);
	diag_t d = pbs_out_address(&id_pbs, &tp, "client network");
	if (d != NULL) {
		log_diag(RC_LOG_SERIOUS, outs->out_logger, &d, "%s", "");
		return false;
	}

	if (!usehost) {
		ip_address tm = subnet_mask(net);
		diag_t d = pbs_out_address(&id_pbs, &tm, "client mask");
		if (d != NULL) {
			log_diag(RC_LOG_SERIOUS, outs->out_logger, &d, "%s", "");
			return false;
		}
	}

	close_output_pbs(&id_pbs);
	return TRUE;
}

/*
 * Produce the new key material of Quick Mode.
 * RFC 2409 "IKE" section 5.5
 * specifies how this is to be done.
 */
static void compute_proto_keymat(struct state *st,
				 uint8_t protoid,
				 struct ipsec_proto_info *pi,
				 const char *satypename)
{
	size_t needed_len = 0; /* bytes of keying material needed */

	/*
	 * Add up the requirements for keying material (It probably
	 * doesn't matter if we produce too much!)
	 *
	 * XXX: This entire switch can probably be reduced to just the
	 * "default:" case.
	 */
	switch (protoid) {
	case PROTO_IPSEC_ESP:
		switch (pi->attrs.transattrs.ta_ikev1_encrypt) {
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
			if (st->st_esp.attrs.transattrs.enckeylen != 0) {
				needed_len =
					st->st_esp.attrs.transattrs.enckeylen /
					BITS_PER_BYTE;
				/* XXX: obtained from peer - was it verified for validity yet? */
			}
			break;
		case ESP_AES_CTR:
			if (st->st_esp.attrs.transattrs.enckeylen != 0) {
				needed_len =
					st->st_esp.attrs.transattrs.enckeylen /
					BITS_PER_BYTE;
				/* XXX: obtained from peer - was it verified for validity yet? */
			} else {
				/* if no keylength set, pick strongest allowed */
				needed_len = AES_CTR_KEY_MAX_LEN / BITS_PER_BYTE;
			}
			/* AES_CTR requires an extra AES_CTR_SALT_BYTES (4) bytes of salt */
			needed_len += AES_CTR_SALT_BYTES;
			break;
		case ESP_AES_GCM_8:
		case ESP_AES_GCM_12:
		case ESP_AES_GCM_16:
			/* valid keysize enforced before we get here */
			if (st->st_esp.attrs.transattrs.enckeylen != 0) {
				passert(st->st_esp.attrs.transattrs.enckeylen == 128 ||
					st->st_esp.attrs.transattrs.enckeylen == 192 ||
					st->st_esp.attrs.transattrs.enckeylen == 256);
				needed_len = st->st_esp.attrs.transattrs.enckeylen / BITS_PER_BYTE;
			} else {
				/* if no keylength set, pick strongest allowed */
				needed_len = AEAD_AES_KEY_MAX_LEN / BITS_PER_BYTE;
			}
			/* AES_GCM requires an extra AES_GCM_SALT_BYTES (4) bytes of salt */
			needed_len += AES_GCM_SALT_BYTES;
			break;
		case ESP_AES_CCM_8:
		case ESP_AES_CCM_12:
		case ESP_AES_CCM_16:
			/* valid keysize enforced before we get here */
			if (st->st_esp.attrs.transattrs.enckeylen != 0) {
				passert(st->st_esp.attrs.transattrs.enckeylen == 128 ||
					st->st_esp.attrs.transattrs.enckeylen == 192 ||
					st->st_esp.attrs.transattrs.enckeylen == 256);
				needed_len = st->st_esp.attrs.transattrs.enckeylen / BITS_PER_BYTE;
			} else {
				/* if no keylength set, pick strongest allowed */
				needed_len = AEAD_AES_KEY_MAX_LEN / BITS_PER_BYTE;
			}
			/* AES_CCM requires an extra AES_CCM_SALT_BYTES (3) bytes of salt */
			needed_len += AES_CCM_SALT_BYTES;
			break;

		case ESP_CAMELLIA:
			/* if an attribute is set, then use that! */
			if (st->st_esp.attrs.transattrs.enckeylen == 0) {
				needed_len = CAMELLIA_BLOCK_SIZE;
			} else {
				needed_len =
					st->st_esp.attrs.transattrs.enckeylen /
					BITS_PER_BYTE;
				/* XXX: obtained from peer - was it verified for validity yet? */
			}
			break;

		case ESP_CAST:
		case ESP_TWOFISH:
		case ESP_SERPENT:
		/* ESP_SEED is for IKEv1 only and not supported. Its number in IKEv2 has been re-used */
			bad_case(pi->attrs.transattrs.ta_ikev1_encrypt);

		default:
			/* bytes */
			needed_len = encrypt_max_key_bit_length(pi->attrs.transattrs.ta_encrypt) / BITS_PER_BYTE;
			if (needed_len > 0) {
				/* XXX: check key_len coupling with kernel.c's */
				if (pi->attrs.transattrs.enckeylen) {
					needed_len =
						pi->attrs.transattrs.enckeylen
						/ BITS_PER_BYTE;
					dbg("compute_proto_keymat: key_len=%d from peer",
					    (int)needed_len);
				}
				break;
			}
			bad_case(pi->attrs.transattrs.ta_ikev1_encrypt);
		}
		dbg("compute_proto_keymat: needed_len (after ESP enc)=%d", (int)needed_len);
		needed_len += pi->attrs.transattrs.ta_integ->integ_keymat_size;
		dbg("compute_proto_keymat: needed_len (after ESP auth)=%d", (int)needed_len);
		break;

	case PROTO_IPSEC_AH:
		needed_len += pi->attrs.transattrs.ta_integ->integ_keymat_size;
		break;

	default:
		bad_case(protoid);
	}

	pi->keymat_len = needed_len;

	pfreeany(pi->our_keymat);
	pi->our_keymat = ikev1_section_5_keymat(st->st_oakley.ta_prf,
						st->st_skeyid_d_nss,
						st->st_dh_shared_secret,
						protoid,
						THING_AS_SHUNK(pi->our_spi),
						st->st_ni, st->st_nr,
						needed_len,
						st->st_logger).ptr;

	pfreeany(pi->peer_keymat);
	pi->peer_keymat = ikev1_section_5_keymat(st->st_oakley.ta_prf,
						 st->st_skeyid_d_nss,
						 st->st_dh_shared_secret,
						 protoid,
						 THING_AS_SHUNK(pi->attrs.spi),
						 st->st_ni, st->st_nr,
						 needed_len,
						 st->st_logger).ptr;

	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s KEYMAT", satypename);
		DBG_dump("  KEYMAT computed:", pi->our_keymat,
			 pi->keymat_len);
		DBG_dump("  Peer KEYMAT computed:", pi->peer_keymat,
			 pi->keymat_len);
	}
}

static void compute_keymats(struct state *st)
{
	if (st->st_ah.present)
		compute_proto_keymat(st, PROTO_IPSEC_AH, &st->st_ah, "AH");
	if (st->st_esp.present)
		compute_proto_keymat(st, PROTO_IPSEC_ESP, &st->st_esp, "ESP");
}

/* Decode the variable part of an ID packet (during Quick Mode).
 * This is designed for packets that identify clients, not peers.
 * Rejects 0.0.0.0/32 or IPv6 equivalent because
 * (1) it is wrong and (2) we use this value for inband signalling.
 */
static bool decode_net_id(struct isakmp_ipsec_id *id,
			  pb_stream *id_pbs,
			  ip_subnet *net,
			  const char *which,
			  struct logger *logger)
{
	const struct ip_info *afi = NULL;

	/* Note: the following may be a pointer into static memory
	 * that may be recycled, but only if the type is not known.
	 * That case is disposed of very early -- in the first switch.
	 */
	const char *idtypename = enum_show(&ike_idtype_names, id->isaiid_idtype);

	switch (id->isaiid_idtype) {
	case ID_IPV4_ADDR:
	case ID_IPV4_ADDR_SUBNET:
	case ID_IPV4_ADDR_RANGE:
		afi = &ipv4_info;
		break;
	case ID_IPV6_ADDR:
	case ID_IPV6_ADDR_SUBNET:
	case ID_IPV6_ADDR_RANGE:
		afi = &ipv6_info;
		break;
	case ID_FQDN:
		log_message(RC_COMMENT, logger,
			    "%s type is FQDN", which);
		return TRUE;

	default:
		/* XXX support more */
		log_message(RC_LOG_SERIOUS, logger, "unsupported ID type %s",
			    idtypename);
		/* XXX Could send notification back */
		return FALSE;
	}

	switch (id->isaiid_idtype) {
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
	{
		ip_address temp_address;
		diag_t d = pbs_in_address(id_pbs, &temp_address, afi, "ID address");
		if (d != NULL) {
			log_diag(RC_LOG, logger, &d, "%s", "");
			return false;
		}
		/* i.e., "zero" */
		if (address_eq_any(&temp_address)) {
			ipstr_buf b;
			log_message(RC_LOG_SERIOUS, logger,
				    "%s ID payload %s is invalid (%s) in Quick I1",
				    which, idtypename, ipstr(&temp_address, &b));
			/* XXX Could send notification back */
			return false;
		}
		happy(endtosubnet(&temp_address, net, HERE));
		subnet_buf b;
		dbg("%s is %s", which, str_subnet(net, &b));
		break;
	}

	case ID_IPV4_ADDR_SUBNET:
	case ID_IPV6_ADDR_SUBNET:
	{
		diag_t d;

		ip_address temp_address, temp_mask;
		d = pbs_in_address(id_pbs, &temp_address, afi, "ID address");
		if (d != NULL) {
			log_diag(RC_LOG, logger, &d, "%s", "");
			return false;
		}

		d = pbs_in_address(id_pbs, &temp_mask, afi, "ID mask");
		if (d != NULL) {
			log_diag(RC_LOG, logger, &d, "%s", "");
			return false;
		}

		err_t ughmsg = address_mask_to_subnet(&temp_address, &temp_mask, net);
		if (ughmsg == NULL &&
		    subnet_contains_no_addresses(net))
			/* i.e., ::/128 or 0.0.0.0/32 */
			ughmsg = "subnet contains no addresses";
		if (ughmsg != NULL) {
			log_message(RC_LOG_SERIOUS, logger,
				    "%s ID payload %s bad subnet in Quick I1 (%s)",
				    which, idtypename, ughmsg);
			/* XXX Could send notification back */
			return FALSE;
		}
		subnet_buf buf;
		dbg("%s is subnet %s", which, str_subnet(net, &buf));
		break;
	}

	case ID_IPV4_ADDR_RANGE:
	case ID_IPV6_ADDR_RANGE:
	{
		diag_t d;

		ip_address temp_address_from;
		d = pbs_in_address(id_pbs, &temp_address_from, afi, "ID from address");
		if (d != NULL) {
			log_diag(RC_LOG, logger, &d, "%s", "");
			return false;
		}

		ip_address temp_address_to;
		d = pbs_in_address(id_pbs, &temp_address_to, afi, "ID to address");
		if (d != NULL) {
			log_diag(RC_LOG, logger, &d, "%s", "");
			return false;
		}

		err_t ughmsg = rangetosubnet(&temp_address_from,
					     &temp_address_to, net);
		if (ughmsg == NULL &&
		    subnet_contains_no_addresses(net))
			/* i.e., ::/128 or 0.0.0.0/32 */
			ughmsg = "range contains no addresses";
		if (ughmsg != NULL) {
			ipstr_buf a, b;

			log_message(RC_LOG_SERIOUS, logger,
				    "%s ID payload in Quick I1, %s %s - %s unacceptable: %s",
				    which, idtypename,
				    ipstr(&temp_address_from, &a),
				    ipstr(&temp_address_to, &b),
				    ughmsg);
			return FALSE;
		}
		subnet_buf buf;
		dbg("%s is subnet %s (received as range)", which, str_subnet(net, &buf));
		break;
	}
	}

	/* set the port selector */
	setportof(htons(id->isaiid_port), &net->addr);

	dbg("%s protocol/port is %d/%d", which, id->isaiid_protoid, id->isaiid_port);

	return TRUE;
}

/* like decode, but checks that what is received matches what was sent */
static bool check_net_id(struct isakmp_ipsec_id *id,
			 pb_stream *id_pbs,
			 uint8_t *protoid,
			 uint16_t *port,
			 ip_subnet *net,
			 const char *which,
			 struct logger *logger)
{
	ip_subnet net_temp;
	bool bad_proposal = FALSE;

	if (!decode_net_id(id, id_pbs, &net_temp, which, logger))
		return FALSE;

	if (!samesubnet(net, &net_temp)) {
		subnet_buf subrec;
		subnet_buf subxmt;
		log_message(RC_LOG_SERIOUS, logger,
			    "%s subnet returned doesn't match my proposal - us: %s vs them: %s",
			    which, str_subnet(net, &subxmt),
			    str_subnet(&net_temp, &subrec));
		log_message(RC_LOG_SERIOUS, logger,
			    "Allowing questionable (microsoft) proposal anyway");
		bad_proposal = FALSE;
	}
	if (*protoid != id->isaiid_protoid) {
		log_message(RC_LOG_SERIOUS, logger,
			    "%s peer returned protocol id does not match my proposal - us: %d vs them: %d",
			    which, *protoid, id->isaiid_protoid);
		log_message(RC_LOG_SERIOUS, logger,
			    "Allowing questionable (microsoft) proposal anyway]");
		bad_proposal = FALSE;
	}
	/*
	 * workaround for #802- "our client ID returned doesn't match my proposal"
	 * until such time as bug #849 is properly fixed.
	 */
	if (*port != id->isaiid_port) {
		log_message(RC_LOG_SERIOUS, logger,
			    "%s peer returned port doesn't match my proposal - us: %d vs them: %d",
			    which, *port, id->isaiid_port);
		if (*port != 0 && id->isaiid_port != 1701) {
			log_message(RC_LOG_SERIOUS, logger,
				    "Allowing bad L2TP/IPsec proposal (see bug #849) anyway");
			bad_proposal = FALSE;
		} else {
			bad_proposal = TRUE;
		}
	}

	return !bad_proposal;
}

/* Compute Phase 2 IV.
 * Uses Phase 1 IV from st_iv; puts result in st_new_iv.
 */
void init_phase2_iv(struct state *st, const msgid_t *msgid)
{
	const struct hash_desc *h = st->st_oakley.ta_prf->hasher;
	passert(h != NULL);

	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("last Phase 1 IV:", st->st_v1_ph1_iv);
		DBG_dump_hunk("current Phase 1 IV:", st->st_v1_iv);
	}

	struct crypt_hash *ctx = crypt_hash_init("Phase 2 IV", h,
						 st->st_logger);
	crypt_hash_digest_hunk(ctx, "PH1_IV", st->st_v1_ph1_iv);
	passert(*msgid != 0);
	passert(sizeof(msgid_t) == sizeof(uint32_t));
	msgid_t raw_msgid = htonl(*msgid);
	crypt_hash_digest_thing(ctx, "MSGID", raw_msgid);
	st->st_v1_new_iv = crypt_hash_final_mac(&ctx);
}

static ke_and_nonce_cb quick_outI1_continue;	/* type assertion */

void quick_outI1(struct fd *whack_sock,
		 struct state *isakmp_sa,
		 struct connection *c,
		 lset_t policy,
		 unsigned long try,
		 so_serial_t replacing,
		 struct xfrm_user_sec_ctx_ike *uctx
		 )
{
	struct state *st = ikev1_duplicate_state(isakmp_sa, whack_sock);
	update_state_connection(st, c);
	passert(c != NULL);

	st->st_policy = policy;
	st->st_try = try;

	st->sec_ctx = NULL;
	if (uctx != NULL) {
		st->sec_ctx = clone_thing(*uctx, "sec ctx structure");
		dbg("pending phase 2 with security context \"%s\"",
		    st->sec_ctx->sec_ctx_value);
	}

	st->st_myuserprotoid = c->spd.this.protocol;
	st->st_peeruserprotoid = c->spd.that.protocol;
	st->st_myuserport = c->spd.this.port;
	st->st_peeruserport = c->spd.that.port;

	st->st_v1_msgid.id = generate_msgid(isakmp_sa);
	change_state(st, STATE_QUICK_I1); /* from STATE_UNDEFINED */

	binlog_refresh_state(st);

	/* figure out PFS group, if any */

	if (policy & POLICY_PFS ) {
		/*
		 * Old code called ike_alg_pfsgroup() and that first
		 * checked st->st_policy for POLICY_PFS.  It's assumed
		 * the check was redundant.
		 */
		pexpect((st->st_policy & POLICY_PFS));
		/*
		 * See if pfs_group has been specified for this conn,
		 * use that group.
		 * if not, fallback to old use-same-as-P1 behaviour
		 */
		st->st_pfs_group = ikev1_quick_pfs(c->child_proposals);
		/* otherwise, use the same group as during Phase 1:
		 * since no negotiation is possible, we pick one that is
		 * very likely supported.
		 */
		if (st->st_pfs_group == NULL)
			st->st_pfs_group = isakmp_sa->st_oakley.ta_dh;
	}

	LOG_JAMBUF(RC_LOG, st->st_logger, buf) {
		jam(buf, "initiating Quick Mode %s", prettypolicy(policy));
		if (replacing != SOS_NOBODY) {
			jam(buf, " to replace #%lu", replacing);
		}
		jam(buf, " {using isakmp#%lu msgid:%08" PRIx32 " proposal=",
			isakmp_sa->st_serialno, st->st_v1_msgid.id);
		if (st->st_connection->child_proposals.p != NULL) {
			jam_proposals(buf, st->st_connection->child_proposals.p);
		} else {
			jam(buf, "defaults");
		}
		jam(buf, " pfsgroup=");
		if ((policy & POLICY_PFS) != LEMPTY) {
			jam_string(buf, st->st_pfs_group->common.fqn);
		} else {
			jam_string(buf, "no-pfs");
		}
		jam(buf, "}");
	}

	/* save for post crypto logging */
	st->st_ipsec_pred = replacing;

	if (policy & POLICY_PFS) {
		submit_ke_and_nonce(st, st->st_pfs_group,
				    quick_outI1_continue,
				    "quick_outI1 KE");
	} else {
		submit_ke_and_nonce(st, NULL /* no-nonce*/,
				    quick_outI1_continue,
				    "quick_outI1 KE");
	}
}

static ke_and_nonce_cb quick_outI1_continue_tail;	/* type assertion */

static stf_status quick_outI1_continue(struct state *st,
				       struct msg_digest *unused_md,
				       struct dh_local_secret *local_secret,
				       chunk_t *nonce)
{
	dbg("quick_outI1_continue for #%lu: calculated ke+nonce, sending I1",
	    st->st_serialno);

	pexpect(unused_md == NULL); /* no packet */
	passert(st != NULL);

	/*
	 * XXX: Read and weep:
	 *
	 * - when the tail function fails, ST is leaked
	 *
	 * - there is no QUICK I0->I1 state transition
	 *
	 * - compilete_v1_state_transition() isn't called
	 *
	 * - trying to call compilete_v1_state_transition() digs a
	 *   hole - as it assumes md (perhaps this is why the function
	 *   wasn't called)
	 */
	stf_status e = quick_outI1_continue_tail(st, unused_md, local_secret, nonce);
	if (e == STF_INTERNAL_ERROR) {
		log_state(RC_LOG_SERIOUS, st,
			  "%s: quick_outI1_tail() failed with STF_INTERNAL_ERROR",
			  __func__);
	}
	/*
	 * This way all the broken behaviour is ignored.
	 */
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

static stf_status quick_outI1_continue_tail(struct state *st,
					    struct msg_digest *unused_md,
					    struct dh_local_secret *local_secret,
					    chunk_t *nonce)
{
	dbg("quick_outI1_continue for #%lu: calculated ke+nonce, sending I1",
	    st->st_serialno);

	pexpect(unused_md == NULL); /* no packet */
	passert(st != NULL);

	struct state *isakmp_sa = state_with_serialno(st->st_clonedfrom);
	struct connection *c = st->st_connection;
	pb_stream rbody;
	bool has_client = c->spd.this.has_client || c->spd.that.has_client ||
			  c->spd.this.protocol != 0 || c->spd.that.protocol != 0 ||
			  c->spd.this.port != 0 || c->spd.that.port != 0;

	if (isakmp_sa == NULL) {
		/* phase1 state got deleted while cryptohelper was working */
		log_state(RC_LOG_SERIOUS, st,
			  "phase2 initiation failed because parent ISAKMP #%lu is gone",
			  st->st_clonedfrom);
		return STF_FATAL;
	}

	if (isakmp_sa->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
		/* Duplicate nat_traversal status in new state */
		st->hidden_variables.st_nat_traversal =
			isakmp_sa->hidden_variables.st_nat_traversal;
		if (LHAS(isakmp_sa->hidden_variables.st_nat_traversal,
			 NATED_HOST))
			has_client = TRUE;
		v1_maybe_natify_initiator_endpoints(st, HERE);
	} else {
		st->hidden_variables.st_nat_traversal = LEMPTY;
	}

	/* set up reply */
	reply_stream = open_pbs_out("reply packet",reply_buffer, sizeof(reply_buffer), st->st_logger);

	/* HDR* out */
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
					  ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_QUICK,
			.isa_msgid = st->st_v1_msgid.id,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
		};
		hdr.isa_ike_initiator_spi = st->st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = st->st_ike_spis.responder;
		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* HASH(1) -- create and note space to be filled later */
	struct v1_hash_fixup hash_fixup;
	if (!emit_v1_HASH(V1_HASH_1, "outI1",
			  IMPAIR_v1_QUICK_EXCHANGE,
			  st, &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* SA out */

	/* Emit SA payload based on a subset of the policy bits.
	 * POLICY_COMPRESS is considered iff we can do IPcomp.
	 */
	{
		lset_t pm = st->st_policy & (POLICY_ENCRYPT |
					     POLICY_AUTHENTICATE |
					     can_do_IPcomp ? POLICY_COMPRESS : 0);
		dbg("emitting quick defaults using policy %s",
		     bitnamesof(sa_policy_bit_names, pm));

		if (!ikev1_out_sa(&rbody,
				  &ipsec_sadb[pm >> POLICY_IPSEC_SHIFT],
				  st, FALSE, FALSE)) {
			return STF_INTERNAL_ERROR;
		}
	}

	{
		/* Ni out */
		if (!ikev1_ship_nonce(&st->st_ni, nonce, &rbody, "Ni")) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* [ KE ] out (for PFS) */
	if (st->st_pfs_group != NULL) {
		if (!ikev1_ship_KE(st, local_secret, &st->st_gi, &rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* [ IDci, IDcr ] out */
	if (has_client) {
		/* IDci (we are initiator), then IDcr (peer is responder) */
		if (!emit_subnet_id(&c->spd.this.client,
				    st->st_myuserprotoid,
				    st->st_myuserport, &rbody) ||
		    !emit_subnet_id(&c->spd.that.client,
				    st->st_peeruserprotoid,
				    st->st_peeruserport, &rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	if ((st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA) &&
	    !(st->st_policy & POLICY_TUNNEL) &&
	    LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		/** Send NAT-OA if our address is NATed */
		if (!nat_traversal_add_natoa(&rbody, st, true /* initiator */)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* finish computing  HASH(1), inserting it in output */
	fixup_v1_HASH(st, &hash_fixup, st->st_v1_msgid.id, rbody.cur);

	/* encrypt message, except for fixed part of header */

	init_phase2_iv(isakmp_sa, &st->st_v1_msgid.id);
	restore_new_iv(st, isakmp_sa->st_v1_new_iv);

	if (!ikev1_encrypt_message(&rbody, st)) {
		return STF_INTERNAL_ERROR;
	}

	record_and_send_v1_ike_msg(st, &reply_stream,
		"reply packet from quick_outI1");

	delete_event(st);
	clear_retransmits(st);
	start_retransmits(st);

	if (st->st_ipsec_pred == SOS_NOBODY) {
		log_state(RC_NEW_V1_STATE + st->st_state->kind, st,
			  "%s", st->st_state->story);
	} else {
		log_state(RC_NEW_V1_STATE + st->st_state->kind, st,
			  "%s, to replace #%lu",
			  st->st_state->story,
			  st->st_ipsec_pred);
		st->st_ipsec_pred = SOS_NOBODY;
	}

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
 * - quick_inI1_outR1_tail does the rest of the job
 *   XXX: why the function split?
 *
 * At the end of quick_inI1_outR1_tail, we have all the info we need, but we
 * haven't done any nonce generation or DH that we might need
 * to do, so that are two crypto continuations that do this work,
 * they are:
 *    quick_inI1_outR1_continue1 -- called after NONCE/KE
 *    quick_inI1_outR1_continue2 -- called after DH (if PFS)
 *
 * we have to call nonce/ke and DH if we are doing PFS.
 */

/* hold anything we can handle of a Phase 2 ID */
struct p2id {
	ip_subnet net;
	uint8_t proto;
	uint16_t port;
};

struct verify_oppo_bundle {
	bool failure_ok;	/* if true, quick_inI1_outR1_tail will try
				 * other things on DNS failure
				 */
	struct msg_digest *md;
	struct p2id my, peers;
	struct crypt_mac new_iv;
	/* int whackfd; */	/* not needed because we are Responder */
};

static stf_status quick_inI1_outR1_tail(struct verify_oppo_bundle *b);

stf_status quick_inI1_outR1(struct state *p1st, struct msg_digest *md)
{
	passert(p1st != NULL && p1st == md->st);
	struct connection *c = p1st->st_connection;
	struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];
	struct verify_oppo_bundle b;

	/* [ IDci, IDcr ] in
	 * We do this now (probably out of physical order) because
	 * we wish to select the correct connection before we consult
	 * it for policy.
	 */

	if (id_pd != NULL) {
		struct payload_digest *IDci = id_pd->next;

		/* ??? we are assuming IPSEC_DOI */

		/* IDci (initiator is peer) */

		if (!decode_net_id(&id_pd->payload.ipsec_id, &id_pd->pbs,
				   &b.peers.net, "peer client", p1st->st_logger))
			return STF_FAIL + INVALID_ID_INFORMATION;

		/* Hack for MS 818043 NAT-T Update.
		 *
		 * <http://support.microsoft.com/kb/818043>
		 * "L2TP/IPsec NAT-T update for Windows XP and Windows 2000"
		 * This update is has a bug.  We choose to work around that
		 * bug rather than failing to interoperate.
		 * As to what the bug is, Paul says:
		 * "I believe on rekey, it sent a bogus subnet or wrong type of ID."
		 * ??? needs more complete description.
		 */
		if (id_pd->payload.ipsec_id.isaiid_idtype == ID_FQDN) {
			log_state(RC_LOG_SERIOUS, p1st,
				  "Applying workaround for MS-818043 NAT-T bug");
			zero(&b.peers.net);
			happy(endtosubnet(&c->spd.that.host_addr,
					  &b.peers.net, HERE));
		}
		/* End Hack for MS 818043 NAT-T Update */

		b.peers.proto = id_pd->payload.ipsec_id.isaiid_protoid;
		b.peers.port = id_pd->payload.ipsec_id.isaiid_port;
		update_selector_hport(&b.peers.net, b.peers.port);

		/* IDcr (we are responder) */

		if (!decode_net_id(&IDci->payload.ipsec_id, &IDci->pbs,
				   &b.my.net, "our client", p1st->st_logger))
			return STF_FAIL + INVALID_ID_INFORMATION;

		b.my.proto = IDci->payload.ipsec_id.isaiid_protoid;
		b.my.port = IDci->payload.ipsec_id.isaiid_port;
		update_selector_hport(&b.my.net, b.my.port);

		/*
		 * if there is a NATOA payload, then use it as
		 *    &st->st_connection->spd.that.client, if the type
		 * of the ID was FQDN
		 *
		 * we actually do NATOA calculation again later on,
		 * but we need the info here, and we don't have a state
		 * to store it in until after we've done the authorization steps.
		 */
		if ((p1st->hidden_variables.st_nat_traversal &
		     NAT_T_DETECTED) &&
		    (p1st->hidden_variables.st_nat_traversal &
		     NAT_T_WITH_NATOA) &&
		    (id_pd->payload.ipsec_id.isaiid_idtype == ID_FQDN)) {
			struct hidden_variables hv;
			char idfqdn[IDTOA_BUF];
			size_t idlen = pbs_room(&IDci->pbs);

			if (idlen >= sizeof(idfqdn)) {
				/* ??? truncation seems rude and dangerous */
				idlen = sizeof(idfqdn) - 1;
			}
			/* ??? what should happen if fqdn contains '\0'? */
			memcpy(idfqdn, IDci->pbs.cur, idlen);
			idfqdn[idlen] = '\0';

			hv = p1st->hidden_variables;
			nat_traversal_natoa_lookup(md, &hv, p1st->st_logger);

			if (address_is_specified(&hv.st_nat_oa)) {
				endtosubnet(&hv.st_nat_oa, &b.peers.net, HERE);
				subnet_buf buf;
				log_state(RC_LOG_SERIOUS, p1st,
					  "IDci was FQDN: %s, using NAT_OA=%s %d as IDci",
					  idfqdn, str_subnet(&b.peers.net, &buf),
					  isanyaddr(&hv.st_nat_oa)/*XXX: always 0?*/);
			}
		}
	} else {
		/* implicit IDci and IDcr: peer and self */
		if (endpoint_type(&c->spd.this.host_addr) !=
		    endpoint_type(&c->spd.that.host_addr))
			return STF_FAIL;

		happy(endtosubnet(&c->spd.this.host_addr, &b.my.net, HERE));
		happy(endtosubnet(&c->spd.that.host_addr, &b.peers.net, HERE));
		b.peers.proto = b.my.proto = 0;
		b.peers.port = b.my.port = 0;
	}
	b.md = md;
	save_new_iv(p1st, b.new_iv);

	/*
	 * FIXME - DAVIDM
	 * "b" is on the stack,  for OPPO  tunnels this will be bad, in
	 * quick_inI1_outR1_start_query it saves a pointer to it before
	 * a crypto (async op).
	 */
	return quick_inI1_outR1_tail(&b);
}


/* forward definitions */
static stf_status quick_inI1_outR1_continue12_tail(struct state *st, struct msg_digest *md);

static ke_and_nonce_cb quick_inI1_outR1_continue1;	/* forward decl and type assertion */
static dh_shared_secret_cb quick_inI1_outR1_continue2;	/* forward decl and type assertion */

static stf_status quick_inI1_outR1_tail(struct verify_oppo_bundle *b)
{
	struct msg_digest *md = b->md;
	struct state *const p1st = md->st;
	struct connection *c = p1st->st_connection;
	ip_subnet *our_net = &b->my.net,
	*peers_net = &b->peers.net;
	struct hidden_variables hv;

	{
		/*
		 * XXX: ADDRESS/MASK:PROTOCOL/PORT - is a pretty
		 * messed up way of logging things.  Should at least
		 * follow SUB -%d-> SUB format.
		 *
		 * XXX: why is protocol always logged as an integer.
		 */
		subnet_buf s1, d1;
		log_state(RC_LOG, p1st, "the peer proposed: %s:%d/%d -> %s:%d/%d",
			  str_subnet(our_net, &s1), c->spd.this.protocol, c->spd.this.port,
			  str_subnet(peers_net, &d1), c->spd.that.protocol, c->spd.that.port);
	}

	/* Now that we have identities of client subnets, we must look for
	 * a suitable connection (our current one only matches for hosts).
	 */
	{
		struct connection *p = find_client_connection(c,
							      our_net, peers_net,
							      b->my.proto,
							      b->my.port,
							      b->peers.proto,
							      b->peers.port);

		if ((p1st->hidden_variables.st_nat_traversal &
		      NAT_T_DETECTED) &&
		     !(p1st->st_policy & POLICY_TUNNEL) &&
		     p == NULL) {
			p = c;
			connection_buf cib;
			dbg("using something (we hope the IP we or they are NAT'ed to) for transport mode connection "PRI_CONNECTION"",
			    pri_connection(p, &cib));
		}

		if (p == NULL) {
			/* This message occurs in very puzzling circumstances
			 * so we must add as much information and beauty as we can.
			 */
			struct end
				me = c->spd.this,
				he = c->spd.that;
			char buf[2 * sizeof(subnet_buf) + 2 * sizeof(address_buf) + 2 *
				 sizeof(id_buf) + 2 * sizeof(address_buf) + 12];                       /* + 12 for separating */
			size_t l;

			me.client = *our_net;
			me.has_client = !subnetisaddr(our_net, &me.host_addr);
			me.protocol = b->my.proto;
			me.port = b->my.port;

			he.client = *peers_net;
			he.has_client = !subnetisaddr(peers_net, &he.host_addr);
			he.protocol = b->peers.proto;
			he.port = b->peers.port;

			l = format_end(buf, sizeof(buf), &me, NULL, TRUE,
				       LEMPTY, oriented(*c));
			snprintf(buf + l, sizeof(buf) - l, "...");
			l += strlen(buf + l);
			(void)format_end(buf + l, sizeof(buf) - l, &he, NULL,
					 FALSE, LEMPTY, oriented(*c));
			log_state(RC_LOG, p1st,
				  "cannot respond to IPsec SA request because no connection is known for %s",
				  buf);
			return STF_FAIL + INVALID_ID_INFORMATION;
		}

		/* did we find a better connection? */
		if (p != c) {
			/* We've got a better connection: it can support the
			 * specified clients.  But it may need instantiation.
			 */
			if (p->kind == CK_TEMPLATE) {
				/* Plain Road Warrior because no OPPO for IKEv1
				 * instantiate, carrying over authenticated peer ID
				 */
				p = rw_instantiate(p, &c->spd.that.host_addr,
						   peers_net,
						   &c->spd.that.id);
			}
			/* temporarily bump up cur_debugging to get "using..." message
			 * printed if we'd want it with new connection.
			 */
			{
				lset_t old_cur_debugging = cur_debugging;

				set_debugging(lmod(cur_debugging, p->extra_debugging));
				connection_buf cib;
				dbg("using connection "PRI_CONNECTION"",
				    pri_connection(p, &cib));
				set_debugging(old_cur_debugging);
			}
			c = p;
		}

		/* fill in the client's true ip address/subnet */
		dbg("client: %s  port wildcard: %s  virtual: %s",
		    bool_str(c->spd.that.has_client),
		    bool_str(c->spd.that.has_port_wildcard),
		    bool_str(is_virtual_connection(c)));

		/* fill in the client's true port */
		if (c->spd.that.has_port_wildcard) {
			int port = htons(b->peers.port);

			setportof(port, &c->spd.that.host_addr);
			setportof(port, &c->spd.that.client.addr);

			c->spd.that.port = b->peers.port;
			c->spd.that.has_port_wildcard = FALSE;
		}

		if (is_virtual_connection(c)) {
			char cthat[END_BUF];

			c->spd.that.client = *peers_net;
			c->spd.that.has_client = true;
			virtual_ip_delref(&c->spd.that.virt, HERE);

			if (subnetishost(peers_net) &&
			    addrinsubnet(&c->spd.that.host_addr, peers_net)) {
				c->spd.that.has_client = FALSE;
			}

			format_end(cthat, sizeof(cthat), &c->spd.that, NULL,
				   TRUE, LEMPTY, oriented(*c));
			dbg("setting phase 2 virtual values to %s", cthat);
		}
	}

	passert((p1st->st_policy & POLICY_PFS) == 0 ||
		p1st->st_pfs_group != NULL);

	/* now that we are sure of our connection, create our new state, and
	 * do any asynchronous cryptographic operations that we may need to
	 * make it all work.
	 */

	hv = p1st->hidden_variables;
	if ((hv.st_nat_traversal & NAT_T_DETECTED) &&
	    (hv.st_nat_traversal & NAT_T_WITH_NATOA))
		nat_traversal_natoa_lookup(md, &hv, p1st->st_logger);

	/* create our new state */
	{
		struct state *const st = ikev1_duplicate_state(p1st, null_fd);

		/* first: fill in missing bits of our new state object
		 * note: we don't copy over st_peer_pubkey, the public key
		 * that authenticated the ISAKMP SA.  We only need it in this
		 * routine, so we can "reach back" to p1st to get it.
		 */
		if (st->st_connection != c) {
			update_state_connection(st, c);
		}

		st->st_try = 0; /* not our job to try again from start */

		st->st_v1_msgid.id = md->hdr.isa_msgid;

		restore_new_iv(st, b->new_iv);

		switch_md_st(md, st, HERE);	/* feed back new state */

		st->st_peeruserprotoid = b->peers.proto;
		st->st_peeruserport = b->peers.port;
		st->st_myuserprotoid = b->my.proto;
		st->st_myuserport = b->my.port;

		change_state(st, STATE_QUICK_R0);

		binlog_refresh_state(st);

		/* copy hidden variables (possibly with changes) */
		st->hidden_variables = hv;

		/* copy the connection's
		 * IPSEC policy into our state.  The ISAKMP policy is water under
		 * the bridge, I think.  It will reflect the ISAKMP SA that we
		 * are using.
		 */
		st->st_policy = (p1st->st_policy & POLICY_ID_AUTH_MASK) |
				(c->policy & ~POLICY_ID_AUTH_MASK);

		if (p1st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
			/* ??? this partially overwrites what was done via hv */
			st->hidden_variables.st_nat_traversal =
				p1st->hidden_variables.st_nat_traversal;
			nat_traversal_change_port_lookup(md, md->st);
			v1_maybe_natify_initiator_endpoints(st, HERE);
		} else {
			/* ??? this partially overwrites what was done via hv */
			st->hidden_variables.st_nat_traversal = LEMPTY;
		}

		passert(st->st_connection != NULL);
		passert(st->st_connection == c);

		/* process SA in */
		{
			struct payload_digest *const sapd =
				md->chain[ISAKMP_NEXT_SA];
			pb_stream in_pbs = sapd->pbs;

			/* parse and accept body, setting variables, but not forming
			 * our reply. We'll make up the reply later on.
			 *
			 * note that we process the copy of the pbs,
			 * so that we can process it again in the
			 * tail(). XXX: Huh, this is the tail
			 * function!
			 *
			 */
			st->st_pfs_group = &unset_group;
			RETURN_STF_FAILURE(parse_ipsec_sa_body(&in_pbs,
							       &sapd->payload.
							       sa,
							       NULL,
							       FALSE, st));
		}

		/* Ni in */
		RETURN_STF_FAILURE(accept_v1_nonce(st->st_logger, md, &st->st_ni, "Ni"));

		/* [ KE ] in (for PFS) */
		RETURN_STF_FAILURE(accept_PFS_KE(st, md, &st->st_gi,
						 "Gi", "Quick Mode I1"));

		passert(st->st_pfs_group != &unset_group);

		passert(st->st_connection != NULL);

		submit_ke_and_nonce(st, st->st_pfs_group/*possibly-null*/,
				    quick_inI1_outR1_continue1,
				    "quick_inI1_outR1_tail");

		passert(st->st_connection != NULL);
		return STF_SUSPEND;
	}
}

static stf_status quick_inI1_outR1_continue1(struct state *st,
					     struct msg_digest *md,
					     struct dh_local_secret *local_secret,
					     chunk_t *nonce)
{
	dbg("quick_inI1_outR1_cryptocontinue1 for #%lu: calculated ke+nonce, calculating DH",
	    st->st_serialno);

	passert(st->st_connection != NULL);

	/* we always calculate a nonce */
	unpack_nonce(&st->st_nr, nonce);

	if (st->st_pfs_group != NULL) {
		/* PFS is on: do a new DH */
		unpack_KE_from_helper(st, local_secret, &st->st_gr);
		submit_dh_shared_secret(st, st->st_gi,
					quick_inI1_outR1_continue2,
					HERE);
		/*
		 * XXX: Since more crypto has been requested, MD needs
		 * to be re suspended.  If the original crypto request
		 * did everything this wouldn't be needed.
		 */
		return STF_SUSPEND;
	} else {
		/*
		 * but if PFS is off, we don't do a second DH, so just
		 * call the continuation with NULL struct
		 * pluto_crypto_req *
		 */
		return quick_inI1_outR1_continue12_tail(st, md);
	}
}

static stf_status quick_inI1_outR1_continue2(struct state *st,
					     struct msg_digest *md)
{
	dbg("quick_inI1_outR1_cryptocontinue2 for #%lu: calculated DH, sending R1",
	    st->st_serialno);

	passert(st->st_connection != NULL);
	passert(md != NULL);
	return quick_inI1_outR1_continue12_tail(st, md);
}

/*
 * Spit out the IPsec ID payload we got.
 *
 * We go to some trouble to use out_struct so NP
 * for adjacent packets is handled correctly.
 */
static bool echo_id(pb_stream *outs,
		    const struct payload_digest *const id_pd)
{
	struct isakmp_ipsec_id id = id_pd->payload.ipsec_id;
	id.isaiid_np = 0;
	/* We leave .isaiid_length: It will be updated to the same value */

	uint8_t *hs = outs->cur;
	pb_stream id_body;
	if (!out_struct(&id, &isakmp_ipsec_identification_desc, outs, &id_body))
		return FALSE;
	ptrdiff_t hl = id_body.cur - hs;	/* length of header */

	if (!out_raw(id_pd->pbs.start + hl, pbs_room(&id_pd->pbs) - hl, &id_body, "ID body"))
		return FALSE;

	close_output_pbs(&id_body);
	return TRUE;
}

static stf_status quick_inI1_outR1_continue12_tail(struct state *st, struct msg_digest *md)
{
	struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];
	struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];

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
	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, TRUE,
				       &reply_stream, reply_buffer, sizeof(reply_buffer),
				       &rbody, st->st_logger);

	struct v1_hash_fixup hash_fixup;
	if (!emit_v1_HASH(V1_HASH_2, "quick inR1 outI2",
			  IMPAIR_v1_QUICK_EXCHANGE,
			  st, &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	passert(st->st_connection != NULL);

	pb_stream r_sa_pbs;

	{
		struct isakmp_sa sa = {
			.isasa_doi = ISAKMP_DOI_IPSEC,
		};
		if (!out_struct(&sa, &isakmp_sa_desc, &rbody, &r_sa_pbs))
			return STF_INTERNAL_ERROR;
	}

	/* parse and accept body, this time recording our reply */
	RETURN_STF_FAILURE(parse_ipsec_sa_body(&sapd->pbs,
					       &sapd->payload.sa,
					       &r_sa_pbs,
					       FALSE, st));

	passert(st->st_pfs_group != &unset_group);

	if ((st->st_policy & POLICY_PFS) && st->st_pfs_group == NULL) {
		log_state(RC_LOG_SERIOUS, st,
			  "we require PFS but Quick I1 SA specifies no GROUP_DESCRIPTION");
		return STF_FAIL + NO_PROPOSAL_CHOSEN; /* ??? */
	}

	log_state(RC_LOG, st,
		  "responding to Quick Mode proposal {msgid:%08" PRIx32 "}",
		  st->st_v1_msgid.id);
	{
		char instbuf[END_BUF];
		const struct connection *c = st->st_connection;
		const struct spd_route *sr = &c->spd;

		format_end(instbuf, sizeof(instbuf), &sr->this, &sr->that,
			   TRUE, LEMPTY, oriented(*c));
		log_state(RC_LOG, st, "    us: %s", instbuf);

		format_end(instbuf, sizeof(instbuf), &sr->that, &sr->this,
			   FALSE, LEMPTY, oriented(*c));
		log_state(RC_LOG, st, "  them: %s", instbuf);
	}

	/**** finish reply packet: Nr [, KE ] [, IDci, IDcr ] ****/

	{
#ifdef IMPAIR_UNALIGNED_R1_MSG
		const char *padstr = getenv("PLUTO_UNALIGNED_R1_MSG");
#endif
		/* Nr out */
		if (!ikev1_justship_nonce(&st->st_nr, &rbody, "Nr"))
			return STF_INTERNAL_ERROR;

#ifdef IMPAIR_UNALIGNED_R1_MSG
		if (padstr != NULL) {
			unsigned long padsize;
			err_t ugh = ttoulb(padstr, 0, 10, 100, &padsize);
			pb_stream vid_pbs;

			if (ugh != NULL) {
				log_state(RC_LOG, st, "$PLUTO_UNALIGNED_R1_MSG malformed: %s; pretending it is 3", ugh);
				padsize = 3;
			}

			log_state(RC_LOG, st, "inserting fake VID payload of %lu size",
				  padsize);

			if (st->st_pfs_group != NULL)
				np = ISAKMP_NEXT_KE;
			else if (id_pd != NULL)
				np = ISAKMP_NEXT_ID;
			else
				np = ISAKMP_NEXT_NONE;

			if (!ikev1_out_generic(np,
					 &isakmp_vendor_id_desc, &rbody,
					 &vid_pbs))
				return STF_INTERNAL_ERROR;

			if (!out_zero(padsize, &vid_pbs, "Filler VID"))
				return STF_INTERNAL_ERROR;

			close_output_pbs(&vid_pbs);
		}
#endif
	}

	/* [ KE ] out (for PFS) */
	if (st->st_pfs_group != NULL && st->st_gr.ptr != NULL) {
		if (!ikev1_justship_KE(st->st_logger, &st->st_gr, &rbody))
			return STF_INTERNAL_ERROR;
	}

	/* [ IDci, IDcr ] out */
	if (id_pd != NULL) {
		passert(id_pd->next->next == NULL);	/* exactly two */
		if (!echo_id(&rbody, id_pd) ||
		    !echo_id(&rbody, id_pd->next))
			return STF_INTERNAL_ERROR;
	}

	/* Compute reply HASH(2) and insert in output */
	fixup_v1_HASH(st, &hash_fixup, st->st_v1_msgid.id, rbody.cur);

	/* Derive new keying material */
	compute_keymats(st);

	/* Tell the kernel to establish the new inbound SA
	 * (unless the commit bit is set -- which we don't support).
	 * We do this before any state updating so that
	 * failure won't look like success.
	 */
#ifdef USE_XFRM_INTERFACE
	struct connection *c = st->st_connection;
	if (c->xfrmi != NULL && c->xfrmi->if_id != 0)
		if (add_xfrmi(c, st->st_logger))
			return STF_FATAL;
#endif
	if (!install_inbound_ipsec_sa(st))
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */

	/* we only audit once for IPsec SA's, we picked the inbound SA */
	linux_audit_conn(st, LAK_CHILD_START);

	/* encrypt message, except for fixed part of header */
	if (!ikev1_encrypt_message(&rbody, st)) {
		delete_ipsec_sa(st);
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */
	}

	dbg("finished processing quick inI1");
	return STF_OK;
}

/* Handle (the single) message from Responder in Quick Mode.
 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ] -->
 * HDR*, HASH(3)
 * (see RFC 2409 "IKE" 5.5)
 * Installs inbound and outbound IPsec SAs, routing, etc.
 */
static stf_status quick_inR1_outI2_tail(struct state *st, struct msg_digest *md);

static dh_shared_secret_cb quick_inR1_outI2_continue;	/* forward decl and type assertion */

stf_status quick_inR1_outI2(struct state *st, struct msg_digest *md)
{
	/* SA in */
	{
		struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];

		RETURN_STF_FAILURE(parse_ipsec_sa_body(&sa_pd->pbs,
						       &sa_pd->payload.sa,
						       NULL, TRUE, st));
	}

	/* Nr in */
	RETURN_STF_FAILURE(accept_v1_nonce(st->st_logger, md, &st->st_nr, "Nr"));

	/* [ KE ] in (for PFS) */
	RETURN_STF_FAILURE(accept_PFS_KE(st, md, &st->st_gr, "Gr",
					 "Quick Mode R1"));

	if (st->st_pfs_group != NULL) {
		/* set up DH calculation */
		submit_dh_shared_secret(st, st->st_gr,
					quick_inR1_outI2_continue,
					HERE);
		return STF_SUSPEND;
	} else {
		/* just call the tail function */
		return quick_inR1_outI2_tail(st, md);
	}
}

static stf_status quick_inR1_outI2_continue(struct state *st,
					    struct msg_digest *md)
{
	dbg("quick_inR1_outI2_continue for #%lu: calculated ke+nonce, calculating DH",
	    st->st_serialno);

	passert(st->st_connection != NULL);
	passert(md != NULL);
	return quick_inR1_outI2_tail(st, md);
}

stf_status quick_inR1_outI2_tail(struct state *st, struct msg_digest *md)
{
	struct connection *c = st->st_connection;

	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, TRUE,
				       &reply_stream, reply_buffer, sizeof(reply_buffer),
				       &rbody, st->st_logger);

	if ((st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
	    (st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA))
		nat_traversal_natoa_lookup(md, &st->hidden_variables, st->st_logger);

	/* [ IDci, IDcr ] in; these must match what we sent */

	{
		struct payload_digest *const IDci = md->chain[ISAKMP_NEXT_ID];
		struct payload_digest *IDcr;

		if (IDci != NULL) {
			/* ??? we are assuming IPSEC_DOI */

			/* IDci (we are initiator) */
			if (!check_net_id(&IDci->payload.ipsec_id, &IDci->pbs,
					  &st->st_myuserprotoid,
					  &st->st_myuserport,
					  &st->st_connection->spd.this.client,
					  "our client", st->st_logger))
				return STF_FAIL + INVALID_ID_INFORMATION;

			/* we checked elsewhere that we got two of them */
			IDcr = IDci->next;
			passert(IDcr != NULL);

			/* IDcr (responder is peer) */

			if (!check_net_id(&IDcr->payload.ipsec_id, &IDcr->pbs,
					  &st->st_peeruserprotoid,
					  &st->st_peeruserport,
					  &st->st_connection->spd.that.client,
					  "peer client", st->st_logger))
				return STF_FAIL + INVALID_ID_INFORMATION;

			/*
			 * if there is a NATOA payload, then use it as
			 *    &st->st_connection->spd.that.client, if the type
			 * of the ID was FQDN
			 */
			if ((st->hidden_variables.st_nat_traversal &
			     NAT_T_DETECTED) &&
			    (st->hidden_variables.st_nat_traversal &
			     NAT_T_WITH_NATOA) &&
			    IDcr->payload.ipsec_id.isaiid_idtype == ID_FQDN) {
				char idfqdn[IDTOA_BUF];
				size_t idlen = pbs_room(&IDcr->pbs);

				if (idlen >= sizeof(idfqdn)) {
					/* ??? truncation seems rude and dangerous */
					idlen = sizeof(idfqdn) - 1;
				}
				/* ??? what should happen if fqdn contains '\0'? */
				memcpy(idfqdn, IDcr->pbs.cur, idlen);
				idfqdn[idlen] = '\0';

				endtosubnet(&st->hidden_variables.st_nat_oa,
					    &st->st_connection->spd.that.client,
					    HERE);
				subnet_buf buf;
				log_state(RC_LOG_SERIOUS, st,
					  "IDcr was FQDN: %s, using NAT_OA=%s as IDcr",
					  idfqdn,
					  str_subnet(&st->st_connection->spd.that.client, &buf));
			}
		} else {
			/* no IDci, IDcr: we must check that the defaults match our proposal */
			if (!subnetisaddr(&c->spd.this.client,
					  &c->spd.this.host_addr) ||
			    !subnetisaddr(&c->spd.that.client,
					  &c->spd.that.host_addr)) {
				log_state(RC_LOG_SERIOUS, st,
					  "IDci, IDcr payloads missing in message but default does not match proposal");
				return STF_FAIL + INVALID_ID_INFORMATION;
			}
		}
	}

	/* ??? We used to copy the accepted proposal into the state, but it was
	 * never used.  From sa_pd->pbs.start, length pbs_room(&sa_pd->pbs).
	 */

	/**************** build reply packet HDR*, HASH(3) ****************/

	/* HDR* out done */

	/* HASH(3) out -- sometimes, we add more content */
	{
		struct v1_hash_fixup hash_fixup;

#ifdef IMPAIR_UNALIGNED_I2_MSG
		{
			const char *padstr = getenv("PLUTO_UNALIGNED_I2_MSG");

			if (padstr != NULL) {
				unsigned long padsize;
				err_t ugh = ttoulb(padstr, 0, 10, 100, &padsize)
				pb_stream vid_pbs;

				if (ugh != NULL) {
					log_state(RC_LOG, st, "$PLUTO_UNALIGNED_I2_MSG malformed: %s; pretending it is 3",
						  ugh);
					padsize = 3;
				}

				log_state(RC_LOG, st,
					  "inserting fake VID payload of %u size",
					  padsize);
				START_HASH_PAYLOAD_NO_R_HASH_START(rbody,
								   ISAKMP_NEXT_VID);

				if (!ikev1_out_generic(ISAKMP_NEXT_NONE,
						 &isakmp_vendor_id_desc,
						 &rbody, &vid_pbs))
					return STF_INTERNAL_ERROR;

				if (!out_zero(padsize, &vid_pbs, "Filler VID"))
					return STF_INTERNAL_ERROR;

				close_output_pbs(&vid_pbs);
			} else {
				START_HASH_PAYLOAD(rbody,
						   ISAKMP_NEXT_NONE);
			}
		}
#else
		if (!emit_v1_HASH(V1_HASH_3, "quick_inR1_outI2",
				  IMPAIR_v1_QUICK_EXCHANGE, st, &hash_fixup, &rbody)) {
			return STF_INTERNAL_ERROR;
		}
#endif

		fixup_v1_HASH(st, &hash_fixup, st->st_v1_msgid.id, NULL);
	}

	/* Derive new keying material */
	compute_keymats(st);

	/* Tell the kernel to establish the inbound, outbound, and routing part
	 * of the new SA (unless the commit bit is set -- which we don't support).
	 * We do this before any state updating so that
	 * failure won't look like success.
	 */
#ifdef USE_XFRM_INTERFACE
	if (c->xfrmi != NULL && c->xfrmi->if_id != 0)
		if (add_xfrmi(c, st->st_logger))
			return STF_FATAL;
#endif
	if (!install_ipsec_sa(st, TRUE))
		return STF_INTERNAL_ERROR;

	/* encrypt message, except for fixed part of header */

	if (!ikev1_encrypt_message(&rbody, st)) {
		delete_ipsec_sa(st);
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */
	}

	set_newest_ipsec_sa("inR1_outI2", st);

	if (dpd_init(st) != STF_OK) {
		delete_ipsec_sa(st);
		return STF_FAIL;
	}

	return STF_OK;
}

/* Handle last message of Quick Mode.
 * HDR*, HASH(3) -> done
 * (see RFC 2409 "IKE" 5.5)
 * Installs outbound IPsec SAs, routing, etc.
 */
stf_status quick_inI2(struct state *st, struct msg_digest *md UNUSED)
{
	/* Tell the kernel to establish the outbound and routing part of the new SA
	 * (the previous state established inbound)
	 * (unless the commit bit is set -- which we don't support).
	 * We do this before any state updating so that
	 * failure won't look like success.
	 */
#ifdef USE_XFRM_INTERFACE
	struct connection *c = st->st_connection;
	if (c->xfrmi != NULL && c->xfrmi->if_id != 0)
		if (add_xfrmi(c, st->st_logger))
			return STF_FATAL;
#endif
	if (!install_ipsec_sa(st, FALSE))
		return STF_INTERNAL_ERROR;

	set_newest_ipsec_sa("inI2", st);

	update_iv(st);  /* not actually used, but tidy */

	/*
	 * If we have dpd delay and dpdtimeout set, then we are doing DPD
	 * on this conn, so initialize it
	 */
	if (dpd_init(st) != STF_OK) {
		delete_ipsec_sa(st);
		return STF_FAIL;
	}

	return STF_OK;
}
