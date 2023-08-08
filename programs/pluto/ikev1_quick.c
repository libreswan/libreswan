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
#include "crypt_prf.h"
#include "crypt_hash.h"
#include "ikev1.h"
#include "ikev1_quick.h"
#include "ikev1_continuations.h"
#include "host_pair.h"
#include "ikev1_xauth.h"

#include "nat_traversal.h"
#include "ikev1_nat.h"
#include "virtual_ip.h"
#include "ikev1_dpd.h"
#include "pluto_x509.h"
#include "ip_address.h"
#include "ip_info.h"
#include "ip_protocol.h"
#include "ip_selector.h"
#include "ikev1_hash.h"
#include "ikev1_message.h"
#include "crypt_ke.h"
#include <blapit.h>
#include "crypt_dh.h"
#include "unpack.h"
#include "orient.h"

#ifdef USE_XFRM_INTERFACE
# include "kernel_xfrm_interface.h"
#endif

struct connection *find_v1_client_connection(struct connection *c,
					     const ip_selector *local_client,
					     const ip_selector *remote_client);

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
static v1_notification_t accept_PFS_KE(struct state *st, struct msg_digest *md,
				       chunk_t *dest, const char *val_name,
				       const char *msg_name)
{
	struct payload_digest *const ke_pd = md->chain[ISAKMP_NEXT_KE];

	if (ke_pd == NULL) {
		if (st->st_pfs_group != NULL) {
			log_state(RC_LOG_SERIOUS, st,
				  "missing KE payload in %s message", msg_name);
			return v1N_INVALID_KEY_INFORMATION;
		}
		return v1N_NOTHING_WRONG;
	} else {
		if (st->st_pfs_group == NULL) {
			log_state(RC_LOG_SERIOUS, st,
				  "%s message KE payload requires a GROUP_DESCRIPTION attribute in SA",
				  msg_name);
			return v1N_INVALID_KEY_INFORMATION;
		}
		if (ke_pd->next != NULL) {
			log_state(RC_LOG_SERIOUS, st,
				  "%s message contains several KE payloads; we accept at most one",
				  msg_name);
			return v1N_INVALID_KEY_INFORMATION; /* ??? */
		}
		if (!unpack_KE(dest, val_name, st->st_pfs_group,
			       ke_pd, st->st_logger)) {
			return v1N_INVALID_KEY_INFORMATION;
		}
		return v1N_NOTHING_WRONG;
	}
}

/* Initiate quick mode.
 * --> HDR*, HASH(1), SA, Nr [, KE ] [, IDci, IDcr ]
 * (see RFC 2409 "IKE" 5.5)
 * Note: this is not called from demux.c
 */

static bool emit_subnet_id(enum perspective perspective,
			   const ip_subnet net,
			   uint8_t protoid,
			   uint16_t port,
			   struct pbs_out *outs)
{
	const struct ip_info *ai = subnet_type(&net);
	const bool usehost = (subnet_prefix_bits(net) == ai->mask_cnt);
	pb_stream id_pbs;

	enum ike_id_type idtype =
		(perspective == REMOTE_PERSPECTIVE &&
		 impair.v1_remote_quick_id > 0 ? (int)impair.v1_remote_quick_id - 1/*unbias*/ :
		 usehost ? ai->id_ip_addr :
		 ai->id_ip_addr_subnet);

	struct isakmp_ipsec_id id = {
		.isaiid_idtype = idtype,
		.isaiid_protoid = protoid,
		.isaiid_port = port,
	};

	if (!out_struct(&id, &isakmp_ipsec_identification_desc, outs, &id_pbs))
		return false;

	ip_address tp = subnet_prefix(net);
	if (!pbs_out_address(&id_pbs, tp, "client network")) {
		/* already logged */
		return false;
	}

	if (!usehost) {
		ip_address tm = subnet_prefix_mask(net);
		if (!pbs_out_address(&id_pbs, tm, "client mask")) {
			/* already logged */
			return false;
		}
	}

	close_output_pbs(&id_pbs);
	return true;
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

	free_chunk_content(&pi->inbound.keymat);
	pi->inbound.keymat = ikev1_section_5_keymat(st->st_oakley.ta_prf,
						    st->st_skeyid_d_nss,
						    st->st_dh_shared_secret,
						    protoid,
						    THING_AS_SHUNK(pi->inbound.spi),
						    st->st_ni, st->st_nr,
						    needed_len,
						    st->st_logger);
	PASSERT(st->st_logger, pi->inbound.keymat.len == needed_len);

	free_chunk_content(&pi->outbound.keymat);
	pi->outbound.keymat = ikev1_section_5_keymat(st->st_oakley.ta_prf,
						     st->st_skeyid_d_nss,
						     st->st_dh_shared_secret,
						     protoid,
						     THING_AS_SHUNK(pi->outbound.spi),
						     st->st_ni, st->st_nr,
						     needed_len,
						     st->st_logger);
	PASSERT(st->st_logger, pi->outbound.keymat.len == needed_len);

	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s KEYMAT", satypename);
		DBG_dump_hunk("  inbound:", pi->inbound.keymat);
		DBG_dump_hunk("  outbound:", pi->outbound.keymat);
	}
}

static void compute_keymats(struct state *st)
{
	if (st->st_ah.present)
		compute_proto_keymat(st, PROTO_IPSEC_AH, &st->st_ah, "AH");
	if (st->st_esp.present)
		compute_proto_keymat(st, PROTO_IPSEC_ESP, &st->st_esp, "ESP");
}

/*
 * Decode the variable part of an ID packet (during Quick Mode).
 *
 * This is designed for packets that identify clients, not peers.
 * Rejects 0.0.0.0/32 or IPv6 equivalent because (1) it is wrong and
 * (2) we use this value for inband signalling.
 */
static bool decode_net_id(struct isakmp_ipsec_id *id,
			  struct pbs_in *id_pbs,
			  ip_selector *client,
			  const char *which,
			  struct logger *logger)
{
	*client = unset_selector;
	const struct ip_info *afi = NULL;

	/* IDB and IDTYPENAME must have same scope. */
	enum ike_id_type id_type = id->isaiid_idtype;
	esb_buf idb;
	const char *idtypename = enum_show(&ike_id_type_names, id_type, &idb);

	switch (id_type) {
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
		llog(RC_COMMENT, logger, "%s type is FQDN", which);
		return true;

	default:
		/* XXX support more */
		llog(RC_LOG_SERIOUS, logger, "unsupported ID type %s",
		     idtypename);
		/* XXX Could send notification back */
		return false;
	}

	ip_subnet net;
	switch (id_type) {
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
	{
		ip_address temp_address;
		diag_t d = pbs_in_address(id_pbs, &temp_address, afi, "ID address");
		if (d != NULL) {
			llog_diag(RC_LOG, logger, &d, "%s", "");
			return false;
		}
		/* i.e., "zero" */
		if (!address_is_specified(temp_address)) {
			address_buf b;
			llog(RC_LOG_SERIOUS, logger,
			     "%s ID payload %s is invalid (%s) in Quick I1",
			     which, idtypename, str_address(&temp_address, &b));
			/* XXX Could send notification back */
			return false;
		}
		net = subnet_from_address(temp_address);
		subnet_buf b;
		dbg("%s is %s", which, str_subnet(&net, &b));
		break;
	}

	case ID_IPV4_ADDR_SUBNET:
	case ID_IPV6_ADDR_SUBNET:
	{
		diag_t d;

		ip_address temp_address;
		d = pbs_in_address(id_pbs, &temp_address, afi, "ID address");
		if (d != NULL) {
			llog_diag(RC_LOG, logger, &d, "%s", "");
			return false;
		}

		ip_address temp_mask;
		d = pbs_in_address(id_pbs, &temp_mask, afi, "ID mask");
		if (d != NULL) {
			llog_diag(RC_LOG, logger, &d, "%s", "");
			return false;
		}

		err_t ughmsg = address_mask_to_subnet(temp_address, temp_mask, &net);
		if (ughmsg == NULL && subnet_is_zero(net)) {
			/* i.e., ::/128 or 0.0.0.0/32 */
			ughmsg = "subnet contains no addresses";
		}
		if (ughmsg != NULL) {
			llog(RC_LOG_SERIOUS, logger,
			     "%s ID payload %s bad subnet in Quick I1 (%s)",
			     which, idtypename, ughmsg);
			/* XXX Could send notification back */
			return false;
		}
		subnet_buf buf;
		dbg("%s is subnet %s", which, str_subnet(&net, &buf));
		break;
	}

	case ID_IPV4_ADDR_RANGE:
	case ID_IPV6_ADDR_RANGE:
	{
		diag_t d;

		ip_address temp_address_from;
		d = pbs_in_address(id_pbs, &temp_address_from, afi, "ID from address");
		if (d != NULL) {
			llog_diag(RC_LOG, logger, &d, "%s", "");
			return false;
		}

		ip_address temp_address_to;
		d = pbs_in_address(id_pbs, &temp_address_to, afi, "ID to address");
		if (d != NULL) {
			llog_diag(RC_LOG, logger, &d, "%s", "");
			return false;
		}

		err_t ughmsg = addresses_to_nonzero_subnet(temp_address_from,
							   temp_address_to, &net);
		if (ughmsg != NULL) {
			address_buf a, b;
			llog(RC_LOG_SERIOUS, logger,
			     "%s ID payload in Quick I1, %s %s - %s unacceptable: %s",
			     which, idtypename,
			     str_address_sensitive(&temp_address_from, &a),
			     str_address_sensitive(&temp_address_to, &b),
			     ughmsg);
			return false;
		}

		subnet_buf buf;
		dbg("%s is subnet %s (received as range)", which, str_subnet(&net, &buf));
		break;
	}
	default:
		/* first case rejected all others */
		bad_case(id_type);
	}

	const ip_protocol *protocol = protocol_by_ipproto(id->isaiid_protoid);
	if (!pexpect(protocol != NULL)) {
		/* things would need to be pretty screwed up */
		return false;
	}

	ip_port port = ip_hport(id->isaiid_port);
	*client = selector_from_subnet_protocol_port(net, protocol, port);

	return true;
}

/*
 * Like decode, but checks that what is received matches what was
 * sent.
 */

static bool check_net_id(struct isakmp_ipsec_id *id,
			 struct pbs_in *id_pbs,
			 uint8_t protoid,
			 uint16_t port,
			 ip_subnet net,
			 const char *which,
			 struct logger *logger)
{
	bool bad_proposal = false;

	ip_selector selector_temp;
	if (!decode_net_id(id, id_pbs, &selector_temp, which, logger))
		return false;
	/* toss the proto/port */
	ip_subnet subnet_temp = selector_subnet(selector_temp);

	if (!subnet_eq_subnet(net, subnet_temp)) {
		subnet_buf subrec;
		subnet_buf subxmt;
		llog(RC_LOG_SERIOUS, logger,
			    "%s subnet returned doesn't match my proposal - us: %s vs them: %s",
			    which, str_subnet(&net, &subxmt),
			    str_subnet(&subnet_temp, &subrec));
		llog(RC_LOG_SERIOUS, logger,
		     "Allowing questionable (microsoft) proposal anyway");
		bad_proposal = false;
	}
	if (protoid != id->isaiid_protoid) {
		llog(RC_LOG_SERIOUS, logger,
		     "%s peer returned protocol id does not match my proposal - us: %d vs them: %d",
		     which, protoid, id->isaiid_protoid);
		llog(RC_LOG_SERIOUS, logger,
		     "Allowing questionable (microsoft) proposal anyway]");
		bad_proposal = false;
	}
	/*
	 * workaround for #802- "our client ID returned doesn't match my proposal"
	 * until such time as bug #849 is properly fixed.
	 */
	if (port != id->isaiid_port) {
		llog(RC_LOG_SERIOUS, logger,
		     "%s peer returned port doesn't match my proposal - us: %d vs them: %d",
		     which, port, id->isaiid_port);
		if (port != 0 && id->isaiid_port != 1701) {
			llog(RC_LOG_SERIOUS, logger,
				    "Allowing bad L2TP/IPsec proposal (see bug #849) anyway");
			bad_proposal = false;
		} else {
			bad_proposal = true;
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
		 shunk_t sec_label)
{
	struct state *st = ikev1_duplicate_state(c, isakmp_sa, SA_INITIATOR, whack_sock);
	passert(c != NULL);

	st->st_policy = policy;
	st->st_try = try;

	if (c->config->sec_label.len != 0) {
		dbg("pending phase 2 with base security context '"PRI_SHUNK"'",
		    pri_shunk(c->config->sec_label));
		if (sec_label.len != 0) {
			st->st_v1_acquired_sec_label = clone_hunk(sec_label, "st_acquired_sec_label");
			dbg("pending phase 2 with 'instance' security context '"PRI_SHUNK"'",
			    pri_shunk(sec_label));
		}
	}


	st->st_v1_msgid.id = generate_msgid(isakmp_sa);
	change_v1_state(st, STATE_QUICK_I1); /* from STATE_UNDEFINED */

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
		st->st_pfs_group = ikev1_quick_pfs(c->config->child_proposals);
		/* otherwise, use the same group as during Phase 1:
		 * since no negotiation is possible, we pick one that is
		 * very likely supported.
		 */
		if (st->st_pfs_group == NULL)
			st->st_pfs_group = isakmp_sa->st_oakley.ta_dh;
	}

	LLOG_JAMBUF(RC_LOG, st->st_logger, buf) {
		jam(buf, "initiating Quick Mode ");
		jam_connection_policies(buf, st->st_connection);
		if (replacing != SOS_NOBODY) {
			jam(buf, " to replace #%lu", replacing);
		}
		jam(buf, " {using isakmp#%lu msgid:%08" PRIx32 " proposal=",
			isakmp_sa->st_serialno, st->st_v1_msgid.id);
		if (st->st_connection->config->child_proposals.p != NULL) {
			jam_proposals(buf, st->st_connection->config->child_proposals.p);
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
	st->st_v1_ipsec_pred = replacing;

	if (policy & POLICY_PFS) {
		submit_ke_and_nonce(st, st->st_pfs_group,
				    quick_outI1_continue, HERE);
	} else {
		submit_ke_and_nonce(st, NULL /* no-nonce*/,
				    quick_outI1_continue, HERE);
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

	struct state *isakmp_sa = state_by_serialno(st->st_clonedfrom);
	struct connection *c = st->st_connection;
	pb_stream rbody;
	bool has_client = (c->spd.this.has_client ||
			   c->spd.that.has_client ||
			   c->spd.this.client.ipproto != 0 ||
			   c->spd.that.client.ipproto != 0 ||
			   c->spd.this.client.hport != 0 ||
			   c->spd.that.client.hport != 0);

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
			has_client = true;
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
					     POLICY_COMPRESS);
		policy_buf pb;
		dbg("emitting quick defaults using policy %s",
		    str_policy(pm, &pb));

		if (!ikev1_out_sa(&rbody, IKEv1_ipsec_db_sa(pm),
				  st, false, false)) {
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
		if (!emit_subnet_id(LOCAL_PERSPECTIVE,
				    selector_subnet(c->spd.this.client),
				    c->spd.this.client.ipproto,
				    c->spd.this.client.hport, &rbody) ||
		    !emit_subnet_id(REMOTE_PERSPECTIVE,
				    selector_subnet(c->spd.that.client),
				    c->spd.that.client.ipproto,
				    c->spd.that.client.hport, &rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	if ((st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA) &&
	    !(st->st_policy & POLICY_TUNNEL) &&
	    LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		/** Send NAT-OA if our address is NATed */
		if (!v1_nat_traversal_add_initiator_natoa(&rbody, st)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* finish computing HASH(1), inserting it in output */
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

	if (st->st_v1_ipsec_pred == SOS_NOBODY) {
		log_state(RC_NEW_V1_STATE + st->st_state->kind, st,
			  "%s", st->st_state->story);
	} else {
		log_state(RC_NEW_V1_STATE + st->st_state->kind, st,
			  "%s, to replace #%lu",
			  st->st_state->story,
			  st->st_v1_ipsec_pred);
		st->st_v1_ipsec_pred = SOS_NOBODY;
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

static stf_status quick_inI1_outR1_tail(struct state *p1st, struct msg_digest *md,
					const ip_selector *local_client,
					const ip_selector *remote_client,
					struct crypt_mac new_iv);

stf_status quick_inI1_outR1(struct state *p1st, struct msg_digest *md)
{
	passert(p1st != NULL && p1st == md->v1_st);
	struct connection *c = p1st->st_connection;
	ip_selector local_client;
	ip_selector remote_client;

	/*
	 * [ IDci, IDcr ] in
	 *
	 * We do this now (probably out of physical order) because we
	 * wish to select the correct connection before we consult it
	 * for policy.
	 */

	struct payload_digest *const IDci = md->chain[ISAKMP_NEXT_ID];
	if (IDci != NULL) {
		struct payload_digest *IDcr = IDci->next;

		/* ??? we are assuming IPSEC_DOI */

		/* IDci (initiator is remote peer) */

		if (!decode_net_id(&IDci->payload.ipsec_id, &IDci->pbs,
				   &remote_client, "peer client", p1st->st_logger))
			return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;

		/* for code overwriting above */
		const ip_protocol *remote_protocol = protocol_by_ipproto(IDci->payload.ipsec_id.isaiid_protoid);
		ip_port remote_port = ip_hport(IDci->payload.ipsec_id.isaiid_port);

		/* Hack for MS 818043 NAT-T Update.
		 *
		 * <http://support.microsoft.com/kb/818043>
		 * "L2TP/IPsec NAT-T update for Windows XP and Windows
		 * 2000" This update is has a bug.  We choose to work
		 * around that bug rather than failing to
		 * interoperate.  As to what the bug is, Paul says: "I
		 * believe on rekey, it sent a bogus subnet or wrong
		 * type of ID."  ??? needs more complete description.
		 */
		if (IDci->payload.ipsec_id.isaiid_idtype == ID_FQDN) {
			log_state(RC_LOG_SERIOUS, p1st,
				  "Applying workaround for MS-818043 NAT-T bug");
			remote_client = selector_from_address_protocol_port(c->remote->host.addr,
									    remote_protocol,
									    remote_port);
		}
		/* End Hack for MS 818043 NAT-T Update */


		/* IDcr (we are local responder) */

		if (!decode_net_id(&IDcr->payload.ipsec_id, &IDcr->pbs,
				   &local_client, "our client", p1st->st_logger))
			return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;

		/*
		 * if there is a NATOA payload, then use it as
		 *    &st->st_connection->spd.that.client, if the type
		 * of the ID was FQDN
		 *
		 * We actually do NATOA calculation again later on,
		 * but we need the info here, and we don't have a
		 * state to store it in until after we've done the
		 * authorization steps.
		 */
		if ((p1st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
		    (p1st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA) &&
		    (IDci->payload.ipsec_id.isaiid_idtype == ID_FQDN)) {
			struct hidden_variables hv;
			shunk_t idfqdn = pbs_in_left_as_shunk(&IDcr->pbs);

			hv = p1st->hidden_variables;
			nat_traversal_natoa_lookup(md, &hv, p1st->st_logger);

			if (address_is_specified(hv.st_nat_oa)) {
				remote_client = selector_from_address_protocol_port(hv.st_nat_oa,
										    remote_protocol,
										    remote_port);
				LLOG_JAMBUF(RC_LOG_SERIOUS, p1st->st_logger, buf) {
					jam(buf, "IDci was FQDN: ");
					jam_sanitized_hunk(buf, idfqdn);
					jam(buf, ", using NAT_OA=");
					jam_selector_subnet_port(buf, &remote_client);
					jam(buf, " as IDci");
				}
			}
		}
	} else {
		/* implicit IDci and IDcr: peer and self */
		if (address_type(&c->local->host.addr) != address_type(&c->remote->host.addr))
			return STF_FAIL_v1N;

		local_client = selector_from_address(c->local->host.addr);
		remote_client = selector_from_address(c->remote->host.addr);
	}

	struct crypt_mac new_iv;
	save_new_iv(p1st, new_iv);

	/*
	 * XXX: merge.
	 */
	return quick_inI1_outR1_tail(p1st, md, &local_client, &remote_client, new_iv);
}

/* forward definitions */
static stf_status quick_inI1_outR1_continue12_tail(struct state *st, struct msg_digest *md);

static ke_and_nonce_cb quick_inI1_outR1_continue1;	/* forward decl and type assertion */
static dh_shared_secret_cb quick_inI1_outR1_continue2;	/* forward decl and type assertion */

static stf_status quick_inI1_outR1_tail(struct state *p1st, struct msg_digest *md,
					const ip_selector *local_client,
					const ip_selector *remote_client,
					struct crypt_mac new_iv)
{
	pexpect(p1st == md->v1_st);
	struct connection *c = p1st->st_connection;
	struct hidden_variables hv;

	/*
	 * XXX: isn't local->remote backwards?  The peer things it
	 * proposed the reverse?
	 */
	selectors_buf sb;
	log_state(RC_LOG, p1st, "the peer proposed: %s",
		  str_selectors(local_client, remote_client, &sb));

	/* Now that we have identities of client subnets, we must look for
	 * a suitable connection (our current one only matches for hosts).
	 */
	{
		struct connection *p = find_v1_client_connection(c, local_client, remote_client);

		if ((p1st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
		    !(p1st->st_policy & POLICY_TUNNEL) &&
		    p == NULL) {
			p = c;
			connection_buf cib;
			dbg("using something (we hope the IP we or they are NAT'ed to) for transport mode connection "PRI_CONNECTION"",
			    pri_connection(p, &cib));
		}

		if (p == NULL) {
			LLOG_JAMBUF(RC_LOG, p1st->st_logger, buf) {
				jam(buf, "cannot respond to IPsec SA request because no connection is known for ");

				/*
				 * This message occurs in very
				 * puzzling circumstances so we must
				 * add as much information and beauty
				 * as we can.
				 */

				struct end local = c->spd.this;
				local.client = *local_client;
				local.has_client = !selector_eq_address(*local_client, local.host->addr);
				jam_end(buf, &local, NULL, LEFT_END, LEMPTY, oriented(c));

				jam(buf, "...");

				struct end remote = c->spd.that;
				remote.client = *remote_client;
				remote.has_client = !selector_eq_address(*remote_client, remote.host->addr);
				jam_end(buf, &remote, NULL, RIGHT_END, LEMPTY, oriented(c));
			}
			return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
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
				p = rw_instantiate(p, &c->remote->host.addr,
						   remote_client,
						   &c->remote->host.id);
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
		    bool_str(c->spd.that.config->client.protoport.has_port_wildcard),
		    bool_str(is_virtual_connection(c)));

		/* fill in the client's true port */
		if (c->spd.that.config->client.protoport.has_port_wildcard) {
			int port = selector_port(*remote_client).hport;
			update_selector_hport(&c->spd.that.client, port);
		}

		if (is_virtual_connection(c)) {

			c->spd.that.client = *remote_client;
			rehash_db_spd_route_remote_client(&c->spd);
			c->spd.that.has_client = true;
			virtual_ip_delref(&c->spd.that.virt);

			if (selector_eq_address(*remote_client, c->remote->host.addr)) {
				c->spd.that.has_client = false;
			}

			LSWDBGP(DBG_BASE, buf) {
				jam(buf, "setting phase 2 virtual values to ");
				jam_end(buf, &c->spd.that, NULL, LEFT_END, LEMPTY, oriented(c));
			}
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
		struct state *const st = ikev1_duplicate_state(c, p1st, SA_RESPONDER, null_fd);

		/* first: fill in missing bits of our new state object
		 * note: we don't copy over st_peer_pubkey, the public key
		 * that authenticated the ISAKMP SA.  We only need it in this
		 * routine, so we can "reach back" to p1st to get it.
		 */

		st->st_try = 0; /* not our job to try again from start */

		st->st_v1_msgid.id = md->hdr.isa_msgid;

		restore_new_iv(st, new_iv);

		switch_md_st(md, st, HERE);	/* feed back new state */

		change_v1_state(st, STATE_QUICK_R0);

		binlog_refresh_state(st);

		/* copy hidden variables (possibly with changes) */
		st->hidden_variables = hv;

		/* copy the connection's
		 * IPSEC policy into our state.  The ISAKMP policy is water under
		 * the bridge, I think.  It will reflect the ISAKMP SA that we
		 * are using.
		 */
		st->st_policy = c->policy;

		if (p1st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
			/* ??? this partially overwrites what was done via hv */
			st->hidden_variables.st_nat_traversal =
				p1st->hidden_variables.st_nat_traversal;
			nat_traversal_change_port_lookup(md, md->v1_st);
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
			RETURN_STF_FAIL_v1NURE(parse_ipsec_sa_body(&in_pbs,
							       &sapd->payload.
							       sa,
							       NULL,
							       false, st));
		}

		/* Ni in */
		RETURN_STF_FAIL_v1NURE(accept_v1_nonce(st->st_logger, md, &st->st_ni, "Ni"));

		/* [ KE ] in (for PFS) */
		RETURN_STF_FAIL_v1NURE(accept_PFS_KE(st, md, &st->st_gi,
						 "Gi", "Quick Mode I1"));

		passert(st->st_pfs_group != &unset_group);

		passert(st->st_connection != NULL);

		submit_ke_and_nonce(st, st->st_pfs_group/*possibly-null*/,
				    quick_inI1_outR1_continue1, HERE);

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
		submit_dh_shared_secret(st, st, st->st_gi,
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
		return false;
	ptrdiff_t hl = id_body.cur - hs;	/* length of header */

	if (!out_raw(id_pd->pbs.start + hl, pbs_room(&id_pd->pbs) - hl, &id_body, "ID body"))
		return false;

	close_output_pbs(&id_body);
	return true;
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
	ikev1_init_pbs_out_from_md_hdr(md, true,
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
	RETURN_STF_FAIL_v1NURE(parse_ipsec_sa_body(&sapd->pbs,
					       &sapd->payload.sa,
					       &r_sa_pbs,
					       false, st));

	passert(st->st_pfs_group != &unset_group);

	if ((st->st_policy & POLICY_PFS) && st->st_pfs_group == NULL) {
		log_state(RC_LOG_SERIOUS, st,
			  "we require PFS but Quick I1 SA specifies no GROUP_DESCRIPTION");
		return STF_FAIL_v1N + v1N_NO_PROPOSAL_CHOSEN; /* ??? */
	}

	log_state(RC_LOG, st,
		  "responding to Quick Mode proposal {msgid:%08" PRIx32 "}",
		  st->st_v1_msgid.id);
	LLOG_JAMBUF(RC_LOG, st->st_logger, buf) {
		jam(buf, "    us: ");
		const struct connection *c = st->st_connection;
		const struct spd_route *sr = &c->spd;
		jam_end(buf, &sr->this, &sr->that, LEFT_END, LEMPTY, oriented(c));
		jam(buf, "  them: ");
		jam_end(buf, &sr->that, &sr->this, RIGHT_END, LEMPTY, oriented(c));
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

		RETURN_STF_FAIL_v1NURE(parse_ipsec_sa_body(&sa_pd->pbs,
						       &sa_pd->payload.sa,
						       NULL, true, st));
	}

	/* Nr in */
	RETURN_STF_FAIL_v1NURE(accept_v1_nonce(st->st_logger, md, &st->st_nr, "Nr"));

	/* [ KE ] in (for PFS) */
	RETURN_STF_FAIL_v1NURE(accept_PFS_KE(st, md, &st->st_gr, "Gr",
					 "Quick Mode R1"));

	if (st->st_pfs_group != NULL) {
		/* set up DH calculation */
		submit_dh_shared_secret(st, st, st->st_gr,
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
	ikev1_init_pbs_out_from_md_hdr(md, true,
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
					  c->spd.this.client.ipproto,
					  c->spd.this.client.hport,
					  selector_subnet(st->st_connection->spd.this.client),
					  "our client", st->st_logger))
				return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;

			/* we checked elsewhere that we got two of them */
			IDcr = IDci->next;
			passert(IDcr != NULL);

			/* IDcr (responder is peer) */

			if (!check_net_id(&IDcr->payload.ipsec_id, &IDcr->pbs,
					  c->spd.that.client.ipproto,
					  c->spd.that.client.hport,
					  selector_subnet(st->st_connection->spd.that.client),
					  "peer client", st->st_logger))
				return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;

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
				shunk_t idfqdn = pbs_in_left_as_shunk(&IDcr->pbs);
				st->st_connection->spd.that.client =
					selector_from_address(st->hidden_variables.st_nat_oa);
				LLOG_JAMBUF(RC_LOG_SERIOUS, st->st_logger, buf) {
					jam(buf, "IDcr was FQDN: ");
					jam_sanitized_hunk(buf, idfqdn);
					jam(buf, ", using NAT_OA=");
					jam_selector_subnet(buf, &st->st_connection->spd.that.client);
					jam(buf, " as IDcr");
				}
			}
		} else {
			/*
			 * No IDci, IDcr: we must check that the
			 * defaults match our proposal.
			 */
			if (!selector_eq_address(c->spd.this.client, c->local->host.addr) ||
			    !selector_eq_address(c->spd.that.client, c->remote->host.addr)) {
				log_state(RC_LOG_SERIOUS, st,
					  "IDci, IDcr payloads missing in message but default does not match proposal");
				return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
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
	if (!install_ipsec_sa(st, true))
		return STF_INTERNAL_ERROR;

	/* encrypt message, except for fixed part of header */

	if (!ikev1_encrypt_message(&rbody, st)) {
		delete_ipsec_sa(st);
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */
	}

	set_newest_v1_ipsec_sa(__func__, st);

	if (dpd_init(st) != STF_OK) {
		delete_ipsec_sa(st);
		return STF_FAIL_v1N;
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
	if (!install_ipsec_sa(st, false))
		return STF_INTERNAL_ERROR;

	set_newest_v1_ipsec_sa(__func__, st);

	update_iv(st);  /* not actually used, but tidy */

	/*
	 * If we have dpd delay and dpdtimeout set, then we are doing DPD
	 * on this conn, so initialize it
	 */
	if (dpd_init(st) != STF_OK) {
		delete_ipsec_sa(st);
		return STF_FAIL_v1N;
	}

	return STF_OK;
}

/*
 * With virtual addressing, we must not allow someone to use an already
 * used (by another id) addr/net.
 */
static bool is_virtual_net_used(struct connection *c,
				const ip_selector *peer_net,
				const struct id *peer_id)
{
	struct connection_filter cq = { .where = HERE, };
	while (next_connection_new2old(&cq)) {
		struct connection *d = cq.c;
		switch (d->kind) {
		case CK_PERMANENT:
		case CK_TEMPLATE:
		case CK_INSTANCE:

			if (d->kind == CK_TEMPLATE &&
			    !d->remote->config->client.subnet.is_set) {
				/*
				 * For instance when the template''s
				 * peer's protoport=udp/%any but
				 * peers' subnet is not set.  The
				 * peer's .client is constructed from
				 * %any:udp/%any.
				 *
				 * Since this has to be narrowed, any
				 * comparison is pointless.
				 */
				connection_buf dcb;
				enum_buf kb;
				dbg(" skipping %s "PRI_CONNECTION" as remote's %ssubnet is wild (not set)",
				    str_enum_short(&connection_kind_names, d->kind, &kb),
				    pri_connection(d, &dcb),
				    d->remote->config->leftright);
				continue;
			}

			if (!selector_overlaps_selector(*peer_net, d->spd.that.client)) {
				/*
				 * For instance when PEER_NET is IPv6
				 * and remote .client is IPv4 (but can
				 * be pretty much anything that
				 * doesn't intersect).
				 */
				connection_buf dcb;
				enum_buf kb;
				dbg(" skipping %s "PRI_CONNECTION" as there is no overlap",
				    str_enum_short(&connection_kind_names, d->kind, &kb),
				    pri_connection(d, &dcb));
				continue;
			}

			if (same_id(&d->remote->host.id, peer_id)) {
				/*
				 * Assumed to be a replace?
				 */
				connection_buf dcb;
				enum_buf kb;
				id_buf idb;
				dbg(" skipping %s "PRI_CONNECTION" as it has the same id: %s",
				    str_enum_short(&connection_kind_names, d->kind, &kb),
				    pri_connection(d, &dcb),
				    str_id(&d->remote->host.id, &idb));
				continue;
			}

			if (!kernel_ops->overlap_supported) {
				connection_buf cbuf;
				subnet_buf pcb, dcb;
				llog(RC_LOG_SERIOUS, c->logger,
				     "peer Virtual IP %s overlapping %s from "PRI_CONNECTION" is not supported by the kernel interface %s",
				     str_selector_subnet(peer_net, &pcb),
				     str_selector_subnet(&d->spd.that.client, &dcb),
				     pri_connection(d, &cbuf),
				     kernel_ops->interface_name);
				return true;
			}

			if (POLICY_OVERLAPIP & c->policy & d->policy) {
				connection_buf cbuf;
				subnet_buf pcb, dcb;
				llog(RC_LOG, c->logger,
				     "peer Virtual IP %s overlapping %s from "PRI_CONNECTION" permitted by mutual consent (and kernel support)",
				     str_selector_subnet(peer_net, &pcb),
				     pri_connection(d, &cbuf),
				     str_selector_subnet(&d->spd.that.client, &dcb));
				/*
				 * Look for another overlap to report
				 * on.
				 */
				continue;
			}

			/*
			 * We're not allowed to overlap.  Carefully
			 * report.
			 */

			if (LIN(POLICY_OVERLAPIP, c->policy)) {
				/* not C; must be D objecting */
				connection_buf cbuf;
				subnet_buf pcb, dcb;
				llog(RC_LOG_SERIOUS, c->logger,
				     "peer Virtual IP %s overlapping %s fobidden by "PRI_CONNECTION" policy",
				     str_selector_subnet(peer_net, &pcb),
				     pri_connection(d, &cbuf),
				     str_selector_subnet(&d->spd.that.client, &dcb));
			} else if (LIN(POLICY_OVERLAPIP, d->policy)) {
				/* not D; must be C objecting */
				connection_buf cbuf;
				subnet_buf pcb, dcb;
				llog(RC_LOG_SERIOUS, c->logger,
				     "policy forbids peer Virtual IP %s overlapping %s from "PRI_CONNECTION"",
				     str_selector_subnet(peer_net, &pcb),
				     pri_connection(d, &cbuf),
				     str_selector_subnet(&d->spd.that.client, &dcb));
			} else {
				/* must be both D and C objecting */
				connection_buf cbuf;
				subnet_buf pcb, dcb;
				llog(RC_LOG_SERIOUS, c->logger,
				     "peer Virtual IP %s overlapping %s from "PRI_CONNECTION" is forbidden (neither agrees)",
				     str_selector_subnet(peer_net, &pcb),
				     str_selector_subnet(&d->spd.that.client, &dcb),
				     pri_connection(d, &cbuf));
			}

			return true; /* already used by another one */

		case CK_GOING_AWAY:
		default:
			break;
		}
	}
	return false; /* you can safely use it */
}

/*
 * find_client_connection: given a connection suitable for ISAKMP
 * (i.e. the hosts match), find a one suitable for IPSEC
 * (i.e. with matching clients).
 *
 * If we don't find an exact match (not even our current connection),
 * we try for one that still needs instantiation.  Try Road Warrior
 * abstract connections and the Opportunistic abstract connections.
 * This requires inverse instantiation: abstraction.
 *
 * After failing to find an exact match, we abstract the peer
 * to be NO_IP (the wildcard value).  This enables matches with
 * Road Warrior and Opportunistic abstract connections.
 *
 * After failing that search, we also abstract the Phase 1 peer ID
 * if possible.  If the peer's ID was the peer's IP address, we make
 * it NO_ID; instantiation will make it the peer's IP address again.
 *
 * If searching for a Road Warrior abstract connection fails,
 * and conditions are suitable, we search for the best Opportunistic
 * abstract connection.
 *
 * Note: in the end, both Phase 1 IDs must be preserved, after any
 * instantiation.  They are the IDs that have been authenticated.
 */

#define PATH_WEIGHT 1
#define WILD_WEIGHT (MAX_CA_PATH_LEN + 1)
#define PRIO_WEIGHT ((MAX_WILDCARDS + 1) * WILD_WEIGHT)

/* fc_try: a helper function for find_client_connection */
static struct connection *fc_try(const struct connection *c,
				 const ip_address local_address,
				 const ip_address remote_address,
				 const ip_selector *local_client,
				 const ip_selector *remote_client)
{
	if (selector_is_unset(local_client) ||
	    selector_is_unset(remote_client)) {
		return NULL;
	}

	struct connection *best = NULL;
	policy_prio_t best_prio = BOTTOM_PRIO;
	const bool remote_is_host = selector_eq_address(*remote_client,
							c->remote->host.addr);

	err_t virtualwhy = NULL;
	FOR_EACH_HOST_PAIR_CONNECTION(local_address, remote_address, d) {

		if (d->config->ike_version != IKEv1) {
			continue;
		}

		if (d->kind == CK_INSTANCE && d->remote->host.id.kind == ID_NULL) {
			connection_buf cb;
			dbg("skipping unauthenticated "PRI_CONNECTION" with ID_NULL",
			    pri_connection(d, &cb));
			continue;
		}

		if (d->policy & POLICY_GROUP)
			continue;

		selectors_buf sb;
		dbg("  fc_try: looking at %s",
		    str_selectors(&d->spd.this.client, &d->spd.that.client, &sb));

		/*
		 * ??? what should wildcards and pathlen default to?
		 * Coverity Scan detected that they could be referenced without initialization.
		 * This happens if the connaliases match.
		 * This bug was introduced in 605c8010007.
		 * For now, I've defaulted them to the largest values.
		 */
		int wildcards = MAX_WILDCARDS;
		int pathlen = MAX_CA_PATH_LEN;

		if (!(c->config->connalias != NULL &&
		      d->config->connalias != NULL &&
		      streq(c->config->connalias, d->config->connalias))) {
			if (!(same_id(&c->local->host.id, &d->local->host.id) &&
			      match_id("", &c->remote->host.id, &d->remote->host.id, &wildcards) &&
			      trusted_ca(ASN1(c->remote->config->host.ca),
					 ASN1(d->remote->config->host.ca), &pathlen))) {
				continue;
			}
		}

		/* compare protocol and ports */
		unsigned local_protocol = local_client->ipproto;
		unsigned remote_protocol = remote_client->ipproto;
		int local_port = local_client->hport;
		int remote_port = remote_client->hport;
		if (!(d->spd.this.client.ipproto == local_protocol &&
		      d->spd.that.client.ipproto == remote_protocol &&
		      (d->spd.this.client.hport == 0 ||
		       d->spd.this.client.hport == local_port) &&
		      (d->spd.that.config->client.protoport.has_port_wildcard ||
		       d->spd.that.client.hport == remote_port))) {
			continue;
		}

		/*
		 * non-Opportunistic case:
		 * local_client must match.
		 *
		 * So must remote_client, but the testing is complicated
		 * by the fact that the peer might be a wildcard
		 * and if so, the default value of that.client
		 * won't match the default remote_net. The appropriate test:
		 *
		 * If d has a peer client, it must match remote_net.
		 * If d has no peer client, remote_net must just have peer itself.
		 */

		for (const struct spd_route *sr = &d->spd;
		     best != d && sr != NULL; sr = sr->spd_next) {

			if (DBGP(DBG_BASE)) {
				selector_buf s1, d1;
				selector_buf s3, d3;
				DBG_log("  fc_try trying %s:%s:%d/%d -> %s:%d/%d%s vs %s:%s:%d/%d -> %s:%d/%d%s",
					c->name,
					str_selector_subnet_port(local_client, &s1),
					c->spd.this.client.ipproto,
					c->spd.this.client.hport,
					str_selector_subnet_port(remote_client, &d1),
					c->spd.that.client.ipproto,
					c->spd.that.client.hport,
					is_virtual_connection(c) ?
					"(virt)" : "", d->name,
					str_selector_subnet_port(&sr->this.client, &s3),
					sr->this.client.ipproto,
					sr->this.client.hport,
					str_selector_subnet_port(&sr->that.client, &d3),
					sr->that.client.ipproto,
					sr->that.client.hport,
					is_virtual_sr(sr) ? "(virt)" : "");
			}

			if (!selector_range_eq_selector_range(sr->this.client, *local_client)) {
				if (DBGP(DBG_BASE)) {
					selector_buf s1, s3;
					DBG_log("   our client (%s) not in local_net (%s)",
						str_selector_subnet_port(&sr->this.client, &s3),
						str_selector_subnet_port(local_client, &s1));
				}
				continue;
			}

			if (sr->that.has_client) {

				if (!selector_range_eq_selector_range(sr->that.client, *remote_client) &&
				    !is_virtual_sr(sr)) {
					if (DBGP(DBG_BASE)) {
						selector_buf d1, d3;
						DBG_log("   their client (%s) not in same remote_net (%s)",
							str_selector_subnet_port(&sr->that.client, &d3),
							str_selector_subnet_port(remote_client, &d1));
					}
					continue;
				}

				virtualwhy = check_virtual_net_allowed(d,
								       selector_subnet(*remote_client),
								       sr->that.host->addr);

				if (is_virtual_sr(sr) &&
				    (virtualwhy != NULL ||
				     is_virtual_net_used(d, remote_client,
							 &sr->that.host->id))) {
					dbg("   virtual net not allowed");
					continue;
				}
			} else if (!remote_is_host) {
				continue;
			}

			/*
			 * We've run the gauntlet -- success:
			 * We've got an exact match of subnets.
			 * The connection is feasible, but we continue looking
			 * for the best.
			 * The highest priority wins, implementing eroute-like
			 * rule.
			 * - a routed connection is preferrred
			 * - given that, the smallest number of ID wildcards
			 *   are preferred
			 * - given that, the shortest CA pathlength is preferred
			 * - given that, not switching is preferred
			 */
			policy_prio_t prio =
				PRIO_WEIGHT * routed(sr->routing) +
				WILD_WEIGHT * (MAX_WILDCARDS - wildcards) +
				PATH_WEIGHT * (MAX_CA_PATH_LEN - pathlen) +
				(c == d ? 1 : 0) +
				1;
			if (prio > best_prio) {
				best = d;
				best_prio = prio;
			}
		}
	}

	if (best != NULL && NEVER_NEGOTIATE(best->policy))
		best = NULL;

	dbg("  fc_try concluding with %s [%" PRIu32 "]",
	    (best ? best->name : "none"), best_prio);

	if (best == NULL && virtualwhy != NULL) {
		llog(RC_LOG, c->logger,
		     "peer proposal was rejected in a virtual connection policy: %s",
		     virtualwhy);
	}

	return best;
}

static struct connection *fc_try_oppo(const struct connection *c,
				      ip_address local_address,
				      const ip_selector *local_client,
				      const ip_selector *remote_client)
{
	if (selector_is_unset(local_client) ||
	    selector_is_unset(remote_client)) {
		return NULL;
	}

	struct connection *best = NULL;
	policy_prio_t best_prio = BOTTOM_PRIO;

	FOR_EACH_HOST_PAIR_CONNECTION(local_address, unset_address, d) {

		if (d->config->ike_version != IKEv1) {
			continue;
		}

		if (d->kind == CK_INSTANCE && d->remote->host.id.kind == ID_NULL) {
			connection_buf cb;
			dbg("skipping unauthenticated "PRI_CONNECTION" with ID_NULL",
			    pri_connection(d, &cb));
			continue;
		}

		if (d->policy & POLICY_GROUP)
			continue;

		int wildcards, pathlen;
		if (!(same_id(&c->local->host.id, &d->local->host.id) &&
		      match_id("", &c->remote->host.id, &d->remote->host.id, &wildcards) &&
		      trusted_ca(ASN1(c->remote->config->host.ca), ASN1(d->remote->config->host.ca), &pathlen))) {
			continue;
		}

		/* compare protocol and ports */
		unsigned local_protocol = selector_protocol(*local_client)->ipproto;
		unsigned remote_protocol = selector_protocol(*remote_client)->ipproto;
		int local_port = hport(selector_port(*local_client));
		int remote_port = hport(selector_port(*remote_client));
		if (d->spd.this.client.ipproto != local_protocol ||
			(d->spd.this.client.hport &&
			 d->spd.this.client.hport != local_port) ||
			d->spd.that.client.ipproto != remote_protocol ||
			(d->spd.that.client.hport != remote_port &&
			 !d->spd.that.config->client.protoport.has_port_wildcard))
			continue;

		/*
		 * Opportunistic case:
		 * local_net must be inside d->spd.this.client
		 * and remote_net must be inside d->spd.that.client
		 * Note: this host_pair chain also has shunt
		 * eroute conns (clear, drop), but they won't
		 * be marked as opportunistic.
		 */

		for (const struct spd_route *sr = &d->spd;
		     sr != NULL; sr = sr->spd_next) {

			if (DBGP(DBG_BASE)) {
				selector_buf s1;
				selector_buf d1;
				selector_buf s3;
				selector_buf d3;
				DBG_log("  fc_try_oppo trying %s:%s -> %s vs %s:%s -> %s",
					c->name, str_selector_subnet_port(local_client, &s1),
					str_selector_subnet_port(remote_client, &d1),
					d->name, str_selector_subnet_port(&sr->this.client, &s3),
					str_selector_subnet_port(&sr->that.client, &d3));
			}

			if (!selector_range_in_selector_range(*local_client, sr->this.client) ||
			    !selector_range_in_selector_range(*remote_client, sr->that.client))
				continue;

			/*
			 * The connection is feasible, but we continue looking
			 * for the best.
			 * The highest priority wins, implementing eroute-like
			 * rule.
			 * - our smallest client subnet is preferred (longest
			 *   mask)
			 * - given that, peers smallest client subnet is preferred
			 * - given that, a routed connection is preferrred
			 * - given that, the smallest number of ID wildcards
			 *   are preferred
			 * - given that, the shortest CA pathlength is preferred
			 */
			policy_prio_t prio =
				PRIO_WEIGHT * (d->policy_prio + routed(sr->routing)) +
				WILD_WEIGHT * (MAX_WILDCARDS - wildcards) +
				PATH_WEIGHT * (MAX_CA_PATH_LEN - pathlen);

			if (prio > best_prio) {
				best = d;
				best_prio = prio;
			}
		}
	}

	/* if the best wasn't opportunistic, we fail: it must be a shunt */
	if (best != NULL &&
	    (NEVER_NEGOTIATE(best->policy) ||
	     (best->policy & POLICY_OPPORTUNISTIC) == LEMPTY))
		best = NULL;

	dbg("  fc_try_oppo concluding with %s [%" PRIu32 "]",
	    (best ? best->name : "none"), best_prio);
	return best;
}

struct connection *find_v1_client_connection(struct connection *const c,
					     const ip_selector *local_client,
					     const ip_selector *remote_client)
{
	struct connection *d;

	/* weird things can happen to our interfaces */
	if (!oriented(c)) {
		return NULL;
	}

	if (DBGP(DBG_BASE)) {
		selectors_buf sb;
		DBG_log("find_v1_client_connection starting with %s", c->name);
		DBG_log("  looking for %s",
			str_selectors(local_client, remote_client, &sb));
	}

	if (selector_is_unset(local_client)) {
		dbg("peer's local client is not set");
		return NULL;
	}

	if (selector_is_unset(remote_client)) {
		dbg("peer's remote client is not set");
		return NULL;
	}

	/*
	 * Give priority to current connection
	 * but even greater priority to a routed concrete connection.
	 */
	{
		struct connection *unrouted = NULL;
		int srnum = -1;

		for (const struct spd_route *sr = &c->spd; unrouted == NULL && sr != NULL;
			sr = sr->spd_next) {
			srnum++;

			if (DBGP(DBG_BASE)) {
				selector_buf s2;
				selector_buf d2;
				DBG_log("  concrete checking against sr#%d %s -> %s", srnum,
					str_selector_subnet_port(&sr->this.client, &s2),
					str_selector_subnet_port(&sr->that.client, &d2));
			}

			unsigned local_protocol = selector_protocol(*local_client)->ipproto;
			int local_port = selector_port(*local_client).hport;
			unsigned remote_protocol = selector_protocol(*remote_client)->ipproto;
			int remote_port = selector_port(*remote_client).hport;
			if (selector_range_eq_selector_range(sr->this.client, *local_client) &&
			    selector_range_eq_selector_range(sr->that.client, *remote_client) &&
			    sr->this.client.ipproto == local_protocol &&
			    (!sr->this.client.hport ||
			     sr->this.client.hport == local_port) &&
			    (sr->that.client.ipproto == remote_protocol) &&
			    (!sr->that.client.hport ||
			     sr->that.client.hport == remote_port)) {
				if (routed(sr->routing))
					return c;

				unrouted = c;
			}
		}

		/* exact match? */
		/*
		 * clang 3.4 says: warning: Access to field
		 * 'host_pair' results in a dereference of a null
		 * pointer (loaded from variable 'c')
		 *
		 * If so, the caller must have passed NULL for it
		 * and earlier references would be wrong (segfault).
		 */
		d = fc_try(c, c->local->host.addr, c->remote->host.addr,
			   local_client, remote_client);

		dbg("  fc_try %s gives %s", c->name, (d ? d->name : "none"));

		if (d == NULL)
			d = unrouted;
	}

	if (d == NULL) {
		/*
		 * look for an abstract connection to match
		 */
		ip_address local_address = unset_address;
		for (const struct spd_route *sra = &c->spd;
		     sra != NULL && !address_is_specified(local_address);
		     sra = sra->spd_next) {
			FOR_EACH_HOST_PAIR_CONNECTION(sra->this.host->addr,
						      unset_address, ignore) {
				local_address = sra->this.host->addr;
				selector_buf s2;
				selector_buf d2;
				DBG_log("  checking hostpair %s -> %s",
					str_selector_subnet_port(&sra->this.client, &s2),
					str_selector_subnet_port(&sra->that.client, &d2));
				break;
			}
		}

		if (address_is_specified(local_address)) {
			/* RW match with actual remote_id or abstract remote_id? */
			d = fc_try(c, local_address, unset_address,
				   local_client, remote_client);

			if (d == NULL &&
			    selector_contains_one_address(*local_client) &&
			    selector_contains_one_address(*remote_client)) {
				/*
				 * Opportunistic match?
				 * Always use abstract remote_id.
				 * Note that later instantiation will result
				 * in the same remote_id.
				 */
				d = fc_try_oppo(c, local_address, local_client, remote_client);
			}
		}
	}

	dbg("  concluding with d = %s", (d ? d->name : "none"));
	return d;
}
