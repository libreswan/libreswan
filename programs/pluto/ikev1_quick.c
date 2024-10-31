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
#include "ikev1.h"
#include "ikev1_quick.h"
#include "ikev1_continuations.h"
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
#include "instantiate.h"
#include "terminate.h"
#include "addresspool.h"
#include "ipsec_interface.h"
#include "verbose.h"

struct connection *find_v1_client_connection(struct connection *c,
					     const ip_selector *local_client,
					     const ip_selector *remote_client,
					     struct verbose verbose);

static stf_status quick_outI1_continue_tail(struct ike_sa *ike,
					    struct child_sa *child,
					    struct dh_local_secret *local_secret,
					    chunk_t *nonce);
static stf_status quick_inI1_outR1_continue_tail(struct ike_sa *ike,
						 struct child_sa *child,
						 struct msg_digest *md);

stf_status quick_inR1_outI2_continue_tail(struct ike_sa *ike,
					  struct child_sa *child,
					  struct msg_digest *md);

static dh_shared_secret_cb quick_inR1_outI2_continue;	/* forward decl and type assertion */
static ke_and_nonce_cb quick_inI1_outR1_continue1;	/* forward decl and type assertion */
static dh_shared_secret_cb quick_inI1_outR1_continue2;	/* forward decl and type assertion */

static ke_and_nonce_cb quick_outI1_continue;	/* type assertion */

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

static v1_notification_t accept_PFS_KE(struct child_sa *child, struct msg_digest *md,
				       chunk_t *dest, const char *val_name,
				       const char *msg_name)
{
	struct payload_digest *const ke_pd = md->chain[ISAKMP_NEXT_KE];

	if (ke_pd == NULL) {
		if (child->sa.st_pfs_group != NULL) {
			llog(RC_LOG, child->sa.logger,
			     "missing KE payload in %s message", msg_name);
			return v1N_INVALID_KEY_INFORMATION;
		}
		return v1N_NOTHING_WRONG;
	} else {
		if (child->sa.st_pfs_group == NULL) {
			llog(RC_LOG, child->sa.logger,
			     "%s message KE payload requires a GROUP_DESCRIPTION attribute in SA",
			     msg_name);
			return v1N_INVALID_KEY_INFORMATION;
		}
		if (ke_pd->next != NULL) {
			llog(RC_LOG, child->sa.logger,
			     "%s message contains several KE payloads; we accept at most one",
			     msg_name);
			return v1N_INVALID_KEY_INFORMATION; /* ??? */
		}
		if (!unpack_KE(dest, val_name, child->sa.st_pfs_group,
			       ke_pd, child->sa.logger)) {
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
	struct pbs_out id_pbs;

	enum ike_id_type idtype =
		(perspective == REMOTE_PERSPECTIVE && impair.v1_remote_quick_id.enabled ? (int)impair.v1_remote_quick_id.value :
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
static bool compute_proto_keymat(struct state *st,
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
	{
		/*
		 * If there is encryption, then ENCKEYLEN contains the
		 * required number of bits.
		 */
		size_t encrypt_key_size = BYTES_FOR_BITS(pi->trans_attrs.enckeylen);
		/*
		 * Finally, some encryption algorithms such as AEAD
		 * and CTR require "salt" as part of the "starting
		 * variable".
		 */
		const struct encrypt_desc *encrypt = pi->trans_attrs.ta_encrypt;
		size_t encrypt_salt_size = (encrypt != NULL ? encrypt->salt_size : 0);
		needed_len = encrypt_key_size + encrypt_salt_size;
		ldbg(st->logger, "compute_proto_keymat: encrypt_key_size %zd encrypt_salt_size %zd needed_len=%zd",
		     encrypt_key_size, encrypt_salt_size, encrypt_salt_size);
		needed_len += pi->trans_attrs.ta_integ->integ_keymat_size;
		dbg("compute_proto_keymat: needed_len (after ESP auth)=%d", (int)needed_len);
		break;
	}

	case PROTO_IPSEC_AH:
		needed_len += pi->trans_attrs.ta_integ->integ_keymat_size;
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
						    st->logger);
	PASSERT(st->logger, pi->inbound.keymat.len == needed_len);

	free_chunk_content(&pi->outbound.keymat);
	pi->outbound.keymat = ikev1_section_5_keymat(st->st_oakley.ta_prf,
						     st->st_skeyid_d_nss,
						     st->st_dh_shared_secret,
						     protoid,
						     THING_AS_SHUNK(pi->outbound.spi),
						     st->st_ni, st->st_nr,
						     needed_len,
						     st->logger);
	PASSERT(st->logger, pi->outbound.keymat.len == needed_len);

	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s KEYMAT", satypename);
		DBG_dump_hunk("  inbound:", pi->inbound.keymat);
		DBG_dump_hunk("  outbound:", pi->outbound.keymat);
	}

	return true;
}

static bool compute_keymats(struct state *st)
{
	if (st->st_ah.protocol == &ip_protocol_ah)
		return compute_proto_keymat(st, PROTO_IPSEC_AH, &st->st_ah, "AH");
	if (st->st_esp.protocol == &ip_protocol_esp)
		return compute_proto_keymat(st, PROTO_IPSEC_ESP, &st->st_esp, "ESP");
	return false;
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
	const char *idtypename = str_enum(&ike_id_type_names, id_type, &idb);

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
		llog(RC_LOG, logger, "%s type is FQDN", which);
		return true;

	default:
		/* XXX support more */
		llog(RC_LOG, logger, "unsupported ID type %s",
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
			llog(RC_LOG, logger, "%s", str_diag(d));
			pfree_diag(&d);
			return false;
		}
		/* i.e., "zero" */
		if (!address_is_specified(temp_address)) {
			address_buf b;
			llog(RC_LOG, logger,
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
			llog(RC_LOG, logger, "%s", str_diag(d));
			pfree_diag(&d);
			return false;
		}

		ip_address temp_mask;
		d = pbs_in_address(id_pbs, &temp_mask, afi, "ID mask");
		if (d != NULL) {
			llog(RC_LOG, logger, "%s", str_diag(d));
			pfree_diag(&d);
			return false;
		}

		err_t ughmsg = address_mask_to_subnet(temp_address, temp_mask, &net);
		if (ughmsg == NULL && subnet_is_zero(net)) {
			/* i.e., ::/128 or 0.0.0.0/32 */
			ughmsg = "subnet contains no addresses";
		}
		if (ughmsg != NULL) {
			llog(RC_LOG, logger,
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
			llog(RC_LOG, logger, "%s", str_diag(d));
			pfree_diag(&d);
			return false;
		}

		ip_address temp_address_to;
		d = pbs_in_address(id_pbs, &temp_address_to, afi, "ID to address");
		if (d != NULL) {
			llog(RC_LOG, logger, "%s", str_diag(d));
			pfree_diag(&d);
			return false;
		}

		err_t ughmsg = addresses_to_nonzero_subnet(temp_address_from,
							   temp_address_to, &net);
		if (ughmsg != NULL) {
			address_buf a, b;
			llog(RC_LOG, logger,
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

	const struct ip_protocol *protocol = protocol_from_ipproto(id->isaiid_protoid);
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
		llog(RC_LOG, logger,
			    "%s subnet returned doesn't match my proposal - us: %s vs them: %s",
			    which, str_subnet(&net, &subxmt),
			    str_subnet(&subnet_temp, &subrec));
		llog(RC_LOG, logger,
		     "Allowing questionable (microsoft) proposal anyway");
		bad_proposal = false;
	}
	if (protoid != id->isaiid_protoid) {
		llog(RC_LOG, logger,
		     "%s peer returned protocol id does not match my proposal - us: %d vs them: %d",
		     which, protoid, id->isaiid_protoid);
		llog(RC_LOG, logger,
		     "Allowing questionable (microsoft) proposal anyway]");
		bad_proposal = false;
	}
	/*
	 * workaround for #802- "our client ID returned doesn't match my proposal"
	 * until such time as bug #849 is properly fixed.
	 */
	if (port != id->isaiid_port) {
		llog(RC_LOG, logger,
		     "%s peer returned port doesn't match my proposal - us: %d vs them: %d",
		     which, port, id->isaiid_port);
		if (port != 0 && id->isaiid_port != 1701) {
			llog(RC_LOG, logger,
				    "Allowing bad L2TP/IPsec proposal (see bug #849) anyway");
			bad_proposal = false;
		} else {
			bad_proposal = true;
		}
	}

	return !bad_proposal;
}

struct child_sa *quick_outI1(struct ike_sa *isakmp,
			     struct connection *c,
			     const struct child_policy *policy,
			     so_serial_t replacing)
{
	passert(c != NULL);
	struct child_sa *child = new_v1_child_sa(c, isakmp, SA_INITIATOR);

	child->sa.st_policy = (*policy);

	child->sa.st_v1_msgid.id = generate_msgid(&isakmp->sa);
	change_v1_state(&child->sa, STATE_QUICK_I1); /* from STATE_UNDEFINED */

	binlog_refresh_state(&child->sa);

	/* figure out PFS group, if any */

	if (child->sa.st_connection->config->child_sa.pfs) {
		/*
		 * See if pfs_group has been specified for this conn,
		 * use that group.
		 * if not, fallback to old use-same-as-P1 behaviour
		 */
		child->sa.st_pfs_group = ikev1_quick_pfs(c->config->child_sa.proposals);
		/* otherwise, use the same group as during Phase 1:
		 * since no negotiation is possible, we pick one that is
		 * very likely supported.
		 */
		if (child->sa.st_pfs_group == NULL)
			child->sa.st_pfs_group = isakmp->sa.st_oakley.ta_dh;
	}

	LLOG_JAMBUF(RC_LOG, child->sa.logger, buf) {
		jam(buf, "initiating Quick Mode ");
		jam_connection_policies(buf, child->sa.st_connection);
		if (replacing != SOS_NOBODY) {
			jam(buf, " to replace #%lu", replacing);
		}
		jam(buf, " {using isakmp"PRI_SO" msgid:%08" PRIx32 " proposal=",
		    pri_so(isakmp->sa.st_serialno), child->sa.st_v1_msgid.id);
		if (child->sa.st_connection->config->child_sa.proposals.p != NULL) {
			jam_proposals(buf, child->sa.st_connection->config->child_sa.proposals.p);
		} else {
			jam(buf, "defaults");
		}
		jam(buf, " pfsgroup=");
		if (child->sa.st_pfs_group != NULL) {
			jam_string(buf, child->sa.st_pfs_group->common.fqn);
		} else {
			jam_string(buf, "no-pfs");
		}
		jam(buf, "}");
	}

	/* save for post crypto logging */
	child->sa.st_v1_ipsec_pred = replacing;

	submit_ke_and_nonce(/*callback*/&child->sa,
			    /*task*/&child->sa,
			    /*no-md*/NULL,
			    child->sa.st_pfs_group/*could-be-null*/,
			    quick_outI1_continue,
			    /*detach_whack*/false, HERE);
	return child;
}

static stf_status quick_outI1_continue(struct state *child_sa,
				       struct msg_digest *unused_md,
				       struct dh_local_secret *local_secret,
				       chunk_t *nonce)
{
	pexpect(unused_md == NULL); /* no packet */

	struct child_sa *child = pexpect_child_sa(child_sa);
	if (pbad(child == NULL)) {
		return STF_INTERNAL_ERROR;
	}

	struct ike_sa *ike = isakmp_sa_where(child, HERE);
	if (ike == NULL) {
		/* phase1 state got deleted while cryptohelper was working */
		llog(RC_LOG, child->sa.logger,
		     "%s() failed because parent ISAKMP "PRI_SO" is gone",
		     __func__, pri_so(child->sa.st_clonedfrom));
		return STF_FATAL;
	}

	ldbg(child->sa.logger, "%s() for "PRI_SO": calculated ke+nonce, sending I1",
	     __func__, pri_so(child->sa.st_serialno));

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
	stf_status e = quick_outI1_continue_tail(ike, child, local_secret, nonce);
	if (e == STF_INTERNAL_ERROR) {
		llog(RC_LOG, child->sa.logger,
		     "%s(): %s_tail() failed with STF_INTERNAL_ERROR",
		     __func__, __func__);
	}
	/*
	 * This way all the broken behaviour is ignored.
	 */
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

static stf_status quick_outI1_continue_tail(struct ike_sa *ike,
					    struct child_sa *child,
					    struct dh_local_secret *local_secret,
					    chunk_t *nonce)
{
	ldbg(child->sa.logger,
	     "%s() for "PRI_SO": calculated ke+nonce, sending I1",
	     __func__, pri_so(child->sa.st_serialno));

	struct connection *c = child->sa.st_connection;
	struct pbs_out rbody;
	bool has_client = (c->local->child.has_client ||
			   c->remote->child.has_client ||
			   c->spd->local->client.ipproto != 0 ||
			   c->spd->remote->client.ipproto != 0 ||
			   c->spd->local->client.hport != 0 ||
			   c->spd->remote->client.hport != 0);

	if (nat_traversal_detected(&ike->sa)) {
		/* Duplicate nat_traversal status in new state */
		child->sa.hidden_variables.st_nat_traversal =
			ike->sa.hidden_variables.st_nat_traversal;
		if (ike->sa.hidden_variables.st_nated_host) {
			has_client = true;
		}
		v1_maybe_natify_initiator_endpoints(&child->sa, HERE);
	} else {
		child->sa.hidden_variables.st_nat_traversal = LEMPTY;
	}

	/* set up reply */
	reply_stream = open_pbs_out("reply packet",reply_buffer, sizeof(reply_buffer), child->sa.logger);

	/* HDR* out */
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
					  ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_QUICK,
			.isa_msgid = child->sa.st_v1_msgid.id,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
		};
		hdr.isa_ike_initiator_spi = child->sa.st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = child->sa.st_ike_spis.responder;
		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* HASH(1) -- create and note space to be filled later */
	struct v1_hash_fixup hash_fixup;
	if (!emit_v1_HASH(V1_HASH_1, "outI1",
			  IMPAIR_v1_QUICK_EXCHANGE,
			  &child->sa, &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* SA out */

	/*
	 * Emit SA payload based on a subset of the policy bits.
	 * POLICY_COMPRESS is considered iff we can do IPcomp.
	 */
	{
		struct ipsec_db_policy pm = {
			.encrypt = (child->sa.st_connection->config->child_sa.encap_proto == ENCAP_PROTO_ESP),
			.authenticate = (child->sa.st_connection->config->child_sa.encap_proto == ENCAP_PROTO_AH),
			.compress = child->sa.st_policy.compress,
		};

		ldbg(child->sa.logger,
		     "emitting quick defaults using policy:%s%s%s",
		     (pm.encrypt ? " encrypt" : ""),
		     (pm.authenticate ? " authenticate" : ""),
		     (pm.compress ? " compress" : ""));

		if (!ikev1_out_quick_sa(&rbody, &child->sa)) {
			return STF_INTERNAL_ERROR;
		}
	}

	{
		/* Ni out */
		if (!ikev1_ship_nonce(&child->sa.st_ni, nonce, &rbody, "Ni")) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* [ KE ] out (for PFS) */
	if (child->sa.st_pfs_group != NULL) {
		if (!ikev1_ship_KE(&child->sa, local_secret, &child->sa.st_gi, &rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* [ IDci, IDcr ] out */
	if (has_client) {
		/* IDci (we are initiator) followed by ... */
		if (impair.v1_emit_quick_id.enabled &&
		    impair.v1_emit_quick_id.value < 1) {
			llog(RC_LOG, child->sa.logger, "IMPAIR: skipping Quick Mode client initiator ID (IDci)");
		} else {
			if (!emit_subnet_id(LOCAL_PERSPECTIVE,
					    selector_subnet(c->spd->local->client),
					    c->spd->local->client.ipproto,
					    c->spd->local->client.hport, &rbody)) {
				return STF_INTERNAL_ERROR;
			}
		}
		/* ... IDcr (peer is responder) */
		if (impair.v1_emit_quick_id.enabled &&
		    impair.v1_emit_quick_id.value < 2) {
			llog(RC_LOG, child->sa.logger, "IMPAIR: skipping Quick Mode client responder ID (IDcr)");
		} else {
			if (!emit_subnet_id(REMOTE_PERSPECTIVE,
					    selector_subnet(c->spd->remote->client),
					    c->spd->remote->client.ipproto,
					    c->spd->remote->client.hport, &rbody)) {
				return STF_INTERNAL_ERROR;
			}
		}
		/* bonus? */
		if (impair.v1_emit_quick_id.enabled &&
		    impair.v1_emit_quick_id.value > 2) {
			llog(RC_LOG, child->sa.logger, "IMPAIR: adding bonus Quick Mode client ID");
			if (!emit_subnet_id(LOCAL_PERSPECTIVE,
					    selector_subnet(c->spd->local->client),
					    c->spd->local->client.ipproto,
					    c->spd->local->client.hport, &rbody)) {
				return STF_INTERNAL_ERROR;
			}
		}
	}

	if (c->config->child_sa.encap_mode == ENCAP_MODE_TRANSPORT &&
	    (child->sa.hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA) &&
	    child->sa.hidden_variables.st_nated_host) {
		/** Send NAT-OA if our address is NATed */
		if (!v1_nat_traversal_add_initiator_natoa(&rbody, &child->sa)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* finish computing HASH(1), inserting it in output */
	fixup_v1_HASH(&child->sa, &hash_fixup, child->sa.st_v1_msgid.id, rbody.cur);

	/* encrypt message, except for fixed part of header */

	init_phase2_iv(&ike->sa, &child->sa.st_v1_msgid.id);
	restore_new_iv(&child->sa, ike->sa.st_v1_new_iv);

	if (!ikev1_close_and_encrypt_message(&rbody, &child->sa)) {
		return STF_INTERNAL_ERROR;
	}

	record_and_send_v1_ike_msg(&child->sa, &reply_stream,
		"reply packet from quick_outI1");

	delete_v1_event(&child->sa);
	clear_retransmits(&child->sa);
	start_retransmits(&child->sa);

	if (child->sa.st_v1_ipsec_pred == SOS_NOBODY) {
		llog(RC_LOG, child->sa.logger,
		     "%s", child->sa.st_state->story);
	} else {
		llog(RC_LOG, child->sa.logger, "%s, to replace #%lu",
		     child->sa.st_state->story,
		     child->sa.st_v1_ipsec_pred);
		child->sa.st_v1_ipsec_pred = SOS_NOBODY;
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

stf_status quick_inI1_outR1(struct state *ike_sa, struct msg_digest *md)
{
	VERBOSE_DBGP(DBG_BASE, ike_sa->logger,
		     "in %s() with "PRI_SO, __func__, pri_so(ike_sa->st_serialno));
	vassert(ike_sa == md->v1_st);

	struct ike_sa *ike = pexpect_parent_sa(ike_sa);
	struct connection *c = ike->sa.st_connection; /* parent, tentative */

	/*
	 * 5.5 Phase 2 - Quick Mode
	 *
	 * The identities of the SAs negotiated in Quick Mode are
	 * implicitly assumed to be the IP addresses of the ISAKMP
	 * peers, without any implied constraints on the protocol or
	 * port numbers allowed, unless client identifiers are
	 * specified in Quick Mode.  If ISAKMP is acting as a client
	 * negotiator on behalf of another party, the identities of
	 * the parties MUST be passed as IDci and then IDcr.  Local
	 * policy will dictate whether the proposals are acceptable
	 * for the identities specified.  If the client identities are
	 * not acceptable to the Quick Mode responder (due to policy
	 * or other reasons), a Notify payload with Notify Message
	 * Type INVALID-ID-INFORMATION (18) SHOULD be sent.
	 *
	 * Hence parse [ IDci, IDcr ] in
	 *
	 * We do this now (probably out of physical order) because we
	 * wish to select the correct connection before we consult it
	 * for policy.
	 */

	ip_selector local_client; /* must-be-determined */
	ip_selector remote_client; /* must-be-determined */

	struct payload_digest *const IDci = md->chain[ISAKMP_NEXT_ID];
	if (IDci != NULL) {
		struct payload_digest *IDcr = IDci->next;
		PASSERT(ike->sa.logger, IDcr != NULL); /* checked in ikev1.c */

		/* ??? we are assuming IPSEC_DOI */

		/* IDci (initiator is remote peer) */

		if (!decode_net_id(&IDci->payload.ipsec_id, &IDci->pbs,
				   &remote_client, "peer client", ike->sa.logger))
			return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;

		/* for code overwriting above */
		const struct ip_protocol *remote_protocol = protocol_from_ipproto(IDci->payload.ipsec_id.isaiid_protoid);
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
			llog(RC_LOG, ike->sa.logger,
			     "applying workaround for MS-818043 NAT-T bug");
			remote_client = selector_from_address_protocol_port(c->remote->host.addr,
									    remote_protocol,
									    remote_port);
		}
		/* End Hack for MS 818043 NAT-T Update */


		/* IDcr (we are local responder) */

		if (!decode_net_id(&IDcr->payload.ipsec_id, &IDcr->pbs,
				   &local_client, "our client", ike->sa.logger))
			return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;

		/*
		 * if there is a NATOA payload, then use it as
		 *    &st->st_connection->spd->remote->client, if the type
		 * of the ID was FQDN
		 *
		 * We actually do NATOA calculation again later on,
		 * but we need the info here, and we don't have a
		 * state to store it in until after we've done the
		 * authorization steps.
		 */
		if (nat_traversal_detected(&ike->sa) &&
		    (ike->sa.hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA) &&
		    (IDci->payload.ipsec_id.isaiid_idtype == ID_FQDN)) {
			struct hidden_variables hv;
			shunk_t idfqdn = pbs_in_left(&IDcr->pbs);

			hv = ike->sa.hidden_variables;
			nat_traversal_natoa_lookup(md, &hv, ike->sa.logger);

			if (address_is_specified(hv.st_nat_oa)) {
				remote_client = selector_from_address_protocol_port(hv.st_nat_oa,
										    remote_protocol,
										    remote_port);
				LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
					jam(buf, "IDci was FQDN: ");
					jam_sanitized_hunk(buf, idfqdn);
					jam(buf, ", using NAT_OA=");
					jam_selector_subnet_port(buf, &remote_client);
					jam(buf, " as IDci");
				}
			}
		}
	} else {
		/*
		 * Implicit IDci and IDcr: peer and self.
		 */
		if (address_type(&c->local->host.addr) != address_type(&c->remote->host.addr))
			return STF_FAIL_v1N;

		local_client = selector_from_address(c->local->host.addr);
		remote_client = selector_from_address(c->remote->host.addr);
	}

	struct crypt_mac new_iv;
	save_new_iv(&ike->sa, new_iv);

	struct hidden_variables hv;

	/*
	 * Note: the peer's IDr is our LOCAL_CLIENT, and the peer's
	 * IDi is our REMOTE_CLIENT.
	 */
	selector_pair_buf sb;
	llog(RC_LOG, ike->sa.logger, "the peer proposed: %s",
	     str_selector_pair(&local_client, &remote_client, &sb));

	/*
	 * Now that we have identities of client subnets, we must look
	 * for a suitable connection (the IKE SA's connection only
	 * matches for hosts and IDs).
	 */
	struct connection *p = find_v1_client_connection(ike->sa.st_connection,
							 &local_client, &remote_client,
							 verbose);

	/*
	 * For instance: ikev1-l2tp-02 and ikev1-nat-transport-02.
	 */
	if (p == NULL &&
	    c->config->child_sa.encap_mode == ENCAP_MODE_TRANSPORT &&
	    nat_traversal_detected(&ike->sa)) {
		p = c;
		vdbg("using existing connection; nothing better and current is NAT'ed and transport mode");
	}

	/*
	 * For instance: nat-pluto-04.
	 *
	 * Note that, as demonstrated by nat-pluto-04, virtual-private
	 * is not IFF transport-mode.
	 */
	if (p == NULL &&
	    /* c->config->child_sa.encap_mode == ENCAP_MODE_TRANSPORT && */
	    is_virtual_remote(c, verbose)) {
		p = c;
		vdbg("using existing connection; nothing better and current is virtual-private");
	}

	/*
	 * The lookup can fail because the peer things it has a lease
	 * but the connection has not because the peer skipped CONFIG.
	 *
	 * For instance, the peer was put to sleep (laptop lid closed)
	 * leading to a DPD failure and connection delete.  When the
	 * peer wakes it should use MODE-CONFIG to renew the lease but
	 * that seems to be skipped (perhaps it hasn't expired?).
	 *
	 * For instance, this end crashes, the peer then tries to
	 * quickly re-establish.  Even though INITIAL_CONTACT is sent
	 * at the end of MAIN mode, the peer still assumes it has the
	 * lease and skips MODE-CONFIG.
	 *
	 * The lease may be available.  But if it isn't what next?
	 * And even if it is there's no guarentee that the rest of the
	 * MODE-CONFIG, such as DNS, is correct.
	 *
	 * XXX: IKEv1 only does IPv4.
	 */
	if (p == NULL &&
	    c->remote->config->host.pool_ranges.ip[IPv4_INDEX].len > 0 &&
	    !c->remote->child.lease[IPv4_INDEX].is_set) {

		if (!selector_eq_selector(local_client, c->spd->local->client)) {
			selector_buf lb, cb;
			llog(RC_LOG, ike->sa.logger,
			     "Quick Mode request rejected, peer requested lease but proposed local selector %s does not match connection %s; deleting ISAKMP SA",
			     str_selector(&local_client, &lb),
			     str_selector(&c->spd->local->client, &cb));
			return STF_FATAL;
		}

		err_t e = lease_that_selector(c, ike->sa.st_xauth_username,
					      &remote_client, ike->sa.logger);
		if (e != NULL) {
			selector_buf cb;
			llog(RC_LOG, ike->sa.logger,
			     "Quick Mode request rejected, peer requested lease of %s but it is unavailable, %s; deleting ISAKMP SA",
			     str_selector(&remote_client, &cb), e);
			return STF_FATAL;
		}

		p = c;
		selector_buf sb;
		llog(RC_LOG, ike->sa.logger,
		     "Quick Mode without mode-config, recovered previously assigned lease %s",
		     str_selector(&remote_client, &sb));

		vdbg("another hack to get the SPD in sync");
		c->spd->remote->client = remote_client;
		spd_db_rehash_remote_client(c->spd);
	}

	if (p == NULL) {
		LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
			jam(buf, "cannot respond to IPsec SA request because no connection is known for ");

			/*
			 * This message occurs in very puzzling
			 * circumstances so we must add as much
			 * information and beauty as we can.
			 */

			struct spd_end local = *c->spd->local;
			local.client = local_client;
			jam_spd_end(buf, c, &local, NULL, LEFT_END, oriented(c));

			jam_string(buf, "...");

			struct spd_end remote = *c->spd->remote;
			remote.client = remote_client;
			jam_spd_end(buf, c, &remote, NULL, RIGHT_END, oriented(c));
		}
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	/* did we find a better connection? */
	if (p != c) {
		/*
		 * We've got a better connection: it can support the
		 * specified clients.  But it may need instantiation.
		 */
		if (is_template(p)) {
			/*
			 * Plain Road Warrior because no OPPO for
			 * IKEv1 instantiate, carrying over
			 * authenticated peer ID
			 *
			 * Don't try to update the instantiated
			 * template's address when it is already set.
			 */
			p = rw_responder_refined_instantiate(p, c->remote->host.addr,
							     &remote_client,
							     &c->remote->host.id,
							     HERE); /* must delref */
		} else {
			p = connection_addref(p, p->logger); /* must delref */
		}
		connection_buf cib;
		vdbg("using connection "PRI_CONNECTION"", pri_connection(p, &cib));
		c = p;
	} else {
		c = connection_addref(c, c->logger); /* must delref */
	}

	/* fill in the client's true ip address/subnet */

	const struct ip_info *client_afi = selector_info(remote_client);
	if (client_afi == NULL) {
		client_afi = &unspec_ip_info;
	}

	selector_buf csb;
	selector_buf rcb;
	address_buf lb;
	vdbg("%s() client: %s %s; port wildcard: %s; virtual-private: %s; addresspool %s; current remote: %u %s",
	     __func__,
	     bool_str(c->remote->child.has_client),
	     str_selector(&c->spd->remote->client, &rcb),
	     bool_str(c->remote->config->child.protoport.has_port_wildcard),
	     bool_str(is_virtual_remote(c, verbose)),
	     str_address(&c->remote->child.lease[client_afi->ip_index], &lb),
	     c->remote->child.selectors.proposed.len,
	     str_selector(&c->remote->child.selectors.proposed.list[0], &csb));

	/* fill in the client's true port */

	if (c->remote->config->child.protoport.has_port_wildcard) {
		ip_selector selector =
			selector_from_range_protocol_port(selector_range(c->remote->child.selectors.proposed.list[0]),
							  selector_protocol(c->remote->child.selectors.proposed.list[0]),
							  selector_port(remote_client));
		update_first_selector(c, remote, selector);
	}

	if (is_virtual_remote(c, verbose)) {

		vdbg("virtual-private: spd %s/%s; config %s/%s",
		     bool_str(c->spd->local->virt != NULL),
		     bool_str(c->spd->remote->virt != NULL),
		     bool_str(c->local->config->child.virt != NULL),
		     bool_str(c->remote->config->child.virt != NULL));

		update_first_selector(c, remote, remote_client);
		spd_db_rehash_remote_client(c->spd);
		set_child_has_client(c, remote, true);
		virtual_ip_delref(&c->spd->remote->virt);

		if (selector_eq_address(remote_client, c->remote->host.addr)) {
			set_child_has_client(c, remote, false);
		}

		LDBGP_JAMBUF(DBG_BASE, &global_logger, buf) {
			jam(buf, PRI_VERBOSE, pri_verbose);
			jam(buf, "setting phase 2 virtual values to ");
			jam_spd_end(buf, c, c->spd->remote, NULL, LEFT_END, oriented(c));
		}
	}

	/*
	 * Some sanity checks - confirm above configured connection.
	 *
	 * XXX: IKEv1 only does IPv4 address pool.
	 */

	if (!c->spd->remote->client.is_set) {
		llog(RC_LOG, ike->sa.logger, "Quick Mode request rejected; connection has no remote client selector");
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	if (!c->spd->local->client.is_set) {
		llog(RC_LOG, ike->sa.logger, "Quick Mode request rejected; connection has no remote client selector");
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	/* now that we are sure of our connection, create our new state, and
	 * do any asynchronous cryptographic operations that we may need to
	 * make it all work.
	 */

	hv = ike->sa.hidden_variables;
	if (nat_traversal_detected(&ike->sa) &&
	    (hv.st_nat_traversal & NAT_T_WITH_NATOA))
		nat_traversal_natoa_lookup(md, &hv, ike->sa.logger);

	/* create our new state */

	struct child_sa *child = new_v1_child_sa(c, ike, SA_RESPONDER);
	/* delref stack reference */
	struct connection *cc = c;
	connection_delref(&cc, cc->logger);

	/*
	 * first: fill in missing bits of our new state object note:
	 * we don't copy over st_peer_pubkey, the public key that
	 * authenticated the ISAKMP SA.  We only need it in this
	 * routine, so we can "reach back" to p1st to get it.
	 */

	child->sa.st_v1_msgid.id = md->hdr.isa_msgid;

	restore_new_iv(&child->sa, new_iv);

	switch_md_st(md, &child->sa, HERE);	/* feed back new state */

	change_v1_state(&child->sa, STATE_QUICK_R0);

	binlog_refresh_state(&child->sa);

	/* copy hidden variables (possibly with changes) */
	child->sa.hidden_variables = hv;

	/*
	 * copy the connection's IPSEC policy into our state.  The
	 * ISAKMP policy is water under the bridge, I think.  It will
	 * reflect the ISAKMP SA that we are using.
	 */
	child->sa.st_policy = child_sa_policy(c);

	if (nat_traversal_detected(&ike->sa)) {
		/* ??? this partially overwrites what was done via hv */
		child->sa.hidden_variables.st_nat_traversal =
			ike->sa.hidden_variables.st_nat_traversal;
		nat_traversal_change_port_lookup(md, md->v1_st);
		v1_maybe_natify_initiator_endpoints(&child->sa, HERE);
	} else {
		/* ??? this partially overwrites what was done via hv */
		child->sa.hidden_variables.st_nat_traversal = LEMPTY;
	}

	passert(child->sa.st_connection != NULL);
	passert(child->sa.st_connection == c);

	/* process SA in */
	{
		struct payload_digest *const sapd =
			md->chain[ISAKMP_NEXT_SA];
		struct pbs_in in_pbs = sapd->pbs;

		/*
		 * parse and accept body, setting variables, but not
		 * forming our reply. We'll make up the reply later
		 * on.
		 *
		 * note that we process the copy of the pbs,
		 * so that we can process it again in the
		 * tail(). XXX: Huh, this is the tail
		 * function!
		 */
		child->sa.st_pfs_group = &unset_group;
		RETURN_STF_FAIL_v1NURE(parse_ipsec_sa_body(&in_pbs,
							   &sapd->payload.
							   sa,
							   NULL,
							   false,
							   child));
	}

	/* Ni in */
	RETURN_STF_FAIL_v1NURE(accept_v1_nonce(child->sa.logger, md, &child->sa.st_ni, "Ni"));

	/* [ KE ] in (for PFS) */
	RETURN_STF_FAIL_v1NURE(accept_PFS_KE(child, md, &child->sa.st_gi,
					     "Gi", "Quick Mode I1"));

	passert(child->sa.st_pfs_group != &unset_group);

	submit_ke_and_nonce(/*callback*/&child->sa, /*task*/&child->sa, md,
			    child->sa.st_pfs_group/*possibly-null*/,
			    quick_inI1_outR1_continue1,
			    /*detach_whack*/false, HERE);

	return STF_SUSPEND;

}

static stf_status quick_inI1_outR1_continue1(struct state *child_sa,
					     struct msg_digest *md,
					     struct dh_local_secret *local_secret,
					     chunk_t *nonce)
{
	struct child_sa *child = pexpect_child_sa(child_sa);
	if (pbad(child == NULL)) {
		return STF_INTERNAL_ERROR;
	}

	struct ike_sa *ike = isakmp_sa_where(child, HERE);
	if (ike == NULL) {
		/* phase1 state got deleted while cryptohelper was working */
		llog(RC_LOG, child->sa.logger,
		     "%s() failed because parent ISAKMP "PRI_SO" is gone",
		     __func__, pri_so(child->sa.st_clonedfrom));
		return STF_FATAL;
	}

	ldbg(child->sa.logger, "%s() for "PRI_SO": calculated ke+nonce, calculating DH",
	     __func__, pri_so(child->sa.st_serialno));

	/* we always calculate a nonce */
	unpack_nonce(&child->sa.st_nr, nonce);

	if (child->sa.st_pfs_group != NULL) {
		/* PFS is on: do a new DH */
		unpack_KE_from_helper(&child->sa, local_secret, &child->sa.st_gr);
		submit_dh_shared_secret(/*callback*/&child->sa, /*task*/&child->sa, md,
					child->sa.st_gi,
					quick_inI1_outR1_continue2,
					HERE);
		/*
		 * XXX: Since more crypto has been requested, MD needs
		 * to be re suspended.  If the original crypto request
		 * did everything this wouldn't be needed.
		 */
		return STF_SUSPEND;
	}

	/*
	 * but if PFS is off, we don't do a second DH, so just call
	 * the continuation with NULL struct pluto_crypto_req *
	 */
	return quick_inI1_outR1_continue_tail(ike, child, md);
}

static stf_status quick_inI1_outR1_continue2(struct state *child_sa,
					     struct msg_digest *md)
{
	passert(md != NULL);

	struct child_sa *child = pexpect_child_sa(child_sa);
	if (pbad(child == NULL)) {
		return STF_INTERNAL_ERROR;
	}

	struct ike_sa *ike = isakmp_sa_where(child, HERE);
	if (ike == NULL) {
		/* phase1 state got deleted while cryptohelper was working */
		llog(RC_LOG, child->sa.logger,
		     "%s() failed because parent ISAKMP "PRI_SO" is gone",
		     __func__, pri_so(child->sa.st_clonedfrom));
		return STF_FATAL;
	}

	ldbg(child->sa.logger, "%s() for "PRI_SO": calculated DH, sending R1",
	     __func__, pri_so(child->sa.st_serialno));

	return quick_inI1_outR1_continue_tail(ike, child, md);
}

/*
 * Spit out the IPsec ID payload we got.
 */
static bool echo_id(struct pbs_out *outs,
		    const struct payload_digest *const id_pd)
{
	/* Re-pack the received ID.  */
	struct isakmp_ipsec_id id_header = {
		.isaiid_idtype = id_pd->payload.ipsec_id.isaiid_idtype,
		.isaiid_protoid = id_pd->payload.ipsec_id.isaiid_protoid,
		.isaiid_port = id_pd->payload.ipsec_id.isaiid_port,
	};
	struct pbs_out id_body;
	if (!pbs_out_struct(outs, &isakmp_ipsec_identification_desc,
			    &id_header, sizeof(id_header), &id_body)) {
		return false;
	}

	/*
	 * And the ID proper.
	 *
	 * As part of reading the header, id_pb.pbs is set up so that
	 * .start points at the header, .cursor (.cur) points at the
	 * header's end, and .roof points at .start+.isaiid_length
	 * (i.e., length of payload with trailing junk trimmed).
	 *
	 * However:
	 *
	 * There's code using id_pd.pbs to read the payload breaking
	 * that assumption.  Hence, the need to re-compute the
	 * location of the Indentifer Data using hunk_slice().  See
	 * decode_net_id().
	 */
	shunk_t id_all = pbs_in_all(&id_pd->pbs);
	shunk_t id_data = hunk_slice(id_all, sizeof(id_header), id_all.len);

	if (!pbs_out_hunk(&id_body, id_data, "ID body")) {
		return false;
	}

	close_output_pbs(&id_body);
	return true;
}

/*
 * Note: install_inbound_ipsec_sa is only used by the Responder.
 * The Responder will subsequently use install_ipsec_sa for the outbound.
 * The Initiator uses install_ipsec_sa to install both at once.
 */

static void terminate_conflicts(struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;

	/*
	 * If our peer has a fixed-address client, check if we already
	 * have a route for that client that conflicts.  We will take
	 * this as proof that that route and the connections using it
	 * are obsolete and should be eliminated.  Interestingly, this
	 * is the only case in which we can tell that a connection is
	 * obsolete.
	 *
	 * XXX: can this make use of connection_routability() and / or
	 * get_connection_spd_conflicts() below?
	 */
	passert(is_permanent(c) || is_instance(c));
	if (c->remote->child.has_client) {
		for (;; ) {
			struct spd_owner owner = spd_owner(c->spd, RT_UNROUTED/*ignored*/,
							   child->sa.logger, HERE);

			if (owner.bare_route == NULL)
				break; /* nobody interesting has a route */
			struct connection *co = owner.bare_route->connection;
			if (co == c) {
				break; /* nobody interesting has a route */
			}

			/* note: we ignore the client addresses at this end */
			/* XXX: but compating interfaces doesn't ?!? */
			if (sameaddr(&co->remote->host.addr,
				     &c->remote->host.addr) &&
			    co->iface == c->iface)
				break;  /* existing route is compatible */

			if (kernel_ops->overlap_supported) {
				/*
				 * Both are transport mode, allow overlapping.
				 * [bart] not sure if this is actually
				 * intended, but am leaving it in to make it
				 * behave like before
				 */
				if (c->config->child_sa.encap_mode == ENCAP_MODE_TRANSPORT &&
				    co->config->child_sa.encap_mode == ENCAP_MODE_TRANSPORT)
					break;

				/* Both declared that overlapping is OK. */
				if (c->config->overlapip && co->config->overlapip)
					break;
			}

			address_buf b;
			connection_buf cib;
			llog_sa(RC_LOG, child,
				"route to peer's client conflicts with "PRI_CONNECTION" %s; releasing old connection to free the route",
				pri_connection(co, &cib),
				str_address_sensitive(&co->remote->host.addr, &b));

			if (is_instance(co)) {
				/*
				 * NOTE: CO not C.
				 *
				 * Presumably the instance CO looses
				 * to the permanent connection C.
				 */
				connection_addref(co, child->sa.logger);
				terminate_all_connection_states(co, HERE);
				connection_delref(&co, child->sa.logger);
			} else {
				/*
				 * NOTE: C not CO; why?
				 */
				terminate_all_connection_states(c, HERE);
			}
		}
	}
}

stf_status quick_inI1_outR1_continue_tail(struct ike_sa *ike,
					  struct child_sa *child,
					  struct msg_digest *md)
{
	passert(ike != NULL); /* use it */
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
				       &rbody, child->sa.logger);

	struct v1_hash_fixup hash_fixup;
	if (!emit_v1_HASH(V1_HASH_2, "quick inR1 outI2",
			  IMPAIR_v1_QUICK_EXCHANGE,
			  &child->sa, &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	struct pbs_out r_sa_pbs;

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
					       false, child));

	passert(child->sa.st_pfs_group != &unset_group);

	if (child->sa.st_connection->config->child_sa.pfs && child->sa.st_pfs_group == NULL) {
		llog(RC_LOG, child->sa.logger,
		     "we require PFS but Quick I1 SA specifies no GROUP_DESCRIPTION");
		return STF_FAIL_v1N + v1N_NO_PROPOSAL_CHOSEN; /* ??? */
	}

	llog(RC_LOG, child->sa.logger,
	     "responding to Quick Mode proposal {msgid:%08" PRIx32 "} using ISAKMP SA "PRI_SO,
	     child->sa.st_v1_msgid.id,
	     pri_so(child->sa.st_clonedfrom));
	LLOG_JAMBUF(RC_LOG, child->sa.logger, buf) {
		jam(buf, "    us: ");
		const struct connection *c = child->sa.st_connection;
		const struct spd *sr = c->spd;
		jam_spd_end(buf, c, sr->local, sr->remote, LEFT_END, oriented(c));
		jam_string(buf, "  them: ");
		jam_spd_end(buf, c, sr->remote, sr->local, RIGHT_END, oriented(c));
	}

	/**** finish reply packet: Nr [, KE ] [, IDci, IDcr ] ****/

	/* Nr out */
	if (!ikev1_justship_nonce(&child->sa.st_nr, &rbody, "Nr")) {
		return STF_INTERNAL_ERROR;
	}

	/* [ KE ] out (for PFS) */
	if (child->sa.st_pfs_group != NULL && child->sa.st_gr.ptr != NULL) {
		if (!ikev1_justship_KE(child->sa.logger, &child->sa.st_gr, &rbody))
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
	fixup_v1_HASH(&child->sa, &hash_fixup, child->sa.st_v1_msgid.id, rbody.cur);

	/* Derive new keying material */
	if (!compute_keymats(&child->sa)) {
		return STF_FATAL;
	}

	/* Tell the kernel to establish the new inbound SA
	 * (unless the commit bit is set -- which we don't support).
	 * We do this before any state updating so that
	 * failure won't look like success.
	 */

	terminate_conflicts(child);

	if (!connection_establish_inbound(child, HERE)) {
		return STF_FAIL_v1N; /* ??? we may be partly committed */
	}

	/* encrypt message, except for fixed part of header */
	if (!ikev1_close_and_encrypt_message(&rbody, &child->sa)) {
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

stf_status quick_inR1_outI2(struct state *child_sa, struct msg_digest *md)
{
	struct child_sa *child = pexpect_child_sa(child_sa);
	if (pbad(child == NULL)) {
		return STF_INTERNAL_ERROR;
	}

	struct ike_sa *ike = isakmp_sa_where(child, HERE);
	if (ike == NULL) {
		/* phase1 state got deleted while cryptohelper was working */
		llog(RC_LOG, child->sa.logger,
		     "%s() failed because parent ISAKMP "PRI_SO" is gone",
		     __func__, pri_so(child->sa.st_clonedfrom));
		return STF_FATAL;
	}

	/* SA in */
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
	RETURN_STF_FAIL_v1NURE(parse_ipsec_sa_body(&sa_pd->pbs,
						   &sa_pd->payload.sa,
						   NULL, true, child));

	/* Nr in */
	RETURN_STF_FAIL_v1NURE(accept_v1_nonce(child->sa.logger, md, &child->sa.st_nr, "Nr"));

	/* [ KE ] in (for PFS) */
	RETURN_STF_FAIL_v1NURE(accept_PFS_KE(child, md, &child->sa.st_gr, "Gr",
					     "Quick Mode R1"));

	if (child->sa.st_pfs_group != NULL) {
		/* set up DH calculation */
		submit_dh_shared_secret(/*callback*/&child->sa, /*task*/&child->sa, md,
					child->sa.st_gr,
					quick_inR1_outI2_continue,
					HERE);
		return STF_SUSPEND;
	}

	/* just call the tail function */
	return quick_inR1_outI2_continue_tail(ike, child, md);
}

static stf_status quick_inR1_outI2_continue(struct state *child_sa,
					    struct msg_digest *md)
{
	struct child_sa *child = pexpect_child_sa(child_sa);
	if (pbad(child == NULL)) {
		return STF_INTERNAL_ERROR;
	}

	struct ike_sa *ike = isakmp_sa_where(child, HERE);
	if (ike == NULL) {
		/* phase1 state got deleted while cryptohelper was working */
		llog(RC_LOG, child->sa.logger,
		     "phase2 initiation failed because parent ISAKMP #%lu is gone",
		     child->sa.st_clonedfrom);
		return STF_FATAL;
	}

	ldbg(child->sa.logger,
	     "quick_inR1_outI2_continue for "PRI_SO": calculated ke+nonce, calculating DH",
	     pri_so(child->sa.st_serialno));

	passert(md != NULL);
	return quick_inR1_outI2_continue_tail(ike, child, md);
}

stf_status quick_inR1_outI2_continue_tail(struct ike_sa *ike, struct child_sa *child, struct msg_digest *md)
{
	struct connection *c = child->sa.st_connection;

	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, true,
				       &reply_stream, reply_buffer, sizeof(reply_buffer),
				       &rbody, child->sa.logger);

	if (nat_traversal_detected(&child->sa) &&
	    (child->sa.hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA))
		nat_traversal_natoa_lookup(md, &child->sa.hidden_variables, child->sa.logger);

	/* [ IDci, IDcr ] in; these must match what we sent */

	{
		struct payload_digest *const IDci = md->chain[ISAKMP_NEXT_ID];
		struct payload_digest *IDcr;

		if (IDci != NULL) {
			/* ??? we are assuming IPSEC_DOI */

			/* IDci (we are initiator) */
			if (!check_net_id(&IDci->payload.ipsec_id, &IDci->pbs,
					  c->spd->local->client.ipproto,
					  c->spd->local->client.hport,
					  selector_subnet(child->sa.st_connection->spd->local->client),
					  "our client", child->sa.logger))
				return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;

			/* we checked elsewhere that we got two of them */
			IDcr = IDci->next;
			passert(IDcr != NULL);

			/* IDcr (responder is peer) */

			if (!check_net_id(&IDcr->payload.ipsec_id, &IDcr->pbs,
					  c->spd->remote->client.ipproto,
					  c->spd->remote->client.hport,
					  selector_subnet(child->sa.st_connection->spd->remote->client),
					  "peer client", child->sa.logger))
				return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;

			/*
			 * if there is a NATOA payload, then use it as
			 *    &child->sa.st_connection->spd->remote->client, if the type
			 * of the ID was FQDN
			 */
			if (nat_traversal_detected(&child->sa) &&
			    (child->sa.hidden_variables.st_nat_traversal &
			     NAT_T_WITH_NATOA) &&
			    IDcr->payload.ipsec_id.isaiid_idtype == ID_FQDN) {
				shunk_t idfqdn = pbs_in_left(&IDcr->pbs);
				update_first_selector(child->sa.st_connection, remote,
						      selector_from_address(child->sa.hidden_variables.st_nat_oa));
				LLOG_JAMBUF(RC_LOG, child->sa.logger, buf) {
					jam(buf, "IDcr was FQDN: ");
					jam_sanitized_hunk(buf, idfqdn);
					jam(buf, ", using NAT_OA=");
					jam_selector_subnet(buf, &child->sa.st_connection->spd->remote->client);
					jam(buf, " as IDcr");
				}
			}
		} else {
			/*
			 * No IDci, IDcr: we must check that the
			 * defaults match our proposal.
			 */
			if (!selector_eq_address(c->spd->local->client, c->local->host.addr) ||
			    !selector_eq_address(c->spd->remote->client, c->remote->host.addr)) {
				llog(RC_LOG, child->sa.logger,
				     "IDci, IDcr payloads missing in message but default does not match proposal");
				return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
			}
		}
	}

	/**************** build reply packet HDR*, HASH(3) ****************/

	/* HDR* out done */

	/* HASH(3) out -- sometimes, we add more content */

	struct v1_hash_fixup hash_fixup;

	if (!emit_v1_HASH(V1_HASH_3, "quick_inR1_outI2",
			  IMPAIR_v1_QUICK_EXCHANGE, &child->sa, &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	fixup_v1_HASH(&child->sa, &hash_fixup, child->sa.st_v1_msgid.id, NULL);

	/* Derive new keying material */
	compute_keymats(&child->sa);

	/* Tell the kernel to establish the inbound, outbound, and routing part
	 * of the new SA (unless the commit bit is set -- which we don't support).
	 * We do this before any state updating so that
	 * failure won't look like success.
	 */

	if (!connection_establish_child(ike, child, HERE))
		return STF_FAIL_v1N;

	/* encrypt message, except for fixed part of header */

	if (!ikev1_close_and_encrypt_message(&rbody, &child->sa)) {
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */
	}

	if (dpd_init(&child->sa) != STF_OK) {
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
	/*
	 * IKE must still exist as how else could the quick message
	 * have been decrypted?
	 */
	struct child_sa *child = pexpect_child_sa(st);
	struct ike_sa *ike = ike_sa(st, HERE);
	PEXPECT(child->sa.logger, ike != NULL);

	if (!connection_establish_outbound(ike, child, HERE))
		return STF_FAIL_v1N;

	update_iv(st);  /* not actually used, but tidy */

	/*
	 * If we have dpd delay and dpdtimeout set, then we are doing DPD
	 * on this conn, so initialize it
	 */
	if (dpd_init(st) != STF_OK) {
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
	struct connection_filter cq = {
		.ike_version = IKEv1,
		.search = {
			.order = NEW2OLD,
			.verbose.logger = c->logger,
			.where = HERE,
		},
	};
	while (next_connection(&cq)) {
		struct connection *d = cq.c;
		switch (d->local->kind) {
		case CK_PERMANENT:
		case CK_TEMPLATE:
		case CK_INSTANCE:

			if (is_template(d) &&
			    d->remote->config->child.selectors.len > 0) {
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
				    str_enum_short(&connection_kind_names, d->local->kind, &kb),
				    pri_connection(d, &dcb),
				    d->remote->config->leftright);
				continue;
			}

			if (!selector_overlaps_selector(*peer_net, d->spd->remote->client)) {
				/*
				 * For instance when PEER_NET is IPv6
				 * and remote .client is IPv4 (but can
				 * be pretty much anything that
				 * doesn't intersect).
				 */
				connection_buf dcb;
				enum_buf kb;
				dbg(" skipping %s "PRI_CONNECTION" as there is no overlap",
				    str_enum_short(&connection_kind_names, d->local->kind, &kb),
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
				    str_enum_short(&connection_kind_names, d->local->kind, &kb),
				    pri_connection(d, &dcb),
				    str_id(&d->remote->host.id, &idb));
				continue;
			}

			if (!kernel_ops->overlap_supported) {
				connection_buf cbuf;
				subnet_buf pcb, dcb;
				llog(RC_LOG, c->logger,
				     "peer Virtual IP %s overlapping %s from "PRI_CONNECTION" is not supported by the kernel interface %s",
				     str_selector_subnet(peer_net, &pcb),
				     str_selector_subnet(&d->spd->remote->client, &dcb),
				     pri_connection(d, &cbuf),
				     kernel_ops->interface_name);
				return true;
			}

			if (c->config->overlapip && d->config->overlapip) {
				connection_buf cbuf;
				subnet_buf pcb, dcb;
				llog(RC_LOG, c->logger,
				     "peer Virtual IP %s overlapping %s from "PRI_CONNECTION" permitted by mutual consent (and kernel support)",
				     str_selector_subnet(peer_net, &pcb),
				     pri_connection(d, &cbuf),
				     str_selector_subnet(&d->spd->remote->client, &dcb));
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

			if (c->config->overlapip) {
				/* not C; must be D objecting */
				connection_buf cbuf;
				subnet_buf pcb, dcb;
				llog(RC_LOG, c->logger,
				     "peer Virtual IP %s overlapping %s forbidden by "PRI_CONNECTION" policy",
				     str_selector_subnet(peer_net, &pcb),
				     pri_connection(d, &cbuf),
				     str_selector_subnet(&d->spd->remote->client, &dcb));
			} else if (d->config->overlapip) {
				/* not D; must be C objecting */
				connection_buf cbuf;
				subnet_buf pcb, dcb;
				llog(RC_LOG, c->logger,
				     "policy forbids peer Virtual IP %s overlapping %s from "PRI_CONNECTION"",
				     str_selector_subnet(peer_net, &pcb),
				     pri_connection(d, &cbuf),
				     str_selector_subnet(&d->spd->remote->client, &dcb));
			} else {
				/* must be both D and C objecting */
				connection_buf cbuf;
				subnet_buf pcb, dcb;
				llog(RC_LOG, c->logger,
				     "peer Virtual IP %s overlapping %s from "PRI_CONNECTION" is forbidden (neither agrees)",
				     str_selector_subnet(peer_net, &pcb),
				     str_selector_subnet(&d->spd->remote->client, &dcb),
				     pri_connection(d, &cbuf));
			}

			return true; /* already used by another one */

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

/*
 * fc_try() an unhelpful confusion of find_client_connection.
 */
static struct connection *fc_try(const struct connection *c,
				 const ip_address local_address,
				 const ip_address remote_address,
				 const ip_selector *local_client,
				 const ip_selector *remote_client,
				 struct verbose verbose)
{
	selector_pair_buf spb;
	address_buf lb, rb;
	vdbg("%s() %s<-%s %s",
	     __func__,
	     str_address(&local_address, &lb), str_address(&remote_address, &rb),
	     str_selector_pair(local_client, remote_client, &spb));
	verbose.level++;

	if (selector_is_unset(local_client) ||
	    selector_is_unset(remote_client)) {
		vdbg("null selectors!?!");
		return NULL;
	}

	struct connection *best = NULL;
	connection_priority_t best_prio = BOTTOM_PRIORITY;
	const bool remote_is_host = selector_eq_address(*remote_client,
							c->remote->host.addr);

	err_t virtualwhy = NULL;
	struct connection_filter hpf = {
		.host_pair = {
			.local = &local_address,
			.remote = &remote_address, /* could be %any */
		},
		.ike_version = IKEv1,
		.search = {
			.order = NEW2OLD,
			.verbose = verbose,
			.where = HERE,
		},
	};

	while (next_connection(&hpf)) {

		struct connection *d = hpf.c;
		struct verbose verbose = hpf.search.verbose;

		connection_buf cb;
		selector_pair_buf sb;
		vdbg("looking at "PRI_CONNECTION" with %s",
		     pri_connection(d, &cb),
		     str_selector_pair(&d->spd->local->client, &d->spd->remote->client, &sb));
		verbose.level++;

		if (is_instance(d) && d->remote->host.id.kind == ID_NULL) {
			vdbg("skipping unauthenticated connection instance with ID_NULL");
			continue;
		}

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
			if (!same_id(&c->local->host.id, &d->local->host.id)) {
				vdbg("skipping connection with same connalias but different IDs (logic is too complex)");
				continue;
			}
			if (!match_id(&c->remote->host.id, &d->remote->host.id,
				      &wildcards, verbose)) {
				vdbg("skipping connection with same connalias but mismatched ID (logic is too complex)");
				continue;
			}
			if (!trusted_ca(ASN1(c->remote->host.config->ca),
					ASN1(d->remote->host.config->ca), &pathlen)) {
				vdbg("skipping connection with same connalias but untrusted CA (logic is too complex)");
				continue;
			}
		}

		/*
		 * non-Opportunistic case: local_client must match.
		 *
		 * So must remote_client, but the testing is
		 * complicated by the fact that the peer might be a
		 * wildcard and if so, the default value of
		 * that.client won't match the default remote_net. The
		 * appropriate test:
		 *
		 * If d has a peer client, it must match remote_net.
		 * If d has no peer client, remote_net must just have peer itself.
		 */

		vdbg("checking connection's SPDs");
		verbose.level++;

		FOR_EACH_ITEM(d_spd, &d->child.spds) {

			selector_buf s1, d1;
			selector_buf s3, d3;
			vdbg("trying %s:%s:%d/%d -> %s:%d/%d%s vs %s:%s:%d/%d -> %s:%d/%d%s",
			     c->name,
			     str_selector_subnet_port(local_client, &s1),
			     c->spd->local->client.ipproto,
			     c->spd->local->client.hport,
			     str_selector_subnet_port(remote_client, &d1),
			     c->spd->remote->client.ipproto,
			     c->spd->remote->client.hport,
			     (is_virtual_remote(c, verbose) ? "(virt)" : ""),
			     d->name,
			     str_selector_subnet_port(&d_spd->local->client, &s3),
			     d_spd->local->client.ipproto,
			     d_spd->local->client.hport,
			     str_selector_subnet_port(&d_spd->remote->client, &d3),
			     d_spd->remote->client.ipproto,
			     d_spd->remote->client.hport,
			     (is_virtual_spd_end(d_spd->remote, verbose) ? "(virt)" : ""));

			if (!selector_range_eq_selector_range(d_spd->local->client, *local_client)) {
				selector_buf s1, s3;
				vdbg("our client (%s) not in local_net (%s)",
				     str_selector_subnet_port(&d_spd->local->client, &s3),
				     str_selector_subnet_port(local_client, &s1));
				continue;
			}

			/* compare protocol and ports */

			if (d_spd->local->client.ipproto != local_client->ipproto) {
				vdbg("skipping connection SPD with wrong local protocol");
				continue;
			}

			if (d_spd->remote->client.ipproto != remote_client->ipproto) {
				vdbg("skipping connection SPD with wrong remote protocol");
				continue;
			}

			if (d_spd->local->client.hport != 0 &&
			    d_spd->local->client.hport != local_client->hport) {
				vdbg("skipping connection SPD with wrong local port");
				continue;
			}

			if (!d->remote->config->child.protoport.has_port_wildcard &&
			    d_spd->remote->client.hport != remote_client->hport) {
				vdbg("skipping connection with wrong remote port");
				continue;
			}

			if (d_spd->remote->child->has_client) {

				if (!selector_range_eq_selector_range(d_spd->remote->client, *remote_client) &&
				    !is_virtual_spd_end(d_spd->remote, verbose)) {
					selector_buf d1, d3;
					vdbg("their client (%s) not in same remote_net (%s)",
					     str_selector_subnet_port(&d_spd->remote->client, &d3),
					     str_selector_subnet_port(remote_client, &d1));
					continue;
				}

				virtualwhy = check_virtual_net_allowed(d,
								       selector_subnet(*remote_client),
								       d_spd->remote->host->addr,
								       verbose);

				if (is_virtual_spd_end(d_spd->remote, verbose) &&
				    (virtualwhy != NULL ||
				     is_virtual_net_used(d, remote_client,
							 &d_spd->remote->host->id))) {
					vdbg("virtual net not allowed");
					continue;
				}
			} else if (!remote_is_host) {
				vdbg("not remote_is_host, so!?!");
				continue;
			}

			/*
			 * We've run the gauntlet -- success:
			 * We've got an exact match of subnets.
			 * The connection is feasible, but we continue looking
			 * for the best.
			 * The highest priority wins, implementing eroute-like
			 * rule.
			 * - a routed connection is preferred
			 * - given that, the smallest number of ID wildcards
			 *   are preferred
			 * - given that, the shortest CA pathlength is preferred
			 * - given that, not switching is preferred
			 */
			connection_priority_t prio =
				PRIO_WEIGHT * kernel_route_installed(d) +
				WILD_WEIGHT * (MAX_WILDCARDS - wildcards) +
				PATH_WEIGHT * (MAX_CA_PATH_LEN - pathlen) +
				(c == d ? 1 : 0) +
				1;
			if (prio <= best_prio) {
				vdbg("not the best as %d <= %d", prio, best_prio);
				continue;
			}

			vdbg("best so far!");
			best = d;
			best_prio = prio;
			break;
		}
	}

	if (best != NULL && never_negotiate(best)) {
		connection_buf cb;
		llog(RC_LOG, verbose.logger,
		     "best connection "PRI_CONNECTION" is never-negotiate, ignoring",
		     pri_connection(best, &cb));
		return NULL;
	}

	if (best != NULL) {
		connection_buf cb;
		vdbg("concluding with "PRI_CONNECTION" with priority %d",
		     pri_connection(best, &cb), best_prio);
		return best;
	}

	if (virtualwhy != NULL) {
		/* this may not be the only/real reason! */
		llog(RC_LOG, verbose.logger,
		     "peer proposal was rejected in a virtual connection policy: %s",
		     virtualwhy);
	}

	vdbg("concluding with no matching connection");
	return NULL;
}

struct connection *find_v1_client_connection(struct connection *const c,
					     const ip_selector *local_client,
					     const ip_selector *remote_client,
					     struct verbose verbose)
{
	selector_pair_buf sb;
	connection_buf cb;
	vdbg("%s() looking for %s, starting with "PRI_CONNECTION,
	     __func__, str_selector_pair(local_client, remote_client, &sb),
	     pri_connection(c, &cb));
	verbose.level++;

	/* weird things can happen to our interfaces */
	if (!oriented(c)) {
		vdbg("connection is unoriented");
		return NULL;
	}

	if (selector_is_unset(local_client)) {
		vdbg("peer's local client is not set");
		return NULL;
	}

	if (selector_is_unset(remote_client)) {
		vdbg("peer's remote client is not set");
		return NULL;
	}

	/*
	 * Give priority to current connection
	 * but even greater priority to a routed concrete connection.
	 */

	struct connection *d;
	int srnum = -1;
	struct connection *unrouted = NULL;

	FOR_EACH_ITEM(spd, &c->child.spds) {

		srnum++;

		selector_buf s2;
		selector_buf d2;
		vdbg("concrete checking against sr#%d %s -> %s", srnum,
		     str_selector_subnet_port(&spd->local->client, &s2),
		     str_selector_subnet_port(&spd->remote->client, &d2));

		/* compare selector ranges */

		if (!selector_range_eq_selector_range(spd->local->client, *local_client)) {
			selector_buf s1, s3;
			vdbg("our client (%s) does not have a matching local selector range (%s)",
			     str_selector_subnet_port(&spd->local->client, &s3),
			     str_selector_subnet_port(local_client, &s1));
			continue;
		}

		if (!selector_range_eq_selector_range(spd->remote->client, *remote_client)) {
			selector_buf s1, s3;
			vdbg("our client (%s) does not have a matching remote selector range (%s)",
			     str_selector_subnet_port(&spd->remote->client, &s3),
			     str_selector_subnet_port(remote_client, &s1));
			continue;
		}

		/* compare protocol */

		if (spd->local->client.ipproto != local_client->ipproto) {
			vdbg("skipping connection SPD with wrong local protocol");
			continue;
		}

		if (spd->remote->client.ipproto != remote_client->ipproto) {
			vdbg("skipping connection SPD with wrong remote protocol");
			continue;
		}

		/* compare port */

		if (spd->local->client.hport != 0 &&
		    spd->local->client.hport != local_client->hport) {
			vdbg("skipping connection SPD with wrong local port");
			continue;
		}

		if (spd->remote->client.hport != 0 &&
		    spd->remote->client.hport != remote_client->hport) {
			vdbg("skipping connection with wrong remote port");
			continue;
		}

		/* instant winner */
		if (kernel_route_installed(c)) {
			vdbg("connection has route installed; instant winner!");
			return c;
		}

		/* save for after fc_try() */
		vdbg("saving unrouted connection for later");
		unrouted = c;
	}

	/* exact match? */
	/*
	 * clang 3.4 says: warning: Access to field 'host_pair'
	 * results in a dereference of a null pointer (loaded from
	 * variable 'c')
	 *
	 * If so, the caller must have passed NULL for it and earlier
	 * references would be wrong (segfault).
	 */
	d = fc_try(c, c->local->host.addr, c->remote->host.addr,
		   local_client, remote_client, verbose);
	if (d != NULL) {
		connection_buf cb;
		vdbg("success! fc_try %s gives "PRI_CONNECTION,
		     c->name, pri_connection(d, &cb));
		return d;
	}

	if (unrouted != NULL) {
		connection_buf cb;
		vdbg("success! early search gave unrouted "PRI_CONNECTION,
		     pri_connection(unrouted, &cb));
		return unrouted;
	}

	/*
	 * Retry looking for a template.
	 */

	d = fc_try(c, c->local->host.addr, unset_address,
		   local_client, remote_client, verbose);
	if (d != NULL) {
		connection_buf cb;
		vdbg("success! template search found "PRI_CONNECTION,
		     pri_connection(d, &cb));
		return d;
	}

	vdbg("concluding with no connection");
	return NULL;
}
