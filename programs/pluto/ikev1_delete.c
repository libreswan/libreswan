/* Delete IKEv1, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2008 Ilia Sotnikov
 * Copyright (C) 2009 Seong-hun Lim
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010-2019 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#include "ikev1_delete.h"

#include "ip_said.h"

#include "defs.h"
#include "log.h"
#include "state.h"
#include "connections.h"
#include "ikev1.h"
#include "demux.h"
#include "pending.h"
#include "send.h"
#include "ipsec_doi.h"		/* for init_phase2_iv() !?! */
#include "ikev1_message.h"
#include "nat_traversal.h"
#include "kernel.h"
#include "ikev1_msgid.h"
#include "ikev1_hash.h"
#include "ikev1_nat.h"
#include "packet.h"
#include "terminate.h"

void send_v1_delete(struct ike_sa *ike, struct state *st, where_t where)
{
	ldbg(st->logger, "hacking around IKEv1 send'n'log delete for "PRI_SO" "PRI_WHERE,
	     pri_so(st->st_serialno), pri_where(where));

	if (!PEXPECT(st->logger, IS_V1_ISAKMP_SA_ESTABLISHED(&ike->sa))) {
		return;
	}

	struct pbs_out r_hdr_pbs;
	msgid_t msgid;
	ip_said said[EM_MAXRELSPIS];
	ip_said *ns = said;

	/* only once */
	on_delete(st, skip_send_delete);

	/*
	 * Find the established ISAKMP SA, can't send a delete notify
	 * without this.
	 */
	if (IS_IPSEC_SA_ESTABLISHED(st)) {
		if (st->st_ah.protocol == &ip_protocol_ah) {
			*ns = said_from_address_protocol_spi(st->st_connection->local->host.addr,
							     &ip_protocol_ah,
							     st->st_ah.inbound.spi);
			ns++;
		}
		if (st->st_esp.protocol == &ip_protocol_esp) {
			*ns = said_from_address_protocol_spi(st->st_connection->local->host.addr,
							     &ip_protocol_esp,
							     st->st_esp.inbound.spi);
			ns++;
		}

		PASSERT(st->logger, ns != said); /* there must be some SAs to delete */
	}

	if (impair.send_no_delete) {
		llog(RC_LOG, st->logger, "IMPAIR: impair-send-no-delete set - not sending Delete/Notify");
		return;
	}

	msgid = generate_msgid(&ike->sa);

	uint8_t buffer[8192];	/* ??? large enough for any deletion notification? */
	struct pbs_out reply_pbs = open_pbs_out("delete msg", buffer, sizeof(buffer), st->logger);

	/* HDR* */
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_INFO,
			.isa_msgid = msgid,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
		};
		hdr.isa_ike_initiator_spi = ike->sa.st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = ike->sa.st_ike_spis.responder;
		passert(out_struct(&hdr, &isakmp_hdr_desc, &reply_pbs,
				   &r_hdr_pbs));
	}

	/* HASH -- value to be filled later */
	struct v1_hash_fixup hash_fixup;
	if (!emit_v1_HASH(V1_HASH_1, "send delete",
			  IMPAIR_v1_DELETE_EXCHANGE,
			  &ike->sa, &hash_fixup, &r_hdr_pbs)) {
		return /* STF_INTERNAL_ERROR */;
	}

	/* Delete Payloads */
	if (st == &ike->sa) {
		struct isakmp_delete isad = {
			.isad_doi = ISAKMP_DOI_IPSEC,
			.isad_spisize = 2 * COOKIE_SIZE,
			.isad_protoid = PROTO_ISAKMP,
			.isad_nospi = 1,
		};

		struct pbs_out del_pbs;
		switch (impair.v1_isakmp_delete_payload) {
		case IMPAIR_EMIT_NO:
			passert(out_struct(&isad, &isakmp_delete_desc, &r_hdr_pbs, &del_pbs));
			passert(out_raw(st->st_ike_spis.initiator.bytes, COOKIE_SIZE,
					&del_pbs, "initiator SPI"));
			passert(out_raw(st->st_ike_spis.responder.bytes, COOKIE_SIZE,
					&del_pbs, "responder SPI"));
			close_output_pbs(&del_pbs);
			break;
		case IMPAIR_EMIT_OMIT:
			llog(RC_LOG, st->logger, "IMPAIR: omitting ISKMP delete payload");
			break;
		case IMPAIR_EMIT_EMPTY:
			passert(out_struct(&isad, &isakmp_delete_desc, &r_hdr_pbs, &del_pbs));
			llog(RC_LOG, st->logger, "IMPAIR: emitting empty (i.e., no SPI) ISKMP delete payload");
			close_output_pbs(&del_pbs);
			break;
		case IMPAIR_EMIT_DUPLICATE:
			llog(RC_LOG, st->logger, "IMPAIR: emitting duplicate ISKMP delete payloads");
			for (unsigned nr = 0; nr < 2; nr++) {
				passert(out_struct(&isad, &isakmp_delete_desc, &r_hdr_pbs, &del_pbs));
				passert(out_raw(st->st_ike_spis.initiator.bytes, COOKIE_SIZE,
						&del_pbs, "initiator SPI"));
				passert(out_raw(st->st_ike_spis.responder.bytes, COOKIE_SIZE,
						&del_pbs, "responder SPI"));
				close_output_pbs(&del_pbs);
			}
			break;
		}

	} else {
		while (ns != said) {
			ns--;
			const struct ip_protocol *proto = said_protocol(*ns);
			struct isakmp_delete isad = {
				.isad_doi = ISAKMP_DOI_IPSEC,
				.isad_spisize = sizeof(ipsec_spi_t),
				.isad_protoid = proto->ikev1_protocol_id,
				.isad_nospi = 1,
			};

			struct pbs_out del_pbs;
			switch (impair.v1_ipsec_delete_payload) {
			case IMPAIR_EMIT_NO:
				passert(out_struct(&isad, &isakmp_delete_desc,
						   &r_hdr_pbs, &del_pbs));
				passert(out_raw(&ns->spi, sizeof(ipsec_spi_t),
						&del_pbs, "delete payload"));
				close_output_pbs(&del_pbs);
				break;
			case IMPAIR_EMIT_OMIT:
				llog(RC_LOG, st->logger, "IMPAIR: omitting IPsec delete payload");
				break;
			case IMPAIR_EMIT_EMPTY:
				passert(out_struct(&isad, &isakmp_delete_desc,
						   &r_hdr_pbs, &del_pbs));
				llog(RC_LOG, st->logger, "IMPAIR: emitting empty (i.e., no SPI) IPsec delete payload");
				close_output_pbs(&del_pbs);
				break;
			case IMPAIR_EMIT_DUPLICATE:
				llog(RC_LOG, st->logger, "IMPAIR: emitting duplicate IPsec delete payloads");
				for (unsigned nr = 0; nr < 2; nr++) {
					passert(out_struct(&isad, &isakmp_delete_desc,
							   &r_hdr_pbs, &del_pbs));
					passert(out_raw(&ns->spi, sizeof(ipsec_spi_t),
							&del_pbs, "delete payload"));
					close_output_pbs(&del_pbs);
				}
				break;
			}

			if (impair.ikev1_del_with_notify) {
				struct pbs_out cruft_pbs;

				log_state(RC_LOG, st, "IMPAIR: adding bogus Notify payload after IKE Delete payload");
				struct isakmp_notification isan = {
					.isan_doi = ISAKMP_DOI_IPSEC,
					.isan_protoid = PROTO_ISAKMP,
					.isan_spisize = COOKIE_SIZE * 2,
					.isan_type = v1N_INVALID_PAYLOAD_TYPE,
				};

				passert(out_struct(&isan, &isakmp_notification_desc, &r_hdr_pbs,
					&cruft_pbs));
				passert(out_raw(&ns->spi, sizeof(ipsec_spi_t), &cruft_pbs,
					"notify payload"));
				close_output_pbs(&cruft_pbs);
			}
		}
	}

	/* calculate hash value and patch into Hash Payload */
	fixup_v1_HASH(&ike->sa, &hash_fixup, msgid, r_hdr_pbs.cur);

	/*
	 * Do a dance to avoid needing a new state object.
	 * We use the Phase 1 State. This is the one with right
	 * IV, for one thing.
	 * The tricky bits are:
	 * - we need to preserve (save/restore) st_iv (but not st_iv_new)
	 * - we need to preserve (save/restore) st_tpacket.
	 */
	{
		struct crypt_mac old_iv;

		save_iv(&ike->sa, old_iv);
		init_phase2_iv(&ike->sa, msgid, "IKE sending delete", HERE);

		passert(close_and_encrypt_v1_message(&r_hdr_pbs, &ike->sa));

		send_pbs_out_using_state(&ike->sa, "delete notify", &reply_pbs);

		/* get back old IV for this state */
		restore_iv(&ike->sa, old_iv);
	}
}

void llog_n_maybe_send_v1_delete(struct ike_sa *ike, struct state *st, where_t where)
{
	llog_sa_delete_n_send(ike, st);
	if (ike == NULL) {
		on_delete(st, skip_send_delete);
	} else {
		send_v1_delete(ike, st, where);
	}
}

/*
 * find_phase2_state_to_delete: find an AH or ESP SA to delete
 *
 * We are supposed to be given the other side's SPI.  Certain CISCO
 * implementations send our side's SPI instead.  We'll accept this,
 * but mark it as bogus.
 */

static struct child_sa *find_phase2_state_to_delete(const struct ike_sa *ike,
						    uint8_t protoid,
						    ipsec_spi_t spi,
						    bool *bogus)
{
	struct child_sa *bogusst = NULL;
	*bogus = false;

	struct state_filter sf = {
		.search = {
			.order = NEW2OLD,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
	};
	while (next_state(&sf)) {
		if (!IS_CHILD_SA(sf.st)) {
			continue;
		}
		struct child_sa *child = pexpect_child_sa(sf.st);
		if (!IS_IPSEC_SA_ESTABLISHED(&child->sa)) {
			continue;
		}
		if (!connections_can_share_parent(ike->sa.st_connection,
						  child->sa.st_connection)) {
			continue;
		}
		const struct ipsec_proto_info *pr =
			(protoid == PROTO_IPSEC_AH ? &child->sa.st_ah :
			 &child->sa.st_esp);
		if (pr->protocol == NULL) {
			continue;
		}
		if (pr->outbound.spi == spi) {
			*bogus = false;
			return child;
		}

		if (pr->inbound.spi == spi) {
			*bogus = true;
			bogusst = child;
			/* don't return! */
		}
	}
	return bogusst;
}

/*
 * Accept a Delete SA notification, and process it if valid.
 *
 * @param st State structure
 * @param md Message Digest
 * @param p Payload digest
 *
 * DANGER: this may stomp on *SDP and md->v1_st.
 *
 * Returns FALSE when the payload is crud.
 */

static bool handle_v1_delete_payload(struct state **stp,
				     struct msg_digest *md,
				     struct payload_digest *p)
{
	const struct isakmp_delete *d = &(p->payload.delete);

	struct ike_sa *ike = pexpect_ike_sa(*stp);

	if (d->isad_nospi == 0) {
		llog(RC_LOG, ike->sa.logger,
		     "ignoring Delete SA payload: no SPI");
		return false;
	}

	size_t sizespi;
	switch (d->isad_protoid) {
	case PROTO_ISAKMP:
		sizespi = 2 * COOKIE_SIZE;
		break;

	case PROTO_IPSEC_AH:
	case PROTO_IPSEC_ESP:
		sizespi = sizeof(ipsec_spi_t);
		break;

	case PROTO_IPCOMP:
		/* nothing interesting to delete */
		return true;

	default:
	{
		esb_buf b;
		llog(RC_LOG, ike->sa.logger,
		     "ignoring Delete SA payload: unknown Protocol ID (%s)",
		     str_enum(&ikev1_protocol_names, d->isad_protoid, &b));
		return false;
	}
	}

	if (d->isad_spisize != sizespi) {
		esb_buf b;
		llog(RC_LOG, ike->sa.logger,
		     "ignoring Delete SA payload: bad SPI size (%d) for %s",
		     d->isad_spisize,
		     str_enum(&ikev1_protocol_names, d->isad_protoid, &b));
		return false;
	}

	if (pbs_left(&p->pbs) != d->isad_nospi * sizespi) {
		llog(RC_LOG, ike->sa.logger,
		     "ignoring Delete SA payload: invalid payload size");
		return false;
	}

	for (unsigned i = 0; i < d->isad_nospi; i++) {
		if (d->isad_protoid == PROTO_ISAKMP) {
			/*
			 * ISAKMP
			 */
			ike_spis_t cookies;
			diag_t d;

			passert(sizeof(cookies.initiator) == COOKIE_SIZE);
			d = pbs_in_thing(&p->pbs, cookies.initiator, "iCookie");
			if (d != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				return false;
			}

			d = pbs_in_thing(&p->pbs, cookies.responder, "rCookie");
			if (d != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				return false;
			}

			/* this only finds ISAKMP SAs. Right!?! */
			struct ike_sa *dst = find_v1_isakmp_sa(&cookies);
			if (dst == NULL) {
				llog(RC_LOG, ike->sa.logger,
				     "ignoring Delete SA payload: ISAKMP SA not found (maybe expired)");
				continue;
			}

			if (!same_peer_ids(ike->sa.st_connection,
					   dst->sa.st_connection)) {
				/*
				 * we've not authenticated the relevant
				 * identities
				 */
				llog(RC_LOG, ike->sa.logger,
				     "ignoring Delete SA payload: ISAKMP SA used to convey Delete has different IDs from ISAKMP SA it deletes");
				continue;
			}

			/* note: this code is cloned for handling self_delete */
			llog(RC_LOG, ike->sa.logger,
			     "received Delete SA payload: %sdeleting ISAKMP State "PRI_SO,
			     (dst == ike ? "self-" : ""),
			     pri_so(dst->sa.st_serialno));
			if (dst->sa.st_connection->config->ikev1_natt != NATT_NONE) {
				nat_traversal_change_port_lookup(md, &dst->sa);
				v1_maybe_natify_initiator_endpoints(&ike->sa, HERE);
			}
			/*
			 * IKEv1 semantics: when an ISAKMP is deleted
			 * its children are left alone.  If the intent
			 * is to delete both then two messages are
			 * sent.
			 */
			bool self_inflicted = (dst == ike);
			connection_delete_ike(&dst, HERE);
			if (self_inflicted) {
				/* bail; IKE SA no longer viable */
				*stp = md->v1_st = NULL;
				dst = ike = NULL;
				return true; /* caller will see ST==NULL */
			}
		} else {
			/*
			 * IPSEC (ESP/AH)
			 */
			ipsec_spi_t spi;	/* network order */
			diag_t dt = pbs_in_thing(&p->pbs, spi, "SPI");
			if (dt != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(dt));
				pfree_diag(&dt);
				return false;
			}

			bool bogus;
			struct child_sa *p2d = find_phase2_state_to_delete(ike,
									   d->isad_protoid,
									   spi,
									   &bogus);
			if (p2d == NULL) {
				esb_buf b;
				llog(RC_LOG, ike->sa.logger,
				     "ignoring Delete SA payload: IPsec %s SA with SPI "PRI_IPSEC_SPI" not found (maybe expired)",
				     str_enum(&ikev1_protocol_names, d->isad_protoid, &b),
				     pri_ipsec_spi(spi));
				continue;
			}

			passert(&ike->sa != &p2d->sa);	/* st is an IKE SA */
			if (bogus) {
				esb_buf b;
				llog(RC_LOG, ike->sa.logger,
				     "warning: Delete SA payload: IPsec %s SA with SPI "PRI_IPSEC_SPI" is our own SPI (bogus implementation) - deleting anyway",
				     str_enum(&ikev1_protocol_names, d->isad_protoid, &b),
				     pri_ipsec_spi(spi));
			}

			if (p2d->sa.st_connection->config->ikev1_natt != NATT_NONE) {
				nat_traversal_change_port_lookup(md, &p2d->sa);
				v1_maybe_natify_initiator_endpoints(&ike->sa, HERE);
			}

			llog_sa(RC_LOG, p2d,
				"received Delete SA payload via "PRI_SO,
				pri_so(ike->sa.st_serialno));
			p2d->sa.st_replace_margin = deltatime(0); /*NEEDED?*/
			connection_delete_child(&p2d, HERE);

		}
	}

	return true;
}

bool handle_v1_delete_payloads(struct state **stp,
			       struct msg_digest *md)
{
	/* Need state for things to be encrypted */
	if ((*stp) == NULL) {
		/* should not be here */
		llog(RC_LOG, md->logger,
		     "ignoring Delete SA payload: no state");
		return false;
	}

	if (!IS_IKE_SA(*stp)) {
		llog(RC_LOG, (*stp)->logger,
		     "ignoring Delete SA payload: not an ISAKMP SA");
		return false;
	}

	/* We only listen to encrypted notifications */
	if (!md->encrypted) {
		llog(RC_LOG, (*stp)->logger,
		     "ignoring Delete SA payload: not encrypted");
		return false;
	}
	/* If there is no SA related to this request, but it was encrypted */
	if (!IS_V1_ISAKMP_SA_ESTABLISHED((*stp))) {
		/* can't happen (if msg is encrypt), but just to be sure */
		llog(RC_LOG, (*stp)->logger,
		     "ignoring Delete SA payload: ISAKMP SA not established");
		return false;
	}

	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_D];
	     p != NULL; p = p->next) {
		if (!handle_v1_delete_payload(stp, md, p)) {
			ldbg(md->logger, "bailing with bad delete message");
			return false;
		}
		if ((*stp) == NULL) {
			ldbg(md->logger, "bailing due to self-inflicted delete");
			return false;
		}
	}
	return true;
}
