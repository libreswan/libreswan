/* Libreswan NAT-Traversal
 *
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2005 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2006 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Gilles Espinasse <g.esp@free.fr>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Shinichi Furuso <Shinichi.Furuso@jp.sony.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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
 */

#include "defs.h"
#include "nat_traversal.h"
#include "ikev2_nat.h"
#include "iface.h"
#include "state.h"
#include "connections.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "ikev2_send.h"
#include "log.h"
#include "ikev2_notification.h"

/*
 * Add NAT-Traversal IKEv2 Notify payload (v2N)
 */
bool ikev2_out_nat_v2n(struct pbs_out *outs, struct state *st,
		       const ike_spi_t *ike_responder_spi)
{
	/*
	 * IKE SA INIT exchange can have responder's SPI still zero.
	 * While .st_ike_spis.responder should also be zero it often
	 * isn't - code likes to install the responder's SPI before
	 * everything is ready (only to have to the remove it).
	 */
	ike_spis_t ike_spis = {
		.initiator = st->st_ike_spis.initiator,
		.responder = *ike_responder_spi,
	};

	/* if encapsulation=yes, force NAT-T detection by using wrong port for hash calc */
	uint16_t lport = endpoint_hport(st->st_iface_endpoint->local_endpoint);
	if (st->st_connection->config->encapsulation == YNA_YES) {
		ldbg(st->logger, "NAT-T: encapsulation=yes, so mangling hash to force NAT-T detection");
		lport = 0;
	}
	ip_endpoint local_endpoint = set_endpoint_port(st->st_iface_endpoint->local_endpoint, ip_hport(lport));
	ip_endpoint remote_endpoint = st->st_remote_endpoint;
	return ikev2_out_natd(&local_endpoint, &remote_endpoint,
			      &ike_spis, outs);
}

bool ikev2_out_natd(const ip_endpoint *local_endpoint,
		    const ip_endpoint *remote_endpoint,
		    const ike_spis_t *ike_spis,
		    struct pbs_out *outs)
{
	ldbg(outs->logger, "NAT-Traversal: add v2N payloads");

	/* First: one with local (source) IP & port */

	struct crypt_mac hb = natd_hash(&ike_alg_hash_sha1, ike_spis, *local_endpoint,
					outs->logger);
	if (!emit_v2N_hunk(v2N_NAT_DETECTION_SOURCE_IP, hb, outs)) {
		return false;
	}

	/* Second: one with remote (destination) IP & port */

	hb = natd_hash(&ike_alg_hash_sha1, ike_spis, *remote_endpoint,
		       outs->logger);
	if (!emit_v2N_hunk(v2N_NAT_DETECTION_DESTINATION_IP, hb, outs)) {
		return false;
	}

	return true;
}

bool v2_nat_detected(struct ike_sa *ike, struct msg_digest *md)
{
	/* TODO: This use must be allowed even with USE_SHA1=false */
	static const struct hash_desc *hasher = &ike_alg_hash_sha1;

	passert(ike != NULL);
	passert(md->iface != NULL);

	/* must have both */
	if (md->pd[PD_v2N_NAT_DETECTION_SOURCE_IP] == NULL ||
	    md->pd[PD_v2N_NAT_DETECTION_DESTINATION_IP] == NULL) {
		return false;
	}
	/* table of both */
	const struct pbs_in *(detection_payloads[]) = {
		&md->pd[PD_v2N_NAT_DETECTION_DESTINATION_IP]->pbs,
		&md->pd[PD_v2N_NAT_DETECTION_SOURCE_IP]->pbs,
	};

	/*
	 * XXX: use the the IKE SPIs from the message header.
	 *
	 * The IKE_SA_INIT initiator doesn't know the responder's SPI
	 * so will have sent hashes using a responder SPI of 0.
	 *
	 * On the other hand, the responder does no its own SPI and so
	 * hashes against that.
	 */

	/* First: one with my IP & port. */
	struct crypt_mac hash_local = natd_hash(hasher, &md->hdr.isa_ike_spis,
						md->iface->local_endpoint,
						ike->sa.logger);
	/* Second: one with sender IP & port */
	struct crypt_mac hash_remote = natd_hash(hasher, &md->hdr.isa_ike_spis,
						 md->sender, ike->sa.logger);

	bool found_local = false;
	bool found_remote = false;

	for (const struct pbs_in **p = detection_payloads;
	     p < detection_payloads + elemsof(detection_payloads);
	     p++) {
		passert(*p != NULL);
		shunk_t hash = pbs_in_left(*p);
		/* redundant, also checked by hunk_eq() */
		if (hash.len != hasher->hash_digest_size)
			continue;
		/* ??? do we know from the isan_type which of these to test? */
		/* XXX: should this check pbs_left(), see other code */
		if (hunk_eq(hash, hash_local)) {
			found_local = true;
		}
		if (hunk_eq(hash, hash_remote)) {
			found_remote = true;
		}
	}

	natd_lookup_common(&ike->sa, md->sender, found_local, found_remote);
	return nat_traversal_detected(&ike->sa);
}

bool v2_natify_initiator_endpoints(struct ike_sa *ike, where_t where)
{
	/*
	 * Float the local port to :PLUTO_NAT_PORT (:4500).  This
	 * means rebinding the interface.
	 */
	if (ike->sa.st_iface_endpoint->esp_encapsulation_enabled) {
		endpoint_buf b1;
		dbg("NAT: #%lu not floating local port; interface %s supports encapsulated ESP "PRI_WHERE,
		    ike->sa.st_serialno,
		    str_endpoint(&ike->sa.st_iface_endpoint->local_endpoint, &b1),
		    pri_where(where));
	} else if (ike->sa.st_iface_endpoint->float_nat_initiator) {
		/*
		 * For IPv4, both :PLUTO_PORT and :PLUTO_NAT_PORT are
		 * opened by server.c so the new endpoint using
		 * :PLUTO_NAT_PORT should exist.  IPv6 nat isn't
		 * supported.
		 */
		ip_endpoint new_local_endpoint = set_endpoint_port(ike->sa.st_iface_endpoint->local_endpoint, ip_hport(NAT_IKE_UDP_PORT));
		/* returns new reference */
		struct iface_endpoint *i =
			find_iface_endpoint_by_local_endpoint(new_local_endpoint);
		if (i == NULL) {
			endpoint_buf b2;
			llog_sa(RC_LOG/*fatal!*/, ike,
				  "NAT: cannot float to %s as no such interface",
				  str_endpoint(&new_local_endpoint, &b2));
			return false; /* must enable NAT */
		}
		endpoint_buf b1, b2;
		dbg("NAT: #%lu floating local port from %s to %s using NAT_IKE_UDP_PORT "PRI_WHERE,
		    ike->sa.st_serialno,
		    str_endpoint(&ike->sa.st_iface_endpoint->local_endpoint, &b1),
		    str_endpoint(&new_local_endpoint, &b2),
		    pri_where(where));
		iface_endpoint_delref(&ike->sa.st_iface_endpoint);
		ike->sa.st_iface_endpoint = i;
	} else {
		endpoint_buf b1;
		llog_sa(RC_LOG/*fatal!*/, ike,
			  "NAT: cannot switch to NAT port and interface %s does not support NAT",
			  str_endpoint(&ike->sa.st_iface_endpoint->local_endpoint, &b1));
		return false;
	}

	/*
	 * Float the remote port from IKE_UDP_PORT (:500) to
	 * :NAT_IKE_UDP_PORT (:4500).
	 *
	 * XXX: see also end_host_port().  Some of these are
	 * redundant, but logging is useful.
	 */
	unsigned remote_hport = endpoint_hport(ike->sa.st_remote_endpoint);
	if (ike->sa.st_connection->remote->host.config->ikeport != 0) {
		dbg("NAT: #%lu not floating remote port; hardwired to ikeport=%u "PRI_WHERE,
		    ike->sa.st_serialno, ike->sa.st_connection->remote->host.config->ikeport,
		    pri_where(where));
	} else if (remote_hport != IKE_UDP_PORT) {
		dbg("NAT: #%lu not floating remote port; already pointing at non-IKE_UDP_PORT %u "PRI_WHERE,
		    ike->sa.st_serialno, remote_hport, pri_where(where));
	} else {
		pexpect(remote_hport == IKE_UDP_PORT);
		/* same address+protocol; change port */
		ip_endpoint new_endpoint = set_endpoint_port(ike->sa.st_remote_endpoint,
							     ip_hport(NAT_IKE_UDP_PORT));
		endpoint_buf oep, nep;
		ldbg(ike->sa.logger,
		     "NAT: "PRI_SO" floating remote port from %s to %s using NAT_IKE_UDP_PORT "PRI_WHERE,
		     pri_so(ike->sa.st_serialno),
		     str_endpoint(&ike->sa.st_remote_endpoint, &oep),
		     str_endpoint(&new_endpoint, &nep),
		     pri_where(where));
		ike->sa.st_remote_endpoint = new_endpoint;
	}

	return true;
}
