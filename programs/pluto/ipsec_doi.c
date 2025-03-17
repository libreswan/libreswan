/*
 * IPsec DOI and Oakley resolution routines
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2010-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2006  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2011 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2014-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Antony Antony <antony@phenome.org>
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
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "keys.h"
#include "demux.h"      /* needs packet.h */
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "server.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "ikev1_quick.h"
#include "whack.h"
#include "asn1.h"
#include "crypto.h"
#include "secrets.h"
#include "crypt_dh.h"
#include "ike_alg.h"
#include "ike_alg_integ.h"
#include "ike_alg_encrypt.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1.h"
#include "ikev1_continuations.h"
#include "ikev2.h"
#include "ikev2_send.h"
#include "ikev1_xauth.h"
#include "ip_info.h"
#include "nat_traversal.h"
#include "ikev1_dpd.h"
#include "pluto_x509.h"
#include "ip_address.h"
#include "pluto_stats.h"
#include "chunk.h"
#include "pending.h"
#include "iface.h"
#include "ikev2_delete.h"	/* for record_v2_delete(); but call is dying */
#include "orient.h"
#include "initiate.h"
#include "ikev2_ike_sa_init.h"

/*
 * Start from policy in (ipsec) state, not connection.  This ensures
 * that rekeying doesn't downgrade security.  I admit that this
 * doesn't capture everything.
 */

struct child_policy capture_child_rekey_policy(struct state *st)
{
	/*
	 * ESP/AH are non-negotiatable, hence the connection value can
	 * be used.
	 *
	 * Note that the initiate code tests for non-LEMPTY policy
	 * when deciding if an IKE (ISAKMP) SA should also initiate
	 * the connection as a Child SA (look for add_pending()).
	 */
	const struct connection *c = st->st_connection;
	if (c->config->child_sa.encap_proto == ENCAP_PROTO_ESP ||
	    c->config->child_sa.encap_proto == ENCAP_PROTO_AH) {
		return (struct child_policy) {
			.is_set = true,
			.transport = (st->st_kernel_mode == KERNEL_MODE_TRANSPORT),
			.compress = (st->st_ipcomp.protocol == &ip_protocol_ipcomp),
		};
	}

	/*
	 * Without ESP/AH the connection must be never-negotiate,
	 * hence return unset.
	 */
	return (struct child_policy){0}; /*empty*/
}

void jam_child_sa_details(struct jambuf *buf, struct state *st)
{
	struct connection *const c = st->st_connection;
	const char *ini = "{";

	if (st->st_esp.protocol == &ip_protocol_esp) {
		jam_string(buf, ini);
		ini = " ";
		bool nat = nat_traversal_detected(st);
		bool tfc = c->config->child_sa.tfcpad != 0 && !st->st_seen_no_tfc;
		bool esn = st->st_esp.trans_attrs.esn_enabled;
		bool iptfs = st->st_seen_and_use_iptfs;
		bool tcp = st->st_iface_endpoint->io->protocol == &ip_protocol_tcp;

		if (nat)
			dbg("NAT-T: NAT Traversal detected - their IKE port is '%d'",
			     c->remote->host.port);

		jam(buf, "ESP%s%s%s%s=>0x%08" PRIx32 " <0x%08" PRIx32 "",
		    tcp ? "inTCP" : nat ? "inUDP" : "",
		    esn ? "/ESN" : "",
		    tfc ? "/TFC" : "",
		    iptfs ? "/IPTFS" : "",
		    ntohl(st->st_esp.outbound.spi),
		    ntohl(st->st_esp.inbound.spi));
		jam(buf, " xfrm=%s", st->st_esp.trans_attrs.ta_encrypt->common.fqn);
		/* log keylen when it is required and/or "interesting" */
		if (!st->st_esp.trans_attrs.ta_encrypt->keylen_omitted ||
		    (st->st_esp.trans_attrs.enckeylen != 0 &&
		     st->st_esp.trans_attrs.enckeylen != st->st_esp.trans_attrs.ta_encrypt->keydeflen)) {
			jam(buf, "_%u", st->st_esp.trans_attrs.enckeylen);
		}
		jam(buf, "-%s", st->st_esp.trans_attrs.ta_integ->common.fqn);

		if ((st->st_ike_version == IKEv2) && st->st_pfs_group != NULL) {
			jam_string(buf, "-");
			jam_string(buf, st->st_pfs_group->common.fqn);
		}

		/*
		 * We should really mark this somewhere on the child state
		 */
		if (c->iface->nic_offload && (c->config->nic_offload == NIC_OFFLOAD_PACKET ||
			c->config->nic_offload == NIC_OFFLOAD_CRYPTO)) {
			jam(buf, " nic-offload=%s", c->config->nic_offload == NIC_OFFLOAD_PACKET ?
				"packet" : "crypto");
		}

	}

	if (st->st_ah.protocol == &ip_protocol_ah) {
		jam_string(buf, ini);
		ini = " ";
		jam(buf, "AH%s=>0x%08" PRIx32 " <0x%08" PRIx32 " xfrm=%s",
		    st->st_ah.trans_attrs.esn_enabled ? "/ESN" : "",
		    ntohl(st->st_ah.outbound.spi),
		    ntohl(st->st_ah.inbound.spi),
		    st->st_ah.trans_attrs.ta_integ->common.fqn);
	}

	if (st->st_ipcomp.protocol == &ip_protocol_ipcomp) {
		jam_string(buf, ini);
		ini = " ";
		jam(buf, "IPCOMP=>0x%08" PRIx32 " <0x%08" PRIx32,
		    ntohl(st->st_ipcomp.outbound.spi),
		    ntohl(st->st_ipcomp.inbound.spi));
	}

	if (address_is_specified(st->hidden_variables.st_nat_oa)) {
		jam_string(buf, ini);
		ini = " ";
		jam_string(buf, "NATOA=");
		jam_address_sensitive(buf, &st->hidden_variables.st_nat_oa);
	}

	if (address_is_specified(st->hidden_variables.st_natd)) {
		jam_string(buf, ini);
		ini = " ";
		jam_string(buf, "NATD=");
		jam_address_sensitive(buf, &st->hidden_variables.st_natd);
		jam(buf, ":%d", endpoint_hport(st->st_remote_endpoint));
	}

	jam_string(buf, ini);
	ini = " ";
	jam_string(buf, "DPD=");
	if (st->st_ike_version == IKEv1 && !st->hidden_variables.st_peer_supports_dpd) {
		jam_string(buf, "unsupported");
	} else if (dpd_active_locally(st->st_connection)) {
		jam_string(buf, "active");
	} else {
		jam_string(buf, "passive");
	}

	if (st->st_xauth_username[0] != '\0') {
		jam_string(buf, ini);
		ini = " ";
		jam_string(buf, "username=");
		jam_string(buf, st->st_xauth_username);
	}

	jam_string(buf, "}");
}

void jam_parent_sa_details(struct jambuf *buf, struct state *st)
{
	passert(st->st_oakley.ta_encrypt != NULL);
	passert(st->st_oakley.ta_prf != NULL);
	passert(st->st_oakley.ta_dh != NULL);

	jam_string(buf, "{");

	if (st->st_ike_version == IKEv1) {
		jam(buf, "auth=");
		jam_enum_short(buf, &oakley_auth_names, st->st_oakley.auth);
		jam(buf, " ");
	}

	jam(buf, "cipher=%s", st->st_oakley.ta_encrypt->common.fqn);
	if (st->st_oakley.enckeylen > 0) {
		/* XXX: also check omit key? */
		jam(buf, "_%d", st->st_oakley.enckeylen);
	}

	/*
	 * Note: for IKEv1 and AEAD encrypters,
	 * st->st_oakley.ta_integ is 'none'!
	 */
	jam_string(buf, " integ=");
	if (st->st_ike_version == IKEv2) {
		if (st->st_oakley.ta_integ == &ike_alg_integ_none) {
			jam_string(buf, "n/a");
		} else {
			jam_string(buf, st->st_oakley.ta_integ->common.fqn);
		}
	} else {
		/*
		 * For IKEv1, since the INTEG algorithm is potentially
		 * (always?) NULL.  Display the PRF.  The choice and
		 * behaviour are historic.
		 */
		jam_string(buf, st->st_oakley.ta_prf->common.fqn);
	}

	if (st->st_ike_version == IKEv2) {
		jam(buf, " prf=%s", st->st_oakley.ta_prf->common.fqn);
	}

	jam(buf, " group=%s}", st->st_oakley.ta_dh->common.fqn);
}
