/*
 * Libreswan whack functions to communicate with pluto (whack.c)
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2011 Mattias Walström <lazzer@vmlinux.org>
 * Copyright (C) 2012-2017 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include <sys/types.h>
#include <sys/un.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "lsw_socket.h"

#include "ttodata.h"

#include "ipsecconf/starterwhack.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/keywords.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "whack.h"
#include "id.h"
#include "ip_address.h"
#include "ip_info.h"
#include "lswlog.h"

static bool set_whack_end(struct whack_end *w,
			  const struct starter_end *l)
{
	const char *lr = l->leftright;
	w->leftright = lr;

	for (enum config_conn_keyword kw = 1; kw < CONFIG_CONN_KEYWORD_ROOF; kw++) {
		w->conn->value[kw] = l->values[kw].string;
	}

	return true;
}

int starter_whack_add_conn(const char *ctlsocket,
			   const struct starter_conn *conn,
			   struct logger *logger)
{
	struct whack_message msg;
	init_whack_message(&msg, WHACK_FROM_ADDCONN);

	msg.whack_command = WHACK_ADD;
	msg.name = conn->name;

	for (enum config_conn_keyword kw = 1; kw < CONFIG_CONN_KEYWORD_ROOF; kw++) {
		msg.conn[END_ROOF].value[kw] = conn->values[kw].string;
	}

	msg.nic_offload = conn->values[KNCF_NIC_OFFLOAD].option;
	msg.ikelifetime = conn->values[KNCF_IKELIFETIME].deltatime;
	msg.ipsec_lifetime = conn->values[KNCF_IPSEC_LIFETIME].deltatime;
	msg.rekeymargin = conn->values[KNCF_REKEYMARGIN].deltatime;

	msg.retransmit_timeout = conn->values[KNCF_RETRANSMIT_TIMEOUT].deltatime;

	msg.pfs = conn->values[KWYN_PFS].option;
	msg.compress = conn->values[KWYN_COMPRESS].option;
	msg.type = conn->values[KNCF_TYPE].option;
	msg.authby = conn->values[KWS_AUTHBY].string;

	msg.never_negotiate_shunt = conn->never_negotiate_shunt;
	msg.negotiation_shunt = conn->negotiation_shunt;
	msg.failure_shunt = conn->failure_shunt;
	msg.autostart = conn->values[KNCF_AUTO].option;

	msg.metric = conn->values[KNCF_METRIC].option;

	msg.narrowing = conn->values[KWYN_NARROWING].option;
	msg.rekey = conn->values[KWYN_REKEY].option;
	msg.reauth = conn->values[KWYN_REAUTH].option;

	msg.send_esp_tfc_padding_not_supported =
		conn->values[KWYN_SEND_ESP_TFC_PADDING_NOT_SUPPORTED].option;
	msg.reject_simultaneous_ike_auth = conn->values[KWYN_REJECT_SIMULTANEOUS_IKE_AUTH].option;

	if (conn->values[KNCF_TCP_REMOTEPORT].set) {
		msg.tcp_remoteport = conn->values[KNCF_TCP_REMOTEPORT].option;
	}

	if (conn->values[KNCF_ENABLE_TCP].set) {
		msg.enable_tcp = conn->values[KNCF_ENABLE_TCP].option;
	}

	msg.encapsulation = conn->values[KNCF_ENCAPSULATION].option;

	msg.nat_keepalive = conn->values[KWYN_NAT_KEEPALIVE].option;

	/* can be 0 aka unset */
	msg.nat_ikev1_method = conn->values[KNCF_NAT_IKEv1_METHOD].option;

	/* Activate sending out own vendorid */
	msg.send_vendorid = conn->values[KWYN_SEND_VENDORID].option;

	/* Activate Cisco quircky behaviour not replacing old IPsec SA's */
	msg.initial_contact = conn->values[KWYN_INITIAL_CONTACT].option;

	msg.fake_strongswan = conn->values[KWYN_FAKE_STRONGSWAN].option;

	/*
	 * Cisco (UNITY).
	 */
	msg.debug = conn->values[KWS_DEBUG].string;

	msg.vti_routing = conn->values[KWYN_VTI_ROUTING].option;
	msg.vti_shared = conn->values[KWYN_VTI_SHARED].option;

	msg.send_redirect = conn->values[KNCF_SEND_REDIRECT].option;

	msg.session_resumption = conn->values[KWYN_SESSION_RESUMPTION].option;

	msg.mobike = conn->values[KWYN_MOBIKE].option; /*yn_options*/
	msg.intermediate = conn->values[KWYN_INTERMEDIATE].option; /*yn_options*/
	msg.sha2_truncbug = conn->values[KWYN_SHA2_TRUNCBUG].option; /*yn_options*/
	msg.share_lease = conn->values[KWYN_SHARE_LEASE].option; /*yn_options*/
	msg.overlapip = conn->values[KWYN_OVERLAPIP].option; /*yn_options*/
	msg.ms_dh_downgrade = conn->values[KWYN_MS_DH_DOWNGRADE].option; /*yn_options*/
	msg.pfs_rekey_workaround = conn->values[KWYN_PFS_REKEY_WORKAROUND].option;
	msg.dns_match_id = conn->values[KWYN_DNS_MATCH_ID].option; /* yn_options */
	msg.pam_authorize = conn->values[KWYN_PAM_AUTHORIZE].option; /* yn_options */
	msg.ignore_peer_dns = conn->values[KWYN_IGNORE_PEER_DNS].option; /* yn_options */
	msg.ikepad = conn->values[KNCF_IKEPAD].option; /* yna_options */
	msg.require_id_on_certificate = conn->values[KWYN_REQUIRE_ID_ON_CERTIFICATE].option; /* yn_options */
	msg.modecfgpull = conn->values[KWYN_MODECFGPULL].option; /* yn_options */
	msg.aggressive = conn->values[KWYN_AGGRESSIVE].option; /* yn_options */

	msg.decap_dscp = conn->values[KWYN_DECAP_DSCP].option; /* yn_options */
	msg.encap_dscp = conn->values[KWYN_ENCAP_DSCP].option; /* yn_options */
	msg.nopmtudisc = conn->values[KWYN_NOPMTUDISC].option; /* yn_options */
	msg.accept_redirect = conn->values[KWYN_ACCEPT_REDIRECT].option; /* yn_options */
	msg.fragmentation = conn->values[KNCF_FRAGMENTATION].option; /* yna_options */
	msg.esn = conn->values[KNCF_ESN].option; /* yne_options */
	msg.ppk = conn->values[KNCF_PPK].option; /* nppi_options */

	if (conn->values[KNCF_XAUTHBY].set)
		msg.xauthby = conn->values[KNCF_XAUTHBY].option;
	if (conn->values[KNCF_XAUTHFAIL].set)
		msg.xauthfail = conn->values[KNCF_XAUTHFAIL].option;

	if (!set_whack_end(&msg.end[LEFT_END], &conn->end[LEFT_END])) {
		return -1;
	}
	if (!set_whack_end(&msg.end[RIGHT_END], &conn->end[RIGHT_END])) {
		return -1;
	}

	msg.phase2 = conn->values[KNCF_PHASE2].option;

	int r = whack_send_msg(&msg, ctlsocket, NULL, NULL, 0, 0, logger);
	if (r != 0)
		return r;

	return 0;
}

int starter_whack_listen(const char *ctlsocket, struct logger *logger)
{
	struct whack_message msg;
	init_whack_message(&msg, WHACK_FROM_ADDCONN);
	msg.whack_command = WHACK_LISTEN;
	return whack_send_msg(&msg, ctlsocket, NULL, NULL, 0, 0, logger);
}
