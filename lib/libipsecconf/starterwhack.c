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

#include "lswalloc.h"
#include "lswlog.h"
#include "whack.h"
#include "id.h"
#include "ip_address.h"
#include "ip_info.h"
#include "lswlog.h"

static bool set_whack_end(struct whack_end *w,
			  const struct starter_end *l,
			  struct logger *logger)
{
	const char *lr = l->leftright;
	w->leftright = lr;

	/*
	 * Deal with ADDCONN's legacy ID syntax where, instead of
	 * "\,", ",," was used to escape commas!
	 *
	 * Don't move to pluto, so that when ADDCONN dies, this hack
	 * goes with it.
	 */

	if (l->values[KWS_ID].set) {
		char *value = l->values[KWS_ID].string;
		/*
		 * Fixup old ",," in a ID_DER_ASN1_DN to proper
		 * backslash comma.
		 */
		if (value[0] != '@' &&
		    strstr(value, ",,") != NULL &&
		    strstr(value, "=") != NULL) {
			llog(RC_LOG, logger,
			     "changing legacy ',,' to '\\,' in %sid=%s",
			     lr, value);
			char *cc;
			while ((cc = strstr(value, ",,")) != NULL) {
				cc[0] = '\\';
			}
		}
		w->id = value;
	}

	w->host = l->values[KWS_HOST].string;
	w->nexthop = l->values[KWS_NEXTHOP].string;
	w->sourceip = l->values[KWS_SOURCEIP].string; /* could be NULL */
	w->vti = l->values[KWS_VTI].string; /* could be NULL */
	w->interface_ip = l->values[KWS_INTERFACE_IP].string; /* could be NULL */

	/* validate the KSCF_SUBNET */
	if (l->values[KWS_SUBNET].set) {
		char *value = l->values[KWS_SUBNET].string;
		if (startswith(value, "vhost:") || startswith(value, "vnet:")) {
			w->virt = value;
		} else {
			w->subnet = value;
		}
	}

	w->subnets = l->values[KSCF_SUBNETS].string;
	w->ikeport = l->values[KWS_IKEPORT].string;
	w->protoport = l->values[KWS_PROTOPORT].string;
	w->cert = l->values[KWS_CERT].string;
	w->ckaid = l->values[KWS_CKAID].string;

	static const struct {
		enum ipseckey_algorithm_type alg;
		enum keywords kscf;
		const char *name;
	} keys[] = {
		{ .alg = IPSECKEY_ALGORITHM_RSA, KW_RSASIGKEY, "rsasigkey", },
		{ .alg = IPSECKEY_ALGORITHM_ECDSA, KW_ECDSAKEY, "ecdsakey", },
		{ .alg = IPSECKEY_ALGORITHM_X_PUBKEY, KW_PUBKEY, "pubkey", },
	};
	FOR_EACH_ELEMENT(key, keys) {
		if (!l->values[key->kscf].set) {
			continue;
		}

		switch (l->values[key->kscf].option) {

		case PUBKEY_DNSONDEMAND:
			w->key_from_DNS_on_demand = true;
			break;

		case PUBKEY_PREEXCHANGED:
			/*
			 * Only send over raw (prexchanged) rsapubkeys
			 * (i.e., not %cert et.a.)
			 *
			 * XXX: but what is with the two rsasigkeys?
			 * Whack seems to be willing to send pluto two
			 * raw pubkeys under the same ID.  Just assume
			 * that the first key should be used for the
			 * CKAID.
			 */
			w->key_from_DNS_on_demand = false;
			w->pubkey = l->values[key->kscf].string;
			w->pubkey_alg = key->alg;
			break;

		default:
			w->key_from_DNS_on_demand = false;
			break;
		}

		break;
	}

	w->ca = l->values[KWS_CA].string;
	w->sendcert = l->values[KWS_SENDCERT].string;

	if (l->values[KNCF_AUTH].set)
		w->auth = l->values[KNCF_AUTH].option;

	if (l->values[KNCF_EAP].set)
		w->eap = l->values[KNCF_EAP].option;
	else
		w->eap = IKE_EAP_NONE;

	w->updown = l->values[KWS_UPDOWN].string;

	w->xauthserver = l->values[KWYN_XAUTHSERVER].option;
	w->xauthclient = l->values[KWYN_XAUTHCLIENT].option;
	w->xauthusername = l->values[KWS_USERNAME].string;

	w->groundhog = l->values[KWYN_GROUNDHOG].option;

	w->modecfgserver = l->values[KWYN_MODECONFIGSERVER].option;
	w->modecfgclient = l->values[KWYN_MODECONFIGCLIENT].option;
	w->cat = l->values[KWYN_CAT].option;		/* yn_options */

	w->addresspool = l->values[KWS_ADDRESSPOOL].string;
	return true;
}

static void conn_log_val(struct logger *logger,
			 const struct starter_conn *conn,
			 const char *name, const char *value)
{
	if (value != NULL) {
		ldbg(logger, "conn: \"%s\" %s=%s", conn->name, name, value);
	}
}

int starter_whack_add_conn(const char *ctlsocket,
			   const struct starter_conn *conn,
			   struct logger *logger)
{
	struct whack_message msg = {
		.whack_from = WHACK_FROM_ADDCONN,
		.whack_command = WHACK_ADD,
		.name = conn->name,
	};

	msg.hostaddrfamily = conn->values[KWS_HOSTADDRFAMILY].string;
	msg.nic_offload = conn->values[KNCF_NIC_OFFLOAD].option;
	msg.ikelifetime = conn->values[KNCF_IKELIFETIME].deltatime;
	msg.ipsec_lifetime = conn->values[KNCF_IPSEC_LIFETIME].deltatime;
	msg.rekeymargin = conn->values[KNCF_REKEYMARGIN].deltatime;
	msg.ipsec_max_bytes = conn->values[KWS_IPSEC_MAX_BYTES].string;
	msg.ipsec_max_packets = conn->values[KWS_IPSEC_MAX_PACKETS].string;
	msg.rekeyfuzz = conn->values[KWS_REKEYFUZZ].string;
	msg.replay_window = conn->values[KWS_REPLAY_WINDOW].string;
	msg.ipsec_interface = conn->values[KWS_IPSEC_INTERFACE].string;

	msg.retransmit_interval = conn->values[KNCF_RETRANSMIT_INTERVAL].deltatime;
	msg.retransmit_timeout = conn->values[KNCF_RETRANSMIT_TIMEOUT].deltatime;

	msg.keyexchange = conn->values[KWS_KEYEXCHANGE].string;
	msg.ikev2 = conn->values[KWS_IKEv2].string;
	msg.pfs = conn->values[KWYN_PFS].option;
	msg.compress = conn->values[KWYN_COMPRESS].option;
	msg.type = conn->values[KNCF_TYPE].option;
	msg.phase2 = conn->values[KNCF_PHASE2].option;
	msg.authby = conn->values[KWS_AUTHBY].string;

	msg.never_negotiate_shunt = conn->never_negotiate_shunt;
	msg.negotiation_shunt = conn->negotiation_shunt;
	msg.failure_shunt = conn->failure_shunt;
	msg.autostart = conn->values[KNCF_AUTO].option;

	msg.connalias = conn->values[KSCF_CONNALIAS].string;

	msg.metric = conn->values[KNCF_METRIC].option;

	msg.narrowing = conn->values[KWYN_NARROWING].option;
	msg.rekey = conn->values[KWYN_REKEY].option;
	msg.reauth = conn->values[KWYN_REAUTH].option;

	if (conn->values[KNCF_MTU].set)
		msg.mtu = conn->values[KNCF_MTU].option;
	if (conn->values[KNCF_PRIORITY].set)
		msg.priority = conn->values[KNCF_PRIORITY].option;
	if (conn->values[KNCF_TFC].set)
		msg.tfc = conn->values[KNCF_TFC].option;
	msg.send_esp_tfc_padding_not_supported =
		conn->values[KWYN_SEND_ESP_TFC_PADDING_NOT_SUPPORTED].option;
	msg.nflog_group = conn->values[KWS_NFLOG_GROUP].string;
	msg.reqid = conn->values[KWS_REQID].string;

	if (conn->values[KNCF_TCP_REMOTEPORT].set) {
		msg.tcp_remoteport = conn->values[KNCF_TCP_REMOTEPORT].option;
	}

	if (conn->values[KNCF_ENABLE_TCP].set) {
		msg.enable_tcp = conn->values[KNCF_ENABLE_TCP].option;
	}

	/* default to HOLD */
	msg.dpddelay = conn->values[KWS_DPDDELAY].string;
	msg.dpdtimeout = conn->values[KWS_DPDTIMEOUT].string;

	msg.sendca = conn->values[KWS_SENDCA].string;

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
	msg.remote_peer_type = conn->values[KWS_REMOTE_PEER_TYPE].string;
	msg.cisco_unity = conn->values[KWS_CISCO_UNITY].string;
	msg.nm_configured = conn->values[KWS_NM_CONFIGURED].string;
	msg.cisco_split = conn->values[KWS_CISCO_SPLIT].string;

	msg.sec_label = conn->values[KWS_SEC_LABEL].string;
	msg.conn_debug = conn->values[KW_DEBUG].option;

	msg.modecfgdns = conn->values[KWS_MODECFGDNS].string;
	msg.modecfgdomains = conn->values[KWS_MODECFGDOMAINS].string;
	msg.modecfgbanner = conn->values[KWS_MODECFGBANNER].string;

	msg.mark = conn->values[KWS_MARK].string;
	msg.mark_in = conn->values[KWS_MARK_IN].string;
	msg.mark_out = conn->values[KWS_MARK_OUT].string;

	msg.vti_interface = conn->values[KWS_VTI_INTERFACE].string;
	conn_log_val(logger, conn, "vti-interface", msg.vti_interface);
	msg.vti_routing = conn->values[KWYN_VTI_ROUTING].option;
	msg.vti_shared = conn->values[KWYN_VTI_SHARED].option;

	msg.ppk_ids = conn->values[KWS_PPK_IDS].string;

	msg.redirect_to = conn->values[KWS_REDIRECT_TO].string;
	conn_log_val(logger, conn, "redirect-to", msg.redirect_to);
	msg.accept_redirect_to = conn->values[KWS_ACCEPT_REDIRECT_TO].string;
	conn_log_val(logger, conn, "accept-redirect-to", msg.accept_redirect_to);
	msg.send_redirect = conn->values[KNCF_SEND_REDIRECT].option;

	msg.session_resumption = conn->values[KWYN_SESSION_RESUMPTION].option;

	msg.mobike = conn->values[KWYN_MOBIKE].option; /*yn_options*/
	msg.intermediate = conn->values[KWYN_INTERMEDIATE].option; /*yn_options*/
	msg.sha2_truncbug = conn->values[KWYN_SHA2_TRUNCBUG].option; /*yn_options*/
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

	msg.iptfs = conn->values[KWYN_IPTFS].option; /* yn_options */
	msg.iptfs_fragmentation = conn->values[KWYN_IPTFS_FRAGMENTATION].option; /* yn_options */
	msg.iptfs_packet_size = conn->values[KNCF_IPTFS_PACKET_SIZE].option;
	msg.iptfs_max_queue_size = conn->values[KNCF_IPTFS_MAX_QUEUE_SIZE].option;
	msg.iptfs_reorder_window = conn->values[KWS_IPTFS_REORDER_WINDOW].string;
	msg.iptfs_init_delay = conn->values[KNCF_IPTFS_INIT_DELAY].deltatime;
	msg.iptfs_drop_time = conn->values[KNCF_IPTFS_DROP_TIME].deltatime;

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

	if (!set_whack_end(&msg.end[LEFT_END], &conn->end[LEFT_END], logger))
		return -1;
	if (!set_whack_end(&msg.end[RIGHT_END], &conn->end[RIGHT_END], logger))
		return -1;

	msg.esp = conn->values[KWS_ESP].string;
	msg.ike = conn->values[KWS_IKE].string;

	int r = whack_send_msg(&msg, ctlsocket, NULL, NULL, 0, 0, logger);
	if (r != 0)
		return r;

	return 0;
}

int starter_whack_listen(const char *ctlsocket, struct logger *logger)
{
	struct whack_message msg = {
		.whack_from = WHACK_FROM_ADDCONN,
		.whack_command = WHACK_LISTEN,
	};
	return whack_send_msg(&msg, ctlsocket, NULL, NULL, 0, 0, logger);
}
