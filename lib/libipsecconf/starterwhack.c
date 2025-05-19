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
			  const struct ip_info *host_afi,
			  struct logger *logger)
{
	const char *lr = l->leftright;
	w->leftright = lr;

	/* validate the KSCF_ID */
	if (l->values[KSCF_ID].string != NULL) {
		char *value = l->values[KSCF_ID].string;
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
	} else if (l->resolve.host.type == KH_IPADDR) {
		address_buf b;
		w->id = clone_str(str_address(&l->resolve.host.addr, &b), "if id");
	}

	w->host_type = l->resolve.host.type;

	switch (l->resolve.host.type) {
	case KH_IPADDR:
	case KH_IFACE:
		w->host_addr = l->resolve.host.addr;
		break;

	case KH_DEFAULTROUTE:
	case KH_IPHOSTNAME:
		/* note: we always copy the name string below */
		w->host_addr = unset_address;
		break;

	case KH_OPPO:
	case KH_GROUP:
	case KH_OPPOGROUP:
		/* policy should have been set to OPPO */
		w->host_addr = unset_address;
		break;

	case KH_ANY:
		w->host_addr = unset_address;
		break;

	default:
		printf("Failed to load connection %s= is not set\n", lr);
		return false;
	}
	w->host_addr_name = l->values[KW_IP].string;

	switch (l->resolve.nexthop.type) {
	case KH_IPADDR:
		w->nexthop = l->resolve.nexthop.addr;
		break;

	case KH_DEFAULTROUTE: /* acceptable to set nexthop to %defaultroute */
	case KH_NOTSET:	/* acceptable to not set nexthop */
		/*
		 * but, get the family set up right
		 *
		 * XXX the nexthop type has to get into the whack
		 * message!
		 */
		w->nexthop = host_afi->address.unspec;
		break;

	default:
		printf("%s: do something with nexthop case: %d\n", lr,
			l->resolve.nexthop.type);
		break;
	}

	w->sourceip = l->values[KSCF_SOURCEIP].string; /* could be NULL */
	w->vti = l->values[KSCF_VTI].string; /* could be NULL */
	w->interface_ip = l->values[KSCF_INTERFACE_IP].string; /* could be NULL */

	/* validate the KSCF_SUBNET */
	if (l->values[KSCF_SUBNET].string != NULL) {
		char *value = l->values[KSCF_SUBNET].string;
		if (startswith(value, "vhost:") || startswith(value, "vnet:")) {
			w->virt = value;
		} else {
			w->subnet = value;
		}
	}

	w->subnets = l->values[KSCF_SUBNETS].string;
	w->ikeport = l->values[KNCF_IKEPORT].string;

	if (l->values[KSCF_PROTOPORT].set) {
		char *value = l->values[KSCF_PROTOPORT].string;
		err_t ugh = ttoprotoport(shunk1(value), &w->protoport);

		if (ugh != NULL) {
			llog_error(logger, 0, "bad %sprotoport=%s [%s]",
				   lr, value, ugh);
			return false;
		}
	}

	w->cert = l->values[KSCF_CERT].string;
	w->ckaid = l->values[KSCF_CKAID].string;

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

	w->ca = l->values[KSCF_CA].string;
	w->sendcert = l->values[KNCF_SENDCERT].string;

	if (l->values[KNCF_AUTH].set)
		w->auth = l->values[KNCF_AUTH].option;

	if (l->values[KNCF_EAP].set)
		w->eap = l->values[KNCF_EAP].option;
	else
		w->eap = IKE_EAP_NONE;

	w->updown = l->values[KSCF_UPDOWN].string;

	w->xauthserver = l->values[KWYN_XAUTHSERVER].option;
	w->xauthclient = l->values[KWYN_XAUTHCLIENT].option;
	w->xauthusername = l->values[KSCF_USERNAME].string;

	w->groundhog = l->values[KSCF_GROUNDHOG].option;

	w->modecfgserver = l->values[KNCF_MODECONFIGSERVER].option;
	w->modecfgclient = l->values[KNCF_MODECONFIGCLIENT].option;
	w->cat = l->values[KNCF_CAT].option;		/* yn_options */

	w->addresspool = l->values[KSCF_ADDRESSPOOL].string;
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

	msg.host_afi = conn->host_afi;

	if (conn->end[RIGHT_END].resolve.host.type == KH_IPHOSTNAME)
		msg.dnshostname = conn->end[RIGHT_END].values[KW_IP].string;

	msg.nic_offload = conn->values[KNCF_NIC_OFFLOAD].option;
	if (conn->values[KNCF_IKELIFETIME].set) {
		msg.ikelifetime = conn->values[KNCF_IKELIFETIME].deltatime;
	}
	if (conn->values[KNCF_IPSEC_LIFETIME].set) {
		msg.ipsec_lifetime = conn->values[KNCF_IPSEC_LIFETIME].deltatime;
	}
	if (conn->values[KNCF_REKEYMARGIN].set) {
		msg.rekeymargin = conn->values[KNCF_REKEYMARGIN].deltatime;
	}
	msg.ipsec_max_bytes = conn->values[KWS_IPSEC_MAX_BYTES].string;
	msg.ipsec_max_packets = conn->values[KWS_IPSEC_MAX_PACKETS].string;
	msg.rekeyfuzz = conn->values[KWS_REKEYFUZZ].string;
	msg.replay_window = conn->values[KWS_REPLAY_WINDOW].string;
	msg.ipsec_interface = conn->values[KWS_IPSEC_INTERFACE].string;

	if (conn->values[KNCF_RETRANSMIT_INTERVAL].set) {
		msg.retransmit_interval = conn->values[KNCF_RETRANSMIT_INTERVAL].deltatime;
	}
	if (conn->values[KNCF_RETRANSMIT_TIMEOUT].set) {
		msg.retransmit_timeout = conn->values[KNCF_RETRANSMIT_TIMEOUT].deltatime;
	}

	msg.keyexchange = conn->values[KWS_KEYEXCHANGE].string;
	msg.ikev2 = conn->values[KWS_IKEv2].string;
	msg.pfs = conn->values[KNCF_PFS].option;
	msg.compress = conn->values[KNCF_COMPRESS].option;
	msg.type = conn->values[KNCF_TYPE].option;
	msg.phase2 = conn->values[KNCF_PHASE2].option;
	msg.authby = conn->values[KWS_AUTHBY].string;

	msg.never_negotiate_shunt = conn->never_negotiate_shunt;
	msg.negotiation_shunt = conn->negotiation_shunt;
	msg.failure_shunt = conn->failure_shunt;
	msg.autostart = conn->values[KNCF_AUTO].option;

	msg.connalias = conn->values[KSCF_CONNALIAS].string;

	msg.metric = conn->values[KNCF_METRIC].option;

	msg.narrowing = conn->values[KNCF_NARROWING].option;
	msg.rekey = conn->values[KNCF_REKEY].option;
	msg.reauth = conn->values[KNCF_REAUTH].option;

	if (conn->values[KNCF_MTU].set)
		msg.mtu = conn->values[KNCF_MTU].option;
	if (conn->values[KNCF_PRIORITY].set)
		msg.priority = conn->values[KNCF_PRIORITY].option;
	if (conn->values[KNCF_TFC].set)
		msg.tfc = conn->values[KNCF_TFC].option;
	msg.send_esp_tfc_padding_not_supported =
		conn->values[KWYN_SEND_ESP_TFC_PADDING_NOT_SUPPORTED].option;
	msg.nflog_group = conn->values[KNCF_NFLOG_GROUP].string;
	msg.reqid = conn->values[KNCF_REQID].string;

	if (conn->values[KNCF_TCP_REMOTEPORT].set) {
		msg.tcp_remoteport = conn->values[KNCF_TCP_REMOTEPORT].option;
	}

	if (conn->values[KNCF_ENABLE_TCP].set) {
		msg.enable_tcp = conn->values[KNCF_ENABLE_TCP].option;
	}

	/* default to HOLD */
	msg.dpddelay = conn->values[KSCF_DPDDELAY].string;
	msg.dpdtimeout = conn->values[KSCF_DPDTIMEOUT].string;

	msg.sendca = conn->values[KNCF_SENDCA].string;

	msg.encapsulation = conn->values[KNCF_ENCAPSULATION].option;

	msg.nat_keepalive = conn->values[KWYN_NAT_KEEPALIVE].option;

	/* can be 0 aka unset */
	msg.nat_ikev1_method = conn->values[KNCF_NAT_IKEv1_METHOD].option;

	/* Activate sending out own vendorid */
	msg.send_vendorid = conn->values[KNCF_SEND_VENDORID].option;

	/* Activate Cisco quircky behaviour not replacing old IPsec SA's */
	msg.initial_contact = conn->values[KWYN_INITIAL_CONTACT].option;

	msg.fake_strongswan = conn->values[KNCF_FAKE_STRONGSWAN].option;

	/*
	 * Cisco (UNITY).
	 */
	msg.remote_peer_type = conn->values[KWS_REMOTE_PEER_TYPE].string;
	msg.cisco_unity = conn->values[KWS_CISCO_UNITY].string;
	msg.nm_configured = conn->values[KWS_NM_CONFIGURED].string;

	msg.sec_label = conn->values[KSCF_SEC_LABEL].string;
	msg.conn_debug = conn->values[KW_DEBUG].option;

	msg.modecfgdns = conn->values[KSCF_MODECFGDNS].string;
	msg.modecfgdomains = conn->values[KSCF_MODECFGDOMAINS].string;
	msg.modecfgbanner = conn->values[KSCF_MODECFGBANNER].string;

	msg.mark = conn->values[KSCF_MARK].string;
	msg.mark_in = conn->values[KSCF_MARK_IN].string;
	msg.mark_out = conn->values[KSCF_MARK_OUT].string;

	msg.vti_interface = conn->values[KSCF_VTI_INTERFACE].string;
	conn_log_val(logger, conn, "vti-interface", msg.vti_interface);
	msg.vti_routing = conn->values[KNCF_VTI_ROUTING].option;
	msg.vti_shared = conn->values[KNCF_VTI_SHARED].option;

	msg.ppk_ids = conn->values[KSCF_PPK_IDS].string;

	msg.redirect_to = conn->values[KSCF_REDIRECT_TO].string;
	conn_log_val(logger, conn, "redirect-to", msg.redirect_to);
	msg.accept_redirect_to = conn->values[KSCF_ACCEPT_REDIRECT_TO].string;
	conn_log_val(logger, conn, "accept-redirect-to", msg.accept_redirect_to);
	msg.send_redirect = conn->values[KNCF_SEND_REDIRECT].option;

	msg.session_resumption = conn->values[KNCF_SESSION_RESUMPTION].option;

	msg.mobike = conn->values[KNCF_MOBIKE].option; /*yn_options*/
	msg.intermediate = conn->values[KNCF_INTERMEDIATE].option; /*yn_options*/
	msg.sha2_truncbug = conn->values[KNCF_SHA2_TRUNCBUG].option; /*yn_options*/
	msg.overlapip = conn->values[KNCF_OVERLAPIP].option; /*yn_options*/
	msg.ms_dh_downgrade = conn->values[KNCF_MS_DH_DOWNGRADE].option; /*yn_options*/
	msg.pfs_rekey_workaround = conn->values[KNCF_PFS_REKEY_WORKAROUND].option;
	msg.dns_match_id = conn->values[KNCF_DNS_MATCH_ID].option; /* yn_options */
	msg.pam_authorize = conn->values[KNCF_PAM_AUTHORIZE].option; /* yn_options */
	msg.ignore_peer_dns = conn->values[KNCF_IGNORE_PEER_DNS].option; /* yn_options */
	msg.ikepad = conn->values[KNCF_IKEPAD].option; /* yna_options */
	msg.require_id_on_certificate = conn->values[KNCF_REQUIRE_ID_ON_CERTIFICATE].option; /* yn_options */
	msg.modecfgpull = conn->values[KNCF_MODECFGPULL].option; /* yn_options */
	msg.aggressive = conn->values[KNCF_AGGRESSIVE].option; /* yn_options */

	msg.iptfs = conn->values[KNCF_IPTFS].option; /* yn_options */
	msg.iptfs_fragmentation = conn->values[KNCF_IPTFS_FRAGMENTATION].option; /* yn_options */
	msg.iptfs_packet_size = conn->values[KNCF_IPTFS_PACKET_SIZE].option;
	msg.iptfs_max_queue_size = conn->values[KNCF_IPTFS_MAX_QUEUE_SIZE].option;
	msg.iptfs_reorder_window = conn->values[KNCF_IPTFS_REORDER_WINDOW].option;
	msg.iptfs_init_delay = conn->values[KNCF_IPTFS_INIT_DELAY].deltatime;
	msg.iptfs_drop_time = conn->values[KNCF_IPTFS_DROP_TIME].deltatime;

	msg.decap_dscp = conn->values[KNCF_DECAP_DSCP].option; /* yn_options */
	msg.encap_dscp = conn->values[KNCF_ENCAP_DSCP].option; /* yn_options */
	msg.nopmtudisc = conn->values[KNCF_NOPMTUDISC].option; /* yn_options */
	msg.accept_redirect = conn->values[KNCF_ACCEPT_REDIRECT].option; /* yn_options */
	msg.fragmentation = conn->values[KNCF_FRAGMENTATION].option; /* yna_options */
	msg.esn = conn->values[KNCF_ESN].option; /* yne_options */
	msg.ppk = conn->values[KNCF_PPK].option; /* nppi_options */

	if (conn->values[KNCF_XAUTHBY].set)
		msg.xauthby = conn->values[KNCF_XAUTHBY].option;
	if (conn->values[KNCF_XAUTHFAIL].set)
		msg.xauthfail = conn->values[KNCF_XAUTHFAIL].option;

	if (!set_whack_end(&msg.end[LEFT_END], &conn->end[LEFT_END],
			   conn->host_afi, logger))
		return -1;
	if (!set_whack_end(&msg.end[RIGHT_END], &conn->end[RIGHT_END],
			   conn->host_afi, logger))
		return -1;

	msg.esp = conn->values[KSCF_ESP].string;
	msg.ike = conn->values[KSCF_IKE].string;

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
