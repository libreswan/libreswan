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
	} else if (l->addrtype == KH_IPADDR) {
		address_buf b;
		w->id = clone_str(str_address(&l->addr, &b), "if id");
	}

	w->host_type = l->addrtype;

	switch (l->addrtype) {
	case KH_IPADDR:
	case KH_IFACE:
		w->host_addr = l->addr;
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

	switch (l->nexttype) {
	case KH_IPADDR:
		w->nexthop = l->nexthop;
		break;

	case KH_DEFAULTROUTE: /* acceptable to set nexthop to %defaultroute */
	case KH_NOTSET:	/* acceptable to not set nexthop */
		/*
		 * but, get the family set up right
		 *
		 * XXX the nexthop type has to get into the whack
		 * message!
		 */
		w->nexthop = l->host_family->address.unspec;
		break;

	default:
		printf("%s: do something with nexthop case: %d\n", lr,
			l->nexttype);
		break;
	}

	w->sourceip = l->values[KSCF_SOURCEIP].string; /* could be NULL */

	if (cidr_is_specified(l->vti_ip))
		w->host_vtiip = l->vti_ip;

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
	w->host_ikeport = l->values[KNCF_IKEPORT].option;

	if (l->values[KSCF_PROTOPORT].set) {
		char *value = l->values[KSCF_PROTOPORT].string;
		err_t ugh = ttoprotoport(value, &w->protoport);

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
	if (l->values[KNCF_SENDCERT].set)
		w->sendcert = l->values[KNCF_SENDCERT].option;
	else
		w->sendcert = CERT_ALWAYSSEND;

	if (l->values[KNCF_AUTH].set)
		w->auth = l->values[KNCF_AUTH].option;

	if (l->values[KNCF_EAP].set)
		w->eap = l->values[KNCF_EAP].option;
	else
		w->eap = IKE_EAP_NONE;

	w->updown = l->values[KSCF_UPDOWN].string;

	if (l->values[KNCF_XAUTHSERVER].set)
		w->xauth_server = l->values[KNCF_XAUTHSERVER].option;
	if (l->values[KNCF_XAUTHCLIENT].set)
		w->xauth_client = l->values[KNCF_XAUTHCLIENT].option;
	if (l->values[KSCF_USERNAME].set)
		w->xauth_username = l->values[KSCF_USERNAME].string;
	if (l->values[KSCF_GROUNDHOG].set)
		w->groundhog = l->values[KSCF_GROUNDHOG].string;

	w->modecfgserver = l->values[KNCF_MODECONFIGSERVER].option;
	w->modecfgclient = l->values[KNCF_MODECONFIGCLIENT].option;
	w->cat = l->values[KNCF_CAT].option;		/* yn_options */

	w->addresspool = l->values[KSCF_ADDRESSPOOL].string;
	return true;
}

static int starter_whack_add_pubkey(const char *leftright,
				    const char *ctlsocket,
				    const struct starter_conn *conn,
				    char *keyid,
				    const char *pubkey,
				    enum ipseckey_algorithm_type pubkey_alg,
				    struct logger *logger)
{
	struct whack_message msg = {
		.whack_from = WHACK_FROM_ADDCONN,
		.whack_key = true,
		.pubkey_alg = pubkey_alg,
		.keyid = keyid,
	};

	int base;
	switch (pubkey_alg) {
	case IPSECKEY_ALGORITHM_RSA:
	case IPSECKEY_ALGORITHM_ECDSA:
		base = 0; /* figure it out */
		break;
	case IPSECKEY_ALGORITHM_X_PUBKEY:
		base = 64; /* dam it */
		break;
	default:
		bad_case(pubkey_alg);
	}

	chunk_t keyspace = NULL_HUNK; /* must free */
	err_t err = ttochunk(shunk1(pubkey), base, &keyspace);
	if (err != NULL) {
		enum_buf pkb;
		llog_error(logger, 0, "conn %s: %s%s malformed [%s]",
			   conn->name, leftright,
			   str_enum(&ipseckey_algorithm_config_names, pubkey_alg, &pkb),
			   err);
		return 1;
	}

	enum_buf pkb;
	ldbg(logger, "\tsending %s %s%s=%s",
	     conn->name, leftright,
	     str_enum(&ipseckey_algorithm_config_names, pubkey_alg, &pkb),
	     pubkey);
	msg.keyval = keyspace;
	int ret = whack_send_msg(&msg, ctlsocket, NULL, NULL, 0, 0, logger);
	free_chunk_content(&keyspace);

	if (ret < 0) {
		return ret;
	}

	return 0;
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
		.whack_add = true,
		.name = conn->name,
	};

	msg.host_afi = conn->end[LEFT_END].host_family;
	msg.child_afi = conn->clientaddrfamily;

	if (conn->end[RIGHT_END].addrtype == KH_IPHOSTNAME)
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
	msg.sa_ipsec_max_bytes = conn->values[KNCF_IPSEC_MAXBYTES].option;
	msg.sa_ipsec_max_packets = conn->values[KNCF_IPSEC_MAXPACKETS].option;
	msg.sa_rekeyfuzz_percent = conn->values[KNCF_REKEYFUZZ].option;
	if (conn->values[KNCF_KEYINGTRIES].set) {
		msg.keyingtries.set = true;
		msg.keyingtries.value = conn->values[KNCF_KEYINGTRIES].option;
	}
	msg.replay_window = conn->values[KNCF_REPLAY_WINDOW].option; /*has default*/
	msg.ipsec_interface = conn->values[KWS_IPSEC_INTERFACE].string;

	if (conn->values[KNCF_RETRANSMIT_INTERVAL].set) {
		msg.retransmit_interval = conn->values[KNCF_RETRANSMIT_INTERVAL].deltatime;
	}
	if (conn->values[KNCF_RETRANSMIT_TIMEOUT].set) {
		msg.retransmit_timeout = conn->values[KNCF_RETRANSMIT_TIMEOUT].deltatime;
	}

	msg.ike_version = conn->ike_version;
	msg.ikev2 = conn->values[KNCF_IKEv2].option;
	msg.pfs = conn->values[KNCF_PFS].option;
	msg.compress = conn->values[KNCF_COMPRESS].option;
	msg.type = conn->values[KNCF_TYPE].option;
	msg.phase2 = conn->values[KNCF_PHASE2].option;
	msg.authby = conn->authby;
	msg.sighash_policy = conn->sighash_policy;
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
	if (conn->values[KNCF_NO_ESP_TFC].set)
		msg.send_no_esp_tfc = conn->values[KNCF_NO_ESP_TFC].option;
	if (conn->values[KNCF_NFLOG_CONN].set)
		msg.nflog_group = conn->values[KNCF_NFLOG_CONN].option;

	if (conn->values[KNCF_REQID].set) {
		if (conn->values[KNCF_REQID].option <= 0 ||
		    conn->values[KNCF_REQID].option > IPSEC_MANUAL_REQID_MAX) {
			llog_error(logger, 0,
				   "ignoring reqid value - range must be 1-%u",
				   IPSEC_MANUAL_REQID_MAX);
		} else {
			msg.sa_reqid = conn->values[KNCF_REQID].option;
		}
	}

	if (conn->values[KNCF_TCP_REMOTEPORT].set) {
		msg.tcp_remoteport = conn->values[KNCF_TCP_REMOTEPORT].option;
	}

	if (conn->values[KNCF_ENABLE_TCP].set) {
		msg.enable_tcp = conn->values[KNCF_ENABLE_TCP].option;
	}

	/* default to HOLD */
	msg.dpddelay = conn->values[KSCF_DPDDELAY].string;
	msg.dpdtimeout = conn->values[KSCF_DPDTIMEOUT].string;

	if (conn->values[KNCF_SEND_CA].set)
		msg.send_ca = conn->values[KNCF_SEND_CA].option;
	else
		msg.send_ca = CA_SEND_NONE;


	msg.encapsulation = conn->values[KNCF_ENCAPSULATION].option;

	if (conn->values[KNCF_NAT_KEEPALIVE].set)
		msg.nat_keepalive = conn->values[KNCF_NAT_KEEPALIVE].option;
	else
		msg.nat_keepalive = true;

	/* can be 0 aka unset */
	msg.nat_ikev1_method = conn->values[KNCF_NAT_IKEv1_METHOD].option;

	/* Activate sending out own vendorid */
	if (conn->values[KNCF_SEND_VENDORID].set)
		msg.send_vendorid = conn->values[KNCF_SEND_VENDORID].option;

	/* Activate Cisco quircky behaviour not replacing old IPsec SA's */
	if (conn->values[KNCF_INITIAL_CONTACT].set)
		msg.initial_contact = conn->values[KNCF_INITIAL_CONTACT].option;

	/* Activate their quircky behaviour - rumored to be needed for ModeCfg and RSA */
	if (conn->values[KNCF_CISCO_UNITY].set)
		msg.cisco_unity = conn->values[KNCF_CISCO_UNITY].option;

	if (conn->values[KNCF_VID_STRONGSWAN].set)
		msg.fake_strongswan = conn->values[KNCF_VID_STRONGSWAN].option;

	/* Active our Cisco interop code if set */
	msg.remote_peer_type = conn->values[KNCF_REMOTE_PEER_TYPE].option;

#ifdef HAVE_NM
	/* Network Manager support */
	msg.nm_configured = conn->values[KNCF_NM_CONFIGURED].option;
#endif

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

	if (!set_whack_end(&msg.end[LEFT_END], &conn->end[LEFT_END], logger))
		return -1;
	if (!set_whack_end(&msg.end[RIGHT_END], &conn->end[RIGHT_END], logger))
		return -1;

	msg.esp = conn->values[KSCF_ESP].string;
	msg.ike = conn->values[KSCF_IKE].string;

	/*
	 * Save the "computed" pubkeys and IDs before the pointers in
	 * MSG are pickled.
	 */
	const char *left_pubkey = msg.end[LEFT_END].pubkey;
	const char *right_pubkey = msg.end[RIGHT_END].pubkey;
	char *left_id = msg.end[LEFT_END].id;
	char *right_id = msg.end[RIGHT_END].id;

	int r = whack_send_msg(&msg, ctlsocket, NULL, NULL, 0, 0, logger);
	if (r != 0)
		return r;

	/*
	 * XXX: the above sent over the pubkeys, why repeat?
	 *
	 * Because the above sending over pubkeys is a hack (but still
	 * the right thing to do).
	 */
	if (left_id != NULL && left_pubkey != NULL) {
		int r = starter_whack_add_pubkey("left", ctlsocket, conn,
						 left_id, left_pubkey,
						 msg.end[LEFT_END].pubkey_alg,
						 logger);
		if (r != 0) {
			return r;
		}
	}
	if (right_id != NULL && right_pubkey != NULL) {
		int r = starter_whack_add_pubkey("right", ctlsocket, conn,
						 right_id, right_pubkey,
						 msg.end[RIGHT_END].pubkey_alg,
						 logger);
		if (r != 0) {
			return r;
		}
	}

	return 0;
}

int starter_whack_listen(const char *ctlsocket, struct logger *logger)
{
	struct whack_message msg = {
		.whack_from = WHACK_FROM_ADDCONN,
		.whack_listen = true,
	};
	return whack_send_msg(&msg, ctlsocket, NULL, NULL, 0, 0, logger);
}
