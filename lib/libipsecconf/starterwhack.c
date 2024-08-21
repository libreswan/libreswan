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
	if (l->strings[KSCF_ID] != NULL) {
		char *value = l->strings[KSCF_ID];
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
	w->host_addr_name = l->strings[KW_IP];

	switch (l->nexttype) {
	case KH_IPADDR:
		w->host_nexthop = l->nexthop;
		break;

	case KH_DEFAULTROUTE: /* acceptable to set nexthop to %defaultroute */
	case KH_NOTSET:	/* acceptable to not set nexthop */
		/*
		 * but, get the family set up right
		 * XXX the nexthop type has to get into the whack message!
		 */
		w->host_nexthop = l->host_family->address.unspec;
		break;

	default:
		printf("%s: do something with nexthop case: %d\n", lr,
			l->nexttype);
		break;
	}

	w->sourceip = l->strings[KSCF_SOURCEIP]; /* could be NULL */

	if (cidr_is_specified(l->vti_ip))
		w->host_vtiip = l->vti_ip;

	if (cidr_is_specified(l->ifaceip))
		w->ifaceip = l->ifaceip;

	/* validate the KSCF_SUBNET */
	if (l->strings[KSCF_SUBNET] != NULL) {
		char *value = l->strings[KSCF_SUBNET];
		if (startswith(value, "vhost:") || startswith(value, "vnet:")) {
			w->virt = value;
		} else {
			w->subnet = value;
		}
	}

	w->subnets = l->strings[KSCF_SUBNETS];
	w->host_ikeport = l->options[KNCF_IKEPORT];
	w->protoport = l->protoport;

	w->cert = l->strings[KSCF_CERT];
	w->ckaid = l->strings[KSCF_CKAID];

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
		if (!l->set[key->kscf]) {
			continue;
		}

		switch (l->options[key->kscf]) {

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
			w->pubkey = l->strings[key->kscf];
			w->pubkey_alg = key->alg;
			break;

		default:
			w->key_from_DNS_on_demand = false;
			break;
		}

		break;
	}

	w->ca = l->strings[KSCF_CA];
	if (l->set[KNCF_SENDCERT])
		w->sendcert = l->options[KNCF_SENDCERT];
	else
		w->sendcert = CERT_ALWAYSSEND;

	if (l->set[KNCF_AUTH])
		w->auth = l->options[KNCF_AUTH];

	if (l->set[KNCF_EAP])
		w->eap = l->options[KNCF_EAP];
	else
		w->eap = IKE_EAP_NONE;

	w->updown = l->strings[KSCF_UPDOWN];

	if (l->set[KNCF_XAUTHSERVER])
		w->xauth_server = l->options[KNCF_XAUTHSERVER];
	if (l->set[KNCF_XAUTHCLIENT])
		w->xauth_client = l->options[KNCF_XAUTHCLIENT];
	if (l->set[KSCF_USERNAME])
		w->xauth_username = l->strings[KSCF_USERNAME];
	if (l->set[KSCF_GROUNDHOG])
		w->groundhog = l->strings[KSCF_GROUNDHOG];

	if (l->set[KNCF_MODECONFIGSERVER])
		w->modecfg_server = l->options[KNCF_MODECONFIGSERVER];
	if (l->set[KNCF_MODECONFIGCLIENT])
		w->modecfg_client = l->options[KNCF_MODECONFIGCLIENT];
	if (l->set[KNCF_CAT])
		w->cat = l->options[KNCF_CAT];

	w->addresspool = l->strings[KSCF_ADDRESSPOOL];
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

	msg.host_afi = conn->left.host_family;
	msg.child_afi = conn->clientaddrfamily;

	if (conn->right.addrtype == KH_IPHOSTNAME)
		msg.dnshostname = conn->right.strings[KW_IP];

	msg.nic_offload = conn->options[KNCF_NIC_OFFLOAD];
	if (conn->set[KNCF_IKELIFETIME_MS]) {
		msg.ikelifetime = deltatime_ms(conn->options[KNCF_IKELIFETIME_MS]);
	}
	if (conn->set[KNCF_IPSEC_LIFETIME_MS]) {
		msg.ipsec_lifetime = deltatime_ms(conn->options[KNCF_IPSEC_LIFETIME_MS]);
	}
	msg.sa_rekey_margin = deltatime_ms(conn->options[KNCF_REKEYMARGIN_MS]);
	msg.sa_ipsec_max_bytes = conn->options[KNCF_IPSEC_MAXBYTES];
	msg.sa_ipsec_max_packets = conn->options[KNCF_IPSEC_MAXPACKETS];
	msg.sa_rekeyfuzz_percent = conn->options[KNCF_REKEYFUZZ];
	if (conn->set[KNCF_KEYINGTRIES]) {
		msg.keyingtries.set = true;
		msg.keyingtries.value = conn->options[KNCF_KEYINGTRIES];
	}
	msg.replay_window = conn->options[KNCF_REPLAY_WINDOW]; /*has default*/
	msg.ipsec_interface = conn->strings[KSCF_IPSEC_INTERFACE];

	msg.retransmit_interval = deltatime_ms(conn->options[KNCF_RETRANSMIT_INTERVAL_MS]);
	msg.retransmit_timeout = deltatime_ms(conn->options[KNCF_RETRANSMIT_TIMEOUT_MS]);

	msg.ike_version = conn->ike_version;
	msg.ikev2 = conn->options[KNCF_IKEv2];
	msg.pfs = conn->options[KNCF_PFS];
	msg.compress = conn->options[KNCF_COMPRESS];
	msg.type = conn->options[KNCF_TYPE];
	msg.phase2 = conn->options[KNCF_PHASE2];
	msg.authby = conn->authby;
	msg.sighash_policy = conn->sighash_policy;
	msg.never_negotiate_shunt = conn->never_negotiate_shunt;
	msg.negotiation_shunt = conn->negotiation_shunt;
	msg.failure_shunt = conn->failure_shunt;
	msg.autostart = conn->options[KNCF_AUTO];

	msg.connalias = conn->strings[KSCF_CONNALIAS];

	msg.metric = conn->options[KNCF_METRIC];

	msg.narrowing = conn->options[KNCF_NARROWING];
	msg.rekey = conn->options[KNCF_REKEY];
	msg.reauth = conn->options[KNCF_REAUTH];

	if (conn->set[KNCF_MTU])
		msg.mtu = conn->options[KNCF_MTU];
	if (conn->set[KNCF_PRIORITY])
		msg.priority = conn->options[KNCF_PRIORITY];
	if (conn->set[KNCF_TFC])
		msg.tfc = conn->options[KNCF_TFC];
	if (conn->set[KNCF_NO_ESP_TFC])
		msg.send_no_esp_tfc = conn->options[KNCF_NO_ESP_TFC];
	if (conn->set[KNCF_NFLOG_CONN])
		msg.nflog_group = conn->options[KNCF_NFLOG_CONN];

	if (conn->set[KNCF_REQID]) {
		if (conn->options[KNCF_REQID] <= 0 ||
		    conn->options[KNCF_REQID] > IPSEC_MANUAL_REQID_MAX) {
			llog_error(logger, 0,
				   "ignoring reqid value - range must be 1-%u",
				   IPSEC_MANUAL_REQID_MAX);
		} else {
			msg.sa_reqid = conn->options[KNCF_REQID];
		}
	}

	if (conn->set[KNCF_TCP_REMOTEPORT]) {
		msg.tcp_remoteport = conn->options[KNCF_TCP_REMOTEPORT];
	}

	if (conn->set[KNCF_ENABLE_TCP]) {
		msg.enable_tcp = conn->options[KNCF_ENABLE_TCP];
	}

	/* default to HOLD */
	msg.dpddelay = conn->strings[KSCF_DPDDELAY];
	msg.dpdtimeout = conn->strings[KSCF_DPDTIMEOUT];

	if (conn->set[KNCF_SEND_CA])
		msg.send_ca = conn->options[KNCF_SEND_CA];
	else
		msg.send_ca = CA_SEND_NONE;


	msg.encapsulation = conn->options[KNCF_ENCAPSULATION];

	if (conn->set[KNCF_NAT_KEEPALIVE])
		msg.nat_keepalive = conn->options[KNCF_NAT_KEEPALIVE];
	else
		msg.nat_keepalive = true;

	/* can be 0 aka unset */
	msg.nat_ikev1_method = conn->options[KNCF_NAT_IKEv1_METHOD];

	/* Activate sending out own vendorid */
	if (conn->set[KNCF_SEND_VENDORID])
		msg.send_vendorid = conn->options[KNCF_SEND_VENDORID];

	/* Activate Cisco quircky behaviour not replacing old IPsec SA's */
	if (conn->set[KNCF_INITIAL_CONTACT])
		msg.initial_contact = conn->options[KNCF_INITIAL_CONTACT];

	/* Activate their quircky behaviour - rumored to be needed for ModeCfg and RSA */
	if (conn->set[KNCF_CISCO_UNITY])
		msg.cisco_unity = conn->options[KNCF_CISCO_UNITY];

	if (conn->set[KNCF_VID_STRONGSWAN])
		msg.fake_strongswan = conn->options[KNCF_VID_STRONGSWAN];

	/* Active our Cisco interop code if set */
	msg.remote_peer_type = conn->options[KNCF_REMOTE_PEER_TYPE];

#ifdef HAVE_NM
	/* Network Manager support */
	msg.nm_configured = conn->options[KNCF_NM_CONFIGURED];
#endif

	msg.sec_label = conn->strings[KSCF_SEC_LABEL];
	msg.conn_debug = conn->options[KW_DEBUG];

	msg.modecfgdns = conn->strings[KSCF_MODECFGDNS];
	msg.modecfgdomains = conn->strings[KSCF_MODECFGDOMAINS];
	msg.modecfgbanner = conn->strings[KSCF_MODECFGBANNER];

	msg.mark = conn->strings[KSCF_MARK];
	msg.mark_in = conn->strings[KSCF_MARK_IN];
	msg.mark_out = conn->strings[KSCF_MARK_OUT];

	msg.vti_interface = conn->strings[KSCF_VTI_INTERFACE];
	conn_log_val(logger, conn, "vti-interface", msg.vti_interface);
	msg.vti_routing = conn->options[KNCF_VTI_ROUTING];
	msg.vti_shared = conn->options[KNCF_VTI_SHARED];

	msg.ppk_ids = conn->strings[KSCF_PPK_IDS];

	msg.redirect_to = conn->strings[KSCF_REDIRECT_TO];
	conn_log_val(logger, conn, "redirect-to", msg.redirect_to);
	msg.accept_redirect_to = conn->strings[KSCF_ACCEPT_REDIRECT_TO];
	conn_log_val(logger, conn, "accept-redirect-to", msg.accept_redirect_to);
	msg.send_redirect = conn->options[KNCF_SEND_REDIRECT];

	msg.mobike = conn->options[KNCF_MOBIKE]; /*yn_options*/
	msg.intermediate = conn->options[KNCF_INTERMEDIATE]; /*yn_options*/
	msg.sha2_truncbug = conn->options[KNCF_SHA2_TRUNCBUG]; /*yn_options*/
	msg.overlapip = conn->options[KNCF_OVERLAPIP]; /*yn_options*/
	msg.ms_dh_downgrade = conn->options[KNCF_MS_DH_DOWNGRADE]; /*yn_options*/
	msg.pfs_rekey_workaround = conn->options[KNCF_PFS_REKEY_WORKAROUND];
	msg.dns_match_id = conn->options[KNCF_DNS_MATCH_ID]; /* yn_options */
	msg.pam_authorize = conn->options[KNCF_PAM_AUTHORIZE]; /* yn_options */
	msg.ignore_peer_dns = conn->options[KNCF_IGNORE_PEER_DNS]; /* yn_options */
	msg.ikepad = conn->options[KNCF_IKEPAD]; /* yn_options */
	msg.require_id_on_certificate = conn->options[KNCF_REQUIRE_ID_ON_CERTIFICATE]; /* yn_options */
	msg.modecfgpull = conn->options[KNCF_MODECFGPULL]; /* yn_options */
	msg.aggressive = conn->options[KNCF_AGGRESSIVE]; /* yn_options */
	msg.decap_dscp = conn->options[KNCF_DECAP_DSCP]; /* yn_options */
	msg.encap_dscp = conn->options[KNCF_ENCAP_DSCP]; /* yn_options */
	msg.nopmtudisc = conn->options[KNCF_NOPMTUDISC]; /* yn_options */
	msg.accept_redirect = conn->options[KNCF_ACCEPT_REDIRECT]; /* yn_options */
	msg.fragmentation = conn->options[KNCF_FRAGMENTATION]; /* yna_options */
	msg.esn = conn->options[KNCF_ESN]; /* yne_options */
	msg.ppk = conn->options[KNCF_PPK]; /* nppi_options */

	if (conn->set[KNCF_XAUTHBY])
		msg.xauthby = conn->options[KNCF_XAUTHBY];
	if (conn->set[KNCF_XAUTHFAIL])
		msg.xauthfail = conn->options[KNCF_XAUTHFAIL];

	if (!set_whack_end(&msg.left, &conn->left, logger))
		return -1;
	if (!set_whack_end(&msg.right, &conn->right, logger))
		return -1;

	msg.esp = conn->strings[KSCF_ESP];
	msg.ike = conn->strings[KSCF_IKE];

	/*
	 * Save the "computed" pubkeys and IDs before the pointers in
	 * MSG are pickled.
	 */
	const char *left_pubkey = msg.left.pubkey;
	const char *right_pubkey = msg.right.pubkey;
	char *left_id = msg.left.id;
	char *right_id = msg.right.id;

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
						 msg.left.pubkey_alg,
						 logger);
		if (r != 0) {
			return r;
		}
	}
	if (right_id != NULL && right_pubkey != NULL) {
		int r = starter_whack_add_pubkey("right", ctlsocket, conn,
						 right_id, right_pubkey,
						 msg.right.pubkey_alg,
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
