/*
 * Libreswan config file parser (keywords.c)
 * Copyright (C) 2003-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013-2016 Antony Antony <antony@phenome.org>
 * Copyright (C) 2016-2022 Andrew Cagney
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#include "constants.h"		/* for yn_option_names; */
#include "lswcdefs.h"		/* for elemsof() */

#include "ipsecconf/config_conn.h"
#include "ipsecconf/keywords.h"
#include "xauthby.h"
#include "xauthfail.h"
#include "shunt.h"
#include "sparse_names.h"
#include "encap_proto.h"

/*
 * Values for right= and left=
 */

static const struct sparse_names kw_phase2types_names = {
	.list = {
		/* note: these POLICY bits happen to fit in an unsigned int */
		/* note2: ah+esp is no longer supported as per RFC-8221 Section 4 */
		SPARSE("esp",      ENCAP_PROTO_ESP),
		SPARSE("ah",       ENCAP_PROTO_AH),
		SPARSE("default",  ENCAP_PROTO_UNSET), /* i.e., let pluto decide */
		SPARSE_NULL
	},
};

static const struct keyword_def config_conn_keyword[] = {
#define K(KEYNAME, VALIDITY, TYPE, FIELD, ...) [FIELD] = { .keyname = KEYNAME, .validity = VALIDITY, .type = TYPE, .field = FIELD, ##__VA_ARGS__ }

  /*
   * This is "left=" and "right="
   */
  K("",  kv_leftright,  kt_string,  KWS_HOST),

  K("debug",  LEMPTY, kt_string, KWS_DEBUG),

  K("subnet",  kv_leftright,  kt_string,  KWS_SUBNET),
  K("subnets",  kv_leftright,  kt_appendlist,  KSCF_SUBNETS),
  K("sourceip",  kv_leftright,  kt_string,  KWS_SOURCEIP),
  K("ikeport",  kv_leftright,  kt_string,  KWS_IKEPORT),
  K("interface-ip", kv_leftright,  kt_string, KWS_INTERFACE_IP),
  K("vti",  kv_leftright,  kt_string,  KWS_VTI),
  K("nexthop",  kv_leftright,  kt_string,  KWS_NEXTHOP),
  K("updown",  kv_leftright,  kt_string,  KWS_UPDOWN),
  K("id",  kv_leftright,  kt_string,  KWS_ID),

  /*
   * Note: these are merged into .pubkey + .pubkey_alg before sending
   * to pluto.
   */
  K("rsasigkey",  kv_leftright,  kt_string,  KWS_RSASIGKEY),
  K("ecdsakey",  kv_leftright,  kt_string,  KWS_ECDSAKEY),
  K("pubkey",  kv_leftright,  kt_string,  KWS_PUBKEY),

  K("cert",  kv_leftright,  kt_string,  KWS_CERT),
  K("ckaid",  kv_leftright,  kt_string,  KWS_CKAID),
  K("sendcert",  kv_leftright,  kt_string,  KWS_SENDCERT),
  K("ca",  kv_leftright,  kt_string,  KWS_CA),
  K("xauthserver",  kv_leftright,  kt_sparse_name,  KWYN_XAUTHSERVER, .sparse_names = &yn_option_names),
  K("xauthclient",  kv_leftright,  kt_sparse_name,  KWYN_XAUTHCLIENT, .sparse_names = &yn_option_names),
  K("modecfgserver",  kv_leftright,  kt_sparse_name,  KWYN_MODECONFIGSERVER, .sparse_names = &yn_option_names),
  K("modecfgclient",  kv_leftright,  kt_sparse_name,  KWYN_MODECONFIGCLIENT, .sparse_names = &yn_option_names),
  K("username",  kv_leftright,  kt_string,  KWS_USERNAME),
  K("addresspool",  kv_leftright,  kt_string,  KWS_ADDRESSPOOL),
  K("auth",  kv_leftright, kt_string,  KWS_AUTH),
#ifdef USE_CAT
  K("cat",  kv_leftright,  kt_sparse_name,  KWYN_CAT, .sparse_names = &yn_option_names),
#endif
  K("protoport",  kv_leftright,  kt_string,  KWS_PROTOPORT),
  K("autheap",  kv_leftright,  kt_string,  KWS_AUTHEAP),
  K("groundhog",  kv_leftright,  kt_sparse_name,  KWYN_GROUNDHOG, .sparse_names = &yn_option_names),

  /* these are conn statements which are not left/right */

  K("auto",  LEMPTY,  kt_sparse_name,  KNCF_AUTO, .sparse_names = &autostart_names),
  K("also",  kv_duplicateok,  kt_also,  KSCF_ALSO),
  K("hostaddrfamily",  LEMPTY,  kt_string,  KWS_HOSTADDRFAMILY),
  K("type",  LEMPTY,  kt_sparse_name,  KNCF_TYPE, .sparse_names = &type_option_names),
  K("authby",  LEMPTY,  kt_string,  KWS_AUTHBY),
  K("keyexchange",  LEMPTY,  kt_string,  KWS_KEYEXCHANGE),
  K("ikev2",  LEMPTY,  kt_string,  KWS_IKEv2),
  K("ppk",  LEMPTY, kt_sparse_name, KNCF_PPK, .sparse_names = &nppi_option_names),
  K("ppk-ids",  LEMPTY, kt_string, KWS_PPK_IDS),
  K("intermediate",  LEMPTY, kt_sparse_name, KWYN_INTERMEDIATE, .sparse_names = &yn_option_names),
  K("esn",  LEMPTY,  kt_sparse_name,  KNCF_ESN, .sparse_names = &yne_option_names),
  K("decap-dscp",  LEMPTY,  kt_sparse_name,  KWYN_DECAP_DSCP, .sparse_names = &yn_option_names),
  K("encap-dscp",  LEMPTY,  kt_sparse_name,  KWYN_ENCAP_DSCP, .sparse_names = &yn_option_names),
  K("nopmtudisc",  LEMPTY,  kt_sparse_name,  KWYN_NOPMTUDISC, .sparse_names = &yn_option_names),
  K("fragmentation",  LEMPTY,  kt_sparse_name,  KNCF_FRAGMENTATION, .sparse_names = &ynf_option_names),
  K("mobike",  LEMPTY,  kt_sparse_name,  KWYN_MOBIKE, .sparse_names = &yn_option_names),
  K("narrowing",  LEMPTY,  kt_sparse_name,  KWYN_NARROWING, .sparse_names = &yn_option_names),
  K("pam-authorize",  LEMPTY,  kt_sparse_name,  KWYN_PAM_AUTHORIZE, .sparse_names = &yn_option_names),
  K("send-redirect",  LEMPTY,  kt_sparse_name,  KNCF_SEND_REDIRECT, .sparse_names = &yna_option_names),
  K("redirect-to",  LEMPTY,  kt_string,  KWS_REDIRECT_TO),
  K("accept-redirect",  LEMPTY,  kt_sparse_name, KWYN_ACCEPT_REDIRECT, .sparse_names = &yn_option_names),
  K("accept-redirect-to",  LEMPTY,  kt_string, KWS_ACCEPT_REDIRECT_TO),
  K("pfs",  LEMPTY,  kt_sparse_name,  KWYN_PFS, .sparse_names = &yn_option_names),
  K("session-resumption",  LEMPTY,  kt_sparse_name,  KWYN_SESSION_RESUMPTION, .sparse_names = &yn_option_names),

  K("nat-keepalive",  LEMPTY,  kt_sparse_name,  KWYN_NAT_KEEPALIVE, .sparse_names = &yn_option_names),

  K("initial-contact",  LEMPTY,  kt_sparse_name,  KWYN_INITIAL_CONTACT, .sparse_names = &yn_option_names),
  K("send-esp-tfc-padding-not-supported",  LEMPTY,  kt_sparse_name,  KWYN_SEND_ESP_TFC_PADDING_NOT_SUPPORTED, .sparse_names = &yn_option_names),

  K("iptfs",  LEMPTY,  kt_sparse_name,  KWYN_IPTFS, .sparse_names = &yn_option_names),
  K("iptfs-fragmentation",  LEMPTY,  kt_sparse_name,  KWYN_IPTFS_FRAGMENTATION, .sparse_names = &yn_option_names),
  K("iptfs-packet-size",  LEMPTY,  kt_string,  KWS_IPTFS_PACKET_SIZE),
  K("iptfs-max-queue-size",  LEMPTY,  kt_string,  KWS_IPTFS_MAX_QUEUE_SIZE),
  K("iptfs-reorder-window",  LEMPTY,  kt_string,  KWS_IPTFS_REORDER_WINDOW),
  K("iptfs-init-delay",  LEMPTY,  kt_seconds,  KNCF_IPTFS_INIT_DELAY),
  K("iptfs-drop-time",  LEMPTY,  kt_seconds,  KNCF_IPTFS_DROP_TIME),

  K("fake-strongswan",  LEMPTY,  kt_sparse_name,  KWYN_FAKE_STRONGSWAN, .sparse_names = &yn_option_names),
  K("send-vendorid",  LEMPTY,  kt_sparse_name,  KWYN_SEND_VENDORID, .sparse_names = &yn_option_names),
  K("sha2-truncbug",  LEMPTY,  kt_sparse_name,  KWYN_SHA2_TRUNCBUG, .sparse_names = &yn_option_names),
  K("share-lease",  LEMPTY,  kt_sparse_name,  KWYN_SHARE_LEASE, .sparse_names = &yn_option_names),
  K("ms-dh-downgrade",  LEMPTY,  kt_sparse_name,  KWYN_MS_DH_DOWNGRADE, .sparse_names = &yn_option_names),
  K("pfs-rekey-workaround",  LEMPTY,  kt_sparse_name,  KWYN_PFS_REKEY_WORKAROUND, .sparse_names = &yn_option_names),
  K("require-id-on-certificate",  LEMPTY,  kt_sparse_name,  KWYN_REQUIRE_ID_ON_CERTIFICATE, .sparse_names = &yn_option_names),
  K("dns-match-id,",  LEMPTY,  kt_sparse_name,  KWYN_DNS_MATCH_ID, .sparse_names = &yn_option_names),
  K("ipsec-max-bytes",  LEMPTY,  kt_string,  KWS_IPSEC_MAX_BYTES),
  K("ipsec-max-packets",  LEMPTY,  kt_string,  KWS_IPSEC_MAX_PACKETS),
  K("ipsec-lifetime",  LEMPTY,  kt_seconds,  KNCF_IPSEC_LIFETIME),

  K("retransmit-timeout",  LEMPTY,  kt_seconds,  KNCF_RETRANSMIT_TIMEOUT),
  K("retransmit-interval",  LEMPTY,  kt_string,  KWS_RETRANSMIT_INTERVAL),

  K("ikepad",  LEMPTY,  kt_sparse_name,  KNCF_IKEPAD, .sparse_names = &yna_option_names),
  K("nat-ikev1-method",  LEMPTY,  kt_sparse_name,  KNCF_NAT_IKEv1_METHOD, .sparse_names = &nat_ikev1_method_option_names),

  K("sec-label",  LEMPTY,  kt_string,  KWS_SEC_LABEL),

  /* Cisco interop: remote peer type */
  K("remote-peer-type",  LEMPTY,  kt_string,  KWS_REMOTE_PEER_TYPE),
  /* Network Manager support */
  K("nm-configured",  LEMPTY,  kt_string,  KWS_NM_CONFIGURED),
  K("cisco-unity",  LEMPTY,  kt_string,  KWS_CISCO_UNITY),
  K("cisco-split",  LEMPTY,  kt_string,  KWS_CISCO_SPLIT),

  K("xauthby",  LEMPTY,  kt_sparse_name,  KNCF_XAUTHBY, .sparse_names = &xauthby_names),
  K("xauthfail",  LEMPTY,  kt_sparse_name,  KNCF_XAUTHFAIL, .sparse_names = &xauthfail_names),
  K("modecfgpull",  LEMPTY,  kt_sparse_name,  KWYN_MODECFGPULL, .sparse_names = &yn_option_names),
  K("modecfgdns",  LEMPTY,  kt_string,  KWS_MODECFGDNS),
  K("modecfgdomains",  LEMPTY,  kt_string,  KWS_MODECFGDOMAINS),
  K("modecfgbanner",  LEMPTY,  kt_string,  KWS_MODECFGBANNER),
  K("ignore-peer-dns",  LEMPTY,  kt_sparse_name,  KWYN_IGNORE_PEER_DNS, .sparse_names = &yn_option_names),
  K("mark",  LEMPTY,  kt_string,  KWS_MARK),
  K("mark-in",  LEMPTY,  kt_string,  KWS_MARK_IN),
  K("mark-out",  LEMPTY,  kt_string,  KWS_MARK_OUT),
  K("vti-interface",  LEMPTY,  kt_string,  KWS_VTI_INTERFACE),
  K("vti-routing",  LEMPTY,  kt_sparse_name,  KWYN_VTI_ROUTING, .sparse_names = &yn_option_names),
  K("vti-shared",  LEMPTY,  kt_sparse_name,  KWYN_VTI_SHARED, .sparse_names = &yn_option_names),
  K("ipsec-interface",  LEMPTY, kt_string, KWS_IPSEC_INTERFACE),

  K("nic-offload",  LEMPTY,  kt_sparse_name,  KNCF_NIC_OFFLOAD, .sparse_names = &nic_offload_option_names),

  K("encapsulation",  LEMPTY,  kt_sparse_name,  KNCF_ENCAPSULATION, .sparse_names = &yna_option_names),

  K("overlapip",  LEMPTY,  kt_sparse_name,  KWYN_OVERLAPIP, .sparse_names = &yn_option_names),
  K("reauth",  LEMPTY,  kt_sparse_name,  KWYN_REAUTH, .sparse_names = &yn_option_names),
  K("rekey",  LEMPTY,  kt_sparse_name,  KWYN_REKEY, .sparse_names = &yn_option_names),
  K("rekeymargin",  LEMPTY,  kt_seconds,  KNCF_REKEYMARGIN),
  K("rekeyfuzz",  LEMPTY,  kt_string,  KWS_REKEYFUZZ),
  K("replay-window",  LEMPTY,  kt_string,  KWS_REPLAY_WINDOW),
  K("ikelifetime",  LEMPTY,  kt_seconds,  KNCF_IKELIFETIME),
  K("failureshunt",  LEMPTY,  kt_sparse_name,  KNCF_FAILURESHUNT, .sparse_names = &failure_shunt_names),
  K("negotiationshunt",  LEMPTY,  kt_sparse_name,  KNCF_NEGOTIATIONSHUNT, .sparse_names = &negotiation_shunt_names),

  K("enable-tcp",  LEMPTY, kt_sparse_name, KNCF_ENABLE_TCP, .sparse_names = &tcp_option_names),
  K("tcp-remoteport",  LEMPTY, kt_unsigned, KNCF_TCP_REMOTEPORT),

  K("connalias",  LEMPTY,  kt_appendstring,  KSCF_CONNALIAS),

  /* attributes of the phase1 policy */
  K("ike",  LEMPTY,  kt_string,  KWS_IKE),
  /* attributes of the phase2 policy */
  K("esp",  LEMPTY,  kt_string,  KWS_ESP),
  K("ah",   LEMPTY,  kt_string,  KWS_AH),
  K("phase2",  LEMPTY,  kt_sparse_name,  KNCF_PHASE2, .sparse_names = &kw_phase2types_names),
  K("phase2alg",  LEMPTY,  kt_string,  KWS_PHASE2ALG),

  K("compress",  LEMPTY,  kt_sparse_name,  KWYN_COMPRESS, .sparse_names = &yn_option_names),

  /* route metric */
  K("metric",  LEMPTY,  kt_unsigned,  KNCF_METRIC),

  /* DPD */
  K("dpddelay",  LEMPTY,  kt_string,  KWS_DPDDELAY),
  K("ikev1-dpdtimeout",  LEMPTY,  kt_string,  KWS_DPDTIMEOUT),

  K("sendca",  LEMPTY,  kt_string,  KWS_SENDCA),

  K("mtu",  LEMPTY,  kt_string,  KWS_MTU),
  K("priority",  LEMPTY,  kt_string,  KWS_PRIORITY),
  K("tfc",  LEMPTY,  kt_string,  KWS_TFC),
  K("reqid",  LEMPTY,  kt_string,  KWS_REQID),
#ifdef USE_NFLOG
  K("nflog-group",  LEMPTY,  kt_string,  KWS_NFLOG_GROUP),
#endif

  K("aggressive",  LEMPTY,  kt_sparse_name,  KWYN_AGGRESSIVE, .sparse_names = &yn_option_names),

  /*
   * Force first alias/obsolete keyword into slot following all
   * defined keywords.  Else compiler tries to store it into above
   * keyword's slot + 1, which is likely occupied by another keyword.
   * The result is a nonsensical error.
   */
  [CONFIG_CONN_KEYWORD_ROOF] =

  /* alias for compatibility - undocumented on purpose */

#define A(KEYNAME, VALIDITY, TYPE, FIELD, ...) { .keyname = KEYNAME, .validity = VALIDITY|kv_alias, .type = TYPE, .field = FIELD, ##__VA_ARGS__ }
  A("aggrmode", LEMPTY,  kt_sparse_name,  KWYN_AGGRESSIVE, .sparse_names = &yn_option_names),
  A("keylife", LEMPTY,  kt_seconds,  KNCF_IPSEC_LIFETIME), /* old name */
  A("lifetime", LEMPTY,  kt_seconds,  KNCF_IPSEC_LIFETIME), /* old name */
  A("phase2alg", LEMPTY,  kt_string,  KWS_ESP),	/* obsolete */
  A("dpdtimeout", LEMPTY,  kt_string,  KWS_DPDTIMEOUT), /* old name */
#ifdef USE_NFLOG
  A("nflog", LEMPTY,  kt_string,  KWS_NFLOG_GROUP), /* old-name */
#endif
  A("salifetime", LEMPTY,  kt_seconds,  KNCF_IPSEC_LIFETIME), /* old name */
  /* xauthusername is still used in NetworkManager-libreswan :/ */
  A("xauthusername",  kv_leftright,  kt_string,  KWS_USERNAME), /* old alias */
  A("ah", LEMPTY,  kt_string,  KWS_ESP),
  A("policy-label", LEMPTY,  kt_string,  KWS_SEC_LABEL), /* obsolete variant */
  /* another alias used by NetworkManager-libreswan :/ */
  A("remote_peer_type", LEMPTY,  kt_string,  KWS_REMOTE_PEER_TYPE),
  A("send-no-esp-tfc", LEMPTY,  kt_sparse_name,  KWYN_SEND_ESP_TFC_PADDING_NOT_SUPPORTED, .sparse_names = &yn_option_names), /*compat, but forever*/

  /* obsolete config setup options */

#define O(KEYNAME, ...) { .keyname = KEYNAME, .type = kt_obsolete, }

  O("dpdaction"),
  O("clientaddrfamily"),
  O("keyingtries"),

#undef O
#undef A
#undef K
};

const struct keywords_def config_conn_keywords = {
	.len = elemsof(config_conn_keyword),
	.item = config_conn_keyword,
};
