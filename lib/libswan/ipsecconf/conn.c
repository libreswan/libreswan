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

#include "ipsecconf/conn.h"
#include "ipsecconf/keywords.h"
#include "xauthby.h"
#include "xauthfail.h"
#include "shunt.h"
#include "sparse_names.h"
#include "encap_proto.h"

/*
 * Values for right= and left=
 */

static const struct keyword_def config_conn_keyword[] = {
#define K(KEYNAME, VALIDITY, TYPE, FIELD, ...) [FIELD] = { .keyname = KEYNAME, .field = FIELD, .type = TYPE, .validity = VALIDITY, ##__VA_ARGS__ }

  /*
   * This is "left=" and "right="
   */
  K("",  kv_leftright,  kt_string,  KWS_HOST),

  K("debug",  LEMPTY, kt_string, KWS_DEBUG),

  K("subnet",  kv_leftright,  kt_string,  KWS_SUBNET),
  K("subnets",  kv_leftright,  kt_appendlist,  KWS_SUBNETS),
  K("sourceip",  kv_leftright,  kt_string,  KWS_SOURCEIP),
  K("ikeport",  kv_leftright,  kt_string,  KWS_IKEPORT),
  K("interface-ip", kv_leftright,  kt_string, KWS_INTERFACE_IP),
  K("vti",  kv_leftright,  kt_string,  KWS_VTI),
  K("nexthop",  kv_leftright,  kt_string,  KWS_NEXTHOP),
  K("updown",  kv_leftright,  kt_string,  KWS_UPDOWN),
  K("id",  kv_leftright,  kt_string,  KWS_ID),

  K("rsasigkey",  kv_leftright,  kt_string,  KWS_RSASIGKEY),
  K("ecdsakey",  kv_leftright,  kt_string,  KWS_ECDSAKEY),
  K("eddsakey",  kv_leftright,  kt_string,  KWS_EDDSAKEY),
  K("pubkey",  kv_leftright,  kt_string,  KWS_PUBKEY),

  K("cert",  kv_leftright,  kt_string,  KWS_CERT),
  K("ckaid",  kv_leftright,  kt_string,  KWS_CKAID),
  K("sendcert",  kv_leftright,  kt_string,  KWS_SENDCERT),
  K("ca",  kv_leftright,  kt_string,  KWS_CA),
  K("xauthserver",  kv_leftright,  kt_string,  KWS_XAUTHSERVER),
  K("xauthclient",  kv_leftright,  kt_string,  KWS_XAUTHCLIENT),
  K("modecfgserver",  kv_leftright,  kt_string,  KWS_MODECFGSERVER),
  K("modecfgclient",  kv_leftright,  kt_string,  KWS_MODECFGCLIENT),
  K("username",  kv_leftright,  kt_string,  KWS_USERNAME),
  K("addresspool",  kv_leftright,  kt_string,  KWS_ADDRESSPOOL),
  K("auth",  kv_leftright, kt_string,  KWS_AUTH),

#ifdef USE_CAT
# define NOSUP LEMPTY
#else
# define NOSUP kv_nosup
#endif
  K("cat",  kv_leftright|NOSUP,  kt_string,  KWS_CAT),
#undef NOSUP

  K("protoport",  kv_leftright,  kt_string,  KWS_PROTOPORT),
  K("autheap",  kv_leftright,  kt_string,  KWS_AUTHEAP),
  K("groundhog",  kv_leftright,  kt_string,  KWS_GROUNDHOG),

  /* these are conn statements which are not left/right */

  K("auto",  LEMPTY,  kt_sparse_name,  KNCF_AUTO, .sparse_names = &autostart_names),
  K("also",  kv_duplicateok,  kt_also,  KSCF_ALSO),
  K("hostaddrfamily",  LEMPTY,  kt_string,  KWS_HOSTADDRFAMILY),
  K("type",  LEMPTY,  kt_sparse_name,  KNCF_TYPE, .sparse_names = &type_option_names),
  K("authby",  LEMPTY,  kt_string,  KWS_AUTHBY),
  K("keyexchange",  LEMPTY,  kt_string,  KWS_KEYEXCHANGE),
  K("ikev2",  LEMPTY,  kt_string,  KWS_IKEv2),
  K("ppk",  LEMPTY, kt_string, KWS_PPK),
  K("ppk-ids",  LEMPTY, kt_string, KWS_PPK_IDS),
  K("intermediate",  LEMPTY, kt_string, KWS_INTERMEDIATE),
  K("esn",  LEMPTY,  kt_string,  KWS_ESN),
  K("decap-dscp",  LEMPTY,  kt_string,  KWS_DECAP_DSCP),
  K("encap-dscp",  LEMPTY,  kt_string,  KWS_ENCAP_DSCP),
  K("nopmtudisc",  LEMPTY,  kt_string,  KWS_NOPMTUDISC),
  K("fragmentation",  LEMPTY,  kt_string,  KWS_FRAGMENTATION),
  K("mobike",  LEMPTY,  kt_string,  KWS_MOBIKE),
  K("narrowing",  LEMPTY,  kt_string,  KWS_NARROWING),
  K("pam-authorize",  LEMPTY,  kt_string,  KWS_PAM_AUTHORIZE),
  K("send-redirect",  LEMPTY,  kt_string,  KWS_SEND_REDIRECT),
  K("redirect-to",  LEMPTY,  kt_string,  KWS_REDIRECT_TO),
  K("accept-redirect",  LEMPTY,  kt_string, KWS_ACCEPT_REDIRECT),
  K("accept-redirect-to",  LEMPTY,  kt_string, KWS_ACCEPT_REDIRECT_TO),
  K("pfs",  LEMPTY,  kt_string,  KWS_PFS),
  K("session-resumption",  LEMPTY,  kt_string,  KWS_SESSION_RESUMPTION),

  K("nat-keepalive",  LEMPTY,  kt_string,  KWS_NAT_KEEPALIVE),

  K("initial-contact",  LEMPTY,  kt_string,  KWS_INITIAL_CONTACT),
  K("send-esp-tfc-padding-not-supported",  LEMPTY,  kt_string,  KWS_SEND_ESP_TFC_PADDING_NOT_SUPPORTED),
  K("reject-simultaneous-ike-auth", LEMPTY, kt_string, KWS_REJECT_SIMULTANEOUS_IKE_AUTH),

  K("iptfs",  LEMPTY,  kt_string,  KWS_IPTFS),
  K("iptfs-fragmentation",  LEMPTY,  kt_string,  KWS_IPTFS_FRAGMENTATION),
  K("iptfs-packet-size",  LEMPTY,  kt_string,  KWS_IPTFS_PACKET_SIZE),
  K("iptfs-max-queue-size",  LEMPTY,  kt_string,  KWS_IPTFS_MAX_QUEUE_SIZE),
  K("iptfs-reorder-window",  LEMPTY,  kt_string,  KWS_IPTFS_REORDER_WINDOW),
  K("iptfs-init-delay",  LEMPTY,  kt_string,  KWS_IPTFS_INIT_DELAY),
  K("iptfs-drop-time",  LEMPTY,  kt_string,  KWS_IPTFS_DROP_TIME),

  K("fake-strongswan",  LEMPTY,  kt_string,  KWS_FAKE_STRONGSWAN),
  K("send-vendorid",  LEMPTY,  kt_string,  KWS_SEND_VENDORID),
  K("sha2-truncbug",  LEMPTY,  kt_string,  KWS_SHA2_TRUNCBUG),
  K("share-lease",  LEMPTY,  kt_string,  KWS_SHARE_LEASE),
  K("ms-dh-downgrade",  LEMPTY,  kt_string,  KWS_MS_DH_DOWNGRADE),
  K("pfs-rekey-workaround",  LEMPTY,  kt_string,  KWS_PFS_REKEY_WORKAROUND),
  K("require-id-on-certificate",  LEMPTY,  kt_string,  KWS_REQUIRE_ID_ON_CERTIFICATE),
  K("dns-match-id,",  LEMPTY,  kt_string,  KWS_DNS_MATCH_ID),
  K("ipsec-max-bytes",  LEMPTY,  kt_string,  KWS_IPSEC_MAX_BYTES),
  K("ipsec-max-packets",  LEMPTY,  kt_string,  KWS_IPSEC_MAX_PACKETS),
  K("ipsec-lifetime",  LEMPTY,  kt_string,  KWS_IPSEC_LIFETIME),

  K("retransmit-timeout",  LEMPTY,  kt_string,  KWS_RETRANSMIT_TIMEOUT),
  K("retransmit-interval",  LEMPTY,  kt_string,  KWS_RETRANSMIT_INTERVAL),

  K("ikepad",  LEMPTY,  kt_string,  KWS_IKEPAD),
  K("nat-ikev1-method",  LEMPTY,  kt_string,  KWS_NAT_IKEv1_METHOD),

  K("sec-label",  LEMPTY,  kt_string,  KWS_SEC_LABEL),

  /* Cisco interop: remote peer type */
  K("remote-peer-type",  LEMPTY,  kt_string,  KWS_REMOTE_PEER_TYPE),
  /* Network Manager support */
  K("nm-configured",  LEMPTY,  kt_string,  KWS_NM_CONFIGURED),
  K("cisco-unity",  LEMPTY,  kt_string,  KWS_CISCO_UNITY),
  K("cisco-split",  LEMPTY,  kt_string,  KWS_CISCO_SPLIT),

  K("xauthby",  LEMPTY,  kt_string,  KWS_XAUTHBY),
  K("xauthfail",  LEMPTY,  kt_string,  KWS_XAUTHFAIL),
  K("modecfgpull",  LEMPTY,  kt_string,  KWS_MODECFGPULL),
  K("modecfgdns",  LEMPTY,  kt_string,  KWS_MODECFGDNS),
  K("modecfgdomains",  LEMPTY,  kt_string,  KWS_MODECFGDOMAINS),
  K("modecfgbanner",  LEMPTY,  kt_string,  KWS_MODECFGBANNER),
  K("ignore-peer-dns",  LEMPTY,  kt_string,  KWS_IGNORE_PEER_DNS),

  K("mark",  LEMPTY,  kt_string,  KWS_MARK),
  K("mark-in",  LEMPTY,  kt_string,  KWS_MARK_IN),
  K("mark-out",  LEMPTY,  kt_string,  KWS_MARK_OUT),

  K("vti-interface",  LEMPTY,  kt_string,  KWS_VTI_INTERFACE),
  K("vti-routing",  LEMPTY,  kt_string,  KWS_VTI_ROUTING),
  K("vti-shared",  LEMPTY,  kt_string,  KWS_VTI_SHARED),

  K("ipsec-interface",  LEMPTY, kt_string, KWS_IPSEC_INTERFACE),

  K("clones", LEMPTY, kt_string, KWS_CLONES),

  K("nic-offload",  LEMPTY,  kt_string,  KWS_NIC_OFFLOAD),

  K("encapsulation",  LEMPTY,  kt_string,  KWS_ENCAPSULATION),

  K("overlapip",  LEMPTY,  kt_string,  KWS_OVERLAPIP),
  K("reauth",  LEMPTY,  kt_string,  KWS_REAUTH),
  K("rekey",  LEMPTY,  kt_string,  KWS_REKEY),
  K("rekeymargin",  LEMPTY,  kt_string,  KWS_REKEYMARGIN),
  K("rekeyfuzz",  LEMPTY,  kt_string,  KWS_REKEYFUZZ),
  K("replay-window",  LEMPTY,  kt_string,  KWS_REPLAY_WINDOW),
  K("ikelifetime",  LEMPTY,  kt_string,  KWS_IKELIFETIME),
  K("failureshunt",  LEMPTY,  kt_sparse_name,  KNCF_FAILURESHUNT, .sparse_names = &failure_shunt_names),
  K("negotiationshunt",  LEMPTY,  kt_sparse_name,  KNCF_NEGOTIATIONSHUNT, .sparse_names = &negotiation_shunt_names),

  K("enable-tcp",  LEMPTY, kt_string, KWS_ENABLE_TCP),
  K("tcp-remoteport",  LEMPTY, kt_string, KWS_TCP_REMOTEPORT),

  K("connalias",  LEMPTY,  kt_appendstring,  KWS_CONNALIAS),

  /* attributes of the phase1 policy */
  K("ike",  LEMPTY,  kt_string,  KWS_IKE),
  /* attributes of the phase2 policy */
  K("esp",  LEMPTY,  kt_string,  KWS_ESP),
  K("ah",   LEMPTY,  kt_string,  KWS_AH),
  K("phase2",  LEMPTY,  kt_string,  KWS_PHASE2),
  K("phase2alg",  LEMPTY,  kt_string,  KWS_PHASE2ALG),

  K("compress",  LEMPTY,  kt_string,  KWS_COMPRESS),

  /* route metric */
  K("metric",  LEMPTY,  kt_string,  KWS_METRIC),

  /* DPD */
  K("dpddelay",  LEMPTY,  kt_string,  KWS_DPDDELAY),
  K("ikev1-dpdtimeout",  LEMPTY,  kt_string,  KWS_DPDTIMEOUT),

  K("sendca",  LEMPTY,  kt_string,  KWS_SENDCA),

  K("mtu",  LEMPTY,  kt_string,  KWS_MTU),
  K("priority",  LEMPTY,  kt_string,  KWS_PRIORITY),
  K("tfc",  LEMPTY,  kt_string,  KWS_TFC),
  K("reqid",  LEMPTY,  kt_string,  KWS_REQID),

#ifdef USE_NFLOG
# define NOSUP LEMPTY
#else
# define NOSUP kv_nosup
#endif
  K("nflog-group",  NOSUP,  kt_string,  KWS_NFLOG_GROUP),
#undef NOSUP

  K("aggressive",  LEMPTY,  kt_string,  KWS_AGGRESSIVE),

  /*
   * Force first alias/obsolete keyword into slot following all
   * defined keywords.  Else compiler tries to store it into above
   * keyword's slot + 1, which is likely occupied by another keyword.
   * The result is a nonsensical error.
   */
  [CONFIG_CONN_KEYWORD_ROOF] =

  /* alias for compatibility - undocumented on purpose */

#define A(KEYNAME, VALIDITY, TYPE, FIELD, ...) { .keyname = KEYNAME, .validity = VALIDITY|kv_alias, .type = TYPE, .field = FIELD, ##__VA_ARGS__ }

  A("aggrmode", LEMPTY,  kt_string,  KWS_AGGRESSIVE),
  A("keylife", LEMPTY,  kt_string,  KWS_IPSEC_LIFETIME), /* old name */
  A("lifetime", LEMPTY,  kt_string,  KWS_IPSEC_LIFETIME), /* old name */
  A("phase2alg", LEMPTY,  kt_string,  KWS_ESP),	/* obsolete */
  A("dpdtimeout", LEMPTY,  kt_string,  KWS_DPDTIMEOUT), /* old name */
#ifdef USE_NFLOG
  A("nflog", LEMPTY,  kt_string,  KWS_NFLOG_GROUP), /* old-name */
#endif
  A("salifetime", LEMPTY,  kt_string,  KWS_IPSEC_LIFETIME), /* old name */
  /* xauthusername is still used in NetworkManager-libreswan :/ */
  A("xauthusername",  kv_leftright,  kt_string,  KWS_USERNAME), /* old alias */
  A("ah", LEMPTY,  kt_string,  KWS_ESP),
  A("policy-label", LEMPTY,  kt_string,  KWS_SEC_LABEL), /* obsolete variant */
  /* another alias used by NetworkManager-libreswan :/ */
  A("remote_peer_type", LEMPTY,  kt_string,  KWS_REMOTE_PEER_TYPE),
  A("send-no-esp-tfc", LEMPTY,  kt_string,  KWS_SEND_ESP_TFC_PADDING_NOT_SUPPORTED), /*compat, but forever*/

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
