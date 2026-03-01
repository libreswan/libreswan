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
#include "shunt.h"

/*
 * Values for right= and left=
 */

static const struct keyword_def config_conn_keyword[] = {
#define K(KEYNAME, VALIDITY, TYPE, FIELD, ...) [FIELD] = { .keyname = KEYNAME, .field = FIELD, .type = TYPE, .validity = VALIDITY, ##__VA_ARGS__ }
#define KWS(KEYNAME, VALIDITY, FIELD) K(KEYNAME, VALIDITY, kt_string, FIELD)

  /*
   * This is "left=" and "right="
   */
  KWS("", kv_leftright, KWS_HOST),

  K("subnets", kv_leftright, kt_appendstrings, KWS_SUBNETS),

  KWS("debug", LEMPTY, KWS_DEBUG),
  KWS("subnet", kv_leftright, KWS_SUBNET),
  KWS("sourceip", kv_leftright, KWS_SOURCEIP),
  KWS("ikeport", kv_leftright, KWS_IKEPORT),
  KWS("interface-ip", kv_leftright, KWS_INTERFACE_IP),
  KWS("vti", kv_leftright, KWS_VTI),
  KWS("nexthop", kv_leftright, KWS_NEXTHOP),
  KWS("updown", kv_leftright, KWS_UPDOWN),
  KWS("updown-config", kv_leftright, KWS_UPDOWN_CONFIG),
  KWS("id", kv_leftright, KWS_ID),

  KWS("rsasigkey", kv_leftright, KWS_RSASIGKEY),
  KWS("ecdsakey", kv_leftright, KWS_ECDSAKEY),
  KWS("eddsakey", kv_leftright, KWS_EDDSAKEY),
  KWS("pubkey", kv_leftright, KWS_PUBKEY),

  KWS("cert", kv_leftright, KWS_CERT),
  KWS("ckaid", kv_leftright, KWS_CKAID),
  KWS("sendcert", kv_leftright, KWS_SENDCERT),
  KWS("ca", kv_leftright, KWS_CA),
  KWS("xauthserver", kv_leftright, KWS_XAUTHSERVER),
  KWS("xauthclient", kv_leftright, KWS_XAUTHCLIENT),
  KWS("modecfgserver", kv_leftright, KWS_MODECFGSERVER),
  KWS("modecfgclient", kv_leftright, KWS_MODECFGCLIENT),
  KWS("username", kv_leftright, KWS_USERNAME),
  KWS("addresspool", kv_leftright, KWS_ADDRESSPOOL),
  KWS("auth", kv_leftright, KWS_AUTH),

#ifdef USE_CAT
# define NOSUP LEMPTY
#else
# define NOSUP kv_nosup
#endif
  KWS("cat", kv_leftright|NOSUP, KWS_CAT),
#undef NOSUP

  KWS("protoport", kv_leftright, KWS_PROTOPORT),
  KWS("autheap", kv_leftright, KWS_AUTHEAP),
  KWS("groundhog", kv_leftright, KWS_GROUNDHOG),

  /* these are conn statements which are not left/right */

  K("also", kv_duplicateok, kt_also, KSCF_ALSO),
  K("connalias", LEMPTY, kt_appendstrings, KWS_CONNALIAS),

  KWS("auto", LEMPTY, KWS_AUTO),
  KWS("hostaddrfamily", LEMPTY, KWS_HOSTADDRFAMILY),
  KWS("authby", LEMPTY, KWS_AUTHBY),
  KWS("keyexchange", LEMPTY, KWS_KEYEXCHANGE),
  KWS("ikev2", LEMPTY, KWS_IKEv2),
  KWS("ppk", LEMPTY, KWS_PPK),
  KWS("ppk-ids", LEMPTY, KWS_PPK_IDS),
  KWS("intermediate", LEMPTY, KWS_INTERMEDIATE),
  KWS("esn", LEMPTY, KWS_ESN),
  KWS("decap-dscp", LEMPTY, KWS_DECAP_DSCP),
  KWS("encap-dscp", LEMPTY, KWS_ENCAP_DSCP),
  KWS("nopmtudisc", LEMPTY, KWS_NOPMTUDISC),
  KWS("fragmentation", LEMPTY, KWS_FRAGMENTATION),
  KWS("mobike", LEMPTY, KWS_MOBIKE),
  KWS("narrowing", LEMPTY, KWS_NARROWING),
  KWS("pam-authorize", LEMPTY, KWS_PAM_AUTHORIZE),
  KWS("send-redirect", LEMPTY, KWS_SEND_REDIRECT),
  KWS("redirect-to", LEMPTY, KWS_REDIRECT_TO),
  KWS("accept-redirect", LEMPTY, KWS_ACCEPT_REDIRECT),
  KWS("accept-redirect-to", LEMPTY, KWS_ACCEPT_REDIRECT_TO),
  KWS("pfs", LEMPTY, KWS_PFS),
  KWS("session-resumption", LEMPTY, KWS_SESSION_RESUMPTION),

  KWS("nat-keepalive", LEMPTY, KWS_NAT_KEEPALIVE),

  KWS("initial-contact", LEMPTY, KWS_INITIAL_CONTACT),
  KWS("send-esp-tfc-padding-not-supported", LEMPTY, KWS_SEND_ESP_TFC_PADDING_NOT_SUPPORTED),
  KWS("reject-simultaneous-ike-auth", LEMPTY, KWS_REJECT_SIMULTANEOUS_IKE_AUTH),

  KWS("iptfs", LEMPTY, KWS_IPTFS),
  KWS("iptfs-fragmentation", LEMPTY, KWS_IPTFS_FRAGMENTATION),
  KWS("iptfs-packet-size", LEMPTY, KWS_IPTFS_PACKET_SIZE),
  KWS("iptfs-max-queue-size", LEMPTY, KWS_IPTFS_MAX_QUEUE_SIZE),
  KWS("iptfs-reorder-window", LEMPTY, KWS_IPTFS_REORDER_WINDOW),
  KWS("iptfs-init-delay", LEMPTY, KWS_IPTFS_INIT_DELAY),
  KWS("iptfs-drop-time", LEMPTY, KWS_IPTFS_DROP_TIME),

  KWS("fake-strongswan", LEMPTY, KWS_FAKE_STRONGSWAN),
  KWS("send-vendorid", LEMPTY, KWS_SEND_VENDORID),
  KWS("sha2-truncbug", LEMPTY, KWS_SHA2_TRUNCBUG),
  KWS("share-lease", LEMPTY, KWS_SHARE_LEASE),
  KWS("ms-dh-downgrade", LEMPTY, KWS_MS_DH_DOWNGRADE),
  KWS("pfs-rekey-workaround", LEMPTY, KWS_PFS_REKEY_WORKAROUND),
  KWS("require-id-on-certificate", LEMPTY, KWS_REQUIRE_ID_ON_CERTIFICATE),
  KWS("dns-match-id,", LEMPTY, KWS_DNS_MATCH_ID),
  KWS("ipsec-max-bytes", LEMPTY, KWS_IPSEC_MAX_BYTES),
  KWS("ipsec-max-packets", LEMPTY, KWS_IPSEC_MAX_PACKETS),
  KWS("ipsec-lifetime", LEMPTY, KWS_IPSEC_LIFETIME),

  KWS("retransmit-timeout", LEMPTY, KWS_RETRANSMIT_TIMEOUT),
  KWS("retransmit-interval", LEMPTY, KWS_RETRANSMIT_INTERVAL),

  KWS("ikepad", LEMPTY, KWS_IKEPAD),
  KWS("nat-ikev1-method", LEMPTY, KWS_NAT_IKEv1_METHOD),

  KWS("sec-label", LEMPTY, KWS_SEC_LABEL),

  /* Cisco interop: remote peer type */
  KWS("remote-peer-type", LEMPTY, KWS_REMOTE_PEER_TYPE),
  /* Network Manager support */
  KWS("nm-configured", LEMPTY, KWS_NM_CONFIGURED),
  KWS("cisco-unity", LEMPTY, KWS_CISCO_UNITY),
  KWS("cisco-split", LEMPTY, KWS_CISCO_SPLIT),

  KWS("xauthby", LEMPTY, KWS_XAUTHBY),
  KWS("xauthfail", LEMPTY, KWS_XAUTHFAIL),
  KWS("modecfgpull", LEMPTY, KWS_MODECFGPULL),
  KWS("modecfgdns", LEMPTY, KWS_MODECFGDNS),
  KWS("modecfgdomains", LEMPTY, KWS_MODECFGDOMAINS),
  KWS("modecfgbanner", LEMPTY, KWS_MODECFGBANNER),
  KWS("ignore-peer-dns", LEMPTY, KWS_IGNORE_PEER_DNS),

  KWS("mark", LEMPTY, KWS_MARK),
  KWS("mark-in", LEMPTY, KWS_MARK_IN),
  KWS("mark-out", LEMPTY, KWS_MARK_OUT),

  KWS("vti-interface", LEMPTY, KWS_VTI_INTERFACE),
  KWS("vti-routing", LEMPTY, KWS_VTI_ROUTING),
  KWS("vti-shared", LEMPTY, KWS_VTI_SHARED),

  KWS("ipsec-interface", LEMPTY, KWS_IPSEC_INTERFACE),

  KWS("clones", LEMPTY, KWS_CLONES),

  KWS("nic-offload", LEMPTY, KWS_NIC_OFFLOAD),

  KWS("encapsulation", LEMPTY, KWS_ENCAPSULATION),

  KWS("overlapip", LEMPTY, KWS_OVERLAPIP),
  KWS("reauth", LEMPTY, KWS_REAUTH),
  KWS("rekey", LEMPTY, KWS_REKEY),
  KWS("rekeymargin", LEMPTY, KWS_REKEYMARGIN),
  KWS("rekeyfuzz", LEMPTY, KWS_REKEYFUZZ),
  KWS("replay-window", LEMPTY, KWS_REPLAY_WINDOW),
  KWS("ikelifetime", LEMPTY, KWS_IKELIFETIME),

  KWS("type", LEMPTY, KWS_TYPE),
  KWS("failureshunt", LEMPTY, KWS_FAILURESHUNT),
  KWS("negotiationshunt", LEMPTY, KWS_NEGOTIATIONSHUNT),

  KWS("enable-tcp", LEMPTY, KWS_ENABLE_TCP),
  KWS("tcp-remoteport", LEMPTY, KWS_TCP_REMOTEPORT),

  /* attributes of the phase1 policy */
  KWS("ike", LEMPTY, KWS_IKE),
  /* attributes of the phase2 policy */
  KWS("esp", LEMPTY, KWS_ESP),
  KWS("ah",  LEMPTY, KWS_AH),
  KWS("phase2", LEMPTY, KWS_PHASE2),
  KWS("phase2alg", LEMPTY, KWS_PHASE2ALG),

  KWS("compress", LEMPTY, KWS_COMPRESS),

  /* route metric */
  KWS("metric", LEMPTY, KWS_METRIC),

  /* DPD */
  KWS("dpddelay", LEMPTY, KWS_DPDDELAY),
  KWS("ikev1-dpdtimeout", LEMPTY, KWS_DPDTIMEOUT),

  KWS("sendca", LEMPTY, KWS_SENDCA),

  KWS("mtu", LEMPTY, KWS_MTU),
  KWS("priority", LEMPTY, KWS_PRIORITY),
  KWS("tfc", LEMPTY, KWS_TFC),
  KWS("reqid", LEMPTY, KWS_REQID),

#ifdef USE_NFLOG
# define NOSUP LEMPTY
#else
# define NOSUP kv_nosup
#endif
  KWS("nflog-group", NOSUP, KWS_NFLOG_GROUP),
#undef NOSUP

  KWS("aggressive", LEMPTY, KWS_AGGRESSIVE),

  /*
   * Force first alias/obsolete keyword into slot following all
   * defined keywords.  Else compiler tries to store it into above
   * keyword's slot + 1, which is likely occupied by another keyword.
   * The result is a nonsensical error.
   */
  [CONFIG_CONN_KEYWORD_ROOF] =

  /* alias for compatibility - undocumented on purpose */

#define A(KEYNAME, VALIDITY, FIELD, ...) { .keyname = KEYNAME, .validity = VALIDITY|kv_alias, .type = kt_string, .field = FIELD, ##__VA_ARGS__ }

  A("aggrmode", LEMPTY, KWS_AGGRESSIVE),
  A("keylife", LEMPTY, KWS_IPSEC_LIFETIME), /* old name */
  A("lifetime", LEMPTY, KWS_IPSEC_LIFETIME), /* old name */
  A("phase2alg", LEMPTY, KWS_ESP),	/* obsolete */
  A("dpdtimeout", LEMPTY, KWS_DPDTIMEOUT), /* old name */
#ifdef USE_NFLOG
  A("nflog", LEMPTY, KWS_NFLOG_GROUP), /* old-name */
#endif
  A("salifetime", LEMPTY, KWS_IPSEC_LIFETIME), /* old name */
  /* xauthusername is still used in NetworkManager-libreswan :/ */
  A("xauthusername", kv_leftright, KWS_USERNAME), /* old alias */
  A("ah", LEMPTY, KWS_ESP),
  A("policy-label", LEMPTY, KWS_SEC_LABEL), /* obsolete variant */
  /* another alias used by NetworkManager-libreswan :/ */
  A("remote_peer_type", LEMPTY, KWS_REMOTE_PEER_TYPE),
  A("send-no-esp-tfc", LEMPTY, KWS_SEND_ESP_TFC_PADDING_NOT_SUPPORTED), /*compat, but forever*/

  /* obsolete config setup options */

#define O(KEYNAME, ...) { .keyname = KEYNAME, .type = kt_obsolete, }

  O("dpdaction"),
  O("clientaddrfamily"),
  O("keyingtries"),

#undef O
#undef A
#undef K
#undef KWS
};

const struct keywords_def config_conn_keywords = {
	.len = elemsof(config_conn_keyword),
	.item = config_conn_keyword,
};
