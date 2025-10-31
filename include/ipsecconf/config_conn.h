/* Libreswan config file parser keywords processor
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013-2016 Antony Antony <antony@phenome.org>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020, Yulia Kuzovkova <ukuzovkova@gmail.com>
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
 *
 */

#ifndef IPSECCONF_CONFIG_CONN_H
#define IPSECCONF_CONFIG_CONN_H

/*
 * Keyword value indexes.  The value is stored in:
 *
 * + the keyword table determines: the keyword type; where it is valid
 *   and where the value is stored are stored:
 *
 *   "config setup; keyword=": in .setup.{strings,options,set}[].
 *   "conn ...' keyword=": in .{strings,options,set}[]
 *   "conn ; left...": in .{left,right}.{strings,options,set}[]
 *
 * + The original string is always stored in .strings[] and should be
 *   used when logging errors.
 *
 * + .set[] is made non-zero (either k_set or k_default); code tests
 *   for non-zero to determine if a value is present
 *
 * + for historic reasons, some of the enums have strange prefixes
 *   and/or strange grouping.  For instance, KSF_* options only appear
 *   in "config setup" so if the same option used between multiple
 *   sections the prefix should be changed.
 */

enum config_conn_keyword {
	/* zero is reserved */

	/*
	 * Generic keywords, add more here.
	 */
	KWS_DEBUG = 1,
	KWS_HOST,
	KWS_NEXTHOP,

	KWS_RSASIGKEY,
	KWS_ECDSAKEY,
	KWS_EDDSAKEY,
	KWS_PUBKEY,

	KWS_IPSEC_INTERFACE,

	KWS_CLONES,	/* RFC 9611 */

	/*
	 * By convention, these are connection strings (KSCF is
	 * Keyword String Connection Flag?).  The initial ones come in
	 * left/right variants.
	 */

	KWYN_GROUNDHOG,	/* left/right */
	KWS_UPDOWN,	/* left/right */
	KWS_ID,		/* left/right */
	KWS_CERT,	/* left/right */
	KWS_CKAID,	/* left/right */
	KWS_CA,	/* left/right */
	KWS_PROTOPORT,	/* left/right */
	KWS_SOURCEIP,	/* left/right */
	KWS_VTI,	/* left/right */
	KWS_INTERFACE_IP,  /* left/right */
	KWS_USERNAME,	/* left/right */
	KWS_ADDRESSPOOL,	/* left/right */
	KWS_SUBNET,	/* left/right */
	KWS_SUBNETS,	/* left/right */

	KWS_AUTHBY,

	KWS_PPK_IDS,
	KWS_MODECFGDNS,
	KWS_MODECFGDOMAINS,

	KWS_IKE,
	KWS_ESP,
	KWS_AH,
	KNCF_PHASE2,
	KWS_PHASE2ALG,

	KWS_MODECFGBANNER,
	KSCF_ALSO,
	KWS_REDIRECT_TO,
	KWS_ACCEPT_REDIRECT_TO,
	KWS_CONNALIAS,
	KWS_SEC_LABEL,
	KWS_MARK,
	KWS_MARK_IN,
	KWS_MARK_OUT,
	KWS_VTI_INTERFACE,
	KWS_DPDDELAY,
	KWS_DPDTIMEOUT,

	/*
	 * By convention, these are connection numeric (or boolean)
	 * values (KNCF is Keyword Numeric Connection Flag?).  The
	 * initial ones come in left/right variants.
	 */

	KWYN_XAUTHSERVER,	/* left/right */
	KWYN_XAUTHCLIENT,	/* left/right */
	KWYN_MODECONFIGSERVER,	/* left/right */
	KWYN_MODECONFIGCLIENT,	/* left/right */
	KWYN_CAT,	/* left/right */
	KWS_SENDCERT,	/* left/right */
	KWS_IKEPORT,		/* left/right: IKE Port that must be used */
	KWS_AUTH,	/* left/right */
	KWS_AUTHEAP,	/* left/right */

	KWYN_PFS_REKEY_WORKAROUND,

	KNCF_FAILURESHUNT,
	KNCF_NEGOTIATIONSHUNT,
	KNCF_TYPE,
	KWYN_MOBIKE,
	KWS_MTU,
	KWS_PRIORITY,
	KWS_TFC,
	KWYN_IPTFS,
	KWYN_IPTFS_FRAGMENTATION,
	KWS_IPTFS_PACKET_SIZE,
	KWS_IPTFS_MAX_QUEUE_SIZE,
	KNCF_IPTFS_INIT_DELAY,
	KWS_IPTFS_REORDER_WINDOW,
	KNCF_IPTFS_DROP_TIME,
	KWS_REQID,
	KWS_SENDCA,
	KNCF_METRIC,
	KNCF_AUTO,
	KWYN_PFS,
	KWYN_SHA2_TRUNCBUG,
	KWYN_SHARE_LEASE,
	KWYN_MS_DH_DOWNGRADE,
	KWYN_REQUIRE_ID_ON_CERTIFICATE,
	KWYN_DNS_MATCH_ID,
	KNCF_IPSEC_LIFETIME,
	KWS_IPSEC_MAX_BYTES,
	KWS_IPSEC_MAX_PACKETS,
	KWYN_REKEY,
	KWYN_REAUTH,
	KNCF_REKEYMARGIN,
	KWS_REKEYFUZZ,
	KWYN_COMPRESS,
	KWS_REPLAY_WINDOW,
	KNCF_IKELIFETIME,
	KNCF_RETRANSMIT_TIMEOUT,
	KWS_RETRANSMIT_INTERVAL,
	KWYN_AGGRESSIVE,
	KWYN_MODECFGPULL,
	KNCF_ENCAPSULATION,
	KWS_IKEv2,		/* obsolete, use KEYEXCHANGE */
	KWS_KEYEXCHANGE,
	KNCF_PPK,
	KWYN_INTERMEDIATE,	/* enable support for Intermediate Exchange */
	KNCF_ESN,
	KWYN_DECAP_DSCP,
	KWYN_ENCAP_DSCP,
	KWYN_NOPMTUDISC,
	KWYN_NARROWING,
	KWYN_PAM_AUTHORIZE,
	KNCF_SEND_REDIRECT,	/* this and next word are used for IKEv2 Redirect Mechanism */
	KWYN_ACCEPT_REDIRECT,	/* see RFC 5685 for more details */
	KWS_HOSTADDRFAMILY,
	KWYN_OVERLAPIP,		/* Allow overlapping IPsec policies */
	KNCF_XAUTHBY,		/* method of xauth user auth - file, pam or alwaysok */
	KNCF_XAUTHFAIL,		/* method of failing, soft or hard */
	KNCF_FRAGMENTATION,	/* Enable support for IKE fragmentation */
	KWYN_NAT_KEEPALIVE,	/* per conn enabling/disabling of sending keep-alives */
	KWYN_INITIAL_CONTACT,	/* send initial contact VID */

	/* cisco unity stuff */
	KWS_REMOTE_PEER_TYPE,	/* Cisco interop: remote peer type */
	KWS_CISCO_UNITY,	/* send cisco unity VID */
	KWS_NM_CONFIGURED,	/* Network Manager support */
	KWS_CISCO_SPLIT,	/* send cisco unity VID */

	KWYN_SEND_ESP_TFC_PADDING_NOT_SUPPORTED,
	KWYN_REJECT_SIMULTANEOUS_IKE_AUTH,
	KWYN_FAKE_STRONGSWAN,	/* send strongswan VID (required for twofish/serpent) */
	KWYN_SEND_VENDORID,	/* per conn sending of our own libreswan vendorid */
	KNCF_IKEPAD,		/* pad IKE packets to 4 bytes */
	KNCF_NAT_IKEv1_METHOD,	/* ikev1 NAT-T payloads to send/process */
	KWS_NFLOG_GROUP,	/* Enable per-conn nflog device */
	KWYN_VTI_ROUTING,	/* let updown do routing into VTI device */
	KWYN_VTI_SHARED,	/* VTI device is shared - enable checks and disable cleanup */
	KNCF_NIC_OFFLOAD,	/* xfrm offload to network device */
	KNCF_ENABLE_TCP,	/* TCP (yes/no/fallback) */
	KNCF_TCP_REMOTEPORT,	/* TCP remote port - default 4500 */
	KWYN_IGNORE_PEER_DNS,	/* Accept DNS nameservers from peer */
	KWYN_SESSION_RESUMPTION,	/* RFC 5723 IKE_RESUME */

#define CONFIG_CONN_KEYWORD_ROOF (KWYN_SESSION_RESUMPTION + 1)
};

#endif
