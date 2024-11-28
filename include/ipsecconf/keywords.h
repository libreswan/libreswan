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

#ifndef _KEYWORDS_H_
#define _KEYWORDS_H_

#include <sys/queue.h>		/* for TAILQ_ENTRY() et.al. */
#include <stdint.h>		/* for uintmax_t */

#include "lset.h"
#include "constants.h"
#include "deltatime.h"

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

enum keywords {

	/*
	 * Generic keywords, add more here.
	 */
	KW_DEBUG,
	KW_IP,
	KW_NEXTHOP,
	KW_RSASIGKEY,
	KW_ECDSAKEY,
	KW_PUBKEY,

	/*
	 * By convention, these are global configuration strings and
	 * only appear in the "config setup" section (KSF == Keyword
	 * String Flag?).
	 */
	KSF_CURLIFACE,
	KSF_VIRTUALPRIVATE,
	KSF_SYSLOG,
	KSF_DUMPDIR,
	KSF_STATSBINARY,
	KSF_IPSECDIR,
	KSF_NSSDIR,
	KSF_SECRETSFILE,
	KSF_PERPEERDIR,
	KSF_MYVENDORID,
	KSF_LOGFILE,
	KSF_PLUTO_DNSSEC_ROOTKEY_FILE,
	KSF_PLUTO_DNSSEC_ANCHORS,
	KSF_PROTOSTACK,
	KSF_GLOBAL_REDIRECT,
	KSF_GLOBAL_REDIRECT_TO,
	KSF_LISTEN,
	KSF_OCSP_URI,
	KSF_OCSP_TRUSTNAME,

	/*
	 * By convention, these are global configuration numeric (and
	 * boolean) values and only appear in the "config setup"
	 * section (KBF == Keyword Boolean Flag?).
	 */
	KBF_UNIQUEIDS,
	KBF_DO_DNSSEC,
	KBF_LOGTIME,
	KBF_LOGAPPEND,
	KBF_LOGIP,
	KBF_AUDIT_LOG,
	KBF_IKEBUF,
	KBF_IKE_ERRQUEUE,
	KBF_PERPEERLOG,
#ifdef XFRM_LIFETIME_DEFAULT
	KBF_XFRMLIFETIME,
#endif
	KBF_CRL_STRICT,
	KBF_CRL_CHECKINTERVAL,
	KBF_OCSP_STRICT,
	KBF_OCSP_ENABLE,
	KBF_OCSP_TIMEOUT_SECONDS,
	KBF_OCSP_CACHE_SIZE,
	KBF_OCSP_CACHE_MIN_AGE_SECONDS,
	KBF_OCSP_CACHE_MAX_AGE_SECONDS,
	KBF_OCSP_METHOD,
	KBF_CURL_TIMEOUT_SECONDS,
	KBF_SEEDBITS,
	KBF_DROP_OPPO_NULL,
	KBF_KEEP_ALIVE,
	KBF_NHELPERS,
	KBF_SHUNTLIFETIME,
	KBF_FORCEBUSY, 		/* obsoleted for KBF_DDOS_MODE */
	KBF_DDOS_IKE_THRESHOLD,
	KBF_MAX_HALFOPEN_IKE,
	KBF_NFLOG_ALL,		/* Enable global nflog device */
	KBF_DDOS_MODE,		/* set DDOS mode */
	KBF_SECCOMP,		/* set SECCOMP mode */

	KBF_LISTEN_TCP,		/* listen on TCP port 4500 - default no */
	KBF_LISTEN_UDP,		/* listen on UDP port 500/4500 - default yes */
	KBF_GLOBAL_IKEv1,	/* global ikev1 policy - default drop */

	/*
	 * By convention, these are connnection strings (KSCF is
	 * Keyword String Connection Flag?).  The initial ones come in
	 * left/right variants.
	 */

	KSCF_GROUNDHOG,	/* left/right */
	KSCF_UPDOWN,	/* left/right */
	KSCF_ID,	/* left/right */
	KSCF_CERT,	/* left/right */
	KSCF_CKAID,	/* left/right */
	KSCF_CA,	/* left/right */
	KSCF_PROTOPORT,	/* left/right */
	KSCF_SOURCEIP,	/* left/right */
	KSCF_VTI_IP,	/* left/right */
	KSCF_INTERFACE_IP,  /* left/right */
	KSCF_USERNAME,	/* left/right */
	KSCF_ADDRESSPOOL,	/* left/right */
	KSCF_SUBNET,	/* left/right */
	KSCF_SUBNETS,	/* left/right */

	KSCF_IPSEC_INTERFACE,
	KSCF_AUTHBY,
	KSCF_PPK_IDS,
	KSCF_MODECFGDNS,
	KSCF_MODECFGDOMAINS,
	KSCF_IKE,
	KSCF_MODECFGBANNER,
	KSCF_ESP,
	KSCF_ALSO,
	KSCF_REDIRECT_TO,
	KSCF_ACCEPT_REDIRECT_TO,
	KSCF_CONNALIAS,
	KSCF_SEC_LABEL,
	KSCF_MARK,
	KSCF_MARK_IN,
	KSCF_MARK_OUT,
	KSCF_VTI_INTERFACE,
	KSCF_DPDDELAY,
	KSCF_DPDTIMEOUT,

	/*
	 * By convention, these are connection numeric (or boolean)
	 * values (KNCF is Keyword Numeric Connection Flag?).  The
	 * initial ones come in left/right variants.
	 */

	KNCF_XAUTHSERVER,	/* left/right */
	KNCF_XAUTHCLIENT,	/* left/right */
	KNCF_MODECONFIGSERVER,	/* left/right */
	KNCF_MODECONFIGCLIENT,	/* left/right */
	KNCF_CAT,	/* left/right */
	KNCF_SENDCERT,	/* left/right */
	KNCF_IKEPORT,		/* left/right: IKE Port that must be used */
	KNCF_AUTH,	/* left/right */
	KNCF_EAP,	/* left/right */

	KNCF_PFS_REKEY_WORKAROUND,
	KNCF_FIREWALL,
	KNCF_IDTYPE,
	KNCF_SPIBASE,
	KNCF_SPI,
	KNCF_ESPREPLAYWINDOW,

	KNCF_FAILURESHUNT,
	KNCF_NEGOTIATIONSHUNT,
	KNCF_TYPE,
	KNCF_MOBIKE,
	KNCF_MTU,
	KNCF_PRIORITY,
	KNCF_TFC,
	KNCF_IPTFS,
	KNCF_IPTFS_FRAGMENTATION,
	KNCF_IPTFS_PKT_SIZE,
	KNCF_IPTFS_MAX_QUEUE,
	KNCF_IPTFS_INIT_DELAY,
	KNCF_IPTFS_REORD_WIN,
	KNCF_IPTFS_DROP_TIME,
	KNCF_REQID,
	KNCF_SEND_CA,
	KNCF_METRIC,
	KNCF_PHASE2,
	KNCF_AUTO,
	KNCF_PFS,
	KNCF_SHA2_TRUNCBUG,
	KNCF_MS_DH_DOWNGRADE,
	KNCF_REQUIRE_ID_ON_CERTIFICATE,
	KNCF_DNS_MATCH_ID,
	KNCF_IPSEC_LIFETIME,
	KNCF_IPSEC_MAXBYTES,
	KNCF_IPSEC_MAXPACKETS,
	KNCF_REKEY,
	KNCF_REAUTH,
	KNCF_REKEYMARGIN,
	KNCF_REKEYFUZZ,
	KNCF_COMPRESS,
	KNCF_KEYINGTRIES,
	KNCF_REPLAY_WINDOW,
	KNCF_IKELIFETIME,
	KNCF_RETRANSMIT_TIMEOUT,
	KNCF_RETRANSMIT_INTERVAL,
	KNCF_AGGRESSIVE,
	KNCF_MODECFGPULL,
	KNCF_ENCAPSULATION,
	KNCF_IKEv2,		/* obsolete, use KEYEXCHANGE */
	KNCF_KEYEXCHANGE,
	KNCF_PPK,
	KNCF_INTERMEDIATE,	/* enable support for Intermediate Exchange */
	KNCF_ESN,
	KNCF_DECAP_DSCP,
	KNCF_ENCAP_DSCP,
	KNCF_NOPMTUDISC,
	KNCF_NARROWING,
	KNCF_PAM_AUTHORIZE,
	KNCF_SEND_REDIRECT,	/* this and next word are used for IKEv2 Redirect Mechanism */
	KNCF_ACCEPT_REDIRECT,	/* see RFC 5685 for more details */
	KNCF_HOSTADDRFAMILY,
	KNCF_CLIENTADDRFAMILY,
	KNCF_OVERLAPIP,		/* Allow overlapping IPsec policies */
	KNCF_REMOTE_PEER_TYPE,	/* Cisco interop: remote peer type */
	KNCF_NM_CONFIGURED,	/* Network Manager support */
	KNCF_SAREFTRACK,	/* saref tracking parameter for _updown */
	KNCF_OBSOLETE,		/* to ignore but warn obsoleted keywords */
	KNCF_XAUTHBY,		/* method of xauth user auth - file, pam or alwaysok */
	KNCF_XAUTHFAIL,		/* method of failing, soft or hard */
	KNCF_FRAGMENTATION,	/* Enable support for IKE fragmentation */
	KNCF_NAT_KEEPALIVE,	/* per conn enabling/disabling of sending keep-alives */
	KNCF_INITIAL_CONTACT,	/* send initial contact VID */
	KNCF_CISCO_UNITY,	/* send cisco unity VID */
	KNCF_NO_ESP_TFC,	/* send ESP_TFC_PADDING_NOT_SUPPORTED */
	KNCF_VID_STRONGSWAN,	/* send strongswan VID (required for twofish/serpent) */
	KNCF_SEND_VENDORID,	/* per conn sending of our own libreswan vendorid */
	KNCF_IKEPAD,		/* pad IKE packets to 4 bytes */
	KNCF_NAT_IKEv1_METHOD,	/* ikev1 NAT-T payloads to send/process */
	KNCF_NFLOG_CONN,	/* Enable per-conn nflog device */
	KNCF_VTI_ROUTING,	/* let updown do routing into VTI device */
	KNCF_VTI_SHARED,	/* VTI device is shared - enable checks and disable cleanup */
	KNCF_NIC_OFFLOAD,	/* xfrm offload to network device */
	KNCF_ENABLE_TCP,	/* TCP (yes/no/fallback) */
	KNCF_TCP_REMOTEPORT,	/* TCP remote port - default 4500 */
	KNCF_IGNORE_PEER_DNS,	/* Accept DNS nameservers from peer */
	KNCF_SESSION_RESUMPTION,	/* RFC 5723 IKE_RESUME */

	KW_roof,
};

/* these are bits set in a word */
enum keyword_valid {
	kv_config = LELEM(0),           /* may be present in config section */
	kv_conn   = LELEM(1),           /* may be present in conn section */
	kv_leftright = LELEM(2),        /* comes in leftFOO and rightFOO variants */
	kv_both = LELEM(2) | LELEM(3),	/* also comes in FOO meaning left-FOO and right-FOO */

	kv_alias  = LELEM(5),           /* is an alias for another keyword */
	kv_policy = LELEM(6),           /* is a policy affecting verb, processed specially */
	kv_processed = LELEM(7),        /* is processed, do not output literal string */
	kv_duplicateok = LELEM(8),	/* within a connection, the
					 * item can be duplicated
					 * (notably also=) */
#if 0
	kv_overrideok = LELEM(?),	/* between merged connections
					 * (also=), the item can be
					 * overwritten */
#endif
};
#define KV_CONTEXT_MASK (kv_config | kv_conn | kv_leftright)

/*
 * Potential keyword values for fields like {left,right}rsasigkey=.
 *
 * This is internal to the config parser and doesn't belong in whack
 * or on the wire.
 */
enum keyword_pubkey {
	PUBKEY_NOTSET       = 0,
	PUBKEY_DNSONDEMAND  = 1,
	PUBKEY_CERTIFICATE  = 2,
	PUBKEY_PREEXCHANGED = LOOSE_ENUM_OTHER,
};

enum keyword_type {
	kt_string,              /* value is some string */
	kt_appendstring,        /* value is some string, append duplicates */
	kt_appendlist,          /* value is some list, append duplicates */
	kt_filename,            /* value is a filename string */
	kt_dirname,             /* value is a dir name string */
	kt_bool,                /* value is an on/off type */
	kt_sparse_name,         /* value is from .sparse_name table */
	kt_lset,                /* a set of values from .sparse_name */
	kt_host,	        /* %-prefixed .sparse_name, or a hostname string */
	kt_pubkey,	        /* %-prefixed .sparse_name, or a pubkey string */
	kt_unsigned,            /* an unsigned integer */
	kt_seconds,             /* deltatime, default in seconds */
	kt_milliseconds,        /* deltatime, default in milliseconds (1/1000s) */
	kt_percent,             /* a number representing percentage */
	kt_byte,                /* a number representing Binary bytes with prefixs. KiB.. IEC 60027-2/ISO 8000 */
	kt_binary,              /* a number representing Binary prefixes Ki. IEC 60027-2/ISO 8000  */
	kt_range,               /* ip address range 1.2.3.4-1.2.3.10 */
	kt_ipaddr,              /* an IP address */
	kt_subnet,              /* an IP address subnet */
	kt_idtype,              /* an ID type */
	kt_bitstring,           /* an encryption/authentication key */
	kt_also,		/* i.e., #include */
	kt_obsolete,            /* option that is obsoleted, allow keyword but warn and ignore */
};

struct keyword_def {
	const char        *keyname;
	unsigned int validity;          /* has bits from enum keyword_valid (kv_*) */
	enum keyword_type type;
	unsigned int field;             /* one of keyword_*_field */
	const struct sparse_names *sparse_names;
	const struct lmod_info *info;
};

struct keyword {
	const struct keyword_def *keydef;
	bool keyleft;
	bool keyright;
	char *string;
};

/* note: these lists are dynamic */
struct kw_list {
	struct kw_list *next;
	struct keyword keyword;
	char *string;
	uintmax_t number;
	deltatime_t deltatime;
};

struct section_list {
	TAILQ_ENTRY(section_list) link;

	char *name;
	struct kw_list *kw;
	bool beenhere;
};

struct config_parsed {
	struct kw_list *config_setup;

	TAILQ_HEAD(sectionhead, section_list) sections;
	int ipsec_conf_version;

	struct section_list conn_default;
};

extern const struct keyword_def ipsec_conf_keywords[];

#endif /* _KEYWORDS_H_ */
