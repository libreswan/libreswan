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

#include "lset.h"

#ifndef _LIBRESWAN_H
#include "libreswan.h"
#include "constants.h"
#endif

#include <sys/queue.h>

/*
 * These are global configuration strings.
 * They only appear in "config setup" section.
 * Indices for .setup.strings[], .setup.strings_set[]
 */
enum keyword_string_config_field {
	KSF_INTERFACES, /* loose_enum eventually */
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

	KSF_ROOF
};

/*
 * These are global config Bools (or numbers).
 * They only appear in "config setup" section.
 * Indices for .setup.option[], .setup.options_set[]
 */
enum keyword_numeric_config_field {
	KBF_UNIQUEIDS,
	KBF_DO_DNSSEC,
	KBF_LOGTIME,
	KBF_LOGAPPEND,
	KBF_LOGIP,
	KBF_AUDIT_LOG,
	KBF_IKEBUF,
	KBF_IKE_ERRQUEUE,
	KBF_PERPEERLOG,
	KBF_XFRMLIFETIME,
	KBF_CRL_STRICT,
	KBF_CRL_CHECKINTERVAL,
	KBF_OCSP_STRICT,
	KBF_OCSP_ENABLE,
	KBF_OCSP_TIMEOUT,
	KBF_OCSP_CACHE_SIZE,
	KBF_OCSP_CACHE_MIN,
	KBF_OCSP_CACHE_MAX,
	KBF_OCSP_METHOD,
	KBF_CURLTIMEOUT,
	KBF_SEEDBITS,
	KBF_DROP_OPPO_NULL,
	KBF_KEEPALIVE,
	KBF_PLUTODEBUG,
	KBF_NHELPERS,
	KBF_SHUNTLIFETIME,
	KBF_FORCEBUSY, 		/* obsoleted for KBF_DDOS_MODE */
	KBF_DDOS_IKE_THRESHOLD,
	KBF_MAX_HALFOPEN_IKE,
	KBF_SECCTX,		/* security context attribute value for labeled ipsec */
	KBF_NFLOG_ALL,		/* Enable global nflog device */
	KBF_DDOS_MODE,		/* set DDOS mode */
	KBF_SECCOMP,		/* set SECCOMP mode */

	KBF_LISTEN_TCP,		/* listen on TCP port 4500 - default no */
	KBF_LISTEN_UDP,		/* listen on UDP port 500/4500 - default yes */

	KBF_ROOF
};

/*
 * These are conn strings.
 * The initial ones come in left/right variants.
 *
 * NOTE: loose_enum values have both string and integer types
 * WITH THE SAME INDEX!  They come in left and right= variants.
 *
 * Indices for .strings[], .strings_set[]
 * or .{left|right}.strings[], .{left|right}.strings_set[]
 */

enum keyword_string_conn_field {
	KSCF_IP,	/* loose_enum */ /* left/right */
	KSCF_NEXTHOP,	/* loose_enum */ /* left/right */
	KSCF_RSAKEY1,	/* loose_enum */ /* left/right */
	KSCF_RSAKEY2,	/* loose_enum */ /* left/right */
	KSCF_XFRM_IF_ID,
		KSCF_last_loose = KSCF_XFRM_IF_ID,

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
		KSCF_last_leftright = KSCF_SUBNETS,

	KSCF_AUTHBY,
	KSCF_MODECFGDNS,
	KSCF_MODECFGDOMAINS,
	KSCF_IKE,
	KSCF_MODECFGBANNER,
	KSCF_ESP,
	KSCF_ALSO,
	KSCF_ALSOFLIP,
	KSCF_REDIRECT_TO,
	KSCF_ACCEPT_REDIRECT_TO,
	KSCF_CONNALIAS,
	KSCF_POLICY_LABEL,
	KSCF_CONN_MARK_BOTH,
	KSCF_CONN_MARK_IN,
	KSCF_CONN_MARK_OUT,
	KSCF_VTI_IFACE,

	KSCF_ROOF
};

/*
 * conn numbers (or bool).
 * The initial ones come in left/right variants.
 *
 * NOTE: loose_enum values have both string and integer types
 * WITH THE SAME INDEX!  They come in left and right= variants.
 *
 * Indices for .option[], .options_set[]
 * or .{left|right}.option[], .{left|right}.options_set[]
 */

enum keyword_numeric_conn_field {
	KNCF_IP		= KSCF_IP,	/* loose_enum */ /* left/right */
	KNCF_NEXTHOP	= KSCF_NEXTHOP,	/* loose_enum */ /* left/right */
	KNCF_RSAKEY1	= KSCF_RSAKEY1,	/* loose_enum */ /* left/right */
	KNCF_RSAKEY2	= KSCF_RSAKEY2,	/* loose_enum */ /* left/right */
	KNCF_XFRM_IF_ID =  KSCF_XFRM_IF_ID,

	KNCF_XAUTHSERVER,	/* left/right */
	KNCF_XAUTHCLIENT,	/* left/right */
	KNCF_MODECONFIGSERVER,	/* left/right */
	KNCF_MODECONFIGCLIENT,	/* left/right */
	KNCF_CAT,	/* left/right */
	KNCF_SENDCERT,	/* left/right */
	KNCF_IKEPORT,		/* left/right: IKE Port that must be used */
	KNCF_AUTH,	/* left/right */

		KNCF_last_leftright = KNCF_AUTH,

	KNCF_FIREWALL,
	KNCF_IDTYPE,
	KNCF_SPIBASE,
	KNCF_SPI,
	KNCF_ESPREPLAYWINDOW,

	/* ??? these were once in keyword_numeric_config_field (KBF prefix) */
	KNCF_DPDACTION,
	KNCF_FAILURESHUNT,
	KNCF_NEGOTIATIONSHUNT,
	KNCF_TYPE,
	KNCF_MOBIKE,
	KNCF_CONNMTU,
	KNCF_PRIORITY,
	KNCF_TFCPAD,
	KNCF_REQID,
	KNCF_SEND_CA,
	KNCF_DPDDELAY,
	KNCF_DPDTIMEOUT,
	KNCF_METRIC,
	KNCF_PHASE2,
	KNCF_KEYEXCHANGE,
	KNCF_AUTO,
	KNCF_PFS,
	KNCF_SHA2_TRUNCBUG,
	KNCF_MSDH_DOWNGRADE,
	KNCF_SAN_ON_CERT,
	KNCF_DNS_MATCH_ID,
	KNCF_SALIFETIME,
	KNCF_REKEY,
	KNCF_REAUTH,
	KNCF_REKEYMARGIN,
	KNCF_REKEYFUZZ,
	KNCF_COMPRESS,
	KNCF_KEYINGTRIES,
	KNCF_REPLAY_WINDOW,
	KNCF_IKELIFETIME,
	KNCF_RETRANSMIT_TIMEOUT,
	KNCF_RETRANSMIT_INTERVAL_MS,
	KNCF_AGGRMODE,
	KNCF_MODECONFIGPULL,
	KNCF_ENCAPS,
	KNCF_IKEv2,
	KNCF_PPK,
	KNCF_ESN,
	KNCF_DECAP_DSCP,
	KNCF_NOPMTUDISC,
	KNCF_IKEv2_ALLOW_NARROWING,
	KNCF_IKEv2_PAM_AUTHORIZE,
	KNCF_SEND_REDIRECT,	/* this and next word are used for IKEv2 Redirect Mechanism */
	KNCF_ACCEPT_REDIRECT,	/* see RFC 5685 for more details */
	KNCF_HOSTADDRFAMILY,
	KNCF_CLIENTADDRFAMILY,
	KNCF_OVERLAPIP,		/* Allow overlapping IPsec policies */
	KNCF_REMOTEPEERTYPE,	/* Cisco interop: remote peer type */
	KNCF_NMCONFIGURED,	/* Network Manager support */
	KNCF_SAREFTRACK,	/* saref tracking parameter for _updown */
	KNCF_WARNIGNORE,	/* to ignore obsoleted keywords */
	KNCF_XAUTHBY,		/* method of xauth user auth - file, pam or alwaysok */
	KNCF_XAUTHFAIL,		/* method of failing, soft or hard */
	KNCF_IKE_FRAG,		/* Enable support for IKE fragmentation */
	KNCF_NAT_KEEPALIVE,	/* per conn enabling/disabling of sending keep-alives */
	KNCF_INITIAL_CONTACT,	/* send initial contact VID */
	KNCF_CISCO_UNITY,	/* send cisco unity VID */
	KNCF_NO_ESP_TFC,	/* send ESP_TFC_PADDING_NOT_SUPPORTED */
	KNCF_VID_STRONGSWAN,	/* send strongswan VID (required for twofish/serpent) */
	KNCF_SEND_VENDORID,	/* per conn sending of our own libreswan vendorid */
	KNCF_IKEPAD,		/* pad IKE packets to 4 bytes */
	KNCF_IKEV1_NATT,	/* ikev1 NAT-T payloads to send/process */
	KNCF_NFLOG_CONN,	/* Enable per-conn nflog device */
	KNCF_VTI_ROUTING,	/* let updown do routing into VTI device */
	KNCF_VTI_SHARED,	/* VTI device is shared - enable checks and disable cleanup */
	KNCF_NIC_OFFLOAD,	/* xfrm offload to network device */

	/*
	 * TCP: these names match the whack.message field name, but
	 * not the option.  All three should probably be consistent.
	 */
	KNCF_TCPONLY,		/* TCP: per connection? Description? */
	KNCF_REMOTE_TCPPORT,	/* TCP: per connection? Description? */

	KNCF_ROOF
};

/*
 * comparing members of two different enums draws warnings from GCC
 * so we cast one to int
 */
#define KEY_STRINGS_ROOF ((int)KSF_ROOF > KSCF_ROOF ? \
				KSF_ROOF : KSCF_ROOF)

#define KEY_NUMERIC_ROOF ((int)KBF_ROOF > KNCF_ROOF ? \
				KBF_ROOF : KNCF_ROOF)

/* these are bits set in a word */
enum keyword_valid {
	kv_config = LELEM(0),           /* may be present in config section */
	kv_conn   = LELEM(1),           /* may be present in conn section */
	kv_leftright = LELEM(2),        /* comes in leftFOO and rightFOO varients */
	kv_alias  = LELEM(5),           /* is an alias for another keyword */
	kv_policy = LELEM(6),           /* is a policy affecting verb, processed specially */
	kv_processed = LELEM(7),        /* is processed, do not output literal string */
	kv_duplicateok = LELEM(8),      /* it is okay if also= items are duplicated */
};
#define KV_CONTEXT_MASK (kv_config | kv_conn | kv_leftright)

/* values keyexchange= */
enum keyword_keyexchange {
	KE_NONE = 0,
	KE_IKE  = 1,
};

/* values for auto={add,start,route,ignore} */
enum keyword_auto {
	STARTUP_IGNORE     = 0,
	STARTUP_POLICY     = 1,
	STARTUP_ADD        = 2,
	STARTUP_ONDEMAND   = 3,
	STARTUP_START      = 4
};

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

enum keyword_satype {
	KS_TUNNEL    = 0,
	KS_TRANSPORT = 1,
	KS_PASSTHROUGH=2,
	KS_DROP      = 3,
	KS_REJECT    = 4,
};

enum keyword_failure_shunt {
	KFS_FAIL_NONE,
	KFS_FAIL_PASS,
	KFS_FAIL_DROP,
	KFS_FAIL_REJECT
};

enum keyword_negotiation_shunt {
	KNS_FAIL_PASS,
	KNS_FAIL_DROP
};

enum keyword_type {
	kt_string,              /* value is some string */
	kt_appendstring,        /* value is some string, append duplicates */
	kt_appendlist,          /* value is some list, append duplicates */
	kt_filename,            /* value is a filename string */
	kt_dirname,             /* value is a dir name string */
	kt_bool,                /* value is an on/off type */
	kt_invertbool,          /* value is an off/on type ("disable") */
	kt_enum,                /* value is from a set of key words */
	kt_list,                /* a set of values from a set of key words */
	kt_lset,		/* a set of values from an enum name */
	kt_loose_enum,          /* either a string, or a %-prefixed enum */
	kt_rsakey,              /* a key, or set of values */
	kt_number,              /* an integer */
	kt_time,                /* a number representing time */
	kt_percent,             /* a number representing percentage */
	kt_range,               /* ip address range 1.2.3.4-1.2.3.10 */
	kt_ipaddr,              /* an IP address */
	kt_subnet,              /* an IP address subnet */
	kt_idtype,              /* an ID type */
	kt_bitstring,           /* an encryption/authentication key */
	kt_comment,             /* a value that is a cooked comment */
	kt_obsolete,            /* option that is obsoleted, allow keyword but warn and ignore */
	kt_obsolete_quiet,      /* option that is obsoleted, allow keyword but don't bother warning */
};

struct keyword_def {
	const char        *keyname;
	unsigned int validity;          /* has bits from enum keyword_valid (kv_*) */
	enum keyword_type type;
	unsigned int field;             /* one of keyword_*_field */
	const struct keyword_enum_values *validenum;
	const struct lmod_info *info;
};

struct keyword {
	const struct keyword_def *keydef;
	bool keyleft;
	char               *string;
};

/* note: these lists are dynamic */
struct kw_list {
	struct kw_list *next;
	struct keyword keyword;
	char *string;
	unsigned int number;
};

struct starter_comments {
	TAILQ_ENTRY(starter_comments) link;
	char *x_comment;
	char *commentvalue;
};

TAILQ_HEAD(starter_comments_list, starter_comments);

struct section_list {
	TAILQ_ENTRY(section_list) link;

	char *name;
	struct kw_list *kw;
	struct starter_comments_list comments;
	bool beenhere;
};

struct config_parsed {
	struct kw_list *config_setup;

	TAILQ_HEAD(sectionhead, section_list) sections;
	int ipsec_conf_version;

	struct starter_comments_list comments;

	struct section_list conn_default;
};

extern const struct keyword_def ipsec_conf_keywords[];

extern lset_t parser_lset(const struct keyword_def *kd, const char *s);
extern unsigned int parser_enum_list(const struct keyword_def *kd, const char *s,
				     bool list);
extern unsigned int parser_loose_enum(struct keyword *k, const char *s);

#endif /* _KEYWORDS_H_ */
