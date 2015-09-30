/* Libreswan config file parser keywords processor
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef _KEYWORDS_H_
#define _KEYWORDS_H_

#ifndef _LIBRESWAN_H
#include "libreswan.h"
#include "constants.h"
#endif

/*
 * these are global configuration parameters, and appear in
 * "config setup" stanza, and as non-left/right items in
 * the "conn foo" stanzas
 */
enum keyword_string_config_field {
	KSF_INTERFACES    = 0, /* loose_enum eventually */
	/* KSF_PACKETDEFAULT = 5, */
	KSF_CURLIFACE,
	KSF_VIRTUALPRIVATE,
	KSF_SYSLOG,
	KSF_DUMPDIR,
	KSF_STATSBINARY,
	KSF_IPSECDIR,
	KSF_SECRETSFILE,
	KSF_PERPEERDIR,
	KSF_MYID,
	KSF_MYVENDORID,
	KSF_PLUTOSTDERRLOG,
	KSF_PROTOSTACK,
	KSF_IKE,
	KSF_ESP,
	KSF_ALSO,
	KSF_ALSOFLIP,
	KSF_CONNALIAS,
	KSF_LISTEN,
	KSF_POLICY_LABEL,
	KSF_MODECFGDNS1,
	KSF_MODECFGDNS2,
	KSF_MODECFGDOMAIN,
	KSF_MODECFGBANNER,
	KSF_OCSPURI,
	KSF_OCSPTRUSTNAME,
	KSF_MAX
};

/* Numeric fields also include boolean fields */
/* and do not come in right/left variants */
enum keyword_numeric_config_field {
	KBF_DPDACTION,
	KBF_FAILURESHUNT,
	KBF_NEGOTIATIONSHUNT,
	KBF_TYPE,
	KBF_FRAGICMP,
	KBF_HIDETOS,
	KBF_UNIQUEIDS,
	KBF_PLUTOSTDERRLOGTIME,
	KBF_PLUTOSTDERRLOGAPPEND,
	KBF_IKEPORT,
	KBF_PLUTOFORK,
	KBF_PERPEERLOG,
	KBF_OVERRIDEMTU,
	KBF_CONNMTU,
	KBF_PRIORITY,
	KBF_REQID,
	KBF_XFRMLIFETIME,
	KBF_STRICTCRLPOLICY,
	KBF_STRICTOCSPPOLICY,
	KBF_OCSPENABLE,
	KBF_OCSPTIMEOUT,
	KBF_CURLTIMEOUT,
	KBF_SEND_CA,
	KBF_NATIKEPORT,
	KBF_SEEDBITS,
	KBF_KEEPALIVE,
	KBF_PLUTORESTARTONCRASH,
	KBF_CRLCHECKINTERVAL,
	KBF_KLIPSDEBUG,
	KBF_PLUTODEBUG,
	KBF_NHELPERS,
	KBF_OPPOENCRYPT,
	KBF_DPDDELAY,
	KBF_DPDTIMEOUT,
	KBF_METRIC,
	KBF_PHASE2,
	KBF_AUTHBY,
	KBF_KEYEXCHANGE,
	KBF_AUTO,
	KBF_PFS,
	KBF_SHA2_TRUNCBUG,
	KBF_SALIFETIME,
	KBF_REKEY,
	KBF_REKEYMARGIN,
	KBF_REKEYFUZZ,
	KBF_COMPRESS,
	KBF_KEYINGTRIES,
	KBF_ARRIVALCHECK,
	KBF_IKELIFETIME,
	KBF_SHUNTLIFETIME,
	KBF_RETRANSMIT_TIMEOUT,
	KBF_RETRANSMIT_INTERVAL,
	KBF_AGGRMODE,
	KBF_MODECONFIGPULL,
	KBF_FORCEENCAP,
	KBF_IKEv2,
	KBF_IKEv2_ALLOW_NARROWING,
	KBF_IKEv2_PAM_AUTHORIZE,
	KBF_CONNADDRFAMILY,
	KBF_FORCEBUSY, /* obsoleted for KBF_DDOS_MODE */
	KBF_DDOS_IKE_TRESHOLD,
	KBF_MAX_HALFOPEN_IKE,
	KBF_OVERLAPIP,
	KBF_REMOTEPEERTYPE,     /*Cisco interop: remote peer type */
	KBF_NMCONFIGURED,       /*Network Manager support */
	KBF_LABELED_IPSEC,
	KBF_SAREFTRACK,         /* saref tracking paramter for _updown */
	KBF_WARNIGNORE,         /* to ignore obsoleted keywords */
	KBF_SECCTX,             /*security context attribute value for labeled ipsec */
	KBF_XAUTHBY,            /* method of xauth user auth - file, pam or alwaysok */
	KBF_XAUTHFAIL,          /* method of failing, soft or hard */
	KBF_IKE_FRAG,
	KBF_NAT_KEEPALIVE,      /* per conn enabling/disabling of sending keep-alives - different from global force_keepalives */
	KBF_INITIAL_CONTACT,
	KBF_CISCO_UNITY,
	KBF_SEND_VENDORID,      /* per conn sending of our own libreswan vendorid */
	KBF_IKEPAD,             /* pad IKE packets to 4 bytes */
	KBF_IKEV1_NATT,		/* ikev1 NAT-T payloads to send/process */
	KBF_NFLOG_ALL,
	KBF_NFLOG_CONN,
	KBF_DDOS_MODE,
	KBF_MAX
};

/*
 * these are global configuration parameters, and appear in
 * normal conn sections, some of them come in left/right variants.
 *
 * NOTE: loose_enum values have both string and integer types,
 * and MUST have the same index for each.
 *
 * they come in left and right= variants.
 *
 */

enum keyword_string_conn_field {
	KSCF_IP           = 0,  /* loose_enum */
	KSCF_SUBNET       = 1,
	KSCF_NEXTHOP      = 2,  /* loose_enum */
	KSCF_UPDOWN       = 3,
	KSCF_ID           = 4,
	KSCF_RSAKEY1      = 5,  /* loose_enum */
	KSCF_RSAKEY2      = 6,  /* loose_enum */
	KSCF_CERT         = 7,
	KSCF_CA           = 8,
	KSCF_SUBNETWITHIN = 9,
	KSCF_PROTOPORT    = 10,
	KSCF_ESPENCKEY    = 13,
	KSCF_ESPAUTHKEY   = 14,
	KSCF_SOURCEIP     = 15,
	KSCF_XAUTHUSERNAME= 16,
	KSCF_SUBNETS      = 17,
	KSCF_ADDRESSPOOL  = 18,
	KSCF_MAX
};

enum keyword_numeric_conn_field {
	KNCF_IP               = 0,      /* loose_enum */
	KNCF_FIREWALL         = 1,
	KNCF_NEXTHOP          = 2,      /* loose_enum */
	KNCF_IDTYPE           = 3,
	KNCF_SPIBASE          = 4,
	KNCF_RSAKEY1          = 5,      /* loose_enum */
	KNCF_RSAKEY2          = 6,      /* loose_enum */
	KNCF_XAUTHSERVER      = 7,
	KNCF_XAUTHCLIENT      = 8,
	KNCF_MODECONFIGSERVER = 9,
	KNCF_MODECONFIGCLIENT = 10,
	KNCF_SPI,
	KNCF_ESPREPLAYWINDOW,
	KNCF_SENDCERT,
	KNCF_MAX
};

/* ??? seems a little funny that KEY_STRINGS_MAX is really +1 */
#define KEY_STRINGS_MAX (((int)KSF_MAX > \
			  (int)KSCF_MAX ? (int)KSF_MAX : (int)KSCF_MAX) + 1)

/* ??? seems a little funny that KEY_NUMERIC_MAX is really +1 */
#define KEY_NUMERIC_MAX (((int)KBF_MAX > \
			  (int)KNCF_MAX ? (int)KBF_MAX : (int)KNCF_MAX) + 1)

/* these are bits set in a word */
enum keyword_valid {
	kv_config = LELEM(0),           /* may be present in config section */
	kv_conn   = LELEM(1),           /* may be present in conn section */
	kv_leftright = LELEM(2),        /* comes in leftFOO and rightFOO varients */
	kv_auto   = LELEM(3),           /* valid when keyingtype=auto */
	kv_manual = LELEM(4),           /* valid when keyingtype=manual */
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
	kt_comment,             /* a value which is a cooked comment */
	kt_obsolete,            /* option that is obsoleted, allow keyword but warn and ignore */
	kt_obsolete_quiet,      /* option that is obsoleted, allow keyword but don't bother warning */
};

#define NOT_ENUM NULL

struct keyword_def {
	const char        *keyname;
	unsigned int validity;          /* has bits kv_config or kv_conn set */
	enum keyword_type type;
	unsigned int field;             /* one of keyword_*_field */
	const struct keyword_enum_values *validenum;
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
	char        *string;
	double decimal;
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

extern const struct keyword_def ipsec_conf_keywords_v2[];

extern unsigned int parser_enum_list(const struct keyword_def *kd, const char *s,
				     bool list);
extern unsigned int parser_loose_enum(struct keyword *k, const char *s);

#endif /* _KEYWORDS_H_ */
