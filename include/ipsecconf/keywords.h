/* FreeS/WAN config file parser (parser.h)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
 * RCSID $Id: keywords.h,v 1.16 2004/12/02 16:26:02 ken Exp $
 */

#ifndef _KEYWORDS_H_
#define _KEYWORDS_H_

#ifndef _OPENSWAN_H
#include "openswan.h"
#include "constants.h"
#endif


/*
 * these are global configuration parameters, and appear in
 * "config setup" stanza, and as non-left/right items in
 * the "conn foo" stanzas
 */
enum keyword_string_config_field {
    KSF_DPDACTION    = 0,  /* loose_enum evantually */
    KSF_INTERFACES,
    KSF_PREPLUTO,
    KSF_POSTPLUTO,
    /* KSF_PACKETDEFAULT = 5, */
    KSF_VIRTUALPRIVATE,
    KSF_SYSLOG,
    KSF_DUMPDIR,
    KSF_MANUALSTART,
    KSF_PLUTOLOAD,
    KSF_PLUTOSTART,
    KSF_MYID,
    KSF_PLUTO,
    KSF_PLUTOOPTS,
    KSF_PLUTOSTDERRLOG,
    KSF_PROTOSTACK,
    KSF_IKE,
    KSF_ESP,
    KSF_ALSO,
    KSF_ALSOFLIP,
    KSF_MAX
};

/* Numeric fields also include boolean fields */
/* and do not come in right/left variants */
enum keyword_numeric_config_field {
    KBF_DPDACTION        = 0,
    KBF_FAILURESHUNT = 1,
    KBF_TYPE         = 2,
    KBF_FRAGICMP,
    KBF_HIDETOS,
    KBF_UNIQUEIDS,
    KBF_PLUTOWAIT,
    KBF_FORWARDCONTROL,
    KBF_OVERRIDEMTU,
    KBF_STRICTCRLPOLICY,
    KBF_NOCRSEND,
    KBF_NATTRAVERSAL,
    KBF_KEEPALIVE,
    KBF_PLUTORESTARTONCRASH,
    KBF_RPFILTER,
    KBF_CRLCHECKINTERVAL,
    KBF_KLIPSDEBUG,
    KBF_PLUTODEBUG,
    KBF_NHELPERS,
    KBF_OPPOENCRYPT,
    KBF_DPDDELAY,
    KBF_DPDTIMEOUT,
    KBF_PHASE2,
    KBF_AUTHBY,
    KBF_KEYEXCHANGE,
    KBF_AUTO,
    KBF_PFS,
    KBF_SALIFETIME,
    KBF_REKEY,
    KBF_REKEYMARGIN,
    KBF_REKEYFUZZ,
    KBF_COMPRESS,
    KBF_KEYINGTRIES,
    KBF_ARRIVALCHECK,
    KBF_IKELIFETIME,
    KBF_AGGRMODE,
    KBF_MODECONFIGPULL,
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
    KSCF_MAX          = 16
};


enum keyword_numeric_conn_field {
    KNCF_IP               = 0,  /* loose_enum */
    KNCF_FIREWALL         = 1,
    KNCF_NEXTHOP          = 2,  /* loose_enum */
    KNCF_IDTYPE           = 3,
    KNCF_SPIBASE          = 4,
    KNCF_RSAKEY1          = 5,  /* loose_enum */
    KNCF_RSAKEY2          = 6,  /* loose_enum */
    KNCF_XAUTHSERVER      = 7,
    KNCF_XAUTHCLIENT      = 8,
    KNCF_MODECONFIGSERVER = 9,
    KNCF_MODECONFIGCLIENT = 10,
    KNCF_SPI,
    KNCF_ESPREPLAYWINDOW,
    KNCF_MAX              
};

#define KEY_STRINGS_MAX (KSF_MAX > KSCF_MAX ? KSF_MAX : KSCF_MAX)+1
#define KEY_NUMERIC_MAX (KBF_MAX > KNCF_MAX ? KBF_MAX : KNCF_MAX)+1

/* these are bits set in a word */
enum keyword_valid {
    kv_config = LELEM(0),
    kv_conn   = LELEM(1),
    kv_leftright = LELEM(2),
    kv_auto   = LELEM(3),
    kv_manual = LELEM(4),
    kv_alias  = LELEM(5),
    kv_policy = LELEM(6),     /* is a policy affecting verb, processed specially */
    kv_processed = LELEM(7),  /* is processed, do not output literal string */
};

/* values keyexchange= */
enum keyword_keyexchange {
    KE_NONE = 0,
    KH_IKE  = 1,
};

/* values for auto={add,start,route,ignore} */
enum keyword_auto {
    STARTUP_NO      = 0,
    STARTUP_POLICY  = 1,
    STARTUP_ADD     = 2,
    STARTUP_ROUTE   = 3,
    STARTUP_START   = 4
};

enum keyword_satype {
    KS_TUNNEL    = 0,
    KS_TRANSPORT = 1,
    KS_UDPENCAP  = 2,
    KS_PASSTHROUGH=3,
    KS_DROP      = 4,
    KS_REJECT    = 5,
};

enum keyword_type {
    kt_string,             /* value is some string */
    kt_appendstring,       /* value is some string, append duplicates */
    kt_filename,           /* value is a filename string */
    kt_dirname,            /* value is a dir name string */
    kt_bool,               /* value is an on/off type */
    kt_invertbool,         /* value is an off/on type ("disable") */
    kt_enum,               /* value is from a set of key words */
    kt_list,               /* a set of values from a set of key words */
    kt_loose_enum,         /* either a string, or a %-prefixed enum */
    kt_rsakey,             /* a key, or set of values */
    kt_number,             /* an integer */
    kt_time,               /* a number representing time */
    kt_percent,            /* a number representing percentage */
    kt_ipaddr,             /* an IP address */
    kt_subnet,             /* an IP address subnet */
    kt_idtype,             /* an ID type */
    kt_bitstring,          /* an encryption/authentication key */
};

#define NOT_ENUM NULL

struct keyword_def {
    const char        *keyname;
    unsigned int       validity;       /* has bits kv_config or kv_conn set */
    enum keyword_type  type;
    unsigned int       field;          /* one of keyword_*_field */
    struct keyword_enum_values *validenum;
};

struct keyword {
    struct keyword_def *keydef;
    bool                keyleft;
    char               *string;
};

struct kw_list {
    struct kw_list *next;
    struct keyword  keyword;
    char        *string;
    double       decimal;
    unsigned int number;
};

struct section_list {
    TAILQ_ENTRY(section_list) link;

    char *name;    
    struct kw_list *kw;
    bool  beenhere;
};

struct config_parsed {
    struct kw_list *config_setup;

    TAILQ_HEAD(sectionhead, section_list) sections;
    int ipsec_conf_version;

    struct section_list conn_default;
    bool                got_default;
};

extern struct keyword_def ipsec_conf_keywords_v2[];
extern const int ipsec_conf_keywords_v2_count;

extern unsigned int parser_enum_list(struct keyword_def *kd, const char *s, bool list);
extern unsigned int parser_loose_enum(struct keyword *k, const char *s);


#endif /* _KEYWORDS_H_ */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
