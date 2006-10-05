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
 * "config setup" stanza.
 */
enum keyword_string_config_field {
    KSF_INTERFACES = 0,
    KSF_PREPLUTO   = 3,
    KSF_POSTPLUTO  = 4,
    /* KSF_PACKETDEFAULT = 5, */
    KSF_VIRTUALPRIVATE= 6, 
    KSF_SYSLOG     = 7,
    KSF_DUMPDIR    = 8,
    KSF_MANUALSTART= 9,
    KSF_PLUTOLOAD  = 10,
    KSF_PLUTOSTART = 11,
    KSF_MYID       = 13,
    KSF_PLUTO      = 14,
    KSF_PLUTOOPTS  = 15,
    KSF_PLUTOSTDERRLOG=16,
    KSF_PROTOSTACK  =17,
    KSF_MAX        = 19
};

/* Numeric fields also include boolean fields */
/* and do not come in right/left variants */
enum keyword_numeric_config_field {
    KBF_FRAGICMP = 0,
    KBF_HIDETOS  = 1,
    KBF_UNIQUEIDS= 2,
    KBF_PLUTOWAIT= 3,
    KBF_FORWARDCONTROL = 5,
    KBF_OVERRIDEMTU = 6,
    KBF_STRICTCRLPOLICY = 7,
    KBF_NOCRSEND    = 8,
    KBF_NATTRAVERSAL = 9,
    KBF_KEEPALIVE    = 10,
    KBF_PLUTORESTARTONCRASH = 11,
    KBF_RPFILTER     = 12,
    KBF_CRLCHECKINTERVAL = 13,
    KBF_TYPE       = 14,
    KBF_KEYEXCHANGE= 16,
    KBF_AUTO       = 17,
    KBF_PFS        = 18,
    KBF_SALIFETIME = 19,
    KBF_REKEY      = 20,
    KBF_REKEYMARGIN= 21,
    KBF_REKEYFUZZ  = 22,
    KBF_COMPRESS   = 23,
    KBF_KEYINGTRIES  = 24,
    KBF_ARRIVALCHECK = 25,
    KBF_FAILURESHUNT = 26,
    KBF_IKELIFETIME  = 27,
    KBF_KLIPSDEBUG   = 28,
    KBF_PLUTODEBUG   = 29,
    KBF_NHELPERS     = 30,
    KBF_OPPOENCRYPT  = 31,
    KBF_AGGRMODE         = 32,
    KBF_XAUTHSERVER      = 33,
    KBF_XAUTHCLIENT      = 34,
    KBF_MODECONFIGSERVER = 35,
    KBF_MODECONFIGCLIENT = 36,
    KBF_MODECONFIGPULL   = 37,

    KBF_MAX          = 38
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
    KSCF_IKE          = 11,
    KSCF_ESP          = 12,
    KSCF_ESPENCKEY    = 13,
    KSCF_ESPAUTHKEY   = 14,
    KSCF_DPDACTION    = 15,
    KSCF_SOURCEIP     = 16,
    KSCF_ALSO         = 17,
    KSCF_ALSOFLIP     = 18,                     /* XXX still to handle */
    KSCF_MAX          = 19
};


enum keyword_numeric_conn_field {
    KNCF_IP               = 0,  /* loose_enum */
    KNCF_FIREWALL         = 1,
    KNCF_NEXTHOP          = 2,  /* loose_enum */
    KNCF_IDTYPE           = 3,
    KNCF_SPIBASE          = 4,
    KNCF_RSAKEY1          = 5,  /* loose_enum */
    KNCF_RSAKEY2          = 6,  /* loose_enum */
    KNCF_SPI              = 7,
    KNCF_ESPREPLAYWINDOW  = 8,
    KNCF_DPDDELAY         = 9,
    KNCF_DPDTIMEOUT       = 10,
    KNCF_DPDACTION        = 11,
    KNCF_PHASE2           = 12,
    KNCF_AUTHBY           = 13,
    KNCF_MAX              = 19
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
    kv_policy = LELEM(6),
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
