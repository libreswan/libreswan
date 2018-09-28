/* manifest constants
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2016-2018, Andrew Cagney
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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

#include "lset.h"

# ifndef DEFAULT_DNSSEC_ROOTKEY_FILE
#  define DEFAULT_DNSSEC_ROOTKEY_FILE "<unused>"
# endif

/*
 * IETF has no recommendations
 * FIPS SP800-77 sayas IKE max is 24h, IPsec max is 8h
 * We say maximum for either is 1d
 */
#define IKE_SA_LIFETIME_DEFAULT secs_per_hour
#define IKE_SA_LIFETIME_MAXIMUM secs_per_day
#define IPSEC_SA_LIFETIME_DEFAULT secs_per_hour * 8
#define IPSEC_SA_LIFETIME_MAXIMUM secs_per_day
#define FIPS_IPSEC_SA_LIFETIME_MAXIMUM secs_per_hour * 8
#define FIPS_MIN_RSA_KEY_SIZE 3072

#define PLUTO_SHUNT_LIFE_DURATION_DEFAULT (15 * secs_per_minute)
#define PLUTO_HALFOPEN_SA_LIFE (secs_per_minute )

#define SA_REPLACEMENT_MARGIN_DEFAULT (9 * secs_per_minute) /* IPSEC & IKE */
#define SA_REPLACEMENT_FUZZ_DEFAULT 100 /* (IPSEC & IKE) 100% of MARGIN */
#define SA_REPLACEMENT_RETRIES_DEFAULT 0 /* (IPSEC & IKE) */

#define SA_LIFE_DURATION_K_DEFAULT 0xFFFFFFFFlu

#define IKE_BUF_AUTO 0 /* use system values for IKE socket buffer size */

enum kernel_interface {
	NO_KERNEL = 1,
	USE_KLIPS = 2,
	USE_NETKEY= 3,
	USE_WIN2K = 4,
	USE_MASTKLIPS = 5,
	USE_BSDKAME = 6,
};

/* RFC 3706 Dead Peer Detection */
enum dpd_action {
	DPD_ACTION_DISABLED,	/* happens for type=passthrough */
	DPD_ACTION_CLEAR,
	DPD_ACTION_HOLD,
	DPD_ACTION_RESTART
};

enum send_ca_policy {
	CA_SEND_NONE = 0,
	CA_SEND_ISSUER = 1,
	CA_SEND_ALL = 2,
};

/* Cisco interop: values remote_peer_type= */
enum keyword_remotepeertype {
	NON_CISCO = 0,
	CISCO = 1,
};

/* keep in sync with ikev2_asym_auth_names */
enum keyword_authby {
	AUTH_UNSET	= 0,
	AUTH_NEVER	= 1,
	AUTH_PSK	= 2,
	AUTH_RSASIG	= 3,
	AUTH_ECDSA      = 4,
	AUTH_NULL	= 5,
};

enum keyword_xauthby {
	XAUTHBY_FILE = 0,
	XAUTHBY_PAM = 1,
	XAUTHBY_ALWAYSOK = 2,
};

enum keyword_xauthfail {
	XAUTHFAIL_HARD = 0,
	XAUTHFAIL_SOFT = 1,
};

/* OCSP related constants - defaults picked from NSS defaults */
#define OCSP_DEFAULT_CACHE_SIZE 1000
#define OCSP_DEFAULT_CACHE_MIN_AGE 3600
#define OCSP_DEFAULT_CACHE_MAX_AGE 24 * 3600
#define OCSP_DEFAULT_TIMEOUT 2

enum keyword_ocsp_method {
	OCSP_METHOD_GET = 0, /* really GET plus POST - see NSS code */
	OCSP_METHOD_POST = 1, /* only POST */
};

/* corresponding name table is sd_action_names */
enum sd_actions {
	PLUTO_SD_EXIT = 1,
	PLUTO_SD_START = 2,
	PLUTO_SD_WATCHDOG = 3,
	PLUTO_SD_RELOADING = 4,
	PLUTO_SD_READY = 5,
	PLUTO_SD_STOPPING = 6,
};

/*
 * NAT-Traversal defines for nat_traveral type from nat_traversal.h
 *
 * Elements for a set.
 * The first members are used to specify the type of NAT Traversal.
 * The second part says which ends are doing NAT.
 * ??? perhaps these ought to be partitioned into separate sets.
 */
enum natt_method {
	NAT_TRAVERSAL_METHOD_none,	/* unknown or unspecified */
	NAT_TRAVERSAL_METHOD_IETF_02_03,
	NAT_TRAVERSAL_METHOD_IETF_05,	/* same as RFC */
	NAT_TRAVERSAL_METHOD_IETF_RFC,

	NATED_HOST,	/* we are behind NAT */
	NATED_PEER	/* peer is behind NAT */
};

/* Timer events */

enum event_type {
	EVENT_NULL,			/* non-event */

	/* events not associated with states */

	EVENT_REINIT_SECRET,		/* Refresh cookie secret */
	EVENT_SHUNT_SCAN,		/* scan shunt eroutes known to kernel */
	EVENT_PENDING_DDNS,		/* try to start connections where DNS failed at init */
	EVENT_SD_WATCHDOG,		/* update systemd's watchdog interval */
	EVENT_PENDING_PHASE2,		/* do not make pending phase2 wait forever */
	EVENT_CHECK_CRLS,		/* check/update CRLS */

	/* events associated with states */

	EVENT_SO_DISCARD,		/* v1/v2 discard unfinished state object */
	EVENT_v1_RETRANSMIT,		/* v1 Retransmit IKE packet */
	EVENT_v1_SEND_XAUTH,		/* v1 send xauth request */
	EVENT_SA_REPLACE,		/* v1/v2 SA replacement event */
	EVENT_SA_REPLACE_IF_USED,	/* v1 SA replacement event */
	EVENT_v2_SA_REPLACE_IF_USED_IKE, /* v2 IKE SA, replace if IPsec SA is in use */
	EVENT_v2_SA_REPLACE_IF_USED,    /* v2 IPSEC SA, replace if used */
	EVENT_SA_EXPIRE,		/* v1/v2 SA expiration event */
	EVENT_NAT_T_KEEPALIVE,		/* NAT Traversal Keepalive */
	EVENT_DPD,			/* v1 dead peer detection */
	EVENT_DPD_TIMEOUT,		/* v1 dead peer detection timeout */
	EVENT_CRYPTO_TIMEOUT,		/* v1/v2 after some time, give up on crypto helper */
	EVENT_PAM_TIMEOUT,		/* v1/v2 give up on PAM helper */

	EVENT_v2_RETRANSMIT,		/* v2 Initiator: Retransmit IKE packet */
	EVENT_v2_RESPONDER_TIMEOUT,	/* v2 Responder: give up on IKE Initiator */
	EVENT_v2_LIVENESS,		/* for dead peer detection */
	EVENT_v2_RELEASE_WHACK,		/* release the whack fd */
	EVENT_v2_INITIATE_CHILD,	/* initiate a IPsec child */
	EVENT_v2_SEND_NEXT_IKE,		/* send next IKE message using parent */
	EVENT_v2_ADDR_CHANGE,		/* process IP address deletion */
	EVENT_RETAIN,			/* don't change the previous event */
};

#define EVENT_REINIT_SECRET_DELAY	secs_per_hour
#define EVENT_GIVEUP_ON_DNS_DELAY	(5 * secs_per_minute)
#define EVENT_RELEASE_WHACK_DELAY	10	/* seconds */

#define RTM_NEWADDR_ROUTE_DELAY		3 /* seconds */

#define PARENT_MIN_LIFE			1 /* second */
#define EXPIRE_OLD_SA			1 /* second */
#define REPLACE_ORPHAN			1 /* second */

/*
 * an arbitrary milliseconds delay for responder. A workaround for iOS, iPhone.
 * If xauth message arrive before main mode response iPhone may abort.
 */
#define EVENT_v1_SEND_XAUTH_DELAY_MS	80 /* milliseconds */

#define RETRANSMIT_TIMEOUT_DEFAULT	60  /* seconds */
#ifndef RETRANSMIT_INTERVAL_DEFAULT_MS
# define RETRANSMIT_INTERVAL_DEFAULT_MS	500 /* wait time doubled each retransmit - in milliseconds */
#endif
#define DELETE_SA_DELAY			RETRANSMIT_TIMEOUT_DEFAULT /* wait until the other side giveup on us */
#define EVENT_CRYPTO_TIMEOUT_DELAY	RETRANSMIT_TIMEOUT_DEFAULT /* wait till the other side give up on us */
#define EVENT_PAM_TIMEOUT_DELAY		RETRANSMIT_TIMEOUT_DEFAULT /* wait until this side give up on PAM */

/* is pluto automatically switching busy state or set manually */
enum ddos_mode {
	DDOS_undefined,
	DDOS_AUTO,
	DDOS_FORCE_BUSY,
	DDOS_FORCE_UNLIMITED
};

/*
 * seccomp mode
 * on syscall violation, enabled kills pluto, tolerant ignores syscall
 */
enum seccomp_mode {
	SECCOMP_undefined,
	SECCOMP_ENABLED,
	SECCOMP_TOLERANT,
	SECCOMP_DISABLED
};

/*
 * status for state-transition-function
 *
 * Note: STF_FAIL + <notification> (<notification> is either
 * notification_t or v2_notification_t) means fail with that
 * notification.  Since <notification> is a uint16_t, it is limited to
 * 65535 possible values (0 isn't valid).
 */

typedef enum {
	STF_IGNORE,             /* don't respond */
	STF_SUSPEND,            /* unfinished -- don't release resources */
	STF_OK,                 /* success */
	STF_INTERNAL_ERROR,     /* discard everything, we failed */
	STF_FATAL,              /* just stop. we can't continue. */
	STF_DROP,               /* just stop, delete any state, and don't log or respond */
	STF_FAIL,               /* discard everything, something failed.  notification_t added.
				 * values STF_FAIL + x are notifications.
				 */
	STF_ROOF = STF_FAIL + 65536 /* see RFC and above */
} stf_status;

/* Misc. stuff */

#define MAXIMUM_v1_ACCEPTED_DUPLICATES        2
/*
 * maximum retransmits per exchange, for IKEv1 (initiator and responder),
 * IKEv2 initiator
 */
#define MAXIMUM_RETRANSMITS_PER_EXCHANGE     12

#define MAXIMUM_RESPONDER_WAIT		   200 /* seconds before responder giveup */
#define MAXIMUM_INVALID_KE_RETRANS 3

#define MAXIMUM_MALFORMED_NOTIFY             16

#define MAX_INPUT_UDP_SIZE             65536
#define MIN_OUTPUT_UDP_SIZE		1024
#define MAX_OUTPUT_UDP_SIZE            65536

#define MAX_IKE_FRAGMENTS       16

#define KERNEL_PROCESS_Q_PERIOD 1 /* seconds */
#define DEFAULT_MAXIMUM_HALFOPEN_IKE_SA 50000 /* fairly arbitrary */
#define DEFAULT_IKE_SA_DDOS_THRESHOLD 25000 /* fairly arbitrary */

#define IPSEC_SA_DEFAULT_REPLAY_WINDOW 32

#define IKE_V2_OVERLAPPING_WINDOW_SIZE	1 /* our default for rfc 7296 # 2.3 */

#define PPK_ID_MAXLEN 64 /* fairly arbitrary */

/*
 * debugging settings: a set of selections for reporting These would
 * be more naturally situated in log.h, but they are shared with
 * whack.
 *
 * IMPAIR_* actually change behaviour, usually badly, to aid in
 * testing.  Naturally, these are not included in ALL.
 *
 * NOTE: A change to WHACK_MAGIC in whack.h will be required too.
 */

/*
 * Index of DBG set elements.
 *
 * Note: these are NOT sets: use LELEM to turn these into singletons.
 * Used by whack and pluto.
 *
 * NOTE: when updating/adding x_IX, do so to x in the next table too!
 */

enum {
	DBG_floor_IX = 0,

	DBG_RAW_IX = DBG_floor_IX,
	DBG_PARSING_IX,
	DBG_EMITTING_IX,
	DBG_CONTROL_IX,
	DBG_LIFECYCLE_IX,
	DBG_KERNEL_IX,
	DBG_DNS_IX,
	DBG_OPPO_IX,
	DBG_CONTROLMORE_IX,

	DBG_NATT_IX,
	DBG_X509_IX,
	DBG_DPD_IX,
	DBG_XAUTH_IX,
	DBG_RETRANSMITS_IX,
	DBG_OPPOINFO_IX,

	/* below are excluded from debug=all */
	DBG_CRYPT_IX,
	DBG_CRYPT_LOW_IX,
	DBG_PRIVATE_IX,
	DBG_PROPOSAL_PARSER_IX,

	DBG_WHACKWATCH_IX,
	DBG_ADD_PREFIX_IX,

	DBG_roof_IX,		/* first unassigned DBG is assigned to IMPAIR! */
};

/* Sets of Debug items */

#define DBG_MASK	LRANGE(DBG_floor_IX, DBG_roof_IX - 1)
#define DBG_NONE        0                                       /* no options on, including impairments */
#define DBG_ALL         LRANGES(DBG_RAW, DBG_OPPOINFO)          /* all but some exceptions (see below) */

/* singleton sets: must be kept in sync with the items! */

#define DBG_RAW		LELEM(DBG_RAW_IX)
#define DBG_PARSING	LELEM(DBG_PARSING_IX)
#define DBG_EMITTING	LELEM(DBG_EMITTING_IX)
#define DBG_CONTROL	LELEM(DBG_CONTROL_IX)
#define DBG_LIFECYCLE	LELEM(DBG_LIFECYCLE_IX)
#define DBG_KERNEL	LELEM(DBG_KERNEL_IX)
#define DBG_DNS		LELEM(DBG_DNS_IX)
#define DBG_OPPO	LELEM(DBG_OPPO_IX)
#define DBG_CONTROLMORE	LELEM(DBG_CONTROLMORE_IX)
#define DBG_NATT	LELEM(DBG_NATT_IX)
#define DBG_X509	LELEM(DBG_X509_IX)
#define DBG_DPD		LELEM(DBG_DPD_IX)
#define DBG_XAUTH	LELEM(DBG_XAUTH_IX)
#define DBG_RETRANSMITS	LELEM(DBG_RETRANSMITS_IX)
#define DBG_OPPOINFO	LELEM(DBG_OPPOINFO_IX)

/* These are not part of "all" debugging */
#define DBG_CRYPT	LELEM(DBG_CRYPT_IX)
#define DBG_CRYPT_LOW	LELEM(DBG_CRYPT_LOW_IX)
#define DBG_PRIVATE	LELEM(DBG_PRIVATE_IX)
#define DBG_PROPOSAL_PARSER	LELEM(DBG_PROPOSAL_PARSER_IX)

#define DBG_WHACKWATCH	LELEM(DBG_WHACKWATCH_IX)
#define DBG_ADD_PREFIX	LELEM(DBG_ADD_PREFIX_IX)

/*
 * Index of IMPAIR set elements.
 *
 * see impair.c (libswan) for a definition of each of these fields.
 *
 * XXX: For now, these share the same lset_t as the DBG elements
 * above.
 */

enum {
	IMPAIR_floor_IX = DBG_roof_IX,

	IMPAIR_BUST_MI2_IX = IMPAIR_floor_IX,
	IMPAIR_BUST_MR2_IX,
	IMPAIR_DROP_I2_IX,
	IMPAIR_SA_CREATION_IX,
	IMPAIR_JACOB_TWO_TWO_IX,

	IMPAIR_ALLOW_NULL_NONE_IX,
	IMPAIR_MAJOR_VERSION_BUMP_IX,
	IMPAIR_MINOR_VERSION_BUMP_IX,

	IMPAIR_TIMEOUT_ON_RETRANSMIT_IX,
	IMPAIR_DELETE_ON_RETRANSMIT_IX,
	IMPAIR_SUPPRESS_RETRANSMITS_IX,

	IMPAIR_SEND_BOGUS_PAYLOAD_FLAG_IX,
	IMPAIR_SEND_BOGUS_ISAKMP_FLAG_IX,

	IMPAIR_SEND_NO_DELETE_IX,
	IMPAIR_SEND_NO_IKEV2_AUTH_IX,
	IMPAIR_SEND_NO_XAUTH_R0_IX,
	IMPAIR_DROP_XAUTH_R0_IX,
	IMPAIR_SEND_NO_MAIN_R2_IX,
	IMPAIR_FORCE_FIPS_IX,
	IMPAIR_SEND_KEY_SIZE_CHECK_IX,
	IMPAIR_SEND_BOGUS_DCOOKIE_IX,
	IMPAIR_OMIT_HASH_NOTIFY_REQUEST_IX,
	IMPAIR_IGNORE_HASH_NOTIFY_REQUEST_IX,
	IMPAIR_IGNORE_HASH_NOTIFY_RESPONSE_IX,
	IMPAIR_IKEv2_EXCLUDE_INTEG_NONE_IX,
	IMPAIR_IKEv2_INCLUDE_INTEG_NONE_IX,

	IMPAIR_REPLAY_DUPLICATES_IX,
	IMPAIR_REPLAY_FORWARD_IX,
	IMPAIR_REPLAY_BACKWARD_IX,

	IMPAIR_REPLAY_ENCRYPTED_IX,
	IMPAIR_CORRUPT_ENCRYPTED_IX,

	IMPAIR_PROPOSAL_PARSER_IX,

	IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_SA_INIT_IX,
	IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH_IX,
	IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK_IX,
	IMPAIR_UNKNOWN_PAYLOAD_CRITICAL_IX,

	IMPAIR_ALLOW_DNS_INSECURE_IX,

	IMPAIR_SEND_PKCS7_THINGIE_IX,

	IMPAIR_roof_IX	/* first unassigned IMPAIR */
};

/* Sets of Impair items */

#define IMPAIR_MASK	LRANGE(IMPAIR_floor_IX, IMPAIR_roof_IX - 1)

/* singleton sets: must be kept in sync with the items! */

#define IMPAIR_BUST_MI2	LELEM(IMPAIR_BUST_MI2_IX)
#define IMPAIR_BUST_MR2	LELEM(IMPAIR_BUST_MR2_IX)
#define IMPAIR_DROP_I2	LELEM(IMPAIR_DROP_I2_IX)
#define IMPAIR_SA_CREATION	LELEM(IMPAIR_SA_CREATION_IX)
#define IMPAIR_JACOB_TWO_TWO	LELEM(IMPAIR_JACOB_TWO_TWO_IX)
#define IMPAIR_ALLOW_NULL_NONE		LELEM(IMPAIR_ALLOW_NULL_NONE_IX)
#define IMPAIR_MAJOR_VERSION_BUMP	LELEM(IMPAIR_MAJOR_VERSION_BUMP_IX)
#define IMPAIR_MINOR_VERSION_BUMP	LELEM(IMPAIR_MINOR_VERSION_BUMP_IX)

#define IMPAIR_TIMEOUT_ON_RETRANSMIT	LELEM(IMPAIR_TIMEOUT_ON_RETRANSMIT_IX)
#define IMPAIR_DELETE_ON_RETRANSMIT	LELEM(IMPAIR_DELETE_ON_RETRANSMIT_IX)
#define IMPAIR_SUPPRESS_RETRANSMITS	LELEM(IMPAIR_SUPPRESS_RETRANSMITS_IX)

#define IMPAIR_SEND_BOGUS_PAYLOAD_FLAG	LELEM(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG_IX)
#define IMPAIR_SEND_BOGUS_ISAKMP_FLAG	LELEM(IMPAIR_SEND_BOGUS_ISAKMP_FLAG_IX)

#define IMPAIR_SEND_NO_DELETE	LELEM(IMPAIR_SEND_NO_DELETE_IX)
#define IMPAIR_SEND_NO_IKEV2_AUTH	LELEM(IMPAIR_SEND_NO_IKEV2_AUTH_IX)
#define IMPAIR_SEND_NO_XAUTH_R0	LELEM(IMPAIR_SEND_NO_XAUTH_R0_IX)
#define IMPAIR_DROP_XAUTH_R0	LELEM(IMPAIR_DROP_XAUTH_R0_IX)
#define IMPAIR_SEND_NO_MAIN_R2	LELEM(IMPAIR_SEND_NO_MAIN_R2_IX)
#define IMPAIR_FORCE_FIPS	LELEM(IMPAIR_FORCE_FIPS_IX)
#define IMPAIR_SEND_KEY_SIZE_CHECK	LELEM(IMPAIR_SEND_KEY_SIZE_CHECK_IX)
#define IMPAIR_SEND_BOGUS_DCOOKIE	LELEM(IMPAIR_SEND_BOGUS_DCOOKIE_IX)
#define IMPAIR_OMIT_HASH_NOTIFY_REQUEST		LELEM(IMPAIR_OMIT_HASH_NOTIFY_REQUEST_IX)
#define IMPAIR_IGNORE_HASH_NOTIFY_REQUEST	LELEM(IMPAIR_IGNORE_HASH_NOTIFY_REQUEST_IX)
#define IMPAIR_IGNORE_HASH_NOTIFY_RESPONSE	LELEM(IMPAIR_IGNORE_HASH_NOTIFY_RESPONSE_IX)
#define IMPAIR_IKEv2_EXCLUDE_INTEG_NONE LELEM(IMPAIR_IKEv2_EXCLUDE_INTEG_NONE_IX)
#define IMPAIR_IKEv2_INCLUDE_INTEG_NONE LELEM(IMPAIR_IKEv2_INCLUDE_INTEG_NONE_IX)

#define IMPAIR_REPLAY_DUPLICATES 	LELEM(IMPAIR_REPLAY_DUPLICATES_IX)
#define IMPAIR_REPLAY_FORWARD	 	LELEM(IMPAIR_REPLAY_FORWARD_IX)
#define IMPAIR_REPLAY_BACKWARD 		LELEM(IMPAIR_REPLAY_BACKWARD_IX)

#define IMPAIR_REPLAY_ENCRYPTED			LELEM(IMPAIR_REPLAY_ENCRYPTED_IX)
#define IMPAIR_CORRUPT_ENCRYPTED		LELEM(IMPAIR_CORRUPT_ENCRYPTED_IX)

#define IMPAIR_PROPOSAL_PARSER 			LELEM(IMPAIR_PROPOSAL_PARSER_IX)

#define IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_SA_INIT	LELEM(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_SA_INIT_IX)
#define IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH	LELEM(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH_IX)
#define IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK	LELEM(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK_IX)
#define IMPAIR_UNKNOWN_PAYLOAD_CRITICAL		LELEM(IMPAIR_UNKNOWN_PAYLOAD_CRITICAL_IX)

#define IMPAIR_ALLOW_DNS_INSECURE		LELEM(IMPAIR_ALLOW_DNS_INSECURE_IX)

#define IMPAIR_SEND_PKCS7_THINGIE		LELEM(IMPAIR_SEND_PKCS7_THINGIE_IX)

/* State of exchanges
 *
 * The name of the state describes the last message sent, not the
 * message currently being input or output (except during retry).
 * In effect, the state represents the last completed action.
 * All routines are about transitioning to the next state
 * (which might actually be the same state).
 *
 * IKE V1 messages are sometimes called [MAQ][IR]n where
 * - M stands for Main Mode (Phase 1);
 *   A stands for Aggressive Mode (Phase 1);
 *   Q stands for Quick Mode (Phase 2)
 * - I stands for Initiator;
 *   R stands for Responder
 * - n, a digit, stands for the number of the message from this role
 *   within this exchange
 *
 * It would be more convenient if each state accepted a message
 * and produced one.  This is not the case for states at the start
 * or end of an exchange.  To fix this, we pretend that there are
 * MR0 and QR0 messages before the MI1 and QR1 messages.
 *
 * STATE_MAIN_R0 and STATE_QUICK_R0 are ephemeral states (not
 * retained between messages) representing the state that accepts the
 * first message of an exchange that has been read but not yet processed
 * and accepted.
 *
 * v1_state_microcode_table in ikev1.c and
 * v2_state_microcode_table in ikev2.c describe
 * other important details.
 */

enum state_kind {
	STATE_UNDEFINED,

	/* Hack so state numbers don't change */

	STATE_UNUSED_1,
	STATE_UNUSED_2,

	/* IKE states */

	STATE_IKEv1_FLOOR,

	STATE_MAIN_R0 = STATE_IKEv1_FLOOR,
	STATE_MAIN_I1,
	STATE_MAIN_R1,
	STATE_MAIN_I2,
	STATE_MAIN_R2,
	STATE_MAIN_I3,
	STATE_MAIN_R3,
	STATE_MAIN_I4,

	STATE_AGGR_R0,
	STATE_AGGR_I1,
	STATE_AGGR_R1,
	STATE_AGGR_I2,
	STATE_AGGR_R2,

	STATE_QUICK_R0,
	STATE_QUICK_I1,
	STATE_QUICK_R1,
	STATE_QUICK_I2,
	STATE_QUICK_R2,

	STATE_INFO,
	STATE_INFO_PROTECTED,

	/* Xauth states */
	STATE_XAUTH_R0,         /* server state has sent request, awaiting reply */
	STATE_XAUTH_R1,         /* server state has sent success/fail, awaiting reply */
	STATE_MODE_CFG_R0,      /* these states are used on the responder */
	STATE_MODE_CFG_R1,
	STATE_MODE_CFG_R2,

	STATE_MODE_CFG_I1,              /* this is used on the initiator */

	STATE_XAUTH_I0,                 /* client state is awaiting request */
	STATE_XAUTH_I1,                 /* client state is awaiting result code */

	STATE_IKEv1_ROOF,	/* not a state! */

	/*
	 * IKEv2 states.
	 *
	 * Note that message reliably sending is done by initiator
	 * only, unlike with IKEv1.
	 */
	STATE_IKEv2_FLOOR,

	STATE_IKEv2_BASE = STATE_IKEv2_FLOOR,	/* state when faking a state */

	/* INITIATOR states */
	/* STATE_PARENT_I0,	** waiting for KE to finish */
	STATE_PARENT_I1,        /* IKE_SA_INIT: sent initial message, waiting for reply */
	STATE_PARENT_I2,        /* IKE_AUTH: sent auth message, waiting for reply */
	STATE_PARENT_I3,        /* IKE_AUTH done: received auth response */

	/*
	 * RESPONDER states
	 * No real actions, initiator is responsible
	 * for all work states.
	 * ??? what does that mean?
	 */
	/* STATE_PARENT_R0,	** just starting */
	STATE_PARENT_R1,	/* IKE_SA_INIT: sent response */
	STATE_PARENT_R2,	/* IKE_AUTH: sent response */

	/* IKEv2 CREATE_CHILD_SA INITIATOR states */
	STATE_V2_CREATE_I0,     /* ephemeral: sent nothing yet */
	STATE_V2_CREATE_I,      /* sent first message of CREATE_CHILD new IPsec */

	STATE_V2_REKEY_IKE_I0,  /* ephemeral: sent nothing yet */
	STATE_V2_REKEY_IKE_I,   /* sent first message (via parrenti) to rekey parent */
	STATE_V2_REKEY_CHILD_I0,
	STATE_V2_REKEY_CHILD_I, /* sent first message (via parent to rekey child sa. */
	/* IKEv2 CREATE_CHILD_SA Responder states */
	STATE_V2_CREATE_R,     /* ephemeral: sent nothing yet. */
	STATE_V2_REKEY_IKE_R,  /* ephemeral: sent nothing yet terminal state STATE_PARENT_R2 */
	STATE_V2_REKEY_CHILD_R,

	STATE_V2_IPSEC_I,	/* IPsec SA final state - CREATE_CHILD & AUTH */
	STATE_V2_IPSEC_R,

	/* IKEv2 Delete States */
	STATE_IKESA_DEL,
	STATE_CHILDSA_DEL,

	/*
	 * Because state numbers can't change (whack logs include the
	 * number as part of the message!) add new states here.
	 */
	STATE_PARENT_R0,
	STATE_PARENT_I0,	/* waiting for KE to finish */

	STATE_IKEv2_ROOF	/* not a state! */
};

/* STATE_IKEv2_ROOF lurks in the code so leave space for it */
#define STATE_IKE_ROOF (STATE_IKEv2_ROOF+1)	/* not a state! */

/*
 * The IKEv2 (RFC 7296) original role.  Either the "original
 * initiator" or the "original responder" as identified by the I
 * (Initiator flag).
 *
 * The "original initiator" will set the I (Initiator) flag
 * (ISAKMP_FLAGS_v2_IKE_I) when sending either the initial SA_INIT
 * packet or CREATE_CHILD_SA rekey-ike request.  The original
 * responder will see the I flag set in all packets it receives from
 * the original initiator.
 *
 * The original role is used to identify which SPI (cookie) to use in
 * the header and which keying material to use when encrypting and
 * decrypting SK payloads.
 *
 * The IKEv1 equivalent is the phase1 role.  It is identified by the
 * IKEv1 IS_PHASE1_INIT() macro.
 *
 * The values are chosen such that no role has values that overlap.
 */
enum original_role {
	ORIGINAL_INITIATOR = 1, /* IKE_I present */
	ORIGINAL_RESPONDER = 2, /* IKE_I missing */
};

/*
 * The IKEv2 message role.  Is this message a request or a response
 * (to a request) as determined by the IKEv2 "R (Response)" flag.
 *
 * Since either end can initiate a request either end can set the
 * R(Repsonse) flag.
 *
 * During a CHILD_SA exchange it is the request initiator (receives
 * the MESSAGE_RESPONSE) and request responder (receives the
 * MESSAGE_REQUEST), and not the original (IKE SA) initiator /
 * responder that determine how crypto material is carved up.
 *
 * The values are chosen such that no role has values that overlap.
 */

enum message_role {
	MESSAGE_REQUEST = 3, /* MSG_R missing */
	MESSAGE_RESPONSE = 4, /* MSR_R present */
};

/*
 * The SA role determined by who initiated the SA.
 *
 * For both an IKE and CHILD SA it is determined by who sent the
 * request.
 *
 * The values are chosen such that no role has values that overlap.
 *
 * XXX: If IKEv2 code correctly used CHILD_SA and IKE_SA then
 * ORIGINAL_ROLE, above is probably be redundant - An IKE SA's SA_ROLE
 * should be consistent with its ORIGINAL_ROLE.  Currently code isn't
 * consistent, so both are used/defined.
 */
enum sa_role {
	SA_INITIATOR = 5,
	SA_RESPONDER = 6,
};


#define PHASE1_INITIATOR_STATES  (LELEM(STATE_MAIN_I1) | \
				  LELEM(STATE_MAIN_I2) | \
				  LELEM(STATE_MAIN_I3) | \
				  LELEM(STATE_MAIN_I4) | \
				  LELEM(STATE_AGGR_I1) | \
				  LELEM(STATE_AGGR_I2) | \
				  LELEM(STATE_XAUTH_I0) | \
				  LELEM(STATE_XAUTH_I1) | \
				  LELEM(STATE_MODE_CFG_I1))


#define IS_PHASE1_INIT(s) ((LELEM(s) & PHASE1_INITIATOR_STATES) != LEMPTY)

#define IS_PHASE1(s) (STATE_MAIN_R0 <= (s) && (s) <= STATE_AGGR_R2)

#define IS_PHASE15(s) (STATE_XAUTH_R0 <= (s) && (s) <= STATE_XAUTH_I1)

#define IS_QUICK(s) (STATE_QUICK_R0 <= (s) && (s) <= STATE_QUICK_R2)

#define ISAKMP_ENCRYPTED_STATES  (LRANGE(STATE_MAIN_R2, STATE_MAIN_I4) | \
				  LRANGE(STATE_AGGR_R1, STATE_AGGR_R2) | \
				  LRANGE(STATE_QUICK_R0, STATE_QUICK_R2) | \
				  LELEM(STATE_INFO_PROTECTED) | \
				  LRANGE(STATE_XAUTH_R0, STATE_XAUTH_I1))

#define IS_ISAKMP_ENCRYPTED(s) ((LELEM(s) & ISAKMP_ENCRYPTED_STATES) != LEMPTY)

/* ??? Is this really authenticate?  Even in xauth case? In STATE_INFO case? */
#define IS_ISAKMP_AUTHENTICATED(s) (STATE_MAIN_R3 <= (s) && \
				    STATE_AGGR_R0 != (s) && \
				    STATE_AGGR_I1 != (s))

#define IKEV2_ISAKMP_INITIATOR_STATES (LELEM(STATE_PARENT_I0) |	\
				       LELEM(STATE_PARENT_I1) |	\
				       LELEM(STATE_PARENT_I2))

#define ISAKMP_SA_ESTABLISHED_STATES  (LELEM(STATE_MAIN_R3) | \
				       LELEM(STATE_MAIN_I4) | \
				       LELEM(STATE_AGGR_I2) | \
				       LELEM(STATE_AGGR_R2) | \
				       LELEM(STATE_XAUTH_R0) | \
				       LELEM(STATE_XAUTH_R1) | \
				       LELEM(STATE_MODE_CFG_R0) | \
				       LELEM(STATE_MODE_CFG_R1) | \
				       LELEM(STATE_MODE_CFG_R2) | \
				       LELEM(STATE_MODE_CFG_I1) | \
				       LELEM(STATE_XAUTH_I0) | \
				       LELEM(STATE_XAUTH_I1) | \
				       LELEM(STATE_PARENT_I3) | \
				       LELEM(STATE_PARENT_R2))

#define IS_ISAKMP_SA_ESTABLISHED(s) ((LELEM(s) & ISAKMP_SA_ESTABLISHED_STATES) != LEMPTY)

#define IPSECSA_PENDING_STATES (LELEM(STATE_V2_CREATE_I) | \
				LELEM(STATE_V2_CREATE_I0) | \
				LELEM(STATE_V2_CREATE_R) | \
	/* due to a quirk in initiator duplication next one is also needed */ \
				LELEM(STATE_PARENT_I2))

/* IKEv1 or IKEv2 */
#define IS_IPSEC_SA_ESTABLISHED(s) (IS_CHILD_SA(s) && \
				    ((s->st_state) == STATE_QUICK_I2 || \
				    (s->st_state) == STATE_QUICK_R1 || \
				    (s->st_state) == STATE_QUICK_R2 || \
				    (s->st_state) == STATE_V2_IPSEC_I || \
				    (s->st_state) == STATE_V2_IPSEC_R))

#define IS_MODE_CFG_ESTABLISHED(s) ((s) == STATE_MODE_CFG_R2)

/* Only relevant to IKEv2 */

/* adding for just a R2 or I3 check. Will need to be changed when parent/child discerning is fixed */

#define IS_V2_ESTABLISHED(s) ((s) == STATE_PARENT_R2 || \
		(s) == STATE_PARENT_I3 || (s) == STATE_V2_IPSEC_I || \
		(s) == STATE_V2_IPSEC_R)

#define IS_IKE_SA_ESTABLISHED(st) \
	( IS_ISAKMP_SA_ESTABLISHED(st->st_state) || \
		(IS_PARENT_SA_ESTABLISHED(st) && \
		 (st->st_clonedfrom == SOS_NOBODY)))

/*
 * ??? Issue here is that our child SA appears as a
 * STATE_PARENT_I3/STATE_PARENT_R2 state which it should not.
 * So we fall back to checking if it is cloned, and therefore really a child.
 */
#define IS_CHILD_SA_ESTABLISHED(st) \
    ((st->st_state == STATE_V2_IPSEC_I || st->st_state == STATE_V2_IPSEC_R) && \
      IS_CHILD_SA(st))

#define IS_PARENT_SA_ESTABLISHED(st) \
    (((st)->st_state == STATE_PARENT_I3 || (st)->st_state == STATE_PARENT_R2) && \
    !IS_CHILD_SA(st))

#define IS_CHILD_SA(st)  ((st)->st_clonedfrom != SOS_NOBODY)

#define IS_PARENT_SA(st) (!IS_CHILD_SA(st))

#define IS_IKE_SA(st) ( ((st)->st_clonedfrom == SOS_NOBODY) && \
	(IS_PHASE1((st)->st_state) || IS_PHASE15((st)->st_state) || IS_PARENT_SA(st)) )

#define IS_CHILD_SA_INITIATOR(st) \
	((st)->st_state == STATE_V2_CREATE_I0 || \
	  (st)->st_state == STATE_V2_REKEY_CHILD_I0)

#define IS_IKE_REKEY_INITIATOR(st) \
	((st)->st_state == STATE_V2_REKEY_IKE_I0 || \
	 (st)->st_state == STATE_V2_REKEY_IKE_I)

#define IS_CHILD_SA_RESPONDER(st) \
	((st)->st_state == STATE_V2_REKEY_IKE_R || \
	  (st)->st_state == STATE_V2_CREATE_R || \
	  (st)->st_state == STATE_V2_REKEY_CHILD_R)

#define IS_CHILD_IPSECSA_RESPONSE(st) \
	(IS_CHILD_SA(st) && ((st)->st_state == STATE_V2_REKEY_IKE_I || \
	 (st)->st_state == STATE_V2_CREATE_I || \
	 (st)->st_state == STATE_V2_REKEY_CHILD_I))

/* kind of struct connection
 * Ordered (mostly) by concreteness.  Order is exploited.
 */

enum connection_kind {
	CK_GROUP,       /* policy group: instantiates to template */
	CK_TEMPLATE,    /* abstract connection, with wildcard */
	CK_PERMANENT,   /* normal connection */
	CK_INSTANCE,    /* instance of template, created for a particular attempt */
	CK_GOING_AWAY   /* instance being deleted -- don't delete again */
};

/* routing status.
 * Note: routing ignores source address, but erouting does not!
 * Note: a connection can only be routed if it is NEVER_NEGOTIATE
 * or HAS_IPSEC_POLICY.
 */

/* note that this is assumed to be ordered! */
enum routing_t {
	RT_UNROUTED,            /* unrouted */
	RT_UNROUTED_HOLD,       /* unrouted, but HOLD shunt installed */
	RT_ROUTED_ECLIPSED,     /* RT_ROUTED_PROSPECTIVE except bare HOLD or instance has eroute */
	RT_ROUTED_PROSPECTIVE,  /* routed, and prospective shunt installed */
	RT_ROUTED_HOLD,         /* routed, and HOLD shunt installed */
	RT_ROUTED_FAILURE,      /* routed, and failure-context shunt installed */
	RT_ROUTED_TUNNEL,       /* routed, and erouted to an IPSEC SA group */
	RT_UNROUTED_KEYED,       /* keyed, but not routed, on purpose */
};

#define routed(rs) ((rs) > RT_UNROUTED_HOLD)
#define erouted(rs) ((rs) != RT_UNROUTED)
#define shunt_erouted(rs) (erouted(rs) && (rs) != RT_ROUTED_TUNNEL)

enum certpolicy {
	CERT_NEVERSEND   = 1,
	CERT_SENDIFASKED = 2,   /* the default */
	CERT_ALWAYSSEND  = 3,
};

/* this is the default setting. */
#define cert_defaultcertpolicy CERT_ALWAYSSEND

enum ikev1_natt_policy {
	NATT_BOTH = 0, /* the default */
	NATT_RFC = 1,
	NATT_DRAFTS = 2, /* Workaround for Cisco NAT-T bug */
	NATT_NONE = 3 /* Workaround for forcing non-encaps */
};

enum four_options {
	fo_never   = 0,         /* do not propose, do not permit */
	fo_permit  = 1,         /* do not propose, but permit peer to propose */
	fo_propose = 2,         /* propose, and permit, but do not insist  */
	fo_insist  = 3          /* propose, and only accept if peer agrees */
};

enum ynf_options {
	ynf_no   = 0,
	ynf_yes  = 1,
	ynf_force = 2,
};

enum yna_options {
	yna_auto = 1, /* default */
	yna_no = 2,
	yna_yes = 3,
};

enum esn_options {
	ESN_NO = 1, /* default */
	ESN_YES = 2,
	ESN_EITHER = 3,
};

enum saref_tracking {
	SAT_YES = 0,            /* SAref tracking via _updown - the default */
	SAT_NO = 1,             /* no SAref tracking - third party will handle this */
	SAT_CONNTRACK = 2,      /* Saref tracking using connmark optimizations */
};

/* Policies for establishing an SA
 *
 * These are used to specify attributes (eg. encryption) and techniques
 * (eg PFS) for an SA.
 * Note: certain CD_ definitions in whack.c parallel these -- keep them
 * in sync!
 */

extern const char *prettypolicy(lset_t policy);

/*
 * ISAKMP policy elements.
 *
 * A pluto policy is stored in a lset_t so we could have up to 64 elements.
 * Certain policies are more than present/absent and take more than one bit.
 *
 * We need both the bit number (*_IX) and the singleton set for each.
 * The bit numbers are assigned automatically in enum sa_policy_bits.
 *
 * The singleton set version is potentially too big for an enum
 * so these are exhausively defined as macros.  As are derived values.
 *
 * Changes to sa_policy_bits must be reflected in #defines below it and
 * in sa_policy_bit_names.
 */
enum sa_policy_bits {
	/*
	 * XXX: Do not re-order or re-number the following pair.  Bad
	 * things happen.
	 *
	 * (They are used to index an array in spdb.c when determining
	 * default IKEv1 proposals; arguably the array should be
	 * deleted but that is another story).
	 */
	POLICY_PSK_IX = 0,
	POLICY_RSASIG_IX = 1,
	POLICY_ECDSA_IX = 2,
	POLICY_AUTH_NEVER_IX,
	POLICY_AUTH_NULL_IX,

#define POLICY_ID_AUTH_MASK	LRANGE(POLICY_PSK_IX, POLICY_AUTH_NULL_IX)

	POLICY_ENCRYPT_IX,	/* must be first of IPSEC policies */
	POLICY_AUTHENTICATE_IX,	/* must be second */
	POLICY_COMPRESS_IX,	/* must be third */
	POLICY_TUNNEL_IX,
	POLICY_PFS_IX,
	POLICY_DISABLEARRIVALCHECK_IX,	/* suppress tunnel egress address checking */
	POLICY_DECAP_DSCP_IX,	/* decapsulate ToS/DSCP bits */
	POLICY_NOPMTUDISC_IX,
	POLICY_MSDH_DOWNGRADE_IX, /* allow IKEv2 rekey to downgrade DH group - Microsoft bug */
	POLICY_DNS_MATCH_ID_IX, /* perform reverse DNS lookup on IP to confirm ID */
	POLICY_SHA2_TRUNCBUG_IX, /* workaround old Linux kernel (android 4.x) */

#define POLICY_IPSEC_SHIFT	POLICY_ENCRYPT_IX
#define POLICY_IPSEC_MASK	LRANGE(POLICY_ENCRYPT_IX, POLICY_DISABLEARRIVALCHECK_IX)

	/* shunt attributes: what to do when routed without tunnel (2 bits) */
	POLICY_SHUNT0_IX,
	POLICY_SHUNT1_IX,

#define POLICY_SHUNT_SHIFT	POLICY_SHUNT0_IX
#define POLICY_SHUNT_MASK	LRANGE(POLICY_SHUNT0_IX, POLICY_SHUNT1_IX)

#define POLICY_SHUNT_TRAP	(0 * LELEM(POLICY_SHUNT0_IX))	/* default: negotiate */
#define POLICY_SHUNT_PASS	(1 * LELEM(POLICY_SHUNT0_IX))
#define POLICY_SHUNT_DROP	(2 * LELEM(POLICY_SHUNT0_IX))
#define POLICY_SHUNT_REJECT	(3 * LELEM(POLICY_SHUNT0_IX))

	/* fail attributes: what to do with failed negotiation (2 bits) */
	POLICY_FAIL0_IX,
	POLICY_FAIL1_IX,

#define POLICY_FAIL_SHIFT	POLICY_FAIL0_IX
#define POLICY_FAIL_MASK	LRANGE(POLICY_FAIL0_IX, POLICY_FAIL1_IX)

#define POLICY_FAIL_NONE	(0 * LELEM(POLICY_FAIL0_IX)) /* default */
#define POLICY_FAIL_PASS	(1 * LELEM(POLICY_FAIL0_IX))
#define POLICY_FAIL_DROP	(2 * LELEM(POLICY_FAIL0_IX))
#define POLICY_FAIL_REJECT	(3 * LELEM(POLICY_FAIL0_IX))

	/* connection policy
	 * Other policies could vary per state object.  These live in connection.
	 */
	POLICY_NEGO_PASS_IX,	/* install %pass instead of %hold during initial IKE */
	POLICY_DONT_REKEY_IX,	/* don't rekey state either Phase */
	POLICY_REAUTH_IX,	/* IKEv2 only initiate re-authentication */
	POLICY_OPPORTUNISTIC_IX,	/* is this opportunistic? */
	POLICY_GROUP_IX,	/* is this a group template? */
	POLICY_GROUTED_IX,	/* do we want this group routed? */
	POLICY_GROUPINSTANCE_IX,	/* is this a group template instance? */
	POLICY_UP_IX,	/* do we want this up? */
	POLICY_XAUTH_IX,	/* do we offer XAUTH? */
	POLICY_MODECFG_PULL_IX,	/* is modecfg pulled by client? */
	POLICY_AGGRESSIVE_IX,	/* do we do aggressive mode? */
	POLICY_OVERLAPIP_IX,	/* can two conns that have subnet=vhost: declare the same IP? */

	/*
	 * this is mapped by parser's ikev2={four_state}. It is a bit richer
	 * in that we can actually turn off everything, but it expands more
	 * sensibly to an IKEv3 and other methods.
	 */
	POLICY_IKEV1_ALLOW_IX,	/* !accept IKEv1?  0x0100 0000 */
	POLICY_IKEV2_ALLOW_IX,	/* accept IKEv2?   0x0200 0000 */
	POLICY_IKEV2_PROPOSE_IX,	/* propose IKEv2?  0x0400 0000 */
#define POLICY_IKEV2_MASK	LRANGE(POLICY_IKEV1_ALLOW_IX, POLICY_IKEV2_PROPOSE_IX)

	POLICY_IKEV2_ALLOW_NARROWING_IX,	/* Allow RFC-5669 section 2.9? 0x0800 0000 */
	POLICY_IKEV2_PAM_AUTHORIZE_IX,

	POLICY_SAREF_TRACK_IX,	/* Saref tracking via _updown */
	POLICY_SAREF_TRACK_CONNTRACK_IX,	/* use conntrack optimization */

	POLICY_IKE_FRAG_ALLOW_IX,
	POLICY_IKE_FRAG_FORCE_IX,
#define POLICY_IKE_FRAG_MASK	LRANGE(POLICY_IKE_FRAG_ALLOW_IX,POLICY_IKE_FRAG_FORCE_IX)
	POLICY_NO_IKEPAD_IX,	/* pad ike packets to 4 bytes or not */
	POLICY_MOBIKE_IX,	/* allow MOBIKE */
	POLICY_PPK_ALLOW_IX,
	POLICY_PPK_INSIST_IX,
	POLICY_ESN_NO_IX,		/* send/accept ESNno */
	POLICY_ESN_YES_IX,		/* send/accept ESNyes */
#define POLICY_IX_LAST	POLICY_ESN_YES_IX
};

#define POLICY_PSK	LELEM(POLICY_PSK_IX)
#define POLICY_RSASIG	LELEM(POLICY_RSASIG_IX)
#define POLICY_ECDSA   LELEM(POLICY_ECDSA_IX)
#define POLICY_AUTH_NEVER	LELEM(POLICY_AUTH_NEVER_IX)
#define POLICY_AUTH_NULL LELEM(POLICY_AUTH_NULL_IX)
#define POLICY_ENCRYPT	LELEM(POLICY_ENCRYPT_IX)	/* must be first of IPSEC policies */
#define POLICY_AUTHENTICATE	LELEM(POLICY_AUTHENTICATE_IX)	/* must be second */
#define POLICY_COMPRESS	LELEM(POLICY_COMPRESS_IX)	/* must be third */
#define POLICY_TUNNEL	LELEM(POLICY_TUNNEL_IX)
#define POLICY_PFS	LELEM(POLICY_PFS_IX)
#define POLICY_DISABLEARRIVALCHECK	LELEM(POLICY_DISABLEARRIVALCHECK_IX)	/* suppress tunnel egress address checking */
#define POLICY_DECAP_DSCP	LELEM(POLICY_DECAP_DSCP_IX)	/* decap ToS/DSCP bits */
#define POLICY_NOPMTUDISC	LELEM(POLICY_NOPMTUDISC_IX)
#define POLICY_MSDH_DOWNGRADE	LELEM(POLICY_MSDH_DOWNGRADE_IX)
#define POLICY_DNS_MATCH_ID	LELEM(POLICY_DNS_MATCH_ID_IX)
#define POLICY_SHA2_TRUNCBUG	LELEM(POLICY_SHA2_TRUNCBUG_IX)
#define POLICY_SHUNT0	LELEM(POLICY_SHUNT0_IX)
#define POLICY_SHUNT1	LELEM(POLICY_SHUNT1_IX)
#define POLICY_FAIL0	LELEM(POLICY_FAIL0_IX)
#define POLICY_FAIL1	LELEM(POLICY_FAIL1_IX)
#define POLICY_NEGO_PASS	LELEM(POLICY_NEGO_PASS_IX)	/* install %pass during initial IKE */
#define POLICY_DONT_REKEY	LELEM(POLICY_DONT_REKEY_IX)	/* don't rekey state either Phase */
#define POLICY_REAUTH	LELEM(POLICY_REAUTH_IX)	/* IKEv2 initiate reauthentication instead of rekey */
#define POLICY_OPPORTUNISTIC	LELEM(POLICY_OPPORTUNISTIC_IX)	/* is this opportunistic? */
#define POLICY_GROUP	LELEM(POLICY_GROUP_IX)	/* is this a group template? */
#define POLICY_GROUTED	LELEM(POLICY_GROUTED_IX)	/* do we want this group routed? */
#define POLICY_GROUPINSTANCE	LELEM(POLICY_GROUPINSTANCE_IX)	/* is this a group template instance? */
#define POLICY_UP	LELEM(POLICY_UP_IX)	/* do we want this up? */
#define POLICY_XAUTH	LELEM(POLICY_XAUTH_IX)	/* do we offer XAUTH? */
#define POLICY_MODECFG_PULL	LELEM(POLICY_MODECFG_PULL_IX)	/* is modecfg pulled by client? */
#define POLICY_AGGRESSIVE	LELEM(POLICY_AGGRESSIVE_IX)	/* do we do aggressive mode? */
#define POLICY_OVERLAPIP	LELEM(POLICY_OVERLAPIP_IX)	/* can two conns that have subnet=vhost: declare the same IP? */
#define POLICY_IKEV1_ALLOW	LELEM(POLICY_IKEV1_ALLOW_IX)	/* !accept IKEv1?  0x0100 0000 */
#define POLICY_IKEV2_ALLOW	LELEM(POLICY_IKEV2_ALLOW_IX)	/* accept IKEv2?   0x0200 0000 */
#define POLICY_IKEV2_PROPOSE	LELEM(POLICY_IKEV2_PROPOSE_IX)	/* propose IKEv2?  0x0400 0000 */
#define POLICY_IKEV2_ALLOW_NARROWING	LELEM(POLICY_IKEV2_ALLOW_NARROWING_IX)	/* Allow RFC-5669 section 2.9? 0x0800 0000 */
#define POLICY_IKEV2_PAM_AUTHORIZE     LELEM(POLICY_IKEV2_PAM_AUTHORIZE_IX)    /* non-standard, custom PAM authorize call on ID */
#define POLICY_SAREF_TRACK	LELEM(POLICY_SAREF_TRACK_IX)	/* Saref tracking via _updown */
#define POLICY_SAREF_TRACK_CONNTRACK	LELEM(POLICY_SAREF_TRACK_CONNTRACK_IX)	/* use conntrack optimization */
#define POLICY_IKE_FRAG_ALLOW	LELEM(POLICY_IKE_FRAG_ALLOW_IX)
#define POLICY_IKE_FRAG_FORCE	LELEM(POLICY_IKE_FRAG_FORCE_IX)
#define POLICY_NO_IKEPAD	LELEM(POLICY_NO_IKEPAD_IX)	/* pad ike packets to 4 bytes or not */
#define POLICY_MOBIKE		LELEM(POLICY_MOBIKE_IX)	/* allow MOBIKE */
#define POLICY_PPK_ALLOW	LELEM(POLICY_PPK_ALLOW_IX)
#define POLICY_PPK_INSIST	LELEM(POLICY_PPK_INSIST_IX)
#define POLICY_ESN_NO		LELEM(POLICY_ESN_NO_IX)	/* accept or request ESNno */
#define POLICY_ESN_YES		LELEM(POLICY_ESN_YES_IX)	/* accept or request ESNyes */

#define NEGOTIATE_AUTH_HASH_SHA1		LELEM(IKEv2_AUTH_HASH_SHA1)	/* rfc7427 does responder support SHA1? */
#define NEGOTIATE_AUTH_HASH_SHA2_256		LELEM(IKEv2_AUTH_HASH_SHA2_256)	/* rfc7427 does responder support SHA2-256?  */
#define NEGOTIATE_AUTH_HASH_SHA2_384		LELEM(IKEv2_AUTH_HASH_SHA2_384)	/* rfc7427 does responder support SHA2-384? */
#define NEGOTIATE_AUTH_HASH_SHA2_512		LELEM(IKEv2_AUTH_HASH_SHA2_512)	/* rfc7427 does responder support SHA2-512? */
#define NEGOTIATE_AUTH_HASH_IDENTITY		LELEM(IKEv2_AUTH_HASH_IDENTITY)	/* rfc4307-bis does responder support IDENTITY? */

enum sighash_policy_bits {
	POL_SIGHASH_NONE = 0, /* 0 means no RFC 7427 and plain rsav1.5-sha1 or secret */
	POL_SIGHASH_SHA2_256_IX = 1,
	POL_SIGHASH_SHA2_384_IX = 2,
	POL_SIGHASH_SHA2_512_IX = 3,
#define POL_SIGHASH_IX_LAST	POL_SIGHASH_SHA2_512_IX
};
#define POL_SIGHASH_SHA2_256 LELEM(POL_SIGHASH_SHA2_256_IX)
#define POL_SIGHASH_SHA2_384 LELEM(POL_SIGHASH_SHA2_384_IX)
#define POL_SIGHASH_SHA2_512 LELEM(POL_SIGHASH_SHA2_512_IX)

/* Default policy for now is using RSA - this might change to ECC */
#define POLICY_DEFAULT POLICY_RSASIG

/* These policy bits must match exactly: POLICY_XAUTH, POLICY_AGGRESSIVE, POLICY_IKEV1_ALLOW */

/* Any IPsec policy?  If not, a connection description
 * is only for ISAKMP SA, not IPSEC SA.  (A pun, I admit.)
 * Note: a connection can only be routed if it is NEVER_NEGOTIATE
 * or HAS_IPSEC_POLICY.
 */
#define HAS_IPSEC_POLICY(p) (((p) & POLICY_IPSEC_MASK) != 0)

#define NEVER_NEGOTIATE(p)  (LDISJOINT((p), POLICY_ENCRYPT | POLICY_AUTHENTICATE))

/* values for right=/left= */
enum keyword_host {
	KH_NOTSET       = 0,
	KH_DEFAULTROUTE = 1,
	KH_ANY          = 2,
	KH_IFACE        = 3,
	KH_OPPO         = 4,
	KH_OPPOGROUP    = 5,
	KH_GROUP        = 6,
	KH_IPHOSTNAME   = 7,            /* host_addr invalid, only string */
	KH_IPADDR       = LOOSE_ENUM_OTHER,
};

/*
 * related(???) libunbound enumerated types
 *
 * How authenticated is info that might have come from DNS?
 * In order of increasing confidence.
 */
enum dns_auth_level {
	/* 0 is reserved so uninitialized values are meaningless */
	PUBKEY_LOCAL = 1,	/* came from local source, whack, plugin etc */
	DNSSEC_INSECURE,	/* UB returned INSECURE */
	DNSSEC_SECURE,		/* UB returned SECURE */

	DNSSEC_ROOF
};

/*
 * private key types for keys.h
 */
enum PrivateKeyKind {
	/* start at one so accidental 0 will not match */
	PKK_PSK = 1,
	PKK_RSA,
	PKK_XAUTH,
	PKK_PPK,
	PKK_ECDSA, /* should not be needed */
	PKK_NULL,
	PKK_INVALID,
};

#define XAUTH_PROMPT_TRIES 3
#define MAX_XAUTH_USERNAME_LEN 128
#define XAUTH_MAX_PASS_LENGTH 128

#define MIN_LIVENESS 1

enum pluto_exit_code {
	PLUTO_EXIT_OK = 0,
	PLUTO_EXIT_FAIL = 1,
	PLUTO_EXIT_SOCKET_FAIL = 2,
	PLUTO_EXIT_FORK_FAIL = 3,
	PLUTO_EXIT_FIPS_FAIL = 4,
	PLUTO_EXIT_KERNEL_FAIL = 5,
	PLUTO_EXIT_NSS_FAIL = 6,
	PLUTO_EXIT_AUDIT_FAIL = 7,
	PLUTO_EXIT_SECCOMP_FAIL = 8,
	PLUTO_EXIT_UNBOUND_FAIL = 9,
	PLUTO_EXIT_LOCK_FAIL = 10, /* historic value */
};

#define SWAN_MAX_DOMAIN_LEN 256 /* includes nul termination */

extern void init_pluto_constants(void);

/*
 * IPsec SA SPD policy priorities.
 * A smaller value is a higher priority.
 * The bands we use must have 2<<19 distinct values.
 * manual by user	[0 * 1<<19, 1 * 1<<19)
 * static conn		[1 * 1<<19, 2 * 1<<19)
 * opportunistic	[2 * 1<<19, 3 * 1<<19)
 * oe-anonymous		[3 * 1<<19, 4 * 1<<19)
 */
#define PLUTO_SPD_MANUAL_MAX	(1u * (1u << 19) - 1u)	/* not yet used */
#define PLUTO_SPD_STATIC_MAX	(2u * (1u << 19) - 1u)
#define PLUTO_SPD_OPPO_MAX	(3u * (1u << 19) - 1u)
#define PLUTO_SPD_OPPO_ANON_MAX	(4u * (1u << 19) - 1u)
