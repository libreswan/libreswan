/* manifest constants
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2019-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#ifndef PLUTO_CONSTANTS_H
#define PLUTO_CONSTANTS_H

#include "lset.h"
#include "sparse_names.h"

/*
 * Size of hash tables; a prime.
 *
 * Mumble something about modifying hash_table.[hc] so it can grow.
 */
#define STATE_TABLE_SIZE 499

#define DEFAULT_UPDOWN "ipsec _updown"
#define UPDOWN_DISABLED "%disabled"

# ifndef DEFAULT_DNSSEC_ROOTKEY_FILE
#  define DEFAULT_DNSSEC_ROOTKEY_FILE "<unused>"
# endif

enum ike_version {
	/* 0 reserved */
#define IKE_VERSION_FLOOR 1
	IKEv1 = 1,
	IKEv2 = 2,
#define IKE_VERSION_ROOF 3
};

/*
 * IETF has no recommendations
 * FIPS SP800-77 sayas IKE max is 24h, IPsec max is 8h
 * We say maximum for either is 1d
 */
#define IKE_SA_LIFETIME_DEFAULT deltatime(secs_per_hour * 8)
#define IKE_SA_LIFETIME_MAXIMUM deltatime(secs_per_day)
#define FIPS_IKE_SA_LIFETIME_MAXIMUM deltatime(secs_per_day)

#define IPSEC_SA_LIFETIME_DEFAULT deltatime(secs_per_hour * 8)
#define IPSEC_SA_LIFETIME_MAXIMUM deltatime(secs_per_day)
#define FIPS_IPSEC_SA_LIFETIME_MAXIMUM deltatime(secs_per_hour * 8)

#define FIPS_MIN_RSA_KEY_SIZE 2048 /* 112 bits, see SP800-131A */

/*
 * XFRM_INF is a uint64_t, hence use that to define upper bound of
 * constant.
 */
#define IPSEC_SA_MAX_OPERATIONS (UINT64_C(1) << 63)
#define IPSEC_SA_MAX_OPERATIONS_STRING "2^63"		/* how to print IPSEC_SA_MAX_OPERATIONS */
#define IPSEC_SA_MAX_SOFT_LIMIT_PERCENTAGE 50

#define PLUTO_SHUNT_LIFE_DURATION_DEFAULT (15 * secs_per_minute)
#define PLUTO_HALFOPEN_SA_LIFE (secs_per_minute )

#define SA_REPLACEMENT_MARGIN_DEFAULT (9 * secs_per_minute) /* IPSEC & IKE */
#define SA_REPLACEMENT_FUZZ_DEFAULT 100 /* (IPSEC & IKE) 100% of MARGIN */

#define IKE_BUF_AUTO 0 /* use system values for IKE socket buffer size */

#define DEFAULT_XFRM_IF_NAME "ipsec1"

enum send_ca_policy {
	CA_SEND_NONE = 0,
	CA_SEND_ISSUER = 1,
	CA_SEND_ALL = 2,
};

/* values for auto={add,start,{route,ondemand},ignore} */

enum autostart {
	AUTOSTART_UNSET,
	AUTOSTART_IGNORE,
	AUTOSTART_ADD,
	AUTOSTART_ONDEMAND,
	AUTOSTART_UP,
	AUTOSTART_KEEP,
};

extern const struct sparse_names autostart_names;

/* Cisco interop: values remote_peer_type= */
enum keyword_remote_peer_type {
	REMOTE_PEER_UNSET = 0,
	REMOTE_PEER_CISCO,
};

enum keyword_auth {
	AUTH_UNSET = 0,
	AUTH_NEVER,
	AUTH_PSK,
	AUTH_RSASIG,
	AUTH_ECDSA,
	AUTH_NULL,
	AUTH_EAPONLY,
};

enum keyword_xauthby {
	XAUTHBY_FILE = 0,
	XAUTHBY_PAM = 1,
	XAUTHBY_ALWAYSOK = 2,
};

enum allow_global_redirect {
	GLOBAL_REDIRECT_NO = 1,
	GLOBAL_REDIRECT_YES = 2,
	GLOBAL_REDIRECT_AUTO = 3,
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

enum global_ikev1_policy {
	GLOBAL_IKEv1_ACCEPT = 0,
	GLOBAL_IKEv1_REJECT = 1,
	GLOBAL_IKEv1_DROP = 2,
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

/*
 * Timer events not associated with states (aka global
 * timers).
 */

extern const struct enum_names global_timer_names;

enum global_timer {
	EVENT_REINIT_SECRET,		/* Refresh cookie secret */
	EVENT_SHUNT_SCAN,		/* scan shunt eroutes known to kernel */
	EVENT_PENDING_DDNS,		/* try to start connections where DNS failed at init */
	EVENT_SD_WATCHDOG,		/* update systemd's watchdog interval */
	EVENT_CHECK_CRLS,		/* check/update CRLS */

	EVENT_FREE_ROOT_CERTS,
#define FREE_ROOT_CERTS_TIMEOUT		deltatime(5 * secs_per_minute)

	EVENT_RESET_LOG_LIMITER,	/* set rate limited log message count back to 0 */
#define RESET_LOG_LIMITER_FREQUENCY	deltatime(secs_per_hour)

	EVENT_NAT_T_KEEPALIVE,		/* NAT Traversal Keepalive */

	EVENT_PROCESS_KERNEL_QUEUE,	/* non-netkey */
};

/*
 * Connection based events.
 */

enum connection_event_kind {
	CONNECTION_REVIVAL = 1,
};
#define CONNECTION_EVENT_KIND_ROOF (CONNECTION_REVIVAL+1)

extern const struct enum_names connection_event_kind_names;

/*
 * State based events and timers.
 */

extern const struct enum_names event_type_names;

enum event_type {
	EVENT_NULL,			/* non-event */

	/* events associated with connections */

	/* events associated with states */

	EVENT_RETRANSMIT,		/* v1/v2 retransmit IKE packet */

	EVENT_CRYPTO_TIMEOUT,		/* v1/v2 after some time, give up on crypto helper */

	/*
	 * For IKEv2 'replace' is really either a re-key a full
	 * replace, or expire.  IKEv1 should be the same but isn't.
	 */

	EVENT_v1_SEND_XAUTH,		/* v1 send xauth request */
	EVENT_v1_DPD,			/* v1 dead peer detection */
	EVENT_v1_DPD_TIMEOUT,		/* v1 dead peer detection timeout */
	EVENT_v1_PAM_TIMEOUT,		/* v1 give up on PAM helper */
	EVENT_v1_EXPIRE,		/* v1 SA expiration event */
	EVENT_v1_DISCARD,		/* v1 discard unfinished state object */
	EVENT_v1_REPLACE,		/* v1 replacement event */

	EVENT_v2_REKEY,			/* SA rekey event */
	EVENT_v2_REPLACE,		/* v2 IKE/Child SA replacement event */
	EVENT_v2_EXPIRE,		/* v2 SA expiration (drop-dead) event */
	EVENT_v2_DISCARD,		/* v2 discard unfinished state object */
	EVENT_v2_LIVENESS,		/* for dead peer detection */
	EVENT_v2_ADDR_CHANGE,		/* process IP address deletion */

	EVENT_RETAIN,			/* don't change the previous event */
};

#define EVENT_REINIT_SECRET_DELAY	secs_per_hour
#define EVENT_GIVEUP_ON_DNS_DELAY	(5 * secs_per_minute)
#define EVENT_RELEASE_WHACK_DELAY	10	/* seconds */

#define RTM_NEWADDR_ROUTE_DELAY		deltatime(3) /* seconds */

#define PARENT_MIN_LIFE_DELAY		deltatime(1) /* second */
#define EXPIRE_OLD_SA_DELAY		deltatime(1) /* second */
#define REPLACE_ORPHAN_DELAY		deltatime(1) /* second */

/*
 * an arbitrary milliseconds delay for responder. A workaround for iOS, iPhone.
 * If xauth message arrive before main mode response iPhone may abort.
 */
#define EVENT_v1_SEND_XAUTH_DELAY_MS	80 /* milliseconds */

#define RETRANSMIT_TIMEOUT_DEFAULT	60  /* seconds */
#ifndef RETRANSMIT_INTERVAL_DEFAULT_MS
# define RETRANSMIT_INTERVAL_DEFAULT_MS	500 /* wait time doubled each retransmit - in milliseconds */
#endif
#define EVENT_CRYPTO_TIMEOUT_DELAY	deltatime(RETRANSMIT_TIMEOUT_DEFAULT) /* wait till the other side give up on us */
#define EVENT_v1_PAM_TIMEOUT_DELAY	deltatime(RETRANSMIT_TIMEOUT_DEFAULT) /* wait until this side give up on PAM */

#define REVIVE_CONN_DELAY	deltatime(5) /* seconds */
#define REVIVE_CONN_DELAY_MAX   deltatime(300) /* Do not delay more than 5 minutes per attempt */

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
 * Note: STF_FAIL_v1N + <notification> (<notification> is either
 * notification_t or v2_notification_t) means fail with that
 * notification.  Since <notification> is a uint16_t, it is limited to
 * 65535 possible values (0 isn't valid).
 *
 * tbd? means someone needs to look at the IKEv1/IKEv2 code and figure
 * it out.
 *
 * delete 'if state': delete state is known - the post processing
 * function function complete_*_state_transition() assumes there is a
 * message and if it contains a state (*MDP)->ST delete it.  XXX: This
 * is messed up - a state transition function, which by definition is
 * operating on a state, should require a state and not the message.
 *
 * delete 'maybe?': For IKEv2, delete the IKE_SA_INIT responder state
 * but only when STF_FAIL_v1N+<v2notification>.  IKEv1?  XXX: With no
 * clear / fast rule, this just creates confusion; perhaps the intent
 * is for it to delete larval response states, who knows?
 *
 * respond 'message?': if the state transition says a message should
 * be sent (hopefully there is one).
 *
 * respond 'maybe?': For instance, with IKEv2 when a responder and
 * STF_FAIL_v1N+<notification>, a notification is sent as the only content
 * in a response.  XXX: for IKEv2 this is broken: KE responses can't
 * use it - need to suggest KE; AUTH responses can't use it - need to
 * send other stuff (but they do breaking auth).
 */

typedef enum {
	/*
	 * XXX: Upon the state transition function's return do not
	 * call complete_v[12]_state_transition(), do not pass go, and
	 * do not collect $200.
	 *
	 * This is a hack so that (old) state transitions functions
	 * that directly directly call complete*() (or other scary
	 * stuff) can signal the common code that the normal sequence
	 * of: call state transition function; call complete() should
	 * be bypassed.  For instance, the IKEv1 crypto and PAM
	 * continuation functions.
	 */
	STF_SKIP_COMPLETE_STATE_TRANSITION,
	/*                      		   TRANSITION  DELETE    SEND */
	STF_IGNORE,            			/*     no        no       no  */
	STF_SUSPEND,            		/*   suspend     no       no  */
	STF_OK,                 		/*    yes        no     response? */
	STF_OK_INITIATOR_DELETE_IKE,		/*    yes        yes      no */
	STF_OK_INITIATOR_SEND_DELETE_IKE,	/*    yes        yes    request */
	STF_OK_RESPONDER_DELETE_IKE,		/*    yes        yes    response? */
	STF_INTERNAL_ERROR,			/*     no        no      never? */
	STF_FATAL,				/*     no        yes     never */
	STF_FAIL_v1N,       			/*     no       maybe?   response? */
#define STF_ROOF (STF_FAIL_v1N + 65536) /* see RFC and above */
} stf_status;

/* Misc. stuff */

#define MAXIMUM_v1_ACCEPTED_DUPLICATES        2
/*
 * maximum retransmits per exchange, for IKEv1 (initiator and responder),
 * IKEv2 initiator
 */
#define MAXIMUM_RETRANSMITS_PER_EXCHANGE     12

#define EXCHANGE_TIMEOUT_DELAY	   	deltatime(200) /* seconds before giving up on an exchange */

#define MAXIMUM_INVALID_KE_RETRANS 3

#define MAXIMUM_MALFORMED_NOTIFY             16

#define MAX_INPUT_UDP_SIZE             65536
#define MIN_OUTPUT_UDP_SIZE		1024
#define MAX_OUTPUT_UDP_SIZE            65536

#define MAX_IKE_FRAGMENTS       32 /* Windows has been observed to send 29 fragments :/ */

#define KERNEL_PROCESS_Q_PERIOD 1 /* seconds */
#define DEFAULT_MAXIMUM_HALFOPEN_IKE_SA 50000 /* fairly arbitrary */
#define DEFAULT_IKE_SA_DDOS_THRESHOLD 25000 /* fairly arbitrary */

#define IPSEC_SA_DEFAULT_REPLAY_WINDOW 128 /* for Linux, requires 2.6.39+ */

#define IKE_V2_OVERLAPPING_WINDOW_SIZE	1 /* our default for rfc 7296 # 2.3 */

#define PPK_ID_MAXLEN 64 /* fairly arbitrary */

/*
 * debugging settings: a set of selections for reporting These would
 * be more naturally situated in log.h, but they are shared with
 * whack.
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

	DBG_BASE_IX = DBG_floor_IX,
	DBG_ROUTING_IX,

	DBG_base_IX = DBG_ROUTING_IX,

	/* below are also enabled by debug=all */

	DBG_CPU_USAGE_IX,
	DBG_REFCNT_IX,

	DBG_all_IX = DBG_REFCNT_IX,

	/* below are also enabled by debug=tmi */

	DBG_TMI_IX,

	DBG_tmi_IX = DBG_TMI_IX,

	/* below are excluded */

	DBG_CRYPT_IX,
	DBG_PRIVATE_IX,

	DBG_WHACKWATCH_IX,
	DBG_ADD_PREFIX_IX,

	DBG_roof_IX,
};

/* Sets of Debug items */

#define DBG_MASK	LRANGE(DBG_floor_IX, DBG_roof_IX - 1)
#define DBG_NONE        LEMPTY                               /* no options on, including impairments */

#define DBG_BASE        LELEM(DBG_BASE_IX)
#define DBG_ROUTING	LELEM(DBG_ROUTING_IX)
#define DBG_CPU_USAGE	LELEM(DBG_CPU_USAGE_IX)
#define DBG_REFCNT	LELEM(DBG_REFCNT_IX)

#define DBG_ALL		LRANGE(DBG_floor_IX, DBG_all_IX)

#define DBG_TMI		LELEM(DBG_TMI_IX)

#define DBG_CRYPT	LELEM(DBG_CRYPT_IX)
#define DBG_PRIVATE	LELEM(DBG_PRIVATE_IX)

/* so things don't break */
#define DBG_PROPOSAL_PARSER	DBG_TMI

#define DBG_WHACKWATCH	LELEM(DBG_WHACKWATCH_IX)
#define DBG_ADD_PREFIX	LELEM(DBG_ADD_PREFIX_IX)

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

	/* IKE states */

#ifdef USE_IKEv1
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
#endif

	/*
	 * IKEv2 states.
	 *
	 * Note: that message reliably sending is done by initiator
	 * only, unlike with IKEv1.
	 *
	 * Note: order matters.  Larval states come before
	 * ESTABLISHED_*_SA.
	 */
	STATE_IKEv2_FLOOR,

	/* IKE SA */

	STATE_V2_IKE_SA_INIT_I0 = STATE_IKEv2_FLOOR,	/* waiting for KE to finish */

	STATE_V2_IKE_SA_INIT_I,		/* Initiator sent Request */
	STATE_V2_IKE_SA_INIT_R0,	/* just starting */
	STATE_V2_IKE_SA_INIT_R,		/* Responder send Response */
	STATE_V2_IKE_SA_INIT_IR,	/* Initiator processed Response */

	STATE_V2_IKE_INTERMEDIATE_I,
	STATE_V2_IKE_INTERMEDIATE_R,
	STATE_V2_IKE_INTERMEDIATE_IR,

	STATE_V2_IKE_AUTH_EAP_R,  /* IKE_AUTH EAP negotiation */

	STATE_V2_IKE_AUTH_I,        /* IKE_AUTH: sent auth message, waiting for reply */

	/* IKEv2 CREATE_CHILD_SA Initiator states */

	STATE_V2_NEW_CHILD_I0,		/* larval: sent nothing yet */
	STATE_V2_NEW_CHILD_R0,		/* larval: sent nothing yet. */
	STATE_V2_NEW_CHILD_I1,		/* sent first message of CREATE_CHILD new IPsec */

	STATE_V2_REKEY_IKE_I0,		/* larval: sent nothing yet */
	STATE_V2_REKEY_IKE_I1,		/* sent first message (via parrenti) to rekey parent */

	STATE_V2_REKEY_CHILD_I0,	/* larval: sent nothing yet */
	STATE_V2_REKEY_CHILD_I1,	/* sent first message (via parent to rekey child sa. */

	/* IKEv2 CREATE_CHILD_SA Responder states */

	STATE_V2_REKEY_IKE_R0,		/* larval: sent nothing yet terminal state STATE_V2_PARENT_R2 */
	STATE_V2_REKEY_CHILD_R0,	/* larval: sent nothing yet. */

	/* IKEv2's established states */

	STATE_V2_ESTABLISHED_IKE_SA,
	STATE_V2_ESTABLISHED_CHILD_SA,

	/*
	 * (unimplemented) after a state is deleted it can lurk for a
	 * while so that it still responds to retransmits and ignores
	 * responses.
	 */
	STATE_V2_ZOMBIE,

	STATE_IKEv2_ROOF	/* not a state! */
};

/* STATE_IKEv2_ROOF lurks in the code so leave space for it */
#define STATE_IKE_ROOF (STATE_IKEv2_ROOF+1)	/* not a state! */

/*
 * Perspective from which the operation is being performed.
 *
 * For instance, is the hash being computed from the LOCAL or REMOTE
 * perspective?
 */

enum perspective {
	NO_PERSPECTIVE,	/* invalid */
	LOCAL_PERSPECTIVE,
	REMOTE_PERSPECTIVE,
};

extern const struct enum_names perspective_names;

#ifdef USE_IKEv1
#define V1_PHASE1_INITIATOR_STATES  (LELEM(STATE_MAIN_I1) | \
				     LELEM(STATE_MAIN_I2) | \
				     LELEM(STATE_MAIN_I3) | \
				     LELEM(STATE_MAIN_I4) | \
				     LELEM(STATE_AGGR_I1) | \
				     LELEM(STATE_AGGR_I2) | \
				     LELEM(STATE_XAUTH_I0) |	\
				     LELEM(STATE_XAUTH_I1) |	\
				     LELEM(STATE_MODE_CFG_I1))

#define IS_V1_PHASE1(ST) (STATE_MAIN_R0 <= (ST) && (ST) <= STATE_AGGR_R2)

#define IS_V1_PHASE15(ST) (STATE_XAUTH_R0 <= (ST) && (ST) <= STATE_XAUTH_I1)

#define IS_V1_QUICK(ST) (STATE_QUICK_R0 <= (ST) && (ST) <= STATE_QUICK_R2)

#define V1_ISAKMP_ENCRYPTED_STATES  (LRANGE(STATE_MAIN_R2, STATE_MAIN_I4) | \
				     LRANGE(STATE_AGGR_R1, STATE_AGGR_R2) | \
				     LRANGE(STATE_QUICK_R0, STATE_QUICK_R2) | \
				     LELEM(STATE_INFO_PROTECTED) |	\
				     LRANGE(STATE_XAUTH_R0, STATE_XAUTH_I1))

#define IS_V1_ISAKMP_ENCRYPTED(ST) ((LELEM(ST) & V1_ISAKMP_ENCRYPTED_STATES) != LEMPTY)

/* ??? Is this really authenticate?  Even in xauth case? In STATE_INFO case? */
#define IS_V1_ISAKMP_AUTHENTICATED(ST) (STATE_MAIN_R3 <= ((ST)->kind) && \
					STATE_AGGR_R0 != ((ST)->kind) && \
					STATE_AGGR_I1 != ((ST)->kind))

#define V1_ISAKMP_SA_ESTABLISHED_STATES  (LELEM(STATE_MAIN_R3) | \
					  LELEM(STATE_MAIN_I4) | \
					  LELEM(STATE_AGGR_I2) | \
					  LELEM(STATE_AGGR_R2) | \
					  LELEM(STATE_XAUTH_R0) |	\
					  LELEM(STATE_XAUTH_R1) |	\
					  LELEM(STATE_MODE_CFG_R0) |	\
					  LELEM(STATE_MODE_CFG_R1) |	\
					  LELEM(STATE_MODE_CFG_R2) |	\
					  LELEM(STATE_MODE_CFG_I1) |	\
					  LELEM(STATE_XAUTH_I0) |	\
					  LELEM(STATE_XAUTH_I1))

#define IS_V1_ISAKMP_SA_ESTABLISHED(ST)					\
	((LELEM((ST)->st_state->kind) & V1_ISAKMP_SA_ESTABLISHED_STATES) != LEMPTY)

#define IS_ISAKMP_SA_ESTABLISHED(ST)					\
	((LELEM((ST)->st_state->kind) & V1_ISAKMP_SA_ESTABLISHED_STATES) != LEMPTY)

#define IS_V1_ISAKMP_SA(ST) ((ST)->st_ike_version == IKEv1 && (ST)->st_clonedfrom == SOS_NOBODY)
#define IS_ISAKMP_SA(ST) ((ST)->st_ike_version == IKEv1 && (ST)->st_clonedfrom == SOS_NOBODY)

#define IS_V1_MODE_CFG_ESTABLISHED(ST) (((ST)->kind) == STATE_MODE_CFG_R2)

#else /* no IKEV1 */
/* saves a bunch of ugly ifdefs elsewhere */
#define IS_V1_ISAKMP_SA_ESTABLISHED(ST) false
#endif

#define IKEV2_ISAKMP_INITIATOR_STATES (LELEM(STATE_V2_IKE_SA_INIT_I0) |	\
				       LELEM(STATE_V2_IKE_SA_INIT_I) |	\
				       LELEM(STATE_V2_IKE_AUTH_I))

/* IKEv1 or IKEv2 */
#ifdef USE_IKEv1
#define IS_IPSEC_SA_ESTABLISHED(ST) (IS_CHILD_SA(ST) &&			\
				     (((ST)->st_state->kind) == STATE_QUICK_I2 || \
				      ((ST)->st_state->kind) == STATE_QUICK_R1 || \
				      ((ST)->st_state->kind) == STATE_QUICK_R2 || \
				      ((ST)->st_state->kind) == STATE_V2_ESTABLISHED_CHILD_SA))
#else
#define IS_IPSEC_SA_ESTABLISHED(ST) (IS_CHILD_SA(ST) &&			\
				     ((ST)->st_state->kind) == STATE_V2_ESTABLISHED_CHILD_SA)
#endif

/*
 * ??? Issue here is that our child SA appears as a
 * STATE_V2_PARENT_I3/STATE_PARENT_R2 state which it should not.
 * So we fall back to checking if it is cloned, and therefore really a child.
 */

#define IS_CHILD_SA_ESTABLISHED(ST)				\
	((ST)->st_state->kind == STATE_V2_ESTABLISHED_CHILD_SA)

#define IS_IKE_SA_ESTABLISHED(ST)				\
	((ST)->st_state->kind == STATE_V2_ESTABLISHED_IKE_SA)

#define IS_CHILD_SA(st)  ((st)->st_clonedfrom != SOS_NOBODY)
#define IS_IKE_SA(st)	 ((st)->st_clonedfrom == SOS_NOBODY)

#define IS_PARENT_SA(ST) ((ST)->st_clonedfrom == SOS_NOBODY) /* IKEv1 or IKEv2 */
#define IS_PARENT_SA_ESTABLISHED(ST) (IS_IKE_SA_ESTABLISHED(ST) || IS_ISAKMP_SA_ESTABLISHED(ST))

/*
 * Kind of struct connection
 *
 * Ordered (mostly) by concreteness.  Order is exploited (for
 * instance, when listing connections the kind is used as the second
 * sort key after name but before instance number which means that
 * templates are grouped, followed by their instances, weird).
 */

enum connection_kind {
	CK_INVALID = 0,		/* better name? */
	CK_GROUP,       	/* policy group: instantiates to CK_TEMPLATE+POLICY_GROUPINSTANCE */
	CK_TEMPLATE,    	/* abstract connection, with wildcard */
	CK_PERMANENT,   	/* normal connection */
	CK_INSTANCE,    	/* instance of template, created for a
				 * particular attempt */
	CK_LABELED_TEMPLATE,	/* labels are in their own little world */
	CK_LABELED_PARENT,
	CK_LABELED_CHILD,
#define CONNECTION_KIND_ROOF (CK_LABELED_CHILD+1)
};

enum certpolicy {
	CERT_NEVERSEND   = 1,
	CERT_SENDIFASKED = 2,   /* the default */
	CERT_ALWAYSSEND  = 3,
};

/* this is the default setting. */
#define cert_defaultcertpolicy CERT_ALWAYSSEND

enum ikev1_natt_policy {
	NATT_BOTH = 1, /* the default */
	NATT_RFC = 2,
	NATT_DRAFTS = 3, /* Workaround for Cisco NAT-T bug */
	NATT_NONE = 4 /* Workaround for forcing non-encaps */
};

extern const struct sparse_names nat_ikev1_method_option_names;

enum nppi_options {
	NPPI_UNSET = 0,
	NPPI_NEVER,		/* do not propose, do not permit */
	NPPI_PERMIT,		/* do not propose, but permit peer to propose */
	NPPI_PROPOSE,		/* propose, and permit, but do not insist */
	NPPI_INSIST		/* propose, and only accept if peer agrees */
};

extern const struct sparse_names nppi_option_names;

enum ynf_options {
	YNF_UNSET = 0,
	YNF_YES,
	YNF_NO,
	YNF_FORCE,
};

extern const struct sparse_names ynf_option_names;

enum yn_options {
	YN_UNSET = 0,
	YN_NO = 1,
	YN_YES = 2,
};

/* includes things like 0/1 */
extern const struct sparse_names yn_option_names;

/* excludes 0/1 */
extern const struct sparse_names yn_text_option_names;

enum yna_options {
	YNA_UNSET = 0,
	YNA_AUTO = 1, /* default?!? */
	YNA_NO = 2,
	YNA_YES = 3,
};

extern const struct sparse_names yna_option_names;

enum yne_options {
	YNE_UNSET,
	YNE_NO,
	YNE_YES,
	YNE_EITHER,
};

extern const struct sparse_names yne_option_names;

enum tcp_options {
       IKE_TCP_NO = 1,
       IKE_TCP_ONLY = 2,
       IKE_TCP_FALLBACK = 3,
};

extern const struct sparse_names tcp_option_names; /* "no", "yes", "fallback" */

enum eap_options {
	IKE_EAP_NONE = 0, /* default */
	IKE_EAP_TLS = 1,
};

enum nic_offload_options {
	NIC_OFFLOAD_UNSET = 0,
	NIC_OFFLOAD_NO, /* default */
	NIC_OFFLOAD_CRYPTO,
	NIC_OFFLOAD_PACKET,
};

extern const struct sparse_names nic_offload_option_names;

/*
 * Policies for establishing an SA
 *
 * These are used to specify attributes (eg. encryption) and
 * techniques (eg PFS) for an SA.
 *
 * Note: certain CD_ definitions in whack.c parallel these -- keep
 * them in sync!
 */

typedef struct {
	char buf[512];/*arbitrary*/
} policy_buf;
const char *str_policy(lset_t policy, policy_buf *buf);
size_t jam_policy(struct jambuf *buf, lset_t policy);

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
 * so these are exhaustively defined as macros.  As are derived values.
 *
 * Changes to sa_policy_bits must be reflected in #defines below it and
 * in sa_policy_bit_names.
 */

enum shunt_policy {
	SHUNT_UNSET,
	SHUNT_IPSEC,	/* only valid with KIND IPSEC */
	SHUNT_NONE,
	SHUNT_HOLD,	/* during negotiation, don't change */
	SHUNT_TRAP,
	SHUNT_PASS,
	SHUNT_DROP,
	SHUNT_REJECT,
#define SHUNT_POLICY_ROOF (SHUNT_REJECT+1)
};

enum shunt_kind {
#define SHUNT_KIND_FLOOR 0
	SHUNT_KIND_NONE,
	SHUNT_KIND_NEVER_NEGOTIATE,
	SHUNT_KIND_ONDEMAND,		/* always SHUNT_TRAP */
	SHUNT_KIND_NEGOTIATION,
	SHUNT_KIND_IPSEC,		/* always SHUNT_IPSEC */
	SHUNT_KIND_FAILURE,
	SHUNT_KIND_BLOCK,      		/* always SHUNT_DROP */
#define never_negotiate_shunt shunt[SHUNT_KIND_NEVER_NEGOTIATE]
#define negotiation_shunt     shunt[SHUNT_KIND_NEGOTIATION]	/* during */
#define failure_shunt         shunt[SHUNT_KIND_FAILURE]		/* after */
#define SHUNT_KIND_ROOF (SHUNT_KIND_BLOCK+1)
};

extern const struct enum_names shunt_kind_names;


enum sa_policy_bits {
	POLICY_ENCRYPT_IX,	/* must be first of IPSEC policies */
	POLICY_AUTHENTICATE_IX,	/* must be second */
	POLICY_COMPRESS_IX,	/* must be third */
	POLICY_TUNNEL_IX,
	POLICY_PFS_IX,
#define POLICY_IX_LAST	POLICY_PFS_IX
};

#define POLICY_ENCRYPT	LELEM(POLICY_ENCRYPT_IX)	/* must be first of IPSEC policies */
#define POLICY_AUTHENTICATE	LELEM(POLICY_AUTHENTICATE_IX)	/* must be second */
#define POLICY_COMPRESS	LELEM(POLICY_COMPRESS_IX)	/* must be third */
#define POLICY_TUNNEL	LELEM(POLICY_TUNNEL_IX)
#define POLICY_PFS	LELEM(POLICY_PFS_IX)

/*
 * RFC 7427 Signature Hash Algorithm exchang
 */

#define POL_SIGHASH_SHA1	LELEM(IKEv2_HASH_ALGORITHM_SHA1)	/* rfc7427 does responder support SHA1? */
#define POL_SIGHASH_SHA2_256	LELEM(IKEv2_HASH_ALGORITHM_SHA2_256)	/* rfc7427 does responder support SHA2-256? */
#define POL_SIGHASH_SHA2_384	LELEM(IKEv2_HASH_ALGORITHM_SHA2_384)	/* rfc7427 does responder support SHA2-384? */
#define POL_SIGHASH_SHA2_512	LELEM(IKEv2_HASH_ALGORITHM_SHA2_512)	/* rfc7427 does responder support SHA2-512? */
#define POL_SIGHASH_IDENTITY	LELEM(IKEv2_HASH_ALGORITHM_IDENTITY)	/* rfc4307-bis does responder support IDENTITY? */
#define POL_SIGHASH_DEFAULTS	(POL_SIGHASH_SHA2_256 | POL_SIGHASH_SHA2_384 | POL_SIGHASH_SHA2_512);

/*
 * values for right=/left=
 *
 * LOOSE_ENUM_OTHER is used by the config parser's loose-enum code to
 * flag that the field didn't match one of the pre-defined "%..."
 * values.
 */
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

enum type_options {
	KS_UNSET,
	KS_TUNNEL,
	KS_TRANSPORT,
	KS_PASSTHROUGH,
	KS_DROP,
	KS_REJECT,
};

extern const struct sparse_names type_option_names;

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
	PLUTO_EXIT_SELINUX_FAIL = 11,
	PLUTO_EXIT_RESERVED_12, /* was PLUTO_EXIT_LEAVE_STATE = 12 */
	/**/
	PLUTO_EXIT_GIT_BISECT_CAN_NOT_TEST = 125,
	PLUTO_EXIT_SHELL_COMMAND_NOT_FOUND = 126,
	PLUTO_EXIT_SHELL_COMMAND_NOT_EXECUTABLE = 127,
};

extern const struct enum_names pluto_exit_code_names;
/*
 * EXPIRE type events from the kernel.
 * Based on these, different actions can be taken, eg skipping delete SPI
 */

enum sa_expire_kind {
	SA_SOFT_EXPIRED,
	SA_HARD_EXPIRED,
#define SA_EXPIRE_KIND_ROOF (SA_HARD_EXPIRED+1)
};


#define SWAN_MAX_DOMAIN_LEN 256 /* includes nul termination */

extern void init_pluto_constants(void);

/*
 * Maximum data (including IKE HDR) allowed in a packet.
 *
 * v1 fragmentation is non-IETF magic voodoo we need to consider for interop:
 * - www.cisco.com/en/US/docs/ios/sec_secure_connectivity/configuration/guide/sec_fragment_ike_pack.html
 * - www.cisco.com/en/US/docs/ios-xml/ios/sec_conn_ikevpn/configuration/15-mt/sec-fragment-ike-pack.pdf
 * - msdn.microsoft.com/en-us/library/cc233452.aspx
 * - iOS/Apple racoon source ipsec-164.9 at www.opensource.apple.com (frak length 1280)
 * - stock racoon source (frak length 552)
 *
 * v2 fragmentation is RFC7383.
 *
 * What is a sane and safe value? iOS/Apple uses 1280, stock racoon uses 552.
 * Why is there no RFC to guide interop people here :/
 *
 * UDP packet overhead: the number of bytes of header and pseudo header
 * - v4 UDP: 20 source addr, dest addr, protocol, length, source port, destination port, length, checksum
 * - v6 UDP: 48 (similar)
 *
 * Other considerations:
 * - optional non-ESP Marker: 4 NON_ESP_MARKER_SIZE
 * - ISAKMP header
 * - encryption representation overhead
 */
#define MIN_MAX_UDP_DATA_v4	(576 - 20)	/* this length must work */
#define MIN_MAX_UDP_DATA_v6	(1280 - 48)	/* this length must work */

// #define OVERHEAD_NON_FRAG_v1	(2*4 + 16)	/* ??? what is this number? */
// #define OVERHEAD_NON_FRAG_v2	(2*4 + 16)	/* ??? what is this number? */

/*
 * ??? perhaps all current uses are not about fragment size, but how large
 * the content of a packet (ie. excluding UDP headers) can be allowed before
 * fragmentation must be considered.
 */

#define ISAKMP_V1_FRAG_OVERHEAD_IPv4	(2*4 + 16)	/* ??? */
#define ISAKMP_V1_FRAG_MAXLEN_IPv4	(MIN_MAX_UDP_DATA_v4 - ISAKMP_V1_FRAG_OVERHEAD_IPv4)
#define ISAKMP_V1_FRAG_OVERHEAD_IPv6	40	/* ??? */
#define ISAKMP_V1_FRAG_MAXLEN_IPv6	(MIN_MAX_UDP_DATA_v6 - ISAKMP_V1_FRAG_OVERHEAD_IPv6)

/* ??? it is unlikely that the v2 numbers should match the v1 numbers */
#define ISAKMP_V2_FRAG_OVERHEAD_IPv4	(2*4 + 16)	/* ??? !!! */
#define ISAKMP_V2_FRAG_MAXLEN_IPv4	(MIN_MAX_UDP_DATA_v4 - ISAKMP_V2_FRAG_OVERHEAD_IPv4)
#define ISAKMP_V2_FRAG_OVERHEAD_IPv6	40	/* ??? !!! */
#define ISAKMP_V2_FRAG_MAXLEN_IPv6	(MIN_MAX_UDP_DATA_v6 - ISAKMP_V1_FRAG_OVERHEAD_IPv6)

#endif
