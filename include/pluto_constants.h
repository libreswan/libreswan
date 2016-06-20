/* manifest constants
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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

/* Control and lock pathnames */

#ifndef DEFAULT_CTLBASE
# define DEFAULT_CTLBASE "/var/run/pluto/pluto"
#endif

#define CTL_SUFFIX ".ctl"       /* for UNIX domain socket pathname */
#define LOCK_SUFFIX ".pid"      /* for pluto's lock */
#define INFO_SUFFIX ".info"     /* for UNIX domain socket for apps */

/* default proposal values and preferences */
/* kept small because in IKEv1 it explodes in transforms of all possible combinations */
#define DEFAULT_OAKLEY_GROUPS    OAKLEY_GROUP_MODP2048, OAKLEY_GROUP_MODP1536, OAKLEY_GROUP_MODP1024
#define DEFAULT_OAKLEY_EALGS	OAKLEY_AES_CBC, OAKLEY_3DES_CBC
#define DEFAULT_OAKLEY_AALGS	OAKLEY_SHA1, OAKLEY_MD5

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

enum keyword_xauthby {
	XAUTHBY_FILE = 0,
	XAUTHBY_PAM = 1,
	XAUTHBY_ALWAYSOK = 2,
};

enum keyword_xauthfail {
	XAUTHFAIL_HARD = 0,
	XAUTHFAIL_SOFT = 1,
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
	EVENT_LOG_DAILY,		/* reset certain log events/stats */
	EVENT_PENDING_DDNS,		/* try to start connections where DNS failed at init */
	EVENT_SD_WATCHDOG,		/* update systemd's watchdog interval */
	EVENT_PENDING_PHASE2,		/* do not make pending phase2 wait forever */

	/* events associated with states */

	EVENT_SO_DISCARD,		/* v1/v2 discard unfinished state object */
	EVENT_v1_RETRANSMIT,		/* v1 Retransmit IKE packet */
	EVENT_v1_SEND_XAUTH,		/* v1 send xauth request */
	EVENT_SA_REPLACE,		/* v1/v2 SA replacement event */
	EVENT_SA_REPLACE_IF_USED,	/* v1 SA replacement event */
	EVENT_v2_SA_REPLACE_IF_USED_IKE, /* v2 IKE SA, replace if IPSec SA is in use */
	EVENT_v2_SA_REPLACE_IF_USED,    /* v2 IPSEC SA, replace if used */
	EVENT_SA_EXPIRE,		/* v1/v2 SA expiration event */
	EVENT_NAT_T_KEEPALIVE,		/* NAT Traversal Keepalive */
	EVENT_DPD,			/* v1 dead peer detection */
	EVENT_DPD_TIMEOUT,		/* v1 dead peer detection timeout */
	EVENT_CRYPTO_FAILED,		/* v1/v2 after some time, give up on crypto helper */

	EVENT_v2_RETRANSMIT,		/* v2 Initiator: Retransmit IKE packet */
	EVENT_v2_RESPONDER_TIMEOUT,	/* v2 Responder: give up on IKE Initiator */
	EVENT_v2_LIVENESS,		/* for dead peer detection */
	EVENT_v2_RELEASE_WHACK,		/* release the whack fd */
	EVENT_RETAIN,			/* don't change the previous event */
};

#define EVENT_REINIT_SECRET_DELAY	secs_per_hour
#define EVENT_GIVEUP_ON_DNS_DELAY	(5 * secs_per_minute)
#define EVENT_RELEASE_WHACK_DELAY	10	/* seconds */

/*
 * an arbitary milliseconds delay for responder. A workaround for iOS, iPhone.
 * If xauth message arrive before main mode response iPhone may abort.
 */
#define EVENT_v1_SEND_XAUTH_DELAY	80 /* milliseconds */

#define RETRANSMIT_TIMEOUT_DEFAULT	60  /* seconds */
//#define RETRANSMIT_INTERVAL_DEFAULT	500 /* wait time doubled each retransmit - in milliseconds */
#define DELETE_SA_DELAY			RETRANSMIT_TIMEOUT_DEFAULT /* wait until the other side giveup on us */
#define EVENT_CRYPTO_FAILED_DELAY	RETRANSMIT_TIMEOUT_DEFAULT /* wait till the other side give up on us */

/*
 * operational importance of this cryptographic operation.
 * this determines if the operation will be dropped (because the other
 * end will retransmit, if they are legit), if it pertains to an on-going
 * connection, or if it is something that we initiated, and therefore
 * we should do it all costs.
 */
enum crypto_importance {
	pcim_notset_crypto,
	pcim_stranger_crypto,
	pcim_known_crypto,
	pcim_ongoing_crypto,
	pcim_local_crypto,
	pcim_demand_crypto
};

/* is pluto automatically switching busy state or set manually */
enum ddos_mode {
	DDOS_undefined,
	DDOS_AUTO,
	DDOS_FORCE_BUSY,
	DDOS_FORCE_UNLIMITED
};

/* status for state-transition-function
 * Note: STF_FAIL + notification_t means fail with that notification
 */

typedef enum {
	STF_IGNORE,             /* don't respond */
	STF_INLINE,             /* set to this on second time through complete_state_trans */
	STF_SUSPEND,            /* unfinished -- don't release resources */
	STF_OK,                 /* success */
	STF_INTERNAL_ERROR,     /* discard everything, we failed */
	STF_TOOMUCHCRYPTO,      /* at this time, we can't do any more crypto,
				 * so just ignore the message, and let them retransmit.
				 */
	STF_FATAL,              /* just stop. we can't continue. */
	STF_DROP,               /* just stop, delete any state, and don't log or respond */
	STF_FAIL,               /* discard everything, something failed.  notification_t added.
				 * values STF_FAIL + x are notifications.
				 */
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
#define MAX_OUTPUT_UDP_SIZE            65536

#define MAX_IKE_FRAGMENTS       16

#define KERNEL_PROCESS_Q_PERIOD 1 /* seconds */
#define DEFAULT_MAXIMUM_HALFOPEN_IKE_SA 50000 /* fairly arbitrary */
#define DEFAULT_IKE_SA_DDOS_THRESHOLD 25000 /* fairly arbitrary */

#define IPSEC_SA_DEFAULT_REPLAY_WINDOW 32

/* debugging settings: a set of selections for reporting
 * These would be more naturally situated in log.h,
 * but they are shared with whack.
 * IMPAIR_* actually change behaviour, usually badly,
 * to aid in testing.  Naturally, these are not included in ALL.
 *
 * NOTE: changes here must be done in concert with changes to DBGOPT_*
 * in whack.c.  A change to WHACK_MAGIC in whack.h will be required too.
 */

/* Index of DBG/IMPAIR set elements.
 * Note: these are NOT sets: use LELEM to turn these into singletons.
 * Used by whack and pluto.
 * NOTE: when updating/adding x_IX, do so to x in the next table too!
 */
enum {
	DBG_RAW_IX,		/* raw packet I/O */
	DBG_CRYPT_IX,		/* encryption/decryption of messages */
	DBG_PARSING_IX,		/* show decoding of messages */
	DBG_EMITTING_IX,	/* show encoding of messages */
	DBG_CONTROL_IX,		/* control flow within Pluto */
	DBG_LIFECYCLE_IX,	/* SA lifecycle */
	DBG_KERNEL_IX,		/* messages with the kernel */
	DBG_DNS_IX,		/* DNS activity */
	DBG_OPPO_IX,		/* opportunism */
	DBG_CONTROLMORE_IX,	/* more detailed debugging */

	DBG_PFKEY_IX,		/* turn on the pfkey library debugging */
	DBG_NATT_IX,		/* debugging of NAT-traversal */
	DBG_X509_IX,		/* X.509/pkix verify, cert retrival */
	DBG_DPD_IX,		/* DPD items */
	DBG_OPPOINFO_IX,	/* log various informational things about oppo/%trap-keying */
	DBG_WHACKWATCH_IX,	/* never let WHACK go */
	DBG_PRIVATE_IX,		/* displays private information: DANGER! */

	IMPAIR_BUST_MI2_IX,			/* make MI2 really large */
	IMPAIR_BUST_MR2_IX,			/* make MR2 really large */
	IMPAIR_SA_CREATION_IX,			/* fail all SA creation */
	IMPAIR_DIE_ONINFO_IX,			/* cause state to be deleted upon receipt of information payload */
	IMPAIR_JACOB_TWO_TWO_IX,		/* cause pluto to send all messages twice. */
						/* cause pluto to send all messages twice. */
	IMPAIR_MAJOR_VERSION_BUMP_IX,		/* cause pluto to send an IKE major version that's higher then we support. */
	IMPAIR_MINOR_VERSION_BUMP_IX,		/* cause pluto to send an IKE minor version that's higher then we support. */
	IMPAIR_RETRANSMITS_IX,			/* cause pluto to never retransmit */
	IMPAIR_SEND_BOGUS_PAYLOAD_FLAG_IX,	/* causes pluto to set a RESERVED PAYLOAD flag to test ignoring/zeroing it */
	IMPAIR_SEND_BOGUS_ISAKMP_FLAG_IX,	/* causes pluto to set a RESERVED ISAKMP flag to test ignoring/zeroing it */
	IMPAIR_SEND_IKEv2_KE_IX,		/* causes pluto to omit sending the KE payload in IKEv2 */
	IMPAIR_SEND_NO_DELETE_IX,		/* causes pluto to omit sending Notify/Delete messages */
	IMPAIR_SEND_NO_IKEV2_AUTH_IX,		/* causes pluto to omit sending an IKEv2 IKE_AUTH packet */
	IMPAIR_FORCE_FIPS_IX,			/* causes pluto to believe we are in fips mode, NSS needs its own hack */
	IMPAIR_SEND_KEY_SIZE_CHECK_IX,		/* causes pluto to omit checking configured ESP key sizes for testing */
	IMPAIR_SEND_ZERO_GX_IX,			/* causes pluto to send a g^x that is zero, breaking DH calculation */
	IMPAIR_SEND_BOGUS_DCOOKIE_IX,		/* causes pluto to send a a bogus IKEv2 DCOOKIE */
	IMPAIR_roof_IX	/* first unassigned IMPAIR */
};

/* Sets of Debug / Impair items */
#define DBG_NONE        0                                       /* no options on, including impairments */
#define DBG_ALL         LRANGES(DBG_RAW, DBG_OPPOINFO)          /* all logging options on EXCEPT DBG_PRIVATE and DBG_WHACKWATCH */

/* singleton sets: must be kept in sync with the items! */

#define DBG_RAW	LELEM(DBG_RAW_IX)
#define DBG_CRYPT	LELEM(DBG_CRYPT_IX)
#define DBG_PARSING	LELEM(DBG_PARSING_IX)
#define DBG_EMITTING	LELEM(DBG_EMITTING_IX)
#define DBG_CONTROL	LELEM(DBG_CONTROL_IX)
#define DBG_LIFECYCLE	LELEM(DBG_LIFECYCLE_IX)
#define DBG_KERNEL	LELEM(DBG_KERNEL_IX)
#define DBG_DNS		LELEM(DBG_DNS_IX)
#define DBG_OPPO	LELEM(DBG_OPPO_IX)
#define DBG_CONTROLMORE	LELEM(DBG_CONTROLMORE_IX)
#define DBG_PFKEY	LELEM(DBG_PFKEY_IX)
#define DBG_NATT	LELEM(DBG_NATT_IX)
#define DBG_X509	LELEM(DBG_X509_IX)
#define DBG_DPD		LELEM(DBG_DPD_IX)
#define DBG_OPPOINFO	LELEM(DBG_OPPOINFO_IX)
#define DBG_WHACKWATCH	LELEM(DBG_WHACKWATCH_IX)

#define DBG_PRIVATE	LELEM(DBG_PRIVATE_IX)

#define IMPAIR_BUST_MI2	LELEM(IMPAIR_BUST_MI2_IX)
#define IMPAIR_BUST_MR2	LELEM(IMPAIR_BUST_MR2_IX)
#define IMPAIR_SA_CREATION	LELEM(IMPAIR_SA_CREATION_IX)
#define IMPAIR_DIE_ONINFO	LELEM(IMPAIR_DIE_ONINFO_IX)
#define IMPAIR_JACOB_TWO_TWO	LELEM(IMPAIR_JACOB_TWO_TWO_IX)
#define IMPAIR_MAJOR_VERSION_BUMP	LELEM(IMPAIR_MAJOR_VERSION_BUMP_IX)
#define IMPAIR_MINOR_VERSION_BUMP	LELEM(IMPAIR_MINOR_VERSION_BUMP_IX)
#define IMPAIR_RETRANSMITS	LELEM(IMPAIR_RETRANSMITS_IX)
#define IMPAIR_SEND_BOGUS_PAYLOAD_FLAG	LELEM(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG_IX)
#define IMPAIR_SEND_BOGUS_ISAKMP_FLAG	LELEM(IMPAIR_SEND_BOGUS_ISAKMP_FLAG_IX)
#define IMPAIR_SEND_IKEv2_KE	LELEM(IMPAIR_SEND_IKEv2_KE_IX)
#define IMPAIR_SEND_NO_DELETE	LELEM(IMPAIR_SEND_NO_DELETE_IX)
#define IMPAIR_SEND_NO_IKEV2_AUTH	LELEM(IMPAIR_SEND_NO_IKEV2_AUTH_IX)
#define IMPAIR_FORCE_FIPS	LELEM(IMPAIR_FORCE_FIPS_IX)
#define IMPAIR_SEND_KEY_SIZE_CHECK	LELEM(IMPAIR_SEND_KEY_SIZE_CHECK_IX)
#define IMPAIR_SEND_ZERO_GX	LELEM(IMPAIR_SEND_ZERO_GX_IX)
#define IMPAIR_SEND_BOGUS_DCOOKIE	LELEM(IMPAIR_SEND_BOGUS_DCOOKIE_IX)

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
	STATE_UNDEFINED = 0,

	/*  Opportunism states: see "Opportunistic Encryption" 2.2 */

	OPPO_ACQUIRE,           /* got an ACQUIRE message for this pair */
	OPPO_GW_DISCOVERED,     /* got TXT specifying gateway */

	/* IKE states */

	STATE_MAIN_R0,
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
	STATE_IKE_ROOF, /* rename to STATE_IKEv1_ROOF */

	/*
	 * IKEv2 states.
	 * Note that message reliably sending is done by initiator only,
	 * unlike with IKEv1.
	 */
	STATE_IKEv2_BASE,	/* state when faking a state */

	/* INITIATOR states */
	STATE_PARENT_I1,        /* IKE_SA_INIT: sent initial message, waiting for reply */
	STATE_PARENT_I2,        /* IKE_AUTH: sent auth message, waiting for reply */
	STATE_PARENT_I3,        /* IKE_AUTH done: received auth response */

	/*
	 * RESPONDER states
	 * No real actions, initiator is responsible
	 * for all work states.
	 * ??? what does that mean?
	 */
	STATE_PARENT_R1,	/* IKE_SA_INIT: sent response */
	STATE_PARENT_R2,	/* IKE_AUTH: sent response */

	/* IKEv2 Delete States */
	STATE_IKESA_DEL,
	STATE_CHILDSA_DEL,

	STATE_IKEv2_ROOF,
};
#define STATE_IKE_FLOOR STATE_MAIN_R0
/* rename to STATE_IKE_ROOF, see above */
#define MAX_STATES STATE_IKEv2_ROOF


/*
 * The IKEv2 (RFC 7296) original role - either the "original
 * initiator" or the "original responder" - as determined by the "I
 * (Initiator)" flag in the (ISAKMP_FLAGS_v2_IKE_I) in the payload
 * header.  The "original initiator" either sent: the initial INIT
 * packet; or, the CREATE_CHILD_SA rekey-ike request.
 *
 * The bit is used to identify which keying material to use when
 * encrypting and decrypting SK payloads.
 *
 * Separate to this is the IKEv2 "R (Response)" flag
 * (ISAKMP_FLAGS_v2_MSG_R) in the payload header.  The response flag
 * that a message is a response to a previous request.  Since either
 * end can send requests, either end can also set the "R" flag.
 *
 * The IKEv1 equivalent is the phase1 role.  It is identified by the
 * IKEv1 IS_PHASE1_INIT() macro.
 */
enum original_role {
	ORIGINAL_INITIATOR = 1,
	ORIGINAL_RESPONDER = 2
};


#define PHASE1_INITIATOR_STATES  (LELEM(STATE_MAIN_I1) | \
				  LELEM(STATE_MAIN_I2) | \
				  LELEM(STATE_MAIN_I3) | \
				  LELEM(STATE_MAIN_I4) | \
				  LELEM(STATE_AGGR_I1) | \
				  LELEM(STATE_AGGR_I2) | \
				  LELEM(STATE_XAUTH_I0) | \
				  LELEM(STATE_XAUTH_I1) | \
				  LELEM(STATE_MODE_CFG_I1) | \
				  LELEM(STATE_PARENT_I1) | \
				  LELEM(STATE_PARENT_I2))


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
#define IS_ISAKMP_AUTHENTICATED(s) (STATE_MAIN_R3 <= (s) \
				    && STATE_AGGR_R0 != (s) \
				    && STATE_AGGR_I1 != (s))

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
				       LELEM(STATE_XAUTH_I1))

#define IS_ISAKMP_SA_ESTABLISHED(s) ((LELEM(s) & ISAKMP_SA_ESTABLISHED_STATES) != LEMPTY)

/* IKEv1 or IKEv2 */
#define IS_IPSEC_SA_ESTABLISHED(s) ((s) == STATE_QUICK_I2 || \
				    (s) == STATE_QUICK_R1 || \
				    (s) == STATE_QUICK_R2 || \
				    (s) == STATE_PARENT_I3 || \
				    (s) == STATE_PARENT_R2)

#define IS_MODE_CFG_ESTABLISHED(s) ((s) == STATE_MODE_CFG_R2)

/* Only relevant to IKEv2 */

/* adding for just a R2 or I3 check. Will need to be changed when parent/child discerning is fixed */

#define IS_V2_ESTABLISHED(s) ((s) == STATE_PARENT_R2 || (s) == STATE_PARENT_I3)

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
    ((st->st_state == STATE_PARENT_I3 || st->st_state == STATE_PARENT_R2) && \
      IS_CHILD_SA(st))

#define IS_PARENT_SA_ESTABLISHED(st) \
    ((st->st_state == STATE_PARENT_I3 || st->st_state == STATE_PARENT_R2) \
	&& !IS_CHILD_SA(st))

#define IS_CHILD_SA(st)  ((st)->st_clonedfrom != SOS_NOBODY)

#define IS_PARENT_SA(st) (!IS_CHILD_SA(st))

#define IS_IKE_SA(st) ( (st->st_clonedfrom == SOS_NOBODY) &&  (IS_PHASE1(st->st_state) || IS_PHASE15(st->st_state) || \
		IS_PARENT_SA(st)) )

#define IS_PARENT_STATE(s) ((s) >= STATE_PARENT_I1 && (s) <= STATE_IKESA_DEL)
#define IS_IKE_STATE(s) (IS_PHASE1(s) || IS_PHASE15(s) || IS_PARENT_STATE(s))

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
	cert_neversend   = 1,
	cert_sendifasked = 2,   /* the default */
	cert_alwayssend  = 3,
};

/* this is the default setting. */
#define cert_defaultcertpolicy cert_alwayssend

enum ikev1_natt_policy {
	natt_both = 0, /* the default */
	natt_rfc = 1,
	natt_drafts = 2 /* Workaround for Cisco NAT-T bug */
};

enum four_options {
	fo_never   = 0,         /* do not propose, do not permit */
	fo_permit  = 1,         /* do not propose, but permit peer to propose */
	fo_propose = 2,         /* propose, and permit, but do not insist  */
	fo_insist  = 3          /* propose, and only accept if peer agrees */
};

enum esn_options {
	esn_no = 1, /* default */
	esn_yes = 2,
	esn_either = 3,
};
enum ynf_options {
	ynf_no   = 0,
	ynf_yes  = 1,
	ynf_force = 2,
};

enum saref_tracking {
	sat_yes = 0,            /* SAref tracking via _updown - the default */
	sat_no = 1,             /* no SAref tracking - third party will handle this */
	sat_conntrack = 2,      /* Saref tracking using connmark optimizations */
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
	POLICY_PSK_IX,
	POLICY_RSASIG_IX,
	POLICY_AUTH_NULL_IX,
#define POLICY_ISAKMP_SHIFT	POLICY_PSK_IX

	/* policies that affect ID types that are acceptable - RSA, PSK, XAUTH
	* ??? This set constant certainly doesn't include XAUTH.
	*/
#define POLICY_ID_AUTH_MASK	LRANGE(POLICY_PSK_IX, POLICY_AUTH_NULL_IX)

	/* Quick Mode (IPSEC) attributes */
	POLICY_ENCRYPT_IX,	/* must be first of IPSEC policies */
	POLICY_AUTHENTICATE_IX,	/* must be second */
	POLICY_COMPRESS_IX,	/* must be third */
	POLICY_TUNNEL_IX,
	POLICY_PFS_IX,
	POLICY_DISABLEARRIVALCHECK_IX,	/* supress tunnel egress address checking */

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
	POLICY_ESN_NO_IX,		/* send/accept ESNno */
	POLICY_ESN_YES_IX,		/* send/accept ESNyes */
#define POLICY_IX_LAST	POLICY_ESN_YES_IX
};

#define POLICY_PSK	LELEM(POLICY_PSK_IX)
#define POLICY_RSASIG	LELEM(POLICY_RSASIG_IX)
#define POLICY_AUTH_NULL LELEM(POLICY_AUTH_NULL_IX)
#define POLICY_ENCRYPT	LELEM(POLICY_ENCRYPT_IX)	/* must be first of IPSEC policies */
#define POLICY_AUTHENTICATE	LELEM(POLICY_AUTHENTICATE_IX)	/* must be second */
#define POLICY_COMPRESS	LELEM(POLICY_COMPRESS_IX)	/* must be third */
#define POLICY_TUNNEL	LELEM(POLICY_TUNNEL_IX)
#define POLICY_PFS	LELEM(POLICY_PFS_IX)
#define POLICY_DISABLEARRIVALCHECK	LELEM(POLICY_DISABLEARRIVALCHECK_IX)	/* supress tunnel egress address checking */
#define POLICY_SHUNT0	LELEM(POLICY_SHUNT0_IX)
#define POLICY_SHUNT1	LELEM(POLICY_SHUNT1_IX)
#define POLICY_FAIL0	LELEM(POLICY_FAIL0_IX)
#define POLICY_FAIL1	LELEM(POLICY_FAIL1_IX)
#define POLICY_NEGO_PASS	LELEM(POLICY_NEGO_PASS_IX)	/* install %pass during initial IKE */
#define POLICY_DONT_REKEY	LELEM(POLICY_DONT_REKEY_IX)	/* don't rekey state either Phase */
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
#define POLICY_ESN_NO		LELEM(POLICY_ESN_NO_IX)	/* accept or request ESNno */
#define POLICY_ESN_YES		LELEM(POLICY_ESN_YES_IX)	/* accept or request ESNyes */

/* These policy bits must match exactly: POLICY_XAUTH, POLICY_AGGRESSIVE, POLICY_IKEV1_ALLOW */

/* Any IPsec policy?  If not, a connection description
 * is only for ISAKMP SA, not IPSEC SA.  (A pun, I admit.)
 * Note: a connection can only be routed if it is NEVER_NEGOTIATE
 * or HAS_IPSEC_POLICY.
 */
#define HAS_IPSEC_POLICY(p) (((p) & POLICY_IPSEC_MASK) != 0)

/* Don't allow negotiation? */
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

/* BIND enumerated types */

/* How authenticated is info that might have come from DNS?
 * In order of increasing confidence.
 */
enum dns_auth_level {
	DAL_UNSIGNED,   /* AD in response, but no signature: no authentication */
	DAL_NOTSEC,     /* no AD in response: authentication impossible */
	DAL_SIGNED,     /* AD and signature in response: authentic */
	DAL_LOCAL       /* locally provided (pretty good) */
};

/*
 * define a macro for use in error messages
 */

#ifdef USE_KEYRR
#define RRNAME "TXT or KEY"
#else
#define RRNAME "TXT"
#endif

/*
 * private key types for keys.h
 */
enum PrivateKeyKind {
	/* start at one so accidental 0 will not match */
	PPK_PSK = 1,
	PPK_RSA,
	PPK_XAUTH,
	PPK_NULL,
};

#define XAUTH_PROMPT_TRIES 3
#define MAX_USERNAME_LEN 128
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
	PLUTO_EXIT_LOCK_FAIL = 10, /* historic value */
};

extern void init_pluto_constants(void);
