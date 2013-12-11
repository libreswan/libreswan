/* manifest constants
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
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
	DPD_ACTION_CLEAR = 0,
	DPD_ACTION_HOLD  = 1,
	DPD_ACTION_RESTART = 2
};

/* Cisco interop: values remote_peer_type= */
enum keyword_remotepeertype {
	NON_CISCO = 0,
	CISCO  = 1,
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

/*
 *  * NAT-Traversal defines for nat_traveral type from nat_traversal.h
 *   *
 *    */
enum natt_method {
	NAT_TRAVERSAL_METHOD_IETF_00_01     =1,
	NAT_TRAVERSAL_METHOD_IETF_02_03     =2,
	NAT_TRAVERSAL_METHOD_IETF_05        =3,
	NAT_TRAVERSAL_METHOD_IETF_RFC       =4,

	NAT_TRAVERSAL_NAT_BHND_ME           =30,
	NAT_TRAVERSAL_NAT_BHND_PEER         =31
};

/* Timer events */

enum event_type {
	EVENT_NULL,                     /* non-event */
	EVENT_REINIT_SECRET,            /* Refresh cookie secret */
	EVENT_SHUNT_SCAN,               /* scan shunt eroutes known to kernel */
	EVENT_SO_DISCARD,               /* discard unfinished state object */
	EVENT_RETRANSMIT,               /* Retransmit packet */
	EVENT_SA_REPLACE,               /* SA replacement event */
	EVENT_SA_REPLACE_IF_USED,       /* SA replacement event */
	EVENT_SA_EXPIRE,                /* SA expiration event */
	EVENT_NAT_T_KEEPALIVE,          /* NAT Traversal Keepalive */
	EVENT_DPD,                      /* dead peer detection */
	EVENT_DPD_TIMEOUT,              /* dead peer detection timeout */

	EVENT_LOG_DAILY,                /* reset certain log events/stats */
	EVENT_CRYPTO_FAILED,            /* after some time, give up on crypto helper */
	EVENT_PENDING_PHASE2,           /* do not make pending phase2 wait forever */
	EVENT_v2_RETRANSMIT,            /* Retransmit v2 packet */
	EVENT_v2_LIVENESS,
	EVENT_PENDING_DDNS,             /* try to start connections where DNS failed at init */
};

#define EVENT_REINIT_SECRET_DELAY               3600    /* 1 hour */
#define EVENT_CRYPTO_FAILED_DELAY               300
#define EVENT_RETRANSMIT_DELAY_0                10      /* 10 seconds */
#define EVENT_GIVEUP_ON_DNS_DELAY               300     /* 5 minutes for DNS */

/*
 * cryptographic helper operations.
 */
enum pluto_crypto_requests {
	pcr_build_kenonce  = 1,
	pcr_rsa_sign       = 2,
	pcr_rsa_check      = 3,
	pcr_x509cert_fetch = 4,
	pcr_x509crl_fetch  = 5,
	pcr_build_nonce    = 6,
	pcr_compute_dh_iv  = 7, /* perform phase 1 calculation: DH + prf */
	pcr_compute_dh     = 8, /* perform phase 2 PFS DH */
	pcr_compute_dh_v2  = 9, /* perform IKEv2 PARENT SA calculation, create SKEYSEED */
};

/*
 * operational importance of this cryptographic operation.
 * this determines if the operation will be dropped (because the other
 * end will retransmit, if they are legit), if it pertains to an on-going
 * connection, or if it is something that we initiated, and therefore
 * we should do it all costs.
 */
enum crypto_importance {
	pcim_notset_crypto=0,
	pcim_stranger_crypto = 1,
	pcim_known_crypto    = 2,
	pcim_ongoing_crypto  = 3,
	pcim_local_crypto    = 4,
	pcim_demand_crypto   = 5
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
	STF_STOLEN,             /* only used by TaProoM */
	STF_FAIL,               /* discard everything, something failed.  notification_t added.
	                         * values STF_FAIL + x are notifications.
	                         */
} stf_status;

/* Misc. stuff */

#define MAXIMUM_RETRANSMISSIONS              2
#define MAXIMUM_RETRANSMISSIONS_INITIAL      20
#define MAXIMUM_RETRANSMISSIONS_QUICK_R1     20

#define MAXIMUM_MALFORMED_NOTIFY             16

#define MAX_INPUT_UDP_SIZE             65536
#define MAX_OUTPUT_UDP_SIZE            65536

#define MAX_IKE_FRAGMENTS       16

/* debugging settings: a set of selections for reporting
 * These would be more naturally situated in log.h,
 * but they are shared with whack.
 * IMPAIR_* actually change behaviour, usually badly,
 * to aid in testing.  Naturally, these are not included in ALL.
 *
 * NOTE: changes here must be done in concert with changes to DBGOPT_*
 * in whack.c.  A change to WHACK_MAGIC in whack.h will be required too.
 */
#ifdef DEBUG

#define DBG_RAW         LELEM(0)                                /* raw packet I/O */
#define DBG_CRYPT       LELEM(1)                                /* encryption/decryption of messages */
#define DBG_PARSING     LELEM(2)                                /* show decoding of messages */
#define DBG_EMITTING    LELEM(3)                                /* show encoding of messages */
#define DBG_CONTROL     LELEM(4)                                /* control flow within Pluto */
#define DBG_LIFECYCLE   LELEM(5)                                /* SA lifecycle */
#define DBG_KERNEL      LELEM(6)                                /* messages with the kernel */
#define DBG_DNS         LELEM(7)                                /* DNS activity */
#define DBG_OPPO        LELEM(8)                                /* opportunism */
#define DBG_CONTROLMORE LELEM(9)                                /* more detailed debugging */

#define DBG_PFKEY       LELEM(10)                               /*turn on the pfkey library debugging*/
#define DBG_NATT        LELEM(11)                               /* debugging of NAT-traversal */
#define DBG_X509        LELEM(12)                               /* X.509/pkix verify, cert retrival */
#define DBG_DPD         LELEM(13)                               /* DPD items */
#define DBG_OPPOINFO    LELEM(14)                               /* log various informational things about oppo/%trap-keying */
#define DBG_WHACKWATCH  LELEM(15)                               /* never let WHACK go */
#define DBG_PRIVATE     LELEM(20)                               /* private information: DANGER! */

#define IMPAIR0 21                                              /* first bit for IMPAIR_* */

#define IMPAIR_DELAY_ADNS_KEY_ANSWER    LELEM(IMPAIR0 + 0)      /* sleep before answering */
#define IMPAIR_DELAY_ADNS_TXT_ANSWER    LELEM(IMPAIR0 + 1)      /* sleep before answering */
#define IMPAIR_BUST_MI2 LELEM(IMPAIR0 + 2)                      /* make MI2 really large */
#define IMPAIR_BUST_MR2 LELEM(IMPAIR0 + 3)                      /* make MR2 really large */
#define IMPAIR_SA_CREATION LELEM(IMPAIR0 + 4)                   /* fail all SA creation */
#define IMPAIR_DIE_ONINFO  LELEM(IMPAIR0 + 5)                   /* cause state to be deleted upon receipt of information payload */
#define IMPAIR_JACOB_TWO_TWO LELEM(IMPAIR0 + 6)                 /* cause pluto to send all messages twice. */
                                                                /* cause pluto to send all messages twice. */
#define IMPAIR_MAJOR_VERSION_BUMP LELEM(IMPAIR0 + 7)            /* cause pluto to send an IKE major version that's higher then we support. */
#define IMPAIR_MINOR_VERSION_BUMP LELEM(IMPAIR0 + 8)            /* cause pluto to send an IKE minor version that's higher then we support. */
#define IMPAIR_RETRANSMITS LELEM(IMPAIR0 + 9)                   /* cause pluto to never retransmit */
#define IMPAIR_SEND_BOGUS_ISAKMP_FLAG LELEM(IMPAIR0 + 10)       /* causes pluto to set a RESERVED ISAKMP flag to test ignoring/zeroing it */

#define DBG_NONE        0                                       /* no options on, including impairments */
#define DBG_ALL         LRANGES(DBG_RAW, DBG_OPPOINFO)          /* all logging options on EXCEPT DBG_PRIVATE and DBG_WHACKWATCH */
#endif

/* State of exchanges
 *
 * The name of the state describes the last message sent, not the
 * message currently being input or output (except during retry).
 * In effect, the state represents the last completed action.
 *
 * Messages are named [MQ][IR]n where
 * - M stands for Main Mode (Phase 1);
 *   Q stands for Quick Mode (Phase 2)
 * - I stands for Initiator;
 *   R stands for Responder
 * - n, a digit, stands for the number of the message
 *
 * It would be more convenient if each state accepted a message
 * and produced one.  This is the case for states at the start
 * or end of an exchange.  To fix this, we pretend that there are
 * MR0 and QR0 messages before the MI1 and QR1 messages.  Similarly,
 * we pretend that there are MR4 and QR2 messages.
 *
 * STATE_MAIN_R0 and STATE_QUICK_R0 are intermediate states (not
 * retained between messages) representing the state that accepts the
 * first message of an exchange has been read but not processed.
 *
 * v1_state_microcode_table in ikev1.c and
 * v2_state_microcode_table in ikev2.c describe
 * other important details.
 */

enum state_kind {
	STATE_UNDEFINED=0, /* 0 -- most likely accident */

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
	STATE_IKE_ROOF,

	/* IKEv2 states.
	 * Note that message reliably sending is done by initiator only,
	 * unlike with IKEv1.
	 */
	STATE_IKEv2_BASE,
	/* INITIATOR states */
	STATE_PARENT_I1,        /* sent initial message, waiting for reply */
	STATE_PARENT_I2,        /* sent auth message, waiting for reply */
	STATE_PARENT_I3,        /* received auth message, done. */

	/* RESPONDER states  --- no real actions, initiator is responsible
	 * for all work states. */
	STATE_PARENT_R1,
	STATE_PARENT_R2,

	/* IKEv2 Delete States */
	STATE_IKESA_DEL,
	STATE_CHILDSA_DEL,

	STATE_IKEv2_ROOF,
};

enum phase1_role {
	INITIATOR=1,
	RESPONDER=2
};

#define STATE_IKE_FLOOR STATE_MAIN_R0

#define PHASE1_INITIATOR_STATES  (LELEM(STATE_MAIN_I1) | LELEM(STATE_MAIN_I2) \
				  | LELEM(STATE_MAIN_I3) | LELEM(STATE_MAIN_I4) \
				  | LELEM(STATE_AGGR_I1) | LELEM(STATE_AGGR_I2) \
				  | LELEM(STATE_XAUTH_I0) | \
				  LELEM(STATE_XAUTH_I1) \
				  | LELEM(STATE_MODE_CFG_I1))
#define IS_PHASE1_INIT(s)         ((s) == STATE_MAIN_I1 \
				   || (s) == STATE_MAIN_I2 \
				   || (s) == STATE_MAIN_I3 \
				   || (s) == STATE_MAIN_I4 \
				   || (s) == STATE_AGGR_I1 \
				   || (s) == STATE_AGGR_I2 \
				   || (s) == STATE_XAUTH_I0 \
				   || (s) == STATE_XAUTH_I1 \
				   || (s) == STATE_MODE_CFG_I1)
#define IS_PHASE1(s) (STATE_MAIN_R0 <= (s) && (s) <= STATE_AGGR_R2)
#define IS_PHASE15(s) (STATE_XAUTH_R0 <= (s) && (s) <= STATE_XAUTH_I1)
#define IS_QUICK(s) (STATE_QUICK_R0 <= (s) && (s) <= STATE_QUICK_R2)
#define IS_ISAKMP_ENCRYPTED(s)     (STATE_MAIN_R2 <= (s) && STATE_AGGR_R0 != \
				    (s) && STATE_AGGR_I1 != (s) && \
				    STATE_INFO != (s))
#define IS_ISAKMP_AUTHENTICATED(s) (STATE_MAIN_R3 <= (s) && STATE_AGGR_R0 != \
				    (s) && STATE_AGGR_I1 != (s))
#define IS_ISAKMP_SA_ESTABLISHED(s) ((s) == STATE_MAIN_R3 || (s) == \
				     STATE_MAIN_I4 \
				     || (s) == STATE_AGGR_I2 || (s) == \
				     STATE_AGGR_R2 \
				     || (s) == STATE_XAUTH_R0 || (s) == \
				     STATE_XAUTH_R1 \
				     || (s) == STATE_MODE_CFG_R0 || (s) == \
				     STATE_MODE_CFG_R1 \
				     || (s) == STATE_MODE_CFG_R2 || (s) == \
				     STATE_MODE_CFG_I1 \
				     || (s) == STATE_XAUTH_I0 || (s) == \
				     STATE_XAUTH_I1)
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

#define IS_IPSEC_SA_ESTABLISHED(s) ((s) == STATE_QUICK_I2 || (s) == \
				    STATE_QUICK_R2)
#define IS_ONLY_INBOUND_IPSEC_SA_ESTABLISHED(s) ((s) == STATE_QUICK_R1)
#define IS_MODE_CFG_ESTABLISHED(s) ((s) == STATE_MODE_CFG_R2)

/* adding for just a R2 or I3 check. Will need to be changed when parent/child discerning is fixed */
#define IS_V2_ESTABLISHED(s) ((s) == STATE_PARENT_R2 || (s) == STATE_PARENT_I3)

#define IS_PARENT_SA_ESTABLISHED(s) ((s) == STATE_PARENT_I2 || (s) == \
				     STATE_PARENT_R1 || (s) == STATE_IKESA_DEL)
/*
 * Issue here is that our child sa appears as a STATE_PARENT_I3/STATE_PARENT_R2 state which it should not
 * So we fall back to checking if it is cloned, and therefor really a child
 */
#define IS_CHILD_SA_ESTABLISHED(st) ( (((st->st_state == STATE_PARENT_I3) || \
					(st->st_state == STATE_PARENT_R2)) && \
				       (st->st_clonedfrom != SOS_NOBODY)) || \
				      (st->st_state == STATE_CHILDSA_DEL) )

#define IS_CHILD_SA(st)  ((st)->st_clonedfrom != SOS_NOBODY)
#define IS_PARENT_SA(st) (!IS_CHILD_SA(st))

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
	RT_UNROUTED_KEYED       /* keyed, but not routed, on purpose */
};

#define routed(rs) ((rs) > RT_UNROUTED_HOLD)
#define erouted(rs) ((rs) != RT_UNROUTED)
#define shunt_erouted(rs) (erouted(rs) && (rs) != RT_ROUTED_TUNNEL)

enum certpolicy {
	cert_neversend   = 1,
	cert_sendifasked = 2,   /* the default */
	cert_alwayssend  = 3,
	cert_forcedtype  = 4,   /* send a Cert payload with given type */
};

/* this is the default setting. */
#define cert_defaultcertpolicy cert_alwayssend

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
 * ISAKMP auth techniques (none means never negotiate)
 * a pluto policy is stored in a lset_t which is an unsigned long long,
 * so we should have 64 bits to play with
 */
enum pluto_policy {
	POLICY_PSK     = LELEM(0),
	POLICY_RSASIG  = LELEM(1),
#define POLICY_ISAKMP_SHIFT     0       /* log2(POLICY_PSK) */

/* policies that affect ID types that are acceptable - RSA, PSK, XAUTH */
	POLICY_ID_AUTH_MASK=LRANGES(POLICY_PSK, POLICY_RSASIG),

/* policies that affect choices of proposal, note, does not include XAUTH */
#define POLICY_ISAKMP(x, xs, xc)  (((x) & LRANGES(POLICY_PSK, POLICY_RSASIG)) + \
				   ((xs) * 4) + ((xc) * 8))

/* Quick Mode (IPSEC) attributes */
	POLICY_ENCRYPT = LELEM(2),      /* must be first of IPSEC policies */
	POLICY_AUTHENTICATE=LELEM(3),   /* must be second */
	POLICY_COMPRESS=LELEM(4),       /* must be third */
	POLICY_TUNNEL  = LELEM(5),
	POLICY_PFS     = LELEM(6),
	POLICY_DISABLEARRIVALCHECK = LELEM(7),  /* supress tunnel egress address checking */

#define POLICY_IPSEC_SHIFT      2               /* log2(POLICY_ENCRYPT) */
	POLICY_IPSEC_MASK =
		LRANGES(POLICY_ENCRYPT, POLICY_DISABLEARRIVALCHECK),

/* shunt attributes: what to do when routed without tunnel (2 bits) */
	POLICY_SHUNT_SHIFT = 8,                                 /* log2(POLICY_SHUNT_PASS) */
	POLICY_SHUNT_MASK  = (03ul << POLICY_SHUNT_SHIFT),
	POLICY_SHUNT_TRAP  = (0ul << POLICY_SHUNT_SHIFT),       /* default: negotiate */
	POLICY_SHUNT_PASS  = (1ul << POLICY_SHUNT_SHIFT),
	POLICY_SHUNT_DROP  = (2ul << POLICY_SHUNT_SHIFT),
	POLICY_SHUNT_REJECT=(3ul << POLICY_SHUNT_SHIFT),

/* fail attributes: what to do with failed negotiation (2 bits) */

	POLICY_FAIL_SHIFT  = 10,        /* log2(POLICY_FAIL_PASS) */
	POLICY_FAIL_MASK   = (03ul << POLICY_FAIL_SHIFT),

	POLICY_FAIL_NONE   = (0ul << POLICY_FAIL_SHIFT), /* default */
	POLICY_FAIL_PASS   = (1ul << POLICY_FAIL_SHIFT),
	POLICY_FAIL_DROP   = (2ul << POLICY_FAIL_SHIFT),
	POLICY_FAIL_REJECT = (3ul << POLICY_FAIL_SHIFT),

/* connection policy
 * Other policies could vary per state object.  These live in connection.
 */
	POLICY_DONT_REKEY   = LELEM(12),        /* don't rekey state either Phase */
	POLICY_OPPO         = LELEM(13),        /* is this opportunistic? */
	POLICY_GROUP        = LELEM(14),        /* is this a group template? */
	POLICY_GROUTED      = LELEM(15),        /* do we want this group routed? */
	POLICY_UP           = LELEM(16),        /* do we want this up? */
	POLICY_XAUTH        = LELEM(17),        /* do we offer XAUTH? */
	POLICY_MODECFG_PULL = LELEM(18),        /* is modecfg pulled by client? */
	POLICY_AGGRESSIVE   = LELEM(19),        /* do we do aggressive mode? */
	POLICY_PERHOST      = LELEM(20),        /* should we specialize the policy to the host? */
	POLICY_SUBHOST      = LELEM(21),        /* if the policy applies below the host level (TCP/UDP/SCTP ports), */
	POLICY_PERPROTO     = LELEM(22),        /* should we specialize the policy to the protocol? */
	POLICY_OVERLAPIP    = LELEM(23),        /* can two conns that have subnet=vhost: declare the same IP? */

	/*
	 * this is mapped by parser's ikev2={four_state}. It is a bit richer
	 * in that we can actually turn off everything, but it expands more
	 * sensibly to an IKEv3 and other methods.
	 */
	POLICY_IKEV1_DISABLE = LELEM(24),       /* !accept IKEv1?  0x0100 0000 */
	POLICY_IKEV2_ALLOW   = LELEM(25),       /* accept IKEv2?   0x0200 0000 */
	POLICY_IKEV2_PROPOSE = LELEM(26),       /* propose IKEv2?  0x0400 0000 */
	POLICY_IKEV2_MASK = POLICY_IKEV1_DISABLE | POLICY_IKEV2_ALLOW |
			    POLICY_IKEV2_PROPOSE,
	POLICY_IKEV2_ALLOW_NARROWING = LELEM(27),       /* Allow RFC-5669 section 2.9? 0x0800 0000 */

	POLICY_SAREF_TRACK    = LELEM(28),              /* Saref tracking via _updown */
	POLICY_SAREF_TRACK_CONNTRACK    = LELEM(29),    /* use conntrack optimization */

	POLICY_IKE_FRAG_ALLOW = LELEM(30),
	POLICY_IKE_FRAG_FORCE = LELEM(31),
	POLICY_IKE_FRAG_MASK = POLICY_IKE_FRAG_ALLOW | POLICY_IKE_FRAG_FORCE,
	POLICY_NO_IKEPAD      = LELEM(32),      /* pad ike packets to 4 bytes or not */

	/* policy used to be an int, but is now lset_t (unsigned long long type), so max is 63 */
};

/* Any IPsec policy?  If not, a connection description
 * is only for ISAKMP SA, not IPSEC SA.  (A pun, I admit.)
 * Note: a connection can only be routed if it is NEVER_NEGOTIATE
 * or HAS_IPSEC_POLICY.
 */
#define HAS_IPSEC_POLICY(p) (((p) & POLICY_IPSEC_MASK) != 0)

/* Don't allow negotiation? */
#define NEVER_NEGOTIATE(p)  (LDISJOINT((p), POLICY_PSK | POLICY_RSASIG | \
				       POLICY_AGGRESSIVE) || \
			     (((p) & POLICY_SHUNT_MASK) != POLICY_SHUNT_TRAP))

/* Oakley transform attributes
 * draft-ietf-ipsec-ike-01.txt appendix A
 */

#define OAKLEY_ENCRYPTION_ALGORITHM    1
#define OAKLEY_HASH_ALGORITHM          2
#define OAKLEY_AUTHENTICATION_METHOD   3
#define OAKLEY_GROUP_DESCRIPTION       4
#define OAKLEY_GROUP_TYPE              5
#define OAKLEY_GROUP_PRIME             6        /* B/V */
#define OAKLEY_GROUP_GENERATOR_ONE     7        /* B/V */
#define OAKLEY_GROUP_GENERATOR_TWO     8        /* B/V */
#define OAKLEY_GROUP_CURVE_A           9        /* B/V */
#define OAKLEY_GROUP_CURVE_B          10        /* B/V */
#define OAKLEY_LIFE_TYPE              11
#define OAKLEY_LIFE_DURATION          12        /* B/V */
#define OAKLEY_PRF                    13
#define OAKLEY_KEY_LENGTH             14
#define OAKLEY_FIELD_SIZE             15
#define OAKLEY_GROUP_ORDER            16        /* B/V */
#define OAKLEY_BLOCK_SIZE             17

/* IPsec DOI attributes
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.5
 */

#define SA_LIFE_TYPE             1
#define SA_LIFE_DURATION         2      /* B/V */
#define GROUP_DESCRIPTION        3
#define ENCAPSULATION_MODE       4
#define AUTH_ALGORITHM           5
#define KEY_LENGTH               6
#define KEY_ROUNDS               7
#define COMPRESS_DICT_SIZE       8
#define COMPRESS_PRIVATE_ALG     9      /* B/V */
#define SECCTX                   32001  /* B/V */

/* for each IPsec attribute, which enum_names describes its values? */

/* SA Lifetime Type attribute
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.5
 * Default time specified in 4.5
 *
 * There are two defaults for IPSEC SA lifetime, SA_LIFE_DURATION_DEFAULT,
 * and PLUTO_SA_LIFE_DURATION_DEFAULT.
 * SA_LIFE_DURATION_DEFAULT is specified in RFC2407 "The Internet IP
 * Security Domain of Interpretation for ISAKMP" 4.5.  It applies when
 * an ISAKMP negotiation does not explicitly specify a life duration.
 * PLUTO_SA_LIFE_DURATION_DEFAULT is specified in pluto(8).  It applies
 * when a connection description does not specify --ipseclifetime.
 * The value of SA_LIFE_DURATION_MAXIMUM is our local policy.
 */

#define SA_LIFE_TYPE_SECONDS   1
#define SA_LIFE_TYPE_KBYTES    2

#define SA_LIFE_DURATION_DEFAULT    28800       /* eight hours (RFC2407 4.5) */
#define PLUTO_SA_LIFE_DURATION_DEFAULT    28800 /* eight hours (pluto(8)) */
#define SA_LIFE_DURATION_MAXIMUM    86400       /* one day */

#define SA_REPLACEMENT_MARGIN_DEFAULT       540 /* (IPSEC & IKE) nine minutes */
#define SA_REPLACEMENT_FUZZ_DEFAULT         100 /* (IPSEC & IKE) 100% of MARGIN */
#define SA_REPLACEMENT_RETRIES_DEFAULT      0   /*  (IPSEC & IKE) */

#define SA_LIFE_DURATION_K_DEFAULT  0xFFFFFFFFlu

/* Oakley Lifetime Type attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * As far as I can see, there is not specification for
 * OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT.  This could lead to interop problems!
 * For no particular reason, we chose one hour.
 * The value of OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM is our local policy.
 */

#define OAKLEY_LIFE_SECONDS   1
#define OAKLEY_LIFE_KILOBYTES 2

#define OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT 3600          /* one hour */
#define OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM 86400         /* 1 day */

enum pubkey_source {
	PUBKEY_NOTSET       = 0,
	PUBKEY_DNS          = 1,
	PUBKEY_DNSONDEMAND  = 2,
	PUBKEY_CERTIFICATE  = 3,
	PUBKEY_PREEXCHANGED = LOOSE_ENUM_OTHER,
};

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
	PPK_PSK = 1,
	/* PPK_DSS, */	/* not implemented */
	PPK_RSA = 3,
	PPK_PIN = 4,
	PPK_XAUTH=5,
};

#define XAUTH_PROMPT_TRIES 3
#define XAUTH_MAX_NAME_LENGTH 128
#define XAUTH_MAX_PASS_LENGTH 128

#define MIN_LIVENESS 1
