/* Structure of messages from whack to Pluto proper.
 *
 * Copyright (C) 1998-2001,2015-2017 D. Hugh Redelmeier.
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2013,2016 Antony Antony <antony@phenome.org>
 * Copyright (C) 2016,2018 Andrew Cagney
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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
 */

#ifndef WHACK_H
#define WHACK_H

#include <stdint.h>		/* for uintmax_t et.al. */

#include "ietf_constants.h"
#include "lset.h"
#include "lmod.h"
#include "deltatime.h"
#include "chunk.h"
#include "reqid.h"
#include "err.h"
#include "ip_range.h"
#include "ip_subnet.h"
#include "ip_protoport.h"
#include "ip_cidr.h"
#include "authby.h"
#include "encap_proto.h"
#include "sa_kind.h"
#include "constants.h"		/* for enum keyword_auth; et.al. */
#include "end.h"
#include "shunt.h"
#include "global_redirect.h"
#include "xauthby.h"
#include "xauthfail.h"
#include "ddos_mode.h"
#include "ipsecconf/config_conn.h"	/* for CONFIG_CONN_KEYWORD_ROOF */

#ifndef DEFAULT_CTL_SOCKET
# define DEFAULT_CTL_SOCKET IPSEC_RUNDIR "/pluto.ctl"
#endif

enum whack_command {
	WHACK_UNUSED,
	WHACK_REREADALL,
	WHACK_FETCHCRLS,
	WHACK_REREADSECRETS,
	WHACK_REREADCERTS,
	/**/
	WHACK_PROCESSSTATUS,
	WHACK_ADDRESSPOOLSTATUS,
	WHACK_CONNECTIONSTATUS,
	WHACK_BRIEFCONNECTIONSTATUS,
	WHACK_BRIEFSTATUS,
	WHACK_FIPSSTATUS,
	WHACK_GLOBALSTATUS,
	WHACK_TRAFFICSTATUS,
	WHACK_SHUNTSTATUS,
	/**/
	WHACK_DELETE,
	WHACK_ADD,
	WHACK_ROUTE,
	WHACK_UNROUTE,
	WHACK_INITIATE,
	WHACK_SUSPND,
	WHACK_ACQUIRE,
	WHACK_DOWN,
	WHACK_SUSPEND,
	/**/
	WHACK_DELETEUSER,
	WHACK_DELETEID,
	WHACK_DELETESTATE,
	WHACK_CRASH,
	/**/
	WHACK_CLEARSTATS,
	WHACK_DDNS,
	WHACK_PURGEOCSP,
	WHACK_SHOWSTATES,
	/**/
#define whack_sa_name(OP) ((OP) == WHACK_REKEY_IKE ? "rekey-ike" :	\
			   (OP) == WHACK_REKEY_CHILD ? "rekey-child" :	\
			   (OP) == WHACK_DELETE_IKE ? "delete-ike" :	\
			   (OP) == WHACK_DELETE_CHILD ? "delete-child" : \
			   (OP) == WHACK_DOWN_IKE ? "down-ike" :	\
			   (OP) == WHACK_DOWN_CHILD ? "down-child" :	\
			   "???")
#define whack_sa_kind(OP) ((OP) == WHACK_REKEY_IKE ? IKE_SA :		\
			   (OP) == WHACK_REKEY_CHILD ? CHILD_SA :	\
			   (OP) == WHACK_DELETE_IKE ? IKE_SA :		\
			   (OP) == WHACK_DELETE_CHILD ? CHILD_SA :	\
			   (OP) == WHACK_DOWN_IKE ? IKE_SA :		\
			   (OP) == WHACK_DOWN_CHILD ? CHILD_SA :	\
			   0)
	WHACK_REKEY_IKE,
	WHACK_REKEY_CHILD,
	WHACK_DELETE_IKE,
	WHACK_DELETE_CHILD,
	WHACK_DOWN_IKE,
	WHACK_DOWN_CHILD,
	/**/
	WHACK_DDOS,
	WHACK_LIST,
	WHACK_CHECKPUBKEYS,
	/**/
#ifdef USE_SECCOMP
	WHACK_SECCOMP_CRASHTEST,
#endif
	WHACK_SHUTDOWN_LEAVE_STATE,
	/**/
	WHACK_ACTIVE_REDIRECT,
	WHACK_GLOBAL_REDIRECT,
	/**/
	WHACK_LISTEN,
	WHACK_UNLISTEN,
};

/*
 * Since the message remains on one host, native representation is
 * used.
 */

/* struct whack_end is a lot like connection.h's struct end
 * It differs because it is going to be shipped down a socket
 * and because whack is a separate program from pluto.
 */
struct whack_end {
	const char *leftright;	/* either "left" or "right" (not shipped) */

	const char *id;		/* id string (if any) -- decoded by pluto */
	const char *groups;		/* access control groups (if any) -- parsed by pluto */


#define we_ca conn->value[KWS_CA]	/* distinguished name string
					 * (if any) -- parsed by
					 * pluto */
	/*
	 * Where, if anywhere, is the public/private key coming from?
	 * Pass everything over and let pluto decide what if anything
	 * conflict.
	 */
#define we_cert conn->value[KWS_CERT]
	const char *ckaid;
	const char *pubkey;
	enum ipseckey_algorithm_type pubkey_alg;

	const char *auth;

	const char *ikeport;			/* host */
	const char *host;
	const char *nexthop;
	const char *sourceip;
	const char *vti;			/* host */
	const char *interface_ip;		/* for ipsec-interface */

	const char *subnet; /* child */
	const char *subnets;	/* alias subnet expansion */
	const char *protoport;

	const char *updown;		/* string */
	const char *virt;
	const char *addresspool;

	enum yn_options xauthserver;	/* for XAUTH */
	enum yn_options xauthclient;
#define we_xauthusername conn->value[KWS_USERNAME]

	enum yn_options cat;		/* IPv4 Client Address Translation */
	const char *sendcert;
	const char *autheap;
	enum ike_cert_type certtype;

	enum yn_options modecfgserver;	/* for MODECFG */
	enum yn_options modecfgclient;
	enum yn_options groundhog;	/* Is this end a groundhog? */

	struct whack_config_conn *conn;
};

/*
 * annex to different messages.
 */

struct whack_listen {
	unsigned ike_socket_bufsize;		/* IKE socket recv/snd buffer size */
	bool ike_socket_errqueue_toggle;	/* toggle MSG_ERRQUEUE on IKE socket */
	enum yn_options ike_socket_errqueue;
};

struct whack_ddos {
	enum ddos_mode mode;	/* for DDOS modes */
};

struct whack_acquire {
	struct {
		ip_address address;
		ip_port port;
	} local, remote;
	const char *label;
	unsigned ipproto;
};

/*
 */

struct whack_config_conn {
	const char *value[CONFIG_CONN_KEYWORD_ROOF];
};

/*
 * Impairments.
 */

struct whack_impair {
	unsigned what;
	uintmax_t value;
	bool enable;
};

struct whack_message {
	/*
	 * Basic Commands: status and shutdown (NOTHING ELSE!!!)
	 *
	 * Whack (pickle.c) sets .magic == WHACK_BASIC_MAGIC IFF
	 * either .whack_status or .whack_shutdown is valid.
	 *
	 * Whack/addconn (pickle.c) set .magic == whack_magic() for
	 * all other cases.
	 */
	struct whack_basic {
#define WHACK_BASIC_MAGIC (((((('w' << 8) + 'h') << 8) + 'k') << 8) + 25)
		unsigned int magic;
		/* DO NOT ADD BOOLS HERE */
		bool whack_status;
		/* NOR HERE */
		bool whack_shutdown;
		/* AND DON'T EVEN THINK ABOUT HERE */
	} basic;

	/*
	 * END OF BASIC COMMANDS
	 *
	 * If you change anything earlier in this struct, update
	 * WHACK_BASIC_MAGIC so DO NOT DO THAT!
	 */

	/* when non-zero, act on this */
	enum whack_command whack_command;

	/* name is used in connection and initiate */
	const char *name;

	/* debugging updates to apply */

	lmod_t whack_debugging;

	/* what to impair and how; a list like structure */

	struct {
		unsigned len;
		struct whack_impair *list;
	} impairments;

	enum whack_from {
		WHACK_FROM_WHACK = 1,
		WHACK_FROM_ADDCONN,
	} whack_from;			/* whack and addconn have
					 * different .whack_add
					 * semantics */
	bool whack_async;

	/*
	 * Command specific parameters.  Commands also share some
	 * options such as .name. above.
	 *
	 * THIS IS NOT A UNION (XXX: but it should be).
	 *
	 * The pickler can't handle conditionally pickling strings
	 * based on .whack_command above.
	 */

	struct {
		struct whack_listen listen;
		struct whack_ddos ddos;
		struct whack_acquire acquire;
	} whack;

#define wm_keyexchange conn[END_ROOF].value[KWS_KEYEXCHANGE]
#define wm_ikev2 conn[END_ROOF].value[KWS_IKEv2]

	const char *authby;
	const char *debug;

	enum shunt_policy shunt[SHUNT_KIND_ROOF];
	enum autostart autostart;
	enum yn_options mobike;		/* allow MOBIKE */
	enum yn_options intermediate;	/* allow Intermediate Exchange */
	enum yn_options sha2_truncbug;	/* allow Intermediate Exchange */
	enum yn_options share_lease;	/* allow further connections to use lease IP */
	enum yn_options overlapip;	/* can two conns that have
					 * subnet=vhost: declare the
					 * same IP? */
	enum yn_options ms_dh_downgrade;	/* allow IKEv2 rekey
						 * to downgrade DH
						 * group - Microsoft
						 * bug */
	enum yn_options pfs_rekey_workaround;	/* during IKEv2 rekey
						 * use full esp=
						 * proposal */
	enum yn_options dns_match_id;	/* perform reverse DNS lookup
					 * on IP to confirm ID */
	enum yn_options pam_authorize;	/* non-standard, custom PAM
					 * authorize call on ID
					 * (IKEv2) */
	enum yn_options ignore_peer_dns;	/* install obtained
						 * DNS servers
						 * locally */
	enum yna_options ikepad;	/* pad ike packets and
					 * payloads to 4 bytes or
					 * not */
	enum yn_options require_id_on_certificate;
					/* require certificates to
					 * have IKE ID on cert SAN */
	enum yn_options modecfgpull;	/* is modecfg pulled by
					 * client? */
	enum yn_options aggressive;	/* do we do aggressive
					 * mode? */
	enum yn_options decap_dscp;	/* decap ToS/DSCP bits */
	enum yn_options encap_dscp;	/* encap ToS/DSCP bits */
	enum yn_options nopmtudisc;	/* ??? */
	enum ynf_options fragmentation;	/* fragment IKE payload */
	enum yne_options esn;		/* accept or request ESN{yes,no} */
	enum nppi_options ppk;		/* pre-shared post-quantum key */
	enum yn_options pfs;
	enum yn_options compress;
	enum type_options type;		/* type=tunnel|transport|SHUNT */
	enum yn_options session_resumption;	/* for RFC 5723 -
						 * IKEv2 Session
						 * Resumption */

#define wm_ipsec_max_bytes conn[END_ROOF].value[KWS_IPSEC_MAX_BYTES]
#define wm_ipsec_max_packets conn[END_ROOF].value[KWS_IPSEC_MAX_PACKETS]

	deltatime_t ikelifetime;
	deltatime_t ipsec_lifetime;

	deltatime_t rekeymargin; /* which SA? */
#define wm_rekeyfuzz conn[END_ROOF].value[KWS_REKEYFUZZ]

#define wm_replay_window conn[END_ROOF].value[KWS_REPLAY_WINDOW]
	deltatime_t retransmit_timeout;
	/* milliseconds, not seconds!*/
#define wm_retransmit_interval conn[END_ROOF].value[KWS_RETRANSMIT_INTERVAL]
	enum nic_offload_options nic_offload;
#define wm_ipsec_interface conn[END_ROOF].value[KWS_IPSEC_INTERFACE]

	/* For IKEv1 RFC 3706 - Dead Peer Detection / IKEv2 liveness */
#define wm_dpddelay conn[END_ROOF].value[KWS_DPDDELAY]		/* seconds */
#define wm_dpdtimeout conn[END_ROOF].value[KWS_DPDTIMEOUT]	/* seconds */

	/* Force the use of NAT-T on a connection */
	enum yna_options encapsulation;

	enum yn_options narrowing;	/* IKEv2 only? */
	enum yn_options rekey;
	enum yn_options reauth;

	/*
	 * TCP: Allow TCP as fallback, only do TCP or only do UDP; and
	 * the port.
	 */
	enum tcp_options enable_tcp;
	uintmax_t tcp_remoteport;

	/* Option to allow per-conn setting of sending of NAT-T
	 * keepalives - default is enabled */
	enum yn_options nat_keepalive;
	/* Option to tweak sending NATT drafts, rfc or both */
	enum ikev1_natt_policy nat_ikev1_method;

	/* Option to allow sending INITIAL-CONTACT payload */
	enum yn_options initial_contact;

	/*
	 * Option to just send the Cisco VID - the other end will behave
	 * differently (ModeCFG + RSA?)
	 */
#define wm_remote_peer_type conn[END_ROOF].value[KWS_REMOTE_PEER_TYPE]
#define wm_cisco_unity conn[END_ROOF].value[KWS_CISCO_UNITY]
#define wm_cisco_split conn[END_ROOF].value[KWS_CISCO_SPLIT]

	/* Option to send strongswan VID to allow better interop */
	enum yn_options fake_strongswan;

	/* send our own libreswan vendorid or not */
	enum yn_options send_vendorid;

	/* Checking if this connection is configured by Network Manager */
#define wm_nm_configured conn[END_ROOF].value[KWS_NM_CONFIGURED]

	/* XAUTH Authentication can be file (default) PAM or 'alwaysok' */
	enum xauthby xauthby;

	/* XAUTH failure mode can be hard (default) or soft */
	enum xauthfail xauthfail;
#define wm_sendca conn[END_ROOF].value[KWS_SENDCA]

	/* Force the MTU for this connection */
#define wm_mtu  conn[END_ROOF].value[KWS_MTU]
#define wm_priority conn[END_ROOF].value[KWS_PRIORITY]
#define wm_tfc conn[END_ROOF].value[KWS_TFC]
	enum yn_options send_esp_tfc_padding_not_supported;

	enum yn_options iptfs;
	enum yn_options iptfs_fragmentation;
#define wm_iptfs_packet_size conn[END_ROOF].value[KWS_IPTFS_PACKET_SIZE] /* 0 for PMTU */
#define wm_iptfs_max_queue_size conn[END_ROOF].value[KWS_IPTFS_MAX_QUEUE_SIZE]
#define wm_iptfs_reorder_window conn[END_ROOF].value[KWS_IPTFS_REORDER_WINDOW]
	deltatime_t iptfs_drop_time;
	deltatime_t iptfs_init_delay;

#define wm_reqid conn[END_ROOF].value[KWS_REQID]
#define wm_nflog_group conn[END_ROOF].value[KWS_NFLOG_GROUP]

	/* sec_label string (if any) -- decoded by pluto */
#define wm_sec_label conn[END_ROOF].value[KWS_SEC_LABEL]

	struct whack_end end[END_ROOF];

#define wm_hostaddrfamily conn[END_ROOF].value[KWS_HOSTADDRFAMILY]

#define wm_ike conn[END_ROOF].value[KWS_IKE]	/* ike algo string
						 * (separated by
						 * commas) */
	enum encap_proto phase2;		/* outer protocol:
						 * ESP|AH */
#define wm_phase2alg conn[END_ROOF].value[KWS_PHASE2ALG]
						/* outer protocol:
						 * alg */
#define wm_esp conn[END_ROOF].value[KWS_ESP]	/* esp algo string
						 * (separated by
						 * commas) */
#define wm_ah conn[END_ROOF].value[KWS_AH]	/* esp algo string
						 * (separated by
						 * commas) */

	/* for WHACK_KEY: */
	bool whack_key;
	bool whack_addkey;
	const char *keyid;	/* string 8 */
	enum ipseckey_algorithm_type pubkey_alg;
	const char *pubkey;

	/* for REMOTE_HOST */
	const char *remote_host;

	/* for WHACK_DELETESTATE: */
	long unsigned int whack_deletestateno;

	/* for WHACK_NFLOG_GROUP: */
	long unsigned int whack_nfloggroup;

	/* for WHACK_CRASH - note if a remote peer is known to have rebooted */
	ip_address whack_crash_peer;

	/* for WHACK_LIST */
	bool whack_utc;
	lset_t whack_list;

	/* for connalias string */
#define wm_connalias conn[END_ROOF].value[KWS_CONNALIAS]

	/* for IKEv1 MODECFG and IKEv2 CP */
#define wm_modecfgdns conn[END_ROOF].value[KWS_MODECFGDNS]
#define wm_modecfgdomains conn[END_ROOF].value[KWS_MODECFGDOMAINS]
#define wm_modecfgbanner conn[END_ROOF].value[KWS_MODECFGBANNER]

#define wm_mark conn[END_ROOF].value[KWS_MARK]
#define wm_mark_in conn[END_ROOF].value[KWS_MARK_IN]
#define wm_mark_out conn[END_ROOF].value[KWS_MARK_OUT]

#define wm_vti_interface conn[END_ROOF].value[KWS_VTI_INTERFACE]
	enum yn_options vti_routing;	/* perform routing into vti
					 * device or not */
	enum yn_options vti_shared;	/* use remote %any and skip
					 * cleanup on down? */

	/* RFC 8784 and draft-ietf-ipsecme-ikev2-qr-alt-04 */
#define wm_ppk_ids conn[END_ROOF].value[KWS_PPK_IDS]

	/*
	 * For RFC 5685 - IKEv2 Redirect mechanism.
	 *
	 * REDIRECT_TO is used by WHACK_ADD, WHACK_ACTIVE_REDIRECT and
	 * WHACK_GLOBAL_REDIRECT.
	 */
	enum global_redirect global_redirect;
	enum yn_options accept_redirect;
	enum yna_options send_redirect;
#define wm_redirect_to conn[END_ROOF].value[KWS_REDIRECT_TO]
#define wm_accept_redirect_to conn[END_ROOF].value[KWS_ACCEPT_REDIRECT_TO]

	/* what metric to put on ipsec routes */
	int metric;

	/* space for strings (hope there is enough room) */
	size_t str_size;
	unsigned char string[4096];

	/*
	 * Danger zone:
	 *
	 * Objective is to replace all the above fields with tupples
	 * (end, index, string) emitted from this table.  That, again,
	 * gets us one step closer to accepting JSON.
	 *
	 * This is not sent over the wire (the message is truncated
	 * somewhere within .string[].
	 *
	 * This array is likely very very empty.
	 *
	 * END_ROOF is used to store global (vs per-end) options.
	 */
#define wm_clones conn[END_ROOF].value[KWS_CLONES]
	struct whack_config_conn conn[END_ROOF+1];
};

void init_whack_message(struct whack_message *wm,
			enum whack_from from);

/*
 * Options of whack --list*** command
 *
 * These should be kept in order of option_enums LST_ values
 */
enum whack_list {
	LIST_PUBKEYS,	/* list all public keys */
	LIST_CERTS,	/* list all host/user certs */
	LIST_CACERTS,	/* list all ca certs */
	LIST_CRLS,	/* list all crls */
	LIST_PSKS,	/* list all preshared keys (by name) */
	LIST_EVENTS,	/* list all queued events */
};

/* omit events from listing options */
#define LIST_ALL	LRANGE(LIST_PUBKEYS, LIST_PSKS)  /* almost all list options */

struct whackpacker {
	struct whack_message *msg;
	unsigned char *str_roof;
	unsigned char *str_next;
	size_t n;
};

extern err_t pack_whack_msg(struct whackpacker *wp, struct logger *logger);
extern diag_t unpack_whack_msg(struct whackpacker *wp, struct logger *logger);

int whack_send_msg(struct whack_message *msg, const char *ctlsocket,
		   char xauthusername[MAX_XAUTH_USERNAME_LEN],
		   char xauthpass[XAUTH_MAX_PASS_LENGTH],
		   int usernamelen, int xauthpasslen,
		   struct logger *logger);

extern bool lsw_alias_cmp(const char *name, const char *aliases);

extern unsigned whack_magic(void);

#endif /* WHACK_H */
