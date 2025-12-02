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

#ifndef PLUTO_CTL_DOMAIN
# define PLUTO_CTL_DOMAIN AF_UNIX
#endif

#ifndef PLUTO_CTL_TYPE
# define PLUTO_CTL_TYPE SOCK_SEQPACKET
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

#define we_id conn->value[KWS_ID]	/* id string (if any) --
					 * decoded by pluto */

#define we_ca conn->value[KWS_CA]	/* distinguished name string
					 * (if any) -- parsed by
					 * pluto */
	/*
	 * Where, if anywhere, is the public/private key coming from?
	 * Pass everything over and let pluto decide what if anything
	 * conflict.
	 */
#define we_cert conn->value[KWS_CERT]
#define we_ckaid conn->value[KWS_CKAID]
#define we_rsasigkey conn->value[KWS_RSASIGKEY]
#define we_ecdsakey conn->value[KWS_ECDSAKEY]
#define we_eddsakey conn->value[KWS_EDDSAKEY]
#define we_pubkey conn->value[KWS_PUBKEY]

#define we_auth conn->value[KWS_AUTH]

#define we_ikeport conn->value[KWS_IKEPORT]	/* host */
#define we_host conn->value[KWS_HOST]
#define we_nexthop conn->value[KWS_NEXTHOP]
#define we_sourceip conn->value[KWS_SOURCEIP]
#define we_vti conn->value[KWS_VTI]		/* host */
#define we_interface_ip conn->value[KWS_INTERFACE_IP]	/* for ipsec-interface */

#define we_subnet conn->value[KWS_SUBNET]	/* child; includes virt: */
#define we_subnets conn->value[KWS_SUBNETS]	/* alias subnet expansion */
#define we_protoport conn->value[KWS_PROTOPORT]

#define we_updown conn->value[KWS_UPDOWN]	/* string */
#define we_addresspool conn->value[KWS_ADDRESSPOOL]

#define we_xauthserver conn->value[KWS_XAUTHSERVER]	/* for XAUTH */
#define we_xauthclient conn->value[KWS_XAUTHCLIENT]
#define we_xauthusername conn->value[KWS_USERNAME]

#define we_cat conn->value[KWS_CAT]		/* IPv4 Client Address
						 * Translation */
#define we_sendcert conn->value[KWS_SENDCERT]
#define we_autheap conn->value[KWS_AUTHEAP]

#define we_modecfgserver conn->value[KWS_MODECFGSERVER]	/* for MODECFG */
#define we_modecfgclient conn->value[KWS_MODECFGCLIENT]

#define we_groundhog conn->value[KWS_GROUNDHOG]	/* Is this end a
						 * groundhog? */

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

struct whack_deletestate {
	long unsigned int state_nr;
};

struct whack_crash {
	/* note if a remote peer is known to have rebooted */
	ip_address peer;
};

/*
 * Order matters - it determines the order in which ALL appears.
 */
enum whack_lists {
#define WHACK_LIST_FLOOR WHACK_LIST_PUBKEYS
	WHACK_LIST_PUBKEYS,	/* list all public keys */
	WHACK_LIST_PSKS,	/* list all preshared keys (by name) */
	WHACK_LIST_CERTS,	/* list all host/user certs */
	WHACK_LIST_CACERTS,	/* list all ca certs */
	WHACK_LIST_CRLS,	/* list all crls */
	WHACK_LIST_EVENTS,	/* list all queued events */
#define WHACK_LIST_ROOF (WHACK_LIST_EVENTS+1)
};

struct whack_list {
	bool list[WHACK_LIST_ROOF];
};

struct whack_initiate {
	const char *remote_host;
#if 0
	const char *name;
#endif
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

	/* generic options applying to anything */
	bool whack_async;
	bool whack_utc;

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
		struct whack_deletestate deletestate;
		struct whack_crash crash;
		struct whack_list list;
		struct whack_initiate initiate;
	} whack;

	const char *authby;

	enum shunt_policy shunt[SHUNT_KIND_ROOF];
	enum autostart autostart;

	struct whack_end end[END_ROOF];

	/* for WHACK_KEY: */
	bool whack_key;
	bool whack_addkey;
	const char *keyid;	/* string 8 */
	enum ipseckey_algorithm_type pubkey_alg;
	const char *pubkey;

	/* for WHACK_ADD */

#define wm_debug conn[END_ROOF].value[KWS_DEBUG]

#define wm_hostaddrfamily conn[END_ROOF].value[KWS_HOSTADDRFAMILY]

#define wm_ike conn[END_ROOF].value[KWS_IKE]	/* ike algo string
						 * (separated by
						 * commas) */
#define wm_phase2 conn[END_ROOF].value[KWS_PHASE2]	/* outer
							 * protocol:
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

	/* XAUTH Authentication can be file (default) PAM or 'alwaysok' */
#define wm_xauthby conn[END_ROOF].value[KWS_XAUTHBY]

	/* XAUTH failure mode can be hard (default) or soft */
#define wm_xauthfail conn[END_ROOF].value[KWS_XAUTHFAIL]
#define wm_sendca conn[END_ROOF].value[KWS_SENDCA]

	/* Option to allow per-conn setting of sending of NAT-T
	 * keepalives - default is enabled */
#define wm_nat_keepalive conn[END_ROOF].value[KWS_NAT_KEEPALIVE]
	/* Option to tweak sending NATT drafts, rfc or both */
#define wm_nat_ikev1_method conn[END_ROOF].value[KWS_NAT_IKEv1_METHOD]

	/*
	 * TCP: Allow TCP as fallback, only do TCP or only do UDP; and
	 * the port.
	 */
#define wm_enable_tcp conn[END_ROOF].value[KWS_ENABLE_TCP]
#define wm_tcp_remoteport conn[END_ROOF].value[KWS_TCP_REMOTEPORT]

	/*
	 * For RFC 5685 - IKEv2 Redirect mechanism.
	 *
	 * REDIRECT_TO is used by WHACK_ADD, WHACK_ACTIVE_REDIRECT and
	 * WHACK_GLOBAL_REDIRECT.
	 */
	enum global_redirect global_redirect;
#define wm_accept_redirect conn[END_ROOF].value[KWS_ACCEPT_REDIRECT]
#define wm_send_redirect conn[END_ROOF].value[KWS_SEND_REDIRECT]
#define wm_redirect_to conn[END_ROOF].value[KWS_REDIRECT_TO]
#define wm_accept_redirect_to conn[END_ROOF].value[KWS_ACCEPT_REDIRECT_TO]

	/* what metric to put on ipsec routes */
#define wm_metric conn[END_ROOF].value[KWS_METRIC]

#define wm_keyexchange conn[END_ROOF].value[KWS_KEYEXCHANGE]
#define wm_ikev2 conn[END_ROOF].value[KWS_IKEv2]

#define wm_ikepad conn[END_ROOF].value[KWS_IKEPAD]	/* pad ike
							 * packets and
							 * payloads to
							 * 4 bytes or
							 * not */
#define wm_fragmentation conn[END_ROOF].value[KWS_FRAGMENTATION]	/* fragment IKE payload */
#define wm_esn conn[END_ROOF].value[KWS_ESN]		/* accept or request ESN{yes,no} */
#define wm_ppk conn[END_ROOF].value[KWS_PPK]		/* pre-shared post-quantum key */
	enum type_options type;		/* type=tunnel|transport|SHUNT */
#define wm_replay_window conn[END_ROOF].value[KWS_REPLAY_WINDOW]

#define wm_nic_offload conn[END_ROOF].value[KWS_NIC_OFFLOAD]
	/* Force the use of NAT-T on a connection */
#define wm_encapsulation conn[END_ROOF].value[KWS_ENCAPSULATION]

#define wm_session_resumption conn[END_ROOF].value[KWS_SESSION_RESUMPTION]	/* for RFC 5723 -
										 * IKEv2 Session
										 * Resumption */

#define wm_ipsec_interface conn[END_ROOF].value[KWS_IPSEC_INTERFACE]

	/* For IKEv1 RFC 3706 - Dead Peer Detection / IKEv2 liveness */
#define wm_dpddelay conn[END_ROOF].value[KWS_DPDDELAY]		/* seconds */
#define wm_dpdtimeout conn[END_ROOF].value[KWS_DPDTIMEOUT]	/* seconds */

#define wm_narrowing conn[END_ROOF].value[KWS_NARROWING]	/* IKEv2 only? */
#define wm_rekey conn[END_ROOF].value[KWS_REKEY]
#define wm_reauth conn[END_ROOF].value[KWS_REAUTH]

#define wm_require_id_on_certificate conn[END_ROOF].value[KWS_REQUIRE_ID_ON_CERTIFICATE]
					/* require certificates to
					 * have IKE ID on cert SAN */
#define wm_modecfgpull conn[END_ROOF].value[KWS_MODECFGPULL]	/* is modecfg pulled by
					 * client? */
#define wm_aggressive conn[END_ROOF].value[KWS_AGGRESSIVE]	/* do we do aggressive
					 * mode? */
#define wm_decap_dscp conn[END_ROOF].value[KWS_DECAP_DSCP]	/* decap ToS/DSCP bits */
#define wm_encap_dscp conn[END_ROOF].value[KWS_ENCAP_DSCP]	/* encap ToS/DSCP bits */
#define wm_nopmtudisc conn[END_ROOF].value[KWS_NOPMTUDISC]	/* ??? */
#define wm_pfs conn[END_ROOF].value[KWS_PFS]
#define wm_compress conn[END_ROOF].value[KWS_COMPRESS]

#define wm_mobike conn[END_ROOF].value[KWS_MOBIKE]		/* allow MOBIKE */
#define wm_intermediate conn[END_ROOF].value[KWS_INTERMEDIATE]	/* allow Intermediate Exchange */
#define wm_sha2_truncbug conn[END_ROOF].value[KWS_SHA2_TRUNCBUG]	/* allow Intermediate Exchange */
#define wm_share_lease conn[END_ROOF].value[KWS_SHARE_LEASE]	/* allow further connections to use lease IP */
#define wm_overlapip conn[END_ROOF].value[KWS_OVERLAPIP]	/* can two conns that have
								 * subnet=vhost: declare the
								 * same IP? */
#define wm_ms_dh_downgrade conn[END_ROOF].value[KWS_MS_DH_DOWNGRADE]	/* allow IKEv2 rekey
									 * to downgrade DH
									 * group - Microsoft
									 * bug */
#define wm_pfs_rekey_workaround conn[END_ROOF].value[KWS_PFS_REKEY_WORKAROUND]	/* during IKEv2 rekey
										 * use full esp=
										 * proposal */
#define wm_dns_match_id conn[END_ROOF].value[KWS_DNS_MATCH_ID]	/* perform reverse DNS lookup
								 * on IP to confirm ID */
#define wm_pam_authorize conn[END_ROOF].value[KWS_PAM_AUTHORIZE]	/* non-standard, custom PAM
									 * authorize call on ID
									 * (IKEv2) */
#define wm_ignore_peer_dns conn[END_ROOF].value[KWS_IGNORE_PEER_DNS]	/* install obtained
									 * DNS servers
									 * locally */

/* Option to allow sending INITIAL-CONTACT payload */
#define wm_initial_contact conn[END_ROOF].value[KWS_INITIAL_CONTACT]

	/*
	 * Option to just send the Cisco VID - the other end will behave
	 * differently (ModeCFG + RSA?)
	 */
#define wm_remote_peer_type conn[END_ROOF].value[KWS_REMOTE_PEER_TYPE]
#define wm_cisco_unity conn[END_ROOF].value[KWS_CISCO_UNITY]
#define wm_cisco_split conn[END_ROOF].value[KWS_CISCO_SPLIT]

	/* Option to send strongswan VID to allow better interop */
#define wm_fake_strongswan conn[END_ROOF].value[KWS_FAKE_STRONGSWAN]

	/* send our own libreswan vendorid or not */
#define wm_send_vendorid conn[END_ROOF].value[KWS_SEND_VENDORID]

	/* Checking if this connection is configured by Network Manager */
#define wm_nm_configured conn[END_ROOF].value[KWS_NM_CONFIGURED]

	/* Force the MTU for this connection */
#define wm_mtu  conn[END_ROOF].value[KWS_MTU]
#define wm_priority conn[END_ROOF].value[KWS_PRIORITY]
#define wm_tfc conn[END_ROOF].value[KWS_TFC]
#define wm_send_esp_tfc_padding_not_supported conn[END_ROOF].value[KWS_SEND_ESP_TFC_PADDING_NOT_SUPPORTED]
#define wm_reject_simultaneous_ike_auth conn[END_ROOF].value[KWS_REJECT_SIMULTANEOUS_IKE_AUTH]

#define wm_reqid conn[END_ROOF].value[KWS_REQID]
#define wm_nflog_group conn[END_ROOF].value[KWS_NFLOG_GROUP]

	/* sec_label string (if any) -- decoded by pluto */
#define wm_sec_label conn[END_ROOF].value[KWS_SEC_LABEL]

	/* for connalias string */
#define wm_connalias conn[END_ROOF].value[KWS_CONNALIAS]

	/* for IKEv1 MODECFG and IKEv2 CP */
#define wm_modecfgdns conn[END_ROOF].value[KWS_MODECFGDNS]
#define wm_modecfgdomains conn[END_ROOF].value[KWS_MODECFGDOMAINS]
#define wm_modecfgbanner conn[END_ROOF].value[KWS_MODECFGBANNER]

	/* RFC 8784 and draft-ietf-ipsecme-ikev2-qr-alt-04 */
#define wm_ppk_ids conn[END_ROOF].value[KWS_PPK_IDS]

#define wm_mark conn[END_ROOF].value[KWS_MARK]
#define wm_mark_in conn[END_ROOF].value[KWS_MARK_IN]
#define wm_mark_out conn[END_ROOF].value[KWS_MARK_OUT]

#define wm_vti_interface conn[END_ROOF].value[KWS_VTI_INTERFACE]
	/* perform routing into vti device or not */
#define wm_vti_routing conn[END_ROOF].value[KWS_VTI_ROUTING]
	/* use remote %any and skip cleanup on down? */
#define wm_vti_shared conn[END_ROOF].value[KWS_VTI_SHARED]

#define wm_iptfs                conn[END_ROOF].value[KWS_IPTFS]
#define wm_iptfs_fragmentation  conn[END_ROOF].value[KWS_IPTFS_FRAGMENTATION]
#define wm_iptfs_packet_size    conn[END_ROOF].value[KWS_IPTFS_PACKET_SIZE] /* 0 for PMTU */
#define wm_iptfs_max_queue_size conn[END_ROOF].value[KWS_IPTFS_MAX_QUEUE_SIZE]
#define wm_iptfs_reorder_window conn[END_ROOF].value[KWS_IPTFS_REORDER_WINDOW]
#define wm_iptfs_drop_time      conn[END_ROOF].value[KWS_IPTFS_DROP_TIME]
#define wm_iptfs_init_delay     conn[END_ROOF].value[KWS_IPTFS_INIT_DELAY]

#define wm_ipsec_max_bytes      conn[END_ROOF].value[KWS_IPSEC_MAX_BYTES]
#define wm_ipsec_max_packets    conn[END_ROOF].value[KWS_IPSEC_MAX_PACKETS]

#define wm_ikelifetime          conn[END_ROOF].value[KWS_IKELIFETIME]
#define wm_ipsec_lifetime       conn[END_ROOF].value[KWS_IPSEC_LIFETIME]
#define wm_rekeymargin          conn[END_ROOF].value[KWS_REKEYMARGIN]	/* which
									 * SA? */
#define wm_rekeyfuzz            conn[END_ROOF].value[KWS_REKEYFUZZ]
#define wm_retransmit_timeout   conn[END_ROOF].value[KWS_RETRANSMIT_TIMEOUT]
#define wm_retransmit_interval  conn[END_ROOF].value[KWS_RETRANSMIT_INTERVAL]	/* milliseconds,
										 * not
										 * seconds!*/

	/*
	 * Danger zone:
	 *
	 * Objective is to replace all the above fields with tupples
	 * (end, index, string) emitted from this table.  That, again,
	 * gets us one step closer to accepting JSON.
	 *
	 * This array is not sent over the wire (the message is
	 * truncated somewhere within .string[].
	 *
	 * This array is likely very very empty.
	 *
	 * END_ROOF is used to store global (vs per-end) options.
	 */

	/* space for strings (hope there is enough room) */
	size_t str_size;
	unsigned char string[4096];

#define wm_clones conn[END_ROOF].value[KWS_CLONES]
	struct whack_config_conn conn[END_ROOF+1];
};

void init_whack_message(struct whack_message *wm,
			enum whack_from from);

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

/*
 * The receiver saves a refcnt'd message so it can be offloaded.
 *
 * Can't clone whack_message as that contains internal pointers.
 */

struct whack_message_refcnt {
	refcnt_t refcnt;
	struct whack_message wm;
};

struct whack_message_refcnt *alloc_whack_message(const struct logger *owner, where_t where);

#endif /* WHACK_H */
