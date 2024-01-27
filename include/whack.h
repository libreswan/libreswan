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
#include "sa_type.h"

#ifndef DEFAULT_CTL_SOCKET
# define DEFAULT_CTL_SOCKET IPSEC_RUNDIR "/pluto.ctl"
#endif


/* Since the message remains on one host, native representation is used.
 * Think of this as horizontal microcode: all selected operations are
 * to be done (in the order declared here).
 *
 * MAGIC is used to help detect version mismatches between whack and Pluto.
 * Whenever the interface (i.e. this struct) changes in form or
 * meaning, change this value (probably by changing the last number).
 *
 * If the command only requires basic actions (status or shutdown),
 * it is likely that the relevant part of the message changes less frequently.
 * Whack uses WHACK_BASIC_MAGIC in those cases.
 *
 * When you increment WHACK_BASIC_MAGIC, reset WHACK_MAGIC's last number to 0.
 * This allows for more WHACK_BASIC_MAGIC values.
 *
 * NOTE: no value of WHACK_BASIC_MAGIC may equal any value of WHACK_MAGIC.
 * Otherwise certain version mismatches will not be detected.
 */

#define WHACK_BASIC_MAGIC (((((('w' << 8) + 'h') << 8) + 'k') << 8) + 25)
#define WHACK_MAGIC (((((('o' << 8) + 'h') << 8) + 'k') << 8) + 49)

/* struct whack_end is a lot like connection.h's struct end
 * It differs because it is going to be shipped down a socket
 * and because whack is a separate program from pluto.
 */
struct whack_end {
	const char *leftright;	/* either "left" or "right" (not shipped) */

	char *id;		/* id string (if any) -- decoded by pluto */
	char *ca;		/* distinguished name string (if any) -- parsed by pluto */
	char *groups;		/* access control groups (if any) -- parsed by pluto */

	/*
	 * Where, if anywhere, is the public/private key coming from?
	 * Pass everything over and let pluto decide what if anything
	 * conflict.
	 */
	char *cert;
	char *ckaid;
	char *pubkey;
	enum ipseckey_algorithm_type pubkey_alg;

	enum keyword_auth auth;

	enum keyword_host host_type;
	ip_address host_addr;
	unsigned host_ikeport;
	ip_address host_nexthop;
	char *sourceip;
	ip_cidr host_vtiip;
	ip_cidr ifaceip;

	char *subnet; /* child */
	char *subnets;	/* alias subnet expansion */
	ip_protoport protoport;

	bool key_from_DNS_on_demand;
	char *updown;		/* string */
	char *virt;
	char *addresspool;
	bool xauth_server;	/* for XAUTH */
	bool xauth_client;
	char *xauth_username;
	bool modecfg_server;	/* for MODECFG */
	bool modecfg_client;
	bool cat;		/* IPv4 Client Address Translation */
	enum certpolicy sendcert;
	enum eap_options eap;
	bool send_ca;
	enum ike_cert_type certtype;

	char *host_addr_name;	/* DNS name for host, of hosttype==IPHOSTNAME
				 * pluto will convert to IP address again,
				 * if this is non-NULL when conn fails.
				 */
	char *groundhog;	/* Is this end a groundhog? */
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
	unsigned int magic;

	bool whack_status;
	bool whack_globalstatus;
	bool whack_clear_stats;
	bool whack_trafficstatus;	/* match name to option/command  */
	bool whack_shuntstatus;
	bool whack_fipsstatus;
	bool whack_briefstatus;
	bool whack_addresspoolstatus;
	bool whack_connectionstatus;
	bool whack_briefconnectionstatus;
	bool whack_showstates;
	bool whack_seccomp_crashtest;

	bool whack_shutdown;

	/* END OF BASIC COMMANDS
	 * If you change anything earlier in this struct, update WHACK_BASIC_MAGIC.
	 */

	bool from_whack;		/* i.e., not addconn; they
					 * have different semantics */

	bool whack_processstatus; /* non-basic */

	bool whack_leave_state; /* non-basic: dont send delete or  clean kernel state on shutdown */
	/* name is used in connection and initiate */
	char *name;

	/* for debugging! */
	lmod_t debugging;
	lset_t conn_debug;

	/* what to impair and how; a list like structure */
	struct {
		unsigned len;
		struct whack_impair *list;
	} impairments;

	/* for WHACK_CONNECTION */

	bool whack_addconn;	/* addconn semantics */
	bool whack_add;		/* whack semantics */
	bool whack_async;

	enum ike_version ike_version;	/* from keyexchange= */
	enum yn_options ikev2;

	struct authby authby;
	lset_t sighash_policy;
	enum shunt_policy shunt[SHUNT_KIND_ROOF];
	enum autostart autostart;
	enum yn_options mobike;		/* allow MOBIKE */
	enum yn_options intermediate;	/* allow Intermediate Exchange */
	enum yn_options sha2_truncbug;	/* allow Intermediate Exchange */
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
	enum yn_options ikepad;		/* pad ike packets to 4 bytes
					 * or not */
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
	enum encap_proto phase2;	/* outer protocol: ESP|AH */

	uintmax_t sa_ipsec_max_bytes;
	uintmax_t sa_ipsec_max_packets;

	deltatime_t ikelifetime;
	deltatime_t ipsec_lifetime;

	deltatime_t sa_rekey_margin;
	uintmax_t sa_rekeyfuzz_percent;

	struct {
		bool set;
		uintmax_t value;
	} keyingtries;

	uintmax_t replay_window;
	deltatime_t retransmit_timeout;
	deltatime_t retransmit_interval;
	enum nic_offload_options nic_offload;
	char *ipsec_interface;

	/* For IKEv1 RFC 3706 - Dead Peer Detection / IKEv2 liveness */
	enum dpd_action dpd_action; /* 0 implies unset */
	char *dpd_delay;	/* seconds */
	char *dpd_timeout;	/* seconds */

	/* Cisco interop:  remote peer type */
	enum keyword_remote_peer_type remote_peer_type;

	/* Force the use of NAT-T on a connection */
	enum yna_options encapsulation;

	enum yn_options ikev2_allow_narrowing;
	enum yn_options rekey;
	enum yn_options reauth;

	/*
	 * TCP: Allow TCP as fallback, only do TCP or only do UDP; and
	 * the port.
	 */
	enum tcp_options enable_tcp;
	uintmax_t tcp_remoteport;

	/* Option to allow per-conn setting of sending of NAT-T keepalives - default is enabled */
	bool nat_keepalive;
	/* Option to tweak sending NATT drafts, rfc or both */
	enum ikev1_natt_policy nat_ikev1_method;

	/* Option to allow sending INITIAL-CONTACT payload - default is disabled */
	bool initial_contact;

	/*
	 * Option to just send the Cisco VID - the other end will behave
	 * differently (ModeCFG + RSA?)
	 */
	bool cisco_unity;

	/* Option to send strongswan VID to allow better interop */
	bool fake_strongswan;

	/* send our own libreswan vendorid or not */
	bool send_vendorid;

	/* Checking if this connection is configured by Network Manager */
	enum yn_options nm_configured;

	/* XAUTH Authentication can be file (default) PAM or 'alwaysok' */
	enum keyword_xauthby xauthby;


	/* XAUTH failure mode can be hard (default) or soft */
	enum keyword_xauthfail xauthfail;
	enum send_ca_policy send_ca;

	/* Force the MTU for this connection */
	int mtu;

	uintmax_t priority;
	uintmax_t tfc;
	bool send_no_esp_tfc;
	reqid_t sa_reqid;
	int nflog_group;

	char *sec_label;	/* sec_label string (if any) -- decoded by pluto */

	/*  note that each end contains string 2/5.id, string 3/6 cert,
	 *  and string 4/7 updown
	 */
	struct whack_end left;
	struct whack_end right;

	/* names match field */
	const struct ip_info *host_afi;
	const struct ip_info *child_afi;

	char *ike;			/* ike algo string (separated by commas) */
	char *pfsgroup;			/* pfsgroup will be "encapsulated" in esp string for pluto */
	char *esp;			/* esp algo string (separated by commas) */

	/* for WHACK_KEY: */
	bool whack_key;
	bool whack_addkey;
	char *keyid;	/* string 8 */
	enum ipseckey_algorithm_type pubkey_alg;
	chunk_t keyval;	/* chunk */

	/* for REMOTE_HOST */
	char *remote_host;

	/* for WHACK_ROUTE: */
	bool whack_route;

	/* for WHACK_UNROUTE: */
	bool whack_unroute;

	/* for WHACK_INITIATE: */
	bool whack_initiate;

	/* for WHACK_OPINITIATE */
	bool whack_oppo_initiate;
	struct {
		struct {
			ip_address address;
			ip_port port;
		} local, remote;
		unsigned ipproto;
	} oppo;

	/* for WHACK_DOWN: */
	bool whack_down;

	/* for WHACK_DELETE: */
	bool whack_delete;

	/* for WHACK_DELETESTATE: */
	bool whack_deletestate;
	long unsigned int whack_deletestateno;

	/* initiate rekey/delete/down SA now */
	enum whack_sa {
		WHACK_REKEY_SA = 1,
		WHACK_DELETE_SA,
		WHACK_DOWN_SA,
	} whack_sa;
#define whack_sa_name(OP) ((OP) == WHACK_REKEY_SA ? "rekey" :	\
			   (OP) == WHACK_DELETE_SA ? "delete" :	\
			   (OP) == WHACK_DOWN_SA ? "down" :	\
			   "???")
	enum sa_type whack_sa_type;

	/* for WHACK_NFLOG_GROUP: */
	long unsigned int whack_nfloggroup;

	/* for WHACK_DELETEUSER: */
	bool whack_deleteuser;
	bool whack_deleteuser_name;

	/* for WHACK_DELETEUSER: */
	bool whack_deleteid;
	bool whack_deleteid_name;

	/* for WHACK_PURGEOCSP */
	bool whack_purgeocsp;

	/* for WHACK_LISTEN: */
	bool whack_listen, whack_unlisten;
	long unsigned int ike_buf_size;	/* IKE socket recv/snd buffer size */
	bool ike_sock_err_toggle; /* toggle MSG_ERRQUEUE on IKE socket */

	/* for DDOS modes */
	enum ddos_mode whack_ddos;

	/* force EVENT_PENDING_DDNS */
	bool whack_ddns;

	/* for WHACK_CRASH - note if a remote peer is known to have rebooted */
	bool whack_crash;
	ip_address whack_crash_peer;

	/* for WHACK_LIST */
	bool whack_utc;
	bool whack_checkpubkeys;	/* --checkpubkeys */
	bool whack_listpubkeys;		/* --listpubkeys */
	lset_t whack_list;

	/* for WHACK_REREAD */

	bool whack_rereadcerts;
	bool whack_rereadsecrets;
	bool whack_fetchcrls;

	/* for connalias string */
	char *connalias;

	/* for IKEv1 MODECFG and IKEv2 CP */
	char *modecfg_dns;
	char *modecfg_domains;
	char *modecfg_banner;

	char *conn_mark_both;
	char *conn_mark_in;
	char *conn_mark_out;

	char *vti_interface;
	enum yn_options vti_routing;	/* perform routing into vti
					 * device or not */
	enum yn_options vti_shared;	/* use remote %any and skip
					 * cleanup on down? */

	/* RFC 8784 and draft-smyslov-ipsecme-ikev2-qr-alt-07 */
	char *ppk_ids;

	/* for RFC 5685 - IKEv2 Redirect mechanism */
	enum allow_global_redirect global_redirect;
	char *global_redirect_to;
	char *redirect_to;		/* either for connection or active */
	enum yn_options accept_redirect;
	char *accept_redirect_to;
	enum yna_options send_redirect;

	/* what metric to put on ipsec routes */
	int metric;

	char *dnshostname;

	/* space for strings (hope there is enough room) */
	size_t str_size;
	unsigned char string[4096];
};

/* options of whack --list*** command
 * these should be kept in order of option_enums LST_ values
 */
#define LIST_NONE	0x0000	/* don't list anything */
#define LIST_PUBKEYS	0x0001	/* list all public keys */
#define LIST_CERTS	0x0002	/* list all host/user certs */
#define LIST_CACERTS	0x0004	/* list all ca certs */
#define LIST_CRLS	0x0008	/* list all crls */
#define LIST_PSKS	0x0010	/* list all preshared keys (by name) */
#define LIST_EVENTS	0x0020	/* list all queued events */

/* omit events from listing options */
#define LIST_ALL	LRANGES(LIST_PUBKEYS, LIST_PSKS)  /* all list options */

struct whackpacker {
	struct whack_message *msg;
	unsigned char *str_roof;
	unsigned char *str_next;
	int n;
};

extern err_t pack_whack_msg(struct whackpacker *wp, struct logger *logger);
extern bool unpack_whack_msg(struct whackpacker *wp, struct logger *logger);
extern void clear_end(const char *leftright, struct whack_end *e);

extern size_t whack_get_secret(char *buf, size_t bufsize);
extern int whack_get_value(char *buf, size_t bufsize);

extern bool lsw_alias_cmp(const char *name, const char *aliases);

#endif /* WHACK_H */
