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

#ifndef _WHACK_H
#define _WHACK_H

#include "ietf_constants.h"
#include "lset.h"
#include "lmod.h"
#include "deltatime.h"
#include "chunk.h"
#include "reqid.h"
#include "err.h"
#include "impair.h"
#include "ip_range.h"
#include "ip_subnet.h"
#include "ip_protoport.h"
#include "ip_cidr.h"

#ifndef DEFAULT_RUNDIR
# define DEFAULT_RUNDIR "/run/pluto/"
#endif

#ifndef DEFAULT_CTL_SOCKET
# define DEFAULT_CTL_SOCKET DEFAULT_RUNDIR "/pluto.ctl"
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
	char *leftright;	/* either "left" or "right" */

	char *id;		/* id string (if any) -- decoded by pluto */
	char *sec_label;	/* sec_label string (if any) -- decoded by pluto */
	char *ca;		/* distinguished name string (if any) -- parsed by pluto */
	char *groups;		/* access control groups (if any) -- parsed by pluto */

	/*
	 * Where, if anywhere, is the public/private key coming from?
	 * Pass everything over and let pluto decide what if anything
	 * conflict.
	 */
	char *cert;
	char *ckaid;
	char *rsasigkey;

	enum keyword_authby authby;

	enum keyword_host host_type;
	ip_address host_addr;
	unsigned host_ikeport;
	ip_address host_nexthop;
	ip_address host_srcip;
	ip_cidr host_vtiip;
	ip_cidr ifaceip;

	ip_subnet client;
	ip_protoport protoport;

	bool has_client;

	bool key_from_DNS_on_demand;
	char *updown;		/* string */
	char *virt;
	ip_range pool_range;	/* store start of v4 addresspool */
	bool xauth_server;	/* for XAUTH */
	bool xauth_client;
	char *xauth_username;
	bool modecfg_server;	/* for MODECFG */
	bool modecfg_client;
	bool cat;		/* IPv4 Client Address Translation */
	enum certpolicy sendcert;
	bool send_ca;
	enum ike_cert_type certtype;

	char *host_addr_name;	/* DNS name for host, of hosttype==IPHOSTNAME
				 * pluto will convert to IP address again,
				 * if this is non-NULL when conn fails.
				 */
};

enum whack_opt_set {
	WHACK_ADJUSTOPTIONS=0,		/* normal case */
	WHACK_SETDUMPDIR=1,		/* string1 contains new dumpdir */
};

struct whack_message {
	unsigned int magic;

	bool whack_status;
	bool whack_global_status;
	bool whack_clear_stats;
	bool whack_traffic_status;
	bool whack_shunt_status;
	bool whack_fips_status;
	bool whack_brief_status;
	bool whack_addresspool_status;
	bool whack_show_states;
	bool whack_seccomp_crashtest;

	bool whack_shutdown;

	/* END OF BASIC COMMANDS
	 * If you change anything earlier in this struct, update WHACK_BASIC_MAGIC.
	 */

	bool whack_process_status; /* non-basic */

	bool whack_leave_state; /* dont send delete or  clean kernel state on shutdown */
	/* name is used in connection and initiate */
	size_t name_len; /* string 1 */
	char *name;

	/* for WHACK_OPTIONS: */

	bool whack_options;

	lmod_t debugging;

	/* what to impair and how */
	struct whack_impair *impairments;
	unsigned nr_impairments;

	/* for WHACK_CONNECTION */

	bool whack_connection;
	bool whack_async;

	enum ike_version ike_version;
	lset_t policy;
	lset_t sighash_policy;
	deltatime_t sa_ike_life_seconds;
	deltatime_t sa_ipsec_life_seconds;
	deltatime_t sa_rekey_margin;
	unsigned long sa_rekey_fuzz;
	unsigned long sa_keying_tries;
	unsigned long sa_replay_window;
	deltatime_t r_timeout; /* in secs */
	deltatime_t r_interval; /* in msec */
	enum yna_options nic_offload;
	uint32_t xfrm_if_id;

	/* For IKEv1 RFC 3706 - Dead Peer Detection */
	deltatime_t dpd_delay;
	deltatime_t dpd_timeout;
	enum dpd_action dpd_action;
	int dpd_count;

	/* Cisco interop:  remote peer type */
	enum keyword_remotepeertype remotepeertype;

	/* Force the use of NAT-T on a connection */
	enum yna_options encaps;

	/* Remote TCP port to use, 0 indicates no TCP */
	int remote_tcpport;

	/* Allow TCP as fallback, only do TCP or only do UDP */
	enum tcp_options iketcp;

	/* Option to allow per-conn setting of sending of NAT-T keepalives - default is enabled  */
	bool nat_keepalive;
	/* Option to tweak sending NATT drafts, rfc or both  */
	enum ikev1_natt_policy ikev1_natt;

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
	bool nmconfigured;

	/* XAUTH Authentication can be file (default) PAM or 'alwaysok' */
	enum keyword_xauthby xauthby;


	/* XAUTH failure mode can be hard (default) or soft */
	enum keyword_xauthfail xauthfail;
	enum send_ca_policy send_ca;

	/* Force the MTU for this connection */
	int connmtu;

	uint32_t sa_priority;
	uint32_t sa_tfcpad;
	bool send_no_esp_tfc;
	reqid_t sa_reqid;
	int nflog_group;

	char *sec_label;

	/*  note that each end contains string 2/5.id, string 3/6 cert,
	 *  and string 4/7 updown
	 */
	struct whack_end left;
	struct whack_end right;

	/* note: if the client is the gateway, the following must be equal */
	sa_family_t tunnel_addr_family;	/* between clients */

	char *ike;			/* ike algo string (separated by commas) */
	char *pfsgroup;			/* pfsgroup will be "encapsulated" in esp string for pluto */
	char *esp;			/* esp algo string (separated by commas) */

	/* for WHACK_KEY: */
	bool whack_key;
	bool whack_addkey;
	char *keyid;	/* string 8 */
	enum pubkey_alg pubkey_alg;
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

	/* for WHACK_TERMINATE: */
	bool whack_terminate;

	/* for WHACK_DELETE: */
	bool whack_delete;

	/* for WHACK_DELETESTATE: */
	bool whack_deletestate;
	long unsigned int whack_deletestateno;

	/* rekey now */
	bool whack_rekey_ike; /* rekey the latest ike now */
	bool whack_rekey_ipsec;  /* rekey latest ipsec now */

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
	bool whack_check_pub_keys;
	lset_t whack_list;

	/* for WHACK_REREAD */
	uint8_t whack_reread;

	/* for connalias string */
	char *connalias;

	/* for IKEv1 MODECFG and IKEv2 CP */
	char *modecfg_dns;
	char *modecfg_domains;
	char *modecfg_banner;

	char *conn_mark_both;
	char *conn_mark_in;
	char *conn_mark_out;

	char *vti_iface;
	bool vti_routing; /* perform routing into vti device or not */
	bool vti_shared; /* use remote %any and skip cleanup on down? */

	/* for RFC 5685 - IKEv2 Redirect mechanism */
	enum allow_global_redirect global_redirect;
	char *global_redirect_to;
	char *redirect_to;
	char *accept_redirect_to;

	char *active_redirect_dests;

	/* what metric to put on ipsec routes */
	int metric;

	char *dnshostname;

	/* for use with general option adjustments */
	enum whack_opt_set opt_set;
	char *string1;
	char *string2;
	char *string3;

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

/* options of whack --reread*** command */

#define REREAD_NONE	0x00		/* don't reread anything */
#define REREAD_SECRETS	0x01		/* reread /etc/ipsec.secrets */
#define REREAD_CRLS	0x02		/* obsoleted - just gives a warning */
#define REREAD_FETCH	0x04		/* update CRL from distribution point(s) */
#define REREAD_CERTS	0x08		/* update CERT(S) of connection(s) */
#define REREAD_ALL	LRANGES(REREAD_SECRETS, REREAD_CERTS)	/* all reread options */

struct whackpacker {
	struct whack_message *msg;
	unsigned char *str_roof;
	unsigned char *str_next;
	int n;
};

extern err_t pack_whack_msg(struct whackpacker *wp);
extern bool unpack_whack_msg(struct whackpacker *wp, struct logger *logger);
extern void clear_end(struct whack_end *e);

extern size_t whack_get_secret(char *buf, size_t bufsize);
extern int whack_get_value(char *buf, size_t bufsize);

extern bool lsw_alias_cmp(const char *name, const char *aliases);

#endif /* _WHACK_H */
