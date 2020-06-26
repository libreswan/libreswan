/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2001,2010-2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@cyclops.xelerance.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 Kim Heino <b@bbbs.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "fd.h"
#include "proposals.h"
#include "connection_db.h"		/* for co_serial_t */
#include "hash_table.h"

/* There are two kinds of connections:
 * - ISAKMP connections, between hosts (for IKE communication)
 * - IPsec connections, between clients (for secure IP communication)
 *
 * An ISAKMP connection looks like:
 *   host<--->host
 *
 * An IPsec connection looks like:
 *   client-subnet<-->host<->nexthop<--->nexthop<->host<-->client-subnet
 *
 * For the connection to be relevant to this instance of Pluto,
 * exactly one of the hosts must be a public interface of our machine
 * known to this instance.
 *
 * The client subnet might simply be the host -- this is a
 * representation of "host mode".
 *
 * Each nexthop defaults to the neighbouring host's IP address.
 * The nexthop is a property of the pair of hosts, not each
 * individually.  It is only needed for IPsec because of the
 * way IPsec is mixed into the kernel routing logic.  Furthermore,
 * only this end's nexthop is actually used.  Eventually, nexthop
 * will be unnecessary.
 *
 * Other information represented:
 * - each connection has a name: a chunk of uninterpreted text
 *   that is unique for each connection.
 * - security requirements (currently just the "policy" flags from
 *   the whack command to initiate the connection, but eventually
 *   much more.  Different for ISAKMP and IPsec connections.
 * - rekeying parameters:
 *   + time an SA may live
 *   + time before SA death that a rekeying should be attempted
 *     (only by the initiator)
 *   + number of times to attempt rekeying
 * - With the current KLIPS, we must route packets for a client
 *   subnet through the ipsec interface (ipsec0).  Only one
 *   gateway can get traffic for a specific (client) subnet.
 *   Furthermore, if the routing isn't in place, packets will
 *   be sent in the clear.
 *   "routing" indicates whether the routing has been done for
 *   this connection.  Note that several connections may claim
 *   the same routing, as long as they agree about where the
 *   packets are to be sent.
 * - With the current KLIPS, only one outbound IPsec SA bundle can be
 *   used for a particular client.  This is due to a limitation
 *   of using only routing for selection.  So only one IPsec state (SA)
 *   may "own" the eroute.  "eroute_owner" is the serial number of
 *   this state, SOS_NOBODY if there is none.  "routing" indicates
 *   what kind of erouting has been done for this connection, if any.
 *
 * Details on routing is in constants.h
 *
 * Operations on Connections:
 *
 * - add a new connection (with all details) [whack command]
 * - delete a connection (by name) [whack command]
 * - initiate a connection (by name) [whack command]
 * - find a connection (by IP addresses of hosts)
 *   [response to peer request; finding ISAKMP connection for IPsec connection]
 *
 * Some connections are templates, missing the address of the peer
 * (represented by INADDR_ANY).  These are always arranged so that the
 * missing end is "that" (there can only be one missing end).  These can
 * be instantiated (turned into real connections) by Pluto in one of two
 * different ways: Road Warrior Instantiation or Opportunistic
 * Instantiation.  A template connection is marked for Opportunistic
 * Instantiation by specifying the peer client as 0.0.0.0/32 (or the IPV6
 * equivalent).  Otherwise, it is suitable for Road Warrior Instantiation.
 *
 * Instantiation creates a new temporary connection, with the missing
 * details filled in.  The resulting template lasts only as long as there
 * is a state that uses it.
 */

/* connection policy priority: how important this policy is
 * - used to implement eroute-like precedence (augmented by a small
 *   bonus for a routed connection).
 * - a whole number
 * - larger is more important
 * - three subcomponents.  In order of decreasing significance:
 *   + length of source subnet mask (9 bits)
 *   + length of destination subnet mask (9 bits)
 *   + bias (8 bit)
 * - a bias of 1 is added to allow prio BOTTOM_PRIO to be less than all
 *   normal priorities
 * - other bias values are created on the fly to give mild preference
 *   to certain conditions (eg. routedness)
 * - priority is inherited -- an instance of a policy has the same priority
 *   as the original policy, even though its subnets might be smaller.
 * - display format: n,m
 *
 * ??? These are NOT the same as sa_priorities but eventually they should be aligned.
 */
typedef uint32_t policy_prio_t;
#define BOTTOM_PRIO   ((policy_prio_t)0)        /* smaller than any real prio */

#define set_policy_prio(c) { (c)->prio = \
		  ((policy_prio_t)(c)->spd.this.client.maskbits << 17) \
		| ((policy_prio_t)(c)->spd.that.client.maskbits << 8) \
		|  (policy_prio_t)1; }

#define POLICY_PRIO_BUF (3 + 1 + 3 + 1 + 10)	/* (10 is to silence GCC) */
extern void fmt_policy_prio(policy_prio_t pp, char buf[POLICY_PRIO_BUF]);

/* Note that we include this even if not X509, because we do not want the
 * structures to change lots.
 */
#include "x509.h"
#include "certs.h"
#include "defs.h"
#include <sys/queue.h>
#include "id.h"    /* for struct id */
#include "lmod.h"
#include "reqid.h"
#include "err.h"
#include "state.h"
#include "ip_endpoint.h"
#include "ip_selector.h"
#include "ip_protoport.h"
#include "whack.h"

struct virtual_t;	/* opaque type */

struct host_pair;	/* opaque type */

struct end {
	const char *leftright;
	struct id id;

	enum keyword_host host_type;
	char *host_addr_name;	/* string version from whack */
	ip_address
		host_addr,
		host_nexthop,
		host_srcip;
	ip_subnet
		host_vtiip,
		ifaceip;

	ip_selector client;

	/* original information from whack */
	struct {
		struct {
			ip_subnet subnet;
			ip_protoport protoport;
		} client;
		struct {
			unsigned ikeport;
		} host;
	} raw;

	bool key_from_DNS_on_demand;
	bool has_client;
	bool has_id_wildcards;
	char *updown;
	uint16_t host_port;		/* where the IKE port is */
	/*
	 * Was the PORT, in the PROTOPORT included in the whack
	 * message "wild"?  Can't use .port as that will have been
	 * scribbled on by a negotiation :-(
	 */
	bool has_port_wildcard;
	uint16_t port;			/* port number, if per-port keying */
	uint8_t protocol;		/* transport-protocol number, if per-X keying */

	enum certpolicy sendcert;	/* whether or not to send the certificate */
	cert_t cert;			/* end certificate */
	chunk_t ca;			/* CA distinguished name of the end certificate's issuer */

	struct virtual_t *virt;

	enum keyword_authby authby;

	bool xauth_server;
	bool xauth_client;
	char *xauth_username;
	char *xauth_password;
	ip_range pool_range;	/* store start of v4 addresspool */

	/*
	 * Track lease addresses.
	 *
	 * HAS_LEASE indicates that "this" sent "that.CLIENT" has an
	 * address from the address pool.
	 *
	 * HAS_INTERNAL_ADDRESS indicates "that" sent "this.CLIENT" is
	 * an address, presumably from the address pool.
	 *
	 * Probably only one field is needed, but then what if the
	 * same pluto is receiving and giving out addresses?
	 */
	bool has_lease;		/* server gave out lease from address pool */
	bool has_internal_address;
	bool modecfg_server;	/* Give local addresses to tunnel's end */
	bool modecfg_client;	/* request address for local end */
	bool cat;		/* IPv4 Client Address Translation */
	bool has_cat;		/* add a CAT iptable rule when a valid INTERNAL_IP4_ADDRESS
				   is received */
};

struct spd_route {
	struct spd_route *spd_next;
	struct end this;
	struct end that;
	so_serial_t eroute_owner;
	enum routing_t routing; /* level of routing in place */
	reqid_t reqid;
};

struct sa_mark {
	uint32_t val;
	uint32_t mask;
	bool unique;
};

struct sa_marks {
	struct sa_mark in;
	struct sa_mark out;
};

/* this struct will be used for
 * storing ephemeral stuff, that doesn't
 * need i.e. to be stored to connection
 * .conf files.
 */
struct ephemeral_variables {
	int revive_delay;
	/* RFC 5685 - IKEv2 Redirect Mechanism */
	int num_redirects;
	realtime_t first_redirect_time;
	ip_address redirect_ip;		/* where to redirect */
	ip_address old_gw_address;	/* address of old gateway */
};

struct connection {
	co_serial_t serialno;
	co_serial_t serial_from;
	char *name;
	enum ike_version ike_version;
	char *foodgroup;
	char *connalias;
	lset_t policy;
	lset_t sighash_policy;
	deltatime_t sa_ike_life_seconds;
	deltatime_t sa_ipsec_life_seconds;
	deltatime_t sa_rekey_margin;
	unsigned long sa_rekey_fuzz;
	unsigned long sa_keying_tries;
	uint32_t sa_priority;
	uint32_t sa_tfcpad;
	bool send_no_esp_tfc;
	uint32_t sa_replay_window; /* Usually 32, KLIPS and XFRM/NETKEY support 64 */
				   /* See also kernel_ops->replay_window */
	struct sa_marks sa_marks; /* contains a MARK values and MASK value for IPsec SA */
	char *vti_iface;
	bool vti_routing; /* should updown perform routing into the vti device */
	bool vti_shared; /* should updown leave remote empty and not cleanup device on down */
	struct pluto_xfrmi *xfrmi; /* pointer to possibly shared interface */

	deltatime_t r_interval; /* initial retransmit time, doubles each time */
	deltatime_t r_timeout; /* max time (in secs) for one packet exchange attempt */
	reqid_t sa_reqid;
	/*
	 * XXX: this field is used by the kernel to remember the mode
	 * that the IPsec SA was installed as so that the delete knows
	 * how to delete it.  Shouldn't that be part of the CHILD SA's
	 * state?
	 */
	int ipsec_mode;			/* tunnel or transport or IKEv1 ... */
	enum yna_options nic_offload;

	/* RFC 3706 DPD */
	deltatime_t dpd_delay;		/* time between checks */
	deltatime_t dpd_timeout;	/* time after which we are dead */
	enum dpd_action dpd_action;	/* what to do when we die */

	bool nat_keepalive;		/* Send NAT-T Keep-Alives if we are behind NAT */
	bool initial_contact;		/* Send INITIAL_CONTACT (RFC-2407) payload? */
	bool cisco_unity;		/* Send Unity VID for cisco compatibility */
	bool fake_strongswan;		/* Send the unversioned strongswan VID */
	bool mobike;			/* Allow MOBIKE */
	bool send_vendorid;		/* Send our vendorid? Security vs Debugging help */
	enum ikev1_natt_policy ikev1_natt; /* whether or not to send IKEv1 draft/rfc NATT VIDs */
	enum yna_options encaps; /* encapsulation mode of auto/yes/no - formerly forceencaps=yes/no */

	bool tcponly;
	int remote_tcpport;

	/* Network Manager support */
#ifdef HAVE_NM
	bool nmconfigured;
#endif
	char *policy_label;

	/* Cisco interop: remote peer type */
	enum keyword_remotepeertype remotepeertype;

	enum keyword_xauthby xauthby;
	enum keyword_xauthfail xauthfail;

	char *log_file_name;			/* name of log file */
	FILE *log_file;				/* possibly open FILE */
	CIRCLEQ_ENTRY(connection) log_link;	/* linked list of open conns {} */
	bool log_file_err;			/* only bitch once */

	struct spd_route spd;

	/* internal fields: */

	unsigned long instance_serial;
	policy_prio_t prio;
	bool instance_initiation_ok;		/* this is an instance of a policy that mandates initiate */
	enum connection_kind kind;
	const struct iface_port *interface;	/* filled in iff oriented */

	struct ephemeral_variables temp_vars;

	so_serial_t		/* state object serial number */
		newest_isakmp_sa,
		newest_ipsec_sa;

	lmod_t extra_debugging;

	/* if multiple policies, next one to apply */
	struct connection *policy_next;

	struct ike_proposals ike_proposals;
	struct child_proposals child_proposals;

	/*
	 * The ALG_INFO converted to IKEv2 format.
	 *
	 * Since they are allocated on-demand so there's no need to
	 * worry about copying them when a connection object gets
	 * cloned.
	 *
	 * For a child SA, two different proposals are used:
	 *
	 * - during the IKE_AUTH exchange a proposal stripped of any
	 *   DH (it uses keying material from the IKE SA's SKSEED).
	 *
	 * - during a CREATE_CHILD_SA exchange, a mash up of the
	 *   proposal and the IKE SA's DH algorithm.  Since the IKE
	 *   SA's DH can change, it too is saved so a rebuild can be
	 *   triggered.
	 *
	 * XXX: has to be a better way?
	 */
	struct ikev2_proposals *v2_ike_proposals;
	struct ikev2_proposals *v2_ike_auth_child_proposals;
	struct ikev2_proposals *v2_create_child_proposals;
	const struct dh_desc *v2_create_child_proposals_default_dh;

	/* host_pair linkage */
	struct host_pair *host_pair;
	struct connection *hp_next;

	struct connection *ac_next;	/* all connections list link */

	enum send_ca_policy send_ca;
	char *dnshostname;

	struct ip_pool *pool; /* IPv4 addresspool as a range, start end */

	char *modecfg_dns;
	char *modecfg_domains;
	char *modecfg_banner;

	uint32_t metric;	/* metric for tunnel routes */
	uint16_t connmtu;	/* mtu for tunnel routes */
	uint32_t statsval;	/* track what we have told statsd */
	uint16_t nflog_group;	/* NFLOG group - 0 means disabled  */
	msgid_t ike_window;     /* IKE v2 window size 7296#section-2.3 */

	char *redirect_to;        /* RFC 5685 */
	char *accept_redirect_to;

	struct list_entry serialno_list_entry;
	struct list_entry hash_table_entries[CONNECTION_HASH_TABLES_ROOF];
};

#define oriented(c) ((c).interface != NULL)
extern bool orient(struct connection *c);

extern bool same_peer_ids(const struct connection *c,
			  const struct connection *d, const struct id *peers_id);

/* Format the topology of a connection end, leaving out defaults.
 * Largest left end looks like: client === host : port [ host_id ] --- hop
 * Note: if that==NULL, skip nexthop
 */
#define END_BUF (SUBNETTOT_BUF + ADDRTOT_BUF + IDTOA_BUF + ADDRTOT_BUF + 10)
extern size_t format_end(char *buf, size_t buf_len,
			 const struct end *this, const struct end *that,
			 bool is_left, lset_t policy, bool filter_rnh);

struct whack_message;   /* forward declaration of tag whack_msg */
extern void add_connection(struct fd *whackfd, const struct whack_message *wm);
extern void restart_connections_by_peer(struct connection *c);
extern void flush_revival(const struct connection *c);

struct xfrm_user_sec_ctx_ike; /* forward declaration */

extern void initiate_ondemand(const ip_address *our_client,
			     const ip_address *peer_client,
			      int transport_proto,
			      bool held,
			      struct fd *whackfd, bool background,
			      struct xfrm_user_sec_ctx_ike *uctx,
			      const char *why);

extern void terminate_connection(const char *name, bool quiet,
				 struct fd *whack);
extern void release_connection(struct connection *c, bool relations, struct fd *whackfd);
extern void delete_connection(struct connection *c, bool relations);
extern void delete_connections_by_name(const char *name, bool strict,
				       struct fd *whack);
extern void delete_every_connection(void);
extern char *add_group_instance(struct fd *whack,
				struct connection *group,
				const ip_subnet *target,
				uint8_t proto,
				uint16_t sport,
				uint16_t dport);

extern void remove_group_instance(const struct connection *group,
				  const char *name);
extern struct connection *route_owner(struct connection *c,
				      const struct spd_route *cur_spd,
				      struct spd_route **srp,
				      struct connection **erop,
				      struct spd_route **esrp);

extern struct connection *shunt_owner(const ip_subnet *ours,
				      const ip_subnet *peers);
extern void rekey_now(const char *name, enum sa_type sa_type, struct fd *whackfd,
		      bool background);

#define remote_id_was_instantiated(c) \
	( (c)->kind == CK_INSTANCE && \
	  ( !id_is_ipaddr(&(c)->spd.that.id) || \
	    sameaddr(&(c)->spd.that.id.ip_addr, &(c)->spd.that.host_addr) ) )

struct state;   /* forward declaration of tag (defined in state.h) */

extern struct connection *conn_by_name(const char *nm, bool strict);

extern struct connection
	*refine_host_connection(const struct state *st, const struct id *peer_id,
			const struct id *tarzan_id,
			bool initiator, lset_t auth_policy /* used by ikev1 */,
			enum keyword_authby, bool *fromcert),
	*find_client_connection(struct connection *c,
			const ip_subnet *our_net,
			const ip_subnet *peer_net,
			const uint8_t our_protocol,
			const uint16_t out_port,
			const uint8_t peer_protocol,
			const uint16_t peer_port),
	*find_connection_for_clients(struct spd_route **srp,
				      const ip_address *our_client,
				      const ip_address *peer_client,
				      int transport_proto);

/* instantiating routines */

struct alg_info;        /* forward declaration of tag (defined in alg_info.h) */

extern struct connection *rw_instantiate(struct connection *c,
					 const ip_address *peer_addr,
					 const ip_subnet *peer_subnet,
					 const struct id *peer_id);
struct connection *oppo_instantiate(struct connection *c,
				    const ip_address *peer_addr,
				    const struct id *peer_id,
				    const ip_address *our_client,
				    const ip_address *peer_client);
extern struct connection *instantiate(struct connection *c,
				      const ip_address *peer_addr,
				      const struct id *peer_id);

extern struct connection *build_outgoing_opportunistic_connection(
		const ip_address *our_client,
		const ip_address *peer_client,
		const int transport_proto);

/* worst case: "[" serial "] " myclient "=== ..." peer "===" peer_client '\0' <cookie> */
#define CONN_INST_BUF \
	(2 + 10 + 1 + SUBNETTOT_BUF + 7 + ADDRTOT_BUF + 3 + SUBNETTOT_BUF + 1 + 1)

extern char *fmt_conn_instance(const struct connection *c,
			       char buf[CONN_INST_BUF]);

/* publicly useful? */
size_t jam_connection_instance(struct lswlog *buf, const struct connection *c);
size_t jam_connection(struct lswlog *buf, const struct connection *c);

/*
 * XXX: Instead of str_connection(), which would require a buffer big
 * enough to fit an any length name, there's PRI_CONNECTION et.al.
 */

typedef struct {
	char buf[CONN_INST_BUF];
} connection_buf;

const char *str_connection_instance(const struct connection *c,
				    connection_buf *buf);

#define PRI_CONNECTION "\"%s\"%s"
#define pri_connection(C,B) (C)->name, str_connection_instance(C, B)

/* operations on "pending", the structure representing Quick Mode
 * negotiations delayed until a Keying Channel has been negotiated.
 */

struct pending; /* forward declaration (opaque outside connections.c) */

extern void release_pending_whacks(struct state *st, err_t story);
extern void unpend(struct ike_sa *ike, struct connection *cc);
extern void update_pending(struct ike_sa *old_ike, struct ike_sa *new_ike);
extern void flush_pending_by_state(struct ike_sa *ike);

extern void connection_discard(struct connection *c);
extern void update_state_connection(struct state *st, struct connection *c);

/* A template connection's eroute can be eclipsed by
 * either a %hold or an eroute for an instance iff
 * the template is a /32 -> /32.  This requires some special casing.
 */
#define eclipsable(sr) (subnetishost(&(sr)->this.client) && \
			subnetishost(&(sr)->that.client))
extern long eclipse_count;
extern struct connection *eclipsed(const struct connection *c, struct spd_route ** /*OUT*/);

/* print connection status */

extern void show_one_connection(struct show *s,
				const struct connection *c);
extern void show_connections_status(struct show *s);
extern int connection_compare(const struct connection *ca,
			      const struct connection *cb);

void connection_check_ddns(struct fd *whackfd);
void connection_check_phase2(struct fd *whackfd);
void init_connections(void);

extern int foreach_connection_by_alias(const char *alias,
				       struct fd *whackfd,
				       int (*f)(struct connection *c,
						struct fd *whackfd,
						void *arg),
				       void *arg);

extern void unshare_connection_end(struct end *e);

extern void liveness_clear_connection(struct connection *c, const char *v);

extern void liveness_action(struct connection *c, enum ike_version ike_version);

extern uint32_t calculate_sa_prio(const struct connection *c, bool oe_shunt);

so_serial_t get_newer_sa_from_connection(struct state *st);

extern bool load_end_cert_and_preload_secret(struct fd *whackfd,
					     const char *which, const char *pubkey,
					     enum whack_pubkey_type pubkey_type,
					     struct end *dst_end);
extern void reread_cert_connections(struct fd *whackfd);

#endif
