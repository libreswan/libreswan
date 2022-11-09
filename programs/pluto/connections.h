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
 * Copyright (C) 2019-2022 Andrew Cagney <cagney@gnu.org>
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
#include "id.h"    /* for struct id */
#include "lmod.h"
#include "err.h"
#include "ip_endpoint.h"
#include "ip_selector.h"
#include "ip_protoport.h"
#include "ip_packet.h"

#include "defs.h"
#include "proposals.h"
#include "hash_table.h"
#include "diag.h"
#include "ckaid.h"
#include "authby.h"
#include "ip_index.h"

/*
 * Note that we include this even if not X509, because we do not want
 * the structures to change lots.
 */
#include "x509.h"
#include "certs.h"
#include "reqid.h"
#include "state.h"
#include "whack.h"

struct host_pair;	/* opaque type */

/*
 * Fast access to a connection.
 */

struct connection *connection_by_serialno(co_serial_t serialno);

/*
 * An extract of the original configuration information for
 * the connection's end sent over by whack.
 */

enum left_right { LEFT_END, RIGHT_END, };
#define END_ROOF 2

/*
 * IKE SA configuration.
 *
 * This contains stuff used by IKE_SA_INIT + IKE_AUTH to establish and
 * then authenticate the IKE SA.
 */

struct host_end_config {
	const char *leftright;

	char *addr_name;	/* string version from whack */

	unsigned ikeport;
	enum keyword_host type;
	/*
	 * Proof of identity.
	 */
	enum keyword_auth auth;
	struct authby authby;

	cert_t cert;			/* end certificate */
	enum certpolicy sendcert;	/* whether or not to send the certificate */
	chunk_t ca;			/* CA distinguished name of the end certificate's issuer */
	ckaid_t *ckaid;

	/*
	 * How to handle CP packets (or MODECFG packets in IKEv1).
	 */
	struct {
		bool server;	/* give local addresses to tunnel's end */
		bool client;	/* request address for local end */
	} modecfg;

	bool client_address_translation;		/* aka CAT */

	struct {
		bool server;
		bool client;
		char *username;
	} xauth;

	enum eap_options eap;		/* whether to require/do EAP auth (eg EAPTLS) */
	bool key_from_DNS_on_demand;
};

/*
 * Child SA configuration.
 *
 * This contains stuff used by CREATE_CHILD_SA to establish an IPsec
 * connection.
 */

struct child_end_config {
	const char *leftright;
	ip_protoport protoport;
	char *updown;

	/*
	 * This means something, although exactly what isn't clear.
	 */
	bool has_client;

	struct {
		ip_selector *list;
		/* log "{.leftright}${.selectors_field}=${.selectors_string} */
		const char *field;
		char *string;
	} selectors;

	ip_address sourceip;

	/*
	 * Weired host related client stuff.
	 *
	 * It's only used when there's a Child SA.
	 */
	ip_cidr host_vtiip;
	ip_cidr ifaceip;
	struct virtual_ip *virt;

	/* Did ...subnet=... appear in the config file? */
	bool v1_config_subnet_specified;
};

struct spd_end_config {
	enum left_right index;
	const char *leftright;
	struct host_end_config host;
	struct child_end_config child;
};

struct ike_info {
	/* 1|2 */
	enum ike_version version;
	/* IKEv1|IKEv2 */
	const char *version_name;
	/* [IKE_SA] = ISAKMP SA | IKE SA */
	/* [IPSEC_SA = IPsec SA | Child SA */
	const char *sa_type_name[SA_TYPE_ROOF];
};

struct config {
	enum ike_version ike_version;
	const struct ike_info *ike_info;

	char *connalias;
	chunk_t sec_label;

	deltatime_t retransmit_interval; /* initial retransmit time, doubles each time */
	deltatime_t retransmit_timeout; /* max time for one packet exchange attempt */
	uintmax_t sa_ipsec_max_bytes;
	uintmax_t sa_ipsec_max_packets;

	deltatime_t sa_ike_max_lifetime;
	deltatime_t sa_ipsec_max_lifetime;
	deltatime_t sa_rekey_margin;
	unsigned long sa_rekey_fuzz;

	lset_t sighash_policy;
	enum shunt_policy prospective_shunt;	/* before */
	enum shunt_policy negotiation_shunt;	/* during */
	enum shunt_policy failure_shunt;	/* after */

	enum keyword_xauthby xauthby;
	enum keyword_xauthfail xauthfail;

	struct {
		char *to;        /* RFC 5685 */
		char *accept;
	} redirect;

	/*
	 * The proposal specified in the config file, and for IKEv2,
	 * that proposal converted to IKEv2 form.
	 *
	 * IKEv2 proposals negotiated during the initial exchanges
	 * (IKE_SA_INIT - IKE SA, IKE_AUTH - Child SA) can be computed
	 * ahead of time, and are stored below.
	 *
	 * However, proposals negotiated during CREATE_CHILD_SA
	 * cannot.  For instance, the CREATE_CHILD_SA may be re-keying
	 * the IKE SA and it's DH is only determined during the
	 * initial negotiation.
	 */
	struct ike_proposals ike_proposals;
	struct child_proposals child_proposals;
	struct ikev2_proposals *v2_ike_proposals;
	struct ikev2_proposals *v2_ike_auth_child_proposals;

	enum yna_options nic_offload;
	char *dnshostname;

	struct {
		ip_address *dns;	/* !.is_set terminated list */
		shunk_t *domains;	/* NULL terminated list */
		char *banner;
	} modecfg;

	/*
	 * IKEv1's RFC 3706 DPD; .delay also used by IKEv2 :-/ */
	struct {
		deltatime_t delay;		/* time between checks */
		deltatime_t timeout;	/* time after which we are dead */
		enum dpd_action action;	/* what to do when we die */
	} dpd;

	bool send_no_esp_tfc;
	bool send_initial_contact;		/* Send INITIAL_CONTACT (RFC-2407) payload? */
	bool send_vendorid;			/* Send our vendorid? Security vs Debugging help */
	bool send_vid_fake_strongswan;		/* Send the unversioned strongswan VID */
	bool send_vid_cisco_unity;		/* Send Unity VID for cisco compatibility */

	struct spd_end_config end[END_ROOF];
};

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

void set_policy_prio(struct connection *c);

typedef struct {
	char buf[3 + 1 + 3 + 1 + 10 + 1];	/* (10 is to silence GCC) */
} policy_prio_buf;
size_t jam_policy_prio(struct jambuf *buf, policy_prio_t pp);
const char *str_policy_prio(policy_prio_t pp, policy_prio_buf *buf);

struct host_end {
	const struct host_end_config *config;
	bool encap;			/* are packets encapsulated */
	uint16_t port;			/* where the IKE port is */
	ip_address nexthop;		/* identifes interface to send packets */
	struct id id;
	ip_address addr;
};

struct child_end {
	const struct child_end_config *config;
};

struct connection_end {
	const struct spd_end_config *config;
	struct host_end host;
	struct child_end child;
};

struct spd_end {
	ip_selector client;

	/*
	 * An extract of the original configuration information for
	 * the connection's end sent over by whack.
	 *
	 * Danger: for a connection instance, this point into the
	 * parent connection.
	 */
	const struct spd_end_config *config;
	struct host_end *host;

	chunk_t sec_label;
	bool has_client;

	struct virtual_ip *virt;

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
	bool has_cat;		/* add a CAT iptable rule when a valid INTERNAL_IP4_ADDRESS
				   is received */
};

struct spd_route {
	struct spd_route *spd_next;
	struct spd_end end[END_ROOF];
	/* point into above */
	struct spd_end *local;		/* must update after clone */
	struct spd_end *remote;		/* must update after clone */
	struct connection *connection;
	so_serial_t eroute_owner;
#define set_spd_owner(SPD, SO)						\
	{								\
		connection_buf cb;					\
		dbg("kernel: spd owner: "PRI_CONNECTION" "PRI_SO"->"PRI_SO" "PRI_WHERE, \
		    pri_connection((SPD)->connection, &cb),		\
		    pri_so((SPD)->eroute_owner),			\
		    /* SO could be an enum :-( */			\
		    pri_so((so_serial_t)SO),				\
		    pri_where(HERE));					\
		(SPD)->eroute_owner = SO;				\
	}

	enum routing_t routing; /* level of routing in place */
#define set_spd_routing(SPD, RT)					\
	{								\
		connection_buf cb;					\
		enum_buf ob, nb;					\
		dbg("kernel: spd routing: "PRI_CONNECTION" %s->%s "PRI_WHERE, \
		    pri_connection((SPD)->connection, &cb),		\
		    str_enum(&routing_story, (SPD)->routing, &ob),	\
		    str_enum(&routing_story, RT, &nb),			\
		    pri_where(HERE));					\
		(SPD)->routing = RT;					\
	}
	reqid_t reqid;
	struct {
		struct list_entry list;
		struct list_entry remote_client;
	} hash_table_entries;
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
	co_serial_t serial_from; /* "0" when connection root */
	char *name;
	struct logger *logger;
	char *foodgroup;
	lset_t policy;
	unsigned long sa_keying_tries;
	uint32_t sa_priority;
	uint32_t sa_tfcpad;
	uint32_t sa_replay_window; /* Usually 32, KLIPS and XFRM/NETKEY support 64 */
				   /* See also kernel_ops->replay_window */
	struct sa_marks sa_marks; /* contains a MARK values and MASK value for IPsec SA */
	char *vti_iface;
	bool vti_routing; /* should updown perform routing into the vti device */
	bool vti_shared; /* should updown leave remote empty and not cleanup device on down */
	struct pluto_xfrmi *xfrmi; /* pointer to possibly shared interface */

	reqid_t sa_reqid;

	bool nat_keepalive;		/* Send NAT-T Keep-Alives if we are behind NAT */
	bool mobike;			/* Allow MOBIKE */
	enum ikev1_natt_policy ikev1_natt; /* whether or not to send IKEv1 draft/rfc NATT VIDs */
	enum yna_options encaps; /* encapsulation mode of auto/yes/no - formerly forceencaps=yes/no */

	enum tcp_options iketcp;	/* Allow TCP as fallback, insist on TCP or stick to UDP */
	int remote_tcpport;		/* TCP remote port to use - local port will be ephemeral */

	/* Network Manager support */
#ifdef HAVE_NM
	bool nmconfigured;
#endif

	/* Cisco interop: remote peer type */
	enum keyword_remotepeertype remotepeertype;

	char *log_file_name;			/* name of log file */
	FILE *log_file;				/* possibly open FILE */
	bool log_file_err;			/* only bitch once */

	struct spd_route *spd;

	/* internal fields: */

	unsigned long instance_serial;
	policy_prio_t policy_prio;
	bool instance_initiation_ok;		/* this is an instance of a policy that mandates initiate */
	enum connection_kind kind;
	struct iface_endpoint *interface;	/* filled in iff oriented */

	struct ephemeral_variables temp_vars;

	so_serial_t		/* state object serial number */
		newest_ike_sa,
		newest_ipsec_sa;

	lmod_t extra_debugging;

	/* if multiple policies, next one to apply */
	struct connection *policy_next;

	/* host_pair linkage */
	struct host_pair *host_pair;
	struct connection *hp_next;

	enum send_ca_policy send_ca;

	struct addresspool *pool[IP_INDEX_ROOF];

	uint32_t metric;	/* metric for tunnel routes */
	uint16_t connmtu;	/* mtu for tunnel routes */
	uint16_t nflog_group;	/* NFLOG group - 0 means disabled */
	msgid_t ike_window;     /* IKE v2 window size 7296#section-2.3 */

	struct {
		struct list_entry list;
		struct list_entry serialno;
		struct list_entry that_id;
	} hash_table_entries;

	/*
	 * An extract of the original configuration information for
	 * the connection's end sent over by whack.  This pointer is
	 * only valid in the root connection created from a whack
	 * message.
	 */
	struct config *root_config;

	/*
	 * Pointers to the connection's original configuration values
	 * as specified by whack.
	 *
	 * For a connection instance, these point into connection the
	 * template.
	 */
	const struct config *config;

	struct connection_end *local;
	struct connection_end *remote;
	struct connection_end end[END_ROOF];
};

extern bool same_peer_ids(const struct connection *c,
			  const struct connection *d, const struct id *peers_id);

/*
 * Format the topology of a connection end, leaving out defaults.
 * Largest left end looks like: client === host : port [ host_id ] ---
 * hop Note: if that==NULL, skip nexthop
 */
void jam_end(struct jambuf *buf, const struct spd_end *this, const struct spd_end *that,
	     enum left_right left_right, lset_t policy, bool filter_rnh);

struct whack_message;   /* forward declaration of tag whack_msg */
extern void add_connection(const struct whack_message *wm, struct logger *logger);

void update_host_ends_from_this_host_addr(struct host_end *this, struct host_end *that);
void update_spd_ends_from_host_ends(struct connection *c);
extern void restart_connections_by_peer(struct connection *c, struct logger *logger);
extern void flush_revival(const struct connection *c);

extern void terminate_connections_by_name(const char *name, bool quiet, struct logger *logger);
extern void release_connection(struct connection *c);
extern void delete_connection(struct connection **cp);
extern void delete_connections_by_name(const char *name, bool strict, struct logger *logger);
extern void delete_every_connection(void);
struct connection *add_group_instance(struct connection *group,
				      const ip_selector *target,
				      uint8_t proto,
				      uint16_t sport,
				      uint16_t dport);

extern struct connection *route_owner(struct connection *c,
				      const struct spd_route *cur_spd,
				      struct spd_route **srp,
				      struct connection **erop,
				      struct spd_route **esrp);

extern struct connection *shunt_owner(const ip_selector *ours,
				      const ip_selector *peers);
extern void rekey_now(const char *name, enum sa_type sa_type,
		      bool background, struct logger *logger);

#define remote_id_was_instantiated(c) \
	( (c)->kind == CK_INSTANCE && \
	  ( !id_is_ipaddr(&(c)->remote->host.id) || \
	    sameaddr(&(c)->remote->host.id.ip_addr, &(c)->remote->host.addr) ) )

struct state;   /* forward declaration of tag (defined in state.h) */

extern struct connection *conn_by_name(const char *nm, bool strict);
struct connection *find_connection_for_packet(struct spd_route **srp,
					      const ip_packet packet,
					      shunk_t sec_label,
					      struct logger *logger);

/* instantiating routines */

struct alg_info;        /* forward declaration of tag (defined in alg_info.h) */

extern struct connection *rw_instantiate(struct connection *c,
					 const ip_address *peer_addr,
					 const ip_selector *peer_subnet,
					 const struct id *peer_id);
struct connection *oppo_instantiate(struct connection *c,
				    const struct id *remote_id,
				    const ip_address *local_address,
				    const ip_address *remote_address);
extern struct connection *instantiate(struct connection *c,
				      const ip_address *peer_addr,
				      const struct id *peer_id,
				      shunk_t sec_label);

struct connection *find_outgoing_opportunistic_template(const ip_packet packet);

/* publicly useful? */
size_t jam_connection_instance(struct jambuf *buf, const struct connection *c);
size_t jam_connection(struct jambuf *buf, const struct connection *c);

size_t jam_connection_policies(struct jambuf *buf, const struct connection *c);
const char *str_connection_policies(const struct connection *c, policy_buf *buf);

/*
 * XXX: Instead of str_connection(), which would require a buffer big
 * enough to fit an any length name, there's PRI_CONNECTION et.al.
*/

typedef struct {
	char buf[/*why?*/ 1 +
		 /*"["*/ 1 +
		 /*<serialno>*/ 10 +
		 /*"]"*/ 1 +
		 /*<myclient*/sizeof(subnet_buf) +
		 /*"=== ..."*/ 7 +
		 /*<peer>*/sizeof(address_buf) +
		 /*"==="*/ 3 +
		 /*<peer_client>*/sizeof(subnet_buf) +
		 /*"\0"*/ 1 +
		 /*<cookie>*/ 1];
} connection_buf;

const char *str_connection_instance(const struct connection *c,
				    connection_buf *buf);

#define PRI_CONNECTION "\"%s\"%s"
#define pri_connection(C,B) (C)->name, str_connection_instance(C, B)

extern void connection_delete_unused_instance(struct connection **cp, struct state *old_state, struct fd *whackfd);

/*
 * A template connection's eroute can be eclipsed by either a %hold or
 * an eroute for an instance IFF the template is a /32 -> /32.  This
 * requires some special casing.
 */
#define eclipsable(sr) (selector_contains_one_address((sr)->local->client) && \
			selector_contains_one_address((sr)->remote->client))
struct spd_route *eclipsing(const struct spd_route *sr);

/* print connection status */

extern void show_connections_status(struct show *s);
extern int connection_compare(const struct connection *ca,
			      const struct connection *cb);

void connection_check_ddns(struct logger *logger);
void connection_check_phase2(struct logger *logger);
void init_connections_timer(void);

extern int foreach_connection_by_alias(const char *alias,
				       int (*f)(struct connection *c,
						void *arg, struct logger *logger),
				       void *arg, struct logger *logger);

/* -1: none found */
extern int foreach_concrete_connection_by_name(const char *name,
					       int (*f)(struct connection *c,
							void *arg, struct logger *logger),
					       void *arg, struct logger *logger);

extern uint32_t calculate_sa_prio(const struct connection *c, bool oe_shunt);

so_serial_t get_newer_sa_from_connection(struct state *st);

diag_t add_end_cert_and_preload_private_key(CERTCertificate *cert,
					    struct host_end *host_end,
					    struct host_end_config *host_end_config,
					    bool preserve_ca,
					    struct logger *logger);

ip_port end_host_port(const struct host_end *this, const struct host_end *that);

/*
 * For iterating over the connection DB.
 *
 * - parameters are only matched when non-NULL or non-zero
 * - .connection can be deleted between calls
 * - some filters have been optimized using hashing, but
 * - worst case is it scans through all connections
 */

struct connection_filter {
	/* filters */
	enum connection_kind kind;
	const char *name;
	const struct id *this_id_eq; /* strict; not same_id() */
	const struct id *that_id_eq; /* strict; not same_id() */
	/* current result (can be safely deleted) */
	struct connection *c;
	/* internal: handle on next entry */
	struct list_entry *internal;
	/* internal: total matches so far */
	unsigned count;
	/* .where MUST BE LAST (See GCC bug 102288) */
	where_t where;
};

bool next_connection_old2new(struct connection_filter *query);
bool next_connection_new2old(struct connection_filter *query);

/*
 * For iterating over the spd_route DB.
 *
 * - parameters are only matched when non-NULL or non-zero
 * - .connection can be deleted between calls
 * - some filters have been optimized using hashing, but
 * - worst case is it scans through all spds
 *
 * Note: the ORDER is based on insertion; so when an entry gets
 * re-hashed (i.e., deleted and then inserted) it also becomes the
 * newest entry.
 */

struct spd_route_filter {
	const ip_selector *remote_client_range;
	/* current result (can be safely deleted) */
	struct spd_route *spd;
	/* internal: handle on next entry */
	struct list_entry *internal;
	/* internal: total matches so far */
	unsigned count;
	/* .where MUST BE LAST (See GCC bug 102288) */
	where_t where;
};

bool next_spd_route(enum chrono order, struct spd_route_filter *srf);

void check_connection(struct connection *c, where_t where);

void replace_connection_that_id(struct connection *c, const struct id *new_id);
void rehash_db_connection_that_id(struct connection *c);

void rehash_db_spd_route_remote_client(struct spd_route *sr);

bool dpd_active_locally(const struct connection *c);

ip_address spd_route_end_sourceip(enum ike_version ike_version, const struct spd_end *end);

#endif
