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
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
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
 *   + length of source subnet mask (8 bits)
 *   + length of destination subnet mask (8 bits)
 *   + bias (8 bit)
 * - a bias of 1 is added to allow prio BOTTOM_PRIO to be less than all
 *   normal priorities
 * - other bias values are created on the fly to give mild preference
 *   to certain conditions (eg. routedness)
 * - priority is inherited -- an instance of a policy has the same priority
 *   as the original policy, even though its subnets might be smaller.
 * - display format: n,m
 */
typedef unsigned long policy_prio_t;
#define BOTTOM_PRIO   ((policy_prio_t)0)        /* smaller than any real prio */

#define set_policy_prio(c) { (c)->prio = \
		  ((policy_prio_t)(c)->spd.this.client.maskbits << 16) \
		| ((policy_prio_t)(c)->spd.that.client.maskbits << 8) \
		|  (policy_prio_t)1; }

#define POLICY_PRIO_BUF (3 + 1 + 3 + 1)
extern void fmt_policy_prio(policy_prio_t pp, char buf[POLICY_PRIO_BUF]);

#ifdef XAUTH_HAVE_PAM
# include <security/pam_appl.h>	/* from pam devel; needed for pam_handle_t */
#endif

/* Note that we include this even if not X509, because we do not want the
 * structures to change lots.
 */
#include "x509.h"
#include "certs.h"
#include "defs.h"
#include <sys/queue.h>
#include "id.h"    /* for struct id */

struct virtual_t;

struct host_pair;	/* opaque type */

struct end {
	struct id id;
	bool left;

	enum keyword_host host_type;
	char *host_addr_name;	/* string version from whack */
	ip_address
		host_addr,
		host_nexthop,
		host_srcip;
	ip_subnet client;

	bool key_from_DNS_on_demand;
	bool has_client;
	bool has_client_wildcard;
	bool has_port_wildcard;
	bool has_id_wildcards;
	char *updown;
	u_int16_t host_port;		/* where the IKE port is */
	bool host_port_specific;	/* if TRUE, then IKE ports are tested for */
	u_int16_t port;			/* port number, if per-port keying */
	u_int8_t protocol;		/* transport-protocol number, if per-X keying */

	enum certpolicy sendcert;	/* whether or not to send the certificate */
	cert_t cert;			/* end certificate */
	chunk_t ca;			/* CA distinguished name of the end certificate's issuer */

	struct virtual_t *virt;

	bool xauth_server;
	bool xauth_client;
	char *username;
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
};
struct sa_marks {
	struct sa_mark in;
	struct sa_mark out;
};

struct connection {
	char *name;
	char *connalias;
	lset_t policy;
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
	unsigned long r_interval; /* initial retransmit time in msec, doubles each time */
	deltatime_t r_timeout; /* max time (in secs) for one packet exchange attempt */
	reqid_t sa_reqid;
	int encapsulation;

	/* RFC 3706 DPD */
	deltatime_t dpd_delay;		/* time between checks */
	deltatime_t dpd_timeout;	/* time after which we are dead */
	enum dpd_action dpd_action;	/* what to do when we die */

	bool nat_keepalive;		/* Suppress sending NAT-T Keep-Alives */
	bool initial_contact;		/* Send INITIAL_CONTACT (RFC-2407) payload? */
	bool cisco_unity;		/* Send Unity VID for cisco compatibility */
	bool fake_strongswan;		/* Send the unversioned strongswan VID */
	bool send_vendorid;		/* Send our vendorid? Security vs Debugging help */
	bool sha2_truncbug;
	enum ikev1_natt_policy ikev1_natt; /* whether or not to send IKEv1 draft/rfc NATT VIDs */

	/* Network Manager support */
#ifdef HAVE_NM
	bool nmconfigured;
#endif

#ifdef HAVE_LABELED_IPSEC
	bool labeled_ipsec;
	char *policy_label;
#endif

	/* Cisco interop: remote peer type */
	enum keyword_remotepeertype remotepeertype;

	enum keyword_xauthby xauthby;
	enum keyword_xauthfail xauthfail;

	bool forceencaps;			/* always use NAT-T encap */

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

	bool initiated;
	bool failed_ikev2;	/* tried ikev2, but failed */

	so_serial_t		/* state object serial number */
		newest_isakmp_sa,
		newest_ipsec_sa;

	lset_t extra_debugging;

	/* note: if the client is the gateway, the following must be equal */
	sa_family_t addr_family;	/* between gateways */
	sa_family_t tunnel_addr_family;	/* between clients */

	/* if multiple policies, next one to apply */
	struct connection *policy_next;

	struct gw_info *gw_info;
	struct alg_info_esp *alg_info_esp;	/* ??? OK for AH too? */
	struct alg_info_ike *alg_info_ike;

	/*
	 * The ALG_INFO converted to IKEv2 format.
	 *
	 * Since they are allocated on-demand so there's no need to
	 * worry about copying them when a connection object gets
	 * cloned.
	 */
	struct ikev2_proposals *ike_proposals;
	struct ikev2_proposals *esp_or_ah_proposals;

	/* host_pair linkage */
	struct host_pair *host_pair;
	struct connection *hp_next;

	struct connection *ac_next;	/* all connections list link */

	enum send_ca_policy send_ca;
#ifdef XAUTH_HAVE_PAM
	pam_handle_t *pamh;		/*  PAM handle for that connection  */
#endif
	char *dnshostname;

	ip_address modecfg_dns1;
	ip_address modecfg_dns2;
	struct ip_pool *pool; /* IPv4 addresspool as a range, start end */
	char *cisco_dns_info; /* scratchpad for writing IP addresses */
	char *modecfg_domain;
	char *modecfg_banner;

	u_int8_t metric;	/* metric for tunnel routes */
	u_int16_t connmtu;	/* mtu for tunnel routes */
	u_int32_t statsval;	/* track what we have told statsd */
	u_int16_t nflog_group;	/* NFLOG group - 0 means disabled  */
};

extern void parse_mark_mask(const struct connection* c,int * mark, int * mask);

#define oriented(c) ((c).interface != NULL)
extern bool orient(struct connection *c);

extern bool same_peer_ids(const struct connection *c,
			  const struct connection *d, const struct id *his_id);

/* Format the topology of a connection end, leaving out defaults.
 * Largest left end looks like: client === host : port [ host_id ] --- hop
 * Note: if that==NULL, skip nexthop
 */
#define END_BUF (SUBNETTOT_BUF + ADDRTOT_BUF + IDTOA_BUF + ADDRTOT_BUF + 10)
extern size_t format_end(char *buf, size_t buf_len,
			 const struct end *this, const struct end *that,
			 bool is_left, lset_t policy, bool filter_rnh);

struct whack_message;   /* forward declaration of tag whack_msg */
extern void add_connection(const struct whack_message *wm);
extern void initiate_connection(const char *name,
				int whackfd,
				lset_t moredebug,
				enum crypto_importance importance);
extern void restart_connections_by_peer(struct connection *c);

#ifdef HAVE_LABELED_IPSEC
struct xfrm_user_sec_ctx_ike; /* forward declaration */
#endif

extern void initiate_ondemand(const ip_address *our_client,
			     const ip_address *peer_client,
			     int transport_proto,
			     bool held,
			     int whackfd
#ifdef HAVE_LABELED_IPSEC
			     , struct xfrm_user_sec_ctx_ike *uctx
#endif
			     , err_t why);
extern void terminate_connection(const char *name);
extern void release_connection(struct connection *c, bool relations);
extern void delete_connection(struct connection *c, bool relations);
extern void delete_connections_by_name(const char *name, bool strict);
extern void delete_every_connection(void);
extern char *add_group_instance(struct connection *group,
				const ip_subnet *target);
extern void remove_group_instance(const struct connection *group,
				  const char *name);
extern void release_dead_interfaces(void);
extern void check_orientations(void);
extern struct connection *route_owner(struct connection *c,
				      const struct spd_route *cur_spd,
				      struct spd_route **srp,
				      struct connection **erop,
				      struct spd_route **esrp);
extern struct connection *shunt_owner(const ip_subnet *ours,
				      const ip_subnet *his);

extern bool uniqueIDs;  /* --uniqueids? */
extern void ISAKMP_SA_established(struct connection *c, so_serial_t serial);

#define his_id_was_instantiated(c) ((c)->kind == CK_INSTANCE \
				    && (id_is_ipaddr(&(c)->spd.that.id) ? \
					sameaddr(&(c)->spd.that.id.ip_addr, \
						 &(c)->spd.that.host_addr) : \
					TRUE))

struct state;   /* forward declaration of tag (defined in state.h) */
extern struct connection
*con_by_name(const char *nm, bool strict);

stf_status ikev2_find_host_connection(struct connection **cp,
		const ip_address *me, u_int16_t my_port, const ip_address *him,
		u_int16_t his_port, lset_t req_policy);

extern struct connection
	*find_host_connection(const ip_address *me, u_int16_t my_port,
		       const ip_address *him, u_int16_t his_port,
		       lset_t req_policy, lset_t policy_exact_mask),
	*find_next_host_connection(struct connection *c,
		       lset_t req_policy, lset_t policy_exact_mask),
	*refine_host_connection(const struct state *st, const struct id *peer_id,
			bool initiator, lset_t auth_policy, bool *fromcert),
	*find_client_connection(struct connection *c,
			const ip_subnet *our_net,
			const ip_subnet *peer_net,
			const u_int8_t our_protocol,
			const u_int16_t out_port,
			const u_int8_t peer_protocol,
			const u_int16_t peer_port),
	*find_connection_for_clients(struct spd_route **srp,
				      const ip_address *our_client,
				      const ip_address *peer_client,
				      int transport_proto);

/* instantiating routines */

struct gw_info;         /* forward declaration of tag (defined in dnskey.h) */
struct alg_info;        /* forward declaration of tag (defined in alg_info.h) */
extern struct connection *rw_instantiate(struct connection *c,
					 const ip_address *him,
					 const ip_subnet *his_net,
					 const struct id *his_id);

extern struct connection *instantiate(struct connection *c,
				      const ip_address *him,
				      const struct id *his_id);

extern struct connection *oppo_instantiate(struct connection *c,
					   const ip_address *him,
					   const struct id *his_id,
					   struct gw_info *gw,
					   const ip_address *our_client,
					   const ip_address *peer_client);

extern struct connection *build_outgoing_opportunistic_connection(
		struct gw_info *gw,
		const ip_address *our_client,
		const ip_address *peer_client);

/* worst case: "[" serial "] " myclient "=== ..." peer "===" hisclient '\0' */
#define CONN_INST_BUF \
	(2 + 10 + 1 + SUBNETTOT_BUF + 7 + ADDRTOT_BUF + 3 + SUBNETTOT_BUF + 1)

extern char *fmt_conn_instance(const struct connection *c,
			       char buf[CONN_INST_BUF]);

/* operations on "pending", the structure representing Quick Mode
 * negotiations delayed until a Keying Channel has been negotiated.
 */

struct pending; /* forward declaration (opaque outside connections.c) */

extern void add_pending(int whack_sock,
			struct state *isakmp_sa,
			struct connection *c,
			lset_t policy,
			unsigned long try,
			so_serial_t replacing
#ifdef HAVE_LABELED_IPSEC
			, struct xfrm_user_sec_ctx_ike *uctx
#endif
			);

extern void release_pending_whacks(struct state *st, err_t story);
extern void unpend(struct state *st);
extern void update_pending(struct state *os, struct state *ns);
extern void flush_pending_by_state(struct state *st);

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

extern void show_one_connection(const struct connection *c);
extern void show_connections_status(void);
extern int connection_compare(const struct connection *ca,
			      const struct connection *cb);

/* export to pending.c */
extern void host_pair_enqueue_pending(const struct connection *c,
				      struct pending *p,
				      struct pending **pnext);
struct pending **host_pair_first_pending(const struct connection *c);

void connection_check_ddns(void);

void connection_check_phase2(void);
void init_connections(void);

extern void setup_client_ports(struct spd_route *sr);

extern int foreach_connection_by_alias(const char *alias,
				       int (*f)(struct connection *c,
						void *arg),
				       void *arg);

extern struct connection *unoriented_connections;

extern void update_host_pairs(struct connection *c);

extern void unshare_connection_end(struct end *e);

extern void liveness_clear_connection(struct connection *c, char *v);
