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
#include "refcnt.h"
#include "encap_mode.h"
#include "verbose.h"

#include "defs.h"
#include "proposals.h"
#include "hash_table.h"
#include "diag.h"
#include "ckaid.h"
#include "authby.h"
#include "ip_index.h"
#include "routing.h"
#include "connection_owner.h"

/*
 * Note that we include this even if not X509, because we do not want
 * the structures to change lots.
 */
#include "x509.h"
#include "certs.h"
#include "reqid.h"
#include "state.h"
#include "whack.h"

struct kernel_acquire;

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
	enum tcp_options iketcp;	/* Allow TCP as fallback,
					 * insist on TCP(YES) or stick
					 * to UDP(NO). */
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

	ip_ranges pool_ranges;	/* see also connection .pool */

	struct {
		bool server;
		bool client;
		char *username;
	} xauth;

	enum eap_options eap;		/* whether to require/do EAP auth (eg EAPTLS) */
	bool key_from_DNS_on_demand;
	bool groundhog;			/* Is groundhog time allowed?
					 * Groundhog effectively
					 * ignores the expiry on the
					 * root certificate. */
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

	bool has_client_address_translation;		/* aka CAT */

	ip_selectors selectors;
	ip_addresses sourceip;
	/*
	 * When set, put this on the ipsec-interface.  Should there be
	 * one for IPv4 and one for IPv6 like sourceip?
	 *
	 * Given interface-ip= and sourceip= are incompatible and the
	 * ipsec-interface code checks for a sourceip=, is this
	 * completely redundant?
	 */
	ip_cidr ipsec_interface_ip;

	/*
	 * Weird host related client stuff.
	 *
	 * It's only used when there's a Child SA.
	 */
	ip_cidr host_vtiip;
	struct virtual_ip *virt;
};

struct config_end {
	enum left_right index;
	const char *leftright;
	struct host_end_config host;
	struct child_end_config child;
};

struct ike_info {
	enum ike_version version;		/* 1|2 */
	const char *version_name;		/* IKEv1|IKEv2 */
	const char *parent_name;		/* IKE | ISAKMP */
	const char *child_name;			/* Child | IPsec */
	const char *parent_sa_name;		/* IKE SA | ISAKMP SA */
	const char *child_sa_name;		/* Child SA | IPsec SA */
	enum event_type expire_event[SA_EXPIRE_KIND_ROOF];
	enum event_type replace_event;
	enum event_type retransmit_event;
};

extern const struct ike_info ikev1_info;
extern const struct ike_info ikev2_info;

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

	enum shunt_policy shunt[SHUNT_KIND_ROOF];

	enum keyword_xauthby xauthby;
	enum keyword_xauthfail xauthfail;
	enum send_ca_policy send_ca;

	reqid_t sa_reqid;

	/* RFC 8784 and draft-ietf-ipsecme-ikev2-qr-alt-04 */
	char *ppk_ids;
	struct shunks *ppk_ids_shunks;

	struct {
		/* make these two an enum? */
		bool send_always;
		bool send_never;
		bool accept;
		char *to;        /* RFC 5685 */
		char *accept_to;
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
	struct ikev2_proposals *v2_ike_proposals;

	enum nic_offload_options nic_offload;
	char *dnshostname;

	struct {
		bool pull;		/* is modecfg pulled by client? */
		ip_addresses dns;	/* !.is_set terminated list */
		shunk_t *domains;	/* NULL terminated list */
		char *banner;
	} modecfg;

	/*
	 * IKEv1's RFC 3706 DPD; .delay also used by IKEv2 :-/ */
	struct {
		deltatime_t delay;		/* time between checks */
		deltatime_t timeout;	/* time after which we are dead */
	} dpd;

	bool rekey;				/* rekey state either Phase */
	bool reauth;				/* IKEv2 only initiate re-authentication */
	bool ikev2_allow_narrowing;
	bool send_no_esp_tfc;
	bool send_initial_contact;		/* Send INITIAL_CONTACT (RFC-2407) payload? */
	bool send_vendorid;			/* Send our vendorid? Security vs Debugging help */
	bool send_vid_fake_strongswan;		/* Send the unversioned strongswan VID */
	bool send_vid_cisco_unity;		/* Send Unity VID for cisco compatibility */

	ip_port remote_tcpport;		/* TCP remote port to use -
					 * local port will be
					 * ephemeral */

	bool mobike;			/* Allow MOBIKE */
	bool intermediate;		/* allow Intermediate Exchange */
	bool sha2_truncbug;		/* workaround old Linux kernel (android 4.x) */
	bool overlapip;			/* can two conns that have
					 * subnet=vhost: declare the
					 * same IP? */

	bool ms_dh_downgrade;		/* allow IKEv2 rekey to
					 * downgrade DH group -
					 * Microsoft bug */
	bool pfs_rekey_workaround;	/* include original proposal
					 * when rekeying */

	bool dns_match_id;		/* perform reverse DNS lookup
					 * on IP to confirm ID */
	bool ikev2_pam_authorize;	/* non-standard, custom PAM
					 * authorize call on ID */
	bool ignore_peer_dns;		/* install obtained DNS
					 * servers locally */
	bool ikepad;			/* pad ike packets to 4 bytes
					 * or not */
	bool require_id_on_certificate;	/* require certificates to
					 * have IKE ID on cert SAN */
	bool aggressive;		/* do we do aggressive
					 * mode? */
	bool decap_dscp;		/* decap ToS/DSCP bits */
	bool encap_dscp;		/* encap ToS/DSCP bits */
	bool nopmtudisc;		/* ??? */

	bool nat_keepalive;		/* Send NAT-T Keep-Alives if
					 * we are behind NAT */

	enum ikev1_natt_policy ikev1_natt;	/* whether or not to
						 * send IKEv1
						 * draft/rfc NATT
						 * VIDs */
	bool opportunistic;		/* is this opportunistic? */

#ifdef HAVE_NM
	bool nm_configured;		/* Network Manager support */
#endif

	bool remote_peer_cisco;		/* Cisco interop: remote peer
					 * type */

	enum yna_options encapsulation;	/* encapsulation mode of
					 * auto/yes/no */

	msgid_t ike_window;		/* IKE v2 window size
					 * 7296#section-2.3 */

	struct {
		char *interface;
		bool routing;		/* should updown perform
					 * routing into the vti
					 * device */
		bool shared;		/* should updown leave remote
					 * empty and not cleanup
					 * device on down */
	} vti;

	struct {
		uintmax_t priority;
		uintmax_t tfcpad;
		uintmax_t replay_window;	/* Usually 32, KLIPS
						   and XFRM/NETKEY
						   support 64.  See
						   also kernel_ops
						   .replay_window */
		uint32_t metric;	/* metric for tunnel routes */
		uint16_t mtu;		/* mtu for tunnel routes */
		bool ipcomp;

		bool iptfs;
		bool iptfs_dont_frag;
		uintmax_t iptfs_pkt_size;
		uintmax_t iptfs_max_qsize;
		uintmax_t iptfs_drop_time;
		uintmax_t iptfs_init_delay;
		uintmax_t iptfs_reord_win;


		enum encap_proto encap_proto;	/* ESP or AH */
		enum encap_mode encap_mode;	/* tunnel or transport */
		bool pfs;			/* use DH */
		/*
		 * The child proposals specified in the config file,
		 * and for IKEv2, that proposal converted to IKEv2
		 * form.
		 *
		 * IKEv2 child proposals negotiated IKE_AUTH - Child
		 * SA) can be computed ahead of time, and are stored
		 * below.  However, proposals negotiated during
		 * CREATE_CHILD_SA cannot.  For instance, the
		 * CREATE_CHILD_SA may be re-keying the IKE SA and
		 * it's DH is only determined during the initial
		 * negotiation.
		 */
		struct child_proposals proposals; /* raw proposals */
		struct ikev2_proposals *v2_ike_auth_proposals;
	} child_sa;

	struct {
		bool allow;
		bool v1_force;		/* IKEv1 only */
	} ike_frag;

	struct {
		bool yes;
		bool no;
	} esn;		/* accept or request ESN{yes,no} */

	struct {
		bool allow;
		bool insist;
	} ppk;

	struct {
		bool enabled;
		uint32_t id;
	} ipsec_interface;

	struct config_end end[END_ROOF];
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

/*
 * Connection priority: how important this connection is
 *
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
 * ??? These are NOT the same as sa_priorities but eventually they
 * should be aligned.
 */

typedef enum { BOTTOM_PRIORITY, } connection_priority_t;
connection_priority_t connection_priority(const struct connection *c);

typedef struct {
	char buf[3 + 1 + 3 + 1/*NUL*/ + 10 + 1/*sentinel*/];	/* (10 is to silence GCC) */
} connection_priority_buf;
size_t jam_connection_priority(struct jambuf *buf, const struct connection *);
const char *str_connection_priority(const struct connection *c, connection_priority_buf *buf);

struct host_end {
	const struct host_end_config *config;
	bool encap;			/* are packets encapsulated */
	uint16_t port;			/* where the IKE port is */
	ip_address nexthop;		/* identifies interface to send packets */
	struct id id;
	ip_address addr;
	ip_address first_addr;		/* The address to use when
					 * first initiating or
					 * reviving a connection; a
					 * connection establised after
					 * a redirect ends up with
					 * .addr pointing at the
					 * redirect. */
};

struct child_end {
	const struct child_end_config *config;
	struct child_end_selectors {
		/*
		 * Space to accumulate one IPv4 and one IPv6 selector
		 * when .proposed isn't pointing at the config
		 * selectors.  The number of valid entries is
		 * proposed.len.  Entries are appended; hence don't
		 * assume IPv4->IPv6 ordering.
		 *
		 * The see append_end_selector(), but be warned other
		 * code fiddles with this.
		 */
		ip_selector assigned[IP_INDEX_ROOF/*space for IPv4+IPv6 in no order*/];
		ip_selectors proposed; /* either .config->selectors or above; do not free */
		/*
		 * XXX: used when logging the established description
		 * of the child in jam_connection_child()?
		 */
		ip_selectors accepted; /* must pfree(.list) */
	} selectors;

	/*
	 * This is important; but it isn't clear why.
	 */
	bool has_client;
#define set_end_child_has_client(C, END, VALUE)				\
	{								\
		enum left_right end_ = END;				\
		where_t where_ = HERE;					\
		bool has_client_ = VALUE;				\
		struct connection *c_ = C;				\
		ldbg(c_->logger,					\
		     "%s.child.has_client: %s -> %s "PRI_WHERE,		\
		     c_->end[end_].config->leftright,			\
		     bool_str(c_->end[end_].child.has_client),		\
		     bool_str(has_client_),				\
		     pri_where(where_));				\
		c_->end[end_].child.has_client = has_client_;		\
	}
#define set_child_has_client(C, END, VALUE)				\
	set_end_child_has_client(C, C->END->config->index, VALUE)

	/*
	 * Track lease addresses.
	 *
	 * .has_lease indicates that the end has been given an address
	 * from the address pool.
	 */
#define nr_child_leases(END)					\
	({							\
		const struct connection_end *end_ = END;	\
		(end_->child.lease[IPv4_INDEX].is_set +		\
		 end_->child.lease[IPv6_INDEX].is_set);		\
	})

	ip_address lease[IP_INDEX_ROOF];
	bool has_cat;		/* add a CAT iptable rule when a valid
				   INTERNAL_IP4_ADDRESS is received */
};

err_t connection_requires_tss(const struct connection *c);

struct connection_end {
	enum connection_kind kind;
	const struct config_end *config;
	struct host_end host;
	struct child_end child;
};

void update_end_selector_where(struct connection *c, enum left_right end,
			       ip_selector s,
			       const char *excuse, where_t where);

#define update_end_selector(C, END, SELECTOR, EXCUSE)			\
	update_end_selector_where(C, END, SELECTOR, EXCUSE, HERE)
#define update_first_selector(C, LR, SELECTOR)				\
	update_end_selector_where(C, (C)->LR->config->index, SELECTOR,	\
				  NULL, HERE)

void append_end_selector(struct connection_end *end,
			 const struct ip_info *afi, ip_selector s,
			 struct logger *logger, where_t where);

#define set_end_selector(END, SELECTOR, LOGGER)				\
	{								\
		PASSERT(LOGGER, (END)->child.selectors.proposed.list == NULL); \
		PASSERT(LOGGER, (END)->child.selectors.proposed.len == 0); \
		append_end_selector(END, selector_info(SELECTOR),	\
				    SELECTOR, LOGGER, HERE);		\
	}

struct spd_end {
	ip_selector client;

	/*
	 * An extract of the original configuration information for
	 * the connection's end sent over by whack.
	 *
	 * Danger: for a connection instance, this point into the
	 * parent connection.
	 */
	const struct config_end *config;
	struct host_end *host;
	struct child_end *child;

	struct virtual_ip *virt;
};

struct spd_owner {
	/*
	 * .bare_route
	 *
	 * Return the owner of the SPD's route (but ignoring the
	 * current SPD).  When this is NULL it is assumed that SPD's
	 * route should be unrouted.
	 *
	 * When rekeying, since the current SPD is excluded, this is
	 * NULL.  Hence this can not be used to determine if the
	 * current SPD is already installed.
	 *
	 * The check excludes SPDs of the connection's parent: this
	 * seems very weak as the parent may still be routed.
	 */
	const struct spd *bare_route;
	/*
	 * .bare_cat
	 *
	 * Any SPD matching LOCAL.HOST (aka client) <-> REMOTE.CLIENT
	 * (ignoring current connection and SPD).  When deleting a CAT
	 * this SPD will be restored.
	 */
	const struct spd *bare_cat;
	/*
	 * .bare_policy
	 *
	 * Assuming SPD doesn't exist (i.e., being deleted), look for
	 * the highest priority policy that matches the selectors.
	 *
	 * Since SPD doesn't exist checks for matching .overlapip
	 * and/or priority aren't needed.
	 */
	const struct spd *bare_policy;
	/*
	 * .policy
	 *
	 * Given an SPD and its new_routing (shunt_kind) return any
	 * SPD that still trumps that SPD.
	 *
	 * An SPD is trumped when there's other SPD with equal or
	 * higher new_routing (shunt_kind).  As a special exception,
	 * an instance isn't trumped when its template is identical.
	 */
	const struct spd *policy;
};

struct spd {
	struct spd_end end[END_ROOF];
	/* point into above */
	struct spd_end *local;		/* must update after clone */
	struct spd_end *remote;		/* must update after clone */
	struct connection *connection;	/* must update after clone */
	bool block;

	struct spd_wip {
		bool ok;
		struct {
			struct bare_shunt **shunt;
		} conflicting;
		struct {
			bool kernel_policy;
			bool route;		/* vs unroute */
			bool up;		/* vs down */
		} installed;
	} wip;
	struct {
		struct list_entry list;
		struct list_entry remote_client;
	} spd_db_entries;
};

struct spds {
	unsigned len;
	struct spd *list;
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

#define PRI_SA_MARK "%"PRIu32"/%#08"PRIx32"%s"
#define pri_sa_mark(M)  (M).val, (M).mask, ((M).unique ? "/unique" : "")

#define sa_mark_eq(L,R) (((L).val & (L).mask) == ((R).val & (R).mask))

struct connection {
	struct refcnt refcnt;
	co_serial_t serialno;
	struct connection *clonedfrom;
	char *name;			/* switch with .prefix? */
	char *prefix;			/* "name"[0][1]; longer than .name!!! */
	struct logger *logger;

	struct {
		bool up;		/* do we want to keep this
					 * connection up? */
		bool route;		/* do we want to keep this
					 * connection routed? */
		bool keep;		/* try a single revival when
					 * responder */
	} policy;
#define set_policy(C, POLICY, VALUE)				\
	({							\
		bool old_ = (C)->POLICY;			\
		bool new_ = VALUE;				\
		pdbg((C)->logger, "%s:%s->%s "PRI_WHERE,	\
		     #POLICY,					\
		     bool_str(old_),				\
		     bool_str(new_),				\
		     pri_where(HERE));				\
		(C)->POLICY = new_;				\
		old_;						\
	})
#define add_policy(C, POLICY)					\
	set_policy(C, POLICY, true)
#define del_policy(C, POLICY)					\
	set_policy(C, POLICY, false)

	struct sa_marks sa_marks;	/* contains a MARK values and
					 * MASK value for IPsec SA
					 * (per-connection) */

	/*
	 * Pointer to possibly shared interface (per-connection).  And
	 * a pointer to CIDR this connection added to the interface.
	 */
	struct ipsec_interface *ipsec_interface;
	struct ipsec_interface_address *ipsec_interface_address;

	char *log_file_name;			/* name of log file */
	FILE *log_file;				/* possibly open FILE */
	bool log_file_err;			/* only bitch once */

	struct child {
		/*
		 * This is identical across kernel-states and shared
		 * by all SPDs.
		 */
		reqid_t reqid;
		chunk_t sec_label;		/* negotiated sec label */
		struct spds spds;
	} child;

	struct spd *spd;			/* HACK: points to child.spds.list */

	/* internal fields: */

	unsigned long next_instance_serial;
	unsigned long instance_serial;

	struct iface_device *iface;			/* filled in iff oriented */

	struct {
		/* RFC 5685 - IKEv2 Redirect Mechanism */
		unsigned attempt;
		ip_address ip;			/* where to redirect */
		ip_address old_gw_address;	/* address of old gateway */
	} redirect;

	struct {
		unsigned attempt;
		deltatime_t delay;		 /* for next time */
		ip_endpoint remote;
		struct iface_endpoint *local;
	} revival;

	/*
	 * Private variables for tracking routing.  Only updated by
	 * routing.c.
	 *
	 * As a simple example:
	 *
	 * <<ipsec route>>
	 *
	 * - the unowned connection installs kernel trap policy and
	 * transitions to on-demand
	 *
	 * acquire
	 *
	 * - an IKE SA is created, the trap policy is changed to block
	 * and .routing_sa is set to the IKE SA; IKE_SA_INIT is
	 * initiated
	 *
	 * IKE_SA_INIT response
	 *
	 * - since the IKE SA owns the connection, a failed response
	 * deleting the IKE SA will trigger revival
	 *
	 * - the Child SA is created and .routing_sa is set to that;
	 * IKE_AUTH is initiated
	 *
	 * IKE_AUTH response
	 *
	 * - since the Child SA owns the connection, a failed response
	 * (either IKE or Child) triggers revival
	 *
	 * - the Child SA installs the IPsec state/policy
	 *
	 * Child SA deleted (or IKE deleting all children)
	 *
	 * - since the Child SA owns the connection, it being deleted
	 * triggers revival
	 */
	struct {
		enum routing state; /* level of routing in place */
		so_serial_t owner[CONNECTION_OWNER_ROOF];
#define routing_sa routing.owner[ROUTING_SA] /* IKE or Child SA! */
#define negotiating_ike_sa routing.owner[NEGOTIATING_IKE_SA]
#define established_ike_sa routing.owner[ESTABLISHED_IKE_SA]
#define negotiating_child_sa routing.owner[NEGOTIATING_CHILD_SA]
#define established_child_sa routing.owner[ESTABLISHED_CHILD_SA]
	} routing;

	struct addresspool *pool[IP_INDEX_ROOF];

	uint16_t nflog_group;	/* NFLOG group - 0 means disabled */

	struct {
		struct list_entry list;
		struct list_entry serialno;
		struct list_entry that_id;
		struct list_entry clonedfrom;
		struct list_entry host_pair;
	} connection_db_entries;

	struct pending *pending;

	struct connection_event *events[CONNECTION_EVENT_KIND_ROOF];

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
			  const struct connection *d);

diag_t add_connection(const struct whack_message *wm, struct logger *logger);

void update_hosts_from_end_host_addr(struct connection *c, enum left_right end,
				     ip_address host_addr, where_t where);

void delete_connection_where(struct connection **cp, where_t where);
#define delete_connection(CP) delete_connection_where(CP, HERE)

struct connection *connection_addref_where(struct connection *c, const struct logger *owner, where_t where);
void connection_delref_where(struct connection **cp, const struct logger *owner, where_t where);
#define connection_addref(C, OWNER) connection_addref_where(C, OWNER, HERE)
#define connection_delref(CP, OWNER) connection_delref_where(CP, OWNER, HERE)

#define remote_id_was_instantiated(c) \
	( is_instance(c) && \
	  ( !id_is_ipaddr(&(c)->remote->host.id) || \
	    sameaddr(&(c)->remote->host.id.ip_addr, &(c)->remote->host.addr) ) )

struct state;   /* forward declaration of tag (defined in state.h) */

bool connection_with_name_exists(const char *name);
struct connection *find_connection_for_packet(const ip_packet packet,
					      shunk_t sec_label,
					      const struct logger *logger);

/* "name"[1]... OE-MAGIC */
size_t jam_connection(struct jambuf *buf, const struct connection *c);

/* "name"[1]... */
size_t jam_connection_short(struct jambuf *buf, const struct connection *c);
const char *str_connection_short(const struct connection *c);

size_t jam_connection_policies(struct jambuf *buf, const struct connection *c);
const char *str_connection_policies(const struct connection *c, policy_buf *buf);

/*
 * XXX: Instead of str_connection(), which would require a buffer big
 * enough to fit an any length name, there's PRI_CONNECTION et.al.
*/

typedef struct {
	char buf[/*why?*/ 1 +
		 /*<myclient*/sizeof(subnet_buf) +
		 /*"=== ..."*/ 7 +
		 /*<peer>*/sizeof(address_buf) +
		 /*"==="*/ 3 +
		 /*<peer_client>*/sizeof(subnet_buf) +
		 /*"\0"*/ 1 +
		 /*<cookie>*/ 1];
} connection_buf;

const char *str_connection_suffix(const struct connection *c,
				    connection_buf *buf);

#define PRI_CONNECTION "%s%s"
#define pri_connection(C,B) str_connection_short(C), str_connection_suffix(C, B)

struct connection **sort_connections(void);
int connection_compare(const struct connection *ca,
		       const struct connection *cb);

so_serial_t get_newer_sa_from_connection(struct state *st);

diag_t add_end_cert_and_preload_private_key(CERTCertificate *cert,
					    struct host_end *host_end,
					    struct host_end_config *host_end_config,
					    bool preserve_ca,
					    struct logger *logger);

ip_port end_host_port(const struct host_end *this, const struct host_end *that);
ip_port local_host_port(const struct connection *c);

/*
 * For iterating over the connection DB.
 *
 * - parameters are only matched when non-NULL or non-zero
 * - .connection can be deleted between calls
 * - some filters have been optimized using hashing, but
 * - worst case is it scans through all connections
 */

struct connection_filter {
	/*
	 * Filters.
	 */
	const enum connection_kind kind;
	const char *const name;
	const char *const alias_root;
	const struct id *const this_id_eq; /* strict; not same_id() */
	const struct id *const that_id_eq; /* strict; not same_id() */
	struct connection *const clonedfrom;
	const enum ike_version ike_version;
	/*
	 * host-pair: matches is_template(), is_instance() and
	 * is_permanent() (i.e., excludes is_group()) and:
	 *
	 * local=&unset: match unoriented(); else remote=&unset: match
	 * oriented() + local + 0.0.0.0 or ::; else match oriented() +
	 * local + remote.
	 */
	const struct {
		const ip_address *const local;
		const ip_address *const remote;
	} host_pair;

	/*
	 * Current result (can be safely deleted).
	 */
	struct connection *c;

	/*
	 * internal
	 */
	struct list_entry *internal; /* handle on next entry; used by next_connection() */
	struct connection **connections; /* refcounted connections; used by all_connections() */
	/* internal: total matches so far */
	unsigned count;

	/*
	 * Required fields.
	 */
	struct /*search*/ {
		const enum chrono order;
		struct verbose verbose; /* writable */
		/* .where MUST BE LAST (See GCC bug 102288) */
		const where_t where;
	} search;
};

/*
 * Can bail early; beware of delete.  Should this be NEW2OLD only?
 */
bool next_connection(struct connection_filter *query);

/*
 * Must iterate over all matches (can't break from loop).
 *
 * All matching connections get an addref() (i.e., making refcnt()>1)
 * and then before each connection is returned, the reference is
 * dropped (i.e., refcnt()>=1).  This means that the current
 * connection has no extra references, and if the reference is the
 * last can be deleted using delete_connection() (pexpect
 * refcnt()==1).
 *
 * However, this also means that, due to the addref(), code can't use
 * delete_connection() to delete anything still in the queue.  Instead
 * the connection should be delref()ed.  If that leaves
 * all_connections() with the last reference the the connection is not
 * returned (it is delref()ed deleting it).
 */

bool all_connections(struct connection_filter *query);

/*
 * For iterating over the spd DB.
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

struct spd_filter {
	const ip_selector *remote_client_range;
	/* current result (can be safely deleted) */
	struct spd *spd;
	/* internal: handle on next entry */
	struct list_entry *internal;
	/* internal: total matches so far */
	unsigned count;
	/* .where MUST BE LAST (See GCC bug 102288) */
	where_t where;
};

bool next_spd(enum chrono order, struct spd_filter *srf);

void replace_connection_that_id(struct connection *c, const struct id *new_id);
void connection_db_rehash_that_id(struct connection *c);
void connection_db_rehash_host_pair(struct connection *c);

void spd_db_rehash_remote_client(struct spd *sr);

bool dpd_active_locally(const struct connection *c);

ip_address spd_end_sourceip(const struct spd_end *spde);

PRINTF_LIKE(3)
void ldbg_connection(const struct connection *c, where_t where,
		     const char *message, ...);

void init_connection_spd(struct connection *c, struct spd *spd);
void alloc_connection_spds(struct connection *c, unsigned nr);
void discard_connection_spds(struct connection *c);
void add_connection_spds(struct connection *c, const struct ip_info *host_afi);

/*
 * Format the topology of a connection end, leaving out defaults.
 * Largest left end looks like: client === host : port [ host_id ] ---
 * hop Note: if that==NULL, skip nexthop
 */
void jam_spd_end(struct jambuf *buf, const struct connection *c,
		 const struct spd_end *this, const struct spd_end *that,
		 enum left_right left_right, bool filter_rnh);

/* connections */

struct connection *alloc_connection(const char *name,
				    struct connection *t,
				    const struct config *config,
				    lset_t debugging,
				    struct logger *logger,
				    where_t where);

/*
 * Three types of labels.
 */

bool is_labeled_where(const struct connection *c, where_t where);
bool is_labeled_template_where(const struct connection *c, where_t where);
bool is_labeled_parent_where(const struct connection *c, where_t where);
bool is_labeled_child_where(const struct connection *c, where_t where);

#define is_labeled(C) is_labeled_where(C, HERE)
#define is_labeled_template(C) is_labeled_template_where(C, HERE)
#define is_labeled_parent(C) is_labeled_parent_where(C, HERE)
#define is_labeled_child(C) is_labeled_child_where(C, HERE)

bool is_permanent(const struct connection *c);

/* also return true when labeled parent or child */
bool is_instance(const struct connection *c);
/* also returns true when labeled template */
bool is_template(const struct connection *c);

/*
 * Labeled parent connections can have IKE/ISAKMP SA.  Labeled child
 * connections can have a Child SA.
 *
 * permanent and template-instance connections allow both, but labeled
 * connections are XOR.
 */
bool can_have_sa(const struct connection *c, enum sa_type sa_type);

bool never_negotiate(const struct connection *c);

bool is_group(const struct connection *c);
bool is_group_instance(const struct connection *c); /* derived from group; template or instance */

bool is_opportunistic(const struct connection *c);
bool is_opportunistic_group(const struct connection *c);
bool is_opportunistic_template(const struct connection *c);
bool is_opportunistic_instance(const struct connection *c);

bool is_xauth(const struct connection *c);

bool is_v1_cisco_split(const struct spd *spd, where_t where);

/* IKE SA | ISAKMP SA || Child SA | IPsec SA */
const char *connection_sa_name(const struct connection *c, enum sa_type sa_type);
/* IKE | ISAKMP || Child | IPsec */
const char *connection_sa_short_name(const struct connection *c, enum sa_type sa_type);

struct child_policy child_sa_policy(const struct connection *c);

bool connections_can_share_parent(const struct connection *c,
				  const struct connection *d);

#endif
