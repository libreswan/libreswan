/* declarations of routines that interface with the kernel's IPsec mechanism
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2011 Michael Richardson <mcr@sandelman.ca>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2013 Kim Heino <b@bbbs.net>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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

#ifndef KERNEL_H
#define KERNEL_H

#include <net/if.h>

#include "monotime.h"
#include "reqid.h"
#include "connections.h"	/* for kernel_priority_t et.al. */
#include "ip_said.h"		/* for SA_AH et.al. */
#include "ip_packet.h"

struct sa_marks;
struct spd_route;
struct iface_dev;
struct raw_iface;
struct show;

enum kernel_state_id { DEFAULT_KERNEL_STATE_ID, };	/* sizeof() >= sizeof(uint32_t) */
enum kernel_policy_id { DEFAULT_KERNEL_POLICY_ID, };	/* sizeof() >= sizeof(uint32_t) */

/*
 * Declare policy things early enough for uses.
 * Some of these things, while they seem like they are KLIPS-only, the
 * definitions are in fact needed by all kernel interfaces at this time.
 *
 * Flags are encoded above the low-order byte of verbs.
 * "real" eroutes are only outbound.  Inbound eroutes don't exist,
 * but an addflow with an INBOUND flag allows IPIP tunnels to be
 * limited to appropriate source and destination addresses.
 */

enum kernel_policy_op {
	/* three bits */
	KERNEL_POLICY_OP_ADD = 1,
	KERNEL_POLICY_OP_DELETE = 2,
	KERNEL_POLICY_OP_REPLACE = 4,
};

extern const struct enum_names kernel_policy_op_names;

/*
 * The protocol used to encapsulate.
 *
 * Since ip-xfrm(8) lists esp, ah, comp, route2, hao and setkey(8)
 * lists ah, esp, ipcomp.
 *
 * XXX: The numbers end up being fed into the kernel so need to match
 * IETF equivalents.
 *
 * XXX: eroute_type includes ET_INT and ET_IPIP but in this context
 * the're not valid.  Hence the separate enum to enforce their
 * exclusion.  Suspect eroute_type can be chopped.
 */

enum encap_proto {
	ENCAP_PROTO_UNSPEC = 0,
	ENCAP_PROTO_ESP = 50,		/* (50)  encryption/auth */
	ENCAP_PROTO_AH = 51,		/* (51)  authentication */
	ENCAP_PROTO_IPCOMP= 108,	/* (108) compression */
};

/*
 * Encapsulation mode.
 *
 * Contrary to the RFCs and ENCAPSULATION_MODE_*, the kernel only has
 * to handle two modes.  Hence an ENUM that only defines those values.
 *
 * Except contrary to that, PF KEY v2 accepts the mode "any".
 */

enum encap_mode {
	ENCAP_MODE_TRANSPORT = 2, /*>true */
	ENCAP_MODE_TUNNEL,
};

extern const struct enum_names encap_mode_names;

enum direction {
	DIRECTION_INBOUND = 2, /*>true*/
	DIRECTION_OUTBOUND,
};

extern const struct enum_names direction_names;


/*
 * Kernel encapsulation policy.
 *
 * This determine how a packet matching a policy should be
 * encapsulated (processed).  For an outgoing packet, the rules are
 * applied in the specified order (and for incoming, in the reverse
 * order).
 *
 * setkey(8) uses the term "rule" when referring to the tuple
 * protocol/mode/src-dst/level while ip-xfrm(8) uses TMPL to describe
 * something far more complex.
 *
 * XXX: this may well need to eventually include things like the
 * addresses; spi; ...?
 */

struct kernel_policy_rule {
	enum encap_proto proto;
	reqid_t reqid;
};

struct kernel_policy_end {
	/*
	 * The SRC/DST selectors of the policy.  This is what captures
	 * the packets so they can be put through the wringer, er,
	 * rules listed below.
	 */
	ip_selector client;
	/*
	 * The route addresses of the encapsulated packets.
	 *
	 * With pfkey and transport mode with nat-traversal we need to
	 * change the remote IPsec SA to point to external ip of the
	 * peer.  Here we substitute real client ip with NATD ip.
	 *
	 * Bug #1004 fix.
	 *
	 * There really isn't "client" with XFRM and transport mode so
	 * eroute must be done to natted, visible ip. If we don't hide
	 * internal IP, communication doesn't work.
	 *
	 * XXX: old comment?
	 */
	ip_selector route;
	/*
	 * The src/dst addresses of the encapsulated packet that are
	 * to go across the public network.
	 *
	 * All rules should use these values?
	 *
	 * With setkey and transport mode, they can be unset; but
	 * libreswan doesn't do that.  Actually they can be IPv[46]
	 * UNSPEC and libreswan does that because XFRM insists on it.
	 */
	ip_address host;
};

typedef struct { uint32_t value; } kernel_priority_t;
#define PRI_KERNEL_PRIORITY PRIu32
#define pri_kernel_priority(P) (P).value

enum offload_type {
	OFFLOAD_NONE,
	OFFLOAD_CRYPTO,
	OFFLOAD_PACKET,
};

struct nic_offload {
	const char *dev;
	enum offload_type type;
};

struct kernel_policy {
	/*
	 * The src/dst selector and src/dst host (and apparently
	 * route).
	 */
	struct kernel_policy_end src;
	struct kernel_policy_end dst;
	kernel_priority_t priority;
	enum shunt_policy shunt;
	where_t where;
	shunk_t sec_label;
	const struct sa_marks *sa_marks;
	const struct pluto_xfrmi *xfrmi;
	enum kernel_policy_id id;
	/*
	 * The rules are applied to an outgoing packet in order they
	 * appear in the rule[] table.  Hence, the output from
	 * .rule[.nr_rules-1] goes across the wire, and rule[0]
	 * specifies the first transform.
	 *
	 * The first transform is also set according to MODE (tunnel
	 * or transport); any other rules are always in transport
	 * mode.
	 */
	enum encap_mode mode;
	unsigned nr_rules;
	struct kernel_policy_rule rule[3/*IPCOMP+{ESP,AH}+PADDING*/];
	struct nic_offload nic_offload;
};

/*
 * The CHILD (IPsec, kernel) SA has two IP ends.
 */

struct kernel_state_end {
	/*
	 * For ESP/AH which is carried by raw IP packets, only an
	 * address is needed to identify an end.  However when
	 * encapsulated (in UDP or TCP) the port is also needed.
	 *
	 * Why not an endpoint so that it encapsulates the port and,
	 * for that matter the protocol?
	 */
	ip_address address;
	int encap_port;
	/*
	 * This is not the subnet you're looking for: the transport
	 * selector or packet filter.
	 *
	 * XXX: old comment?
	 *
	 * The route addresses of the encapsulated packets.
	 *
	 * With pfkey and transport mode with nat-traversal we need to
	 * change the remote IPsec SA to point to external ip of the
	 * peer.  Here we substitute real client ip with NATD ip.
	 *
	 * Bug #1004 fix.
	 *
	 * There really isn't "client" with XFRM and transport mode so
	 * eroute must be done to natted, visible ip. If we don't hide
	 * internal IP, communication doesn't work.
	 */
	ip_selector route;
};

struct kernel_state {
	struct kernel_state_end src;
	struct kernel_state_end dst;

	/*
	 * Is the stack using tunnel mode; and if it is does this SA
	 * need the tunnel-mode bit?
	 *
	 * In tunnel mode, only the inner-most SA (level==0) should
	 * have the tunnel-mode bit set.  And in transport mode, all
	 * SAs get selectors.
	 */
	bool tunnel;
	unsigned level;		/* inner-most is 0 */

	enum direction direction;
	bool esn;
	bool decap_dscp;
	bool nopmtudisc;
	uint32_t tfcpad;
	ipsec_spi_t spi;
	const struct ip_protocol *proto;	/* ESP, AH, IPCOMP */
	const struct ip_encap *encap_type;	/* ESP-in-TCP, ESP-in-UDP; or NULL */
	unsigned replay_window;
	enum kernel_state_id state_id;		/* linux calls this seq */
	reqid_t reqid;

	const struct encrypt_desc *encrypt;
	shunk_t encrypt_key;
	const struct integ_desc *integ;
	shunk_t integ_key;
	const struct ipcomp_desc *ipcomp;

	ip_address *natt_oa;
	const char *story;
	chunk_t sec_label;

	struct nic_offload nic_offload;
	uint32_t xfrm_if_id;
	struct sa_mark mark_set; /* config keyword mark-out */
	uint64_t sa_ipsec_max_bytes;
	uint64_t sa_max_soft_bytes;
	uint64_t sa_ipsec_max_packets;
	uint64_t sa_max_soft_packets;
	deltatime_t sa_lifetime; /* number of seconds until SA expires */
};

/*
 * What to do when there's a policy op returns the ENOENT response?
 *
 * The old test, which looked like this:
 *
 *	bool enoent_ok = (op == KP_DELETE_INBOUND ||
 *			  (op == KP_DELETE_OUTBOUND && ntohl(cur_spi) == SPI_HOLD));
 *
 * but was too forgiving.  It hid bugs such as trying to delete the
 * wrong policy.
 */

enum expect_kernel_policy {
	/* Kernel policy can return either ENOENT or 0. */
	IGNORE_KERNEL_POLICY_MISSING,
#if 0
	REPORT_KERNEL_POLICY_PRESENT,
#endif
	EXPECT_NO_INBOUND,
	/* op can only return 0 */
	EXPECT_KERNEL_POLICY_OK,
};

#define expect_kernel_policy_name(E)					\
	({								\
		enum expect_kernel_policy e_ = E;			\
		const char *n_ = "?";					\
		switch (e_) {						\
		case IGNORE_KERNEL_POLICY_MISSING: n_ = "IGNORE_KERNEL_POLICY_MISSING"; break; \
		case EXPECT_NO_INBOUND: n_ = "EXPECT_NO_INBOUND"; break; \
		case EXPECT_KERNEL_POLICY_OK: n_ = "REPORT_NO_INBOUND"; break; \
		}							\
		n_;							\
	})

struct kernel_ops {
	/*
	 * The names used to identify the interface.
	 *
	 * It's assumed that protostack=PROTOSTACK_NAMES[0] is
	 * preferend.
	 */
	const char **protostack_names;
	/*
	 * This name is fed to updown using the environment variable
	 * PLUTO_STACK.  It needs to match the _updown.* name that was
	 * installed.
	 *
	 * Typically its the same as PROTOSTACK_NAMES[0].  But not
	 * necessarially.  On BSD it's currently "bsdkame", but could
	 * easily be renamed to "setkey" as it is the setkey command
	 * that is used to manage the interface.
	 */
	const char *updown_name;
	/*
	 * The user friendly name to used when logging errors.
	 */
	const char *interface_name;

	bool overlap_supported;
	bool sha2_truncbug_support;
	bool esn_supported;
	uintmax_t max_replay_window;
	int *async_fdp;
	int *route_fdp;

	void (*init)(struct logger *logger);
	void (*shutdown)(struct logger *logger);
	void (*process_queue)(void);
	void (*process_msg)(int, struct logger *);
	bool (*raw_policy)(enum kernel_policy_op op,
			   enum direction dir,
			   enum expect_kernel_policy expect_kernel_policy,
			   const ip_selector *src_client,
			   const ip_selector *dst_client,
			   const struct kernel_policy *policy,
			   deltatime_t use_lifetime,
			   const struct sa_marks *sa_marks,
			   const struct pluto_xfrmi *xfrmi,
			   enum kernel_policy_id id,
			   const shunk_t sec_label,
			   struct logger *logger);

	/*
	 * XXX: to delete an SA, delete it's SPI.
	 */
	bool (*add_sa)(const struct kernel_state *sa,
		       bool replace,
		       struct logger *logger);
	bool (*grp_sa)(const struct kernel_state *sa_outer,
		       const struct kernel_state *sa_inner);
	bool (*get_kernel_state)(const struct kernel_state *sa,
				 uint64_t *bytes,
				 uint64_t *add_time,
				 struct logger *logger);

	/*
	 * Allocate and delete IPsec ESP/AH (IPCOMP) SPIs. (creating a
	 * larval kernel state).
	 *
	 * Compression IDs are allocated using the same system call;
	 * except the MIN/MAX is smaller and IPCOMP is specified as
	 * the protocol.
	 *
	 * Typically the larval kernel state is matured by adding the
	 * negotiated crypto, key, et.al.
	 *
	 *
	 * When deleting the kernel state (larval, mature, ...) only
	 * the SPI and addresses are needed.
	 */
	ipsec_spi_t (*get_ipsec_spi)(ipsec_spi_t avoid,
				     const ip_address *src,
				     const ip_address *dst,
				     const struct ip_protocol *proto,
				     reqid_t reqid,
				     uintmax_t min, uintmax_t max,
				     const char *story,	/* often SAID string */
				     struct logger *logger);
	bool (*del_ipsec_spi)(ipsec_spi_t spi,
			      const struct ip_protocol *proto,
			      const ip_address *src,
			      const ip_address *dst,
			      const char *story,	/* often SAID string */
			      struct logger *logger);

	/*
	 * Returns NULL(ok) or what needs to be enabled.
	 */
	err_t (*migrate_ipsec_sa_is_enabled)(struct logger *);
	bool (*migrate_ipsec_sa)(struct child_sa *child);
	void (*v6holes)(struct logger *logger);
	bool (*poke_ipsec_policy_hole)(int fd, const struct ip_info *afi, struct logger *logger);
	bool (*detect_offload)(const struct raw_iface *ifp, struct logger *logger);
	bool (*poke_ipsec_offload_policy_hole)(struct nic_offload *nic_offload, struct logger *logger);
};

extern int create_socket(const struct raw_iface *ifp, const char *v_name, int port, int proto);

extern const struct kernel_ops *kernel_ops;
#ifdef KERNEL_XFRM
extern const struct kernel_ops xfrm_kernel_ops;
#endif
#ifdef KERNEL_PFKEYV2
extern const struct kernel_ops pfkeyv2_kernel_ops;
#endif

extern const struct kernel_ops *const kernel_stacks[];

/* many bits reach in to use this, but maybe shouldn't */
enum updown {
	UPDOWN_PREPARE,
	UPDOWN_ROUTE,
	UPDOWN_UNROUTE,
	UPDOWN_UP,
	UPDOWN_DOWN,
#ifdef HAVE_NM
	UPDOWN_DISCONNECT_NM,
#endif
};

extern bool do_updown(enum updown updown_verb,
		      const struct connection *c, const struct spd_route *sr,
		      struct state *st, struct logger *logger);

/* bare (connectionless) shunt (eroute) table
 *
 * Bare shunts are those that don't "belong" to a connection.
 * This happens because some %trapped traffic hasn't yet or cannot be
 * assigned to a connection.  The usual reason is that we cannot discover
 * the peer SG.  Another is that even when the peer has been discovered,
 * it may be that no connection matches all the particulars.
 * We record them so that, with scanning, we can discover
 * which %holds are news and which others should expire.
 */

//#define SHUNT_SCAN_INTERVAL     (2 * secs_per_minute)   /* time between scans of eroutes */
#define SHUNT_SCAN_INTERVAL     (2 * 10)   /* time between scans of eroutes */

/* SHUNT_PATIENCE only has resolution down to a multiple of the sample rate,
 * SHUNT_SCAN_INTERVAL.
 * By making SHUNT_PATIENCE an odd multiple of half of SHUNT_SCAN_INTERVAL,
 * we minimize the effects of jitter.
 */
#define SHUNT_PATIENCE  (SHUNT_SCAN_INTERVAL * 15 / 2)  /* inactivity timeout */

extern void show_shunt_status(struct show *);
extern unsigned shunt_count(void);

struct bare_shunt **bare_shunt_ptr(const ip_selector *ours,
				   const ip_selector *peers,
				   const char *why);
void free_bare_shunt(struct bare_shunt **pp);


/* A netlink header defines EM_MAXRELSPIS, the max number of SAs in a group.
 * Is there a PF_KEY equivalent?
 */
#ifndef EM_MAXRELSPIS
# define EM_MAXRELSPIS 4        /* AH ESP IPCOMP IPIP */
#endif

extern void init_kernel(struct logger *logger);

struct connection;      /* forward declaration of tag */
extern void unroute_connection(struct connection *c);
extern void migration_up(struct child_sa *child);
extern void migration_down(struct child_sa *child);

extern bool flush_bare_shunt(const ip_address *src, const ip_address *dst,
			     const struct ip_protocol *transport_proto,
			     enum expect_kernel_policy expect_kernel_policy,
			     const char *why, struct logger *logger);

bool assign_holdpass(struct connection *c,
		     const struct kernel_acquire *b,
		     struct spd_route *spd);

extern bool orphan_holdpass(struct connection *c, struct spd_route *sr,
			    struct logger *logger);

extern ipsec_spi_t get_ipsec_spi(const struct connection *c,
				 const struct ip_protocol *proto,
				 ipsec_spi_t avoid,
				 struct logger *logger/*state*/);
extern ipsec_spi_t get_ipsec_cpi(const struct connection *c,
				 struct logger *logger/*state*/);

bool install_prospective_kernel_policy(struct connection *c);
extern bool install_inbound_ipsec_sa(struct state *st);
extern bool install_ipsec_sa(struct state *st, bool inbound_also);
void uninstall_ipsec_sa(struct state *st);

extern bool was_eroute_idle(struct state *st, deltatime_t idle_max);
extern bool get_ipsec_traffic(struct state *st, struct ipsec_proto_info *sa, enum direction direction);
extern bool migrate_ipsec_sa(struct child_sa *child);

extern void show_kernel_interface(struct show *s);
void shutdown_kernel(struct logger *logger);

bool install_sec_label_connection_policies(struct connection *c, struct logger *logger);

extern deltatime_t bare_shunt_interval;

extern bool kernel_ops_detect_offload(const struct raw_iface *ifp, struct logger *logger);
extern void handle_sa_expire(ipsec_spi_t spi, uint8_t protoid, ip_address *dst,
		      bool hard, uint64_t bytes, uint64_t packets, uint64_t add_time);

extern kernel_priority_t highest_kernel_priority;
kernel_priority_t calculate_kernel_priority(const struct connection *c);

bool prospective_shunt_ok(enum shunt_policy shunt);
bool negotiation_shunt_ok(enum shunt_policy shunt);
bool failure_shunt_ok(enum shunt_policy shunt);

struct kernel_acquire {
	ip_packet packet;			/* that triggered the on-demand exchange */
	bool by_acquire;			/* by kernel acquire, else by whack */
	struct logger *logger;			/* on stack, could have whack attached */
	bool background;			/* close whackfd once started */
	shunk_t sec_label;			/* on stack */
	enum kernel_state_id state_id;		/* matches kernel state's .seq? */
	enum kernel_policy_id policy_id;	/* matches kernel policy's .index? */
};

void jam_kernel_acquire(struct jambuf *buf, const struct kernel_acquire *b);
void setup_esp_nic_offload(struct nic_offload *nic_offload, const struct connection *c,
			   bool *nic_offload_fallback);
#endif
