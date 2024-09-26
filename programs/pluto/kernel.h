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
#include "connections.h"	/* for struct sa_marks et.al. */
#include "ip_said.h"		/* for SA_AH et.al. */
#include "ip_packet.h"
#include "kernel_mode.h"

struct sa_marks;
struct spd;
struct iface_device;
struct kernel_iface;
struct show;
struct kernel_policy;

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
	KERNEL_POLICY_OP_REPLACE = 2,
};

extern const struct enum_names kernel_policy_op_names;

enum direction {
	DIRECTION_INBOUND = 2, /*>true*/
	DIRECTION_OUTBOUND = 4, /* so lset_t works */
};

extern const struct enum_names direction_names;

enum kernel_offload_type {
	KERNEL_OFFLOAD_NONE,
	KERNEL_OFFLOAD_CRYPTO,
	KERNEL_OFFLOAD_PACKET,
};

struct nic_offload {
	const char *dev;
	enum kernel_offload_type type;
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
	enum kernel_mode mode;
	unsigned level;		/* inner-most is 0 */

	enum direction direction;
	bool esn;
	bool decap_dscp;
	bool encap_dscp;
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
	 * preferred.
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

	void (*init)(struct logger *logger);
	void (*flush)(struct logger *logger);
	void (*poke_holes)(struct logger *logger);
	void (*plug_holes)(struct logger *logger);
	void (*shutdown)(struct logger *logger);

	bool (*policy_add)(enum kernel_policy_op op,
			   enum direction dir,
			   const ip_selector *src_client,
			   const ip_selector *dst_client,
			   const struct kernel_policy *policy,
			   deltatime_t use_lifetime,
			   struct logger *logger,
			   const char *func);
	bool (*policy_del)(enum direction dir,
			   enum expect_kernel_policy expect_kernel_policy,
			   const ip_selector *src_client,
			   const ip_selector *dst_client,
			   const struct sa_marks *sa_marks,
			   const struct ipsec_interface *xfrmi,
			   enum kernel_policy_id id,
			   const shunk_t sec_label, /*needed*/
			   struct logger *logger,
			   const char *func);

	/*
	 * XXX: to delete an SA, delete it's SPI.
	 */
	bool (*add_sa)(const struct kernel_state *sa,
		       bool replace,
		       struct logger *logger);
	bool (*get_kernel_state)(const struct kernel_state *sa,
				 uint64_t *bytes,
				 uint64_t *add_time,
				 uint64_t *lastused,
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
	bool (*poke_ipsec_policy_hole)(int fd, const struct ip_info *afi, struct logger *logger);
	bool (*detect_nic_offload)(const char *name, struct logger *logger);
	bool (*poke_ipsec_offload_policy_hole)(struct nic_offload *nic_offload, struct logger *logger);

	/* extensions */
	const struct kernel_ipsec_interface *ipsec_interface;
};

extern int create_socket(const struct kernel_iface *ifp, const char *v_name, int port, int proto);

extern const struct kernel_ops *kernel_ops;
#ifdef KERNEL_XFRM
extern const struct kernel_ops xfrm_kernel_ops;
#endif
#ifdef KERNEL_PFKEYV2
extern const struct kernel_ops pfkeyv2_kernel_ops;
#endif

extern const struct kernel_ops *const kernel_stacks[];

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

extern bool flush_bare_shunt(const ip_address *src, const ip_address *dst,
			     const struct ip_protocol *transport_proto,
			     enum expect_kernel_policy expect_kernel_policy,
			     const char *why, struct logger *logger);

void orphan_holdpass(struct connection *c,
		     struct spd *sr,
		     struct logger *logger);

extern ipsec_spi_t get_ipsec_spi(const struct connection *c,
				 const struct ip_protocol *proto,
				 ipsec_spi_t avoid,
				 struct logger *logger/*state*/);
extern ipsec_spi_t get_ipsec_cpi(const struct connection *c,
				 struct logger *logger/*state*/);

bool unrouted_to_routed(struct connection *c, enum routing new_routing, where_t where);

bool install_inbound_ipsec_sa(struct child_sa *child, enum routing new_routing, where_t where);
struct do_updown {
	bool up;
	bool route;
};
bool install_outbound_ipsec_sa(struct child_sa *child, enum routing new_routing,
			       struct do_updown updown, where_t where);

void teardown_ipsec_kernel_states(struct child_sa *child);
void uninstall_kernel_states(struct child_sa *child);

extern bool was_eroute_idle(struct child_sa *child, deltatime_t idle_max);
extern bool get_ipsec_traffic(struct child_sa *child, struct ipsec_proto_info *sa, enum direction direction);
bool kernel_ops_migrate_ipsec_sa(struct child_sa *child);

extern void show_kernel_interface(struct show *s);
void shutdown_kernel(struct logger *logger);

extern deltatime_t bare_shunt_interval;

extern bool kernel_ops_detect_nic_offload(const char *name, struct logger *logger);
extern void handle_sa_expire(ipsec_spi_t spi, uint8_t protoid, ip_address dst,
			     bool hard, uint64_t bytes, uint64_t packets, uint64_t add_time,
			     struct logger *logger);

typedef struct { uint32_t value; } spd_priority_t;
#define PRI_SPD_PRIORITY PRIu32
#define pri_spd_priority(P) (P).value

extern const spd_priority_t highest_spd_priority;
spd_priority_t spd_priority(const struct spd *spd);

struct kernel_acquire {
	ip_packet packet;			/* that triggered the on-demand exchange */
	bool by_acquire;			/* by kernel acquire, else by whack */
	const struct logger *logger;		/* on stack, could have whack attached */
	bool background;			/* close whackfd once started */
	shunk_t sec_label;			/* on stack */
	enum kernel_state_id state_id;		/* matches kernel state's .seq? */
	enum kernel_policy_id policy_id;	/* matches kernel policy's .index? */
};

void jam_kernel_acquire(struct jambuf *buf, const struct kernel_acquire *b);
void setup_esp_nic_offload(struct nic_offload *nic_offload,
			   const struct connection *c,
			   struct logger *logger);

struct spd_owner spd_owner(const struct spd *spd, enum routing new_routing,
			   struct logger *logger, where_t where);

#endif
