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
#include "connections.h"	/* for policy_prio_t et.al. */
#include "ip_said.h"		/* for SA_AH et.al. */
#include "ip_packet.h"

struct sa_marks;
struct spd_route;
struct iface_dev;
struct raw_iface;
struct show;

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

enum kernel_policy_ops {
	/* three bits */
	KERNEL_POLICY_ADD = 1,
	KERNEL_POLICY_DELETE = 2,
	KERNEL_POLICY_REPLACE = 4,
};

enum kernel_policy_dir {
	/* two bits */
	KERNEL_POLICY_INBOUND = 8,
	KERNEL_POLICY_OUTBOUND = 16,
};

enum kernel_policy_op {
	KP_ADD_OUTBOUND =     (KERNEL_POLICY_ADD    |KERNEL_POLICY_OUTBOUND),
	KP_ADD_INBOUND =      (KERNEL_POLICY_ADD    |KERNEL_POLICY_INBOUND),
	KP_DELETE_OUTBOUND =  (KERNEL_POLICY_DELETE |KERNEL_POLICY_OUTBOUND),
	KP_DELETE_INBOUND =   (KERNEL_POLICY_DELETE |KERNEL_POLICY_INBOUND),
	KP_REPLACE_OUTBOUND = (KERNEL_POLICY_REPLACE|KERNEL_POLICY_OUTBOUND),
	KP_REPLACE_INBOUND =  (KERNEL_POLICY_REPLACE|KERNEL_POLICY_INBOUND),
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
	ENCAP_MODE_TRANSPORT = 1,
	ENCAP_MODE_TUNNEL,
};

#define encap_mode_name(E)						\
	({								\
		enum encap_mode e_ = E;					\
		(e_ == ENCAP_MODE_TUNNEL ? "tunnel" :			\
		 e_ == ENCAP_MODE_TRANSPORT ? "transport" :		\
		 e_ == 0 ? "any!?!" :					\
		 "unknown");						\
	})

/*
 * Direction of packet flow.
 */

enum encap_direction {
	ENCAP_DIRECTION_OUTBOUND,
	ENCAP_DIRECTION_INBOUND,
};

#define encap_direction_name(E)					\
	({							\
		enum encap_flow e_ = E;				\
		(e_ == ENCAP_DIRECTION_INBOUND ? "inbound" :	\
		 e_ == ENCAP_DIRECTION_OUTBOUND ? "outbound" :	\
		 "unknown");					\
	})

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

struct kernel_policy {
	struct {
		/*
		 * The SRC/DST selectors of the policy.  This is what
		 * captures the packets so they can be put through the
		 * wringer, er, rules listed below.
		 */
		ip_selector client;
		/*
		 * The route addresses of the encapsulated packets.
		 *
		 * With pfkey and transport mode with nat-traversal we
		 * need to change the remote IPsec SA to point to
		 * external ip of the peer.  Here we substitute real
		 * client ip with NATD ip.
		 *
		 * Bug #1004 fix.
		 *
		 * There really isn't "client" with XFRM and transport
		 * mode so eroute must be done to natted, visible
		 * ip. If we don't hide internal IP, communication
		 * doesn't work.
		 *
		 * XXX: old comment?
		 */
		ip_selector route;
		/*
		 * The src/dst addresses of the encapsulated packet
		 * that are to go across the public network.
		 *
		 * All rules should use these values?
		 *
		 * With setkey and transport mode, they can be unset;
		 * but libreswan doesn't do that.  Actually they can
		 * be IPv[46] UNSPEC and libreswan does that because
		 * XFRM insists on it.
		 */
		ip_address host;
	} src, dst;
	/*
	 * Index from 1; RULE[0] is always empty; so .nr_rules==0
	 * implies no rules.
	 *
	 * The rules are applied to an outgoing packet in order they
	 * appear in the rule[] table.  Hence, the output from
	 * .rule[.nr_rules] goes across the wire, and rule[1]
	 * specifies the first transform.
	 *
	 * The first transform is also set according to MODE (tunnel
	 * or transport); any other rules are always in transport
	 * mode.
	 */
	enum encap_mode mode;
	unsigned nr_rules;
	struct kernel_policy_rule rule[5]; /* [0]+AH+ESP+COMP+0 */
};

struct kernel_policy bare_kernel_policy(const ip_selector *src,
					const ip_selector *dst);

/*
 * Replaces SADB_X_SATYPE_* for non-KLIPS code. Assumes normal
 * SADB_SATYPE values
 *
 * XXX: Seems largely redundant.  Only place that eroute and
 * ip_protocol have different "values" is when netkey is inserting a
 * shunt - and that looks like a bug.
 */
enum eroute_type {
	ET_UNSPEC = 0,
	ET_AH    = 51,	/* SA_AH,      (51)  authentication */
	ET_ESP   = 50,	/* SA_ESP,     (50)  encryption/auth */
	ET_IPCOMP= 108,	/* SA_COMP,    (108) compression */
	ET_INT   = 61,	/* SA_INT,     (61)  internal type */
	ET_IPIP  = 4,	/* SA_IPIP,    (4)   turn on tunnel type */
};
#define esatype2proto(X) ((int)(X))
#define proto2esatype(X) ((enum eroute_type)(X))

/*
 * The CHILD (IPsec, kernel) SA has two IP ends.
 */

struct kernel_end {
	/*
	 * For ESP/AH which is carried by raw IP packets, only an
	 * address is needed to identify an end.  However when
	 * encapsulated (in UDP or TCP) the port is also needed.
	 *
	 * XXX: why is this a pointer and not simply the value?
	 */
	const ip_address *address;
	int encap_port;
	/*
	 * This is not the subnet you're looking for: the transport
	 * selector or packet filter.
	 */
	const ip_selector *client;
	/*
	 * XXX: for mobike? does this need a port or is the port
	 * optional or unchanging? perhaps the port is assumed to be
	 * embedded in the address (making it an endpoint)
	 */
	ip_address new_address;
};

struct kernel_sa {
	struct kernel_end src;
	struct kernel_end dst;

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

	bool inbound;
	int xfrm_dir;			/* xfrm has 3, in,out & fwd */
	bool esn;
	bool decap_dscp;
	bool nopmtudisc;
	uint32_t tfcpad;
	ipsec_spi_t spi;
	const struct ip_protocol *proto;
	unsigned int transport_proto;
	enum eroute_type esatype;
	unsigned replay_window;
	reqid_t reqid;

	const struct integ_desc *integ;
	unsigned authkeylen;
	unsigned char *authkey;

	const struct ipcomp_desc *ipcomp;
	const struct encrypt_desc *encrypt;
	unsigned enckeylen;
	unsigned char *enckey;

	const struct ip_encap *encap_type;		/* ESP in TCP or UDP; or NULL */
	ip_address *natt_oa;
	const char *story;
	chunk_t sec_label;

	const char *nic_offload_dev;
	uint32_t xfrm_if_id;
	struct sa_mark mark_set; /* config keyword mark-out */

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
	int replay_window;
	int *async_fdp;
	int *route_fdp;

	void (*init)(struct logger *logger);
	void (*shutdown)(struct logger *logger);
	void (*process_queue)(void);
	void (*process_msg)(int, struct logger *);
	bool (*raw_policy)(enum kernel_policy_op op,
			   enum expect_kernel_policy expect_kernel_policy,
			   const ip_selector *src_client,
			   const ip_selector *dst_client,
			   enum shunt_policy shunt_policy,
			   const struct kernel_policy *policy,
			   deltatime_t use_lifetime,
			   uint32_t sa_priority,
			   const struct sa_marks *sa_marks,
			   const struct pluto_xfrmi *xfrmi,
			   const shunk_t sec_label,
			   struct logger *logger);
	/*
	 * XXX: to delete an SA, delete it's SPI.
	 */
	bool (*add_sa)(const struct kernel_sa *sa,
		       bool replace,
		       struct logger *logger);
	bool (*grp_sa)(const struct kernel_sa *sa_outer,
		       const struct kernel_sa *sa_inner);
	bool (*get_sa)(const struct kernel_sa *sa,
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
				     bool tunnel_mode,
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

	bool (*exceptsocket)(int socketfd, int family, struct logger *logger);
	err_t (*migrate_sa_check)(struct logger *);
	bool (*migrate_ipsec_sa)(struct child_sa *child);
	void (*v6holes)(struct logger *logger);
	bool (*poke_ipsec_policy_hole)(int fd, const struct ip_info *afi, struct logger *logger);
	bool (*detect_offload)(const struct raw_iface *ifp, struct logger *logger);
};

extern int create_socket(const struct raw_iface *ifp, const char *v_name, int port, int proto);

extern const struct kernel_ops *kernel_ops;
#ifdef KERNEL_XFRM
extern const struct kernel_ops xfrm_kernel_ops;
#endif
#ifdef KERNEL_BSDKAME
extern const struct kernel_ops bsdkame_kernel_ops;
#endif
#ifdef KERNEL_PFKEYV2
extern const struct kernel_ops pfkeyv2_kernel_ops;
#endif

extern const struct kernel_ops *const kernel_stacks[];

/* helper for invoking call outs */
extern bool fmt_common_shell_out(char *buf, size_t blen,
				 const struct connection *c,
				 const struct spd_route *sr,
				 struct state *st);

/* many bits reach in to use this, but maybe shouldn't */
extern bool do_command(const struct connection *c, const struct spd_route *sr,
		       const char *verb, struct state *st, struct logger *logger);

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

/* A netlink header defines EM_MAXRELSPIS, the max number of SAs in a group.
 * Is there a PF_KEY equivalent?
 */
#ifndef EM_MAXRELSPIS
# define EM_MAXRELSPIS 4        /* AH ESP IPCOMP IPIP */
#endif

extern void init_kernel(struct logger *logger);

struct connection;      /* forward declaration of tag */
extern bool trap_connection(struct connection *c);
extern void unroute_connection(struct connection *c);
extern void migration_up(struct child_sa *child);
extern void migration_down(struct child_sa *child);

extern bool flush_bare_shunt(const ip_address *src, const ip_address *dst,
			     const struct ip_protocol *transport_proto,
			     enum expect_kernel_policy expect_kernel_policy,
			     const char *why, struct logger *logger);

bool assign_holdpass(const struct connection *c,
		     struct spd_route *sr,
		     enum shunt_policy negotiation_shunt,
		     const ip_packet *packet);

extern bool orphan_holdpass(const struct connection *c, struct spd_route *sr,
			    enum shunt_policy failure_shunt, struct logger *logger);

extern enum policy_spi shunt_policy_spi(enum shunt_policy);

struct state;   /* forward declaration of tag */
extern ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid,
				 const struct ip_protocol *proto,
				 const struct spd_route *sr,
				 bool tunnel_mode,
				 struct logger *logger);
extern ipsec_spi_t get_my_cpi(const struct spd_route *sr, bool tunnel_mode,
			      struct logger *logger);

extern bool install_inbound_ipsec_sa(struct state *st);
extern bool install_ipsec_sa(struct state *st, bool inbound_also);
void delete_ipsec_sa(struct state *st);
void delete_larval_ipsec_sa(struct state *st);

extern bool was_eroute_idle(struct state *st, deltatime_t idle_max);
extern bool get_sa_bundle_info(struct state *st, bool inbound, monotime_t *last_contact /* OUTPUT */);
extern bool migrate_ipsec_sa(struct child_sa *child);

extern void show_kernel_interface(struct show *s);
void shutdown_kernel(struct logger *logger);

/*
 * Note: "why" must be in stable storage (not auto, not heap)
 * because we use it indefinitely without copying or pfreeing.
 * Simple rule: use a string literal.
 */
extern void add_bare_shunt(const ip_selector *ours, const ip_selector *peers,
			   enum shunt_policy shunt_policy,
			   co_serial_t from_serialno,
			   const char *why, struct logger *logger);

bool install_sec_label_connection_policies(struct connection *c, struct logger *logger);

extern deltatime_t bare_shunt_interval;

extern bool kernel_ops_detect_offload(const struct raw_iface *ifp, struct logger *logger);

#endif
