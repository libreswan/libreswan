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

#ifndef _KERNEL_H_

#include <net/if.h>

#include "monotime.h"
#include "reqid.h"
#include "connections.h"	/* for policy_prio_t et.al. */
#include "ip_said.h"		/* for SA_AH et.al. */

struct sa_marks;
struct spd_route;
struct iface_dev;
struct show;

extern bool can_do_IPcomp;  /* can system actually perform IPCOMP? */

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

enum kernel_policy_bits {
	/* two bits */
	KERNEL_POLICY_OP_ADD = 1,
	KERNEL_POLICY_OP_DELETE = 2,
	KERNEL_POLICY_OP_REPLACE = 3,
	KERNEL_POLICY_OP_MASK = 3,
	/* one bit */
	KERNEL_POLICY_DIR_IN = 0,
	KERNEL_POLICY_DIR_OUT = 4,
	KERNEL_POLICY_DIR_MASK = 4,
};

enum kernel_policy_op {
	KP_ADD_OUTBOUND =     (KERNEL_POLICY_OP_ADD    |KERNEL_POLICY_DIR_OUT),
	KP_ADD_INBOUND =      (KERNEL_POLICY_OP_ADD    |KERNEL_POLICY_DIR_IN),
	KP_DELETE_OUTBOUND =  (KERNEL_POLICY_OP_DELETE |KERNEL_POLICY_DIR_OUT),
	KP_DELETE_INBOUND =   (KERNEL_POLICY_OP_DELETE |KERNEL_POLICY_DIR_IN),
	KP_REPLACE_OUTBOUND = (KERNEL_POLICY_OP_REPLACE|KERNEL_POLICY_DIR_OUT),
	KP_REPLACE_INBOUND =  (KERNEL_POLICY_OP_REPLACE|KERNEL_POLICY_DIR_IN),
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
 */

enum encap_mode {
	ENCAP_MODE_TRANSPORT,
	ENCAP_MODE_TUNNEL,
};

#define encap_mode_name(E)						\
	({								\
		enum encap_mode e_ = E;					\
		(e_ == ENCAP_MODE_TUNNEL ? "tunnel" :			\
		 e_ == ENCAP_MODE_TRANSPORT ? "transport" :		\
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
 * Encapsulation.
 *
 * This determine how a packet matching a policy should be
 * encapsulated (processed).  The rules are ordered inner-most to
 * outer-most (there's an implied -1 rule matching the actual packet).
 *
 * setkey(8) uses the term "rule" when refering to the tupple
 * protocol/mode/src-dst/level while ip-xfrm(8) uses TMPL to describe
 * something far more complex.
 *
 * XXX: this may well need to eventually include things like the
 * addresses; spi; ...?
 */

struct encap_rule {
	enum encap_proto proto;
	reqid_t reqid;
};

struct kernel_encap {
	const struct ip_protocol *inner_proto;	/*IPIP or ESP|AH */
	enum encap_mode mode;
	int outer; /* -1 when no rules; XXX: good idea? */
	struct encap_rule rule[4]; /* AH+ESP+COMP+0 */
};

extern const struct kernel_encap esp_transport_kernel_encap;
#define esp_transport_proto_info &esp_transport_kernel_encap /* XXX: TBD */

/*
 * How a packet flows through the kernel.
 *
 * In transport mode the kernel code expects both the CLIENT and
 * HOST_ADDR to be for public interfaces, however for L2TP they are
 * not (the client found in the spd might be for an address behind the
 * nat).
 *
 * XXX: host_addr should be an endpoint?  By this point everything has
 * been resolved?
 */

struct kernel_route {
	struct route_end {
		ip_selector client;
		ip_address host_addr;
	} src, dst;
};

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

	enum ipsec_ipcomp_algo ipcomp_algo;

	const struct encrypt_desc *encrypt;
	unsigned enckeylen;
	unsigned char *enckey;

	int outif;
	IPsecSAref_t ref;
	IPsecSAref_t ref_peer;

	const struct ip_encap *encap_type;		/* ESP in TCP or UDP; or NULL */
	ip_address *natt_oa;
	const char *story;
	chunk_t sec_label;

	const char *nic_offload_dev;
	uint32_t xfrm_if_id;
	struct sa_mark mark_set; /* config keyword mark-out */

	deltatime_t sa_lifetime; /* number of seconds until SA expires */
};

struct raw_iface {
	ip_address addr;
	char name[IFNAMSIZ + 20]; /* what would be a safe size? */
	struct raw_iface *next;
};

extern char *pluto_listen;	/* from --listen flag */

struct kernel_ops {
	enum kernel_interface type;
	const char *kern_name;
	bool overlap_supported;
	bool sha2_truncbug_support;
	int replay_window;
	int *async_fdp;
	int *route_fdp;

	void (*init)(struct logger *logger);
	void (*shutdown)(struct logger *logger);
	void (*pfkey_register)(void);
	void (*process_queue)(void);
	void (*process_msg)(int, struct logger *);
	bool (*raw_policy)(enum kernel_policy_op op,
			   const ip_address *this_host,
			   const ip_selector *this_client,
			   const ip_address *that_host,
			   const ip_selector *that_client,
			   ipsec_spi_t cur_spi,
			   ipsec_spi_t new_spi,
			   unsigned int transport_proto,
			   enum eroute_type satype,
			   const struct kernel_encap *encap,
			   deltatime_t use_lifetime,
			   uint32_t sa_priority,
			   const struct sa_marks *sa_marks,
			   const uint32_t xfrm_if_id,
			   const shunk_t sec_label,
			   struct logger *logger);
	bool (*shunt_policy)(enum kernel_policy_op op,
			     const struct connection *c,
			     const struct spd_route *sr,
			     enum routing_t rt_kind,
			     const char *opname,
			     struct logger *logger);
	bool (*eroute_idle)(struct state *st, deltatime_t idle_max);	/* may mutate *st */
	bool (*add_sa)(const struct kernel_sa *sa,
		       bool replace,
		       struct logger *logger);
	bool (*grp_sa)(const struct kernel_sa *sa_outer,
		       const struct kernel_sa *sa_inner);
	bool (*del_sa)(const struct kernel_sa *sa,
		       struct logger *logger);
	bool (*get_sa)(const struct kernel_sa *sa,
		       uint64_t *bytes,
		       uint64_t *add_time,
		       struct logger *logger);
	ipsec_spi_t (*get_spi)(const ip_address *src,
			       const ip_address *dst,
			       const struct ip_protocol *proto,
			       bool tunnel_mode,
			       reqid_t reqid,
			       uintmax_t min, uintmax_t max,
			       const char *story,	/* often SAID string */
			       struct logger *logger);
	void (*process_raw_ifaces)(struct raw_iface *rifaces, struct logger *logger);
	bool (*exceptsocket)(int socketfd, int family, struct logger *logger);
	err_t (*migrate_sa_check)(struct logger *);
	bool (*migrate_sa)(struct state *st);
	void (*v6holes)(struct logger *logger);
	bool (*poke_ipsec_policy_hole)(const struct iface_dev *ifd, int fd, struct logger *logger);
	bool (*detect_offload)(const struct raw_iface *ifp, struct logger *logger);
};

extern int create_socket(const struct raw_iface *ifp, const char *v_name, int port, int proto);

#ifndef IPSECDEVPREFIX
# define IPSECDEVPREFIX "ipsec"
#endif

extern int useful_mastno;
#ifndef MASTDEVPREFIX
# define MASTDEVPREFIX  "mast"
#endif

extern const struct kernel_ops *kernel_ops;
#ifdef XFRM_SUPPORT
extern const struct kernel_ops xfrm_kernel_ops;
#endif
#ifdef BSD_KAME
extern const struct kernel_ops bsdkame_kernel_ops;
#endif

extern struct raw_iface *find_raw_ifaces6(struct logger *logger);

/* helper for invoking call outs */
extern bool fmt_common_shell_out(char *buf, size_t blen,
				 const struct connection *c,
				 const struct spd_route *sr,
				 struct state *st);

/* many bits reach in to use this, but maybe shouldn't */
extern bool do_command(const struct connection *c, const struct spd_route *sr,
		       const char *verb, struct state *st, struct logger *logger);

/* information from /proc/net/ipsec_eroute */

struct eroute_info {
	unsigned long count;
	ip_subnet ours;
	ip_subnet peers;
	ip_address dst;
	ip_said said;
	int transport_proto;
	struct eroute_info *next;
};

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
				   int transport_proto,
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
extern void migration_up(struct connection *c,  struct state *st);
extern void migration_down(struct connection *c,  struct state *st);

extern bool delete_bare_shunt(const ip_address *src, const ip_address *dst,
			      int transport_proto, ipsec_spi_t shunt_spi,
			      bool skip_xfrm_policy_delete,
			      const char *why, struct logger *logger);

extern bool assign_holdpass(const struct connection *c,
			struct spd_route *sr,
			int transport_proto,
			ipsec_spi_t negotiation_shunt,
			const ip_address *src, const ip_address *dst);

extern bool orphan_holdpass(const struct connection *c, struct spd_route *sr,
			    int transport_proto, ipsec_spi_t failure_shunt,
			    struct logger *logger);

extern enum policy_spi shunt_policy_spi(const struct connection *c, bool prospective);

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
extern void delete_ipsec_sa(struct state *st);

extern bool was_eroute_idle(struct state *st, deltatime_t idle_max);
extern bool get_sa_info(struct state *st, bool inbound, deltatime_t *ago /* OUTPUT */);
extern bool migrate_ipsec_sa(struct state *st);
extern bool del_spi(ipsec_spi_t spi,
		    const struct ip_protocol *proto,
		    const ip_address *src,
		    const ip_address *dest,
		    struct logger *logger);

static inline bool compatible_overlapping_connections(const struct connection *a,
						      const struct connection *b)
{
	return kernel_ops->overlap_supported &&
	       a != NULL && b != NULL &&
	       a != b &&
	       LIN(POLICY_OVERLAPIP, a->policy & b->policy);
}

extern void show_kernel_interface(struct show *s);
void shutdown_kernel(struct logger *logger);

/*
 * Note: "why" must be in stable storage (not auto, not heap)
 * because we use it indefinitely without copying or pfreeing.
 * Simple rule: use a string literal.
 */
extern void add_bare_shunt(const ip_selector *ours, const ip_selector *peers,
			   int transport_proto, ipsec_spi_t shunt_spi,
			   const char *why, struct logger *logger);

bool install_se_connection_policies(struct connection *c, struct logger *logger);

bool shunt_policy(enum kernel_policy_op op,
		  const struct connection *c,
		  const struct spd_route *sr,
		  enum routing_t rt_kind,
		  const char *what,
		  struct logger *logger);

extern deltatime_t bare_shunt_interval;

#define _KERNEL_H_
#endif /* _KERNEL_H_ */
