/* declarations of routines that interface with the kernel's IPsec mechanism
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2011 Michael Richardson <mcr@sandelman.ca>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2013 Kim Heino <b@bbbs.net>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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

struct sa_marks;
struct spd_route;

extern bool can_do_IPcomp;  /* can system actually perform IPCOMP? */
extern reqid_t global_reqids;

/*
 * Declare eroute things early enough for uses.
 * Some of these things, while they seem like they are KLIPS-only, the
 * definitions are in fact needed by all kernel interfaces at this time.
 *
 * Flags are encoded above the low-order byte of verbs.
 * "real" eroutes are only outbound.  Inbound eroutes don't exist,
 * but an addflow with an INBOUND flag allows IPIP tunnels to be
 * limited to appropriate source and destination addresses.
 */

#define IPSEC_PROTO_ANY 255

enum pluto_sadb_operations {
	ERO_ADD=1,
	ERO_REPLACE=2,
	ERO_DELETE=3,
	ERO_ADD_INBOUND=4,
	ERO_REPLACE_INBOUND=5,
	ERO_DEL_INBOUND=6
};

#define IPSEC_PROTO_ANY         255

/* KLIPS has:
 * #define ERO_DELETE	SADB_X_DELFLOW
 * #define ERO_ADD	SADB_X_ADDFLOW
 * #define ERO_REPLACE	(SADB_X_ADDFLOW | (SADB_X_SAFLAGS_REPLACEFLOW << ERO_FLAG_SHIFT))
 * #define ERO_ADD_INBOUND	(SADB_X_ADDFLOW | (SADB_X_SAFLAGS_INFLOW << ERO_FLAG_SHIFT))
 * #define ERO_DEL_INBOUND	(SADB_X_DELFLOW | (SADB_X_SAFLAGS_INFLOW << ERO_FLAG_SHIFT))
 */

struct pfkey_proto_info {
	int proto;
	int encapsulation;
	reqid_t reqid;
};

extern const struct pfkey_proto_info null_proto_info[2];

struct sadb_msg;

/* replaces SADB_X_SATYPE_* for non-KLIPS code. Assumes normal SADB_SATYPE values */
enum eroute_type {
	ET_UNSPEC = 0,
	ET_AH    = SA_AH,       /* (51)  authentication */
	ET_ESP   = SA_ESP,      /* (50)  encryption/auth */
	ET_IPCOMP= SA_COMP,     /* (108) compression */
	ET_INT   = SA_INT,      /* (61)  internal type */
	ET_IPIP  = SA_IPIP,     /* (4)   turn on tunnel type */
};
#define esatype2proto(X) ((int)(X))
#define proto2esatype(X) ((enum eroute_type)(X))

struct kernel_sa {
	const ip_address *src;
	const ip_address *dst;

	const ip_address *ndst;		/* netlink migration new destination */
	const ip_address *nsrc;		/* netlink migration new source */

	const ip_subnet *src_client;
	const ip_subnet *dst_client;

	bool inbound;
	int  nk_dir;			/* netky has 3, in,out & fwd */
	bool add_selector;
	bool esn;
	bool decap_dscp;
	bool nopmtudisc;
	uint32_t tfcpad;
	ipsec_spi_t spi;
	unsigned proto;
	unsigned int transport_proto;
	enum eroute_type esatype;
	unsigned replay_window;
	reqid_t reqid;

	unsigned authalg; /* use INTEG */

	const struct integ_desc *integ;
	unsigned authkeylen;
	unsigned char *authkey;

	/*
	 * This field contains the compression algorithm ID (or 0).
	 *
	 * XXX: For the moment, when ESP, it also contains the
	 * encryption algorithm's IKEv1 ID.  This is a just-in-case
	 * some code is still relying on that value.
	 */
	unsigned compalg;

	const struct encrypt_desc *encrypt;
	unsigned enckeylen;
	unsigned char *enckey;

	int outif;
	IPsecSAref_t ref;
	IPsecSAref_t refhim;

	int encapsulation;
	uint16_t natt_sport, natt_dport;
	uint8_t natt_type;
	ip_address *natt_oa;
	const char *text_said;
#ifdef HAVE_LABELED_IPSEC
	struct xfrm_user_sec_ctx_ike *sec_ctx;
#endif
	const char *nic_offload_dev;

	deltatime_t sa_lifetime; /* number of seconds until SA expires */
	/*
	 * Below two enties need to enabled and used,
	 * instead of getting passed
	 * uint32_t sa_priority;
	 * struct sa_marks *sa_marks;
	 */
};

struct raw_iface {
	ip_address addr;
	char name[IFNAMSIZ + 20]; /* what would be a safe size? */
	struct raw_iface *next;
};

/* which kernel interface to use */
extern enum kernel_interface kern_interface;

LIST_HEAD(iface_list, iface_dev);
extern struct iface_list interface_dev;

extern char *pluto_listen;	/* from --listen flag */


/* KAME has a different name for AES */
#if !defined(SADB_X_EALG_AESCBC) && defined(SADB_X_EALG_AES)
#define SADB_X_EALG_AESCBC SADB_X_EALG_AES
#endif

struct kernel_ops {
	enum kernel_interface type;
	const char *kern_name;
	bool inbound_eroute;
	bool overlap_supported;
	bool sha2_truncbug_support;
	int replay_window;
	int *async_fdp;
	int *route_fdp;

	void (*init)(void);
	void (*pfkey_register)(void);
	void (*pfkey_register_response)(const struct sadb_msg *msg);
	void (*process_queue)(void);
	void (*process_msg)(int);
	void (*scan_shunts)(void);
	void (*set_debug)(int,
			  libreswan_keying_debug_func_t debug_func,
			  libreswan_keying_debug_func_t error_func);
	bool (*raw_eroute)(const ip_address *this_host,
			   const ip_subnet *this_client,
			   const ip_address *that_host,
			   const ip_subnet *that_client,
			   ipsec_spi_t cur_spi,
			   ipsec_spi_t new_spi,
			   int sa_proto,
			   unsigned int transport_proto,
			   enum eroute_type satype,
			   const struct pfkey_proto_info *proto_info,
			   deltatime_t use_lifetime,
			   uint32_t sa_priority,
			   const struct sa_marks *sa_marks,
			   enum pluto_sadb_operations op,
			   const char *text_said
#ifdef HAVE_LABELED_IPSEC
			   , const char *policy_label
#endif
			   );
	bool (*shunt_eroute)(const struct connection *c,
			     const struct spd_route *sr,
			     enum routing_t rt_kind,
			     enum pluto_sadb_operations op,
			     const char *opname);
	bool (*sag_eroute)(const struct state *st, const struct spd_route *sr,
			   enum pluto_sadb_operations op, const char *opname);
	bool (*eroute_idle)(struct state *st, deltatime_t idle_max);	/* may mutate *st */
	void (*remove_orphaned_holds)(int transportproto,
				      const ip_subnet *ours,
				      const ip_subnet *his);
	bool (*add_sa)(const struct kernel_sa *sa, bool replace);
	bool (*grp_sa)(const struct kernel_sa *sa_outer,
		       const struct kernel_sa *sa_inner);
	bool (*del_sa)(const struct kernel_sa *sa);
	bool (*get_sa)(const struct kernel_sa *sa, uint64_t *bytes,
		       uint64_t *add_time);
	ipsec_spi_t (*get_spi)(const ip_address *src,
			       const ip_address *dst,
			       int proto,
			       bool tunnel_mode,
			       reqid_t reqid,
			       ipsec_spi_t min,
			       ipsec_spi_t max,
			       const char *text_said);
	bool (*docommand)(const struct connection *c,
			  const struct spd_route *sr,
			  const char *verb,
			  const char *verb_suffix,
			  struct state *st);
	void (*process_ifaces)(struct raw_iface *rifaces);
	bool (*exceptsocket)(int socketfd, int family);
	err_t (*migrate_sa_check)(void);
	bool (*migrate_sa)(struct state *st);
	bool (*v6holes)();
	bool (*poke_ipsec_policy_hole)(struct raw_iface *ifp, int fd);
};

extern int create_socket(struct raw_iface *ifp, const char *v_name, int port);

#ifndef IPSECDEVPREFIX
# define IPSECDEVPREFIX "ipsec"
#endif

extern int useful_mastno;
#ifndef MASTDEVPREFIX
# define MASTDEVPREFIX  "mast"
#endif

extern const struct kernel_ops *kernel_ops;
extern struct raw_iface *find_raw_ifaces4(void);
extern struct raw_iface *find_raw_ifaces6(void);

/* helper for invoking call outs */
extern int fmt_common_shell_out(char *buf, int blen, const struct connection *c,
				const struct spd_route *sr, struct state *st);

#ifdef KLIPS_MAST
/* KLIPS/mast/pfkey things */
extern bool pfkey_plumb_mast_device(int mast_dev);
#endif

/* many bits reach in to use this, but maybe shouldn't */
extern bool do_command(const struct connection *c, const struct spd_route *sr,
		       const char *verb, struct state *st);

extern bool invoke_command(const char *verb, const char *verb_suffix,
			   const char *cmd);

/* information from /proc/net/ipsec_eroute */

struct eroute_info {
	unsigned long count;
	ip_subnet ours;
	ip_subnet his;
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

struct bare_shunt {
	policy_prio_t policy_prio;
	ip_subnet ours;
	ip_subnet his;
	ip_said said;
	int transport_proto;
	unsigned long count;
	monotime_t last_activity;

	/*
	 * Note: "why" must be in stable storage (not auto, not heap)
	 * because we use it indefinitely without copying or pfreeing.
	 * Simple rule: use a string literal.
	 */
	const char *why;

	struct bare_shunt *next;
};

extern void show_shunt_status(void);
extern unsigned show_shunt_count(void);

struct bare_shunt **bare_shunt_ptr(const ip_subnet *ours,
				   const ip_subnet *his,
				   int transport_proto);

/* A netlink header defines EM_MAXRELSPIS, the max number of SAs in a group.
 * Is there a PF_KEY equivalent?
 */
#ifndef EM_MAXRELSPIS
# define EM_MAXRELSPIS 4        /* AH ESP IPCOMP IPIP */
#endif

/*
 * Note: "why" must be in stable storage (not auto, not heap)
 * because we use it indefinitely without copying or pfreeing.
 * Simple rule: use a string literal.
 */
#ifdef HAVE_LABELED_IPSEC
struct xfrm_user_sec_ctx_ike; /* forward declaration of tag */
#endif
extern void record_and_initiate_opportunistic(const ip_subnet *,
					      const ip_subnet *,
					      int transport_proto,
#ifdef HAVE_LABELED_IPSEC
					      struct xfrm_user_sec_ctx_ike *,
#endif
					      const char *why);
extern void init_kernel(void);

struct connection;      /* forward declaration of tag */
extern bool trap_connection(struct connection *c);
extern void unroute_connection(struct connection *c);
extern void migration_up(struct connection *c,  struct state *st);
extern void migration_down(struct connection *c,  struct state *st);

extern bool has_bare_hold(const ip_address *src, const ip_address *dst,
			  int transport_proto);

extern bool delete_bare_shunt(const ip_address *src, const ip_address *dst,
			       int transport_proto, ipsec_spi_t shunt_spi,
			       const char *why);

extern bool replace_bare_shunt(const ip_address *src, const ip_address *dst,
			       policy_prio_t policy_prio,
			       ipsec_spi_t cur_shunt_spi,   /* in host order! */
			       ipsec_spi_t new_shunt_spi,   /* in host order! */
			       int transport_proto,
			       const char *why);

extern bool assign_holdpass(const struct connection *c,
			struct spd_route *sr,
			int transport_proto,
			ipsec_spi_t negotiation_shunt,
			const ip_address *src, const ip_address *dst);

extern bool orphan_holdpass(const struct connection *c, struct spd_route *sr,
		int transport_proto, ipsec_spi_t failure_shunt);

extern ipsec_spi_t shunt_policy_spi(const struct connection *c, bool prospective);

struct state;   /* forward declaration of tag */
extern ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid,
				 int proto,
				 const struct spd_route *sr,
				 bool tunnel_mode);
extern ipsec_spi_t get_my_cpi(const struct spd_route *sr, bool tunnel_mode);

extern bool install_inbound_ipsec_sa(struct state *st);
extern bool install_ipsec_sa(struct state *st, bool inbound_also);
extern void delete_ipsec_sa(struct state *st);
extern bool route_and_eroute(struct connection *c,
			     struct spd_route *sr,
			     struct state *st);

extern bool was_eroute_idle(struct state *st, deltatime_t idle_max);
extern bool get_sa_info(struct state *st, bool inbound, deltatime_t *ago /* OUTPUT */);
extern bool migrate_ipsec_sa(struct state *st);


extern bool eroute_connection(const struct spd_route *sr,
			      ipsec_spi_t cur_spi,
			      ipsec_spi_t new_spi,
			      int proto, enum eroute_type esatype,
			      const struct pfkey_proto_info *proto_info,
			      uint32_t sa_priority,
			      const struct sa_marks *sa_marks,
			      unsigned int op, const char *opname
#ifdef HAVE_LABELED_IPSEC
			      , const char *policy_label
#endif
			      );

static inline bool compatible_overlapping_connections(const struct connection *a,
						      const struct connection *b)
{
	return kernel_ops->overlap_supported &&
	       a != NULL && b != NULL &&
	       a != b &&
	       LIN(POLICY_OVERLAPIP, a->policy & b->policy);
}

#ifdef KLIPS
extern const struct kernel_ops klips_kernel_ops;
#endif
#ifdef KLIPS_MAST
extern const struct kernel_ops mast_kernel_ops;
#endif

extern void show_kernel_interface(void);
extern void free_kernelfd(void);
extern void expire_bare_shunts(void);


/*
 * Note: "why" must be in stable storage (not auto, not heap)
 * because we use it indefinitely without copying or pfreeing.
 * Simple rule: use a string literal.
 */
extern void add_bare_shunt(const ip_subnet *ours, const ip_subnet *his,
		int transport_proto, ipsec_spi_t shunt_spi,
		const char *why);

// TEMPORARY
extern bool raw_eroute(const ip_address *this_host,
		       const ip_subnet *this_client,
		       const ip_address *that_host,
		       const ip_subnet *that_client,
		       ipsec_spi_t cur_spi,
		       ipsec_spi_t new_spi,
		       int sa_proto,
		       unsigned int transport_proto,
		       enum eroute_type esatype,
		       const struct pfkey_proto_info *proto_info,
		       deltatime_t use_lifetime,
		       uint32_t sa_priority,
		       const struct sa_marks *sa_marks,
		       enum pluto_sadb_operations op,
		       const char *opname
#ifdef HAVE_LABELED_IPSEC
		       , const char *policy_label
#endif
		       );

extern deltatime_t bare_shunt_interval;
extern void set_text_said(char *text_said, const ip_address *dst,
			  ipsec_spi_t spi, int sa_proto);
#define _KERNEL_H_
#endif /* _KERNEL_H_ */
