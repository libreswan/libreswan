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
	int mode;
	reqid_t reqid;
};

extern const struct pfkey_proto_info null_proto_info[2];

struct sadb_msg;

/*
 * replaces SADB_X_SATYPE_* for non-KLIPS code. Assumes normal SADB_SATYPE values
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
	const ip_subnet *client;
	/*
	 * XXX: for mobike? does this need a port or is the port
	 * optional or unchanging? perhaps the port is assumed to be
	 * embedded in the address (making it an endpoint)
	 */
	const ip_address *new_address;
};

struct kernel_sa {
	struct kernel_end src;
	struct kernel_end dst;

	bool inbound;
	int  nk_dir;			/* netky has 3, in,out & fwd */
	bool add_selector;
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
	IPsecSAref_t ref_peer;

	int mode;		/* transport or tunnel */
	const struct ip_encap *encap_type;		/* ESP in TCP or UDP; or NULL */
	ip_address *natt_oa;
	const char *text_said;
	struct xfrm_user_sec_ctx_ike *sec_ctx;
	const char *nic_offload_dev;
	uint32_t xfrm_if_id;

	deltatime_t sa_lifetime; /* number of seconds until SA expires */
};

struct raw_iface {
	ip_address addr;
	char name[IFNAMSIZ + 20]; /* what would be a safe size? */
	struct raw_iface *next;
};

extern char *pluto_listen;	/* from --listen flag */


/* KAME has a different name for AES */
#if !defined(SADB_X_EALG_AESCBC) && defined(SADB_X_EALG_AES)
#define SADB_X_EALG_AESCBC SADB_X_EALG_AES
#endif

struct kernel_ops {
	enum kernel_interface type;
	const char *kern_name;
	bool overlap_supported;
	bool sha2_truncbug_support;
	int replay_window;
	int *async_fdp;
	int *route_fdp;

	void (*init)(void);
	void (*shutdown)();
	void (*pfkey_register)(void);
	void (*process_queue)(void);
	void (*process_msg)(int);
	void (*scan_shunts)(void);
	bool (*raw_eroute)(const ip_address *this_host,
			   const ip_subnet *this_client,
			   const ip_address *that_host,
			   const ip_subnet *that_client,
			   ipsec_spi_t cur_spi,
			   ipsec_spi_t new_spi,
			   const struct ip_protocol *sa_proto,
			   unsigned int transport_proto,
			   enum eroute_type satype,
			   const struct pfkey_proto_info *proto_info,
			   deltatime_t use_lifetime,
			   uint32_t sa_priority,
			   const struct sa_marks *sa_marks,
			   const uint32_t xfrm_if_id,
			   enum pluto_sadb_operations op,
			   const char *text_said,
			   const char *policy_label);
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
				      const ip_subnet *peers);
	bool (*add_sa)(const struct kernel_sa *sa, bool replace);
	bool (*grp_sa)(const struct kernel_sa *sa_outer,
		       const struct kernel_sa *sa_inner);
	bool (*del_sa)(const struct kernel_sa *sa);
	bool (*get_sa)(const struct kernel_sa *sa, uint64_t *bytes,
		       uint64_t *add_time);
	ipsec_spi_t (*get_spi)(const ip_address *src,
			       const ip_address *dst,
			       const struct ip_protocol *proto,
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
	void (*process_raw_ifaces)(struct raw_iface *rifaces);
	bool (*exceptsocket)(int socketfd, int family);
	err_t (*migrate_sa_check)(void);
	bool (*migrate_sa)(struct state *st);
	bool (*v6holes)();
	bool (*poke_ipsec_policy_hole)(const struct iface_dev *ifd, int fd);
	bool (*detect_offload)(const struct raw_iface *ifp);
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

extern struct raw_iface *find_raw_ifaces6(void);

/* helper for invoking call outs */
extern bool fmt_common_shell_out(char *buf, size_t blen,
				 const struct connection *c,
				 const struct spd_route *sr,
				 struct state *st);

/* many bits reach in to use this, but maybe shouldn't */
extern bool do_command(const struct connection *c, const struct spd_route *sr,
		       const char *verb, struct state *st);

extern bool invoke_command(const char *verb, const char *verb_suffix,
			   const char *cmd);

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

struct bare_shunt **bare_shunt_ptr(const ip_subnet *ours,
				   const ip_subnet *peers,
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
struct xfrm_user_sec_ctx_ike; /* forward declaration of tag */
extern void record_and_initiate_opportunistic(const ip_selector *our_client,
					      const ip_selector *peer_client,
					      unsigned transport_proto,
					      struct xfrm_user_sec_ctx_ike *,
					      const char *why);
extern void init_kernel(void);

struct connection;      /* forward declaration of tag */
extern bool trap_connection(struct connection *c, struct fd *whackfd);
extern void unroute_connection(struct connection *c);
extern void migration_up(struct connection *c,  struct state *st);
extern void migration_down(struct connection *c,  struct state *st);

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
				 const struct ip_protocol *proto,
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
extern bool del_spi(ipsec_spi_t spi,
		    const struct ip_protocol *proto,
		    const ip_address *src,
		    const ip_address *dest);


extern bool eroute_connection(const struct spd_route *sr,
			      ipsec_spi_t cur_spi,
			      ipsec_spi_t new_spi,
			      const struct ip_protocol *proto,
			      enum eroute_type esatype,
			      const struct pfkey_proto_info *proto_info,
			      uint32_t sa_priority,
			      const struct sa_marks *sa_marks,
			      const uint32_t xfrm_if_id,
			      unsigned int op, const char *opname,
			      const char *policy_label);
static inline bool compatible_overlapping_connections(const struct connection *a,
						      const struct connection *b)
{
	return kernel_ops->overlap_supported &&
	       a != NULL && b != NULL &&
	       a != b &&
	       LIN(POLICY_OVERLAPIP, a->policy & b->policy);
}

extern void show_kernel_interface(struct show *s);
extern void free_kernelfd(void);
extern void expire_bare_shunts(void);


/*
 * Note: "why" must be in stable storage (not auto, not heap)
 * because we use it indefinitely without copying or pfreeing.
 * Simple rule: use a string literal.
 */
extern void add_bare_shunt(const ip_subnet *ours, const ip_subnet *peers,
		int transport_proto, ipsec_spi_t shunt_spi,
		const char *why);

// TEMPORARY
extern bool raw_eroute(const ip_address *this_host,
		       const ip_subnet *this_client,
		       const ip_address *that_host,
		       const ip_subnet *that_client,
		       ipsec_spi_t cur_spi,
		       ipsec_spi_t new_spi,
		       const struct ip_protocol *sa_proto,
		       unsigned int transport_proto,
		       enum eroute_type esatype,
		       const struct pfkey_proto_info *proto_info,
		       deltatime_t use_lifetime,
		       uint32_t sa_priority,
		       const struct sa_marks *sa_marks,
		       const uint32_t xfrm_if_id,
		       enum pluto_sadb_operations op,
		       const char *opname,
		       const char *policy_label);

extern deltatime_t bare_shunt_interval;
extern void set_text_said(char *text_said, const ip_address *dst,
			  ipsec_spi_t spi, const struct ip_protocol *sa_proto);
#define _KERNEL_H_
#endif /* _KERNEL_H_ */
