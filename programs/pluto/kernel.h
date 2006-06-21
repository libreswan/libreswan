/* declarations of routines that interface with the kernel's IPsec mechanism
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: kernel.h,v 1.51 2005/08/24 22:50:50 mcr Exp $
 */

#ifndef _KERNEL_H_

#include <net/if.h>

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

#define IPSEC_PROTO_ANY		255

/* KLIPS has:
   #define ERO_DELETE	SADB_X_DELFLOW
   #define ERO_ADD	SADB_X_ADDFLOW
   #define ERO_REPLACE	(SADB_X_ADDFLOW | (SADB_X_SAFLAGS_REPLACEFLOW << ERO_FLAG_SHIFT))
   #define ERO_ADD_INBOUND	(SADB_X_ADDFLOW | (SADB_X_SAFLAGS_INFLOW << ERO_FLAG_SHIFT))
   #define ERO_DEL_INBOUND	(SADB_X_DELFLOW | (SADB_X_SAFLAGS_INFLOW << ERO_FLAG_SHIFT))
*/

struct pfkey_proto_info {
	int proto;
	int encapsulation;
	unsigned reqid;
};
struct sadb_msg;

/* replaces SADB_X_SATYPE_* for non-KLIPS code. Assumes normal SADB_SATYPE values */
enum eroute_type {
	ET_UNSPEC = 0,
	ET_AH    = SA_AH,
	ET_ESP   = SA_ESP,
	ET_IPCOMP= SA_COMP,
	ET_INT   = SA_INT,    /* internal type */
	ET_IPIP  = SA_IPIP,   /* turn on tunnel type */
};
#define esatype2proto(X) (int)X
#define proto2esatype(X) (enum eroute_type)X

struct kernel_sa {
	const ip_address *src;
	const ip_address *dst;

	const ip_subnet *src_client;
	const ip_subnet *dst_client;

	ipsec_spi_t spi;
	unsigned proto;
	enum eroute_type esatype;
	unsigned replay_window;
	unsigned reqid;

	unsigned authalg;
	unsigned authkeylen;
	unsigned char *authkey;

	unsigned encalg;
	unsigned enckeylen;
	unsigned char *enckey;

	IPsecSAref_t ref, refhim;

	int encapsulation;
#ifdef NAT_TRAVERSAL
	u_int16_t natt_sport, natt_dport;
	u_int8_t transid, natt_type;
	ip_address *natt_oa;
#endif
	const char *text_said;
};

struct raw_iface {
    ip_address addr;
    char name[IFNAMSIZ + 20];	/* what would be a safe size? */
    struct raw_iface *next;
};

LIST_HEAD(iface_list, iface_dev);
extern struct iface_list interface_dev;

/* KAME has a different name for AES */
#if !defined(SADB_X_EALG_AESCBC) && defined(SADB_X_EALG_AES)
#define SADB_X_EALG_AESCBC SADB_X_EALG_AES
#endif

struct kernel_ops {
    enum kernel_interface type;
    const char *kern_name;
    bool inbound_eroute;
    bool policy_lifetime;
    bool overlap_supported;
    int  replay_window;
    int *async_fdp;
    
    void (*init)(void);
    void (*pfkey_register)(void);
    void (*pfkey_register_response)(const struct sadb_msg *msg);
    void (*process_queue)(void);
    void (*process_msg)(void);
    void (*set_debug)(int
		      , openswan_keying_debug_func_t debug_func
		      , openswan_keying_debug_func_t error_func);
    bool (*raw_eroute)(const ip_address *this_host,
		       const ip_subnet *this_client,
		       const ip_address *that_host,
		       const ip_subnet *that_client,
		       ipsec_spi_t spi,
		       unsigned int proto,
		       unsigned int transport_proto,
		       enum eroute_type satype,
		       const struct pfkey_proto_info *proto_info,
		       time_t use_lifetime,
		       enum pluto_sadb_operations op,
		       const char *text_said);
    bool (*shunt_eroute)(struct connection *c
			 , struct spd_route *sr
			 , enum routing_t rt_kind
			 , enum pluto_sadb_operations op
			 , const char *opname);
    bool (*sag_eroute)(struct state *st, struct spd_route *sr
		       , unsigned op, const char *opname);
    bool (*eroute_idle)(struct state *st, time_t idle_max);
    void (*remove_orphaned_holds)(int transportproto
				  , const ip_subnet *ours
				  , const ip_subnet *his);
    bool (*add_sa)(const struct kernel_sa *sa, bool replace);
    bool (*grp_sa)(const struct kernel_sa *sa_outer,
		   const struct kernel_sa *sa_inner);
    bool (*del_sa)(const struct kernel_sa *sa);
    ipsec_spi_t (*get_spi)(const ip_address *src,
			   const ip_address *dst,
			   int proto,
			   bool tunnel_mode,
			   unsigned reqid,
			   ipsec_spi_t min,
			   ipsec_spi_t max,
			   const char *text_said);
    bool (*docommand)(struct connection *c
		      , struct spd_route *sr
		      , const char *verb
		      , struct state *st);
    void (*process_ifaces)(struct raw_iface *rifaces);
};

extern int create_socket(struct raw_iface *ifp, const char *v_name, int port);

#ifndef IPSECDEVPREFIX
# define IPSECDEVPREFIX "ipsec"
#endif

#ifndef MASTDEVPREFIX
# define MASTDEVPREFIX  "mast"
#endif

extern const struct kernel_ops *kernel_ops;
extern struct raw_iface *find_raw_ifaces4(void);
extern struct raw_iface *find_raw_ifaces6(void);

/* helper for invoking call outs */
extern int fmt_common_shell_out(char *buf, int blen, struct connection *c
				, struct spd_route *sr, struct state *st);

/* KLIPS/mast/pfkey things */
extern bool pfkey_plumb_mast_device(int mast_dev);

#if defined(linux)
extern bool do_command_linux(struct connection *c, struct spd_route *sr
			     , const char *verb, struct state *st);
extern bool invoke_command(const char *verb, const char *verb_suffix, char *cmd);
#endif

#if defined(__FreeBSD__)
extern bool do_command_freebsd(struct connection *c, struct spd_route *sr
			       , const char *verb, struct state *st);
extern bool invoke_command(const char *verb, const char *verb_suffix, char *cmd);
#endif

#if defined(__CYGWIN32__)
extern bool do_command_cygwin(struct connection *c, struct spd_route *sr
			      , const char *verb, struct state *st);
#endif


/* information from /proc/net/ipsec_eroute */

struct eroute_info {
    unsigned long count;
    ip_subnet ours;
    ip_subnet his;
    ip_address dst;
    ip_said	said;
    int         transport_proto;
    struct eroute_info *next;
};

extern struct eroute_info *orphaned_holds;

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

#define SHUNT_SCAN_INTERVAL     (60 * 2)   /* time between scans of eroutes */

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
    time_t last_activity;
    char *why;
    struct bare_shunt *next;
};
extern void show_shunt_status(void);

#ifdef DEBUG
extern void DBG_bare_shunt_log(const char *op, const struct bare_shunt *bs);
#define DBG_bare_shunt(op, bs) DBG_bare_shunt_log(op,bs)
#else /* !DEBUG */
#define DBG_bare_shunt(op, bs) {}
#endif /* !DEBUG */

struct bare_shunt **bare_shunt_ptr(const ip_subnet *ours
				   , const ip_subnet *his
				   , int transport_proto);

/* A netlink header defines EM_MAXRELSPIS, the max number of SAs in a group.
 * Is there a PF_KEY equivalent?
 */
#ifndef EM_MAXRELSPIS
# define EM_MAXRELSPIS 4	/* AH ESP IPCOMP IPIP */
#endif

extern void record_and_initiate_opportunistic(const ip_subnet *
					      , const ip_subnet *
					      , int transport_proto
					      , const char *why);

extern void init_kernel(void);

extern void scan_proc_shunts(void);

struct connection;	/* forward declaration of tag */
extern bool trap_connection(struct connection *c);
extern void unroute_connection(struct connection *c);

extern bool has_bare_hold(const ip_address *src, const ip_address *dst
    , int transport_proto);

extern bool replace_bare_shunt(const ip_address *src, const ip_address *dst
			       , policy_prio_t policy_prio
			       , ipsec_spi_t shunt_spi	/* in host order! */
			       , bool repl
			       , int transport_proto
			       , const char *why);

extern bool assign_hold(struct connection *c
			, struct spd_route *sr
 			, int transport_proto
			, const ip_address *src, const ip_address *dst);

extern ipsec_spi_t shunt_policy_spi(struct connection *c, bool prospective);


struct state;	/* forward declaration of tag */
extern ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid
				 , int proto
				 , struct spd_route *sr
				 , bool tunnel_mode);
extern ipsec_spi_t get_my_cpi(struct spd_route *sr, bool tunnel_mode);

extern bool install_inbound_ipsec_sa(struct state *st);
extern bool install_ipsec_sa(struct state *st, bool inbound_also);
extern void delete_ipsec_sa(struct state *st, bool inbound_only);
extern bool route_and_eroute(struct connection *c
			     , struct spd_route *sr
			     , struct state *st);

extern bool was_eroute_idle(struct state *st, time_t idle_max);

#ifdef NAT_TRAVERSAL
extern bool update_ipsec_sa(struct state *st);
#endif

extern bool eroute_connection(struct spd_route *sr
			      , ipsec_spi_t spi, unsigned int proto
			      , unsigned int satype
			      , const struct pfkey_proto_info *proto_info
			      , unsigned int op, const char *opname);

extern const struct kernel_ops klips_kernel_ops;
extern const struct kernel_ops mast_kernel_ops;
extern const struct kernel_ops bsdkame_kernel_ops;

#define _KERNEL_H_
#endif /* _KERNEL_H_ */
