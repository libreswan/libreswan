/* Interface to the PF_KEY v2 IPsec mechanism, for Libreswan
 *
 * Copyright (C)  2022  Andrew Cagney
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

#ifndef KERNEL_SADB_H
#define KERNEL_SADB_H

#include <stdbool.h>
#include <stddef.h>		/* for size_t */
#include <netinet/in.h>		/* for IPPROTO_* */
#include <stdint.h>		/* because pfkeyv2.h doesn't */

#include "lsw-pfkeyv2.h"	/* also pulls in missing types dependencies */

/*
 * struct sadb_x_policy requires these definitions, but OpenBSD
 * doesn't use any of that.  OpenBSD's SADB_X_EXT_POLICY is a total
 * rewrite.
 */

#if defined SADB_X_EXT_POLICY
# if defined __linux__
#  include <linux/ipsec.h>
# elif defined __APPLE__
#  include <netinet6/ipsec.h>	/* guess */
# else
#  include <netipsec/ipsec.h>
# endif
#endif

/*
 * struct sadb_policy requires these additional definitions.
 */

#ifdef SADB_X_EXT_PROTOCOL
# include <sys/socket.h>       /* for struct sockaddr; required by ... */
# include <netinet/ip_ipsp.h>  /* for IPSP_DIRECTION_* */
#endif

#include "lswcdefs.h"
#include "shunk.h"
#include "sparse_names.h"
#include "ip_address.h"
#include "ip_port.h"

struct verbose;
struct logger;
struct ike_alg;
struct jambuf;

enum sadb_type {

	sadb_acquire = SADB_ACQUIRE,
#undef SADB_ACQUIRE
#define SADB_ACQUIRE sadb_acquire

	sadb_add = SADB_ADD,
#undef SADB_ADD
#define SADB_ADD sadb_add

	sadb_delete = SADB_DELETE,
#undef SADB_DELETE
#define SADB_DELETE sadb_delete

	sadb_get = SADB_GET,
#undef SADB_GET
#define SADB_GET sadb_get

	sadb_getspi = SADB_GETSPI,
#undef SADB_GETSPI
#define SADB_GETSPI sadb_getspi

#ifdef SADB_FLUSH
	sadb_flush = SADB_FLUSH,
#undef SADB_FLUSH
#define SADB_FLUSH sadb_flush
#endif

#ifdef SADB_X_SPDFLUSH
	sadb_x_spdflush = SADB_X_SPDFLUSH,
#undef SADB_X_SPDFLUSH
#define SADB_X_SPDFLUSH sadb_x_spdflush
#endif

	sadb_register = SADB_REGISTER,
#undef SADB_REGISTER
#define SADB_REGISTER sadb_register

	sadb_update = SADB_UPDATE,
#undef SADB_UPDATE
#define SADB_UPDATE sadb_update

#ifdef SADB_X_SPDADD
	sadb_x_spdadd = SADB_X_SPDADD,
#undef SADB_X_SPDADD
#define SADB_X_SPDADD sadb_x_spdadd
#endif

#ifdef SADB_X_SPDDELETE
	sadb_x_spddelete = SADB_X_SPDDELETE,
#undef SADB_X_SPDDELETE
#define SADB_X_SPDDELETE sadb_x_spddelete
#endif

#ifdef SADB_X_SPDUPDATE
	sadb_x_spdupdate = SADB_X_SPDUPDATE,
#undef SADB_X_SPDUPDATE
#define SADB_X_SPDUPDATE sadb_x_spdupdate
#endif

#ifdef SADB_X_ADDFLOW
	sadb_x_addflow = SADB_X_ADDFLOW,
#undef SADB_X_ADDFLOW
#define SADB_X_ADDFLOW sadb_x_addflow
#endif

#ifdef SADB_X_DELFLOW
	sadb_x_delflow = SADB_X_DELFLOW,
#undef SADB_X_DELFLOW
#define SADB_X_DELFLOW sadb_x_delflow
#endif

};

enum sadb_satype {

	sadb_satype_ah = SADB_SATYPE_AH,
#undef SADB_SATYPE_AH
#define SADB_SATYPE_AH sadb_satype_ah

	sadb_satype_esp = SADB_SATYPE_ESP,
#undef SADB_SATYPE_ESP
#define SADB_SATYPE_ESP sadb_satype_esp

	sadb_satype_unspec = SADB_SATYPE_UNSPEC,
#undef SADB_SATYPE_UNSPEC
#define SADB_SATYPE_UNSPEC sadb_satype_unspec

	sadb_x_satype_ipcomp = SADB_X_SATYPE_IPCOMP,
#undef SADB_X_SATYPE_IPCOMP
#define SADB_X_SATYPE_IPCOMP sadb_x_satype_ipcomp

};

/* only add what is used */

enum sadb_exttype {

	sadb_ext_address_dst = SADB_EXT_ADDRESS_DST,
#undef SADB_EXT_ADDRESS_DST
#define SADB_EXT_ADDRESS_DST sadb_ext_address_dst

	sadb_ext_address_src = SADB_EXT_ADDRESS_SRC,
#undef SADB_EXT_ADDRESS_SRC
#define SADB_EXT_ADDRESS_SRC sadb_ext_address_src

	sadb_ext_key_auth = SADB_EXT_KEY_AUTH,
#undef SADB_EXT_KEY_AUTH
#define SADB_EXT_KEY_AUTH sadb_ext_key_auth

	sadb_ext_key_encrypt = SADB_EXT_KEY_ENCRYPT,
#undef SADB_EXT_KEY_ENCRYPT
#define SADB_EXT_KEY_ENCRYPT sadb_ext_key_encrypt

	sadb_ext_lifetime_current = SADB_EXT_LIFETIME_CURRENT,
#undef SADB_EXT_LIFETIME_CURRENT
#define SADB_EXT_LIFETIME_CURRENT sadb_ext_lifetime_current

	sadb_ext_lifetime_hard = SADB_EXT_LIFETIME_HARD,
#undef SADB_EXT_LIFETIME_HARD
#define SADB_EXT_LIFETIME_HARD sadb_ext_lifetime_hard

	sadb_ext_lifetime_soft = SADB_EXT_LIFETIME_SOFT,
#undef SADB_EXT_LIFETIME_SOFT
#define SADB_EXT_LIFETIME_SOFT sadb_ext_lifetime_soft

#ifdef SADB_X_EXT_LIFETIME_LASTUSE
	sadb_x_ext_lifetime_lastuse = SADB_X_EXT_LIFETIME_LASTUSE,
#undef SADB_X_EXT_LIFETIME_LASTUSE
#define SADB_X_EXT_LIFETIME_LASTUSE sadb_x_ext_lifetime_lastuse
#endif

	sadb_ext_proposal = SADB_EXT_PROPOSAL,
#undef SADB_EXT_PROPOSAL
#define SADB_EXT_PROPOSAL sadb_ext_proposal

	sadb_ext_sa = SADB_EXT_SA,
#undef SADB_EXT_SA
#define SADB_EXT_SA sadb_ext_sa

#ifdef SADB_X_EXT_SA2
	sadb_x_ext_sa2 = SADB_X_EXT_SA2,
#undef SADB_X_EXT_SA2
#define SADB_X_EXT_SA2 sadb_x_ext_sa2
#endif

	sadb_ext_spirange = SADB_EXT_SPIRANGE,
#undef SADB_EXT_SPIRANGE
#define SADB_EXT_SPIRANGE sadb_ext_spirange

	sadb_ext_supported_auth = SADB_EXT_SUPPORTED_AUTH,
#undef SADB_EXT_SUPPORTED_AUTH
#define SADB_EXT_SUPPORTED_AUTH sadb_ext_supported_auth

	sadb_ext_supported_encrypt = SADB_EXT_SUPPORTED_ENCRYPT,
#undef SADB_EXT_SUPPORTED_ENCRYPT
#define SADB_EXT_SUPPORTED_ENCRYPT sadb_ext_supported_encrypt

#ifdef SADB_X_EXT_SUPPORTED_COMP
	sadb_x_ext_supported_comp = SADB_X_EXT_SUPPORTED_COMP,
#undef SADB_X_EXT_SUPPORTED_COMP
#define SADB_X_EXT_SUPPORTED_COMP sadb_x_ext_supported_comp
#endif

#ifdef SADB_X_EXT_NAT_T_TYPE
	sadb_x_ext_nat_t_type = SADB_X_EXT_NAT_T_TYPE,
#undef SADB_X_EXT_NAT_T_TYPE
#define SADB_X_EXT_NAT_T_TYPE sadb_x_ext_nat_t_type
#endif

#ifdef SADB_X_EXT_POLICY
	sadb_x_ext_policy = SADB_X_EXT_POLICY,
#undef SADB_X_EXT_POLICY
#define SADB_X_EXT_POLICY sadb_x_ext_policy
#endif

#ifdef SADB_X_EXT_SA_REPLAY
	sadb_x_ext_sa_replay = SADB_X_EXT_SA_REPLAY,
#undef SADB_X_EXT_SA_REPLAY
#define SADB_X_EXT_SA_REPLAY sadb_x_ext_sa_replay
#endif

#ifdef SADB_X_EXT_COUNTER /* OpenBSD */
	sadb_x_ext_counter = SADB_X_EXT_COUNTER,
#undef SADB_X_EXT_COUNTER
#define SADB_X_EXT_COUNTER sadb_x_ext_counter
#endif

#ifdef SADB_X_EXT_SRC_MASK /* OpenBSD */
	sadb_x_ext_src_mask = SADB_X_EXT_SRC_MASK,
#undef SADB_X_EXT_SRC_MASK
#define SADB_X_EXT_SRC_MASK sadb_x_ext_src_mask
#endif

#ifdef SADB_X_EXT_DST_MASK /* OpenBSD */
	sadb_x_ext_dst_mask = SADB_X_EXT_DST_MASK,
#undef SADB_X_EXT_DST_MASK
#define SADB_X_EXT_DST_MASK sadb_x_ext_dst_mask
#endif

#ifdef SADB_X_EXT_SRC_FLOW /* OpenBSD */
	sadb_x_ext_src_flow = SADB_X_EXT_SRC_FLOW,
#undef SADB_X_EXT_SRC_FLOW
#define SADB_X_EXT_SRC_FLOW sadb_x_ext_src_flow
#endif

#ifdef SADB_X_EXT_DST_FLOW /* OpenBSD */
	sadb_x_ext_dst_flow = SADB_X_EXT_DST_FLOW,
#undef SADB_X_EXT_DST_FLOW
#define SADB_X_EXT_DST_FLOW sadb_x_ext_dst_flow
#endif

#ifdef SADB_X_EXT_PROTOCOL
	sadb_x_ext_protocol = SADB_X_EXT_PROTOCOL,
#undef SADB_X_EXT_PROTOCOL
#define SADB_X_EXT_PROTOCOL sadb_x_ext_protocol
#endif

#ifdef SADB_X_EXT_FLOW_TYPE
	sadb_x_ext_flow_type = SADB_X_EXT_FLOW_TYPE,
#undef SADB_X_EXT_FLOW_TYPE
#define SADB_X_EXT_FLOW_TYPE sadb_x_ext_flow_type
#endif

#ifdef SADB_X_EXT_REPLAY /* OpenBSD */
	sadb_x_ext_replay = SADB_X_EXT_REPLAY,
#undef SADB_X_EXT_REPLAY
#define SADB_X_EXT_REPLAY sadb_x_ext_replay
#endif

#ifdef SADB_X_EXT_UDPENCAP
	sadb_x_ext_udpencap = SADB_X_EXT_UDPENCAP,
#undef SADB_X_EXT_UDPENCAP
#define SADB_X_EXT_UDPENCAP sadb_x_ext_udpencap
#endif

};

enum sadb_sastate {

	sadb_sastate_dead = SADB_SASTATE_DEAD,
#undef SADB_SASTATE_DEAD
#define SADB_SASTATE_DEAD sadb_sastate_dead

	sadb_sastate_dying = SADB_SASTATE_DYING,
#undef SADB_SASTATE_DYING
#define SADB_SASTATE_DYING sadb_sastate_dying

	sadb_sastate_larval = SADB_SASTATE_LARVAL,
#undef SADB_SASTATE_LARVAL
#define SADB_SASTATE_LARVAL sadb_sastate_larval

	sadb_sastate_mature = SADB_SASTATE_MATURE,
#undef SADB_SASTATE_MATURE
#define SADB_SASTATE_MATURE sadb_sastate_mature

};

#if 0	/* bit mask; not really an enum */
enum sadb_saflags {
	sadb_saflags_pfs = SADB_SAFLAGS_PFS,
#ifdef SADB_X_SAFLAGS_TUNNEL
	sadb_x_saflags_tunnel = SADB_X_SAFLAGS_TUNNEL,
#endif
#ifdef SADB_X_SAFLAGS_CHAINDEL
	sadb_x_saflags_chaindel = SADB_X_SAFLAGS_CHAINDEL,
#endif
#ifdef SADB_X_SAFLAGS_ESN
	sadb_x_saflags_esn = SADB_X_SAFLAGS_ESN,
#endif
#ifdef SADB_X_SAFLAGS_UDPENCAP
	sadb_x_saflags_udpencap = SADB_X_SAFLAGS_UDPENCAP,
#endif
};
#endif

#ifdef SADB_X_EXT_POLICY

enum ipsec_policy {

	ipsec_policy_discard = IPSEC_POLICY_DISCARD,
#undef IPSEC_POLICY_DISCARD
#define IPSEC_POLICY_DISCARD ipsec_policy_discard

	ipsec_policy_ipsec = IPSEC_POLICY_IPSEC,
#undef IPSEC_POLICY_IPSEC
#define IPSEC_POLICY_IPSEC ipsec_policy_ipsec

	ipsec_policy_none = IPSEC_POLICY_NONE,
#undef IPSEC_POLICY_NONE
#define IPSEC_POLICY_NONE ipsec_policy_none

};

#endif

#ifdef SADB_X_EXT_POLICY

enum ipsec_dir {

	ipsec_dir_inbound = IPSEC_DIR_INBOUND,
#undef IPSEC_DIR_INBOUND
#define IPSEC_DIR_INBOUND ipsec_dir_inbound

	ipsec_dir_outbound = IPSEC_DIR_OUTBOUND,
#undef IPSEC_DIR_OUTBOUND
#define IPSEC_DIR_OUTBOUND ipsec_dir_outbound

};

#endif

#ifdef SADB_X_EXT_POLICY

enum ipsec_mode {

#ifdef IPSEC_MODE_ANY
	ipsec_mode_any = IPSEC_MODE_ANY,
#undef IPSEC_MODE_ANY
#else
	ipsec_mode_any = 0,
#endif
#define IPSEC_MODE_ANY ipsec_mode_any

	ipsec_mode_transport = IPSEC_MODE_TRANSPORT,
#undef IPSEC_MODE_TRANSPORT
#define IPSEC_MODE_TRANSPORT ipsec_mode_transport

	ipsec_mode_tunnel = IPSEC_MODE_TUNNEL,
#undef IPSEC_MODE_TUNNEL
#define IPSEC_MODE_TUNNEL ipsec_mode_tunnel

};

#endif

enum ipsec_proto {

	ipsec_proto_ah = IPPROTO_AH,
#undef IPSEC_PROTO_AH
#define IPSEC_PROTO_AH ipsec_proto_ah

	ipsec_proto_esp = IPPROTO_ESP,
#undef IPSEC_PROTO_ESP
#define IPSEC_PROTO_ESP ipsec_proto_esp

	ipsec_proto_ipip = IPPROTO_IPIP,
#undef IPSEC_PROTO_IPIP
#define IPSEC_PROTO_IPIP ipsec_proto_ipip

	ipsec_proto_ipv6 = IPPROTO_IPV6,
#undef IPSEC_PROTO_IPV6
#define IPSEC_PROTO_IPV6 ipsec_proto_ipv6

#ifdef IPSEC_PROTO_ANY
	ipsec_proto_any = IPSEC_PROTO_ANY, /* 255, aka IPSEC_ULPROTO_ANY */
#undef IPSEC_PROTO_ANY
#else
	ipsec_proto_any = 255,
#endif
#define IPSEC_PROTO_ANY ipsec_proto_any

#ifdef IPPROTO_IPCOMP
	ipsec_proto_ipcomp = IPPROTO_IPCOMP,
#undef IPSEC_PROTO_IPCOMP
#define IPSEC_PROTO_IPCOMP ipsec_proto_ipcomp
#endif

#ifdef IPPROTO_COMP
	ipsec_proto_ipcomp = IPPROTO_COMP,
#undef IPSEC_PROTO_IPCOMP
#define IPSEC_PROTO_IPCOMP ipsec_proto_ipcomp
#endif

};

enum ipsec_level {

	ipsec_level_default = IPSEC_LEVEL_DEFAULT,
#undef IPSEC_LEVEL_DEFAULT
#define IPSEC_LEVEL_DEFAULT ipsec_level_default

	ipsec_level_use = IPSEC_LEVEL_USE,
#undef IPSEC_LEVEL_USE
#define IPSEC_LEVEL_USE ipsec_level_use

	ipsec_level_require = IPSEC_LEVEL_REQUIRE,
#undef IPSEC_LEVEL_REQUIRE
#define IPSEC_LEVEL_REQUIRE ipsec_level_require

	ipsec_level_unique = IPSEC_LEVEL_UNIQUE,
#undef IPSEC_LEVEL_UNIQUE
#define IPSEC_LEVEL_UNIQUE ipsec_level_unique

};

#ifdef SADB_X_EXT_FLOW_TYPE

enum sadb_x_flow_type {

	sadb_x_flow_type_use = SADB_X_FLOW_TYPE_USE,
#undef SADB_X_FLOW_TYPE_USE
#define SADB_X_FLOW_TYPE_USE sadb_x_flow_type_use

	sadb_x_flow_type_acquire = SADB_X_FLOW_TYPE_ACQUIRE,
#undef SADB_X_FLOW_TYPE_ACQUIRE
#define SADB_X_FLOW_TYPE_ACQUIRE sadb_x_flow_type_acquire

	sadb_x_flow_type_require = SADB_X_FLOW_TYPE_REQUIRE,
#undef SADB_X_FLOW_TYPE_REQUIRE
#define SADB_X_FLOW_TYPE_REQUIRE sadb_x_flow_type_require

	sadb_x_flow_type_bypass = SADB_X_FLOW_TYPE_BYPASS,
#undef SADB_X_FLOW_TYPE_BYPASS
#define SADB_X_FLOW_TYPE_BYPASS sadb_x_flow_type_bypass

	sadb_x_flow_type_deny = SADB_X_FLOW_TYPE_DENY,
#undef SADB_X_FLOW_TYPE_DENY
#define SADB_X_FLOW_TYPE_DENY sadb_x_flow_type_deny

	sadb_x_flow_type_dontacq = SADB_X_FLOW_TYPE_DONTACQ,
#undef SADB_X_FLOW_TYPE_DONTACQ
#define SADB_X_FLOW_TYPE_DONTACQ sadb_x_flow_type_dontacq

};

#endif

extern const struct sparse_names sadb_aalg_names;
extern const struct sparse_names sadb_calg_names;
extern const struct sparse_names sadb_ealg_names;
extern const struct sparse_names sadb_exttype_names;
extern const struct sparse_names sadb_flow_type_names;
extern const struct sparse_names sadb_identtype_names;
extern const struct sparse_names sadb_lifetime_names;
extern const struct sparse_names sadb_policyflag_names;
extern const struct sparse_names sadb_saflag_names;
extern const struct sparse_names sadb_sastate_names;
extern const struct sparse_names sadb_satype_names;
extern const struct sparse_names sadb_type_names;
extern const struct sparse_sparse_names sadb_protocol_proto_names;
extern const struct sparse_names sadb_protocol_direction_names;
extern const struct sparse_names sadb_x_flow_type_names;

extern const struct sparse_sparse_names sadb_alg_names;
extern const struct sparse_sparse_names sadb_satype_ealg_names;
extern const struct sparse_sparse_names sadb_satype_aalg_names;

extern const struct sparse_names ipsec_proto_names;
extern const struct sparse_names ipsec_policy_names;
extern const struct sparse_names ipsec_dir_names;
extern const struct sparse_names ipsec_mode_names;
extern const struct sparse_names ipsec_level_names;

void llog_sadb(struct verbose verbose, shunk_t msg);

void llog_sadb_alg(struct verbose verbose, const struct sadb_msg *b, enum sadb_exttype, const struct sadb_alg *m);
void llog_sadb_sa(struct verbose verbose, const struct sadb_msg *b, enum sadb_satype, const struct sadb_sa *m);

void llog_sadb_address(struct verbose verbose, const struct sadb_msg *b, const struct sadb_address *m);
void llog_sadb_comb(struct verbose verbose, const struct sadb_msg *b, const struct sadb_comb *m);
void llog_sadb_ext(struct verbose verbose, const struct sadb_msg *b, const struct sadb_ext *m);
void llog_sadb_ident(struct verbose verbose, const struct sadb_msg *b, const struct sadb_ident *m);
void llog_sadb_key(struct verbose verbose, const struct sadb_msg *b, const struct sadb_key *m);
void llog_sadb_lifetime(struct verbose verbose, const struct sadb_msg *b, const struct sadb_lifetime *m);
void llog_sadb_msg(struct verbose verbose, const struct sadb_msg *b, const struct sadb_msg *m);
void llog_sadb_prop(struct verbose verbose, const struct sadb_msg *b, const struct sadb_prop *m);
void llog_sadb_sens(struct verbose verbose, const struct sadb_msg *b, const struct sadb_sens *m);
void llog_sadb_spirange(struct verbose verbose, const struct sadb_msg *b, const struct sadb_spirange *m);
void llog_sadb_supported(struct verbose verbose, const struct sadb_msg *b, const struct sadb_supported *m);
#ifdef SADB_X_EXT_POLICY /* nexted within sadb_x_policy */
void llog_sadb_x_ipsecrequest(struct verbose verbose, const struct sadb_msg *b, const struct sadb_x_ipsecrequest *m);
#endif
#ifdef SADB_X_EXT_NAT_T_FRAG
void llog_sadb_x_nat_t_frag(struct verbose verbose, const struct sadb_msg *b, const struct sadb_x_nat_t_frag *m);
#endif
#ifdef SADB_X_EXT_NAT_T_PORT
void llog_sadb_x_nat_t_port(struct verbose verbose, const struct sadb_msg *b, const struct sadb_x_nat_t_port *m);
#endif
#ifdef SADB_X_EXT_NAT_T_TYPE
void llog_sadb_x_nat_t_type(struct verbose verbose, const struct sadb_msg *b, const struct sadb_x_nat_t_type *m);
#endif
#ifdef SADB_X_EXT_POLICY
void llog_sadb_x_policy(struct verbose verbose, const struct sadb_msg *b, const struct sadb_x_policy *m);
#endif
#ifdef SADB_X_EXT_SA2
void llog_sadb_x_sa2(struct verbose verbose, const struct sadb_msg *b, const struct sadb_x_sa2 *m);
#endif
#ifdef SADB_X_EXT_SA_REPLAY
void llog_sadb_x_sa_replay(struct verbose verbose, const struct sadb_msg *b, const struct sadb_x_sa_replay *m);
#endif
#ifdef SADB_X_EXT_COUNTER
void llog_sadb_x_counter(struct verbose verbose, const struct sadb_msg *b, const struct sadb_x_counter *m);
#endif
#ifdef SADB_X_EXT_PROTOCOL
void llog_sadb_protocol(struct verbose verbose, const struct sadb_msg *b, const struct sadb_protocol *m);
#endif
#ifdef SADB_X_EXT_REPLAY /* OpenBSD */
void llog_sadb_x_replay(struct verbose verbose, const struct sadb_msg *b, const struct sadb_x_replay *m);
#endif
#ifdef SADB_X_EXT_UDPENCAP
void llog_sadb_x_udpencap(struct verbose verbose, const struct sadb_msg *b, const struct sadb_x_udpencap *m);
#endif

bool get_sadb_sockaddr_address_port(shunk_t *cursor,
				    ip_address *address,
				    ip_port *port,
				    struct verbose verbose);
#define GET_SADB(TYPE)							\
	const struct TYPE *get_##TYPE(shunk_t *cursor, shunk_t *type_cursor, \
				      struct verbose verbose);

GET_SADB(sadb_address);
GET_SADB(sadb_comb);
GET_SADB(sadb_ext);
GET_SADB(sadb_ident);
GET_SADB(sadb_key);
GET_SADB(sadb_lifetime);
GET_SADB(sadb_msg);
GET_SADB(sadb_prop);
GET_SADB(sadb_proposal);
GET_SADB(sadb_sa);
GET_SADB(sadb_sens);
GET_SADB(sadb_spirange);
GET_SADB(sadb_supported);
#ifdef SADB_X_EXT_POLICY
GET_SADB(sadb_x_ipsecrequest);
#endif
#ifdef SADB_X_EXT_POLICY
GET_SADB(sadb_x_policy);
#endif
GET_SADB(sadb_x_nat_t_type);
#ifdef SADB_X_EXT_SA2
GET_SADB(sadb_x_sa2);
#endif
#ifdef SADB_X_EXT_SA_REPLAY
GET_SADB(sadb_x_sa_replay);
#endif
#ifdef SADB_X_EXT_COUNTER
GET_SADB(sadb_x_counter);
#endif
#ifdef SADB_X_EXT_PROTOCOL
GET_SADB(sadb_protocol);
#endif
#ifdef SADB_X_EXT_REPLAY /* OpenBSD */
GET_SADB(sadb_x_replay);
#endif
#ifdef SADB_X_EXT_UDPENCAP
GET_SADB(sadb_x_udpencap);
#endif

#undef GET_SADB

#endif
