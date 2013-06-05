/* Libreswan NAT-Traversal
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 */

#ifndef _NAT_TRAVERSAL_H_
#define _NAT_TRAVERSAL_H_

#include "demux.h"

/*
 *  * NAT-Traversal defines for nat_traveral type from nat_traversal.h
 *   *
 *    */

#define NAT_TRAVERSAL_METHOD  (0xffffffff - LELEM(NAT_TRAVERSAL_NAT_BHND_ME) - \
			       LELEM(NAT_TRAVERSAL_NAT_BHND_PEER))

/**
 * NAT-Traversal methods which need NAT-D
 */

#if 0
/* not used anymore, since this is true for all supported natt methods */
#define NAT_T_WITH_NATD \
	( LELEM(NAT_TRAVERSAL_METHOD_IETF_00_01) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_02_03) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_05) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_RFC) )
#endif

/**
 * NAT-Traversal methods which need NAT-OA
 */
#define NAT_T_WITH_NATOA \
	( LELEM(NAT_TRAVERSAL_METHOD_IETF_00_01) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_02_03) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_05) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_RFC) )
/**
 * NAT-Traversal methods which use NAT-KeepAlive
 */
#define NAT_T_WITH_KA \
	( LELEM(NAT_TRAVERSAL_METHOD_IETF_00_01) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_02_03) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_05) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_RFC) )
/**
 * NAT-Traversal methods which use floating port
 */
#define NAT_T_WITH_PORT_FLOATING \
	( LELEM(NAT_TRAVERSAL_METHOD_IETF_02_03) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_05) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_RFC) )

/**
 * NAT-Traversal methods which use officials values (RFC)
 */
#define NAT_T_WITH_RFC_VALUES \
	( LELEM(NAT_TRAVERSAL_METHOD_IETF_RFC) )

/**
 * NAT-Traversal methods which use officials values (RFC) for encapsulation
 */
#define NAT_T_WITH_ENCAPSULATION_RFC_VALUES \
	( LELEM(NAT_TRAVERSAL_METHOD_IETF_RFC) )

/**
 * NAT-Traversal detected
 */
#define NAT_T_DETECTED \
	( LELEM(NAT_TRAVERSAL_NAT_BHND_ME) | \
	  LELEM(NAT_TRAVERSAL_NAT_BHND_PEER) )

void init_nat_traversal(bool activate, unsigned int keep_alive_period,
			bool spf);

extern bool nat_traversal_enabled;
extern bool nat_traversal_support_non_ike;
extern bool nat_traversal_support_port_floating;

/**
 * NAT-D
 */
void nat_traversal_natd_lookup(struct msg_digest *md);
#ifndef PB_STREAM_UNDEFINED
bool nat_traversal_add_natd(u_int8_t np, pb_stream *outs,
			    struct msg_digest *md);
#endif

/**
 * NAT-OA
 */
struct hidden_variables;
void nat_traversal_natoa_lookup(struct msg_digest *md,
				struct hidden_variables *hv);
#ifndef PB_STREAM_UNDEFINED
bool nat_traversal_add_natoa(u_int8_t np, pb_stream *outs,
			     struct state *st, bool initiator);
#endif

/**
 * NAT-keep_alive
 */
void nat_traversal_new_ka_event(void);
void nat_traversal_ka_event(void);

void nat_traversal_show_result(u_int32_t nt, u_int16_t sport);

extern int nat_traversal_espinudp_socket(int sk,
					 const char *fam,
					 u_int32_t type);

/**
 * Vendor ID
 */
#ifndef PB_STREAM_UNDEFINED
bool nat_traversal_add_vid(u_int8_t np, pb_stream *outs);
bool nat_traversal_insert_vid(u_int8_t np, pb_stream *outs, struct state *st);
#endif
u_int32_t nat_traversal_vid_to_method(unsigned short nat_t_vid);

void nat_traversal_change_port_lookup(struct msg_digest *md, struct state *st);

/**
 * New NAT mapping
 */
#ifdef __PFKEY_V2_H
void process_pfkey_nat_t_new_mapping(struct sadb_msg *,
				     struct sadb_ext *[K_SADB_EXT_MAX + 1]);
#endif

/**
 * IKE port floating
 */
bool nat_traversal_port_float(struct state *st, struct msg_digest *md,
			      bool in);

/**
 * Encapsulation mode macro (see demux.c)
 */
#define NAT_T_ENCAPSULATION_MODE(st, nat_t_policy) ( \
		((st)->hidden_variables.st_nat_traversal & NAT_T_DETECTED) \
		? ( ((nat_t_policy) & POLICY_TUNNEL) \
		    ? ( ((st)->hidden_variables.st_nat_traversal & \
			 NAT_T_WITH_ENCAPSULATION_RFC_VALUES) \
			? (ENCAPSULATION_MODE_UDP_TUNNEL_RFC) \
			: (ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS) \
			) \
		    : ( ((st)->hidden_variables.st_nat_traversal & \
			 NAT_T_WITH_ENCAPSULATION_RFC_VALUES) \
			? (ENCAPSULATION_MODE_UDP_TRANSPORT_RFC) \
			: (ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS) \
			) \
		    ) \
		: ( ((st)->st_policy & POLICY_TUNNEL) \
		    ? (ENCAPSULATION_MODE_TUNNEL) \
		    : (ENCAPSULATION_MODE_TRANSPORT) \
		    ) \
		)

#endif /* _NAT_TRAVERSAL_H_ */

