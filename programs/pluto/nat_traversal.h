/* Libreswan NAT-Traversal
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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

#ifndef _NAT_TRAVERSAL_H_
#define _NAT_TRAVERSAL_H_

#include "demux.h"
#include "lswalloc.h"
#include "state.h"
#include "ike_spi.h"

/*
 *  NAT-Traversal defines for nat_traversal type from nat_traversal.h
 */

/**
 * NAT-Traversal methods that need NAT-D
 */

#if 0
/* not used anymore, since this is true for all supported natt methods */
#define NAT_T_WITH_NATD \
	( LELEM(NAT_TRAVERSAL_METHOD_IETF_02_03) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_05) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_RFC) )
#endif

/**
 * NAT-Traversal methods that need NAT-OA (Original Address)
 */
#define NAT_T_WITH_NATOA \
	( LELEM(NAT_TRAVERSAL_METHOD_IETF_02_03) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_05) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_RFC) )
/**
 * NAT-Traversal methods that use NAT-KeepAlive
 */
#define NAT_T_WITH_KA \
	( LELEM(NAT_TRAVERSAL_METHOD_IETF_02_03) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_05) | \
	  LELEM(NAT_TRAVERSAL_METHOD_IETF_RFC) )

/**
 * NAT-Traversal methods that use officials values (RFC)
 */
#define NAT_T_WITH_RFC_VALUES \
	LELEM(NAT_TRAVERSAL_METHOD_IETF_RFC)

/**
 * NAT-Traversal methods that use officials values (RFC) for encapsulation
 */
#define NAT_T_WITH_ENCAPSULATION_RFC_VALUES \
	( LELEM(NAT_TRAVERSAL_METHOD_IETF_RFC) )

/**
 * NAT-Traversal detected
 */
#define NAT_T_DETECTED  ( LELEM(NATED_HOST) | LELEM(NATED_PEER) )

void init_nat_traversal(deltatime_t keep_alive_period);

extern bool nat_traversal_enabled;

/**
 * NAT-D
 */
extern bool ikev1_nat_traversal_add_natd(pb_stream *outs,
					 const struct msg_digest *md);
extern bool v2_nat_detected(struct ike_sa *ike, struct msg_digest *md);

/**
 * NAT-OA
 */
struct hidden_variables;	/* forward */

void nat_traversal_natoa_lookup(struct msg_digest *md,
				struct hidden_variables *hv);
bool nat_traversal_add_natoa(pb_stream *outs,
			     struct state *st, bool initiator);
/*
 * move initiator endpoints (src, dst) to NAT ports.
 */
bool v2_natify_initiator_endpoints(struct ike_sa *ike, where_t where);
void v1_maybe_natify_initiator_endpoints(struct state *st,
					 where_t where);

/**
 * NAT-keep_alive
 */
void nat_traversal_new_ka_event(void);
void nat_traversal_ka_event(struct fd *whackfd);

extern void ikev1_natd_init(struct state *st, struct msg_digest *md);

/**
 * Vendor ID
 */
bool nat_traversal_insert_vid(pb_stream *outs, const struct connection *c);
void set_nat_traversal(struct state *st, const struct msg_digest *md);

void nat_traversal_change_port_lookup(struct msg_digest *md, struct state *st);

/**
 * New NAT mapping
 */
void nat_traversal_new_mapping(struct ike_sa *ike,
			       const ip_endpoint *new_remote_endpoint);

/**
 * IKE port floating
 */
bool nat_traversal_port_float(struct state *st, struct msg_digest *md,
			      bool in);
/* NAT-T IKEv2 v2N */

bool ikev2_out_nat_v2n(pb_stream *outs, struct state *st,
		       const ike_spi_t *ike_resonder_spi);

bool ikev2_out_natd(const ip_endpoint *local_endpoint,
		    const ip_endpoint *remote_endpoint,
		    const ike_spis_t *ike_spis,
		    pb_stream *outs);

/**
 * Encapsulation mode macro (see demux.c)
 * ??? Wow.  Wow.
 */
#define NAT_T_ENCAPSULATION_MODE(st, nat_t_policy) ( \
		((st)->hidden_variables.st_nat_traversal & NAT_T_DETECTED) \
		? ( ((nat_t_policy) & POLICY_TUNNEL) \
		    ? ( ((st)->hidden_variables.st_nat_traversal & \
			 NAT_T_WITH_ENCAPSULATION_RFC_VALUES) \
			? ENCAPSULATION_MODE_UDP_TUNNEL_RFC \
			: ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS \
			) \
		    : ( ((st)->hidden_variables.st_nat_traversal & \
			 NAT_T_WITH_ENCAPSULATION_RFC_VALUES) \
			? ENCAPSULATION_MODE_UDP_TRANSPORT_RFC \
			: ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS \
			) \
		    ) \
		: ( ((st)->st_policy & POLICY_TUNNEL) \
		    ? ENCAPSULATION_MODE_TUNNEL \
		    : ENCAPSULATION_MODE_TRANSPORT \
		    ) \
		)

#endif /* _NAT_TRAVERSAL_H_ */

