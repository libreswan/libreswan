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

struct hash_desc;

extern deltatime_t nat_keepalive_period;

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
bool nat_traversal_detected(struct state *st);

void init_nat_traversal_timer(deltatime_t keep_alive_period, struct logger *logger);

/**
 * IKE port floating
 */
bool nat_traversal_port_float(struct state *st, struct msg_digest *md,
			      bool in);

/* Update settings based on detection */
void detect_nat_common(struct ike_sa *ike,
		       const ip_endpoint sender,
		       bool found_me, bool found_peer);

struct crypt_mac natd_hash(const struct hash_desc *hasher,
			   const ike_spis_t *spis,
			   const ip_endpoint endpoint,
			   struct logger *logger);

/**
 * NAT-keep_alive
 */
void schedule_v2_nat_keepalive(struct ike_sa *ike, where_t where);
void schedule_v1_nat_keepalive(struct state *st);
void event_v1_nat_keepalive(struct state *st);
void event_v2_nat_keepalive(struct ike_sa *ike);

#endif /* _NAT_TRAVERSAL_H_ */
