/* information about connections between hosts
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include "list_entry.h"

struct host_pair {
	const char *magic;
	ip_endpoint local;
	ip_endpoint remote;
	struct connection *connections;         /* connections with this pair */
	struct pending *pending;                /* awaiting Keying Channel */
	struct list_entry host_pair_entry;
};

/* export to pending.c */
extern void host_pair_enqueue_pending(const struct connection *c,
				      struct pending *p,
				      struct pending **pnext);
struct pending **host_pair_first_pending(const struct connection *c);

extern void connect_to_host_pair(struct connection *c);

extern struct connection *find_host_pair_connections(const ip_endpoint *local,
						     const ip_endpoint *remote);

extern struct host_pair *find_host_pair(const ip_endpoint *local,
					const ip_endpoint *remote);

void delete_oriented_hp(struct connection *c);
void host_pair_remove_connection(struct connection *c, bool connection_valid);

extern struct connection *connections;

extern void update_host_pairs(struct connection *c);

extern void release_dead_interfaces(struct fd *whackfd);
extern void check_orientations(void);

void init_host_pair(void);

struct connection *find_v2_host_pair_connection(struct msg_digest *md,
						lset_t *policy, bool *send_reject_response);

struct connection *find_next_host_connection(struct connection *c,
					     lset_t req_policy, lset_t policy_exact_mask);

struct connection *find_host_connection(const ip_endpoint *local,
					const ip_endpoint *remote,
					lset_t req_policy,
					lset_t policy_exact_mask);
