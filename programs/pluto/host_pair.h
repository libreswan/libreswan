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

#ifndef HOST_PAIR_H
#define HOST_PAIR_H

#include "ip_endpoint.h"

#include "id.h"
#include "list_entry.h"

struct msg_digest;
struct connection;
struct pending;

struct host_pair {
	const char *magic;
	/* host-pair doesn't look at ports */
	ip_address local;
	ip_address remote;
	struct connection *connections;         /* connections with this pair */
	struct pending *pending;                /* awaiting Keying Channel */
	struct list_entry host_pair_entry;
};

/* export to pending.c */
extern void host_pair_enqueue_pending(const struct connection *c,
				      struct pending *p);
struct pending **host_pair_first_pending(const struct connection *c);

extern void connect_to_host_pair(struct connection *c);

extern struct host_pair *find_host_pair(const ip_address local, const ip_address remote);

void delete_oriented_hp(struct connection *c);
void host_pair_remove_connection(struct connection *c, bool connection_valid);

extern struct connection *connections;

extern void update_host_pairs(struct connection *c);

extern void release_dead_interfaces(struct logger *logger);
extern void check_orientations(void);

void init_host_pair(void);

struct connection *next_host_pair_connection(const ip_address local,
					     const ip_address remote,
					     struct connection **next,
					     bool first,
					     where_t where);
#define FOR_EACH_HOST_PAIR_CONNECTION(LOCAL, REMOTE, CONNECTION)	\
	for (struct connection *next_ = NULL,				\
		     *CONNECTION = next_host_pair_connection(LOCAL, REMOTE, &next_, true, HERE); \
	     CONNECTION != NULL;					\
	     CONNECTION = next_host_pair_connection(LOCAL, REMOTE, &next_, false, HERE))

#endif
