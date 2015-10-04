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
 */
struct host_pair {
	struct {
		ip_address addr;
		u_int16_t host_port;            /* IKE port */
		bool host_port_specific;        /* if above is interesting */
	} me, him;
	struct connection *connections;         /* connections with this pair */
	struct pending *pending;                /* awaiting Keying Channel */
	struct host_pair *next;
};

extern struct host_pair *host_pairs;

extern void connect_to_host_pair(struct connection *c);
extern struct connection *find_host_pair_connections(const ip_address *myaddr,
						     u_int16_t myport,
						     const ip_address *hisaddr,
						     u_int16_t hisport);

extern struct host_pair *find_host_pair(const ip_address *myaddr,
					u_int16_t myport,
					const ip_address *hisaddr,
					u_int16_t hisport);

#define list_rm(etype, enext, e, ehead) { \
		etype **ep; \
		for (ep = &(ehead); *ep != (e); ep = &(*ep)->enext) \
			passert(*ep != NULL); /* we must not come up empty-handed */ \
		*ep = (e)->enext; \
	}

extern void remove_host_pair(struct host_pair *hp);

extern struct connection *connections;
