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
struct host_pair {
	struct {
		ip_address addr;
		uint16_t host_port;            /* IKE port */
		bool host_port_specific;        /* if above is interesting */
	} me, him;
	struct connection *connections;         /* connections with this pair */
	struct pending *pending;                /* awaiting Keying Channel */
	struct host_pair *next;
};

extern struct host_pair *host_pairs;

extern void connect_to_host_pair(struct connection *c);

extern struct connection *find_host_pair_connections(const ip_address *myaddr,
						     uint16_t myport,
						     const ip_address *hisaddr,
						     uint16_t hisport);

extern struct host_pair *find_host_pair(const ip_address *myaddr,
					uint16_t myport,
					const ip_address *hisaddr,
					uint16_t hisport);

#define LIST_RM(ENEXT, E, EHEAD, EXPECTED)				\
	{								\
		bool found_ = false;					\
		for (typeof(*(EHEAD)) **ep_ = &(EHEAD); *ep_ != NULL; ep_ = &(*ep_)->ENEXT) { \
			if (*ep_ == (E)) {				\
				*ep_ = (E)->ENEXT;			\
				found_ = true;				\
				break;					\
			}						\
		}							\
		/* we must not come up empty-handed? */			\
		pexpect(found_ || !(EXPECTED));				\
	}

void delete_oriented_hp(struct connection *c);

extern struct connection *connections;
