/* extract a connection from a whack message, for libreswan
 *
 * Copyright (C) 1998-2001,2010-2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@cyclops.xelerance.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 Kim Heino <b@bbbs.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2019-2022 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#ifndef EXTRACT_H
#define EXTRACT_H

#include "diag.h"
#include "verbose.h"
#include "ip_address.h"
#include "end.h"
#include "defaultroute.h"

struct whack_message;
struct connection;
struct config;
struct extracted_host_addrs;

diag_t extract_connection(const struct whack_message *wm,
			  const struct extracted_host_addrs *extracted_host_addrs,
			  struct connection *c,
			  struct config *config,
			  struct verbose verbose);

void resolve_connection(struct connection *c, struct verbose verbose);

struct extracted_addr {
	enum keyword_host type;
	const char *key;
	const char *value;	/* points into whack_message! */
	ip_address addr;
};

struct extracted_host_addrs {
	struct extracted_addrs {
		struct extracted_addr host;
		struct extracted_addr nexthop;
		const char *leftright;
	} end[END_ROOF];
	struct resolve_end resolve[END_ROOF];
	bool resolved;
	const struct ip_info *afi;
};

diag_t extract_host_addrs(const struct whack_message *wm,
			  struct extracted_host_addrs *config,
			  struct verbose verbose);

struct extracted_host_addrs extracted_host_addrs_from_host_configs(const struct config *config);

#endif
