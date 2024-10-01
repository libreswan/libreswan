/* invoke updown, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2010 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2016-2022 Andrew Cagney
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#ifndef UPDOWN_H
#define UPDOWN_H

struct state;
struct connection;
struct spd;
struct spds;
struct logger;
struct child_sa;
struct spd_owner;

/* many bits reach in to use this, but maybe shouldn't */
enum updown {
	UPDOWN_PREPARE,
	UPDOWN_ROUTE,
	UPDOWN_UNROUTE,
	UPDOWN_UP,
	UPDOWN_DOWN,
#ifdef HAVE_NM
	UPDOWN_DISCONNECT_NM,
#endif
};

bool do_updown(enum updown updown_verb,
	       const struct connection *c, const struct spd *sr,
	       struct child_sa *child, struct logger *logger);

void do_updown_child(enum updown updown_verb, struct child_sa *child);

/*
 * Value of some environment variables passed down to updown.
 */
struct updown_env {
	/*
	 * Yes when updown is being run because mobike is suspending
	 * the the connection.  This lets the script know that the
	 * sourceip should be deleted.
	*/
	bool pluto_mobike_event;
};

void do_updown_unroute_spd(const struct spd *spd, const struct spd_owner *owner,
			   struct child_sa *child, struct logger *logger,
			   struct updown_env);

#endif
