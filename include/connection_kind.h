/* manifest constants
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2019-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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
 *
 */

#ifndef CONNECTION_KIND_H
#define CONNECTION_KIND_H

/*
 * Kind of struct connection
 *
 * Ordered (mostly) by concreteness.  Order is exploited (for
 * instance, when listing connections the kind is used as the second
 * sort key after name but before instance number which means that
 * templates are grouped, followed by their instances, weird).
 */

enum connection_kind {
	CK_INVALID = 0,		/* better name? */
	CK_GROUP,       	/* policy group: instantiates to CK_TEMPLATE+POLICY_GROUPINSTANCE */
	CK_TEMPLATE,    	/* abstract connection, with wildcard */
	CK_PERMANENT,   	/* normal connection */
	CK_INSTANCE,    	/* instance of template, created for a
				 * particular attempt */
	CK_LABELED_TEMPLATE,	/* labels are in their own little world */
	CK_LABELED_PARENT,
	CK_LABELED_CHILD,
#define CONNECTION_KIND_ROOF (CK_LABELED_CHILD+1)
};

extern const struct enum_names connection_kind_names;

#endif
