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

#ifndef SHUNT_H
#define SHUNT_H

/*
 * Kernel policy to install for a shunt.
 */
enum shunt_policy {
	SHUNT_UNSET,
	SHUNT_IPSEC,	/* only valid with KIND IPSEC */
	SHUNT_NONE,
	SHUNT_HOLD,	/* during negotiation, don't change */
	SHUNT_TRAP,
	SHUNT_PASS,
	SHUNT_DROP,
#define SHUNT_POLICY_ROOF (SHUNT_DROP+1)
};

extern const struct enum_names shunt_policy_names;		/* SHUNT_... */

/*
 * Kinds of shunt.
 *
 * stored as a shunt[] table, but for convenience, and legacy also
 * accessible using macros below.
 */

enum shunt_kind {
#define SHUNT_KIND_FLOOR 0
	SHUNT_KIND_NONE,
	SHUNT_KIND_NEVER_NEGOTIATE,
	SHUNT_KIND_ONDEMAND,		/* always SHUNT_TRAP */
	SHUNT_KIND_NEGOTIATION,
	SHUNT_KIND_IPSEC,		/* always SHUNT_IPSEC */
	SHUNT_KIND_FAILURE,
	SHUNT_KIND_BLOCK,      		/* always SHUNT_DROP */
#define never_negotiate_shunt shunt[SHUNT_KIND_NEVER_NEGOTIATE]
#define negotiation_shunt     shunt[SHUNT_KIND_NEGOTIATION]	/* during */
#define failure_shunt         shunt[SHUNT_KIND_FAILURE]		/* after */
#define SHUNT_KIND_ROOF (SHUNT_KIND_BLOCK+1)
};

extern const struct enum_names shunt_kind_names;
extern const struct sparse_names failure_shunt_names;
extern const struct sparse_names negotiation_shunt_names;
extern const struct sparse_names never_negotiate_shunt_names;

#endif
