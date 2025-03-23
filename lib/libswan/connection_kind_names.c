/*
 * tables of names for values defined in constants.h
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2017 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#include "connection_kind.h"
#include "enum_names.h"
#include "lswcdefs.h"		/* for ARRAY_REF */

/* kind of struct connection */
static const char *const connection_kind_name[] = {
#define S(E) [E - CK_INVALID] = #E
	S(CK_INVALID),
	S(CK_GROUP),		/* policy group: instantiates to template */
	S(CK_TEMPLATE),		/* abstract connection, with wildcard */
	S(CK_PERMANENT),	/* normal connection */
	S(CK_INSTANCE),		/* instance of template */
	S(CK_LABELED_TEMPLATE),
	S(CK_LABELED_PARENT),
	S(CK_LABELED_CHILD),
#undef S
};

const struct enum_names connection_kind_names = {
	CK_INVALID,
	CONNECTION_KIND_ROOF - 1,
	ARRAY_REF(connection_kind_name),
	"CK_", /* prefix */
	NULL
};
