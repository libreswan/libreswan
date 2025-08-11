/* Root Certificate Cache, for libreswan
 *
 * Copyright (C) 2019,2022 Andrew Cagney <cagney@gnu.org>
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
#ifndef ROOT_CERTS_H
#define ROOT_CERTS_H

#include "lswnss.h"
#include "refcnt.h"
#include "where.h"

void init_root_certs(const struct logger *logger);
void free_root_certs(struct logger *logger);

struct root_certs {
	refcnt_t refcnt;
	const struct logger *logger; /* makes refcnt easier */
	CERTCertList *trustcl;
};

struct root_certs *root_certs_addref_where(where_t where, struct logger *owner);
#define root_certs_addref(LOGGER) root_certs_addref_where(HERE, LOGGER)

void root_certs_delref_where(struct root_certs **,
			     struct logger *logger,
			     where_t where);
#define root_certs_delref(ROOT_CERTS, LOGGER) root_certs_delref_where(ROOT_CERTS, LOGGER, HERE)

bool root_certs_empty(const struct root_certs *);

#endif
