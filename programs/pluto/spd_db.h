/* Connection Database, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney <cagney@gnu.org>
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

#ifndef SPD_DB_H
#define SPD_DB_H

#include "where.h"

struct spd;
struct logger;

/* spd route */

void spd_db_init(struct logger *logger);
void spd_db_check(const struct logger *logger, where_t where);

void spd_db_init_spd(struct spd *sr);
void spd_db_check_spd(struct spd *sr, struct logger *logger, where_t where);

void spd_db_add(struct spd *sr);
void spd_db_del(struct spd *sr);

#if 0
void spd_db_rehash_remote_client(struct spd *sr); /* see connections.h */
#endif

#endif
