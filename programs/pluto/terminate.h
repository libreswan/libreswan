/* terminate connection, for libreswan
 *
 * Copyright (C) 2023 Andrew Cagney
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

#ifndef TERMINATE_H
#define TERMINATE_H

#include <stdbool.h>

#include "where.h"

struct connection;
struct logger;

void terminate_connections(struct connection **c, struct logger *logger, where_t where);
void terminate_connections_by_name_or_alias(const char *name, bool quiet, struct logger *logger);

#endif
