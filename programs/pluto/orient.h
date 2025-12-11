/* initiating connections, for libreswan
 *
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

#ifndef ORIENT_H
#define ORIENT_H

#include <stdbool.h>

struct connection;

bool oriented(const struct connection *c);
/*
 * Caller must hold a local reference, or be able to guarantee that
 * there is a floating reference.
 */
bool orient(struct connection *c, const struct logger *logger);
void disorient(struct connection *c);
void check_orientations(struct logger *logger);

void jam_orientation(struct jambuf *buf, struct connection *c, bool oriented_details);

#endif
