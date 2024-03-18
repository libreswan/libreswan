/* Libreswan Ikev1 VendorID
 *
 * Copyright (C) 2022 Andrew Cagney
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

#ifndef IKEV1_VENDORID_H
#define IKEV1_VENDORID_H

#include "shunk.h"

#include "demux.h"

struct logger;
struct connection;

void handle_v1_vendorid(struct msg_digest *md, shunk_t vid,
			struct logger *logger);

bool out_v1VID(struct pbs_out *outs, unsigned int vid);

bool out_v1VID_set(struct pbs_out *outs, const struct connection *c);

#endif
