/* Libreswan IKEv2 VendorID
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

#ifndef IKEV2_VENDORID_H
#define IKEV2_VENDORID_H

#include "shunk.h"

#include "demux.h"

struct logger;

void handle_v2_vendorid(shunk_t vid, struct logger *logger);

bool emit_v2V(struct pbs_out *outs, const char *vid);
bool emit_v2VID(struct pbs_out *outs, enum known_vendorid);

bool vid_is_oppo(const char *vid, size_t len);

#endif
