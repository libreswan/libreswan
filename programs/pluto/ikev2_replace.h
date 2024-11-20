/* IKEv2 replace, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney <cagney@gnu.org>
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

#ifndef IKEV2_REPLACE_H
#define IKEV2_REPLACE_H

#include "monotime.h"

void event_v2_replace(struct state *st, bool detach_whack);
void event_v2_rekey(struct state *st, bool detach_whack);

void ikev2_replace(struct state *st, bool detach_whack);

#endif
