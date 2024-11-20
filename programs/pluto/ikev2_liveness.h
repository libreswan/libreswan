/* IKEv2 LIVENESS probe
 *
 * Copyright (C) 2020 Andrew Cagney
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

#ifndef IKEv2_LIVENESS_H
#define IKEv2_LIVENESS_H

struct state;
struct ike_sa;
struct child_sa;

void event_v2_liveness(struct state *st);
void submit_v2_liveness_exchange(struct ike_sa *ike, so_serial_t);

#endif
