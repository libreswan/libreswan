/* IKEv2 KE routes, for libreswan.
 *
 * Copyright (C) 2025 Andrew Cagney
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

#ifndef IKEV2_KE_H
#define IKEV2_KE_H

#include <stdbool.h>

#include "shunk.h"

struct kem_desc;
struct pbs_out;

bool emit_v2KE(shunk_t ke, const struct kem_desc *kem, struct pbs_out *outs);

#endif
