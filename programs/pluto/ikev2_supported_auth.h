/* IKEv2 SUPPORTED_AUTH_METHODS notification, for libreswan
 *
 * Copyright (C) 2026   Osema Fadhel <osemafadhel01@gmail.com>
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

#ifndef IKEV2_SUPPORTED_AUTH_H
#define IKEV2_SUPPORTED_AUTH_H

#include <stdbool.h>
#include "demux.h"

#define TWO_OCTET_ANNOUNCEMENT_LENGTH 2
#define THREE_OCTET_ANNOUNCEMENT_LENGTH 3

bool emit_v2N_SUPPORTED_AUTH_METHODS(const struct ike_sa *ike, 
                                struct pbs_out *outs);

bool process_v2N_SUPPORTED_AUTH_METHODS(struct ike_sa *ike, 
							    const struct pbs_in *notify_pbs);

#endif
