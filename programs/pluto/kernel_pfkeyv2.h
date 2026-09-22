/* OpenBSD PFKEYv2 declarations, for libreswan
 *
 * Copyright (C) 2026 Amrinder Singh <officialamrindersinghh@gmail.com>
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

#ifndef KERNEL_PFKEYV2_H
#define KERNEL_PFKEYV2_H

#include <stdbool.h>

#include "verbose.h"
#include "shunk.h"
#include "chunk.h"
#include "ip_port.h"
#include "ip_address.h"

struct ip_info;
struct logger;
struct sadb_msg;
struct kernel_acquire;
enum sadb_type;
enum sadb_satype;

/*
 * This has both a KAME and OpenBSD implementation.
 */
bool pfkeyv2_poke_ipsec_policy_hole(int fd, const struct ip_info *afi, struct logger *logger);

#endif
