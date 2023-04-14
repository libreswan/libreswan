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

#ifndef INITIATE_H
#define INITIATE_H

#include "ip_packet.h"

struct kernel_acquire;

bool initiate_connection(struct connection *c, const char *remote_host,
			 bool background, bool log_failure, struct logger *logger);

void ipsecdoi_initiate(struct connection *c,
		       lset_t policy,
		       so_serial_t replacing,
		       const threadtime_t *inception,
		       shunk_t sec_label,
		       bool background, struct logger *logger);

extern void initiate_ondemand(const struct kernel_acquire *b);

#endif
