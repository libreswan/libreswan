/* ipsec whack --addkey et.al., for libreswan
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

#ifndef WHACK_PUBKEY_H
#define WHACK_PUBKEY_H

#include "where.h"
#include "chunk.h"
#include "err.h"

struct whack_message;
struct show;
struct logger;
enum ipseckey_algorithm_type;

err_t whack_pubkey_to_chunk(enum ipseckey_algorithm_type algorithm_type,
			    const char *pubkey_in, chunk_t *pubkey_out);

void key_add_request(const struct whack_message *msg, struct logger *logger);

#endif
