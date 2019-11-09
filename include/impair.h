/* impair operation, for libreswan
 *
 * Copyright (C) 2018-2019 Andrew Cagney
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

#ifndef IMPAIR_H
#define IMPAIR_H

#include <stdbool.h>

#include "lswcdefs.h"

/*
 * Meddle with the contents of a payload.
 */

enum send_impairment {
	SEND_NORMAL = 0,
	SEND_OMIT,
	SEND_EMPTY,
	SEND_DUPLICATE,
	SEND_ROOF, /* >= ROOF -> <number> */
};

/*
 * Meddle with a specific exchange.
 */

enum exchange_impairment {
	NO_EXCHANGE = 0,
	NOTIFICATION_EXCHANGE,
	QUICK_EXCHANGE,
	XAUTH_EXCHANGE,
	DELETE_EXCHANGE,
};

/*
 * add more here
 */
#if 0
enum xxx_impair ...;
#endif

/*
 * What can be impaired.
 *
 * See impair.c for documentation.
 *
 * XXX: make this a structure so it can be copied?
 */

extern bool impair_revival;
extern bool impair_emitting;

extern enum send_impairment impair_ke_payload;
extern enum send_impairment impair_ike_key_length_attribute;
extern enum send_impairment impair_child_key_length_attribute;

extern unsigned impair_log_rate_limit;

extern enum send_impairment impair_v1_hash_payload;
extern enum exchange_impairment impair_v1_hash_exchange;
extern bool impair_v1_hash_check;

/*
 * What whack sends across the wire for a impair.
 */

struct whack_impair {
	unsigned what;
	unsigned how;
};

bool parse_impair(const char *optarg, struct whack_impair *whack_impair, bool enable);

void process_impair(const struct whack_impair *whack_impair);

void help_impair(const char *prefix);

void lswlog_impairments(struct lswlog *buf, const char *prefix, const char *sep);

#endif
