/*
 * Retransmits, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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

#ifndef RETRANSMIT_H
#define RETRANSMIT_H

struct state;

/*
 * Treat as opaque!
 */

typedef struct {
	deltatime_t delay;
	deltatime_t timeout;
	monotime_t start;
	deltatime_t delays;
	unsigned long nr_retransmits;
	unsigned long nr_duplicate_replies;
	unsigned long limit;
	so_serial_t who_for;
} retransmit_t;

unsigned long retransmit_count(struct state *st);

bool count_duplicate(struct state *st, unsigned long limit);

void start_retransmits(struct state *st);

void clear_retransmits(struct state *st);

enum retransmit_action {
	RETRANSMIT_TIMEOUT = 1,
	RETRANSMIT_NO,
	RETRANSMIT_YES,
	/* due to impair */
	TIMEOUT_ON_RETRANSMIT,
};

enum retransmit_action retransmit(struct state *st);


size_t lswlog_retransmit_prefix(struct jambuf *buf, struct state *st);

#endif
