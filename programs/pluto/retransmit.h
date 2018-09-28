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
	enum event_type type;
} retransmit_t;

unsigned long retransmit_count(struct state *st);

bool count_duplicate(struct state *st, unsigned long limit);

void start_retransmits(struct state *st, enum event_type event);

void clear_retransmits(struct state *st);

void suppress_retransmits(struct state *st);

enum retransmit_status {
	RETRANSMITS_TIMED_OUT = 1,
	DELETE_ON_RETRANSMIT,
	RETRANSMIT_NO,
	RETRANSMIT_YES,
};

enum retransmit_status retransmit(struct state *st);

size_t lswlog_retransmit_prefix(struct lswlog *buf, struct state *st);

#endif
