/* timing machinery
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef _TIMER_H
#define _TIMER_H
#include "lswtime.h"

struct state;   /* forward declaration */

struct event {
	time_t ev_time;
	enum event_type ev_type;        /* Event type */
	struct state   *ev_state;       /* Pointer to relevant state (if any) */
	struct event   *ev_next;        /* Pointer to next event */
};

extern void event_schedule(enum event_type type, time_t tm, struct state *st);
extern void handle_timer_event(void);
extern long next_event(void);
extern void delete_event(struct state *st);
extern void daily_log_event(void);
extern void handle_next_timer_event(void);
extern void init_timer(void);

/* extra debugging of dpd event removal */
extern void _delete_dpd_event(struct state *st, const char *file, int lineno);
#define delete_dpd_event(st) _delete_dpd_event(st, __FILE__, __LINE__)

extern void timer_list(void);

#endif /* _TIMER_H */
