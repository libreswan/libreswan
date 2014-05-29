/* timing machinery
 * Copyright (C) 1998-2001,2013  D. Hugh Redelmeier.
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
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

struct state;   /* forward declaration */

struct event {
	monotime_t ev_time;
	enum event_type ev_type;        /* Event type */
	struct state   *ev_state;       /* Pointer to relevant state (if any) */
	struct event   *ev_next;        /* Pointer to next event */
};


extern void event_schedule(enum event_type type, time_t delay, struct state *st);
extern void handle_timer_event(void);
extern long next_event(void);
extern void delete_event(struct state *st);
extern void handle_next_timer_event(void);
extern void init_timer(void);

extern void delete_liveness_event(struct state *st);
/* extra debugging of dpd event removal */
extern void attributed_delete_dpd_event(struct state *st, const char *file, int lineno);
#define delete_dpd_event(st) attributed_delete_dpd_event(st, __FILE__, __LINE__)

extern void timer_list(void);

#endif /* _TIMER_H */
