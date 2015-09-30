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

struct pluto_event {
	enum event_type ev_type;        /* Event type */
	struct state   *ev_state;       /* Pointer to relevant state (if any) */
	struct event *ev;               /* libevent data structure */
	monotime_t ev_time;
};

extern void event_schedule(enum event_type type, time_t delay_sec,
		struct state *st);
extern void event_schedule_ms(enum event_type type, unsigned long delay_ms,
		struct state *st);
extern void delete_event(struct state *st);
extern void handle_next_timer_event(void);
extern void init_timer(void);

extern void delete_liveness_event(struct state *st);
/* extra debugging of dpd event removal */
extern void delete_dpd_event(struct state *st);
extern void timer_list(void);

#endif /* _TIMER_H */
