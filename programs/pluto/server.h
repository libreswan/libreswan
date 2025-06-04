/* get-next-event loop, for libreswan
 *
 * Copyright (C) 1998-2001,2013  D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2019 Andrew Cagney
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#ifndef _SERVER_H
#define _SERVER_H

#include <event2/event.h>		/* from rpm:libevent-devel */
#include <event2/event_struct.h>
#include <event2/listener.h>

#include "timer.h"
#include "err.h"
#include "ip_address.h"
#include "ip_endpoint.h"
#include "ip_sockaddr.h"
#include "diag.h"
#include "pluto_timing.h"		/* for threadtime_t */

struct state;
struct msg_digest;
struct bufferevent;
struct iface_endpoint;
struct iface_device;
struct show;
struct fd_read_listener;
struct fd_accept_listener;
struct timeout;
struct config_setup;

void check_open_fds(struct logger *logger);
void init_ctl_socket(const struct config_setup *oco, struct logger *logger);
void delete_ctl_socket(void);

struct iface_endpoint *connect_to_tcp_endpoint(struct iface_device *local_dev,
					       ip_endpoint remote_endpoint,
					       struct logger *logger); /* TCP: terrible name? */

extern bool listening;  /* should we pay attention to IKE messages? */
extern bool pluto_listen_udp;
extern bool pluto_listen_tcp;

extern enum ddos_mode pluto_ddos_mode; /* auto-detect or manual */
extern unsigned int pluto_max_halfopen; /* Max allowed half-open IKE SA's before refusing */
extern unsigned int pluto_ddos_threshold; /* Max incoming IKE before activating DCOOKIES */

extern enum pluto_ddos_mode ddos_mode;

extern void show_debug_status(struct show *s);
extern void run_server(char *conffile, struct logger *logger) NEVER_RETURNS;

/* XXX: grr, need pointer to function else NEVER_RETURNS is ignored */
typedef void (*server_stopped_cb)(int r) NEVER_RETURNS;
extern void stop_server(server_stopped_cb cb);

struct timer_event {
	threadtime_t inception;
	struct logger *logger;
};

void schedule_timeout(const char *name,
		      struct timeout **to, const deltatime_t delay,
		      void (*cb)(void *arg, const struct timer_event *event),
		      void *arg);
void destroy_timeout(struct timeout **to);

typedef void (fd_accept_listener_cb)(int fd, ip_sockaddr *sa,
				     void *arg, struct logger *logger);
void attach_fd_accept_listener(const char *name,
			       struct fd_accept_listener **fdl, int fd,
			       fd_accept_listener_cb *cb, void *arg);
void detach_fd_accept_listener(struct fd_accept_listener **fdl);

typedef void (fd_read_listener_cb)(int fd, void *arg, struct logger *logger);

void attach_fd_read_listener(struct fd_read_listener **fdl,
			     int fd, const char *name,
			     fd_read_listener_cb *cb, void *arg);
void detach_fd_read_listener(struct fd_read_listener **fdl);

void add_fd_read_listener(int fd, const char *name,
			  fd_read_listener_cb *cb, void *arg);

extern void set_pluto_busy(bool busy);
extern void set_whack_pluto_ddos(enum ddos_mode mode, struct logger *logger);

extern void init_server(struct logger *logger);
extern void free_server(void);

extern struct event_base *get_pluto_event_base(void);

/*
 * Schedule an event (with no timeout) to resume a suspended state.
 * SERIALNO (so_serial_t) is used to identify the state because the
 * state object may not be directly accessible (as happens with worker
 * threads).
 *
 * For instance: a worker thread needing to resume processing of a
 * state on the main thread once crypto has completed; by the main
 * thread when faking STF_SUSPEND by scheduling a new event.
 *
 * On callback:
 *
 * The CALLBACK must check ST's value: if it is NULL then the state
 * "disappeared"; if it is non-NULL then it is for SERIALNO.  Either
 * way the CALLBACK is responsible for releasing CONTEXT.
 *
 * XXX: There's a design flaw here - what happens if a state is
 * simultaneously processing a request and a response - there's only
 * space for one message!  Suspect what saves things is that it
 * doesn't happen in the real world.
 *
 * XXX: resume_cb should return stf_status, but doing this is a mess.
 */

typedef stf_status resume_cb(struct state *st,
			     struct msg_digest *md,
			     void *context);
void schedule_resume(const char *name,
		     so_serial_t serialno,
		     struct msg_digest **mdp,
		     resume_cb *callback, void *context);

/*
 * Schedule a callback on the main event loop now.
 *
 * Unlike schedule_resume(), SERIALNO can be SOS_NOBODY and this
 * doesn't try to unsuspend MD.
 *
 * DELAY should be deltatime(0).  However, impaired code says
 * otherwise.
 */

typedef void callback_cb(const char *story, struct state *st, void *context);
void schedule_callback(const char *story, deltatime_t delay,
		       so_serial_t serialno,
		       callback_cb *callback, void *context);

void whack_impair_call_global_event_handler(enum global_timer type,
					    struct logger *logger);
void call_global_event_handler(enum global_timer type, struct logger *logger);

void complete_state_transition(struct state *st, struct msg_digest *md, stf_status status);

#endif /* SERVER_H */
