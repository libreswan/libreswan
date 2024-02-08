/* get-next-event loop, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002, 2013,2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2016-2021 Andrew Cagney
 * Copyright (C) 2017 D. Hugh Redelmeier <hugh@mimosa.com>
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/wait.h>		/* for wait() and WIFEXITED() et.al. */
#include <resolv.h>

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/thread.h>

#include "lsw_socket.h"

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "kernel.h"             /* for no_klips; needs connections.h */
#include "log.h"
#include "server.h"
#include "timer.h"
#include "packet.h"
#include "demux.h"  /* needs packet.h */
#include "rcv_whack.h"
#include "keys.h"
#include "whack.h"              /* for RC_LOG_SERIOUS */
#include "monotime.h"
#include "ikev1.h"		/* for complete_v1_state_transition() */
#include "ikev2.h"		/* for complete_v2_state_transition() */
#include "iface.h"
#include "server_fork.h"
#include "whack_shutdown.h"	/* for whack_shutdown() and exiting_pluto; */
#include "show.h"

#ifdef USE_XFRM_INTERFACE
#include "kernel_xfrm_interface.h"
#endif

#include "nat_traversal.h"

#include "fips_mode.h"

#ifdef USE_SECCOMP
# include "pluto_seccomp.h"
#endif

#include "pluto_stats.h"
#include "hash_table.h"
#include "ip_address.h"
#include "ip_info.h"

/*
 *  Server main loop and socket initialization routines.
 */

char *pluto_vendorid;

/* pluto's main Libevent event_base */
static struct event_base *pluto_eb =  NULL;

static struct fd_read_listener *pluto_events_head = NULL;

/* control (whack) socket */
int ctl_fd = NULL_FD;   /* file descriptor of control (whack) socket */

struct sockaddr_un ctl_addr = {
	.sun_family = AF_UNIX,
#ifdef USE_SOCKADDR_LEN
	.sun_len = sizeof(struct sockaddr_un),
#endif
	.sun_path = DEFAULT_CTL_SOCKET
};

/* Initialize the control socket.
 * Note: this is called very early, so little infrastructure is available.
 * It is important that the socket is created before the original
 * Pluto process returns.
 */

diag_t init_ctl_socket(struct logger *logger UNUSED/*maybe*/)
{
	delete_ctl_socket();    /* preventative medicine */
	ctl_fd = cloexec_socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctl_fd == -1) {
		return diag_errno(errno, "could not create control socket: ");
	}

	/* to keep control socket secure, use umask */
#ifdef PLUTO_GROUP_CTL
	mode_t ou = umask(~(S_IRWXU | S_IRWXG));
#else
	mode_t ou = umask(~S_IRWXU);
#endif

	if (bind(ctl_fd, (struct sockaddr *)&ctl_addr,
		 offsetof(struct sockaddr_un, sun_path) +
		 strlen(ctl_addr.sun_path)) < 0) {
		return diag_errno(errno, "could not bind control socket: ");
	}
	umask(ou);

#ifdef PLUTO_GROUP_CTL
	{
		struct group *g = getgrnam("pluto");

		if (g != NULL) {
			if (fchown(ctl_fd, -1, g->gr_gid) != 0) {
				llog(RC_LOG_SERIOUS, logger,
					    "cannot chgrp ctl fd(%d) to gid=%d: %s",
					    ctl_fd, g->gr_gid, strerror(errno));
			}
		}
	}
#endif

	/*
	 * 5 (five) is a haphazardly chosen limit for the backlog.
	 * Rumour has it that this is the max on BSD systems.
	 */
	if (listen(ctl_fd, 5) < 0) {
		return diag_errno(errno, "could not listen on control socket: ");
	}

	return NULL;
}

void delete_ctl_socket(void)
{
	/* Is noting failure useful?  Not when used as preventative medicine. */
	unlink(ctl_addr.sun_path);
}

bool listening = false;  /* should we pay attention to IKE messages? */
bool pluto_drop_oppo_null = false; /* drop opportunistic AUTH-NULL on first IKE msg? */
bool pluto_listen_udp = true;
bool pluto_listen_tcp = false;

enum ddos_mode pluto_ddos_mode = DDOS_AUTO; /* default to auto-detect */

enum global_ikev1_policy pluto_ikev1_pol = GLOBAL_IKEv1_DROP;

#ifdef USE_SECCOMP
enum seccomp_mode pluto_seccomp_mode = SECCOMP_DISABLED;
#endif
unsigned int pluto_max_halfopen = DEFAULT_MAXIMUM_HALFOPEN_IKE_SA;
unsigned int pluto_ddos_threshold = DEFAULT_IKE_SA_DDOS_THRESHOLD;
deltatime_t pluto_shunt_lifetime = DELTATIME_INIT(PLUTO_SHUNT_LIFE_DURATION_DEFAULT);

unsigned int pluto_sock_bufsize = IKE_BUF_AUTO; /* use system values */
bool pluto_sock_errqueue = true; /* Enable MSG_ERRQUEUE on IKE socket */

/*
 * Embedded events.
 *
 * Adding:
 *
 * Because this code can run on the non-main thread, the EV must be
 * saved in its final destination before the event is enabled.
 *
 * Otherwise the event on the main thread will try to use EV before it
 * has been saved by the helper thread.
 *
 * For instance, a timer with delay 0 will likely start running in the
 * main thread before this macro has finished.
 *
 * Deleting:
 *
 * "If the event has already executed or has never been added the
 * [event_del()] call will have no effect."
 *
 * "When debugging mode is enabled, [event_debug_unasign()] informs
 * Libevent that an event should no longer be considered as assigned."
 */

#define EVENT_ADD(EVP, EVENTS, FD, TIME, CB)				\
	{								\
		struct event *ev = &(EVP)->ev;				\
		short events = EVENTS;					\
		passert(!event_initialized(ev));			\
		event_assign(ev, pluto_eb, FD, events, CB, EVP);	\
		passert(event_get_events(ev) == events);		\
		passert(event_add(ev, TIME) >= 0);			\
	}

#define EVENT_DEL(EVP)							\
	{								\
		struct event *ev = &(EVP)->ev;				\
		passert(event_initialized(ev));				\
		passert(event_del(ev) >= 0);				\
		event_debug_unassign(ev);				\
		zero(ev);						\
	}

/*
 * Global timer events.
 */

struct global_timer_desc {
	struct event ev;
	global_timer_cb *cb;
	const char *const name;
};

static struct global_timer_desc global_timers[] = {
#define E(T) [T] = { .name = #T, }
	E(EVENT_REINIT_SECRET),
	E(EVENT_SHUNT_SCAN),
	E(EVENT_PENDING_DDNS),
	E(EVENT_SD_WATCHDOG),
	E(EVENT_CHECK_CRLS),
	E(EVENT_FREE_ROOT_CERTS),
	E(EVENT_RESET_LOG_LIMITER),
	E(EVENT_PROCESS_KERNEL_QUEUE),
	E(EVENT_NAT_T_KEEPALIVE),
#undef E
};

static void global_timer_event_cb(evutil_socket_t fd UNUSED,
				  const short event, void *arg)
{
	struct logger logger[1] = { global_logger, }; /* event-handler */
	passert(in_main_thread());
	struct global_timer_desc *gt = arg;
	passert(event & EV_TIMEOUT);
	passert(gt >= global_timers);
	passert(gt < global_timers + elemsof(global_timers));
	dbg("processing global timer %s", gt->name);
	threadtime_t start = threadtime_start();
	gt->cb(logger);
	threadtime_stop(&start, SOS_NOBODY, "global timer %s", gt->name);
}

void call_global_event_inline(enum global_timer timer,
			      struct logger *logger)
{
	passert(in_main_thread());
	/* timer is hardwired so shouldn't happen */
	passert(timer < elemsof(global_timers));

	struct global_timer_desc *gt = &global_timers[timer];
	passert(gt->name != NULL);
	if (!event_initialized(&gt->ev)) {
		llog(RC_LOG, logger,
			    "inject: timer %s is not initialized",
			    gt->name);
		return;
	}

	llog(RC_LOG, logger, "inject: injecting timer event %s", gt->name);
	threadtime_t start = threadtime_start();
	gt->cb(logger);
	threadtime_stop(&start, SOS_NOBODY, "global timer %s", gt->name);
}

void enable_periodic_timer(enum global_timer type, global_timer_cb *cb,
			   deltatime_t period)
{
	passert(in_main_thread());
	passert(type < elemsof(global_timers));
	struct global_timer_desc *gt = &global_timers[type];
	passert(gt->name != NULL);
	gt->cb = cb;
	struct timeval t = timeval_from_deltatime(period);
	EVENT_ADD(gt, EV_TIMEOUT|EV_PERSIST,
		  (evutil_socket_t)-1, &t,
		  global_timer_event_cb);
	/* log */
	deltatime_buf buf;
	dbg("global periodic timer %s enabled with interval of %s seconds",
	    gt->name, str_deltatime(period, &buf));
}

void init_oneshot_timer(enum global_timer type, global_timer_cb *cb)
{
	passert(in_main_thread());
	passert(type < elemsof(global_timers));
	struct global_timer_desc *gt = &global_timers[type];
	/* initialize */
	passert(gt->name != NULL);
	passert(!event_initialized(&gt->ev));
	event_assign(&gt->ev, pluto_eb, (evutil_socket_t)-1,
		     EV_TIMEOUT,
		     global_timer_event_cb, gt/*arg*/);
	gt->cb = cb;
	passert(event_get_events(&gt->ev) == (EV_TIMEOUT));
	dbg("global one-shot timer %s initialized", gt->name);
}

void schedule_oneshot_timer(enum global_timer type, deltatime_t delay)
{
	passert(type < elemsof(global_timers));
	struct global_timer_desc *gt = &global_timers[type];
	deltatime_buf buf;
	dbg("global one-shot timer %s scheduled in %s seconds",
	    gt->name, str_deltatime(delay, &buf));
	passert(event_initialized(&gt->ev));
	passert(event_get_events(&gt->ev) == (EV_TIMEOUT));
	struct timeval t = timeval_from_deltatime(delay);
	passert(event_add(&gt->ev, &t) >= 0);
}

/* urban dictionary says deschedule is a word */
void deschedule_oneshot_timer(enum global_timer type)
{
	passert(type < elemsof(global_timers));
	struct global_timer_desc *gt = &global_timers[type];
	dbg("global one-shot timer %s disabled", gt->name);
	passert(event_initialized(&gt->ev));
	passert(event_del(&gt->ev) >= 0);
}

static void free_global_timers(void)
{
	for (unsigned u = 0; u < elemsof(global_timers); u++) {
		struct global_timer_desc *gt = &global_timers[u];
		if (event_initialized(&gt->ev)) {
			EVENT_DEL(gt);
			dbg("global timer %s uninitialized", gt->name);
		}
	}
}

static void list_global_timers(struct show *s, const monotime_t now)
{
	for (unsigned u = 0; u < elemsof(global_timers); u++) {
		struct global_timer_desc *gt = &global_timers[u];
		/*
		 * XXX: DUE.mt is "set to hold the time at which the
		 * timeout will expire" which is presumably a time and
		 * not a delay (event_add() takes a delay).
		*/
		monotime_t due = monotime_epoch;
		if (event_initialized(&gt->ev) &&
		    event_pending(&gt->ev, EV_TIMEOUT, &due.mt) > 0) {
			const char *what = (event_get_events(&gt->ev) & EV_PERSIST) ? "periodic" : "one-shot";
			deltatime_t delay = monotimediff(due, now);
			deltatime_buf delay_buf;
			show_comment(s, "global %s timer %s is scheduled for %jd (in %s seconds)",
				     what, gt->name,
				     monosecs(due), /* XXX: useful? */
				     str_deltatime(delay, &delay_buf));
		}
	}
}

/*
 * Global signal events.
 */

typedef void (signal_handler_cb)(struct logger *logger);

struct signal_handler {
	struct event ev;
	signal_handler_cb *cb;
	int signal;
	bool persist;
	const char *name;
};

static signal_handler_cb termhandler_cb;
static signal_handler_cb huphandler_cb;
#ifdef USE_SECCOMP
static signal_handler_cb syshandler_cb;
#endif

static struct signal_handler signal_handlers[] = {
	{ .signal = SIGCHLD, .cb = server_fork_sigchld_handler, .persist = true, .name = "PLUTO_SIGCHLD", },
	{ .signal = SIGTERM, .cb = termhandler_cb, .persist = false, .name = "PLUTO_SIGTERM", },
	{ .signal = SIGHUP, .cb = huphandler_cb, .persist = true, .name = "PLUTO_SIGHUP", },
#ifdef USE_SECCOMP
	{ .signal = SIGSYS, .cb = syshandler_cb, .persist = true, .name = "PLUTO_SIGSYS", },
#endif
};

static void signal_handler_handler(evutil_socket_t fd UNUSED,
				   const short event, void *arg)
{
	passert(in_main_thread());
	passert(event & EV_SIGNAL);
	struct logger logger[1] = { global_logger, }; /* event-handler */
	struct signal_handler *se = arg;
	dbg("processing signal %s", se->name);
	threadtime_t start = threadtime_start();
	se->cb(logger);
	threadtime_stop(&start, SOS_NOBODY, "signal handler %s", se->name);
}

static void install_signal_handlers(void)
{
	for (unsigned i = 0; i < elemsof(signal_handlers); i++) {
		struct signal_handler *se = &signal_handlers[i];
		EVENT_ADD(se, EV_SIGNAL | (se->persist ? EV_PERSIST : 0),
			  (evutil_socket_t)se->signal,
			  (struct timeval*)NULL,
			  signal_handler_handler);
		dbg("signal event handler %s installed", se->name);
	}
}

static void free_signal_handlers(void)
{
	for (unsigned i = 0; i < elemsof(signal_handlers); i++) {
		struct signal_handler *se = &signal_handlers[i];
		EVENT_DEL(se);
		dbg("signal event handler %s uninstalled", se->name);
	}
}

static void list_signal_handlers(struct show *s)
{
	for (unsigned i = 0; i < elemsof(signal_handlers); i++) {
		struct signal_handler *se = &signal_handlers[i];
		if (event_initialized(&se->ev) &&
		    event_pending(&se->ev, EV_SIGNAL, NULL) > 0) {
			show_comment(s, "signal event handler %s", se->name);
		}
	}
}

/*
 * Global FD events.
 */

struct fd_read_listener {
	fd_read_listener_cb *cb;
	void *arg;
	const char *name;
	struct event ev;		/* libevent data structure */
	struct fd_read_listener *next;
};

void free_server(void)
{
	if (pluto_eb == NULL) {
		/*
		 * pluto_shutdown() can call free_server() before
		 * init_server(); mumble something about using
		 * atexit().
		 */
		dbg("server event base not initialized");
		return;
	}

	while (pluto_events_head != NULL) {
		struct fd_read_listener *tbd = pluto_events_head;
		pluto_events_head = tbd->next;
		tbd->next = NULL;
		detach_fd_read_listener(&tbd);
	}
	free_global_timers();
	free_signal_handlers();

	dbg("releasing event base");
	event_base_free(pluto_eb);
	pluto_eb = NULL;
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
	/*
	 * Release any global event data such as that allocated by
	 * evthread_use_pthreads().
	 *
	 * The function was added to the code base in 2011 and was
	 * first published in April 2012 as part of 2.1.1-alpha (aka
	 * above magic number). The first stable release was
	 * 2.1.8-stable in January 2017.
	 *
	 * As of 2019, the following OSs are known to not include the
	 * function: RHEL 7.6 / CentOS 7.x (2.0.21-stable); Ubuntu
	 * 16.04.6 LTS (Xenial Xerus) (2.0.21-stable).
	 */
	dbg("releasing global libevent data");
	libevent_global_shutdown();
#else
	dbg("leaking global libevent data (libevent is old)");
#endif
}

static void link_pluto_event_list(struct fd_read_listener *e) {
	e->next = pluto_events_head;
	pluto_events_head = e;
}

/*
 * A wrapper for libevent's event_new + event_add; any error is fatal.
 *
 * When setting up an event, this must be called last.  Else the event
 * can fire before setting it up has finished.
 */

struct timeout {
	const char *name;
	void (*cb)(void *arg, const struct timer_event *event);
	void *arg;
	struct event ev;
};

static void timeout(evutil_socket_t fd UNUSED,
		    const short ev_event UNUSED, void *arg)
{
	struct timeout *tt = arg;
	struct timer_event event = {
		.inception = threadtime_start(),
		.logger = &global_logger,
	};
	tt->cb(tt->arg, &event);
}

void schedule_timeout(const char *name,
		      struct timeout **tt, const deltatime_t delay,
		      void (*cb)(void *arg, const struct timer_event *event),
		      void *arg)
{
	*tt = alloc_thing(struct timeout, name);
	dbg_alloc("tt", *tt, HERE);
	(*tt)->name = name;
	(*tt)->cb = cb;
	(*tt)->arg = arg;
	/*
	 * When DELAY is zero, the photon torpedo may have hit its
	 * target before this function even returns.  Hence TT is a
	 * parameter and is stored before the timer.
	 */
	struct timeval t = timeval_from_deltatime(delay);
	EVENT_ADD(*tt, EV_TIMEOUT, (evutil_socket_t)-1, &t, timeout);
}

void destroy_timeout(struct timeout **tt)
{
	passert(in_main_thread());
	if (*tt != NULL) {
		EVENT_DEL(*tt);
		dbg_free("tt", *tt, HERE);
		pfree(*tt);
		*tt = NULL;
	}
}

/*
 * Schedule a resume event now.
 *
 * Unlike pluto_event_add(), it can't be canceled, can only run once,
 * doesn't show up in the event list, and leaks when the event-loop
 * aborts (like a few others).
 *
 * However, unlike pluto_event_add(), it works from any thread, and
 * cleans up after the event has run.
 */

struct resume_event {
	so_serial_t serialno;
	resume_cb *callback;
	void *context;
	const char *name;
	struct timeout *timer;
};

void complete_state_transition(struct state *st, struct msg_digest *md, stf_status status)
{
	switch (st->st_ike_version) {
#ifdef USE_IKEv1
	case IKEv1:
		complete_v1_state_transition(st, md, status);
		break;
#endif
	case IKEv2:
		complete_v2_state_transition(pexpect_ike_sa(st), md, status);
		break;
	default:
		bad_case(st->st_ike_version);
	}
}

static void resume_handler(void *arg, const struct timer_event *event)
{
	struct resume_event *e = (struct resume_event *)arg;
	/*
	 * At one point, .ne_event was was being set after the event
	 * was enabled.  With multiple threads this resulted in a race
	 * where the event ran before .ne_event was set.  The
	 * pexpect() followed by the passert() demonstrated this - the
	 * pexpect() failed yet the passert() passed.
	 */
	pexpect(e->timer != NULL);
	ldbg(event->logger, "processing resume %s for #%lu", e->name, e->serialno);
	/*
	 * XXX: Don't confuse this and the "callback") code path.
	 * This unsuspends MD, "callback" does not.
	 */
	struct state *st = state_by_serialno(e->serialno);
	if (st == NULL) {
		threadtime_t start = threadtime_start();
		stf_status status = e->callback(NULL, NULL, e->context);
		pexpect(status == STF_SKIP_COMPLETE_STATE_TRANSITION);
		threadtime_stop(&start, e->serialno, "resume %s", e->name);
	} else {
		/* no previous state */
		statetime_t start = statetime_start(st);
		struct msg_digest *md = unsuspend_any_md(st);

		/* trust nothing; so save everything */
		so_serial_t old_st = st->st_serialno;
		so_serial_t old_md_st = md != NULL && md->v1_st != NULL ? md->v1_st->st_serialno : SOS_NOBODY;
		const enum ike_version ike_version = st->st_ike_version;
		/* when MD.ST it matches ST */
		pexpect(old_md_st == SOS_NOBODY || old_md_st == old_st);

		/* run the callback */
		stf_status status = e->callback(st, md, e->context);
		/* this may trash ST and/or MD.ST */

		if (status == STF_SKIP_COMPLETE_STATE_TRANSITION) {
			/* MD.ST may have been freed! */
			ldbg(event->logger,
			     "resume %s for #%lu suppresed complete_v%d_state_transition()%s",
			     e->name, e->serialno, ike_version,
			     (old_md_st != SOS_NOBODY && md->v1_st == NULL ? "; MD.ST disappeared" :
			      old_md_st != SOS_NOBODY && md->v1_st != st ? "; MD.ST was switched" :
			      ""));
		} else {
			/* XXX: mumble something about struct ike_version */
			switch (ike_version) {
#ifdef USE_IKEv1
			case IKEv1:
				/* no switching MD.ST */
				if (old_md_st == SOS_NOBODY) {
					/* (old)md->v1_st == (new)md->v1_st == NULL */
					pexpect(md == NULL || md->v1_st == NULL);
				} else {
					/* md->v1_st didn't change */
					pexpect(md != NULL &&
						md->v1_st != NULL &&
						md->v1_st->st_serialno == old_md_st);
				}
				pexpect(st != NULL); /* see above */
				break;
#endif
			case IKEv2:
				break;
			default:
				bad_case(ike_version);
			}
			complete_state_transition(st, md, status);
		}
		md_delref(&md);
		statetime_stop(&start, "resume %s", e->name);
	}
	passert(e->timer != NULL);
	destroy_timeout(&e->timer);
	pfree(e);
}

void schedule_resume(const char *name, so_serial_t serialno,
		     resume_cb *callback, void *context)
{
	pexpect(serialno != SOS_NOBODY);
	struct resume_event tmp = {
		.serialno = serialno,
		.callback = callback,
		.context = context,
		.name = name,
	};
	struct resume_event *e = clone_thing(tmp, name);
	dbg("scheduling resume %s for #%lu",
	    e->name, e->serialno);

	/*
	 * Everything set up; arm and fire the timer's photon torpedo.
	 * Event may have even run on another thread before the below
	 * call returns.
	 */
	schedule_timeout(name, &e->timer, deltatime(0), resume_handler, e);
}

/*
 * Schedule a callback now.
 */

struct callback_event {
	so_serial_t serialno;
	callback_cb *callback;
	void *context;
	const char *story;
	struct timeout *timer;
};

static void callback_handler(void *arg, const struct timer_event *event)
{
	/*
	 * Save all fields so that all event-loop memory can be freed
	 * _before_ making callback (the callback might run
	 * leak-detective and exit).
	 *
	 * Danger!
	 *
	 * At one point, the code scheduling the event was only
	 * setting the .event field after the event was enabled.  With
	 * multiple threads this resulted in a race where the event
	 * ran and was deleted .event was valid.  Oops!
	 */
	struct callback_event e = *(struct callback_event *)arg;
	passert(e.timer != NULL);
	destroy_timeout(&e.timer);
	pfree(arg);

	struct state *st;
	if (e.serialno == SOS_NOBODY) {
		ldbg(event->logger, "processing callback %s", e.story);
		st = NULL;
	} else {
		/*
		 * XXX: Don't confuse this and the "resume" code paths
		 * - this does not unsuspend MD, "resume" does.
		 */
		ldbg(event->logger, "processing callback %s for #%lu", e.story, e.serialno);
		st = state_by_serialno(e.serialno);
	}

	threadtime_t start = threadtime_start();
	e.callback(e.story, st, e.context);
	threadtime_stop(&start, SOS_NOBODY, "callback %s", e.story);
}

void schedule_callback(const char *story, deltatime_t delay,
		       so_serial_t serialno,
		       callback_cb *callback, void *context)
{
	struct callback_event tmp = {
		.serialno = serialno,
		.callback = callback,
		.context = context,
		.story = story,
	};
	struct callback_event *e = clone_thing(tmp, story);
	dbg("scheduling callback %s (#%lu)", e->story, e->serialno);
	/*
	 * Everything set up; arm and fire the timer's photon torpedo.
	 * Event may have even run on another thread before the below
	 * call returns.
	 */
	schedule_timeout(story, &e->timer, delay, callback_handler, e);
}

static void fd_read_listener_event_handler(evutil_socket_t fd,
					   short events UNUSED,
					   void *arg)
{
	struct logger logger[1] = { global_logger, }; /* event-handler */
	struct fd_read_listener *fdl = arg;
	fdl->cb(fd, fdl->arg, logger);
}

void attach_fd_read_listener(struct fd_read_listener **fdl,
			     int fd, const char *name,
			     fd_read_listener_cb *cb, void *arg)
{
	passert(*fdl == NULL);
	passert(fd >= 0);
	/* create the listener */
	*fdl = alloc_thing(struct fd_read_listener, name);
	dbg_alloc("fdl", *fdl, HERE);
	(*fdl)->name = name;
	(*fdl)->arg = arg;
	(*fdl)->cb = cb;
	EVENT_ADD(*fdl, EV_READ|EV_PERSIST,
		  (evutil_socket_t)fd,
		  (struct timeval*)NULL,
		  fd_read_listener_event_handler);
}

void detach_fd_read_listener(struct fd_read_listener **fdl)
{
	if (*fdl != NULL) {
		EVENT_DEL(*fdl);
		dbg_free("fdl", *fdl, HERE);
		pfree(*fdl);
		*fdl = NULL;
	}
}

void add_fd_read_listener(int fd, const char *name,
			  fd_read_listener_cb *cb, void *arg)
{
	passert(in_main_thread());
	struct fd_read_listener *fdl = NULL;
	attach_fd_read_listener(&fdl, fd, name, cb, arg);
	link_pluto_event_list(fdl);
}

struct fd_accept_listener {
	fd_accept_listener_cb *cb;
	void *arg;
	const char *name;
	struct evconnlistener *ev;
};

static void fd_accept_listener(struct evconnlistener *efc UNUSED,
			       evutil_socket_t fd,
			       struct sockaddr *sockaddr, int sockaddr_len,
			       void *arg)
{
	struct logger logger[1] = { global_logger, }; /* event-handler */
	struct fd_accept_listener *fdl = arg;
	ip_sockaddr sa = {
		.len = sockaddr_len,
	};
	passert(sockaddr_len >= 0 && (size_t)sockaddr_len <= sizeof(sa.sa));
	memcpy(&sa.sa, sockaddr, sockaddr_len);
	fdl->cb(fd, &sa, fdl->arg, logger);
}

void attach_fd_accept_listener(const char *name,
			       struct fd_accept_listener **fdl,
			       int fd, fd_accept_listener_cb *cb, void *arg)
{
	passert(*fdl == NULL);
	passert(fd >= 0);
	*fdl = alloc_thing(struct fd_accept_listener, name);
	dbg_alloc("fdl", *fdl, HERE);
	(*fdl)->cb = cb;
	(*fdl)->arg = arg;
	(*fdl)->name = name;
	(*fdl)->ev = evconnlistener_new(pluto_eb, fd_accept_listener, *fdl,
					LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC,
					/*backlog*/-1, fd);
}

void detach_fd_accept_listener(struct fd_accept_listener **fdl)
{
	if (*fdl != NULL) {
		evconnlistener_free((*fdl)->ev);
		(*fdl)->ev = NULL;
		dbg_free("fdl", *fdl, HERE);
		pfree(*fdl);
		*fdl = NULL;
	}
}

/*
 * dump list of events to whacklog
 */
void list_timers(struct show *s, const monotime_t now)
{
	show_comment(s, "it is now: %jd seconds since monotonic epoch",
		     monosecs(now));

	list_global_timers(s, now);
	list_signal_handlers(s);

	for (struct fd_read_listener *ev = pluto_events_head;
	     ev != NULL; ev = ev->next) {
		SHOW_JAMBUF(s, buf) {
			show_comment(s, "event %s is not timer based", ev->name);
		}
	}
}

void show_debug_status(struct show *s)
{
	SHOW_JAMBUF(s, buf) {
		jam(buf, "debug:");
		if (cur_debugging & DBG_MASK) {
			jam(buf, " ");
			jam_lset_short(buf, &debug_names, "+",
				       cur_debugging & DBG_MASK);
		}
		if (have_impairments()) {
			jam(buf, " impair: ");
			jam_impairments(buf, "+");
		}
	}
}

void show_fips_status(struct show *s)
{
	bool fips = is_fips_mode();
	show_comment(s, "FIPS mode %s", !fips ?
		"disabled" :
		impair.force_fips ? "enabled [forced]" : "enabled");
}

static void huphandler_cb(struct logger *logger)
{
	llog(RC_LOG, logger, "Pluto ignores SIGHUP -- perhaps you want \"whack --listen\"");
}

static void termhandler_cb(struct logger *logger)
{
	whack_shutdown(logger, PLUTO_EXIT_OK);
}

#ifdef USE_SECCOMP
static void syshandler_cb(struct logger *logger)
{
	llog(RC_LOG_SERIOUS, logger, "pluto received SIGSYS - possible SECCOMP violation!");
	if (pluto_seccomp_mode == SECCOMP_ENABLED) {
		fatal(PLUTO_EXIT_SECCOMP_FAIL, logger, "seccomp=enabled mandates daemon restart");
	}
}
#endif

static server_fork_cb addconn_exited; /* type assertion */

static stf_status addconn_exited(struct state *null_st UNUSED,
				 struct msg_digest *null_mdp UNUSED,
				 int status, void *context UNUSED,
				 struct logger *logger UNUSED)
{
	dbg("reaped addconn helper child (status %d)", status);
	return STF_OK;
}

#ifdef EVENT_SET_MEM_FUNCTIONS_IMPLEMENTED
static void *libevent_malloc(size_t size)
{
	void *ptr = uninitialized_malloc(size, __func__);
	dbg_alloc("libevent", ptr, HERE);
	return ptr;
}
static void *libevent_realloc(void *old, size_t size)
{
	if (old != NULL) {
		dbg_free("libevent", old, HERE);
	}
	void *new = uninitialized_realloc(old, size, __func__);
	if (new != NULL) {
		dbg_alloc("libevent", new, HERE);
	}
	return new;
}
static void libevent_free(void *ptr)
{
	dbg_free("libevent", ptr, HERE);
	pfree(ptr);
}
#endif

void init_server(struct logger *logger)
{
	/*
	 * "... if you are going to call this function, you should do
	 * so before any call to any Libevent function that does
	 * allocation."
	 */
#ifdef EVENT_SET_MEM_FUNCTIONS_IMPLEMENTED
	event_set_mem_functions(libevent_malloc, libevent_realloc,
				libevent_free);
	dbg("libevent is using pluto's memory allocator");
#else
	dbg("libevent is using its own memory allocator");
#endif
	llog(RC_LOG, logger,
		    "initializing libevent in pthreads mode: headers: %s (%" PRIx32 "); library: %s (%" PRIx32 ")",
		    LIBEVENT_VERSION, (ev_uint32_t)LIBEVENT_VERSION_NUMBER,
		    event_get_version(), event_get_version_number());
	/*
	 * According to section 'setup Library setup', libevent needs
	 * to be set up in pthreads mode before doing anything else.
	 */
	int r = evthread_use_pthreads();
	passert(r >= 0);
	/* now do anything */
	dbg("creating event base");
	pluto_eb = event_base_new();
	passert(pluto_eb != NULL);
	int s = evthread_make_base_notifiable(pluto_eb);
	passert(s >= 0);
	dbg("libevent initialized");
}

/*
 * listens for incoming ISAKMP packets and Whack messages, and handles
 * timer events.
 *
 * On shutdown, calls SERVER_STOPPED() (which was hopefully set by
 * shutdown code).
 */

static server_stopped_cb server_stopped;

void run_server(char *conffile, struct logger *logger)
{
	/*
	 * setup basic events, CTL and SIGNALs
	 */

	dbg("Setting up events, loop start");

	add_fd_read_listener(ctl_fd, "PLUTO_CTL_FD", whack_handle_cb, NULL);

	install_signal_handlers();

	/* do_whacklisten() is now done by the addconn fork */

	/*
	 * fork()+exec() to issue the command "ipsec addconn
	 */

	static const char addconn_path[] = IPSEC_EXECDIR "/addconn";
	if (access(addconn_path, X_OK) < 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "%s: missing or not executable",
			    addconn_path);
	}

	char *newargv[] = {
		DISCARD_CONST(char *, "addconn"),
		DISCARD_CONST(char *, "--ctlsocket"),
		DISCARD_CONST(char *, ctl_addr.sun_path),
		DISCARD_CONST(char *, "--config"),
		DISCARD_CONST(char *, conffile),
		DISCARD_CONST(char *, "--autoall"), NULL };
	char *newenv[] = { NULL };
	server_fork_exec(addconn_path, newargv, newenv,
			 addconn_exited, NULL, logger);

	/* parent continues */

#ifdef USE_SECCOMP
	init_seccomp_main(logger);
#else
	llog(RC_LOG, logger, "seccomp security not supported");
#endif

	int r = event_base_loop(pluto_eb, 0);
	pexpect(r >= 0);
	server_stopped(r);
}

/*
 * Indicate to libevent that the event-loop should be shutdown.  Once
 * shutdown has completed CB is called.
 */
void stop_server(server_stopped_cb cb)
{
	server_stopped = cb;
	event_base_loopbreak(pluto_eb);
}

void set_whack_pluto_ddos(enum ddos_mode mode, struct logger *logger)
{
	const char *modestr = (mode == DDOS_AUTO ? "auto-detect" :
			       mode == DDOS_FORCE_BUSY ? "active" :
			       "unlimited");
	if (mode == pluto_ddos_mode) {
		llog(RC_LOG, logger,
			    "pluto DDoS protection remains in %s mode", modestr);
		return;
	}

	pluto_ddos_mode = mode;
	llog(RC_LOG, logger, "pluto DDoS protection mode set to %s", modestr);
}

struct event_base *get_pluto_event_base(void)
{
	return pluto_eb;
}
