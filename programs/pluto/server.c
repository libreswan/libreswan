/*
 * get-next-event loop
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
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
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
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
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

#include "sysdep.h"
#include "socketwrapper.h"
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
#include "pluto_crypt.h"        /* cryptographic helper functions */
#include "monotime.h"
#include "ikev1.h"		/* for complete_v1_state_transition() */
#include "ikev2.h"		/* for complete_v2_state_transition() */
#include "state_db.h"
#include "iface.h"

#ifdef USE_XFRM_INTERFACE
#include "kernel_xfrm_interface.h"
#endif

#include "nat_traversal.h"

#include "lswfips.h"

#ifdef HAVE_SECCOMP
# include "pluto_seccomp.h"
#endif

#include "pluto_stats.h"
#include "hash_table.h"
#include "ip_address.h"
#include "hostpair.h"
#include "ip_info.h"

/*
 *  Server main loop and socket initialization routines.
 */

char *pluto_vendorid;

static pid_t addconn_child_pid = 0;

/* pluto's main Libevent event_base */
static struct event_base *pluto_eb =  NULL;

static  struct pluto_event *pluto_events_head = NULL;

/* control (whack) socket */
int ctl_fd = NULL_FD;   /* file descriptor of control (whack) socket */

struct sockaddr_un ctl_addr = {
	.sun_family = AF_UNIX,
#if defined(HAS_SUN_LEN)
	.sun_len = sizeof(struct sockaddr_un),
#endif
	.sun_path  = DEFAULT_CTL_SOCKET
};

/* Initialize the control socket.
 * Note: this is called very early, so little infrastructure is available.
 * It is important that the socket is created before the original
 * Pluto process returns.
 */
err_t init_ctl_socket(void)
{
	err_t failed = NULL;

	delete_ctl_socket();    /* preventative medicine */
	ctl_fd = safe_socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctl_fd == -1) {
		failed = "create";
	} else if (fcntl(ctl_fd, F_SETFD, FD_CLOEXEC) == -1) {
		failed = "fcntl FD+CLOEXEC";
	} else {
		/* to keep control socket secure, use umask */
#ifdef PLUTO_GROUP_CTL
		mode_t ou = umask(~(S_IRWXU | S_IRWXG));
#else
		mode_t ou = umask(~S_IRWXU);
#endif

		if (bind(ctl_fd, (struct sockaddr *)&ctl_addr,
			 offsetof(struct sockaddr_un, sun_path) +
				strlen(ctl_addr.sun_path)) < 0)
			failed = "bind";
		umask(ou);
	}

#ifdef PLUTO_GROUP_CTL
	{
		struct group *g = getgrnam("pluto");

		if (g != NULL) {
			if (fchown(ctl_fd, -1, g->gr_gid) != 0) {
				loglog(RC_LOG_SERIOUS,
				       "Cannot chgrp ctl fd(%d) to gid=%d: %s",
				       ctl_fd, g->gr_gid, strerror(errno));
			}
		}
	}
#endif

	/* 5 is a haphazardly chosen limit for the backlog.
	 * Rumour has it that this is the max on BSD systems.
	 */
	if (failed == NULL && listen(ctl_fd, 5) < 0)
		failed = "listen() on";

	return failed == NULL ? NULL : builddiag(
		"could not %s control socket: %d %s",
		failed, errno,
		strerror(errno));
}

void delete_ctl_socket(void)
{
	/* Is noting failure useful?  Not when used as preventative medicine. */
	unlink(ctl_addr.sun_path);
}

bool listening = FALSE;  /* should we pay attention to IKE messages? */
bool pluto_drop_oppo_null = FALSE; /* drop opportunistic AUTH-NULL on first IKE msg? */
bool pluto_listen_udp = TRUE;
bool pluto_listen_tcp = FALSE;

enum ddos_mode pluto_ddos_mode = DDOS_AUTO; /* default to auto-detect */
#ifdef HAVE_SECCOMP
enum seccomp_mode pluto_seccomp_mode = SECCOMP_DISABLED;
#endif
unsigned int pluto_max_halfopen = DEFAULT_MAXIMUM_HALFOPEN_IKE_SA;
unsigned int pluto_ddos_threshold = DEFAULT_IKE_SA_DDOS_THRESHOLD;
deltatime_t pluto_shunt_lifetime = DELTATIME_INIT(PLUTO_SHUNT_LIFE_DURATION_DEFAULT);

unsigned int pluto_sock_bufsize = IKE_BUF_AUTO; /* use system values */
bool pluto_sock_errqueue = TRUE; /* Enable MSG_ERRQUEUE on IKE socket */

/*
 * Static events.
 */

static void free_static_event(struct event *ev)
{
	/*
	 * "If the event has already executed or has never been added
	 * the [event_del()] call will have no effect.
	 */
	passert(event_del(ev) >= 0);
	/*
	 * "When debugging mode is enabled, informs Libevent that an
	 * event should no longer be considered as assigned."
	 */
	event_debug_unassign(ev);
	zero(ev);
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
	E(EVENT_PENDING_PHASE2),
	E(EVENT_CHECK_CRLS),
	E(EVENT_REVIVE_CONNS),
	E(EVENT_FREE_ROOT_CERTS),
	E(EVENT_RESET_LOG_RATE_LIMIT),
	E(EVENT_PROCESS_KERNEL_QUEUE),
	E(EVENT_NAT_T_KEEPALIVE),
#undef E
};

static void global_timer_event_cb(evutil_socket_t fd UNUSED,
				  const short event, void *arg)
{
	passert(in_main_thread());
	struct global_timer_desc *gt = arg;
	passert(event & EV_TIMEOUT);
	passert(gt >= global_timers);
	passert(gt < global_timers + elemsof(global_timers));
	dbg("processing global timer %s", gt->name);
	threadtime_t start = threadtime_start();
	gt->cb(null_fd);
	threadtime_stop(&start, SOS_NOBODY, "global timer %s", gt->name);
}

void call_global_event_inline(enum global_timer timer, struct fd *whackfd)
{
	passert(in_main_thread());
	if (!pexpect(timer < elemsof(global_timers))) {
		/* timer is hardwired so shouldn't happen */
		return;
	}
	struct global_timer_desc *gt = &global_timers[timer];
	passert(gt->name != NULL);
	if (!event_initialized(&gt->ev)) {
		log_global(RC_LOG, whackfd, "inject: timer %s is not initialized",
			   gt->name);
	}
	log_global(RC_LOG, whackfd, "inject: injecting timer event %s", gt->name);
	threadtime_t start = threadtime_start();
	gt->cb(whackfd);
	threadtime_stop(&start, SOS_NOBODY, "global timer %s", gt->name);
}

void enable_periodic_timer(enum global_timer type, global_timer_cb *cb,
			   deltatime_t period)
{
	passert(in_main_thread());
	passert(type < elemsof(global_timers));
	struct global_timer_desc *gt = &global_timers[type];
	/* initialize */
	passert(gt->name != NULL);
	passert(!event_initialized(&gt->ev));
	event_assign(&gt->ev, pluto_eb, (evutil_socket_t)-1,
		     EV_TIMEOUT|EV_PERSIST,
		     global_timer_event_cb, gt/*arg*/);
	gt->cb = cb;
	passert(event_get_events(&gt->ev) == (EV_TIMEOUT|EV_PERSIST));
	/* enable */
	struct timeval t = timeval_from_deltatime(period);
	passert(event_add(&gt->ev, &t) >= 0);
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
			free_static_event(&gt->ev);
			dbg("global timer %s uninitialized", gt->name);
		}
	}
}

static void list_global_timers(const struct fd *whackfd,
			       monotime_t now)
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
			whack_comment(whackfd,
				  "global %s timer %s is scheduled for %jd (in %s seconds)",
				  what, gt->name,
				  monosecs(due), /* XXX: useful? */
				  str_deltatime(delay, &delay_buf));
		}
	}
}

/*
 * Global signal events.
 */

typedef void (signal_handler_cb)(void);

struct signal_handler {
	struct event ev;
	signal_handler_cb *cb;
	int signal;
	bool persist;
	const char *name;
};

static signal_handler_cb childhandler_cb;
static signal_handler_cb termhandler_cb;
static signal_handler_cb huphandler_cb;
#ifdef HAVE_SECCOMP
static signal_handler_cb syshandler_cb;
#endif

static struct signal_handler signal_handlers[] = {
	{ .signal = SIGCHLD, .cb = childhandler_cb, .persist = true, .name = "PLUTO_SIGCHLD", },
	{ .signal = SIGTERM, .cb = termhandler_cb, .persist = false, .name = "PLUTO_SIGTERM", },
	{ .signal = SIGHUP, .cb = huphandler_cb, .persist = true, .name = "PLUTO_SIGHUP", },
#ifdef HAVE_SECCOMP
	{ .signal = SIGSYS, .cb = syshandler_cb, .persist = true, .name = "PLUTO_SIGSYS", },
#endif
};

static void signal_handler_handler(evutil_socket_t fd UNUSED,
				   const short event, void *arg)
{
	passert(in_main_thread());
	passert(event & EV_SIGNAL);
	struct signal_handler *se = arg;
	dbg("processing signal %s", se->name);
	threadtime_t start = threadtime_start();
	se->cb();
	threadtime_stop(&start, SOS_NOBODY, "signal handler %s", se->name);
}

static void install_signal_handlers(void)
{
	for (unsigned i = 0; i < elemsof(signal_handlers); i++) {
		struct signal_handler *se = &signal_handlers[i];
		passert(!event_initialized(&se->ev));
		event_assign(&se->ev, pluto_eb, (evutil_socket_t)se->signal,
			     EV_SIGNAL | (se->persist ? EV_PERSIST : 0),
			     signal_handler_handler, se);
		passert(event_add(&se->ev, NULL) >= 0);
		dbg("signal event handler %s installed", se->name);
	}
}

static void free_signal_handlers(void)
{
	for (unsigned i = 0; i < elemsof(signal_handlers); i++) {
		struct signal_handler *se = &signal_handlers[i];
		passert(event_initialized(&se->ev));
		free_static_event(&se->ev);
		dbg("signal event handler %s uninstalled", se->name);
	}
}

static void list_signal_handlers(const struct fd *whackfd)
{
	for (unsigned i = 0; i < elemsof(signal_handlers); i++) {
		struct signal_handler *se = &signal_handlers[i];
		if (event_initialized(&se->ev) &&
		    event_pending(&se->ev, EV_SIGNAL, NULL) > 0) {
			whack_comment(whackfd, "signal event handler %s", se->name);
		}
	}
}

/*
 * Pluto events.
 */

static struct pluto_event *free_event_entry(struct pluto_event **evp)
{
	struct pluto_event *e = *evp;
	struct pluto_event *next = e->next;

	/* unlink this pluto_event from the list */
	if (e->ev != NULL) {
		event_free(e->ev);
		e->ev  = NULL;
	}

	dbg("%s: delref %s-pe@%p", __func__,
	    enum_name(&timer_event_names, e->ev_type), e);

	pfree(e);
	*evp = NULL;
	return next;
}

void free_server(void)
{
	if (pluto_eb == NULL) {
		/*
		 * exit_pluto() can call free_server() before
		 * init_server(); mumble something about using
		 * atexit().
		 */
		dbg("server event base not initialized");
		return;
	}

	struct pluto_event **head = &pluto_events_head;
	while (*head != NULL)
		*head = free_event_entry(head);
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

void link_pluto_event_list(struct pluto_event *e) {
	e->next = pluto_events_head;
	pluto_events_head = e;
}

/* delete pluto event (if any); leave *evp == NULL */
void delete_pluto_event(struct pluto_event **evp)
{
	if (*evp != NULL) {
		if ((*evp)->ev_state != NULL) {
			pexpect((*evp)->next == NULL);
			free_event_entry(evp);
		} else {
			for (struct pluto_event **pp = &pluto_events_head; ; ) {
				struct pluto_event *p = *pp;

				passert(p != NULL);

				if (p == *evp) {
					/* found it; unlink this from the list */
					*pp = free_event_entry(evp);
					break;
				}
				pp = &p->next;
			}
			*evp = NULL;
		}
	}
}

/*
 * A wrapper for libevent's event_new + event_add; any error is fatal.
 *
 * When setting up an event, this must be called last.  Else the event
 * can fire before setting it up has finished.
 */

void fire_timer_photon_torpedo(struct event **evp,
			       event_callback_fn cb, void *arg,
			       const deltatime_t delay)
{
	struct event *ev = event_new(pluto_eb, (evutil_socket_t)-1,
				     EV_TIMEOUT, cb, arg);
	passert(ev != NULL);
	/*
	 * Because this code can run on the non-main thread, the EV
	 * timer-event must be saved in its final destination before
	 * the event is enabled.
	 *
	 * Otherwise the event on the main thread will try to use EV
	 * before it has been saved by the helper thread.
	 */
	*evp = ev;
	struct timeval t = timeval_from_deltatime(delay);
	passert(event_add(ev, &t) >= 0);
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
	struct event *event;
};

static void resume_handler(evutil_socket_t fd UNUSED,
			   short events UNUSED, void *arg)
{
	struct resume_event *e = (struct resume_event *)arg;
	/*
	 * At one point, .ne_event was was being set after the event
	 * was enabled.  With multiple threads this resulted in a race
	 * where the event ran before .ne_event was set.  The
	 * pexpect() followed by the passert() demonstrated this - the
	 * pexpect() failed yet the passert() passed.
	 */
	pexpect(e->event != NULL);
	dbg("processing resume %s for #%lu", e->name, e->serialno);
	/*
	 * XXX: Don't confuse this and the "callback") code path.
	 * This unsuspends MD, "callback" does not.
	 */
	struct state *st = state_with_serialno(e->serialno);
	if (st == NULL) {
		threadtime_t start = threadtime_start();
		stf_status status = e->callback(NULL, NULL, e->context);
		pexpect(status == STF_SKIP_COMPLETE_STATE_TRANSITION);
		threadtime_stop(&start, e->serialno, "resume %s", e->name);
	} else {
		/* no previous state */
		pexpect(push_cur_state(st) == SOS_NOBODY);
		statetime_t start = statetime_start(st);
		struct msg_digest *md = unsuspend_md(st);

		/* trust nothing; so save everything */
		so_serial_t old_st = st->st_serialno;
		so_serial_t old_md_st = md != NULL && md->st != NULL ? md->st->st_serialno : SOS_NOBODY;
		enum ike_version ike_version = st->st_ike_version;
		/* when MD.ST it matches ST */
		pexpect(old_md_st == SOS_NOBODY || old_md_st == old_st);

		/* run the callback */
		stf_status status = e->callback(st, md, e->context);
		/* this may trash MD.ST */

		if (status == STF_SKIP_COMPLETE_STATE_TRANSITION) {
			/* MD.ST may have been freed! */
			dbg("resume %s for #%lu suppresed complete_v%d_state_transition()%s",
			    e->name, e->serialno, ike_version,
			    (old_md_st != SOS_NOBODY && md->st == NULL ? "; MD.ST disappeared" :
			     old_md_st != SOS_NOBODY && md->st != st ? "; MD.ST was switched" :
			     ""));
		} else if (old_md_st != SOS_NOBODY && md->st == NULL) {
			/*
			 * XXX: yes, MD.ST can be set to NULL.
			 *
			 * What happens is code deletes ST part way
			 * through a state transition and then tries
			 * to signal this by setting MD.ST to NULL
			 * (presumably it was previously set to ST).
			 *
			 * Of course all the intervening code still
			 * has references to the now-defunct state in
			 * local ST et.al. variables.  What could
			 * possibly go wrong .....
			 *
			 * The relevant code should instead return
			 * STF_deleteme (STF_ZOMBIFY?)  so that the
			 * delete can be performed by the state
			 * transition function.
			 *
			 * XXX/SML: There is no need to abort here in
			 * all cases where st is null, so moved this
			 * precondition to where it's needed.  Some
			 * previous logic appears to have been tooled
			 * to handle null state, and state might be
			 * null legitimately in certain failure cases
			 * (STF_FAIL + xxx).
			 *
			 * One condition for null state is when a new
			 * connection request packet arrives and there
			 * is no suitable matching configuration.  For
			 * example, ikev2_parent_inI1outR1() will
			 * return (STF_FAIL + NO_PROPOSAL_CHOSEN) but
			 * no state in this case.  While other
			 * failures may be better caught before this
			 * function is called, we should be graceful
			 * here.  And for this particular case, and
			 * similar failure cases, we want
			 * SEND_NOTIFICATION (below) to let the peer
			 * know why we've rejected the request.
			 *
			 * Another case of null state is return from
			 * ikev2_parent_inR1BoutI1B which returns
			 * STF_IGNORE.
			 *
			 * Another case occurs when we finish an
			 * Informational Exchange message that causes
			 * us to delete the IKE state.  In fact, that
			 * can be an STF_OK and yet have no remaining
			 * state object at this point.
			 */
			pexpect(ike_version == IKEv2);
			dbg("XXX: resume %s for #%lu deleted MD.ST", e->name, old_st);
		} else {
			/* XXX: mumble something about struct ike_version */
			switch (ike_version) {
			case IKEv1:
				/* no switching MD.ST */
				pexpect(old_md_st == SOS_NOBODY ?
					md == NULL || md->st == NULL :
					md != NULL && md->st != NULL && md->st->st_serialno == old_md_st);
				complete_v1_state_transition(md, status);
				break;
			case IKEv2:
				if (old_md_st == SOS_NOBODY) {
					pexpect(md == NULL || md->st == NULL);
				} else if (pexpect(md != NULL && md->st != NULL)) {
					if (md->st->st_serialno != old_st) {
						dbg("XXX: resume %s for #%lu switched MD.ST to #%lu",
						    e->name, old_st, md->st->st_serialno);
						st = md->st;
					}
				}
				complete_v2_state_transition(st, md, status);
				break;
			default:
				bad_case(ike_version);
			}
		}
		release_any_md(&md);
		statetime_stop(&start, "resume %s", e->name);
		pop_cur_state(SOS_NOBODY);
	}
	passert(e->event != NULL);
	event_free(e->event);
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
	fire_timer_photon_torpedo(&e->event, resume_handler, e,
				  deltatime(0)/*now*/);
}

/*
 * Schedule a callback now.
 */

struct callback_event {
	so_serial_t serialno;
	callback_cb *callback;
	void *context;
	const char *name;
	struct event *event;
};

static void callback_handler(evutil_socket_t fd UNUSED,
			     short events UNUSED, void *arg)
{
	struct callback_event *e = (struct callback_event *)arg;
	/*
	 * At one point, .event was was being set after the event was
	 * enabled.  With multiple threads this resulted in a race
	 * where the event ran before .event was set.  The pexpect()
	 * followed by the passert() demonstrated this - the pexpect()
	 * failed yet the passert() passed.
	 */
	pexpect(e->event != NULL);
	if (e->serialno == SOS_NOBODY) {
		dbg("processing callback %s", e->name);
		threadtime_t start = threadtime_start();
		e->callback(NULL, e->context);
		threadtime_stop(&start, SOS_NOBODY, "callback %s", e->name);
	} else {
		/*
		 * XXX: Don't confuse this and the "resume" code paths
		 * - this does not unsuspend MD, "resume" does.
		 */
		dbg("processing callback %s for #%lu", e->name, e->serialno);
		struct state *st = state_with_serialno(e->serialno);
		if (st == NULL) {
			threadtime_t start = threadtime_start();
			e->callback(NULL, e->context);
			threadtime_stop(&start, e->serialno, "callback %s", e->name);
		} else {
			so_serial_t old_state = push_cur_state(st);
			statetime_t start = statetime_start(st);
			e->callback(st, e->context);
			statetime_stop(&start, "callback %s", e->name);
			pop_cur_state(old_state);
		}
	}
	passert(e->event != NULL);
	event_free(e->event);
	pfree(e);
}

extern void schedule_callback(const char *name, so_serial_t serialno,
			      callback_cb *callback, void *context)
{
	struct callback_event tmp = {
		.serialno = serialno,
		.callback = callback,
		.context = context,
		.name = name,
	};
	struct callback_event *e = clone_thing(tmp, name);
	dbg("scheduling callback %s (#%lu)", e->name, e->serialno);
	/*
	 * Everything set up; arm and fire the timer's photon torpedo.
	 * Event may have even run on another thread before the below
	 * call returns.
	 */
	fire_timer_photon_torpedo(&e->event, callback_handler, e,
				  deltatime(0)/*now*/);
}

void attach_fd_read_sensor(struct event **ev, evutil_socket_t fd,
			   event_callback_fn cb, void *arg)
{
	passert(*ev == NULL);
	*ev = event_new(get_pluto_event_base(), fd,
			EV_READ|EV_PERSIST, cb, arg);
	passert(*ev != NULL);
	/* note call */
	passert(event_add(*ev, NULL) >= 0);
}

/*
 * XXX: Some of the callers save the struct pluto_event reference but
 * some do not.
 */
struct pluto_event *add_fd_read_event_handler(evutil_socket_t fd,
					      event_callback_fn cb, void *arg,
					      const char *name)
{
	passert(in_main_thread());
	pexpect(fd >= 0);
	struct pluto_event *e = alloc_thing(struct pluto_event, name);
	dbg("%s: newref %s-pe@%p", __func__, name, e);
	e->ev_type = EVENT_NULL;
	e->ev_name = name;
	link_pluto_event_list(e);
	/*
	 * Since this is on the main thread, and the event loop isn't
	 * running, there can't be a race between the event being
	 * added and the event firing.
	 */
	attach_fd_read_sensor(&e->ev, fd, cb, arg);
	return e; /* compatible with pluto_event_new for the time being */
}

/*
 * dump list of events to whacklog
 */
void timer_list(const struct fd *whackfd)
{
	monotime_t nw = mononow();

	whack_comment(whackfd,
		  "it is now: %jd seconds since monotonic epoch",
		  monosecs(nw));

	list_global_timers(whackfd, nw);
	list_signal_handlers(whackfd);

	for (struct pluto_event *ev = pluto_events_head;
	     ev != NULL; ev = ev->next) {
		pexpect(ev->ev_state == NULL);
		char buf[256] = "not timer based";

		if (ev->ev_type != EVENT_NULL) {
			snprintf(buf, sizeof(buf), "schd: %jd (in %jds)",
				 monosecs(ev->ev_time),
				 deltasecs(monotimediff(ev->ev_time, nw)));
		}
		whack_comment(whackfd, "event %s is %s", ev->ev_name, buf);
	}

	list_state_events(whackfd, nw);
}

void show_debug_status(struct show *s)
{
	WHACK_LOG(RC_COMMENT, show_fd(s), buf) {
		jam(buf, "debug:");
		if (cur_debugging & DBG_MASK) {
			jam(buf, " ");
			jam_enum_lset_short(buf, &debug_names,
					    "+", cur_debugging & DBG_MASK);
		}
		if (have_impairments()) {
			jam(buf, " impair: ");
			jam_impairments(buf, "+");
		}
	}
}

void show_fips_status(struct show *s)
{
	bool fips = libreswan_fipsmode();
	show_comment(s, "FIPS mode %s", !fips ?
		"disabled" :
		impair.force_fips ? "enabled [forced]" : "enabled");
}

static void huphandler_cb(void)
{
	/* logging is probably not signal handling / threa safe */
	libreswan_log("Pluto ignores SIGHUP -- perhaps you want \"whack --listen\"");
}

static void termhandler_cb(void)
{
	exit_pluto(PLUTO_EXIT_OK);
}

#ifdef HAVE_SECCOMP
static void syshandler_cb(void)
{
	loglog(RC_LOG_SERIOUS, "pluto received SIGSYS - possible SECCOMP violation!");
	if (pluto_seccomp_mode == SECCOMP_ENABLED) {
		loglog(RC_LOG_SERIOUS, "seccomp=enabled mandates daemon restart");
		exit_pluto(PLUTO_EXIT_SECCOMP_FAIL);
	}
}
#endif

#define PID_MAGIC 0x000f000cUL

struct pid_entry {
	unsigned long magic;
	struct list_entry hash_entry;
	pid_t pid;
	void *context;
	pluto_fork_cb *callback;
	so_serial_t serialno;
	const char *name;
	monotime_t start_time;
};

static void jam_pid_entry(struct lswlog *buf, const void *data)
{
	if (data == NULL) {
		jam(buf, "NULL pid");
	} else {
		const struct pid_entry *entry = data;
		passert(entry->magic == PID_MAGIC);
		if (entry->serialno != SOS_NOBODY) {
			jam(buf, "#%lu ", entry->serialno);
		}
		jam(buf, "%s pid %d", entry->name, entry->pid);
	}
}

static hash_t pid_hasher(const pid_t *pid)
{
	return hash_table_hasher(shunk2(pid, sizeof(*pid)), zero_hash);
}

static hash_t pid_entry_hasher(const void *data)
{
	const struct pid_entry *entry = data;
	passert(entry->magic == PID_MAGIC);
	return pid_hasher(&entry->pid);
}

static struct list_entry *pid_entry_entry(void *data)
{
	struct pid_entry *entry = data;
	passert(entry->magic == PID_MAGIC);
	return &entry->hash_entry;
}

static struct list_head pid_entry_slots[23];

static struct hash_table pids_hash_table = {
	.info = {
		.name = "pid table",
		.jam = jam_pid_entry,
	},
	.hasher = pid_entry_hasher,
	.entry = pid_entry_entry,
	.nr_slots = elemsof(pid_entry_slots),
	.slots = pid_entry_slots,
};

static void add_pid(const char *name, so_serial_t serialno, pid_t pid,
		    pluto_fork_cb *callback, void *context)
{
	dbg("forked child %d", pid);
	struct pid_entry *new_pid = alloc_thing(struct pid_entry, "fork pid");
	new_pid->magic = PID_MAGIC;
	new_pid->pid = pid;
	new_pid->callback = callback;
	new_pid->context = context;
	new_pid->serialno = serialno;
	new_pid->name = name;
	new_pid->start_time = mononow();
	add_hash_table_entry(&pids_hash_table, new_pid);
}

int pluto_fork(const char *name, so_serial_t serialno,
	       int op(void *context),
	       pluto_fork_cb *callback, void *context)
{
	pid_t pid = fork();
	switch (pid) {
	case -1:
		LOG_ERRNO(errno, "fork failed");
		return -1;
	case 0: /* child */
		reset_globals();
		exit(op(context));
		break;
	default: /* parent */
		add_pid(name, serialno, pid, callback, context);
		return pid;
	}
}

static pluto_fork_cb addconn_exited; /* type assertion */

static void addconn_exited(struct state *null_st UNUSED,
			   struct msg_digest *null_mdp UNUSED,
			   int status, void *context UNUSED)
{
	dbg("reaped addconn helper child (status %d)", status);
	addconn_child_pid = 0;
}

static void log_status(struct lswlog *buf, int status)
{
	lswlogf(buf, " (");
	if (WIFEXITED(status)) {
		lswlogf(buf, "exited with status %u",
			WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		lswlogf(buf, "terminated with signal %s (%d)",
			strsignal(WTERMSIG(status)),
			WTERMSIG(status));
	} else if (WIFSTOPPED(status)) {
		/* should not happen */
		lswlogf(buf, "stopped with signal %s (%d) but WUNTRACED not specified",
			strsignal(WSTOPSIG(status)),
			WSTOPSIG(status));
	} else if (WIFCONTINUED(status)) {
		lswlogf(buf, "continued");
	} else {
		lswlogf(buf, "wait status %x not recognized!", status);
	}
#ifdef WCOREDUMP
	if (WCOREDUMP(status)) {
		lswlogs(buf, ", core dumped");
	}
#endif
	lswlogs(buf, ")");
}

static void childhandler_cb(void)
{
	while (true) {
		int status;
		errno = 0;
		pid_t child = waitpid(-1, &status, WNOHANG);
		switch (child) {
		case -1: /* error? */
			if (errno == ECHILD) {
				dbg("waitpid returned ECHILD (no child processes left)");
			} else {
				LOG_ERRNO(errno, "waitpid unexpectedly failed");
			}
			return;
		case 0: /* nothing to do */
			dbg("waitpid returned nothing left to do (all child processes are busy)");
			return;
		default:
			LSWDBGP(DBG_BASE, buf) {
				lswlogf(buf, "waitpid returned pid %d",
					child);
				log_status(buf, status);
			}
			struct pid_entry *pid_entry = NULL;
			hash_t hash = pid_hasher(&child);
			struct list_head *bucket = hash_table_bucket(&pids_hash_table, hash);
			FOR_EACH_LIST_ENTRY_OLD2NEW(bucket, pid_entry) {
				passert(pid_entry->magic == PID_MAGIC);
				if (pid_entry->pid == child) {
					break;
				}
			}
			if (pid_entry == NULL) {
				LSWLOG(buf) {
					lswlogf(buf, "waitpid return unknown child pid %d",
						child);
					log_status(buf, status);
				}
			} else {
				struct state *st = state_with_serialno(pid_entry->serialno);
				if (pid_entry->serialno == SOS_NOBODY) {
					pid_entry->callback(NULL, NULL,
							    status, pid_entry->context);
				} else if (st == NULL) {
					LSWDBGP(DBG_BASE, buf) {
						jam_pid_entry(buf, pid_entry);
						lswlogs(buf, " disappeared");
					}
					pid_entry->callback(NULL, NULL,
							    status, pid_entry->context);
				} else {
					so_serial_t old_state = push_cur_state(st);
					struct msg_digest *md = unsuspend_md(st);
					if (DBGP(DBG_CPU_USAGE)) {
						deltatime_t took = monotimediff(mononow(), pid_entry->start_time);
						deltatime_buf dtb;
						DBG_log("#%lu waited %s for '%s' fork()",
							st->st_serialno, str_deltatime(took, &dtb),
							pid_entry->name);
					}
					statetime_t start = statetime_start(st);
					pid_entry->callback(st, md, status,
							    pid_entry->context);
					statetime_stop(&start, "callback for %s",
						       pid_entry->name);
					release_any_md(&md);
					pop_cur_state(old_state);
				}
				del_hash_table_entry(&pids_hash_table, pid_entry);
				pfree(pid_entry);
			}
			break;
		}
	}
}

#ifdef EVENT_SET_MEM_FUNCTIONS_IMPLEMENTED
static void *libevent_malloc(size_t size)
{
	void *ptr = uninitialized_malloc(size, __func__);
	dbg("%s: newref ptr-libevent@%p size %zu", __func__, ptr, size);
	return ptr;
}
static void *libevent_realloc(void *old, size_t size)
{
	void *new = uninitialized_realloc(old, size, __func__);
	if (old == NULL) {
		dbg("%s: newref ptr-libevent@%p size %zu", __func__, new, size);
	} else {
		/* enough to keep refcnt.awk happy */
		dbg("%s: delref ptr-libevent@%p", __func__, old);
		dbg("%s: newref ptr-libevent@%p size %zu", __func__, new, size);
	}
	return new;
}
static void libevent_free(void *ptr)
{
	dbg("%s: delref ptr-libevent@%p", __func__, ptr);
	pfree(ptr);
}
#endif

void init_server(void)
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
	libreswan_log("Initializing libevent in pthreads mode: headers: %s (%" PRIx32 "); library: %s (%" PRIx32 ")",
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

/* call_server listens for incoming ISAKMP packets and Whack messages,
 * and handles timer events.
 */
void call_server(char *conffile)
{
	init_hash_table(&pids_hash_table);

	/*
	 * setup basic events, CTL and SIGNALs
	 */

	dbg("Setting up events, loop start");

	add_fd_read_event_handler(ctl_fd, whack_handle_cb, NULL, "PLUTO_CTL_FD");

	install_signal_handlers();

	/* do_whacklisten() is now done by the addconn fork */

	/*
	 * fork to issue the command "ipsec addconn --autoall"
	 * (or vfork() when fork() isn't available, eg. on embedded platforms
	 * without MMU, like uClibc)
	 */
	{
		/* find a pathname to the addconn program */
		static const char addconn_name[] = "addconn";
		char addconn_path_space[4096]; /* plenty long? */
		ssize_t n;

#if !(defined(macintosh) || (defined(__MACH__) && defined(__APPLE__)))
		/*
		 * The program will be in the same directory as Pluto,
		 * so we use the symbolic link /proc/self/exe to
		 * tell us of the path prefix.
		 */
		n = readlink("/proc/self/exe", addconn_path_space,
			     sizeof(addconn_path_space));
		if (n < 0) {
# ifdef __uClibc__
			/*
			 * Some noMMU systems have no proc/self/exe.
			 * Try without path.
			 */
			n = 0;
# else
			EXIT_LOG_ERRNO(errno,
				       "readlink(\"/proc/self/exe\") failed in call_server()");
# endif
		}
#else
		/* Hardwire a path */
		/* ??? This is wrong. Should end up in a resource_dir on MacOSX -- Paul */
		n = jam_str(addconn_path_space,
				sizeof(addconn_path_space),
				"/usr/local/libexec/ipsec/") -
			addcon_path_space;
#endif

		/* strip any final name from addconn_path_space */
		while (n > 0 && addconn_path_space[n - 1] != '/')
			n--;

		if ((size_t)n >
		    sizeof(addconn_path_space) - sizeof(addconn_name))
			exit_log("path to %s is too long", addconn_name);

		strcpy(addconn_path_space + n, addconn_name);

		if (access(addconn_path_space, X_OK) < 0)
			EXIT_LOG_ERRNO(errno, "%s missing or not executable",
				       addconn_path_space);

		char *newargv[] = { DISCARD_CONST(char *, "addconn"),
				    DISCARD_CONST(char *, "--ctlsocket"),
				    DISCARD_CONST(char *, ctl_addr.sun_path),
				    DISCARD_CONST(char *, "--config"),
				    DISCARD_CONST(char *, conffile),
				    DISCARD_CONST(char *, "--autoall"), NULL };
		char *newenv[] = { NULL };
#if USE_VFORK
		addconn_child_pid = vfork(); /* for better, for worse, in sickness and health..... */
#elif USE_FORK
		addconn_child_pid = fork();
#else
#error "addconn requires USE_VFORK or USE_FORK"
#endif
		if (addconn_child_pid == 0) {
			/*
			 * Child
			 */
			execve(addconn_path_space, newargv, newenv);
			_exit(42);
		}

		/* Parent */

		dbg("created addconn helper (pid:%d) using %s+execve",
		    addconn_child_pid, USE_VFORK ? "vfork" : "fork");
		add_pid("addconn", SOS_NOBODY, addconn_child_pid,
			addconn_exited, NULL);
	}

	/* parent continues */

#ifdef HAVE_SECCOMP
	init_seccomp_main();
#else
	libreswan_log("seccomp security not supported");
#endif

	int r = event_base_loop(pluto_eb, 0);
	passert(r == 0);
}

bool ev_before(struct pluto_event *pev, deltatime_t delay)
{
	struct timeval timeout;
	if (!(event_pending(pev->ev, EV_TIMEOUT, &timeout) & EV_TIMEOUT)) {
		return false;
	}
	return deltatime_cmp(deltatime_from_timeval(timeout), <, delay);
}

void set_whack_pluto_ddos(enum ddos_mode mode)
{
	if (mode == pluto_ddos_mode) {
		loglog(RC_LOG, "pluto DDoS protection remains in %s mode",
		mode == DDOS_AUTO ? "auto-detect" : mode == DDOS_FORCE_BUSY ? "active" : "unlimited");
		return;
	}

	pluto_ddos_mode = mode;
	loglog(RC_LOG, "pluto DDoS protection mode set to %s",
		mode == DDOS_AUTO ? "auto-detect" : mode == DDOS_FORCE_BUSY ? "active" : "unlimited");
}

struct event_base *get_pluto_event_base(void)
{
	return pluto_eb;
}
