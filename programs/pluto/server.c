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
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 D. Hugh Redelmeier <hugh@mimosa.com>
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
#ifdef SOLARIS
# include <sys/sockio.h>        /* for Solaris 2.6: defines SIOCGIFCONF */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/poll.h>   /* only used for forensic poll call */
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

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
#  include <asm/types.h>        /* for __u8, __u32 */
#  include <linux/errqueue.h>
#  include <sys/uio.h>          /* struct iovec */
#endif

#include <libreswan.h>

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
#include "udpfromto.h"

#include "nat_traversal.h"

#include "lswfips.h"

#ifdef HAVE_SECCOMP
# include "pluto_seccomp.h"
#endif

#include "pluto_stats.h"
#include "hash_table.h"
#include "ip_address.h"

/*
 *  Server main loop and socket initialization routines.
 */

char *pluto_vendorid;

static pid_t addconn_child_pid = 0;

/* list of interface devices */
struct iface_list interface_dev;

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

	LIST_INIT(&interface_dev);

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

enum ddos_mode pluto_ddos_mode = DDOS_AUTO; /* default to auto-detect */
#ifdef HAVE_SECCOMP
enum seccomp_mode pluto_seccomp_mode = SECCOMP_DISABLED;
#endif
unsigned int pluto_max_halfopen = DEFAULT_MAXIMUM_HALFOPEN_IKE_SA;
unsigned int pluto_ddos_threshold = DEFAULT_IKE_SA_DDOS_THRESHOLD;
deltatime_t pluto_shunt_lifetime = DELTATIME_INIT(PLUTO_SHUNT_LIFE_DURATION_DEFAULT);

unsigned int pluto_sock_bufsize = IKE_BUF_AUTO; /* use system values */
bool pluto_sock_errqueue = TRUE; /* Enable MSG_ERRQUEUE on IKE socket */

struct iface_port  *interfaces = NULL;  /* public interfaces */

/* Initialize the interface sockets. */

static void mark_ifaces_dead(void)
{
	struct iface_port *p;

	for (p = interfaces; p != NULL; p = p->next)
		p->change = IFN_DELETE;
}

static void free_dead_iface_dev(struct iface_dev *id)
{
	if (--id->id_count == 0) {
		pfree(id->id_vname);
		pfree(id->id_rname);

		LIST_REMOVE(id, id_entry);

		pfree(id);
	}
}

static void free_dead_ifaces(void)
{
	struct iface_port *p;
	bool some_dead = FALSE,
	     some_new = FALSE;

	for (p = interfaces; p != NULL; p = p->next) {
		if (p->change == IFN_DELETE) {
			ipstr_buf b;

			libreswan_log("shutting down interface %s/%s %s:%d",
				      p->ip_dev->id_vname,
				      p->ip_dev->id_rname,
				      ipstr(&p->ip_addr, &b), p->port);
			some_dead = TRUE;
		} else if (p->change == IFN_ADD) {
			some_new = TRUE;
		}
	}

	if (some_dead) {
		struct iface_port **pp;

		release_dead_interfaces();
		delete_states_dead_interfaces();
		for (pp = &interfaces; (p = *pp) != NULL; ) {
			if (p->change == IFN_DELETE) {
				struct iface_dev *id;

				*pp = p->next; /* advance *pp */

				if (p->pev != NULL) {
					delete_pluto_event(&p->pev);
				}

				close(p->fd);

				id = p->ip_dev;
				pfree(p);

				free_dead_iface_dev(id);
			} else {
				pp = &p->next; /* advance pp */
			}
		}
	}

	/* this must be done after the release_dead_interfaces
	 * in case some to the newly unoriented connections can
	 * become oriented here.
	 */
	if (some_dead || some_new)
		check_orientations();
}

void free_ifaces(void)
{
	mark_ifaces_dead();
	free_dead_ifaces();
}

struct raw_iface *static_ifn = NULL;

int create_socket(struct raw_iface *ifp, const char *v_name, int port)
{
	int fd = socket(addrtypeof(&ifp->addr), SOCK_DGRAM, IPPROTO_UDP);
	int fcntl_flags;
	static const int on = TRUE;     /* by-reference parameter; constant, we hope */

	if (fd < 0) {
		LOG_ERRNO(errno, "socket() in create_socket()");
		return -1;
	}

	/* Set socket Nonblocking */
	if ((fcntl_flags = fcntl(fd, F_GETFL)) >= 0) {
		if (!(fcntl_flags & O_NONBLOCK)) {
			fcntl_flags |= O_NONBLOCK;
			if (fcntl(fd, F_SETFL, fcntl_flags) == -1) {
				LOG_ERRNO(errno, "fcntl(,, O_NONBLOCK) in create_socket()");
			}
		}
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		LOG_ERRNO(errno, "fcntl(,, FD_CLOEXEC) in create_socket()");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&on, sizeof(on)) < 0) {
		LOG_ERRNO(errno, "setsockopt SO_REUSEADDR in create_socket()");
		close(fd);
		return -1;
	}

#ifdef SO_PRIORITY
	static const int so_prio = 6; /* rumored maximum priority, might be 7 on linux? */
	if (setsockopt(fd, SOL_SOCKET, SO_PRIORITY,
			(const void *)&so_prio, sizeof(so_prio)) < 0) {
		LOG_ERRNO(errno, "setsockopt(SO_PRIORITY) in find_raw_ifaces4()");
		/* non-fatal */
	}
#endif

	if (pluto_sock_bufsize != IKE_BUF_AUTO) {
#if defined(linux)
		/*
		 * Override system maximum
		 * Requires CAP_NET_ADMIN
		 */
		int so_rcv = SO_RCVBUFFORCE;
		int so_snd = SO_SNDBUFFORCE;
#else
		int so_rcv = SO_RCVBUF;
		int so_snd = SO_SNDBUF;
#endif
		if (setsockopt(fd, SOL_SOCKET, so_rcv,
			(const void *)&pluto_sock_bufsize, sizeof(pluto_sock_bufsize)) < 0) {
				LOG_ERRNO(errno, "setsockopt(SO_RCVBUFFORCE) in find_raw_ifaces4()");
		}
		if (setsockopt(fd, SOL_SOCKET, so_snd,
			(const void *)&pluto_sock_bufsize, sizeof(pluto_sock_bufsize)) < 0) {
				LOG_ERRNO(errno, "setsockopt(SO_SNDBUFFORCE) in find_raw_ifaces4()");
		}
	}



	/* To improve error reporting.  See ip(7). */
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	if (pluto_sock_errqueue) {
		if (setsockopt(fd, SOL_IP, IP_RECVERR, (const void *)&on, sizeof(on)) < 0) {
			LOG_ERRNO(errno, "setsockopt IP_RECVERR in create_socket()");
			close(fd);
			return -1;
		}
	}
#endif

	/* With IPv6, there is no fragmentation after
	 * it leaves our interface.  PMTU discovery
	 * is mandatory but doesn't work well with IKE (why?).
	 * So we must set the IPV6_USE_MIN_MTU option.
	 * See draft-ietf-ipngwg-rfc2292bis-01.txt 11.1
	 */
#ifdef IPV6_USE_MIN_MTU /* YUCK: not always defined */
	if (addrtypeof(&ifp->addr) == AF_INET6 &&
	    setsockopt(fd, SOL_SOCKET, IPV6_USE_MIN_MTU,
		       (const void *)&on, sizeof(on)) < 0) {
		LOG_ERRNO(errno, "setsockopt IPV6_USE_MIN_MTU in process_raw_ifaces()");
		close(fd);
		return -1;
	}
#endif

	/*
	 * NETKEY requires us to poke an IPsec policy hole that allows
	 * IKE packets, unlike KLIPS which implicitly always allows
	 * plaintext IKE.  This installs one IPsec policy per socket
	 * but this function is called for each: IPv4 port 500 and
	 * 4500 IPv6 port 500
	 */
	if (kernel_ops->poke_ipsec_policy_hole != NULL &&
	    !kernel_ops->poke_ipsec_policy_hole(ifp, fd)) {
		return -1;
	}

	setportof(htons(port), &ifp->addr);
	if (bind(fd, sockaddrof(&ifp->addr), sockaddrlenof(&ifp->addr)) < 0) {
		ipstr_buf b;

		LOG_ERRNO(errno, "bind() for %s/%s %s:%u in process_raw_ifaces()",
			  ifp->name, v_name,
			  ipstr(&ifp->addr, &b), (unsigned) port);
		close(fd);
		return -1;
	}
	setportof(htons(pluto_port), &ifp->addr);

#if defined(HAVE_UDPFROMTO)
	/* we are going to use udpfromto.c, so initialize it */
	if (udpfromto_init(fd) == -1) {
		LOG_ERRNO(errno, "udpfromto_init() returned an error - ignored");
	}
#endif

	/* poke a hole for IKE messages in the IPsec layer */
	if (kernel_ops->exceptsocket != NULL) {
		if (!kernel_ops->exceptsocket(fd, AF_INET)) {
			close(fd);
			return -1;
		}
	}

	return fd;
}

static struct pluto_event *free_event_entry(struct pluto_event **evp)
{
	struct pluto_event *e = *evp;
	struct pluto_event *next = e->next;

	/* unlink this pluto_event from the list */
	if (e->ev != NULL) {
		event_free(e->ev);
		e->ev  = NULL;
	}

	DBG(DBG_LIFECYCLE,
			const char *en = enum_name(&timer_event_names, e->ev_type);
			DBG_log("%s: release %s-pe@%p", __func__, en, e));

	pfree(e);
	*evp = NULL;
	return next;
}

static void unlink_pluto_event_list(struct pluto_event **evp) {
	struct pluto_event **pp;
	struct pluto_event *p;
	struct pluto_event *e = *evp;

	for (pp = &pluto_events_head; (p = *pp) != NULL; pp = &p->next) {
		if (p == e) {
			*pp = free_event_entry(evp); /* unlink this entry from the list */
			return;
		}
	}
}

void free_pluto_event_list(void)
{
	struct pluto_event **head = &pluto_events_head;
	while (*head != NULL)
		*head = free_event_entry(head);

}

void link_pluto_event_list(struct pluto_event *e) {
	e->next = pluto_events_head;
	pluto_events_head = e;
}

void delete_pluto_event(struct pluto_event **evp)
{
	if (*evp == NULL) {
		DBG(DBG_CONTROLMORE, DBG_log("%s cannot delete NULL event", __func__));
		return;
	}

	unlink_pluto_event_list(evp);
}

/*
 * A wrapper for libevent's event_new + event_add; any error is fatal.
 *
 * When setting up an event, this must be called last.  Else the event
 * can fire before setting it up has finished.
 */

static void fire_event_photon_torpedo(struct event **evp,
				      evutil_socket_t fd, short events,
				      event_callback_fn cb, void *arg,
				      const deltatime_t *delay)
{
	struct event *ev = event_new(pluto_eb, fd, events, cb, arg);
	passert(ev != NULL);
	/*
	 * EV must be saved in its final destination before the event
	 * is enabled.
	 *
	 * Otherwise the event on the main thread will try to use the
	 * saved EV before it has been saved by the helper thread.
	 */
	*evp = ev;

	int r;
	if (delay == NULL) {
		r = event_add(ev, NULL);
	} else {
		struct timeval t = deltatimeval(*delay);
		r = event_add(ev, &t);
	}
	passert(r >= 0);
}

/*
 * Schedule an event now.
 *
 * Unlike pluto_event_add(), it can't be canceled, can only run once,
 * doesn't show up in the event list, and leaks when the event-loop
 * aborts (like a few others).
 *
 * However, unlike pluto_event_add(), it works from any thread, and
 * cleans up after the event has run.
 */

struct now_event {
	pluto_event_now_cb *ne_callback;
	void *ne_context;
	const char *ne_name;
	struct event *ne_event;
	so_serial_t ne_serialno;
};

static void schedule_event_now_cb(evutil_socket_t fd UNUSED,
				  short events UNUSED,
				  void *arg)
{
	struct now_event *ne = (struct now_event *)arg;
	DBG(DBG_CONTROLMORE,
	    DBG_log("executing now-event %s for %lu",
		    ne->ne_name, ne->ne_serialno));

	/*
	 * At one point, .ne_event was was being set after the event
	 * was enabled.  With multiple threads this resulted in a race
	 * where the event ran before .ne_event was set.  The
	 * pexpect() followed by the passert() demonstrated this - the
	 * pexpect() failed yet the passert() passed.
	 */
	pexpect(ne->ne_event != NULL);
	struct state *st = state_with_serialno(ne->ne_serialno);
	if (st == NULL) {
		ne->ne_callback(NULL, NULL, ne->ne_context);
	} else {
		struct msg_digest *md = unsuspend_md(st);
		so_serial_t old_state = push_cur_state(st);
		ne->ne_callback(st, &md, ne->ne_context);
		release_any_md(&md);
		pop_cur_state(old_state);
	}
	passert(ne->ne_event != NULL);
	event_del(ne->ne_event);
	pfree(ne);
}

void pluto_event_now(const char *name, so_serial_t serialno,
		     pluto_event_now_cb *callback, void *context)
{
	struct now_event *ne = alloc_thing(struct now_event, name);
	ne->ne_callback = callback;
	ne->ne_context = context;
	ne->ne_name = name;
	ne->ne_serialno = serialno;
	DBG(DBG_CONTROLMORE,
	    DBG_log("scheduling now-event %s for #%lu",
		    ne->ne_name, ne->ne_serialno));

	/*
	 * Everything set up; arm and fire torpedo.  Event may have
	 * even run before the below function returns.
	 */
	static const deltatime_t no_delay = DELTATIME_INIT(0);
	fire_event_photon_torpedo(&ne->ne_event,
				  NULL_FD, EV_TIMEOUT,
				  schedule_event_now_cb, ne,
				  &no_delay);
}

/*
 * XXX: custom version of event new used only by timer.c.  If you're
 * looking for how to set up a timer, then don't look here and don't
 * look at timer.c.  Why?
 */
void timer_private_pluto_event_new(struct event **evp,
				   evutil_socket_t fd, short events,
				   event_callback_fn cb, void *arg,
				   deltatime_t delay)
{
	fire_event_photon_torpedo(evp, fd, events, cb, arg, &delay);
}

struct pluto_event *pluto_event_add(evutil_socket_t fd, short events,
				    event_callback_fn cb, void *arg,
				    const deltatime_t *delay,
				    const char *name)
{
	struct pluto_event *e = alloc_thing(struct pluto_event, name);
	e->ev_type = EVENT_NULL;
	e->ev_name = name;
	link_pluto_event_list(e);
	if (delay != NULL) {
		e->ev_time = monotimesum(mononow(), *delay);
	}
	fire_event_photon_torpedo(&e->ev, fd, events, cb, arg, delay);
	return e; /* compaitable with pluto_event_new for the time being */
}

/*
 * dump list of events to whacklog
 */
void timer_list(void)
{
	monotime_t nw;
	struct pluto_event *ev = pluto_events_head;

	if (ev == NULL) {
		/* Just paranoid */
		whack_log(RC_LOG, "no events are queued");
		return;
	}

	nw = mononow();

	whack_log(RC_LOG, "It is now: %jd seconds since monotonic epoch",
		  monosecs(nw));

	while (ev != NULL) {
		struct state *st = ev->ev_state;
		char buf[256] = "not timer based";

		if (ev->ev_type != EVENT_NULL) {
			snprintf(buf, sizeof(buf), "schd: %jd (in %jds)",
				 monosecs(ev->ev_time),
				 deltasecs(monotimediff(ev->ev_time, nw)));
		}

		if (st != NULL && st->st_connection != NULL) {
			char cib[CONN_INST_BUF];
			whack_log(RC_LOG, "event %s is %s \"%s\"%s #%lu",
					ev->ev_name, buf,
					st->st_connection->name,
					fmt_conn_instance(st->st_connection, cib),
					st->st_serialno);
		} else {
			whack_log(RC_LOG, "event %s is %s", ev->ev_name, buf);
		}

		ev = ev->next;
	}
}

void find_ifaces(bool rm_dead)
{
	struct iface_port *ifp;

	if (rm_dead)
		mark_ifaces_dead();

	if (kernel_ops->process_ifaces != NULL) {
		kernel_ops->process_ifaces(find_raw_ifaces4());
		kernel_ops->process_ifaces(find_raw_ifaces6());
		kernel_ops->process_ifaces(static_ifn);
	}

	if (rm_dead)
		free_dead_ifaces(); /* ditch remaining old entries */

	if (interfaces == NULL)
		loglog(RC_LOG_SERIOUS, "no public interfaces found");

	if (listening) {
		for (ifp = interfaces; ifp != NULL; ifp = ifp->next) {
			if (ifp->pev != NULL) {
				delete_pluto_event(&ifp->pev);
				DBG_log("refresh. setup callback for interface %s:%u %d",
						ifp->ip_dev->id_rname, ifp->port,
						ifp->fd);
			}
			char prefix[] ="INTERFACE_FD-";
			char ifp_str[sizeof(prefix) +
				strlen(ifp->ip_dev->id_rname) +
				5 + 1 + 1 /* : + NUL */];
			snprintf(ifp_str, sizeof(ifp_str), "%s:%u",
					ifp->ip_dev->id_rname, ifp->port);
			ifp->pev = pluto_event_add(ifp->fd,
					EV_READ | EV_PERSIST, comm_handle_cb,
					ifp, NULL, ifp_str);
			DBG_log("setup callback for interface %s fd %d",
					ifp_str, ifp->fd);
		}
	}
}

struct iface_port *lookup_iface_ip(ip_address *ip, uint16_t port)
{
	struct iface_port *p;
	for (p = interfaces; p != NULL; p = p->next) {
		if (sameaddr(ip, &p->ip_addr) && (p->port == port))
			return p;
	}

	return NULL;
}

void show_ifaces_status(void)
{
	struct iface_port *p;

	for (p = interfaces; p != NULL; p = p->next) {
		ipstr_buf b;

		whack_log(RC_COMMENT, "interface %s/%s %s@%d",
			  p->ip_dev->id_vname, p->ip_dev->id_rname,
			  ipstr(&p->ip_addr, &b), p->port);
	}
	whack_log(RC_COMMENT, " ");     /* spacer */
}

void show_debug_status(void)
{
	LSWLOG_WHACK(RC_COMMENT, buf) {
		lswlogs(buf, "debug:");
		if (cur_debugging & DBG_MASK) {
			lswlogs(buf, " ");
			lswlog_enum_lset_short(buf, &debug_names,
					       "+", cur_debugging & DBG_MASK);
		}
		if (cur_debugging & IMPAIR_MASK) {
			lswlogs(buf, " impair: ");
			lswlog_enum_lset_short(buf, &impair_names,
					       "+", cur_debugging & IMPAIR_MASK);
		}
	}
}

void show_fips_status(void)
{
#ifdef FIPS_CHECK
	bool fips = libreswan_fipsmode();
#else
	bool fips = FALSE;
#endif
	whack_log(RC_COMMENT, "FIPS mode %s", !fips ?
#ifdef FIPS_CHECK
		"disabled" :
#else
		"disabled [support not compiled in]" :
#endif
		IMPAIR(FORCE_FIPS) ? "enabled [forced]" : "enabled");
}

static void huphandler_cb(int unused UNUSED, const short event UNUSED, void *arg UNUSED)
{
	/* logging is probably not signal handling / threa safe */
	libreswan_log("Pluto ignores SIGHUP -- perhaps you want \"whack --listen\"");
}

static void termhandler_cb(int unused UNUSED, const short event UNUSED, void *arg UNUSED)
{
	exit_pluto(PLUTO_EXIT_OK);
}

#ifdef HAVE_SECCOMP
static void syshandler_cb(int unused UNUSED, const short event UNUSED, void *arg UNUSED)
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
};

static size_t log_pid_entry(struct lswlog *buf, void *data)
{
	if (data == NULL) {
		return lswlogs(buf, "NULL pid");
	} else {
		struct pid_entry *entry = (struct pid_entry*)data;
		passert(entry->magic == PID_MAGIC);
		size_t size = 0;
		if (entry->serialno != SOS_NOBODY) {
			size += lswlogf(buf, "#%lu ", entry->serialno);
		}
		size += lswlogf(buf, "%s pid %d", entry->name, entry->pid);
		return size;
	}
}

static size_t hash_pid_entry(void *data)
{
	struct pid_entry *entry = (struct pid_entry*)data;
	passert(entry->magic == PID_MAGIC);
	return entry->pid;
}

static struct list_head pid_entry_slots[23];

static struct hash_table pids_hash_table = {
	.info = {
		.debug = DBG_CONTROLMORE,
		.name = "pid table",
		.log = log_pid_entry,
	},
	.hash = hash_pid_entry,
	.nr_slots = elemsof(pid_entry_slots),
	.slots = pid_entry_slots,
};

static void add_pid(const char *name, so_serial_t serialno, pid_t pid,
		    pluto_fork_cb *callback, void *context)
{
	DBG(DBG_CONTROL,
	    DBG_log("forked child %d", pid));
	struct pid_entry *new_pid = alloc_thing(struct pid_entry, "fork pid");
	new_pid->magic = PID_MAGIC;
	new_pid->pid = pid;
	new_pid->callback = callback;
	new_pid->context = context;
	new_pid->serialno = serialno;
	new_pid->name = name;
	add_hash_table_entry(&pids_hash_table,
			     new_pid, &new_pid->hash_entry);
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
			   struct msg_digest **null_mdp UNUSED,
			   int status, void *context UNUSED)
{
	DBG(DBG_CONTROLMORE,
	   DBG_log("reaped addconn helper child (status %d)", status));
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

static void childhandler_cb(int unused UNUSED, const short event UNUSED, void *arg UNUSED)
{
	while (true) {
		int status;
		errno = 0;
		pid_t child = waitpid(-1, &status, WNOHANG);
		switch (child) {
		case -1: /* error? */
			if (errno == ECHILD) {
				DBG(DBG_CONTROLMORE,
				    DBG_log("waitpid returned ECHILD (no child processes left)"));
			} else {
				LOG_ERRNO(errno, "waitpid unexpectedly failed");
			}
			return;
		case 0: /* nothing to do */
			DBG(DBG_CONTROLMORE,
			    DBG_log("waitpid returned nothing left to do (all child processes are busy)"));
			return;
		default:
			LSWDBGP(DBG_CONTROLMORE, buf) {
				lswlogf(buf, "waitpid returned pid %d",
					child);
				log_status(buf, status);
			}
			struct pid_entry *pid_entry = NULL;
			struct list_head *head = hash_table_slot_by_hash(&pids_hash_table, child);
			FOR_EACH_LIST_ENTRY_OLD2NEW(head, pid_entry) {
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
					LSWDBGP(DBG_CONTROLMORE, buf) {
						log_pid_entry(buf, pid_entry);
						lswlogs(buf, " disappeared");
					}
					pid_entry->callback(NULL, NULL,
							    status, pid_entry->context);
				} else {
					so_serial_t old_state = push_cur_state(st);
					struct msg_digest *md = unsuspend_md(st);
					pid_entry->callback(st, &md, status,
							    pid_entry->context);
					release_any_md(&md);
					pop_cur_state(old_state);
				}
				del_hash_table_entry(&pids_hash_table,
						     &pid_entry->hash_entry);
				pfree(pid_entry);
			}
			break;
		}
	}
}

void init_event_base(void) {
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
	pluto_eb = event_base_new();
	passert(pluto_eb != NULL);
	int s = evthread_make_base_notifiable(pluto_eb);
	passert(s >= 0);
}

/* call_server listens for incoming ISAKMP packets and Whack messages,
 * and handles timer events.
 */
void call_server(void)
{
	init_hash_table(&pids_hash_table);

	/*
	 * setup basic events, CTL and SIGNALs
	 */

	DBG(DBG_CONTROLMORE, DBG_log("Setting up events, loop start"));

	pluto_event_add(ctl_fd, EV_READ | EV_PERSIST, whack_handle_cb, NULL,
			NULL, "PLUTO_CTL_FD");

	pluto_event_add(SIGCHLD, EV_SIGNAL | EV_PERSIST, childhandler_cb, NULL, NULL,
			"PLUTO_SIGCHLD");

	pluto_event_add(SIGTERM, EV_SIGNAL, termhandler_cb, NULL, NULL,
			"PLUTO_SIGTERM");

	pluto_event_add(SIGHUP, EV_SIGNAL|EV_PERSIST, huphandler_cb, NULL,
			NULL,  "PLUTO_SIGHUP");

#ifdef HAVE_SECCOMP
	pluto_event_add(SIGSYS, EV_SIGNAL, syshandler_cb, NULL, NULL,
			"PLUTO_SIGSYS");
#endif

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

		DBG(DBG_CONTROLMORE,
		    DBG_log("created addconn helper (pid:%d) using %s+execve",
			    addconn_child_pid, USE_VFORK ? "vfork" : "fork"));
		add_pid("addconn", SOS_NOBODY, addconn_child_pid,
			addconn_exited, NULL);
	}

	/* parent continues */

#ifdef HAVE_SECCOMP
	switch (pluto_seccomp_mode) {
	case SECCOMP_ENABLED:
		init_seccomp_main(SCMP_ACT_KILL);
		break;
	case SECCOMP_TOLERANT:
		init_seccomp_main(SCMP_ACT_TRAP);
		break;
	case SECCOMP_DISABLED:
		break;
	default:
		bad_case(pluto_seccomp_mode);
	}
#else
	libreswan_log("seccomp security not supported");
#endif

	int r = event_base_loop(pluto_eb, 0);
	passert(r == 0);
}

/* Process any message on the MSG_ERRQUEUE
 *
 * This information is generated because of the IP_RECVERR socket option.
 * The API is sparsely documented, and may be LINUX-only, and only on
 * fairly recent versions at that (hence the conditional compilation).
 *
 * - ip(7) describes IP_RECVERR
 * - recvmsg(2) describes MSG_ERRQUEUE
 * - readv(2) describes iovec
 * - cmsg(3) describes how to process auxiliary messages
 *
 * ??? we should link this message with one we've sent
 * so that the diagnostic can refer to that negotiation.
 *
 * ??? how long can the messge be?
 *
 * ??? poll(2) has a very incomplete description of the POLL* events.
 * We assume that POLLIN, POLLOUT, and POLLERR are all we need to deal with
 * and that POLLERR will be on iff there is a MSG_ERRQUEUE message.
 *
 * We have to code around a couple of surprises:
 *
 * - Select can say that a socket is ready to read from, and
 *   yet a read will hang.  It turns out that a message available on the
 *   MSG_ERRQUEUE will cause select to say something is pending, but
 *   a normal read will hang.  poll(2) can tell when a MSG_ERRQUEUE
 *   message is pending.
 *
 *   This is dealt with by calling check_msg_errqueue after select
 *   has indicated that there is something to read, but before the
 *   read is performed.  check_msg_errqueue will return TRUE if there
 *   is something left to read.
 *
 * - A write to a socket may fail because there is a pending MSG_ERRQUEUE
 *   message, without there being anything wrong with the write.  This
 *   makes for confusing diagnostics.
 *
 *   To avoid this, we call check_msg_errqueue before a write.  True,
 *   there is a race condition (a MSG_ERRQUEUE message might arrive
 *   between the check and the write), but we should eliminate many
 *   of the problematic events.  To narrow the window, the poll(2)
 *   will await until an event happens (in the case or a write,
 *   POLLOUT; this should be benign for POLLIN).
 */

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
static bool check_msg_errqueue(const struct iface_port *ifp, short interest, const char *before)
{
	struct pollfd pfd;
	int again_count = 0;

	pfd.fd = ifp->fd;
	pfd.events = interest | POLLPRI | POLLOUT;

	while (pfd.revents = 0,
	       poll(&pfd, 1, -1) > 0 && (pfd.revents & POLLERR)) {
		uint8_t buffer[3000]; /* hope that this is big enough */
		union {
			struct sockaddr sa;
			struct sockaddr_in sa_in4;
			struct sockaddr_in6 sa_in6;
		} from;

		ssize_t packet_len;

		struct msghdr emh;
		struct iovec eiov;
		union {
			/* force alignment (not documented as necessary) */
			struct cmsghdr ecms;

			/* how much space is enough? */
			unsigned char space[256];
		} ecms_buf;

		struct cmsghdr *cm;
		char fromstr[sizeof(" for message to  port 65536") +
			     INET6_ADDRSTRLEN];
		struct state *sender = NULL;

		zero(&from.sa);

		emh.msg_name = &from.sa; /* ??? filled in? */
		emh.msg_namelen = sizeof(from);
		emh.msg_iov = &eiov;
		emh.msg_iovlen = 1;
		emh.msg_control = &ecms_buf;
		emh.msg_controllen = sizeof(ecms_buf);
		emh.msg_flags = 0;

		eiov.iov_base = buffer; /* see readv(2) */
		eiov.iov_len = sizeof(buffer);

		packet_len = recvmsg(ifp->fd, &emh, MSG_ERRQUEUE);

		if (emh.msg_flags & MSG_TRUNC)
			libreswan_log("recvmsg: received truncated IKE packet (MSG_TRUNC)");

		if (packet_len == -1) {
			if (errno == EAGAIN) {
				/* 32 is picked from thin air */
				if (again_count == 32) {
					loglog(RC_LOG_SERIOUS, "recvmsg(,, MSG_ERRQUEUE): given up reading socket after 32 EAGAIN errors");
					return FALSE;
				}
				again_count++;
				LOG_ERRNO(errno,
					  "recvmsg(,, MSG_ERRQUEUE) on %s failed (noticed before %s) (attempt %d)",
					  ifp->ip_dev->id_rname, before, again_count);
				continue;
			} else {
				LOG_ERRNO(errno,
					  "recvmsg(,, MSG_ERRQUEUE) on %s failed (noticed before %s)",
					  ifp->ip_dev->id_rname, before);
				break;
			}
		} else if (packet_len == (ssize_t)sizeof(buffer)) {
			libreswan_log(
				"MSG_ERRQUEUE message longer than %zu bytes; truncated",
				sizeof(buffer));
		} else if (packet_len >= (ssize_t)sizeof(struct isakmp_hdr)) {
			sender = find_likely_sender((size_t) packet_len, buffer);
		}

		if (packet_len > 0) {
			DBG_cond_dump(DBG_ALL, "rejected packet:\n", buffer,
			      packet_len);
		}

		DBG_cond_dump(DBG_ALL, "control:\n", emh.msg_control,
			      emh.msg_controllen);

		/* ??? Andi Kleen <ak@suse.de> and misc documentation
		 * suggests that name will have the original destination
		 * of the packet.  We seem to see msg_namelen == 0.
		 * Andi says that this is a kernel bug and has fixed it.
		 * Perhaps in 2.2.18/2.4.0.
		 */
		passert(emh.msg_name == &from.sa);
		DBG_cond_dump(DBG_ALL, "name:\n", emh.msg_name,
			      emh.msg_namelen);

		fromstr[0] = '\0'; /* usual case :-( */
		switch (from.sa.sa_family) {
			char as[INET6_ADDRSTRLEN];

		case AF_INET:
			if (emh.msg_namelen == sizeof(struct sockaddr_in))
				snprintf(fromstr, sizeof(fromstr),
					 " for message to %s port %u",
					 inet_ntop(from.sa.sa_family,
						   &from.sa_in4.sin_addr, as,
						   sizeof(as)),
					 ntohs(from.sa_in4.sin_port));
			break;
		case AF_INET6:
			if (emh.msg_namelen == sizeof(struct sockaddr_in6))
				snprintf(fromstr, sizeof(fromstr),
					 " for message to %s port %u",
					 inet_ntop(from.sa.sa_family,
						   &from.sa_in6.sin6_addr, as,
						   sizeof(as)),
					 ntohs(from.sa_in6.sin6_port));
			break;
		}

		for (cm = CMSG_FIRSTHDR(&emh)
		     ; cm != NULL
		     ; cm = CMSG_NXTHDR(&emh, cm)) {
			if (cm->cmsg_level == SOL_IP &&
			    cm->cmsg_type == IP_RECVERR) {
				/* ip(7) and recvmsg(2) specify:
				 * ee_origin is SO_EE_ORIGIN_ICMP for ICMP
				 *  or SO_EE_ORIGIN_LOCAL for locally generated errors.
				 * ee_type and ee_code are from the ICMP header.
				 * ee_info is the discovered MTU for EMSGSIZE errors
				 * ee_data is not used.
				 *
				 * ??? recvmsg(2) says "SOCK_EE_OFFENDER" but
				 * means "SO_EE_OFFENDER".  The OFFENDER is really
				 * the router that complained.  As such, the port
				 * is meaningless.
				 */

				/* ??? cmsg(3) claims that CMSG_DATA returns
				 * void *, but RFC 2292 and /usr/include/bits/socket.h
				 * say unsigned char *.  The manual is being fixed.
				 */
				struct sock_extended_err *ee =
					(void *)CMSG_DATA(cm);
				const char *offstr = "unspecified";
				char offstrspace[INET6_ADDRSTRLEN];
				char orname[50];

				if (cm->cmsg_len >
				    CMSG_LEN(sizeof(struct sock_extended_err)))
				{
					const struct sockaddr *offender =
						SO_EE_OFFENDER(ee);

					switch (offender->sa_family) {
					case AF_INET:
						offstr = inet_ntop(
							offender->sa_family,
							&((const
							   struct sockaddr_in *)
							  offender)->sin_addr,
							offstrspace,
							sizeof(offstrspace));
						break;
					case AF_INET6:
						offstr = inet_ntop(
							offender->sa_family,
							&((const
							   struct sockaddr_in6
							   *)offender)->sin6_addr,
							offstrspace,
							sizeof(offstrspace));
						break;
					default:
						offstr = "unknown";
						break;
					}
				}

				switch (ee->ee_origin) {
				case SO_EE_ORIGIN_NONE:
					snprintf(orname, sizeof(orname),
						 "none");
					break;
				case SO_EE_ORIGIN_LOCAL:
					snprintf(orname, sizeof(orname),
						 "local");
					break;
				case SO_EE_ORIGIN_ICMP:
					snprintf(orname, sizeof(orname),
						 "ICMP type %d code %d (not authenticated)",
						 ee->ee_type, ee->ee_code);
					break;
				case SO_EE_ORIGIN_ICMP6:
					snprintf(orname, sizeof(orname),
						 "ICMP6 type %d code %d (not authenticated)",
						 ee->ee_type, ee->ee_code);
					break;
				default:
					snprintf(orname, sizeof(orname),
						 "invalid origin %u",
						 ee->ee_origin);
					break;
				}

#define LOG(buf) lswlogf(buf,			\
	"ERROR: asynchronous network error report on %s (sport=%d)%s, complainant %s: %s [errno %" PRIu32 ", origin %s]", \
	ifp->ip_dev->id_rname, ifp->port,	\
	fromstr,				\
	offstr,					\
	strerror(ee->ee_errno),			\
	ee->ee_errno, orname);

				if (packet_len == 1 && buffer[0] == 0xff &&
				    (cur_debugging & DBG_NATT) == 0) {
					/*
					 * don't log NAT-T keepalive related errors unless NATT debug is
					 * enabled
					 */
				} else if (sender != NULL && sender->st_connection != NULL &&
					   LDISJOINT(sender->st_connection->policy, POLICY_OPPORTUNISTIC)) {
					/*
					 * The sender is known and
					 * this isn't an opportunistic
					 * connection, so log.
					 *
					 * XXX: originally this path
					 * was taken unconditionally
					 * but with opportunistic that
					 * got too verbose.  Is there
					 * a global opportunistic
					 * disabled test so that
					 * behaviour can be restored?
					 *
					 * HACK: So that the logging
					 * system doesn't accidentally
					 * include a prefix for the
					 * wrong state et.al., switch
					 * out everything but SENDER.
					 * Better would be to make the
					 * state/connection an
					 * explicit parameter to the
					 * logging system?
					 */
					LSWLOG_STATE(sender, buf) {
						LOG(buf);
					}
				} else {
					/*
					 * Since this output is forced
					 * using DBGP, report the
					 * error using debug-log.
					 */
					LSWDBGP_STATE(DBG_OPPO, sender, buf) {
						LOG(buf);
					}
#undef LOG
				}
			} else if (cm->cmsg_level == SOL_IP &&
				   cm->cmsg_type == IP_PKTINFO) {
				/* do nothing */
			} else {
				/* .cmsg_len is a kernel_size_t(!), but the value
				 * certainly ought to fit in an unsigned long.
				 */
				libreswan_log(
					"unknown cmsg: level %d, type %d, len %zu",
					cm->cmsg_level, cm->cmsg_type,
					 cm->cmsg_len);
			}
		}
	}
	return (pfd.revents & interest) != 0;
}
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

bool check_incoming_msg_errqueue(const struct iface_port *ifp UNUSED,
				 const char *before UNUSED)
{
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	return check_msg_errqueue(ifp, POLLIN, before);
#else
	return true;
#endif	/* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */
}

void check_outgoing_msg_errqueue(const struct iface_port *ifp UNUSED,
				 const char *before UNUSED)
{
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	(void) check_msg_errqueue(ifp, POLLOUT, before);
#endif	/* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */
}

bool should_fragment_ike_msg(struct state *st, size_t len, bool resending)
{
	if (st->st_interface != NULL && st->st_interface->ike_float)
		len += NON_ESP_MARKER_SIZE;

	/* This condition is complex.  Formatting is meant to help reader.
	 *
	 * Hugh thinks his banished style would make this earlier version
	 * a little clearer:
	 * len + natt_bonus
	 *    >= (st->st_connection->addr_family == AF_INET
	 *       ? ISAKMP_FRAG_MAXLEN_IPv4 : ISAKMP_FRAG_MAXLEN_IPv6)
	 * && ((  resending
	 *        && (st->st_connection->policy & POLICY_IKE_FRAG_ALLOW)
	 *        && st->st_seen_fragvid)
	 *     || (st->st_connection->policy & POLICY_IKE_FRAG_FORCE)
	 *     || st->st_seen_fragments))
	 *
	 * ??? the following test does not account for natt_bonus
	 */
	return len >= (st->st_connection->addr_family == AF_INET ?
		       ISAKMP_V1_FRAG_MAXLEN_IPv4 : ISAKMP_V1_FRAG_MAXLEN_IPv6) &&
	    (   (resending &&
			(st->st_connection->policy & POLICY_IKE_FRAG_ALLOW) &&
			st->st_seen_fragvid) ||
		(st->st_connection->policy & POLICY_IKE_FRAG_FORCE) ||
		st->st_seen_fragments   );
}

bool ev_before(struct pluto_event *pev, deltatime_t delay) {
	struct timeval timeout;

	return (event_pending(pev->ev, EV_TIMEOUT, &timeout) & EV_TIMEOUT) &&
		deltaless_tv_dt(timeout, delay);
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
