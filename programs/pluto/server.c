/* get-next-event loop
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002, 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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
#include <sys/wait.h>
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
#include "dnskey.h"             /* needs keys.h and adns.h */
#include "whack.h"              /* for RC_LOG_SERIOUS */
#include "pluto_crypt.h"        /* cryptographic helper functions */
#include "udpfromto.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>
#include "kameipsec.h"

#include "nat_traversal.h"

#include "lsw_select.h"
#include "lswfips.h"

/*
 *  Server main loop and socket initialization routines.
 */

struct pluto_events {
	struct event *ev_ctl ;
	struct event *ev_sig_hup;
	struct event *ev_sig_term;
	struct event *ev_sig_chld;
} pluto_evs;

static const int on = TRUE;     /* by-reference parameter; constant, we hope */

char *pluto_vendorid;

static pid_t addconn_child_pid = 0;

/* list of interface devices */
struct iface_list interface_dev;

/* pluto's main Libevent event_base */
static struct event_base *pluto_eb =  NULL;

/* control (whack) socket */
int ctl_fd = NULL_FD;   /* file descriptor of control (whack) socket */

struct sockaddr_un ctl_addr = {
	.sun_family = AF_UNIX,
#if defined(HAS_SUN_LEN)
	.sun_len = sizeof(struct sockaddr_un),
#endif
	.sun_path  = DEFAULT_CTLBASE CTL_SUFFIX
};

struct sockaddr_un info_addr = {
	.sun_family = AF_UNIX,
#if defined(HAS_SUN_LEN)
	.sun_len = sizeof(struct sockaddr_un),
#endif
	.sun_path  = DEFAULT_CTLBASE INFO_SUFFIX
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
	} else if (setsockopt(ctl_fd, SOL_SOCKET, SO_REUSEADDR,
			      (const void *)&on, sizeof(on)) < 0) {
		failed = "setsockopt";
	} else {
		/* to keep control socket secure, use umask */
#ifdef PLUTO_GROUP_CTL
		mode_t ou = umask(~(S_IRWXU | S_IRWXG));
#else
		mode_t ou = umask(~S_IRWXU);
#endif

		if (bind(ctl_fd, (struct sockaddr *)&ctl_addr,
			 offsetof(struct sockaddr_un,
				  sun_path) + strlen(ctl_addr.sun_path)) < 0)
			failed = "bind";
		umask(ou);
	}

#ifdef PLUTO_GROUP_CTL
	{
		struct group *g;

		g = getgrnam("pluto");
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
unsigned int pluto_max_halfopen = DEFAULT_MAXIMUM_HALFOPEN_IKE_SA;
unsigned int pluto_ddos_threshold = DEFAULT_IKE_SA_DDOS_THRESHOLD;
deltatime_t pluto_shunt_lifetime = { PLUTO_SHUNT_LIFE_DURATION_DEFAULT };

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

				if (p->ev != NULL) {
					event_del(p->ev);
					p->ev = NULL;
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

	if (fd < 0) {
		log_errno((e, "socket() in process_raw_ifaces()"));
		return -1;
	}

	/* Set socket Nonblocking */
	if ((fcntl_flags = fcntl(fd, F_GETFL)) >= 0) {
		if (!(fcntl_flags & O_NONBLOCK)) {
			fcntl_flags |= O_NONBLOCK;
			fcntl(fd, F_SETFL, fcntl_flags);
		}
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		log_errno((e, "fcntl(,, FD_CLOEXEC) in process_raw_ifaces()"));
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&on, sizeof(on)) < 0) {
		log_errno((e,
			   "setsockopt SO_REUSEADDR in process_raw_ifaces()"));
		close(fd);
		return -1;
	}

	/* To improve error reporting.  See ip(7). */
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	if (setsockopt(fd, SOL_IP, IP_RECVERR,
		       (const void *)&on, sizeof(on)) < 0) {
		log_errno((e,
			   "setsockopt IP_RECVERR in process_raw_ifaces()"));
		close(fd);
		return -1;
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
		log_errno((e,
			   "setsockopt IPV6_USE_MIN_MTU in process_raw_ifaces()"));
		close(fd);
		return -1;
	}
#endif

/*
 * NETKEY requires us to poke an IPsec policy hole that allows IKE packets,
 * unlike KLIPS which implicitly always allows plaintext IKE.
 * This installs one IPsec policy per socket but this function is called for each:
 * IPv4 port 500 and 4500
 * IPv6 port 500
 */
#if defined(linux) && defined(NETKEY_SUPPORT)
	if (kern_interface == USE_NETKEY) {
		struct sadb_x_policy policy;
		int level, opt;

		zero(&policy);
		policy.sadb_x_policy_len = sizeof(policy) /
					   IPSEC_PFKEYv2_ALIGN;
		policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
		policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
		policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
		policy.sadb_x_policy_id = 0;

		if (addrtypeof(&ifp->addr) == AF_INET6) {
			level = IPPROTO_IPV6;
			opt = IPV6_IPSEC_POLICY;
		} else {
			level = IPPROTO_IP;
			opt = IP_IPSEC_POLICY;
		}

		if (setsockopt(fd, level, opt,
			       &policy, sizeof(policy)) < 0) {
			log_errno((e,
				   "setsockopt IPSEC_POLICY in process_raw_ifaces()"));
			close(fd);
			return -1;
		}

		policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;

		if (setsockopt(fd, level, opt,
			       &policy, sizeof(policy)) < 0) {
			log_errno((e,
				   "setsockopt IPSEC_POLICY in process_raw_ifaces()"));
			close(fd);
			return -1;
		}
	}
#endif

	setportof(htons(port), &ifp->addr);
	if (bind(fd, sockaddrof(&ifp->addr), sockaddrlenof(&ifp->addr)) < 0) {
		ipstr_buf b;

		log_errno((e, "bind() for %s/%s %s:%u in process_raw_ifaces()",
			   ifp->name, v_name,
			   ipstr(&ifp->addr, &b), (unsigned) port));
		close(fd);
		return -1;
	}
	setportof(htons(pluto_port), &ifp->addr);

#if defined(HAVE_UDPFROMTO)
	/* we are going to use udpfromto.c, so initialize it */
	udpfromto_init(fd);
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

/* a wrapper for libevent's event_new + event_add; any error is fatal */
struct event *pluto_event_new(evutil_socket_t fd, short events,
		event_callback_fn cb, void *arg, const struct timeval *t)
{
	struct event *ev = event_new(pluto_eb, fd, events, cb, arg);
	int r;

	passert(ev != NULL);
	r = event_add(ev, t);
	passert(r >= 0);
	return ev;
}

void find_ifaces(void)
{
	struct iface_port *ifp;

	mark_ifaces_dead();

	if (kernel_ops->process_ifaces != NULL) {
#if !defined(__CYGWIN32__)
		kernel_ops->process_ifaces(find_raw_ifaces4());
		kernel_ops->process_ifaces(find_raw_ifaces6());
#endif
		kernel_ops->process_ifaces(static_ifn);
	}

	free_dead_ifaces(); /* ditch remaining old entries */

	if (interfaces == NULL)
		loglog(RC_LOG_SERIOUS, "no public interfaces found");

	if (listening) {
		for (ifp = interfaces; ifp != NULL; ifp = ifp->next) {
			if (ifp->ev != NULL) {
				event_del(ifp->ev);
				ifp->ev = NULL;
				DBG_log("refresh. setup callback for interface %s:%u %d",
						ifp->ip_dev->id_rname,ifp->port,
						ifp->fd);
			}
			ifp->ev = pluto_event_new(ifp->fd,
					EV_READ | EV_PERSIST, comm_handle_cb,
					ifp, NULL);
			DBG_log("setup callback for interface %s:%u fd %d",
					ifp->ip_dev->id_rname, ifp->port,
					ifp->fd);
		}
	}
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
	whack_log(RC_COMMENT, "debug %s",
		  bitnamesof(debug_bit_names, cur_debugging));
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
		DBGP(IMPAIR_FORCE_FIPS) ? "enabled [forced]" : "enabled");
}

static volatile sig_atomic_t sighupflag = FALSE;

static void huphandler(int sig UNUSED)
{
	sighupflag = TRUE;
}

static volatile sig_atomic_t sigtermflag = FALSE;

static void termhandler(int sig UNUSED)
{
	sigtermflag = TRUE;
}

static void huphandler_cb(int unused UNUSED, const short event UNUSED, void *arg UNUSED)
{
	libreswan_log("Pluto ignores SIGHUP -- perhaps you want \"whack --listen\"");
}

static void termhandler_cb(int unused UNUSED, const short event UNUSED, void *arg UNUSED)
{
	exit_pluto(PLUTO_EXIT_OK);
}

static volatile sig_atomic_t sigchildflag = FALSE;

static void childhandler(int sig UNUSED)
{
	sigchildflag = TRUE;
}

/* perform waitpid() for any children */
static void reapchildren(void)
{
	pid_t child;
	int status;

	errno = 0;

	while ((child = waitpid(-1, &status, WNOHANG)) > 0) {
		if (child == addconn_child_pid) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("reaped addconn helper child"));
			addconn_child_pid = 0;
			continue;
		}
		/* Threads are created instead of child processes when using LIBNSS */
		libreswan_log("child pid=%d (status=%d) is not my child!",
			      child, status);
	}

	if (child == -1) {
		libreswan_log("reapchild failed with errno=%d %s",
			      errno, strerror(errno));
	}
}

static void childhandler_cb(int unused UNUSED, const short event UNUSED, void *arg UNUSED)
{
    reapchildren();
}

void init_event_base(void) {
	DBG(DBG_CONTROLMORE, DBG_log("Initialize libevent base"));
	pluto_eb = event_base_new();
	passert(pluto_eb != NULL);
	passert(evthread_use_pthreads() >= 0);
	passert(evthread_make_base_notifiable(pluto_eb) >= 0);
}

/* free pluto events at the end. better memory accounting. */
static void pluto_event_free(struct pluto_events *pluto_evs)
{
	event_free(pluto_evs->ev_ctl);
	event_free(pluto_evs->ev_sig_chld);
	event_free(pluto_evs->ev_sig_term);
	event_free(pluto_evs->ev_sig_hup);
}

static void main_loop(void)
{
	int r;
	struct pluto_events pluto_evs;

	/*
	 * new lbevent setup and loop
	 * setup basic events
	 */

	DBG(DBG_CONTROLMORE, DBG_log("Setting up events, loop start"));

	pluto_evs.ev_ctl = pluto_event_new(ctl_fd, EV_READ | EV_PERSIST,
				 whack_handle_cb, NULL, NULL);

	pluto_evs.ev_sig_chld = pluto_event_new(SIGCHLD, EV_SIGNAL,
				      childhandler_cb, NULL, NULL);

	pluto_evs.ev_sig_term = pluto_event_new(SIGTERM, EV_SIGNAL,
				      termhandler_cb, NULL, NULL);

	pluto_evs.ev_sig_hup = pluto_event_new(SIGHUP, EV_SIGNAL|EV_PERSIST,
				     huphandler_cb, NULL, NULL);

	r = event_base_loop(pluto_eb, 0);
	passert (r == 0);

	pluto_event_free(&pluto_evs);
}

/* call_server listens for incoming ISAKMP packets and Whack messages,
 * and handles timer events.
 */
void call_server(void)
{
	/* catch SIGHUP and SIGTERM */
	{
		int r;
		struct sigaction act;

		act.sa_handler = &huphandler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0; /* no SA_ONESHOT, no SA_RESTART, no nothing */
		r = sigaction(SIGHUP, &act, NULL);
		passert(r == 0);

		act.sa_handler = &termhandler;
		r = sigaction(SIGTERM, &act, NULL);
		passert(r == 0);

		act.sa_handler = &childhandler;
		act.sa_flags   = SA_RESTART;
		r = sigaction(SIGCHLD, &act, NULL);
		passert(r == 0);
	}

	/* do_whacklisten() is now done by the addconn fork */

	/*
	 * fork to issue the command "ipsec addconn --autoall"
	 * (or vfork() when fork() isn't available, eg on embedded platforms
	 * without MMU, like uClibc
	 */
	{
		/* find a pathname to the addconn program */
		const char *addconn_path = NULL;
		static const char addconn_name[] = "addconn";
		char addconn_path_space[4096]; /* plenty long? */
		ssize_t n = 0;

#if !(defined(macintosh) || (defined(__MACH__) && defined(__APPLE__)))
		{
			/* The program will be in the same directory as Pluto,
			 * so we use the sympolic link /proc/self/exe to
			 * tell us of the path prefix.
			 */
			n = readlink("/proc/self/exe", addconn_path_space,
				     sizeof(addconn_path_space));
			if (n < 0) {
# ifdef __uClibc__
				/* on some nommu we have no proc/self/exe, try without path */
				*addconn_path_space = '\0';
				n = 0;
# else
				exit_log_errno((e,
						"readlink(\"/proc/self/exe\") failed in call_server()"));
# endif
			}
		}
#else
		/* This is wrong. Should end up in a resource_dir on MacOSX -- Paul */
		addconn_path = "/usr/local/libexec/ipsec/addconn";
#endif
		if ((size_t)n > sizeof(addconn_path_space) -
		    sizeof(addconn_name))
			exit_log("path to %s is too long", addconn_name);
		while (n > 0 && addconn_path_space[n - 1] != '/')
			n--;

		strcpy(addconn_path_space + n, addconn_name);
		addconn_path = addconn_path_space;

		if (access(addconn_path, X_OK) < 0)
			exit_log_errno((e, "%s missing or not executable",
					addconn_path));

		char *newargv[] = { DISCARD_CONST(char *, "addconn"),
				    DISCARD_CONST(char *, "--ctlbase"),
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
			 * child
			 *
			 * Note that, when vfork() was used, calls
			 * like sleep() and DBG_log() are not valid.
			 *
			 * XXX: Why the sleep?
			 */
#if USE_FORK
			sleep(1);
#endif
			execve(addconn_path, newargv, newenv);
			_exit(42);
		}
		DBG(DBG_CONTROLMORE,
		    DBG_log("created addconn helper (pid:%d) using %s+execve",
			    addconn_child_pid, USE_VFORK ? "vfork" : "fork"));
		/* parent continues */
	}
	main_loop();
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
 * - cmsg(3) describes how to process auxilliary messages
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
bool check_msg_errqueue(const struct iface_port *ifp, short interest)
{
	struct pollfd pfd;

	pfd.fd = ifp->fd;
	pfd.events = interest | POLLPRI | POLLOUT;

	while (pfd.revents = 0,
	       poll(&pfd, 1, -1) > 0 && (pfd.revents & POLLERR)) {
		u_int8_t buffer[3000]; /* hope that this is big enough */
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

		if (packet_len == -1) {
			log_errno((e,
				   "recvmsg(,, MSG_ERRQUEUE) on %s failed in comm_handle",
				   ifp->ip_dev->id_rname));
			break;
		} else if (packet_len == (ssize_t)sizeof(buffer)) {
			libreswan_log(
				"MSG_ERRQUEUE message longer than %lu bytes; truncated",
				(unsigned long) sizeof(buffer));
		} else if (packet_len >= (ssize_t)sizeof(struct isakmp_hdr)) {
			sender = find_likely_sender((size_t) packet_len, buffer);
		}

		DBG_cond_dump(DBG_ALL, "rejected packet:\n", buffer,
			      packet_len);
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
						 "invalid origin %lu",
						 (unsigned long) ee->ee_origin);
					break;
				}

				if (packet_len == 1 && buffer[0] == 0xff &&
				    (cur_debugging & DBG_NATT) == 0) {
					/*
					 * don't log NAT-T keepalive related errors unless NATT debug is
					 * enabled
					 */
				} else if (DBGP(DBG_OPPO) ||
					   (sender != NULL && sender->st_connection != NULL &&
					    LDISJOINT(sender->st_connection->policy, POLICY_OPPORTUNISTIC)))
				{
					/*
					 * We are selective about printing this
					 * diagnostic since it pours out when
					 * we are doing unrequited authnull OE.
					 * That's the point of the condition
					 * above.
					 * ??? the condition treats all authnull as OE.
					 */
					/* ??? DBGP is controlling non-DBG logging! */
					struct state *old_state = cur_state;

					cur_state = sender;

					/* note dirty trick to suppress ~ at start of format
					 * if we know what state to blame.
					 * Don't bother to report ee_{pad,info,data}.
					 */
					libreswan_log((sender != NULL) + "~"
						"ERROR: asynchronous network error report on %s (sport=%d)%s, complainant %s: %s [errno %lu, origin %s]",
						ifp->ip_dev->id_rname, ifp->port,
						fromstr,
						offstr,
						strerror(ee->ee_errno),
						(unsigned long) ee->ee_errno, orname
						);
					cur_state = old_state;
				}
			} else if (cm->cmsg_level == SOL_IP &&
				   cm->cmsg_type == IP_PKTINFO) {
				/* do nothing */
			} else {
				/* .cmsg_len is a kernel_size_t(!), but the value
				 * certainly ought to fit in an unsigned long.
				 */
				libreswan_log(
					"unknown cmsg: level %d, type %d, len %lu",
					cm->cmsg_level, cm->cmsg_type,
					(unsigned long) cm->cmsg_len);
			}
		}
	}
	return (pfd.revents & interest) != 0;
}
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

/* send_ike_msg logic is broken into layers.
 * The rest of the system thinks it is simple.
 * We have three entrypoints that control options
 * for reporting write failure and actions on resending (fragment?):
 * send_ike_msg(), resend_ike_v1_msg(), and send_keepalive().
 *
 * The first two call send_or_resend_ike_msg().
 * That handles an IKE message.
 * It calls send_frags() if the message needs to be fragmented.
 * Otherwise it calls send_packet() to send it in one gulp.
 *
 * send_frags() breaks an IKE message into fragments and sends
 * them by send_packet().
 *
 * send_keepalive() calls send_packet() directly: uses a special
 * tiny packet; non-ESP marker does not apply; logging on write error
 * is suppressed.
 *
 * send_packet() sends a UDP packet, possibly prefixed by a non-ESP Marker
 * for NATT.  It accepts two chunks because this avoids double-copying.
 */

static bool send_packet(struct state *st, const char *where,
			bool just_a_keepalive,
			const u_int8_t *aptr, size_t alen,
			const u_int8_t *bptr, size_t blen)
{
	/* NOTE: on system with limited stack, buf could be made static */
	u_int8_t buf[MAX_OUTPUT_UDP_SIZE];

	/* Each fragment, if we are doing NATT, needs a non-ESP_Marker prefix.
	 * natt_bonus is the size of the addition (0 if not needed).
	 */
	size_t natt_bonus;

	if (st->st_interface == NULL) {
		libreswan_log("Cannot send packet - interface vanished!");
		return FALSE;
	}

	natt_bonus = !just_a_keepalive &&
				  st->st_interface->ike_float ?
				  NON_ESP_MARKER_SIZE : 0;

	const u_int8_t *ptr;
	size_t len = natt_bonus + alen + blen;
	ssize_t wlen;

	if (len > MAX_OUTPUT_UDP_SIZE) {
		DBG_log("send_ike_msg(): really too big %zu bytes", len);
		return FALSE;
	}

	if (len != alen) {
		/* copying required */

		/* 1. non-ESP Marker (0x00 octets) */
		memset(buf, 0x00, natt_bonus);

		/* 2. chunk a */
		memcpy(buf + natt_bonus, aptr, alen);

		/* 3. chunk b */
		memcpy(buf + natt_bonus + alen, bptr, blen);

		ptr = buf;
	} else {
		ptr = aptr;
	}

	DBG(DBG_CONTROL | DBG_RAW, {
		ipstr_buf b;
		DBG_log("sending %zu bytes for %s through %s:%d to %s:%u (using #%lu)",
			len,
			where,
			st->st_interface->ip_dev->id_rname,
			st->st_interface->port,
			ipstr(&st->st_remoteaddr, &b),
			st->st_remoteport,
			st->st_serialno);
	});
	DBG(DBG_RAW, DBG_dump(NULL, ptr, len));

	setportof(htons(st->st_remoteport), &st->st_remoteaddr);

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	(void) check_msg_errqueue(st->st_interface, POLLOUT);
#endif  /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

	wlen = sendto(st->st_interface->fd,
		      ptr,
		      len, 0,
		      sockaddrof(&st->st_remoteaddr),
		      sockaddrlenof(&st->st_remoteaddr));

	if (wlen != (ssize_t)len) {
		if (just_a_keepalive) {
			ipstr_buf b;

			log_errno((e, "sendto on %s to %s:%u failed in %s",
				   st->st_interface->ip_dev->id_rname,
				   ipstr(&st->st_remoteaddr, &b),
				   st->st_remoteport,
				   where));
		}
		return FALSE;
	}

	/* Send a duplicate packet when this impair is enabled - used for testing */
	if (DBGP(IMPAIR_JACOB_TWO_TWO)) {
		/* sleep for half a second, and second another packet */
		usleep(500000);
		ipstr_buf b;

		DBG_log("JACOB 2-2: resending %zu bytes for %s through %s:%d to %s:%u:",
			len,
			where,
			st->st_interface->ip_dev->id_rname,
			st->st_interface->port,
			ipstr(&st->st_remoteaddr, &b),
			st->st_remoteport);

		wlen = sendto(st->st_interface->fd,
			      ptr,
			      len, 0,
			      sockaddrof(&st->st_remoteaddr),
			      sockaddrlenof(&st->st_remoteaddr));
		if (wlen != (ssize_t)len) {
			if (just_a_keepalive) {
				log_errno((e,
					   "sendto on %s to %s:%u failed in %s",
					   st->st_interface->ip_dev->id_rname,
					   ipstr(&st->st_remoteaddr, &b),
					   st->st_remoteport,
					   where));
			}
			return FALSE;
		}
	}
	return TRUE;
}

/*
 * non-IETF magic voodoo we need to consider for interop:
 * - www.cisco.com/en/US/docs/ios/sec_secure_connectivity/configuration/guide/sec_fragment_ike_pack.html
 * - www.cisco.com/en/US/docs/ios-xml/ios/sec_conn_ikevpn/configuration/15-mt/sec-fragment-ike-pack.pdf
 * - msdn.microsoft.com/en-us/library/cc233452.aspx
 * - iOS/Apple racoon source ipsec-164.9 at www.opensource.apple.com (frak length 1280)
 * - stock racoon source (frak length 552)
 */

static bool send_frags(struct state *st, const char *where)
{
	unsigned int fragnum = 0;

	/* Each fragment, if we are doing NATT, needs a non-ESP_Marker prefix.
	 * natt_bonus is the size of the addition (0 if not needed).
	 */
	const size_t natt_bonus =
		st->st_interface->ike_float ? NON_ESP_MARKER_SIZE : 0;

	/* We limit fragment packets to ISAKMP_FRAG_MAXLEN octets.
	 * max_data_len is the maximum data length that will fit within it.
	 */
	const size_t max_data_len =
		((st->st_connection->addr_family ==
		  AF_INET) ? ISAKMP_V1_FRAG_MAXLEN_IPv4 : ISAKMP_V1_FRAG_MAXLEN_IPv6)
		-
		(natt_bonus + NSIZEOF_isakmp_hdr +
		 NSIZEOF_isakmp_ikefrag);

	u_int8_t *packet_cursor = st->st_tpacket.ptr;
	size_t packet_remainder_len = st->st_tpacket.len;

	/* BUG: this code does not use the marshalling code
	 * in packet.h to translate between wire and host format.
	 * This is dangerous.  The following assertion should
	 * fail in most cases where this cheat won't work.
	 */
	passert(sizeof(struct isakmp_hdr) == NSIZEOF_isakmp_hdr &&
		sizeof(struct isakmp_ikefrag) == NSIZEOF_isakmp_ikefrag);

	while (packet_remainder_len > 0) {
		u_int8_t frag_prefix[NSIZEOF_isakmp_hdr +
				     NSIZEOF_isakmp_ikefrag];
		const size_t data_len = packet_remainder_len > max_data_len ?
					max_data_len : packet_remainder_len;
		const size_t fragpl_len = NSIZEOF_isakmp_ikefrag + data_len;
		const size_t isakmppl_len = NSIZEOF_isakmp_hdr + fragpl_len;

		fragnum++;

		/* emit isakmp header derived from original */
		{
			struct isakmp_hdr *ih =
				(struct isakmp_hdr*) frag_prefix;

			memcpy(ih, st->st_tpacket.ptr, NSIZEOF_isakmp_hdr);
			ih->isa_np = ISAKMP_NEXT_IKE_FRAGMENTATION; /* one octet */
			/* Do we need to set any of ISAKMP_FLAGS_v1_ENCRYPTION?
			 * Seems there might be disagreement between Cisco and Microsoft.
			 * st->st_suspended_md->hdr.isa_flags; TODO must this be set?
			 */
			ih->isa_flags &= ~ISAKMP_FLAGS_v1_ENCRYPTION;
			ih->isa_length = htonl(isakmppl_len);
		}

		/* Append the ike frag header */
		{
			struct isakmp_ikefrag *fh =
				(struct isakmp_ikefrag*) (frag_prefix +
							  NSIZEOF_isakmp_hdr);

			fh->isafrag_np = 0;             /* must be zero */
			fh->isafrag_reserved = 0;       /* reserved at this time, must be zero */
			fh->isafrag_length = htons(fragpl_len);
			fh->isafrag_id = htons(1);      /* In theory required to be unique, in practise not needed? */
			fh->isafrag_number = fragnum;   /* one byte, no htons() call needed */
			fh->isafrag_flags = packet_remainder_len == data_len ?
					    ISAKMP_FRAG_LAST : 0;
		}
		DBG(DBG_CONTROL,
		    DBG_log("sending IKE fragment id '%d', number '%u'%s",
			    1, /* hard coded for now, seems to be what all the cool implementations do */
			    fragnum,
			    packet_remainder_len == data_len ? " (last)" : ""));

		if (!send_packet(st, where, FALSE,
				 frag_prefix, NSIZEOF_isakmp_hdr +
				 NSIZEOF_isakmp_ikefrag,
				 packet_cursor, data_len))
			return FALSE;

		packet_remainder_len -= data_len;
		packet_cursor += data_len;
	}
	return TRUE;
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

static bool send_ikev2_frags(struct state *st, const char *where)
{
	struct ikev2_frag *frag;

	for (frag = st->st_tfrags; frag != NULL; frag = frag->next)
		if (!send_packet(st, where, FALSE,
				 frag->cipher.ptr, frag->cipher.len, NULL, 0))
			return FALSE;

	return TRUE;
}

static bool send_or_resend_ike_msg(struct state *st, const char *where,
				   bool resending)
{
	if (st->st_interface == NULL) {
		libreswan_log("Cannot send packet - interface vanished!");
		return FALSE;
	}

	if (st->st_tfrags != NULL) {
		/* if a V2 packet needs fragmenting it would have already happened */
		passert(st->st_ikev2);
		passert(st->st_tpacket.ptr == NULL);
		return send_ikev2_frags(st, where);
	} else {
		/*
		 * Each fragment, if we are doing NATT, needs a non-ESP_Marker prefix.
		 * natt_bonus is the size of the addition (0 if not needed).
		 */
		size_t natt_bonus = st->st_interface->ike_float ? NON_ESP_MARKER_SIZE : 0;
		size_t len = st->st_tpacket.len;

		passert(len != 0);

		/*
		 * Decide of whether we're to fragment.
		 * Only for IKEv1 (V2 fragments earlier).
		 * ??? why can't we fragment in STATE_MAIN_I1?
		 */
		if (!st->st_ikev2 &&
		    st->st_state != STATE_MAIN_I1 &&
		    should_fragment_ike_msg(st, len + natt_bonus, resending))
		{
			return send_frags(st, where);
		} else {
			return send_packet(st, where, FALSE, st->st_tpacket.ptr,
					   st->st_tpacket.len, NULL, 0);
		}
	}
}

void record_outbound_ike_msg(struct state *st, pb_stream *pbs, const char *what)
{
	passert(pbs_offset(pbs) != 0);
	release_fragments(st);
	freeanychunk(st->st_tpacket);
	clonetochunk(st->st_tpacket, pbs->start, pbs_offset(pbs), what);
}

bool send_ike_msg(struct state *st, const char *where)
{
	return send_or_resend_ike_msg(st, where, FALSE);
}

bool record_and_send_ike_msg(struct state *st, pb_stream *pbs, const char *what)
{
	record_outbound_ike_msg(st, pbs, what);
	return send_ike_msg(st, what);
}

/* hack!  Leaves st->st_tpacket as it was found. */
bool send_ike_msg_without_recording(struct state *st, pb_stream *pbs, const char *where)
{
	chunk_t saved_tpacket = st->st_tpacket;
	bool r;

	setchunk(st->st_tpacket, pbs->start, pbs_offset(pbs));
	r = send_ike_msg(st, where);
	st->st_tpacket = saved_tpacket;
	return r;
}

bool resend_ike_v1_msg(struct state *st, const char *where)
{
	return send_or_resend_ike_msg(st, where, TRUE);
}

/*
 * send keepalive is special in two ways:
 * We don't want send errors logged (too noisy).
 * We don't want the packet prefixed with a non-ESP Marker.
 */
bool send_keepalive(struct state *st, const char *where)
{
	static const unsigned char ka_payload = 0xff;

	return send_packet(st, where, TRUE, &ka_payload, sizeof(ka_payload),
			   NULL, 0);
}

bool ev_before(struct pluto_event *pev, deltatime_t delay) {
	struct timeval timeout;

	return (event_pending(pev->ev, EV_TIMEOUT, &timeout) & EV_TIMEOUT) &&
		deltaless_tv_dt(timeout, delay);
}
void set_whack_pluto_ddos(enum ddos_mode mode)
{
	if (mode == pluto_ddos_mode) {
		loglog(RC_LOG,"pluto DDoS protection remains in %s mode",
		mode == DDOS_AUTO ? "auto-detect" : mode == DDOS_FORCE_BUSY ? "active" : "unlimited");
		return;
	}

	pluto_ddos_mode = mode;
	loglog(RC_LOG,"pluto DDoS protection mode set to %s",
		mode == DDOS_AUTO ? "auto-detect" : mode == DDOS_FORCE_BUSY ? "active" : "unlimited");
}
