/* get-next-event loop
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com> 
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com> 
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
# include <sys/sockio.h>	/* for Solaris 2.6: defines SIOCGIFCONF */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/poll.h>	/* only used for forensic poll call */
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <resolv.h>

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
#  include <asm/types.h>	/* for __u8, __u32 */
#  include <linux/errqueue.h>
#  include <sys/uio.h>	/* struct iovec */
#endif

#include <libreswan.h>

#include "sysdep.h"
#include "socketwrapper.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_HAVE_PAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "kernel.h"  /* for no_klips; needs connections.h */
#include "log.h"
#include "server.h"
#include "timer.h"
#include "packet.h"
#include "demux.h"  /* needs packet.h */
#include "rcv_whack.h"
#include "keys.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "pluto_crypt.h" /* cryptographic helper functions */
#include "udpfromto.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>
#include "kameipsec.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#include "lsw_select.h"

/*
 *  Server main loop and socket initialization routines.
 */

static const int on = TRUE;	/* by-reference parameter; constant, we hope */

bool no_retransmits = FALSE;

pid_t addconn_child_pid = 0;

/* list of interface devices */
struct iface_list interface_dev;

/* control (whack) socket */
int ctl_fd = NULL_FD;	/* file descriptor of control (whack) socket */
struct sockaddr_un ctl_addr = { .sun_family=AF_UNIX,
#if defined(HAS_SUN_LEN)
				.sun_len=sizeof(struct sockaddr_un),
#endif				
				.sun_path  =DEFAULT_CTLBASE CTL_SUFFIX };

/* info (showpolicy) socket */
int policy_fd = NULL_FD;
struct sockaddr_un info_addr= { .sun_family=AF_UNIX,
#if defined(HAS_SUN_LEN)
				.sun_len=sizeof(struct sockaddr_un),
#endif				
				.sun_path  =DEFAULT_CTLBASE INFO_SUFFIX };

/* Initialize the control socket.
 * Note: this is called very early, so little infrastructure is available.
 * It is important that the socket is created before the original
 * Pluto process returns.
 */
err_t
init_ctl_socket(void)
{
    err_t failed = NULL;

    LIST_INIT(&interface_dev);

    delete_ctl_socket();	/* preventative medicine */
    ctl_fd = safe_socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctl_fd == -1)
	failed = "create";
    else if (fcntl(ctl_fd, F_SETFD, FD_CLOEXEC) == -1)
	failed = "fcntl FD+CLOEXEC";
    else if (setsockopt(ctl_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof(on)) < 0)
	failed = "setsockopt";
    else
    {
	/* to keep control socket secure, use umask */
#ifdef PLUTO_GROUP_CTL
	mode_t ou = umask(~(S_IRWXU|S_IRWXG));
#else
	mode_t ou = umask(~S_IRWXU);
#endif

	if (bind(ctl_fd, (struct sockaddr *)&ctl_addr
	, offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0)
	    failed = "bind";
	umask(ou);
    }

#ifdef PLUTO_GROUP_CTL
    {
	struct group *g;

	g = getgrnam("pluto");
	if(g != NULL) {
	    if(fchown(ctl_fd, -1, g->gr_gid) != 0) {
		loglog(RC_LOG_SERIOUS, "Can not chgrp ctl fd(%d) to gid=%d: %s\n"
		       , ctl_fd, g->gr_gid, strerror(errno));
	    }
	}
    }
#endif

    /* 5 is a haphazardly chosen limit for the backlog.
     * Rumour has it that this is the max on BSD systems.
     */
    if (failed == NULL && listen(ctl_fd, 5) < 0)
	failed = "listen() on";

    return failed == NULL? NULL : builddiag("could not %s control socket: %d %s"
	    , failed, errno, strerror(errno));
}

void
delete_ctl_socket(void)
{
    /* Is noting failure useful?  Not when used as preventative medicine. */
    unlink(ctl_addr.sun_path);
}

bool listening = FALSE;	/* should we pay attention to IKE messages? */

struct iface_port  *interfaces = NULL;	/* public interfaces */

/* Initialize the interface sockets. */

static void
mark_ifaces_dead(void)
{
    struct iface_port *p;

    for (p = interfaces; p != NULL; p = p->next)
	p->change = IFN_DELETE;
}

static void
free_dead_iface_dev(struct iface_dev *id)
{
    if(--id->id_count == 0) {
	pfree(id->id_vname);
	pfree(id->id_rname);

	LIST_REMOVE(id, id_entry);

	pfree(id);
    }
}

static void
free_dead_ifaces(void)
{
    struct iface_port *p;
    bool some_dead = FALSE
	, some_new = FALSE;

    for (p = interfaces; p != NULL; p = p->next)
    {
	if (p->change == IFN_DELETE)
	{
	    libreswan_log("shutting down interface %s/%s %s:%d"
			 , p->ip_dev->id_vname
			 , p->ip_dev->id_rname
			 , ip_str(&p->ip_addr), p->port);
	    some_dead = TRUE;
	}
	else if (p->change == IFN_ADD)
	{
	    some_new = TRUE;
	}
    }

    if (some_dead)
    {
	struct iface_port **pp;

	release_dead_interfaces();
	delete_states_dead_interfaces();
	for (pp = &interfaces; (p = *pp) != NULL; )
	{
	    if (p->change == IFN_DELETE)
	    {
		struct iface_dev *id;

		*pp = p->next;	/* advance *pp */
		close(p->fd);

		id = p->ip_dev;
		pfree(p);

		free_dead_iface_dev(id);
	    }
	    else
	    {
		pp = &p->next;	/* advance pp */
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

void
free_ifaces(void)
{
    mark_ifaces_dead();
    free_dead_ifaces();
}

struct raw_iface *static_ifn=NULL;

int
create_socket(struct raw_iface *ifp, const char *v_name, int port)
{
    int fd = socket(addrtypeof(&ifp->addr), SOCK_DGRAM, IPPROTO_UDP);
    int fcntl_flags;

    if (fd < 0)
    {
	log_errno((e, "socket() in process_raw_ifaces()"));
	return -1;
    }

    /* Set socket Nonblocking */
    if ((fcntl_flags=fcntl(fd, F_GETFL)) >= 0) {
	if (!(fcntl_flags & O_NONBLOCK)) {
	    fcntl_flags |= O_NONBLOCK;
	    fcntl(fd, F_SETFL, fcntl_flags);
	}
    }

    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
    {
	log_errno((e, "fcntl(,, FD_CLOEXEC) in process_raw_ifaces()"));
	close(fd);
	return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR
    , (const void *)&on, sizeof(on)) < 0)
    {
	log_errno((e, "setsockopt SO_REUSEADDR in process_raw_ifaces()"));
	close(fd);
	return -1;
    }

    /* To improve error reporting.  See ip(7). */
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
    if (setsockopt(fd, SOL_IP, IP_RECVERR
    , (const void *)&on, sizeof(on)) < 0)
    {
	log_errno((e, "setsockopt IP_RECVERR in process_raw_ifaces()"));
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
#ifdef IPV6_USE_MIN_MTU	/* YUCK: not always defined */
    if (addrtypeof(&ifp->addr) == AF_INET6
    && setsockopt(fd, SOL_SOCKET, IPV6_USE_MIN_MTU
      , (const void *)&on, sizeof(on)) < 0)
    {
	log_errno((e, "setsockopt IPV6_USE_MIN_MTU in process_raw_ifaces()"));
	close(fd);
	return -1;
    }
#endif

#if defined(linux) && defined(NETKEY_SUPPORT)
    if (kern_interface == USE_NETKEY)
    {
	struct sadb_x_policy policy;
	int level, opt;

	memset(&policy, 0, sizeof(struct sadb_x_policy));
	policy.sadb_x_policy_len = sizeof(policy) / IPSEC_PFKEYv2_ALIGN;
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
	policy.sadb_x_policy_id = 0;

	if (addrtypeof(&ifp->addr) == AF_INET6)
	{
	    level = IPPROTO_IPV6;
	    opt = IPV6_IPSEC_POLICY;
	}
	else
	{
	    level = IPPROTO_IP;
	    opt = IP_IPSEC_POLICY;
	}

	if (setsockopt(fd, level, opt
	  , &policy, sizeof(policy)) < 0)
	{
	    log_errno((e, "setsockopt IPSEC_POLICY in process_raw_ifaces()"));
	    close(fd);
	    return -1;
	}

	policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;

	if (setsockopt(fd, level, opt
	  , &policy, sizeof(policy)) < 0)
	{
	    log_errno((e, "setsockopt IPSEC_POLICY in process_raw_ifaces()"));
	    close(fd);
	    return -1;
	}
    }
#endif

    setportof(htons(port), &ifp->addr);
    if (bind(fd, sockaddrof(&ifp->addr), sockaddrlenof(&ifp->addr)) < 0)
    {
	log_errno((e, "bind() for %s/%s %s:%u in process_raw_ifaces()"
	    , ifp->name, v_name
	    , ip_str(&ifp->addr), (unsigned) port));
	close(fd);
	return -1;
    }
    setportof(htons(pluto_port), &ifp->addr);

#if defined(HAVE_UDPFROMTO)
    /* we are going to use udpfromto.c, so initialize it */
    udpfromto_init(fd);
#endif

    /* poke a hole for IKE messages in the IPsec layer */
    if(kernel_ops->exceptsocket) {
	if(!(*kernel_ops->exceptsocket)(fd, AF_INET)) {
	    close(fd);
	    return -1;
	}
    }

    return fd;
}

void
find_ifaces(void)
{
    mark_ifaces_dead();

    if(kernel_ops->process_ifaces) {
#if !defined(__CYGWIN32__)
	kernel_ops->process_ifaces(find_raw_ifaces4());
	kernel_ops->process_ifaces(find_raw_ifaces6());
#endif
	kernel_ops->process_ifaces(static_ifn);
    }

    free_dead_ifaces();	    /* ditch remaining old entries */

    if (interfaces == NULL)
	loglog(RC_LOG_SERIOUS, "no public interfaces found");
}

void
show_ifaces_status(void)
{
    struct iface_port *p;

    for (p = interfaces; p != NULL; p = p->next)
	whack_log(RC_COMMENT, "interface %s/%s %s"
	    , p->ip_dev->id_vname, p->ip_dev->id_rname, ip_str(&p->ip_addr));
}

void
show_debug_status(void)
{
#ifdef DEBUG
    whack_log(RC_COMMENT, "debug %s"
	, bitnamesof(debug_bit_names, cur_debugging));
#endif
}

static volatile sig_atomic_t sighupflag = FALSE;

static void
huphandler(int sig UNUSED)
{
    sighupflag = TRUE;
}

static volatile sig_atomic_t sigtermflag = FALSE;

static void
termhandler(int sig UNUSED)
{
    sigtermflag = TRUE;
}

static volatile sig_atomic_t sigchildflag = FALSE;

static void
childhandler(int sig UNUSED)
{
    sigchildflag = TRUE;
}

/* perform wait4() on all children */
static void
reapchildren(void)
{
    pid_t child;
    int status;
    struct rusage r;

    sigchildflag = FALSE;
    errno=0;

    while((child = wait3(&status, WNOHANG, &r)) > 0) {
	/* got a child to reap */
	if(adns_reapchild(child, status)) continue;
	if(child == addconn_child_pid){
		DBG(DBG_CONTROLMORE,DBG_log("reaped addconn helper child"));
		addconn_child_pid = 0;
		continue;
	}
       /*Threads are created instead of child processes when using LIBNSS*/
	libreswan_log("child pid=%d (status=%d) is not my child!", child, status);
    }
    
    if(child == -1) {
	libreswan_log("reapchild failed with errno=%d %s",
		     errno, strerror(errno));
    }
}

/* call_server listens for incoming ISAKMP packets and Whack messages,
 * and handles timer events.
 */
void
call_server(void)
{
    struct iface_port *ifp;

    /* catch SIGHUP and SIGTERM */
    {
	int r;
	struct sigaction act;

	act.sa_handler = &huphandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;	/* no SA_ONESHOT, no SA_RESTART, no nothing */
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


    /* do equivalent of ipsec whack --listen */
        do_whacklisten();

    /*
     * fork to issue the command "ipsec addconn --autoall"
     * (or vfork() when fork() isn't available, eg on embedded platforms
     * without MMU, like uClibc
     */
    {
	/* find a pathname to the addconn program */
	const char *addconn_path = NULL;
	const char *helper_bin_dir = getenv("IPSEC_EXECDIR");
	static const char addconn_name[] = "addconn";
	char addconn_path_space[4096]; /* plenty long? */
	ssize_t n=0;
	if (helper_bin_dir != NULL)
	{
	   n = strlen(helper_bin_dir);
	   if ((size_t)n <= sizeof(addconn_path_space) - sizeof(addconn_name))
	   {
		strcpy(addconn_path_space, helper_bin_dir);
		if (n > 0 && addconn_path_space[n -1] != '/')
		    addconn_path_space[n++] = '/';
	   }
	}
	else
#if !(defined(macintosh) || (defined(__MACH__) && defined(__APPLE__)))
        {
	  /* The program will be in the same directory as Pluto,
	   * so we use the sympolic link /proc/self/exe to
	   * tell us of the path prefix.
	   */
	   n = readlink("/proc/self/exe", addconn_path_space, sizeof(addconn_path_space));
	   if (n < 0)
# ifdef __uClibc__
	   /* on some nommu we have no proc/self/exe, try without path */
	   *addconn_path_space = '\0', n = 0;
# else
	   exit_log_errno((e
		, "readlink(\"/proc/self/exe\") failed in call_server()"));
# endif
	}
#else
	/* This is wrong. Should end up in a resource_dir on MacOSX -- Paul */
	addconn_path="/usr/local/libexec/ipsec/addconn";
#endif
	if ((size_t)n > sizeof(addconn_path_space) - sizeof(addconn_name))
		exit_log("path to %s is too long", addconn_name);
	while (n > 0 && addconn_path_space[n - 1] != '/')
		n--;

	strcpy(addconn_path_space + n, addconn_name);
	addconn_path = addconn_path_space;

	if (access(addconn_path, X_OK) < 0)
		exit_log_errno((e, "%s missing or not executable", addconn_path));

	char *newargv[] = { "addconn", "--autoall", NULL };
	char *newenv[] = { NULL };
#ifdef HAVE_NO_FORK
	addconn_child_pid = vfork(); /* for better, for worse, in sickness and health..... */
#else
	addconn_child_pid = fork();
#endif
	if (addconn_child_pid == 0) {
		/* child */
		sleep(1);
		DBG(DBG_CONTROLMORE,DBG_log("calling addconn helper using execve"));
		execve(addconn_path, newargv, newenv);
		_exit(42);
	}
	/* parent continues */
    }



    for (;;)
    {
	lsw_fd_set readfds;
	lsw_fd_set writefds;
	int ndes;

	/* wait for next interesting thing */

	for (;;)
	{
	    long next_time = next_event();   /* time to any pending timer event */
	    int maxfd = ctl_fd;

	    if (sigtermflag)
		exit_pluto(0);

	    if (sighupflag)
	    {
		/* Ignorant folks think poking any daemon with SIGHUP
		 * is polite.  We catch it and tell them otherwise.
		 * There is one use: unsticking a hung recvfrom.
		 * This sticking happens sometimes -- kernel bug?
		 */
		sighupflag = FALSE;
		libreswan_log("Pluto ignores SIGHUP -- perhaps you want \"whack --listen\"");
	    }

	    if(sigchildflag) {
		reapchildren();
	    }

	    LSW_FD_ZERO(&readfds);
	    LSW_FD_ZERO(&writefds);
	    LSW_FD_SET(ctl_fd, &readfds);

	    /* the only write file-descriptor of interest */
	    if (adns_qfd != NULL_FD && unsent_ADNS_queries)
	    {
		if (maxfd < adns_qfd)
		    maxfd = adns_qfd;
		LSW_FD_SET(adns_qfd, &writefds);
	    }

	    if (adns_afd != NULL_FD)
	    {
		if (maxfd < adns_afd)
		    maxfd = adns_afd;
		LSW_FD_SET(adns_afd, &readfds);
	    }

#ifdef KLIPS
	    if (kern_interface != NO_KERNEL)
	    {
		int fd = *kernel_ops->async_fdp;

		if (kernel_ops->process_queue)
		    kernel_ops->process_queue();
		if (maxfd < fd)
		    maxfd = fd;
		passert(!LSW_FD_ISSET(fd, &readfds));
		LSW_FD_SET(fd, &readfds);
	    }
#endif

	    if (listening)
	    {
		for (ifp = interfaces; ifp != NULL; ifp = ifp->next)
		{
		    if (maxfd < ifp->fd)
			maxfd = ifp->fd;
		    passert(!LSW_FD_ISSET(ifp->fd, &readfds));
		    LSW_FD_SET(ifp->fd, &readfds);
		}
	    }

	    /* see if helpers need attention */
	    pluto_crypto_helper_sockets(&readfds);

	    if (no_retransmits || next_time < 0)
	    {
		/* select without timer */

		ndes = lsw_select(maxfd + 1, &readfds, &writefds, NULL, NULL);
	    }
	    else if (next_time == 0)
	    {
		/* timer without select: there is a timer event pending,
		 * and it should fire now so don't bother to do the select.
		 */
		ndes = 0;	/* signify timer expiration */
	    }
	    else
	    {
		/* select with timer */

		struct timeval tm;

		tm.tv_sec = next_time;
		tm.tv_usec = 0;
		ndes = lsw_select(maxfd + 1, &readfds, &writefds, NULL, &tm);
	    }

	    if (ndes != -1)
		break;	/* success */

	    if (errno != EINTR)
		exit_log_errno((e, "select() failed in call_server()"));

	    /* retry if terminated by signal */
	}

	DBG(DBG_CONTROL, DBG_log(" "));

	/*
	 * we log the time when we are about to do something so that
	 * we know what time things happened, when not using syslog
	 */
	if(log_to_stderr_desired) {
	    time_t n;
	    
	    static time_t lastn = 0;

	    time(&n);

	    if(log_did_something) { 
		lastn=n;
		log_did_something=FALSE;
		if((n-lastn) > 60) {
		    DBG_log("time is %s (%lu)", ctime(&n), (unsigned long)n);
		}
	    }
	}
		    
	/* figure out what is interesting */
	/* do FD's before events are processed */

	if (ndes > 0)
	{
	    /* at least one file descriptor is ready */

	    if (adns_qfd != NULL_FD && LSW_FD_ISSET(adns_qfd, &writefds))
	    {
		passert(ndes > 0);
		send_unsent_ADNS_queries();
		passert(GLOBALS_ARE_RESET());
		ndes--;
	    }

	    if (adns_afd != NULL_FD && LSW_FD_ISSET(adns_afd, &readfds))
	    {
		passert(ndes > 0);
		DBG(DBG_CONTROL,
		    DBG_log("*received adns message"));
		handle_adns_answer();
		passert(GLOBALS_ARE_RESET());
		ndes--;
	    }

#ifdef KLIPS
	    if (kern_interface != NO_KERNEL
		&& LSW_FD_ISSET(*kernel_ops->async_fdp, &readfds))
	    {
		passert(ndes > 0);
		DBG(DBG_CONTROL,
		    DBG_log("*received kernel message"));
		kernel_ops->process_msg();
		passert(GLOBALS_ARE_RESET());
		ndes--;
	    }
#endif

	    for (ifp = interfaces; ifp != NULL; ifp = ifp->next)
	    {
		if (LSW_FD_ISSET(ifp->fd, &readfds))
		{
		    /* comm_handle will print DBG_CONTROL intro,
		     * with more info than we have here.
		     */

		    passert(ndes > 0);
		    comm_handle(ifp);
		    passert(GLOBALS_ARE_RESET());
		    ndes--;
		}
	    }

	    if (LSW_FD_ISSET(ctl_fd, &readfds))
	    {
		passert(ndes > 0);
		DBG(DBG_CONTROL,
		    DBG_log("*received whack message"));
		whack_handle(ctl_fd);
		passert(GLOBALS_ARE_RESET());
		ndes--;
	    }

	    /* note we process helper things last on purpose */
	    {
		int helpers = pluto_crypto_helper_ready(&readfds);
		DBG(DBG_CONTROL, DBG_log("* processed %d messages from cryptographic helpers\n", helpers));
		
		ndes -= helpers;
	    }

	    passert(ndes == 0);
	}
	if (next_event() == 0 && !no_retransmits)
	{
	    /* timer event ready */
	    DBG(DBG_CONTROL, DBG_log("*time to handle event"));
	    handle_timer_event();
	    passert(GLOBALS_ARE_RESET());
	}
    }
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
bool
check_msg_errqueue(const struct iface_port *ifp, short interest)
{
    struct pollfd pfd;

    pfd.fd = ifp->fd;
    pfd.events = interest | POLLPRI | POLLOUT;

    while (pfd.revents = 0
    , poll(&pfd, 1, -1) > 0 && (pfd.revents & POLLERR))
    {
	u_int8_t buffer[3000];	/* hope that this is big enough */
	union
	{
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
	char fromstr[sizeof(" for message to  port 65536") + INET6_ADDRSTRLEN];
	struct state *sender = NULL;

	zero(&from.sa);

	emh.msg_name = &from.sa;	/* ??? filled in? */
	emh.msg_namelen = sizeof(from);
	emh.msg_iov = &eiov;
	emh.msg_iovlen = 1;
	emh.msg_control = &ecms_buf;
	emh.msg_controllen = sizeof(ecms_buf);
	emh.msg_flags = 0;

	eiov.iov_base = buffer;	/* see readv(2) */
	eiov.iov_len = sizeof(buffer);

	packet_len = recvmsg(ifp->fd, &emh, MSG_ERRQUEUE);

	if (packet_len == -1)
	{
	    log_errno((e, "recvmsg(,, MSG_ERRQUEUE) on %s failed in comm_handle"
		, ifp->ip_dev->id_rname));
	    break;
	}
	else if (packet_len == sizeof(buffer))
	{
	    libreswan_log("MSG_ERRQUEUE message longer than %lu bytes; truncated"
		, (unsigned long) sizeof(buffer));
	}
	else
	{
	    sender = find_sender((size_t) packet_len, buffer);
	}

	DBG_cond_dump(DBG_ALL, "rejected packet:\n", buffer, packet_len);
	DBG_cond_dump(DBG_ALL, "control:\n", emh.msg_control, emh.msg_controllen);
	/* ??? Andi Kleen <ak@suse.de> and misc documentation
	 * suggests that name will have the original destination
	 * of the packet.  We seem to see msg_namelen == 0.
	 * Andi says that this is a kernel bug and has fixed it.
	 * Perhaps in 2.2.18/2.4.0.
	 */
	passert(emh.msg_name == &from.sa);
	DBG_cond_dump(DBG_ALL, "name:\n", emh.msg_name
	    , emh.msg_namelen);

	fromstr[0] = '\0';	/* usual case :-( */
	switch (from.sa.sa_family)
	{
	char as[INET6_ADDRSTRLEN];

	case AF_INET:
	    if (emh.msg_namelen == sizeof(struct sockaddr_in))
		snprintf(fromstr, sizeof(fromstr)
		, " for message to %s port %u"
		    , inet_ntop(from.sa.sa_family
		    , &from.sa_in4.sin_addr, as, sizeof(as))
		    , ntohs(from.sa_in4.sin_port));
	    break;
	case AF_INET6:
	    if (emh.msg_namelen == sizeof(struct sockaddr_in6))
		snprintf(fromstr, sizeof(fromstr)
		    , " for message to %s port %u"
		    , inet_ntop(from.sa.sa_family
		    , &from.sa_in6.sin6_addr, as, sizeof(as))
		    , ntohs(from.sa_in6.sin6_port));
	    break;
	}

	for (cm = CMSG_FIRSTHDR(&emh)
		 ; cm != NULL
		 ; cm = CMSG_NXTHDR(&emh,cm))
	{
	    if (cm->cmsg_level == SOL_IP
		&& cm->cmsg_type == IP_RECVERR)	{
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
		struct sock_extended_err *ee = (void *)CMSG_DATA(cm);
		const char *offstr = "unspecified";
		char offstrspace[INET6_ADDRSTRLEN];
		char orname[50];

		if (cm->cmsg_len > CMSG_LEN(sizeof(struct sock_extended_err)))
		{
		    const struct sockaddr *offender = SO_EE_OFFENDER(ee);

		    switch (offender->sa_family)
		    {
		    case AF_INET:
			offstr = inet_ntop(offender->sa_family
			    , &((const struct sockaddr_in *)offender)->sin_addr
			    , offstrspace, sizeof(offstrspace));
			break;
		    case AF_INET6:
			offstr = inet_ntop(offender->sa_family
			    , &((const struct sockaddr_in6 *)offender)->sin6_addr
			    , offstrspace, sizeof(offstrspace));
			break;
		    default:
			offstr = "unknown";
			break;
		    }
		}

		switch (ee->ee_origin)
		{
		case SO_EE_ORIGIN_NONE:
		    snprintf(orname, sizeof(orname), "none");
		    break;
		case SO_EE_ORIGIN_LOCAL:
		    snprintf(orname, sizeof(orname), "local");
		    break;
		case SO_EE_ORIGIN_ICMP:
		    snprintf(orname, sizeof(orname)
			, "ICMP type %d code %d (not authenticated)"
			, ee->ee_type, ee->ee_code
			);
		    break;
		case SO_EE_ORIGIN_ICMP6:
		    snprintf(orname, sizeof(orname)
			, "ICMP6 type %d code %d (not authenticated)"
			, ee->ee_type, ee->ee_code
			);
		    break;
		default:
		    snprintf(orname, sizeof(orname), "invalid origin %lu"
			, (unsigned long) ee->ee_origin);
		    break;
		}

		{
		    struct state *old_state = cur_state;

		    cur_state = sender;

		    /* note dirty trick to suppress ~ at start of format
		     * if we know what state to blame.
		     */
#ifdef NAT_TRAVERSAL
		    if ((packet_len == 1) && (buffer[0] == 0xff)
#ifdef DEBUG
			&& ((cur_debugging & DBG_NATT) == 0)
#endif
			) {
			    /* don't log NAT-T keepalive related errors unless NATT debug is
			     * enabled
			     */
		    }
		    else
#endif
		    libreswan_log((sender != NULL) + "~"
			"ERROR: asynchronous network error report on %s (sport=%d)"
			"%s"
			", complainant %s"
			": %s"
			" [errno %lu, origin %s"
			/* ", pad %d, info %ld" */
			/* ", data %ld" */
			"]"
			, ifp->ip_dev->id_rname
				 , ifp->port
			, fromstr
			, offstr
			, strerror(ee->ee_errno)
			, (unsigned long) ee->ee_errno
			, orname
			/* , ee->ee_pad, (unsigned long)ee->ee_info */
			/* , (unsigned long)ee->ee_data */
			);
		    cur_state = old_state;
		}
	    }
	    else if (cm->cmsg_level == SOL_IP
		     && cm->cmsg_type == IP_PKTINFO) {
	    }
	    else
	    {
		/* .cmsg_len is a kernel_size_t(!), but the value
		 * certainly ought to fit in an unsigned long.
		 */
		libreswan_log("unknown cmsg: level %d, type %d, len %lu"
		    , cm->cmsg_level, cm->cmsg_type
		    , (unsigned long) cm->cmsg_len);
	    }
	}
    }
    return (pfd.revents & interest) != 0;
}
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

bool
send_packet(struct state *st, const char *where, bool verbose)
{
    u_int8_t ike_pkt[MAX_OUTPUT_UDP_SIZE];
    u_int8_t *ptr;
    unsigned long len;
    ssize_t wlen;

    if ((st->st_interface->ike_float == TRUE) && (st->st_tpacket.len != 1)) {
	if ((unsigned long) st->st_tpacket.len >
	    (MAX_OUTPUT_UDP_SIZE-sizeof(u_int32_t))) {
	    DBG_log("send_packet(): really too big");
	    return FALSE;
	}
	ptr = ike_pkt;
	/** Add Non-ESP marker **/
	memset(ike_pkt, 0, sizeof(u_int32_t));
	memcpy(ike_pkt + sizeof(u_int32_t), st->st_tpacket.ptr,
	       (unsigned long)st->st_tpacket.len);
	len = (unsigned long) st->st_tpacket.len + sizeof(u_int32_t);
    }
    else {
	ptr = st->st_tpacket.ptr;
	len = (unsigned long) st->st_tpacket.len;
    }

    DBG(DBG_CONTROL|DBG_RAW
	, DBG_log("sending %lu bytes for %s through %s:%d to %s:%u (using #%lu)"
		  , (unsigned long) st->st_tpacket.len
		  , where
		  , st->st_interface->ip_dev->id_rname
		  , st->st_interface->port
		  , ip_str(&st->st_remoteaddr)
		  , st->st_remoteport
		  , st->st_serialno));
    DBG(DBG_RAW
	, DBG_dump(NULL, ptr, len));

    setportof(htons(st->st_remoteport), &st->st_remoteaddr);

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
    (void) check_msg_errqueue(st->st_interface, POLLOUT);
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

    wlen = sendto(st->st_interface->fd
		  , ptr
		  , len, 0
		  , sockaddrof(&st->st_remoteaddr)
		  , sockaddrlenof(&st->st_remoteaddr));

#ifdef DEBUG
    /* XXX This is a flow change depending on debug. not good. I assume it is only useful
     * for actual debugging something 
     */
    if(DBGP(IMPAIR_JACOB_TWO_TWO)) {
	/* sleep for half a second, and second another packet */
	usleep(500000);

	DBG_log("JACOB 2-2: resending %lu bytes for %s through %s:%d to %s:%u:"
		, (unsigned long) st->st_tpacket.len
		, where
		, st->st_interface->ip_dev->id_rname
		, st->st_interface->port
		, ip_str(&st->st_remoteaddr)
		, st->st_remoteport);

	wlen = sendto(st->st_interface->fd
		      , ptr
		      , len, 0
		      , sockaddrof(&st->st_remoteaddr)
		      , sockaddrlenof(&st->st_remoteaddr));
    }
#endif

    if (wlen != (ssize_t)len)
    {
        /* do not log NAT-T Keep Alive packets */
        if (!verbose)
	    return FALSE; 
	log_errno((e, "sendto on %s to %s:%u failed in %s"
		   , st->st_interface->ip_dev->id_rname
		   , ip_str(&st->st_remoteaddr)
		   , st->st_remoteport
		   , where));
	return FALSE;
    }
    else
    {
	return TRUE;
    }
}



/*
 * Local Variables:
 * c-basic-offset: 4
 * End Variables:
 */
