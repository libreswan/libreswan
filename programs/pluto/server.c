/* get-next-event loop
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 * RCSID $Id: server.c,v 1.113 2005/08/27 05:51:00 paul Exp $
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
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */
#include <sys/resource.h>
#include <sys/wait.h>

#include <openswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
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
#include "rcv_info.h"
#include "keys.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "pluto_crypt.h" /* cryptographic helper functions */
#include "udpfromto.h"

#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>
#include "kameipsec.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

/*
 *  Server main loop and socket initialization routines.
 */

static const int on = TRUE;	/* by-reference parameter; constant, we hope */

bool no_retransmits = FALSE;

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
    ctl_fd = socket(AF_UNIX, SOCK_STREAM, 0);
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

#ifdef IPSECPOLICY
/* Initialize the info socket.
 */
err_t
init_info_socket(void)
{
    err_t failed = NULL;

    delete_info_socket();	/* preventative medicine */
    info_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (info_fd == -1)
	failed = "create";
    else if (fcntl(info_fd, F_SETFD, FD_CLOEXEC) == -1)
	failed = "fcntl FD+CLOEXEC";
    else if (setsockopt(info_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof(on)) < 0)
	failed = "setsockopt";
    else
    {
	/* this socket should be openable by all proceses */
	mode_t ou = umask(0);

	if (bind(info_fd, (struct sockaddr *)&info_addr
	, offsetof(struct sockaddr_un, sun_path) + strlen(info_addr.sun_path)) < 0)
	    failed = "bind";
	umask(ou);
    }

    /* 64 might be big enough, and the system may limit us anyway.
     */
    if (failed == NULL && listen(info_fd, 64) < 0)
	failed = "listen() on";

    return failed == NULL? NULL : builddiag("could not %s info socket: %d %s"
	    , failed, errno, strerror(errno));
}

void
delete_info_socket(void)
{
    unlink(info_addr.sun_path);
}
#endif /* IPSECPOLICY */


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
	    openswan_log("shutting down interface %s/%s %s:%d"
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

	policy.sadb_x_policy_len = sizeof(policy) / IPSEC_PFKEYv2_ALIGN;
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
	policy.sadb_x_policy_reserved = 0;
	policy.sadb_x_policy_id = 0;
	policy.sadb_x_policy_reserved2 = 0;

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
	if(pluto_crypt_handle_dead_child(child, status)) continue;
	
	openswan_log("child pid=%d (status=%d) is not my child!", child, status);
    }
    
    if(child == -1) {
	openswan_log("reapchild failed with errno=%d %s",
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

    for (;;)
    {
	fd_set readfds;
	fd_set writefds;
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
		openswan_log("Pluto ignores SIGHUP -- perhaps you want \"whack --listen\"");
	    }

	    if(sigchildflag) {
		reapchildren();
	    }

	    FD_ZERO(&readfds);
	    FD_ZERO(&writefds);
	    FD_SET(ctl_fd, &readfds);
#ifdef IPSECPOLICY
	    FD_SET(info_fd, &readfds);
	    if (maxfd < info_fd)
		maxfd = info_fd;
#endif

	    /* the only write file-descriptor of interest */
	    if (adns_qfd != NULL_FD && unsent_ADNS_queries)
	    {
		if (maxfd < adns_qfd)
		    maxfd = adns_qfd;
		FD_SET(adns_qfd, &writefds);
	    }

	    if (adns_afd != NULL_FD)
	    {
		if (maxfd < adns_afd)
		    maxfd = adns_afd;
		FD_SET(adns_afd, &readfds);
	    }

	    if (kern_interface != NO_KERNEL)
	    {
		int fd = *kernel_ops->async_fdp;

		if (kernel_ops->process_queue)
		    kernel_ops->process_queue();
		if (maxfd < fd)
		    maxfd = fd;
		passert(!FD_ISSET(fd, &readfds));
		FD_SET(fd, &readfds);
	    }

	    if (listening)
	    {
		for (ifp = interfaces; ifp != NULL; ifp = ifp->next)
		{
		    if (maxfd < ifp->fd)
			maxfd = ifp->fd;
		    passert(!FD_ISSET(ifp->fd, &readfds));
		    FD_SET(ifp->fd, &readfds);
		}
	    }

	    /* see if helpers need attention */
	    pluto_crypto_helper_sockets(&readfds);

	    if (no_retransmits || next_time < 0)
	    {
		/* select without timer */

		ndes = select(maxfd + 1, &readfds, &writefds, NULL, NULL);
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
		ndes = select(maxfd + 1, &readfds, &writefds, NULL, &tm);
	    }

	    if (ndes != -1)
		break;	/* success */

	    if (errno != EINTR)
		exit_log_errno((e, "select() failed in call_server()"));

	    /* retry if terminated by signal */
	}

	DBG(DBG_CONTROL, DBG_log(BLANK_FORMAT));

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

	if (ndes == 0)
	{
	    /* timer event */

	    if(!no_retransmits)
	    {
		DBG(DBG_CONTROL,
		    DBG_log("*time to handle event"));
		
		handle_timer_event();
		passert(GLOBALS_ARE_RESET());
	    }
	}
	else
	{
	    /* at least one file descriptor is ready */

	    if (adns_qfd != NULL_FD && FD_ISSET(adns_qfd, &writefds))
	    {
		passert(ndes > 0);
		send_unsent_ADNS_queries();
		passert(GLOBALS_ARE_RESET());
		ndes--;
	    }

	    if (adns_afd != NULL_FD && FD_ISSET(adns_afd, &readfds))
	    {
		passert(ndes > 0);
		DBG(DBG_CONTROL,
		    DBG_log("*received adns message"));
		handle_adns_answer();
		passert(GLOBALS_ARE_RESET());
		ndes--;
	    }

	    if (kern_interface != NO_KERNEL
		&& FD_ISSET(*kernel_ops->async_fdp, &readfds))
	    {
		passert(ndes > 0);
		DBG(DBG_CONTROL,
		    DBG_log("*received kernel message"));
		kernel_ops->process_msg();
		passert(GLOBALS_ARE_RESET());
		ndes--;
	    }

	    for (ifp = interfaces; ifp != NULL; ifp = ifp->next)
	    {
		if (FD_ISSET(ifp->fd, &readfds))
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

	    if (FD_ISSET(ctl_fd, &readfds))
	    {
		passert(ndes > 0);
		DBG(DBG_CONTROL,
		    DBG_log("*received whack message"));
		whack_handle(ctl_fd);
		passert(GLOBALS_ARE_RESET());
		ndes--;
	    }

#ifdef IPSECPOLICY
	    if (FD_ISSET(info_fd, &readfds))
	    {
		passert(ndes > 0);
		DBG(DBG_CONTROL,
		    DBG_log("*received info message"));
		info_handle(info_fd);
		passert(GLOBALS_ARE_RESET());
		ndes--;
	    }
#endif

	    /* note we process helper things last on purpose */
	    ndes -= pluto_crypto_helper_ready(&readfds);

	    passert(ndes == 0);
	}
    }
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * End Variables:
 */
