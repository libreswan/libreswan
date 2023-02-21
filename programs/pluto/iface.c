/* iface, for libreswan
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

#include <sys/types.h>
#include <sys/socket.h>		/* MSG_ERRQUEUE if defined */

#include <errno.h>
#include <unistd.h>		/* for close() */
#include <fcntl.h>

#ifdef MSG_ERRQUEUE
# include <netinet/in.h> 	/* for IP_RECVERR */
#endif

#include "lsw_socket.h"

#include "defs.h"

#include "iface.h"
#include "log.h"
#include "host_pair.h"			/* for release_dead_interfaces() */
#include "state.h"			/* for delete_states_dead_interfaces() */
#include "server.h"			/* for *_pluto_event() */
#include "kernel_iface.h"
#include "demux.h"
#include "ip_info.h"
#include "ip_sockaddr.h"
#include "ip_encap.h"
#include "kernel.h"			/* for kernel_ops_detect_offload() */
#include "nat_traversal.h"		/* for nat_traversal_enabled which seems like a broken idea */
#include "show.h"

char *pluto_listen = NULL;		/* from --listen flag */
struct iface_endpoint *interfaces = NULL;  /* public interfaces */

static void jam_iface_endpoint(struct jambuf *buf, const struct iface_endpoint *ifp)
{
	jam(buf, "%d", ifp->fd);
}

LIST_INFO(iface_endpoint, entry, iface_endpoint_info, jam_iface_endpoint);
static struct list_head iface_endpoints = INIT_LIST_HEAD(&iface_endpoints,
							 &iface_endpoint_info);

/*
 * The interfaces - eth0 ...
 */

static void jam_iface_dev(struct jambuf *buf, const struct iface_dev *ifd)
{
	jam_string(buf, ifd->id_rname);
}

LIST_INFO(iface_dev, ifd_entry, iface_dev_info, jam_iface_dev);

static struct list_head interface_dev = INIT_LIST_HEAD(&interface_dev,
						       &iface_dev_info);

static void free_iface_dev(void *obj, where_t where UNUSED)
{
	struct iface_dev *ifd = obj;
	remove_list_entry(&ifd->ifd_entry);
	pfree(ifd->id_rname);
	pfree(ifd);
}

static void add_iface_dev(const struct raw_iface *ifp, struct logger *logger)
{
	where_t where = HERE;
	struct iface_dev *ifd = refcnt_alloc(struct iface_dev, free_iface_dev, where);
	ifd->id_rname = clone_str(ifp->name, "real device name");
	ifd->id_nic_offload = kernel_ops_detect_offload(ifp, logger);
	ifd->id_address = ifp->addr;
	ifd->ifd_change = IFD_ADD;
	init_list_entry(&iface_dev_info, ifd, &ifd->ifd_entry);
	insert_list_entry(&interface_dev, &ifd->ifd_entry);
	dbg("iface: marking %s add", ifd->id_rname);
}

struct iface_dev *find_iface_dev_by_address(const ip_address *address)
{
	struct iface_dev *ifd;
	FOR_EACH_LIST_ENTRY_OLD2NEW(ifd, &interface_dev) {
		if (sameaddr(address, &ifd->id_address)) {
			return ifd;
		}
	}
	return NULL;
}

static void mark_ifaces_dead(void)
{
	struct iface_dev *ifd;
	FOR_EACH_LIST_ENTRY_OLD2NEW(ifd, &interface_dev) {
		dbg("iface: marking %s dead", ifd->id_rname);
		ifd->ifd_change = IFD_DELETE;
	}
}

static void add_or_keep_iface_dev(struct raw_iface *ifp, struct logger *logger)
{
	/* find the iface */
	struct iface_dev *ifd;
	FOR_EACH_LIST_ENTRY_OLD2NEW(ifd, &interface_dev) {
		if (streq(ifd->id_rname, ifp->name) &&
		    sameaddr(&ifd->id_address, &ifp->addr)) {
			dbg("iface: marking %s keep", ifd->id_rname);
			ifd->ifd_change = IFD_KEEP;
			return;
		}
	}
	add_iface_dev(ifp, logger);
}

void release_iface_dev(struct iface_dev **id)
{
	delref(id);
}

static void free_dead_ifaces(struct logger *logger)
{
	struct iface_endpoint *p;
	bool some_dead = false;
	bool some_new = false;

	/*
	 * XXX: this iterates over the interface, and not the
	 * interface_devs, so that it can list all IFACE_PORTs being
	 * shutdown before shutting them down.  Is this useful?
	 */
	dbg("updating interfaces - listing interfaces that are going down");
	for (p = interfaces; p != NULL; p = p->next) {
		if (p->ip_dev->ifd_change == IFD_DELETE) {
			endpoint_buf b;
			llog(RC_LOG, logger,
				    "shutting down interface %s %s",
				    p->ip_dev->id_rname,
				    str_endpoint(&p->local_endpoint, &b));
			some_dead = true;
		} else if (p->ip_dev->ifd_change == IFD_ADD) {
			some_new = true;
		}
	}

	if (some_dead) {
		dbg("updating interfaces - deleting the dead");
		/*
		 * Delete any iface_port's pointing at the dead
		 * iface_dev.
		 */
		release_dead_interfaces(logger);
		delete_states_dead_interfaces(logger);
		for (struct iface_endpoint **pp = &interfaces; (p = *pp) != NULL; ) {
			if (p->ip_dev->ifd_change == IFD_DELETE) {
				*pp = p->next; /* advance *pp (skip p) */
				p->next = NULL;
				iface_endpoint_delref(&p);
			} else {
				pp = &p->next; /* advance pp */
			}
		}

		/*
		 * Finally, release the iface_dev, from its linked
		 * list of iface devs.
		 */
		struct iface_dev *ifd;
		FOR_EACH_LIST_ENTRY_OLD2NEW(ifd, &interface_dev) {
			if (ifd->ifd_change == IFD_DELETE) {
				release_iface_dev(&ifd);
			}
		}
	}

	/* this must be done after the release_dead_interfaces
	 * in case some to the newly unoriented connections can
	 * become oriented here.
	 */
	if (some_dead || some_new) {
		dbg("updating interfaces - checking orientation");
		check_orientations(logger);
	}
}


static void free_iface_endpoint(void *o, where_t where UNUSED)
{
	struct iface_endpoint *ifp = o;
	/* drop any lists */
	pexpect(ifp->next == NULL);
	remove_list_entry(&ifp->entry);
	/* generic stuff */
	ifp->io->cleanup(ifp);
	release_iface_dev(&ifp->ip_dev);
	/* XXX: after cleanup so code can log FD */
	close(ifp->fd);
	ifp->fd = -1;
	pfree(ifp);
}

struct iface_endpoint *alloc_iface_endpoint(int fd,
					    struct iface_dev *ifd,
					    const struct iface_io *io,
					    bool esp_encapsulation_enabled,
					    bool float_nat_initiator,
					    ip_endpoint local_endpoint,
					    where_t where)
{
	struct iface_endpoint *ifp = refcnt_alloc(struct iface_endpoint,
						  free_iface_endpoint,
						  where);
	ifp->fd = fd;
	ifp->ip_dev = addref_where(ifd, where);
	ifp->io = io;
	ifp->esp_encapsulation_enabled = esp_encapsulation_enabled;
	ifp->float_nat_initiator = float_nat_initiator;
	ifp->local_endpoint = local_endpoint;
	init_list_entry(&iface_endpoint_info, ifp, &ifp->entry);
	insert_list_entry(&iface_endpoints, &ifp->entry);
	return ifp;
}

void iface_endpoint_delref_where(struct iface_endpoint **ifp, where_t where)
{
	delref_where(ifp, where);
}

struct iface_endpoint *iface_endpoint_addref_where(struct iface_endpoint *ifp, where_t where)
{
	return addref_where(ifp, where);
}


struct iface_endpoint *bind_iface_endpoint(struct iface_dev *ifd,
					   const struct iface_io *io,
					   ip_port port,
					   bool esp_encapsulation_enabled,
					   bool float_nat_initiator,
					   struct logger *logger)
{
#define BIND_ERROR(MSG, ...)						\
	{								\
		int e = errno;						\
		endpoint_buf eb;					\
		llog_error(logger, e,					\
			   "bind %s %s endpoint %s failed, "MSG,	\
			   ifd->id_rname, io->protocol->name,		\
			   str_endpoint(&local_endpoint, &eb),		\
			   ##__VA_ARGS__);				\
	}

	const struct ip_info *afi = address_type(&ifd->id_address);
	ip_endpoint local_endpoint = endpoint_from_address_protocol_port(ifd->id_address,
									 io->protocol, port);
	if (esp_encapsulation_enabled &&
	    io->protocol->encap_esp->encap_type == 0) {
		errno = 0; /*no-errno*/
		BIND_ERROR("%s encapsulation is not configured (problem with kernel headers?)",
			   io->protocol->encap_esp->name);
		return NULL;
	}

	int fd = cloexec_socket(afi->socket.domain, io->socket.type|SOCK_NONBLOCK, io->protocol->ipproto);
	if (fd < 0) {
		BIND_ERROR("cloexec_socket(%s, %s|SOCK_NONBLOCK, %s)",
			   afi->socket.domain_name, io->socket.type_name, io->protocol->name);
		return NULL;
	}

	static const int on = true;     /* by-reference parameter; constant, we hope */

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&on, sizeof(on)) < 0) {
		BIND_ERROR("setsockopt(SOL_SOCKET, SO_REUSEADDR)");
		close(fd);
		return NULL;
	}

#ifdef SO_PRIORITY
	static const int so_prio = 6; /* rumored maximum priority, might be 7 on linux? */
	if (setsockopt(fd, SOL_SOCKET, SO_PRIORITY, (const void *)&so_prio,
		       sizeof(so_prio)) < 0) {
		BIND_ERROR("setsockopt(SOL_SOCKET, SO_PRIORITY)");
		/* non-fatal; stumble on */
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
		if (setsockopt(fd, SOL_SOCKET, so_rcv, (const void *)&pluto_sock_bufsize,
			       sizeof(pluto_sock_bufsize)) < 0) {
			BIND_ERROR("setsockopt(SOL_SOCKET, SO_RCVBUFFORCE)");
			/* non-fatal; stumble on */
		}
		if (setsockopt(fd, SOL_SOCKET, so_snd, (const void *)&pluto_sock_bufsize,
			       sizeof(pluto_sock_bufsize)) < 0) {
			BIND_ERROR("setsockopt(SOL_SOCKET, SO_SNDBUFFORCE)");
			/* non-fatal; stumble on */
		}
	}

	/* To improve error reporting.  See ip(7). */
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	if (pluto_sock_errqueue) {
		if (setsockopt(fd, SOL_IP, IP_RECVERR, (const void *)&on, sizeof(on)) < 0) {
			BIND_ERROR("setsockopt(SOL_IP, IP_RECVERR)");
			close(fd);
			return NULL;
		}
	}
#endif

	/*
	 * With IPv6, there is no fragmentation after it leaves our
	 * interface.  PMTU discovery is mandatory but doesn't work
	 * well with IKE (why?).  So we must set the IPV6_USE_MIN_MTU
	 * option.
	 *
	 * See draft-ietf-ipngwg-rfc2292bis-01.txt 11.1
	 */
#ifdef IPV6_USE_MIN_MTU /* YUCK: not always defined */
	if (afi == &ipv6_info &&
	    setsockopt(fd, IPPROTO_IPV6, IPV6_USE_MIN_MTU,
		       (const void *)&on, sizeof(on)) < 0) {
		BIND_ERROR("setsockopt(IPPROTO_IPV6, IPV6_USE_MIN_MTU)");
		close(fd);
		return NULL;
	}
#endif

	/*
	 * NETKEY requires us to poke an IPsec policy hole that allows
	 * IKE packets, unlike KLIPS which implicitly always allows
	 * plaintext IKE.  This installs one IPsec policy per socket
	 * but this function is called for each: IPv4 port 500 and
	 * 4500 IPv6 port 500.
	 */
	if (kernel_ops->poke_ipsec_policy_hole != NULL &&
	    !kernel_ops->poke_ipsec_policy_hole(fd, afi, logger)) {
		/* already logged */
		close(fd);
		return NULL;
	}

	ip_sockaddr if_sa = sockaddr_from_endpoint(local_endpoint);
	if (bind(fd, &if_sa.sa.sa, if_sa.len) < 0) {
		BIND_ERROR("bind()");
		close(fd);
		return NULL;
	}

	struct iface_endpoint *ifp =
		alloc_iface_endpoint(fd, ifd, io,
				     esp_encapsulation_enabled,
				     float_nat_initiator,
				     local_endpoint,
				     HERE);

	/*
	 * Insert into public interface list.
	 *
	 * This is the first reference, caller, if it wants to save
	 * IFP must addref.
	 */
	ifp->next = interfaces;
	interfaces = ifp;

	if (esp_encapsulation_enabled &&
	    io->enable_esp_encap != NULL &&
	    !io->enable_esp_encap(ifp, logger)) {
		llog(RC_LOG_SERIOUS, logger,
		     "NAT-Traversal: ESPINUDP for this kernel not supported or not found for family %s; NAT-traversal is turned OFF", afi->af_name);
		nat_traversal_enabled = false;
	}

	endpoint_buf b;
	llog(RC_LOG, logger,
	     "adding %s interface %s %s",
	     io->protocol->name, ifp->ip_dev->id_rname,
	     str_endpoint(&ifp->local_endpoint, &b));

	return ifp;
#undef BIND_ERROR
}

/*
 * Open new interfaces.
 */

static void add_new_ifaces(struct logger *logger)
{
	struct iface_dev *ifd;
	FOR_EACH_LIST_ENTRY_OLD2NEW(ifd, &interface_dev) {
		if (ifd->ifd_change != IFD_ADD)
			continue;

		/*
		 * Port 500 must not add the ESP encapsulation prefix.
		 * And, when NAT is detected, float away.
		 */
		if (pluto_listen_udp) {
			if (bind_iface_endpoint(ifd, &udp_iface_io,
						ip_hport(IKE_UDP_PORT),
						false /*esp_encapsulation_enabled*/,
						true /*float_nat_initiator*/,
						logger) == NULL) {
				ifd->ifd_change = IFD_DELETE;
				continue;
			}
		}

		/*
		 * Port 4500 must add the ESP encapsulation
		 * prefix.  Let it float to itself - code
		 * might rely on it?
		 */
		if (pluto_listen_udp) {
			/* XXX: ignore any errors!?! */
			bind_iface_endpoint(ifd, &udp_iface_io,
					    ip_hport(NAT_IKE_UDP_PORT),
					    true /*esp_encapsulation_enabled*/,
					    true /*float_nat_initiator*/,
					    logger);
		}

		/*
		 * An explicit {left,right} IKE TCP PORT must enable
		 * ESPINUDP so that it can tunnel NAT.  This means
		 * that incoming packets must add the ESP=0 prefix,
		 * which in turn means that it can't interop with port
		 * 500 as that port will never send the ESP=0 prefix.
		 *
		 * See comments in iface.h.
		 */
		if (pluto_listen_tcp) {
			/* XXX: ignore any errors!?! */
			bind_iface_endpoint(ifd, &iketcp_iface_io,
					    ip_hport(NAT_IKE_UDP_PORT),
					    true /*esp_encapsulation_enabled*/,
					    false /*float_nat_initiator*/,
					    logger);
		}
	}
}

void listen_on_iface_endpoint(struct iface_endpoint *ifp, struct logger *logger)
{
	ifp->io->listen(ifp, logger);
	endpoint_buf b;
	dbg("setup callback for interface %s %s fd %d on %s",
	    ifp->ip_dev->id_rname,
	    str_endpoint(&ifp->local_endpoint, &b),
	    ifp->fd, ifp->io->protocol->name);
}

static void process_raw_ifaces(struct raw_iface *rifaces, struct logger *logger)
{
	ip_address lip;	/* --listen filter option */

	if (pluto_listen) {
		err_t e = ttoaddress_num(shunk1(pluto_listen), NULL/*UNSPEC*/, &lip);

		if (e != NULL) {
			DBG_log("invalid listen= option ignored: %s", e);
			pluto_listen = NULL;
		}
		address_buf b;
		dbg("Only looking to listen on %s", str_address(&lip, &b));
	}

	struct raw_iface *ifp;

	for (ifp = rifaces; ifp != NULL; ifp = ifp->next) {
		bool after = false;	/* has vfp passed ifp on the list? */
		bool bad = false;
		struct raw_iface *vfp;

		for (vfp = rifaces; vfp != NULL; vfp = vfp->next) {
			if (vfp == ifp) {
				after = true;
			} else if (sameaddr(&ifp->addr, &vfp->addr)) {
				if (after) {
					ipstr_buf b;

					llog(RC_LOG_SERIOUS, logger,
					            "IP interfaces %s and %s share address %s!",
					       ifp->name, vfp->name,
					       ipstr(&ifp->addr, &b));
				}
				bad = true;
				/* continue just to find other duplicates */
			}
		}

		if (bad)
			continue;

		/*
		 * last check before we actually add the entry.
		 *
		 * ignore if --listen is specified and we do not match
		 */
		if (pluto_listen != NULL && !sameaddr(&lip, &ifp->addr)) {
			ipstr_buf b;

			llog(RC_LOG, logger,
				    "skipping interface %s with %s",
				    ifp->name, ipstr(&ifp->addr, &b));
			continue;
		}

		/*
		 * We've got all we need; see if this is a new thing:
		 * search old interfaces list.
		 */
		add_or_keep_iface_dev(ifp, logger);
	}

	/* delete the raw interfaces list */
	while (rifaces != NULL) {
		struct raw_iface *t = rifaces;

		rifaces = t->next;
		pfree(t);
	}
}

void find_ifaces(bool rm_dead, struct logger *logger)
{
	/*
	 * Sweep the interfaces, after this each is either KEEP, DEAD,
	 * or ADD.
	 */
	mark_ifaces_dead();
	process_raw_ifaces(find_raw_ifaces4(logger), logger);
	process_raw_ifaces(find_raw_ifaces6(logger), logger);
	add_new_ifaces(logger);

	if (rm_dead)
		free_dead_ifaces(logger); /* ditch remaining old entries */

	if (interfaces == NULL)
		llog(RC_LOG_SERIOUS, logger, "no public interfaces found");

	if (listening) {
		for (struct iface_endpoint *ifp = interfaces; ifp != NULL; ifp = ifp->next) {
			listen_on_iface_endpoint(ifp, logger);
		}
	}
}

struct iface_endpoint *find_iface_endpoint_by_local_endpoint(ip_endpoint local_endpoint)
{
	for (struct iface_endpoint *p = interfaces; p != NULL; p = p->next) {
		if (endpoint_eq_endpoint(local_endpoint, p->local_endpoint)) {
			return p;
		}
	}
	return NULL;
}

void show_ifaces_status(struct show *s)
{
	show_separator(s); /* if needed */
	for (struct iface_endpoint *p = interfaces; p != NULL; p = p->next) {
		endpoint_buf b;
		show_comment(s, "interface %s %s %s",
			     p->ip_dev->id_rname,
			     p->io->protocol->name,
			     str_endpoint(&p->local_endpoint, &b));
	}
}

void shutdown_ifaces(struct logger *logger)
{
	/* clean up public interfaces */
	mark_ifaces_dead();
	free_dead_ifaces(logger);
	/* clean up remaining hidden interfaces */
	struct iface_endpoint *ifp;
	FOR_EACH_LIST_ENTRY_NEW2OLD(ifp, &iface_endpoints) {
		iface_endpoint_delref(&ifp);
	}
}
