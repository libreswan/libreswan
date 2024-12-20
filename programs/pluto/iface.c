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
#include "server.h"			/* for *_pluto_event() */
#include "kernel_iface.h"
#include "demux.h"
#include "ip_info.h"
#include "ip_sockaddr.h"
#include "ip_encap.h"
#include "kernel.h"			/* for kernel_ops_nic_detect_offload() */
#include "show.h"
#include "orient.h"			/* for check_orientations() */
#include "terminate.h"

char *pluto_listen = NULL;		/* from --listen flag */
static struct iface_endpoint *interfaces = NULL;  /* public interfaces */

static size_t jam_iface_endpoint_sep(struct jambuf *buf, bool *first)
{
	size_t s = 0;
	if (*first) {
		s = jam_string(buf, " (");
	} else {
		s = jam_string(buf, " ");
	}
	*first = false;
	return s;
}

static size_t jam_iface_endpoint(struct jambuf *buf, const struct iface_endpoint *ifp)
{
	size_t s = 0;
	s += jam_string(buf, "interface");
	s += jam_string(buf, " ");
	s += jam_string(buf, ifp->ip_dev->real_device_name);
	s += jam_string(buf, " ");
	s += jam_endpoint_address_protocol_port(buf, &ifp->local_endpoint);
	bool first = true;
	if (ifp->esp_encapsulation_enabled) {
		/*
		 * Pointing out that an interface encapsulates its
		 * packets is probably meaningful to no one.  However,
		 * pointing out the consequence - that it allows NAT -
		 * is hopefully meaningful to everyone.
		 */
		s += jam_iface_endpoint_sep(buf, &first);
		s += jam_string(buf, "NAT");
	}
	if (!ifp->float_nat_initiator) {
		s += jam_iface_endpoint_sep(buf, &first);
		s += jam_string(buf, "fixed");
	}
	if (!first) {
		s += jam_string(buf, ")");
	}
	return s;
}

LIST_INFO(iface_endpoint, entry, iface_endpoint_info, jam_iface_endpoint);
static struct list_head iface_endpoints = INIT_LIST_HEAD(&iface_endpoints,
							 &iface_endpoint_info);

/*
 * The interfaces - eth0 ...
 */

static size_t jam_iface(struct jambuf *buf, const struct iface_device *ifd)
{
	return jam_string(buf, ifd->real_device_name);
}

LIST_INFO(iface_device, entry, iface_info, jam_iface);

static struct list_head interface_dev = INIT_LIST_HEAD(&interface_dev,
						       &iface_info);

static void add_iface(const struct kernel_iface *ifp, struct logger *logger)
{
	struct iface_device *ifd = refcnt_alloc(struct iface_device, HERE);
	ifd->real_device_name = clone_str(ifp->name, "real device name");
	ifd->local_address = ifp->addr;
	ifd->ifd_change = IFD_ADD;
	ifd->nic_offload = kernel_ops_detect_nic_offload(ifp->name, logger);
	init_list_entry(&iface_info, ifd, &ifd->entry);
	insert_list_entry(&interface_dev, &ifd->entry);
	dbg("iface: marking %s add", ifd->real_device_name);
}

struct iface_device *iface_device_addref_where(struct iface_device *iface, where_t where)
{
	return addref_where(iface, where);
}

struct iface_device *next_iface_device(struct iface_device *iface)
{
	return NEXT_LIST_ENTRY(&interface_dev, iface, entry, OLD2NEW);
}

struct iface_device *find_iface_device_by_address(const ip_address *address)
{
	struct iface_device *ifd;
	FOR_EACH_LIST_ENTRY_OLD2NEW(ifd, &interface_dev) {
		if (sameaddr(address, &ifd->local_address)) {
			return iface_addref(ifd);
		}
	}
	return NULL;
}

static void mark_ifaces_dead(void)
{
	struct iface_device *ifd;
	FOR_EACH_LIST_ENTRY_OLD2NEW(ifd, &interface_dev) {
		dbg("iface: marking %s dead", ifd->real_device_name);
		ifd->ifd_change = IFD_DELETE;
	}
}

static void add_or_keep_iface_dev(struct kernel_iface *ifp, struct logger *logger)
{
	/* find the iface */
	struct iface_device *ifd;
	FOR_EACH_LIST_ENTRY_OLD2NEW(ifd, &interface_dev) {
		if (streq(ifd->real_device_name, ifp->name) &&
		    sameaddr(&ifd->local_address, &ifp->addr)) {
			dbg("iface: marking %s keep", ifd->real_device_name);
			ifd->ifd_change = IFD_KEEP;
			return;
		}
	}
	add_iface(ifp, logger);
}

void iface_device_delref_where(struct iface_device **ifdp, where_t where)
{
	const struct logger *logger = &global_logger;
	struct iface_device *ifd = delref_where(ifdp, logger, where);
	if (ifd != NULL) {
		/* i.e., last reference */
		remove_list_entry(&ifd->entry);
		pfree(ifd->real_device_name);
		pfree(ifd);
	}
}

static void release_dead_interfaces(struct logger *logger)
{
	/*
	 * Release (and for instances, delete) any connections with a
	 * dead interface.
	 *
	 * The connections are scanned new-to-old so that instances
	 * are deleted before templates are released.
	 */
	struct connection_filter cf = {
		.search = {
			.order = NEW2OLD,
			.verbose.logger = logger,
			.where = HERE,
		},
	};
	while (next_connection(&cf)) {
		struct connection *c = cf.c;

		if (!oriented(c)) {
			/* aka c->iface == NULL */
			pdbg(c->logger, "connection interface un-oriented");
			continue;
		}

		passert(c->iface != NULL); /* aka oriented() */
		if (c->iface->ifd_change != IFD_DELETE) {
			address_buf eb;
			pdbg(c->logger, "connection interface %s safe",
			     str_address(&c->iface->local_address, &eb));
			continue;
		}

		address_buf eb;
		pdbg(c->logger, "connection interface %s being deleted",
		     str_address(&c->iface->local_address, &eb));

		/*
		 * This connection interface is going away.
		 *
		 * Since the search is new2old and a connection
		 * instance's template is older, the connection's
		 * template will only be processed after all instances
		 * have been deleted.
		 *
		 * Since a reference is taken, deleting all states of
		 * an instance can't delete the connection.
		 *
		 * What's needed is a variant that doesn't try to send
		 * (it's pointless as the interface has gone).
		 */
		c = connection_addref(c, logger);
		connection_attach(c, logger);
		terminate_all_connection_states(c, HERE);

		/*
		 * ... and then disorient it, moving it to the
		 * unoriented list.  Always do this - the delete code
		 * pexpect()s to find the connection on one of those
		 * lists.
		 */
		PEXPECT(c->logger, oriented(c)); /* per above */
		disorient(c);

		connection_detach(c, logger);
		connection_delref(&c, logger);
	}
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
			     p->ip_dev->real_device_name,
			     str_endpoint(&p->local_endpoint, &b));
			some_dead = true;
		} else if (p->ip_dev->ifd_change == IFD_ADD) {
			some_new = true;
		}
	}

	/*
	 * Now go through and remove any reference to the dead
	 * interfaces either in the interface list or in oriented
	 * connections.
	 */

	if (some_dead) {
		dbg("updating interfaces - deleting the dead");
		/*
		 * Delete any iface_port's pointing at the dead
		 * iface_dev.
		 */
		release_dead_interfaces(logger);
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
		struct iface_device *ifd;
		FOR_EACH_LIST_ENTRY_OLD2NEW(ifd, &interface_dev) {
			if (ifd->ifd_change == IFD_DELETE) {
				iface_device_delref(&ifd);
			}
		}
	}

	/*
	 * Finally go through all connections and see if any can
	 * re-orient.
	 *
	 * For instance, a connection with its interface deleted may
	 * be able to orient to an existing or new interface.
	 */
	if (some_dead || some_new) {
		dbg("updating interfaces - checking orientation");
		check_orientations(logger);
	}
}

struct iface_endpoint *alloc_iface_endpoint(int fd,
					    struct iface_device *ifd,
					    const struct iface_io *io,
					    enum iface_esp_encapsulation esp_encapsulation,
					    enum iface_initiator_port initiator_port,
					    ip_endpoint local_endpoint,
					    where_t where)
{
	struct iface_endpoint *ifp = refcnt_alloc(struct iface_endpoint, where);
	ifp->fd = fd;
	ifp->ip_dev = addref_where(ifd, where);
	ifp->io = io;
	ifp->esp_encapsulation_enabled = (esp_encapsulation == ESP_ENCAPSULATION_ENABLED);
	ifp->float_nat_initiator = (initiator_port == INITIATOR_PORT_FLOATS);
	ifp->local_endpoint = local_endpoint;
	init_list_entry(&iface_endpoint_info, ifp, &ifp->entry);
	insert_list_entry(&iface_endpoints, &ifp->entry);
	return ifp;
}

void iface_endpoint_delref_where(struct iface_endpoint **ifpp, where_t where)
{
	struct iface_endpoint *ifp = delref_where(ifpp, &global_logger, where);
	if (ifp != NULL) {
		/* drop any lists */
		pexpect(ifp->next == NULL);
		remove_list_entry(&ifp->entry);
		/* generic stuff */
		ifp->io->cleanup(ifp);
		iface_device_delref(&ifp->ip_dev);
		/* XXX: after cleanup so code can log FD */
		close(ifp->fd);
		ifp->fd = -1;
		pfree(ifp);
	}
}

struct iface_endpoint *iface_endpoint_addref_where(struct iface_endpoint *ifp, where_t where)
{
	return addref_where(ifp, where);
}

struct iface_endpoint *bind_iface_endpoint(struct iface_device *ifd,
					   const struct iface_io *io,
					   ip_port port,
					   enum iface_esp_encapsulation esp_encapsulation,
					   enum iface_initiator_port initiator_port,
					   struct logger *logger)
{
#define BIND_ERROR(ERROR, MSG, ...)					\
	{								\
		int e = ERROR;						\
		endpoint_buf eb;					\
		llog_error(logger, e,					\
			   "bind %s %s endpoint %s failed, "MSG,	\
			   ifd->real_device_name, io->protocol->name,		\
 			   str_endpoint(&local_endpoint, &eb),		\
			   ##__VA_ARGS__);				\
	}

	const struct ip_info *afi = address_info(ifd->local_address);
	ip_endpoint local_endpoint = endpoint_from_address_protocol_port(ifd->local_address,
									 io->protocol, port);

	switch (esp_encapsulation) {
	case ESP_ENCAPSULATION_ENABLED:
		if (io->protocol->encap_esp->encap_type == 0) {
			errno = 0; /*no-errno*/
			BIND_ERROR(errno, "%s encapsulation is not configured (problem with kernel headers?)",
				   io->protocol->encap_esp->name);
			return NULL;
		}
		break;
	case ESP_ENCAPSULATION_DISABLED:
		break;
	}

	int fd = cloexec_socket(afi->socket.domain, io->socket.type|SOCK_NONBLOCK, io->protocol->ipproto);
	if (fd < 0) {
		BIND_ERROR(errno, "cloexec_socket(%s, %s|SOCK_NONBLOCK, %s)",
			   afi->socket.domain_name, io->socket.type_name, io->protocol->name);
		return NULL;
	}

	static const int on = true;     /* by-reference parameter; constant, we hope */

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&on, sizeof(on)) < 0) {
		BIND_ERROR(errno, "setsockopt(SOL_SOCKET, SO_REUSEADDR)");
		/* after logging so errno isn't trashed */
		close(fd);
		return NULL;
	}

#ifdef SO_PRIORITY
	static const int so_prio = 6; /* rumored maximum priority, might be 7 on linux? */
	if (setsockopt(fd, SOL_SOCKET, SO_PRIORITY, (const void *)&so_prio,
		       sizeof(so_prio)) < 0) {
		BIND_ERROR(errno, "setsockopt(SOL_SOCKET, SO_PRIORITY)");
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
			BIND_ERROR(errno, "setsockopt(SOL_SOCKET, SO_RCVBUFFORCE)");
			/* non-fatal; stumble on */
		}
		if (setsockopt(fd, SOL_SOCKET, so_snd, (const void *)&pluto_sock_bufsize,
			       sizeof(pluto_sock_bufsize)) < 0) {
			BIND_ERROR(errno, "setsockopt(SOL_SOCKET, SO_SNDBUFFORCE)");
			/* non-fatal; stumble on */
		}
	}

	/* To improve error reporting.  See ip(7). */
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	if (pluto_sock_errqueue) {
		if (setsockopt(fd, SOL_IP, IP_RECVERR, (const void *)&on, sizeof(on)) < 0) {
			BIND_ERROR(errno, "setsockopt(SOL_IP, IP_RECVERR)");
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
		BIND_ERROR(errno, "setsockopt(IPPROTO_IPV6, IPV6_USE_MIN_MTU)");
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
		BIND_ERROR(errno, "bind()");
		close(fd);
		return NULL;
	}

	if (esp_encapsulation == ESP_ENCAPSULATION_ENABLED &&
	    io->enable_esp_encapsulation != NULL) {
		int error = io->enable_esp_encapsulation(fd, logger);
		if (error != 0) {
			/* not errno! */
			BIND_ERROR(error, "interface does not support ESPINUDP encapsulation; NAT-traversal is turned OFF");
			esp_encapsulation = ESP_ENCAPSULATION_DISABLED;
		}
	}

	struct iface_endpoint *ifp =
		alloc_iface_endpoint(fd, ifd, io,
				     esp_encapsulation,
				     initiator_port,
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

	LLOG_JAMBUF(RC_LOG, logger, buf) {
		jam_string(buf, "adding ");
		jam_iface_endpoint(buf, ifp);
	}

	return ifp;
#undef BIND_ERROR
}

/*
 * Open new interfaces.
 */

static void add_new_ifaces(struct logger *logger)
{
	struct iface_device *ifd;
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
						ESP_ENCAPSULATION_DISABLED,
						INITIATOR_PORT_FLOATS,
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
					    ESP_ENCAPSULATION_ENABLED,
					    INITIATOR_PORT_FLOATS,
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
					    ESP_ENCAPSULATION_ENABLED,
					    INITIATOR_PORT_FIXED,
					    logger);
		}

		/*
		 * Policy Packet nic offload requires us to poke an IPsec policy
		 * hole that allows IKE packets. This installs one IPsec policy
		 * per interface (that supports offload), this function is called
		 * for port 500.
		 */
		if (ifd->nic_offload && kernel_ops->poke_ipsec_offload_policy_hole != NULL) {
			struct nic_offload nic_offload = {
				.dev = ifd->real_device_name,
				.type = KERNEL_OFFLOAD_PACKET,
			};

			if (!kernel_ops->poke_ipsec_offload_policy_hole(&nic_offload, logger))
				llog(RC_LOG, logger, "poke_ipsec_offload_policy_hole failed");
			/* non-fatal; stumble on */
		}
	}
}

void listen_on_iface_endpoint(struct iface_endpoint *ifp, struct logger *logger)
{
	ifp->io->listen(ifp, logger);
	endpoint_buf b;
	dbg("setup callback for interface %s %s fd %d on %s",
	    ifp->ip_dev->real_device_name,
	    str_endpoint(&ifp->local_endpoint, &b),
	    ifp->fd, ifp->io->protocol->name);
}

static void process_kernel_ifaces(struct kernel_iface *rifaces, struct logger *logger)
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

	struct kernel_iface *ifp;

	for (ifp = rifaces; ifp != NULL; ifp = ifp->next) {
		bool after = false;	/* has vfp passed ifp on the list? */
		bool bad = false;
		struct kernel_iface *vfp;

		for (vfp = rifaces; vfp != NULL; vfp = vfp->next) {
			if (vfp == ifp) {
				after = true;
			} else if (sameaddr(&ifp->addr, &vfp->addr)) {
				if (after) {
					address_buf b;

					llog(RC_LOG, logger,
					            "IP interfaces %s and %s share address %s!",
					       ifp->name, vfp->name,
					       str_address(&ifp->addr, &b));
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
			address_buf b;

			llog(RC_LOG, logger,
				    "skipping interface %s with %s",
				    ifp->name, str_address(&ifp->addr, &b));
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
		struct kernel_iface *t = rifaces;

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
	process_kernel_ifaces(find_kernel_ifaces4(logger), logger);
	process_kernel_ifaces(find_kernel_ifaces6(logger), logger);
	add_new_ifaces(logger);

	if (rm_dead)
		free_dead_ifaces(logger); /* ditch remaining old entries */

	if (interfaces == NULL)
		llog(RC_LOG, logger, "no public interfaces found");

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
			return iface_endpoint_addref(p);
		}
	}
	return NULL;
}

void show_ifaces_status(struct show *s)
{
	show_separator(s); /* if needed */
	for (struct iface_endpoint *p = interfaces; p != NULL; p = p->next) {
		SHOW_JAMBUF(s, buf) {
			jam_iface_endpoint(buf, p);
		}
	}
}

void shutdown_ifaces(struct logger *logger)
{
	/* clean up public interfaces */
	mark_ifaces_dead();
	free_dead_ifaces(logger);
	/* clean up remaining hidden interface endpoints */
	struct iface_endpoint *ifp;
	FOR_EACH_LIST_ENTRY_NEW2OLD(ifp, &iface_endpoints) {
		iface_endpoint_delref(&ifp);
	}
	/* and remaining interfaces */
	struct iface_device *iface;
	FOR_EACH_LIST_ENTRY_NEW2OLD(iface, &interface_dev) {
		iface_device_delref(&iface);
	}
}
