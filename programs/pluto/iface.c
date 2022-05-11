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

#include <unistd.h>		/* for close() */

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
	FOR_EACH_LIST_ENTRY_OLD2NEW(&interface_dev, ifd) {
		if (sameaddr(address, &ifd->id_address)) {
			return ifd;
		}
	}
	return NULL;
}

static void mark_ifaces_dead(void)
{
	struct iface_dev *ifd;
	FOR_EACH_LIST_ENTRY_OLD2NEW(&interface_dev, ifd) {
		dbg("iface: marking %s dead", ifd->id_rname);
		ifd->ifd_change = IFD_DELETE;
	}
}

static void add_or_keep_iface_dev(struct raw_iface *ifp, struct logger *logger)
{
	/* find the iface */
	struct iface_dev *ifd;
	FOR_EACH_LIST_ENTRY_OLD2NEW(&interface_dev, ifd) {
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
		FOR_EACH_LIST_ENTRY_OLD2NEW(&interface_dev, ifd) {
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
	ip_endpoint local_endpoint = endpoint_from_address_protocol_port(ifd->id_address,
									 io->protocol, port);
	if (esp_encapsulation_enabled &&
	    io->protocol->encap_esp->encap_type == 0) {
		endpoint_buf b;
		llog(RC_LOG, logger,
		     "%s encapsulation on %s interface %s %s is not configured (problem with kernel headers?)",
		     io->protocol->encap_esp->name,
		     io->protocol->name,
		     ifd->id_rname, str_endpoint(&local_endpoint, &b));
		return NULL;
	}

	int fd = io->bind_iface_endpoint(ifd, port, esp_encapsulation_enabled, logger);
	if (fd < 0) {
		/* already logged? */
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

	endpoint_buf b;
	llog(RC_LOG, logger,
	     "adding %s interface %s %s",
	     io->protocol->name, ifp->ip_dev->id_rname,
	     str_endpoint(&ifp->local_endpoint, &b));
	return ifp;
}

/*
 * Open new interfaces.
 */

static void add_new_ifaces(struct logger *logger)
{
	struct iface_dev *ifd;
	FOR_EACH_LIST_ENTRY_OLD2NEW(&interface_dev, ifd) {
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

			/*
			 * From linux's xfrm: right now, we do not support
			 * NAT-T on IPv6, because the kernel did not support
			 * it, and gave an error it one tried to turn it on.
			 *
			 * From bsd's kame: right now, we do not support NAT-T
			 * on IPv6, because the kernel did not support it, and
			 * gave an error it one tried to turn it on.
			 *
			 * XXX: Who should we believe?
			 *
			 * Port 4500 can add the ESP encapsulation prefix.
			 * Let it float to itself - code might rely on it?
			 */
			if (address_type(&ifd->id_address) == &ipv4_info) {
				bind_iface_endpoint(ifd, &udp_iface_io,
						    ip_hport(NAT_IKE_UDP_PORT),
						    true /*esp_encapsulation_enabled*/,
						    true /*float_nat_initiator*/,
						    logger);
			}
		}

		/*
		 * An explicit {left,right}IKEPORT can't float away.
		 *
		 * An explicit {left,right}IKEPORT must enable
		 * ESPINUDP so that it can tunnel NAT.  This means
		 * that incoming packets must add the ESP=0 prefix,
		 * which in turn means that it can't interop with port
		 * 500 as that port will never send the ESP=0 prefix.
		 *
		 * See comments in iface.h.
		 */
		if (pluto_listen_tcp) {
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

/* Called to handle --interface <ifname>
 * Semantics: if specified, only these (real) interfaces are considered.
 */

static const char *pluto_ifn[10];
static int pluto_ifn_roof = 0;

bool use_interface(const char *rifn)
{
	if (pluto_ifn_roof >= (int)elemsof(pluto_ifn)) {
		return false;
	} else {
		pluto_ifn[pluto_ifn_roof++] = rifn;
		return true;
	}
}

void shutdown_ifaces(struct logger *logger)
{
	/* clean up public interfaces */
	mark_ifaces_dead();
	free_dead_ifaces(logger);
	/* clean up remaining hidden interfaces */
	struct iface_endpoint *ifp;
	FOR_EACH_LIST_ENTRY_NEW2OLD(&iface_endpoints, ifp) {
		iface_endpoint_delref(&ifp);
	}
}
