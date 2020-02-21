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

#include <unistd.h>

#include "defs.h"

#include "iface.h"
#include "log.h"
#include "hostpair.h"			/* for release_dead_interfaces() */
#include "state.h"			/* for delete_states_dead_interfaces() */
#include "server.h"			/* for *_pluto_event() */
#include "kernel_xfrm_interface.h"	/* for free_xfrmi_ipsec1() */
#include "kernel.h"
#include "demux.h"
#include "iface_udp.h"

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
			endpoint_buf b;
			libreswan_log("shutting down interface %s %s",
				      p->ip_dev->id_rname,
				      str_endpoint(&p->local_endpoint, &b));
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
				*pp = p->next; /* advance *pp */
				delete_pluto_event(&p->pev);
				close(p->fd);
				free_dead_iface_dev(p->ip_dev);
				pfree(p);
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
#ifdef USE_XFRM_INTERFACE
	free_xfrmi_ipsec1();
#endif
}

static void handle_udp_packet_cb(evutil_socket_t unused_fd UNUSED,
				 const short unused_event UNUSED,
				 void *arg)
{
	const struct iface_port *ifp = arg;
	handle_packet_cb(ifp, read_udp_packet);
}

void find_ifaces(bool rm_dead)
{
	if (rm_dead)
		mark_ifaces_dead();

	if (kernel_ops->process_raw_ifaces != NULL) {
		kernel_ops->process_raw_ifaces(find_raw_ifaces4());
		kernel_ops->process_raw_ifaces(find_raw_ifaces6());
	}

	if (rm_dead)
		free_dead_ifaces(); /* ditch remaining old entries */

	if (interfaces == NULL)
		loglog(RC_LOG_SERIOUS, "no public interfaces found");

	if (listening) {
		struct iface_port *ifp;

		for (ifp = interfaces; ifp != NULL; ifp = ifp->next) {
			delete_pluto_event(&ifp->pev);
			ifp->pev = add_fd_read_event_handler(ifp->fd,
							     handle_udp_packet_cb,
							     ifp, "ethX");
			endpoint_buf b;
			dbg("setup callback for interface %s %s fd %d",
			    ifp->ip_dev->id_rname,
			    str_endpoint(&ifp->local_endpoint, &b),
			    ifp->fd);
		}
	}
}

struct iface_port *find_iface_port_by_local_endpoint(ip_endpoint *local_endpoint)
{
	for (struct iface_port *p = interfaces; p != NULL; p = p->next) {
		if (endpoint_eq(*local_endpoint, p->local_endpoint)) {
			return p;
		}
	}
	return NULL;
}

void show_ifaces_status(const struct fd *whackfd)
{
	struct iface_port *p;

	for (p = interfaces; p != NULL; p = p->next) {
		endpoint_buf b;
		whack_comment(whackfd, "interface %s %s",
			  p->ip_dev->id_rname,
			  str_endpoint(&p->local_endpoint, &b));
	}
}
