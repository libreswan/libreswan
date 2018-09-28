/* pfkey interface to the kernel's IPsec mechanism
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003 Herbert Xu.
 * Copyright (C) 2017 Richard Guy Briggs <rgb@tricolour.ca>
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
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libreswan.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "id.h"
#include "connections.h"
#include "state.h"
#include "kernel.h"
#include "kernel_pfkey.h"
#include "timer.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "packet.h"     /* for pb_stream in nat_traversal.h */
#include "nat_traversal.h"
#include "server.h"

#include "alg_info.h"
#include "kernel_alg.h"

static int next_free_mast_device = -1;
int useful_mastno = -1;

/* for now, a kludge */
#define MAX_MAST 64
enum mast_stat {
	MAST_INUSE,     /* not available */
	MAST_AVAIL,     /* created, available */
	MAST_OPEN       /* not created */
};
enum mast_stat mastdevice[MAX_MAST];

/*
 * build list of available mast devices.
 */

static void find_next_free_mast(void)
{
	int mastno;

	for (mastno = 0; mastno < MAX_MAST; mastno++) {
		if (mastdevice[mastno] == MAST_AVAIL) {
			next_free_mast_device = mastno;
			break;
		}
	}
	if (next_free_mast_device == -1) {
		for (mastno = 0; mastno < MAX_MAST; mastno++) {
			if (mastdevice[mastno] == MAST_OPEN) {
				next_free_mast_device = mastno;
				break;
			}
		}
	}
}

static int recalculate_mast_device_list(struct raw_iface *rifaces)
{
	struct raw_iface *ifp;
	int mastno;
	int firstmastno = -1;

	/* mark them all as available */
	next_free_mast_device = -1;
	for (mastno = 0; mastno < MAX_MAST; mastno++)
		mastdevice[mastno] = MAST_OPEN;

	for (ifp = rifaces; ifp != NULL; ifp = ifp->next) {
		/* look for virtual (mast*) interface */
		if (!startswith(ifp->name, MASTDEVPREFIX))
			continue;

		if (sscanf(ifp->name, "mast%d", &mastno) == 1) {
			libreswan_log("found %s device already present",
				      ifp->name);
			mastdevice[mastno] = MAST_AVAIL;
			if (!isunspecaddr(&ifp->addr)) {
				libreswan_log("device %s already in use",
					      ifp->name);
				/* mark it as existing, and in use */
				mastdevice[mastno] = MAST_INUSE;
				if (firstmastno == -1)
					firstmastno = mastno;
			}
		}
	}

	find_next_free_mast();
	return firstmastno;
}

static int allocate_mast_device(void)
{
	int next;

	if (next_free_mast_device == -1)
		find_next_free_mast();

	if (next_free_mast_device != -1) {
		next = next_free_mast_device;
		next_free_mast_device = -1;
		return next;
	}
	return -1;
}

static int init_useful_mast(ip_address addr UNUSED, char *vname, size_t vnlen)
{
	int mastno;

	/*
	 * now, create a mastXXX interface to match, and then configure
	 * it with an IP address that leads out.
	 */
	mastno = allocate_mast_device();
	passert(mastno != -1);
	snprintf(vname, vnlen, "mast%d", mastno);
	if (mastdevice[mastno] == MAST_OPEN) {
		mastdevice[mastno] = MAST_INUSE;
		pfkey_plumb_mast_device(mastno);
	}

	return mastno;
}

static void mast_process_raw_ifaces(struct raw_iface *rifaces)
{
	struct raw_iface *ifp;
	struct iface_port *firstq = NULL;
	char useful_mast_name[256];
	bool found_mast = FALSE;
	ip_address lip; /* --listen filter option */

	if (pluto_listen) {
		err_t e = ttoaddr_num(pluto_listen, 0, AF_UNSPEC, &lip);

		if (e != NULL) {
			DBG_log("invalid listen= option ignored: %s", e);
			pluto_listen = NULL;
		}
	}

	strcpy(useful_mast_name, "useless");

	{
		int new_useful = recalculate_mast_device_list(rifaces);

		if (new_useful != -1)
			useful_mastno = new_useful;
	}

	DBG_log("useful mast device %d", useful_mastno);
	if (useful_mastno >= 0)
		snprintf(useful_mast_name, sizeof(useful_mast_name), "mast%d", useful_mastno);

	/*
	 * For each real interface...
	 */
	for (ifp = rifaces; ifp != NULL; ifp = ifp->next) {
		/* ignore if virtual (ipsec*) interface */
		if (startswith(ifp->name, IPSECDEVPREFIX))
			continue;

		/* ignore if virtual (mast*) interface */
		if (startswith(ifp->name, MASTDEVPREFIX)) {
			found_mast = TRUE;
			continue;
		}

		/* ignore if loopback interface */
		if (startswith(ifp->name, "lo"))
			continue;

		/* ignore if --listen is specified and we do not match */
		if (pluto_listen != NULL && !sameaddr(&lip, &ifp->addr)) {
			ipstr_buf b;

			libreswan_log("skipping interface %s with %s",
				      ifp->name, ipstr(&ifp->addr, &b));
			continue;
		}

		/*
		 * see if this is a new thing: search old interfaces list.
		 */
		do {
			bool newone = TRUE;
			struct iface_dev *id = NULL;
			struct iface_port *q = interfaces;

			while (q != NULL) {
				/* search over if matching old entry found */
				if (streq(q->ip_dev->id_rname, ifp->name) &&
				    sameaddr(&q->ip_addr, &ifp->addr)) {
					newone = FALSE;

					/* matches -- rejuvinate old entry */
					q->change = IFN_KEEP;

					/* look for other interfaces to keep (due to NAT-T) */
					for (q = q->next; q; q = q->next) {
						if (streq(q->ip_dev->id_rname,
							  ifp->name) &&
						    sameaddr(&q->ip_addr,
							     &ifp->addr))
						{
							q->change = IFN_KEEP;
							if (firstq == NULL)
							{
								firstq = q;
								if (useful_mastno
									== -1)
									useful_mastno
										= init_useful_mast(
											firstq->ip_addr,
											useful_mast_name,
											sizeof(useful_mast_name));


							}
						}
					}

					break;
				}

				/* try again */
				q = q->next;
			}

			/* search is over if at end of list */
			if (newone) {
				/* matches nothing -- create a new entry */
				char *vname;
				int fd;
				ipstr_buf b;

				if (useful_mastno == -1)
					useful_mastno = init_useful_mast(
						ifp->addr, useful_mast_name, sizeof(useful_mast_name));

				vname = clone_str(useful_mast_name,
						  "virtual device name mast");
				fd = create_socket(ifp, vname, pluto_port);

				if (fd < 0)
					break;

				q = alloc_thing(struct iface_port,
						"struct iface_port");
				id = alloc_thing(struct iface_dev,
						 "struct iface_dev");

				if (firstq == NULL)
					firstq = q;

				LIST_INSERT_HEAD(&interface_dev, id, id_entry);

				q->fd = fd;
				q->ip_dev = id;
				id->id_rname = clone_str(ifp->name,
							 "real device name");
				id->id_vname = vname;
				id->id_count++;

				q->ip_addr = ifp->addr;
				q->change = IFN_ADD;
				q->port = pluto_port;
				q->ike_float = FALSE;

				/* done with primary interface */
				q->next = interfaces;
				interfaces = q;

				libreswan_log(
					"adding interface %s/%s %s:%d (fd=%d)",
					q->ip_dev->id_vname,
					q->ip_dev->id_rname,
					ipstr(&q->ip_addr, &b),
					q->port, q->fd);

				/*
				 * right now, we do not support NAT-T on IPv6, because
				 * the kernel did not support it, and gave an error
				 * it one tried to turn it on.
				 */
				if (addrtypeof(&ifp->addr) == AF_INET) {
					fd = create_socket(ifp,
							   q->ip_dev->id_vname,
							   pluto_nat_port);
					if (fd < 0) {
						libreswan_log(
							"failed to create socket for NAT-T: %s",
							strerror(errno));
						/* go to next if in list */
						break;
					}
					nat_traversal_espinudp_socket(fd,
								      "IPv4");
					q = alloc_thing(struct iface_port,
							"struct iface_port");
					q->ip_dev = id;
					id->id_count++;

					q->ip_addr = ifp->addr;
					setportof(htons(pluto_nat_port),
						  &q->ip_addr);
					q->port = pluto_nat_port;
					q->fd = fd;
					q->change = IFN_ADD;
					q->ike_float = TRUE;

					q->next = interfaces;
					interfaces = q;
					libreswan_log(
						"adding interface %s/%s %s:%d (fd=%d)",
						q->ip_dev->id_vname, q->ip_dev->id_rname,
						ipstr(&q->ip_addr, &b),
						q->port, q->fd);
				}

			}
		} while (0);
	}

	/* delete the raw interfaces list */
	while (rifaces != NULL) {
		struct raw_iface *t = rifaces;

		rifaces = t->next;
		pfree(t);
	}

	/* make one up for later */
	if ((!found_mast && firstq != NULL) && useful_mastno == -1)
		init_useful_mast(firstq->ip_addr, useful_mast_name, sizeof(useful_mast_name));
}

static bool mast_do_command(const struct connection *c, const struct spd_route *sr,
			    const char *verb, const char *verb_suffix, struct state *st)
{
	char cmd[2048]; /* arbitrary limit on shell command length */
	char common_shell_out_str[2048];
	IPsecSAref_t ref, refhim;

	if (fmt_common_shell_out(common_shell_out_str,
				 sizeof(common_shell_out_str), c, sr,
				 st) == -1) {
		loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb,
		       verb_suffix);
		return FALSE;
	}

	ref = refhim = IPSEC_SAREF_NULL;
	if (st != NULL) {
		ref = st->st_ref;
		refhim = st->st_refhim;
		DBG(DBG_KERNEL,
		    DBG_log("Using saref=%u/%u for verb=%s", ref, refhim,
			    verb));
	}

	if (-1 == snprintf(cmd, sizeof(cmd),
			   "2>&1 " /* capture stderr along with stdout */
			   "PLUTO_MY_REF=%u "
			   "PLUTO_PEER_REF=%u "
			   "PLUTO_SAREF_TRACKING=%s "
			   "PLUTO_VERB='%s%s' "
			   "%s"         /* other stuff   */
			   "%s",        /* actual script */
			   ref,
			   refhim,
			   (c->policy & POLICY_SAREF_TRACK_CONNTRACK) ?
			     "conntrack" :
			   bool_str((c->policy & POLICY_SAREF_TRACK) != LEMPTY),
			   verb, verb_suffix,
			   common_shell_out_str,
			   sr->this.updown))
	{
		loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb,
		       verb_suffix);
		return FALSE;
	}

	return invoke_command(verb, verb_suffix, cmd);
}

static bool mast_do_command_vs(const struct connection *c, const struct spd_route *sr,
			    const char *verb, struct state *st)
{
	const char *verb_suffix;

	/*
	 * Figure out which verb suffix applies.
	 * NOTE: this is a duplicate of code in do_command.
	 */
	{
		const char *hs, *cs;

		switch (addrtypeof(&sr->this.host_addr)) {
		case AF_INET:
			hs = "-host";
			cs = "-client";
			break;
		case AF_INET6:
			hs = "-host-v6";
			cs = "-client-v6";
			break;
		default:
			loglog(RC_LOG_SERIOUS, "unknown address family");
			return FALSE;
		}
		verb_suffix = subnetisaddr(&sr->this.client,
					   &sr->this.host_addr) ?
			      hs : cs;
	}
	return mast_do_command(c, sr, verb, verb_suffix, st);
}

static bool mast_raw_eroute(const ip_address *this_host,
			    const ip_subnet *this_client,
			    const ip_address *that_host,
			    const ip_subnet *that_client,
			    ipsec_spi_t spi,
			    int sa_proto,
			    unsigned int transport_proto,
			    unsigned int satype,
			    const struct pfkey_proto_info *proto_info,
			    deltatime_t use_lifetime,
			    uint32_t sa_priority,
			    const struct sa_mark *sa_mark,
			    enum pluto_sadb_operations op,
			    const char *text_said
#ifdef HAVE_LABELED_IPSEC
			    , const char *policy_label
#endif
			    )
{
	/* actually, we did all the work with iptables in _updown */
	DBG_log("mast_raw_eroute called op=%u said=%s", op, text_said);
	return pfkey_raw_eroute(this_host, this_client, that_host, that_client,
				spi, sa_proto, transport_proto, satype,
				proto_info, use_lifetime, sa_priority, sa_mark, op, text_said
#ifdef HAVE_LABELED_IPSEC
				, policy_label
#endif
				);
}

/* Add/replace/delete a shunt eroute.
 * Such an eroute determines the fate of packets without the use
 * of any SAs.  These are defaults, in effect.
 * If a negotiation has not been attempted, use %trap.
 * If negotiation has failed, the choice between %trap/%pass/%drop/%reject
 * is specified in the policy of connection c.
 */
static bool mast_shunt_eroute(const struct connection *c UNUSED,
			      const struct spd_route *sr UNUSED,
			      enum routing_t rt_kind UNUSED,
			      enum pluto_sadb_operations op UNUSED,
			      const char *opname UNUSED)
{
	DBG_log("mast_shunt_eroute called op=%u/%s", op, opname);
	return TRUE;
}

/**
 * replace existing iptables rule using the updown.mast script.
 * @param st - new state
 * @param sr - new route
 * @return TRUE if add was successful, FALSE otherwise
 */
static bool mast_sag_eroute_replace(const struct state *st, const struct spd_route *sr)
{
	struct connection *c = st->st_connection;
	struct state *old_st;
	bool success;

	/* The state, st, has the new SAref values, but we need to remove
	 * the rule based on the previous state with the old SAref values.
	 * So we have to find it the hard way (it's a cpu hog).
	 */
	old_st = state_with_serialno(sr->eroute_owner);
	if (old_st == NULL)
		old_st = st;

	DBG_log("mast_sag_eroute_replace state #%lu{ref=%d refhim=%d} with #%lu{ref=%d refhim=%d}",
		old_st->st_serialno,
		(int)old_st->st_ref,
		(int)old_st->st_refhim,
		st->st_serialno,
		(int)st->st_ref,
		(int)st->st_refhim);

	/* add the new rule */
	success = mast_do_command_vs(c, sr, "spdadd", st);

	/* drop the old rule -- we ignore failure */
	if (old_st->st_serialno != st->st_serialno)
		(void)mast_do_command_vs(c, sr, "spddel", old_st);

	return success;
}

/* install or remove eroute for SA Group */
static bool mast_sag_eroute(const struct state *st, const struct spd_route *sr,
			    enum pluto_sadb_operations op,
			    const char *opname UNUSED)
{
	bool ok;
	bool addop = FALSE;

	DBG_log("mast_sag_eroute called op=%u/%s", op, opname);

	/* handle ops we have to do no work for */
	switch (op) {
	default:
		bad_case(op);
		return FALSE;

	case ERO_ADD:
	case ERO_ADD_INBOUND:
		addop = TRUE;
	/* fallthrough expected */
	case ERO_REPLACE:
	case ERO_REPLACE_INBOUND:
	case ERO_DELETE:
	case ERO_DEL_INBOUND:
		/* these one require more work... */
		break;
	}

	/* first try to update the routing policy */
	ok = pfkey_sag_eroute(st, sr, op, opname);
	if (!ok) {
		DBG_log("mast_sag_eroute failed to %s/%d pfkey eroute", opname,
			op);
		if (addop)
			/* If the pfkey op failed, and we were adding a new SA,
			 * then it's OK to fail early.
			 */
			return FALSE;
	}

	/* now run the iptable updown script */
	switch (op) {
	case ERO_ADD_INBOUND:
	case ERO_REPLACE_INBOUND:
	case ERO_DEL_INBOUND:
		return TRUE;

	case ERO_ADD:
		return mast_do_command_vs(st->st_connection, sr, "spdadd", st);

	case ERO_DELETE:
		return mast_do_command_vs(st->st_connection, sr, "spddel", st);

	case ERO_REPLACE:
		return mast_sag_eroute_replace(st, sr);

	default:
		/* this should never happen */
		return FALSE;
	}
}

const struct kernel_ops mast_kernel_ops = {
	.type = USE_MASTKLIPS,
	.async_fdp = &pfkeyfd,
	.route_fdp = NULL,
	.replay_window = 64,

	.pfkey_register = klips_pfkey_register,
	.pfkey_register_response = pfkey_register_response,
	.process_queue = pfkey_dequeue,
	.process_msg = pfkey_event,
	.raw_eroute = mast_raw_eroute,
	.shunt_eroute = mast_shunt_eroute,
	.sag_eroute = mast_sag_eroute,
	.add_sa = pfkey_add_sa,
	.grp_sa = pfkey_grp_sa,
	.del_sa = pfkey_del_sa,
	.get_sa = pfkey_get_sa,
	.get_spi = NULL,
	.eroute_idle = pfkey_was_eroute_idle,
	.inbound_eroute = FALSE,
	.scan_shunts = pfkey_scan_shunts,
	.init = init_pfkey,
	.exceptsocket = NULL,
	.docommand = mast_do_command,
	.set_debug = pfkey_set_debug,
	.remove_orphaned_holds = pfkey_remove_orphaned_holds,
	.process_ifaces = mast_process_raw_ifaces,
	.kern_name = "mast",
	.overlap_supported = TRUE,
	.sha2_truncbug_support = FALSE,
	.v6holes = NULL,
};
