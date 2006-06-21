/* pfkey interface to the NetBSD/FreeBSD/OSX IPsec mechanism
 *
 * based upon kernel_klips.c.
 *
 * Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: kernel_pfkey.c,v 1.25 2005/08/24 22:50:50 mcr Exp $
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

#include <openswan.h>
#include <net/pfkeyv2.h>
#include "libpfkey.h"         /* this is a copy of a freebsd libipsec/ file */

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "id.h"
#include "connections.h"
#include "state.h"
#include "kernel.h"
#include "kernel_pfkey.h"
#include "timer.h"
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#ifdef NAT_TRAVERSAL
#include "packet.h"  /* for pb_stream in nat_traversal.h */
#include "nat_traversal.h"
#endif

#include "alg_info.h"
#include "kernel_alg.h"

#ifndef DEFAULT_UPDOWN
# define DEFAULT_UPDOWN "ipsec _updown"
#endif

int pfkeyfd = NULL_FD;

static void
bsdkame_init_pfkey(void)
{
    int pid = getpid();

    /* open PF_KEY socket */

    pfkeyfd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

    if (pfkeyfd == -1)
	exit_log_errno((e, "socket() in init_pfkeyfd()"));

#ifdef NEVER	/* apparently unsupported! */
    if (fcntl(pfkeyfd, F_SETFL, O_NONBLOCK) != 0)
	exit_log_errno((e, "fcntl(O_NONBLOCK) in init_pfkeyfd()"));
#endif
    if (fcntl(pfkeyfd, F_SETFD, FD_CLOEXEC) != 0)
	exit_log_errno((e, "fcntl(FD_CLOEXEC) in init_pfkeyfd()"));

    DBG(DBG_KLIPS,
	DBG_log("process %u listening for PF_KEY_V2 on file descriptor %d", (unsigned)pid, pfkeyfd));
}



static void
bsdkame_process_raw_ifaces(struct raw_iface *rifaces)
{
    struct raw_iface *ifp;

    /* 
     * There are no virtual interfaces, so all interfaces are valid
     */
    for (ifp = rifaces; ifp != NULL; ifp = ifp->next)
    {
	struct raw_iface *v = NULL;	/* matching ipsecX interface */
	bool after = FALSE; /* has vfp passed ifp on the list? */
	bool bad = FALSE;
	struct raw_iface *vfp;

	for (vfp = rifaces; vfp != NULL; vfp = vfp->next)
	{
	    if (vfp == ifp)
	    {
		after = TRUE;
	    }
	    else if (sameaddr(&ifp->addr, &vfp->addr))
	    {
	      if (after)
		{
		  loglog(RC_LOG_SERIOUS
			 , "IP interfaces %s and %s share address %s!"
			 , ifp->name, vfp->name, ip_str(&ifp->addr));
		}
	      bad = TRUE;
	    }
	}

	if (bad)
	    continue;

	/* We've got all we need; see if this is a new thing:
	 * search old interfaces list.
	 */
	{
	    struct iface_port **p = &interfaces;

	    for (;;)
	    {
		struct iface_port *q = *p;
		struct iface_dev *id = NULL;

		/* search is over if at end of list */
		if (q == NULL)
		{
		    /* matches nothing -- create a new entry */
		    int fd = create_socket(ifp, v->name, pluto_port);

		    if (fd < 0)
			break;

#ifdef NAT_TRAVERSAL
		    if (nat_traversal_support_non_ike && addrtypeof(&ifp->addr) == AF_INET)
		    {
			nat_traversal_espinudp_socket(fd, "IPv4", ESPINUDP_WITH_NON_IKE);
		    }
#endif

		    q = alloc_thing(struct iface_port, "struct iface_port");
		    id = alloc_thing(struct iface_dev, "struct iface_dev");

		    LIST_INSERT_HEAD(&interface_dev, id, id_entry);

		    q->ip_dev = id;
		    id->id_rname = clone_str(ifp->name, "real device name");
		    id->id_vname = clone_str(v->name, "virtual device name");
		    id->id_count++;

		    q->ip_addr = ifp->addr;
		    q->fd = fd;
		    q->next = interfaces;
		    q->change = IFN_ADD;
		    q->port = pluto_port;
		    q->ike_float = FALSE;

		    interfaces = q;

		    openswan_log("adding interface %s/%s %s:%d"
				 , q->ip_dev->id_vname
				 , q->ip_dev->id_rname
				 , ip_str(&q->ip_addr)
				 , q->port);

#ifdef NAT_TRAVERSAL
		    /*
		     * right now, we do not support NAT-T on IPv6, because
		     * the kernel did not support it, and gave an error
		     * it one tried to turn it on.
		     */
		    if (nat_traversal_support_port_floating
			&& addrtypeof(&ifp->addr) == AF_INET)
		    {
			fd = create_socket(ifp, v->name, NAT_T_IKE_FLOAT_PORT);
			if (fd < 0) 
			    break;
			nat_traversal_espinudp_socket(fd, "IPv4"
						      , ESPINUDP_WITH_NON_ESP);
			q = alloc_thing(struct iface_port, "struct iface_port");
			q->ip_dev = id;
			id->id_count++;
			
			q->ip_addr = ifp->addr;
			setportof(htons(NAT_T_IKE_FLOAT_PORT), &q->ip_addr);
			q->port = NAT_T_IKE_FLOAT_PORT;
			q->fd = fd;
			q->next = interfaces;
			q->change = IFN_ADD;
			q->ike_float = TRUE;
			interfaces = q;
			openswan_log("adding interface %s/%s %s:%d"
				     , q->ip_dev->id_vname, q->ip_dev->id_rname
				     , ip_str(&q->ip_addr)
				     , q->port);
		    }
#endif
		    break;
		}

		/* search over if matching old entry found */
		if (streq(q->ip_dev->id_rname, ifp->name)
		    && streq(q->ip_dev->id_vname, v->name)
		    && sameaddr(&q->ip_addr, &ifp->addr))
		{
		    /* matches -- rejuvinate old entry */
		    q->change = IFN_KEEP;
#ifdef NAT_TRAVERSAL
		    /* look for other interfaces to keep (due to NAT-T) */
		    for (q = q->next ; q ; q = q->next) {
			if (streq(q->ip_dev->id_rname, ifp->name)
			    && streq(q->ip_dev->id_vname, v->name)
			    && sameaddr(&q->ip_addr, &ifp->addr)) {
				q->change = IFN_KEEP;
			}
		    }
#endif
		    break;
		}

		/* try again */
		p = &q->next;
	    } /* for (;;) */
	}
    }

    /* delete the raw interfaces list */
    while (rifaces != NULL)
    {
	struct raw_iface *t = rifaces;

	rifaces = t->next;
	pfree(t);
    }
}

static bool
bsdkame_do_command(struct connection *c, struct spd_route *sr
		 , const char *verb, struct state *st)
{
    char cmd[1536];     /* arbitrary limit on shell command length */
    char common_shell_out_str[1024];
    const char *verb_suffix;

    /* figure out which verb suffix applies */
    {
        const char *hs, *cs;

        switch (addrtypeof(&sr->this.host_addr))
        {
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
        verb_suffix = subnetisaddr(&sr->this.client, &sr->this.host_addr)
            ? hs : cs;
    }

    if(fmt_common_shell_out(common_shell_out_str, sizeof(common_shell_out_str), c, sr, st)==-1) {
	loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb, verb_suffix);
	return FALSE;
    }
	
    if (-1 == snprintf(cmd, sizeof(cmd)
		       , "2>&1 "   /* capture stderr along with stdout */
		       "PLUTO_VERB='%s%s' "
		       "%s"        /* other stuff   */
		       "%s"        /* actual script */
		       , verb, verb_suffix
		       , common_shell_out_str
		       , sr->this.updown == NULL? DEFAULT_UPDOWN : sr->this.updown))
    {
	loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb, verb_suffix);
	return FALSE;
    }

    return invoke_command(verb, verb_suffix, cmd);
}

static void
bsdkame_pfkey_register(void)
{
    pfkey_send_register(pfkeyfd, SADB_SATYPE_AH);
    pfkey_recv_register(pfkeyfd);
    pfkey_send_register(pfkeyfd, SADB_SATYPE_ESP);
    pfkey_recv_register(pfkeyfd);

    can_do_IPcomp = FALSE;  /* until we get a response from KLIPS */
    pfkey_send_register(pfkeyfd, SADB_X_SATYPE_IPCOMP);
    pfkey_recv_register(pfkeyfd);
}

static void
bsdkame_pfkey_register_response(const struct sadb_msg *msg UNUSED)
{
    passert(0);
}

/* asynchronous messages from our queue */
static void
bsdkame_dequeue(void)
{
    passert(0);
}

/* asynchronous messages directly from PF_KEY socket */
static void
bsdkame_event(void)
{
    passert(0);
}

static bool
bsdkame_raw_eroute(const ip_address *this_host UNUSED
		   , const ip_subnet *this_client UNUSED
		   , const ip_address *that_host UNUSED
		   , const ip_subnet *that_client UNUSED
		   , ipsec_spi_t spi UNUSED
		   , unsigned int proto UNUSED
		   , unsigned int transport_proto UNUSED
		   , enum eroute_type esatype UNUSED
		   , const struct pfkey_proto_info *proto_info UNUSED
		   , time_t use_lifetime UNUSED
		   , enum pluto_sadb_operations op UNUSED
		   , const char *text_said UNUSED)
{
    passert(0);
    return FALSE;
}

/* Add/replace/delete a shunt eroute.
 * Such an eroute determines the fate of packets without the use
 * of any SAs.  These are defaults, in effect.
 * If a negotiation has not been attempted, use %trap.
 * If negotiation has failed, the choice between %trap/%pass/%drop/%reject
 * is specified in the policy of connection c.
 */
static bool
bsdkame_shunt_eroute(struct connection *c UNUSED
		     , struct spd_route *sr UNUSED
		     , enum routing_t rt_kind UNUSED
		     , enum pluto_sadb_operations op UNUSED
		     , const char *opname UNUSED)
{
    passert(0);
    return FALSE;
}

/* install or remove eroute for SA Group */
static bool
bsdkame_sag_eroute(struct state *st UNUSED
		   , struct spd_route *sr UNUSED
		   , unsigned op UNUSED
		   , const char *opname UNUSED)
{
    passert(0);
    return FALSE;
}

static bool
bsdkame_add_sa(const struct kernel_sa *sa UNUSED, bool replace UNUSED)
{
    passert(0);
    return FALSE;
}

static bool
bsdkame_grp_sa(const struct kernel_sa *sa0 UNUSED
	       , const struct kernel_sa *sa1 UNUSED)
{
    passert(0);
    return FALSE;
}

static bool
bsdkame_del_sa(const struct kernel_sa *sa UNUSED)
{
    passert(0);
    return FALSE;
}

/* Check if there was traffic on given SA during the last idle_max
 * seconds. If TRUE, the SA was idle and DPD exchange should be performed.
 * If FALSE, DPD is not necessary. We also return TRUE for errors, as they
 * could mean that the SA is broken and needs to be replace anyway.
 */
static bool
bsdkame_was_eroute_idle(struct state *st UNUSED
			, time_t idle_max UNUSED)
{
    passert(0);
    return FALSE;
}


static void
bsdkame_set_debug(int cur_debug UNUSED
		  , openswan_keying_debug_func_t debug_func UNUSED
		  , openswan_keying_debug_func_t error_func UNUSED)
{
    passert(0);
}

static void
bsdkame_remove_orphaned_holds(int transport_proto  UNUSED
			      , const ip_subnet *ours  UNUSED
			      , const ip_subnet *his UNUSED)
{
    passert(0);
}


const struct kernel_ops bsdkame_kernel_ops = {
    type: USE_BSDKAME,
    kern_name: "bsdkame",
    async_fdp: &pfkeyfd,
    replay_window: 64,
    
    pfkey_register: bsdkame_pfkey_register,
    pfkey_register_response: bsdkame_pfkey_register_response,
    process_queue: bsdkame_dequeue,
    process_msg: bsdkame_event,
    raw_eroute: bsdkame_raw_eroute,
    shunt_eroute: bsdkame_shunt_eroute,
    sag_eroute: bsdkame_sag_eroute,
    add_sa: bsdkame_add_sa,
    grp_sa: bsdkame_grp_sa,
    del_sa: bsdkame_del_sa,
    get_spi: NULL,
    eroute_idle: bsdkame_was_eroute_idle,
    inbound_eroute: FALSE,
    policy_lifetime: FALSE,
    init: bsdkame_init_pfkey,
    docommand: bsdkame_do_command,
    set_debug: bsdkame_set_debug,
    remove_orphaned_holds: bsdkame_remove_orphaned_holds,
    process_ifaces: bsdkame_process_raw_ifaces,
};

