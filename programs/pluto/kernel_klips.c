/* pfkey interface to the kernel's IPsec mechanism
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003 Herbert Xu.
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

#ifdef KLIPS

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
#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

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

static void
klips_process_raw_ifaces(struct raw_iface *rifaces)
{
    struct raw_iface *ifp;

    /* Find all virtual/real interface pairs.
     * For each real interface...
     */
    for (ifp = rifaces; ifp != NULL; ifp = ifp->next)
    {
	struct raw_iface *v = NULL;	/* matching ipsecX interface */
	struct raw_iface fake_v;
	bool after = FALSE; /* has vfp passed ifp on the list? */
	bool bad = FALSE;
	struct raw_iface *vfp;

	/* ignore if virtual (ipsec*) interface */
	if (strncmp(ifp->name, IPSECDEVPREFIX, sizeof(IPSECDEVPREFIX)-1) == 0)
	    continue;

	/* ignore if virtual (mast*) interface */
	if (strncmp(ifp->name, MASTDEVPREFIX, sizeof(MASTDEVPREFIX)-1) == 0)
	    continue;

	for (vfp = rifaces; vfp != NULL; vfp = vfp->next)
	{
	    if (vfp == ifp)
	    {
		after = TRUE;
	    }
	    else if (sameaddr(&ifp->addr, &vfp->addr))
	    {
		/* Different entries with matching IP addresses.
		 * Many interesting cases.
		 */
		if (strncmp(vfp->name, IPSECDEVPREFIX, sizeof(IPSECDEVPREFIX)-1) == 0)
		{
		    if (v != NULL)
		    {
			loglog(RC_LOG_SERIOUS
			    , "ipsec interfaces %s and %s share same address %s"
			    , v->name, vfp->name, ip_str(&ifp->addr));
			bad = TRUE;
		    }
		    else
		    {
			v = vfp;	/* current winner */
		    }
		}
		else
		{
		    /* ugh: a second real interface with the same IP address
		     * "after" allows us to avoid double reporting.
		     */
#if defined(linux) && defined(NETKEY_SUPPORT)
		    if (kern_interface == USE_NETKEY)
		    {
			if (after)
			{
			    bad = TRUE;
			    break;
			}
			continue;
		    }
#endif
		    if (after)
		    {
			loglog(RC_LOG_SERIOUS
			    , "IP interfaces %s and %s share address %s!"
			    , ifp->name, vfp->name, ip_str(&ifp->addr));
		    }
		    bad = TRUE;
		}
	    }
	}

	if (bad)
	    continue;

#if defined(linux) && defined(NETKEY_SUPPORT)
	if (kern_interface == USE_NETKEY)
	{
	    v = ifp;
	    goto add_entry;
	}
#endif

	/* what if we didn't find a virtual interface? */
	if (v == NULL)
	{
	    if (kern_interface == NO_KERNEL)
	    {
		/* kludge for testing: invent a virtual device */
		static const char fvp[] = "virtual";
		fake_v = *ifp;
		passert(sizeof(fake_v.name) > sizeof(fvp));
		strcpy(fake_v.name, fvp);
		addrtot(&ifp->addr, 0, fake_v.name + sizeof(fvp) - 1
		    , sizeof(fake_v.name) - (sizeof(fvp) - 1));
		v = &fake_v;
	    }
	    else
	    {
		DBG(DBG_CONTROL,
			DBG_log("IP interface %s %s has no matching ipsec* interface -- ignored"
			    , ifp->name, ip_str(&ifp->addr)));
		continue;
	    }
	}

	/* We've got all we need; see if this is a new thing:
	 * search old interfaces list.
	 */
#if defined(linux) && defined(NETKEY_SUPPORT)
add_entry:
#endif
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
klips_do_command(struct connection *c, struct spd_route *sr
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

const struct kernel_ops klips_kernel_ops = {
    type: USE_KLIPS,
    async_fdp: &pfkeyfd,
    replay_window: 64,
    
    pfkey_register: klips_pfkey_register,
    pfkey_register_response: klips_pfkey_register_response,
    process_queue: pfkey_dequeue,
    process_msg: pfkey_event,
    raw_eroute: pfkey_raw_eroute,
    shunt_eroute: pfkey_shunt_eroute,
    sag_eroute: pfkey_sag_eroute,
    add_sa: pfkey_add_sa,
    grp_sa: pfkey_grp_sa,
    del_sa: pfkey_del_sa,
    get_spi: NULL,
    eroute_idle: pfkey_was_eroute_idle,
    inbound_eroute: FALSE,
    policy_lifetime: FALSE,
    init: init_pfkey,
    docommand: klips_do_command,
    set_debug: pfkey_set_debug,
    remove_orphaned_holds: pfkey_remove_orphaned_holds,
    process_ifaces: klips_process_raw_ifaces,
    kern_name: "klips"
};
#endif /* KLIPS */


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
