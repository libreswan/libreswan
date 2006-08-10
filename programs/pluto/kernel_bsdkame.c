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
#include <netkey/keydb.h>
#include <netinet/in.h>
#include <netinet6/ipsec.h>
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
unsigned int pfkey_seq = 1;

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
		    int fd = create_socket(ifp, ifp->name, pluto_port);

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
		    id->id_vname = clone_str(ifp->name, "virtual device name");
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
			fd = create_socket(ifp, id->id_vname, NAT_T_IKE_FLOAT_PORT);
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
		    && streq(q->ip_dev->id_vname, ifp->name)
		    && sameaddr(&q->ip_addr, &ifp->addr))
		{
		    /* matches -- rejuvinate old entry */
		    q->change = IFN_KEEP;
#ifdef NAT_TRAVERSAL
		    /* look for other interfaces to keep (due to NAT-T) */
		    for (q = q->next ; q ; q = q->next) {
			if (streq(q->ip_dev->id_rname, ifp->name)
			    && streq(q->ip_dev->id_vname, ifp->name)
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

/*
 * We are were to install a set of policy, when there is in fact an SA
 * that is already setup.
 *
 * Well, the code is actually shared with shunt_eroute, since for KAME,
 * we set up the policy in an abstracted sense.
 *
 */
static bool
bsdkame_raw_eroute(const ip_address *this_host
		   , const ip_subnet *this_client
		   , const ip_address *that_host
		   , const ip_subnet *that_client
		   , ipsec_spi_t spi
		   , unsigned int proto
		   , unsigned int transport_proto
		   , enum eroute_type esatype UNUSED
		   , const struct pfkey_proto_info *proto_info UNUSED
		   , time_t use_lifetime UNUSED
		   , enum pluto_sadb_operations op
		   , const char *text_said UNUSED)
{
    const struct sockaddr *saddr = (const struct sockaddr *)&this_client->addr;
    const struct sockaddr *daddr = (const struct sockaddr *)&that_client->addr;
    char pbuf[512];
    struct sadb_x_policy *policy_struct = (struct sadb_x_policy *)pbuf;
    struct sadb_x_ipsecrequest *ir;
    int policylen;
    int ret;
    int policy = -1;

    switch(spi) {
    case 0:
        /* we're supposed to end up with no eroute: rejig op and opname */
        switch (op)
        {
        case ERO_REPLACE:
            /* replace with nothing == delete */
            op = ERO_DELETE;
            break;
        case ERO_ADD:
            /* add nothing == do nothing */
            return TRUE;

        case ERO_DELETE:
            /* delete remains delete */
            break;
	    
	case ERO_ADD_INBOUND:
	    break;

	case ERO_DEL_INBOUND:
	    break;

        default:
            bad_case(op);
        }
	break;
	
    case SPI_TRAP:
	policy = IPSEC_POLICY_IPSEC;
	break;
	
    case SPI_PASS:
        policy = IPSEC_POLICY_NONE;  /* BYPASS is for sockets only */
	break;

    case SPI_REJECT:
    case SPI_DROP:
	policy = IPSEC_POLICY_DISCARD;
	break;
	
    default:
      DBG_log("shunt_eroute called with spi=%08x\n", spi);
      policy = IPSEC_POLICY_IPSEC;
    }

    memset(pbuf, 0, sizeof(pbuf));

    /* this is sanity check that it got set properly */
    passert(this_client->addr.u.v4.sin_len == sizeof(struct sockaddr_in));
    passert(that_client->addr.u.v4.sin_len == sizeof(struct sockaddr_in));

    passert(policy != -1);

    policy_struct->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
    policy_struct->sadb_x_policy_type = policy;
    policy_struct->sadb_x_policy_dir  = IPSEC_DIR_OUTBOUND;
    policy_struct->sadb_x_policy_id   = 0; /* needs to be set, and recorded */

    policylen = sizeof(*policy_struct);
    
    if(policy == IPSEC_POLICY_IPSEC) {
	const ip_address *me   = this_host;
	const ip_address *him  = that_host;
	unsigned char *addrmem;

	ir = (struct sadb_x_ipsecrequest *)&policy_struct[1];
	  
	ir->sadb_x_ipsecrequest_len = sizeof(struct sadb_x_ipsecrequest)+me->u.v4.sin_len+him->u.v4.sin_len;
	ir->sadb_x_ipsecrequest_proto = proto;

	if(transport_proto == 0) {
	    ir->sadb_x_ipsecrequest_mode=IPSEC_MODE_TUNNEL;
	} else {
	    ir->sadb_x_ipsecrequest_mode=IPSEC_MODE_TRANSPORT;
	}
	ir->sadb_x_ipsecrequest_level=IPSEC_LEVEL_REQUIRE;
	ir->sadb_x_ipsecrequest_reqid=0;  /* not used for now */
   
	addrmem = (unsigned char *)&ir[1];
	memcpy(addrmem, &me->u.v4,  me->u.v4.sin_len);
	addrmem += me->u.v4.sin_len;
	memcpy(addrmem, &him->u.v4, him->u.v4.sin_len);
	
	addrmem += him->u.v4.sin_len;
	
	policylen += ir->sadb_x_ipsecrequest_len;
	
	DBG_log("request_len=%u policylen=%u\n",
		ir->sadb_x_ipsecrequest_len, policylen);

    } else {
	DBG_log("setting policy=%d\n", policy);
    }
	  	
    policy_struct->sadb_x_policy_len =PFKEY_UNIT64(policylen);

    ret = pfkey_send_spdadd(pfkeyfd,
			    saddr, this_client->maskbits,
			    daddr, that_client->maskbits,
			    255 /* proto */,
			    (caddr_t)policy_struct, policylen,
			    pfkey_seq++);

    if(ret < 0) {
	extern int __ipsec_errcode;
	DBG_log("ret = %d from send_spdadd: %d (%s) addr=%p/%p\n", ret
		, __ipsec_errcode, ipsec_strerror()
		, saddr, daddr);
	return FALSE;
    }
    return TRUE;
}

/* Add/replace/delete a shunt eroute.
 * Such an eroute determines the fate of packets without the use
 * of any SAs.  These are defaults, in effect.
 * If a negotiation has not been attempted, use %trap.
 * If negotiation has failed, the choice between %trap/%pass/%drop/%reject
 * is specified in the policy of connection c.
 */
static bool
bsdkame_shunt_eroute(struct connection *c 
		     , struct spd_route *sr 
		     , enum routing_t rt_kind 
		     , enum pluto_sadb_operations op 
		     , const char *opname)
{
    ipsec_spi_t spi = shunt_policy_spi(c, rt_kind == RT_ROUTED_PROSPECTIVE);
    int policy = -1;

    switch(spi) {
    case 0:
        /* we're supposed to end up with no eroute: rejig op and opname */
        switch (op)
        {
        case ERO_REPLACE:
            /* replace with nothing == delete */
            op = ERO_DELETE;
            opname = "delete";
            break;
        case ERO_ADD:
            /* add nothing == do nothing */
            return TRUE;

        case ERO_DELETE:
            /* delete remains delete */
            break;
	    
	case ERO_ADD_INBOUND:
	    break;

	case ERO_DEL_INBOUND:
	    break;

        default:
            bad_case(op);
        }
	break;
	
    case SPI_TRAP:
	policy = IPSEC_POLICY_IPSEC;
	break;
	
    case SPI_PASS:
        policy = IPSEC_POLICY_NONE;  /* BYPASS is for sockets only */
	break;

    case SPI_REJECT:
    case SPI_DROP:
	policy = IPSEC_POLICY_DISCARD;
	break;
	
    default:
      DBG_log("shunt_eroute called with spi=%08x\n", spi);
    }

    if (sr->routing == RT_ROUTED_ECLIPSED && c->kind == CK_TEMPLATE)
    {
        /* We think that we have an eroute, but we don't.
         * Adjust the request and account for eclipses.
         */
        passert(eclipsable(sr));
        switch (op)
        {
        case ERO_REPLACE:
            /* really an add */
            op = ERO_ADD;
            opname = "replace eclipsed";
            eclipse_count--;
            break;
	    
        case ERO_DELETE:
            /* delete unnecessary: we don't actually have an eroute */
            eclipse_count--;
            return TRUE;

        case ERO_ADD:
        default:
            bad_case(op);
        }
    }
    else if (eclipse_count > 0 && op == ERO_DELETE && eclipsable(sr))
    {
        /* maybe we are uneclipsing something */
        struct spd_route *esr;
        struct connection *ue = eclipsed(c, &esr);

        if (ue != NULL)
        {
            esr->routing = RT_ROUTED_PROSPECTIVE;
            return bsdkame_shunt_eroute(ue, esr
				      , RT_ROUTED_PROSPECTIVE
				      , ERO_REPLACE
				      , "restoring eclipsed");
        }
    }

    switch(op) {
    case ERO_REPLACE:
    case ERO_ADD:
    {
	ip_subnet *mine   = &sr->this.client;
	ip_subnet *his    = &sr->that.client;
	const struct sockaddr *saddr = (const struct sockaddr *)&mine->addr;
	const struct sockaddr *daddr = (const struct sockaddr *)&his->addr;
	char pbuf[512];
	char buf2[256];
	struct sadb_x_policy *policy_struct = (struct sadb_x_policy *)pbuf;
	struct sadb_x_ipsecrequest *ir;
	int policylen;
	int ret;
      
	snprintf(buf2, sizeof(buf2)
		 , "eroute_connection %s", opname);

	memset(pbuf, 0, sizeof(pbuf));

	/* XXX need to fix this for v6 */
	mine->addr.u.v4.sin_len  = sizeof(struct sockaddr_in);
	his->addr.u.v4.sin_len   = sizeof(struct sockaddr_in);

	passert(policy != -1);

	policy_struct->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy_struct->sadb_x_policy_type = policy;
	policy_struct->sadb_x_policy_dir  = IPSEC_DIR_OUTBOUND;
        policy_struct->sadb_x_policy_id   = 0; /* needs to be set, and recorded */

	policylen = sizeof(*policy_struct);

	if(policy == IPSEC_POLICY_IPSEC) {
	    ip_address *me   = &sr->this.host_addr;
	    ip_address *him  = &sr->that.host_addr;
	    unsigned char *addrmem;

	    /* should be already filled in */
	    me->u.v4.sin_len  = sizeof(struct sockaddr_in);
	    him->u.v4.sin_len  = sizeof(struct sockaddr_in);

	    ir = (struct sadb_x_ipsecrequest *)&policy_struct[1];
	  
	    ir->sadb_x_ipsecrequest_len = sizeof(struct sadb_x_ipsecrequest)+me->u.v4.sin_len+him->u.v4.sin_len;
	    if(c->policy & POLICY_ENCRYPT) {
	      /* maybe should look at IPCOMP too */
	      ir->sadb_x_ipsecrequest_proto = IPPROTO_ESP;
	    } else {
	      ir->sadb_x_ipsecrequest_proto = IPPROTO_AH;
	    }

	    if(c->policy & POLICY_TUNNEL) {
		ir->sadb_x_ipsecrequest_mode=IPSEC_MODE_TUNNEL;
	    } else {
		ir->sadb_x_ipsecrequest_mode=IPSEC_MODE_TRANSPORT;
	    }
	    ir->sadb_x_ipsecrequest_level=IPSEC_LEVEL_REQUIRE;
	    ir->sadb_x_ipsecrequest_reqid=0;  /* not used for now */
   
	    addrmem = (unsigned char *)&ir[1];
	    memcpy(addrmem, &me->u.v4,  me->u.v4.sin_len);
	    addrmem += me->u.v4.sin_len;
	    memcpy(addrmem, &him->u.v4, him->u.v4.sin_len);

	    addrmem += him->u.v4.sin_len;

	    policylen += ir->sadb_x_ipsecrequest_len;
	
	    DBG_log("request_len=%u policylen=%u\n",
		    ir->sadb_x_ipsecrequest_len, policylen);

	} else {
	  DBG_log("setting policy=%d\n", policy);
	}
	  	
	policy_struct->sadb_x_policy_len =PFKEY_UNIT64(policylen);

	ret = pfkey_send_spdadd(pfkeyfd,
				saddr, mine->maskbits,
				daddr, his->maskbits,
				255 /* proto */,
				(caddr_t)policy_struct, policylen,
				pfkey_seq++);

	if(ret < 0) {
	    extern int __ipsec_errcode;
	    DBG_log("ret = %d from send_spdadd: %d (%s) addr=%p/%p\n", ret
		    , __ipsec_errcode, ipsec_strerror()
		    , saddr, daddr);
	    return FALSE;
	}
	return TRUE;
    }

    case ERO_DELETE:
      {
	/* need to send a delete message */
	ip_subnet *mine   = &sr->this.client;
	ip_subnet *his    = &sr->that.client;
	const struct sockaddr *saddr = (const struct sockaddr *)&mine->addr;
	const struct sockaddr *daddr = (const struct sockaddr *)&his->addr;
	char pbuf[512];
	char buf2[256];
	struct sadb_x_policy *policy_struct = (struct sadb_x_policy *)pbuf;
	int policylen;
	int ret;
      
	DBG_log("need to send a delete message\n");

	snprintf(buf2, sizeof(buf2)
		 , "eroute_connection %s", opname);

	/* XXX need to fix this for v6 */
	mine->addr.u.v4.sin_len  = sizeof(struct sockaddr_in);
	his->addr.u.v4.sin_len   = sizeof(struct sockaddr_in);

	policy_struct->sadb_x_policy_exttype = SADB_X_EXT_POLICY;

	/* this might be wrong! --- probably should use spddelete2() */
	policy_struct->sadb_x_policy_type = IPSEC_POLICY_IPSEC;
	policy_struct->sadb_x_policy_dir  = IPSEC_DIR_OUTBOUND;
        policy_struct->sadb_x_policy_id = 0;

	policylen = sizeof(*policy_struct);

	policy_struct->sadb_x_policy_len =PFKEY_UNIT64(policylen);

	ret = pfkey_send_spddelete(pfkeyfd,
				saddr, mine->maskbits,
				daddr, his->maskbits,
				255 /* proto */,
				(caddr_t)policy_struct, policylen,
				pfkey_seq++);

	if(ret < 0) {
	    extern int __ipsec_errcode;
	    DBG_log("ret = %d from send_spdadd: %d (%s) addr=%p/%p\n", ret
		    , __ipsec_errcode, ipsec_strerror()
		    , saddr, daddr);
	    return FALSE;
	}
	return TRUE;
      break;
      }
    case ERO_ADD_INBOUND:
    case ERO_REPLACE_INBOUND:
    case ERO_DEL_INBOUND:
      bad_case(op);
    }
    return FALSE;
}

/* install or remove eroute for SA Group */
static bool
bsdkame_sag_eroute(struct state *st UNUSED
		   , struct spd_route *sr UNUSED
		   , unsigned op UNUSED
		   , const char *opname UNUSED)
{
    return TRUE;
}

static bool
bsdkame_add_sa(const struct kernel_sa *sa, bool replace)
{
    const struct sockaddr *saddr = (const struct sockaddr *)sa->src;
    const struct sockaddr *daddr = (const struct sockaddr *)sa->dst;
    char keymat[256];
    int ret, mode, satype;
      
    passert(sa->src->u.v4.sin_len == sizeof(struct sockaddr_in));

    if(sa->encapsulation == ENCAPSULATION_MODE_TUNNEL) {
	mode=IPSEC_MODE_TUNNEL;
    } else {
	mode=IPSEC_MODE_TRANSPORT;
    }

    switch(sa->esatype) {
    case ET_AH:
	satype=SADB_SATYPE_AH;
	break;
    case ET_ESP:
	satype=SADB_SATYPE_ESP;
	break;
    case ET_IPCOMP:
	satype=SADB_X_SATYPE_IPCOMP;
	break;
	
    case ET_IPIP:
      return TRUE;

    case ET_INT:
    case ET_UNSPEC:
	bad_case(sa->esatype);
    }

    if((sa->enckeylen + sa->authkeylen) > sizeof(keymat)) {
	openswan_log("Key material is too big for kernel interface: %d>%d\n"
		     , (sa->enckeylen + sa->authkeylen)
		     , sizeof(keymat));
	return FALSE;
    }
    
    memcpy(keymat, sa->enckey, sa->enckeylen);
    memcpy(keymat+sa->enckeylen, sa->authkey, sa->authkeylen);

    ret = pfkey_send_x1(pfkeyfd, (replace ? SADB_UPDATE : SADB_ADD),
			satype, mode,
			saddr, daddr, 
			sa->spi,
			sa->reqid, /* reqid */
			64, /* wsize, replay window size */
			keymat,
			sa->encalg,
			sa->enckeylen,
			sa->authalg,
			sa->authkeylen,
			0, /*flags */
			0, /* l_alloc */
			0, /* l_bytes */
			0, /* l_addtime */
			0, /* l_usetime, */
			pfkey_seq++);

    if(ret < 0) {
	extern int __ipsec_errcode;
	openswan_log("ret = %d from send_add: %d (%s)", ret
		     , __ipsec_errcode, ipsec_strerror());
	return FALSE;
    }

    return TRUE;
}

static bool
bsdkame_grp_sa(const struct kernel_sa *sa0 UNUSED
	       , const struct kernel_sa *sa1 UNUSED)
{
    return TRUE;
}

static bool
bsdkame_del_sa(const struct kernel_sa *sa UNUSED)
{
    return TRUE;
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
bsdkame_set_debug(int cur_debug
		  , openswan_keying_debug_func_t debug_func
		  , openswan_keying_debug_func_t error_func UNUSED)
{
	bsdpfkey_lib_debug = (cur_debug&DBG_PFKEY ? 1 : 0);
	pfkey_debug_func = debug_func;
}

static void
bsdkame_remove_orphaned_holds(int transport_proto  UNUSED
			      , const ip_subnet *ours  UNUSED
			      , const ip_subnet *his UNUSED)
{
    passert(0);
}

static bool
bsdkame_except_socket(int socketfd, int family)
{
	struct sadb_x_policy policy;
	int level, optname;

	switch (family) {
	case AF_INET:
		level = IPPROTO_IP;
		optname = IP_IPSEC_POLICY;
		break;
#ifdef INET6
	case AF_INET6:
		level = IPPROTO_IPV6;
		optname = IPV6_IPSEC_POLICY;
		break;
#endif
	default:
		openswan_log("unsupported address family (%d)\n", family);
		return FALSE;
	}

	memset(&policy, 0, sizeof(policy));
	policy.sadb_x_policy_len = PFKEY_UNIT64(sizeof(policy));
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
	if (setsockopt(socketfd, level, optname, &policy, sizeof(policy)) == -1) {
	    openswan_log("bsdkame except socket setsockopt: %s\n", strerror(errno));
	    return FALSE;
	}
	policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
	if (setsockopt(socketfd, level, optname, &policy, sizeof(policy)) == -1) {
	    openswan_log("bsdkame except socket setsockopt: %s\n", strerror(errno));
	    return FALSE;
	}
	return TRUE;
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
    policy_lifetime: TRUE,
    init: bsdkame_init_pfkey,
    exceptsocket: bsdkame_except_socket, 
    docommand: bsdkame_do_command,
    set_debug: bsdkame_set_debug,
    remove_orphaned_holds: bsdkame_remove_orphaned_holds,
    process_ifaces: bsdkame_process_raw_ifaces,
};

