/*
 * routines that are Linux specific
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: sysdep_linux.c,v 1.2 2005/07/19 20:34:15 ken Exp $
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/queue.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "rnd.h"
#include "id.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "timer.h"
#include "kernel.h"
#include "kernel_netlink.h"
#include "kernel_pfkey.h"
#include "kernel_noklips.h"
#include "packet.h"
#include "x509.h"
#include "log.h"
#include "server.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "keys.h"

/* invoke the updown script to do the routing and firewall commands required
 *
 * The user-specified updown script is run.  Parameters are fed to it in
 * the form of environment variables.  All such environment variables
 * have names starting with "PLUTO_".
 *
 * The operation to be performed is specified by PLUTO_VERB.  This
 * verb has a suffix "-host" if the client on this end is just the
 * host; otherwise the suffix is "-client".  If the address family
 * of the host is IPv6, an extra suffix of "-v6" is added.
 *
 * "prepare-host" and "prepare-client" are used to delete a route
 * that may exist (due to forces outside of Pluto).  It is used to
 * prepare for pluto creating a route.
 *
 * "route-host" and "route-client" are used to install a route.
 * Since routing is based only on destination, the PLUTO_MY_CLIENT_*
 * values are probably of no use (using them may signify a bug).
 *
 * "unroute-host" and "unroute-client" are used to delete a route.
 * Since routing is based only on destination, the PLUTO_MY_CLIENT_*
 * values are probably of no use (using them may signify a bug).
 *
 * "up-host" and "up-client" are run when an eroute is added (not replaced).
 * They are useful for adjusting a firewall: usually for adding a rule
 * to let processed packets flow between clients.  Note that only
 * one eroute may exist for a pair of client subnets but inbound
 * IPsec SAs may persist without an eroute.
 *
 * "down-host" and "down-client" are run when an eroute is deleted.
 * They are useful for adjusting a firewall.
 */

#ifndef DEFAULT_UPDOWN
# define DEFAULT_UPDOWN "ipsec _updown"
#endif

bool
do_command_linux(struct connection *c, struct spd_route *sr
		 , const char *verb, struct state *st)
{
    char cmd[1536];     /* arbitrary limit on shell command length */
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

    /* form the command string */
    {
        char
            nexthop_str[sizeof("PLUTO_NEXT_HOP='' ")+ADDRTOT_BUF],
            me_str[ADDRTOT_BUF],
            myid_str[IDTOA_BUF],
            srcip_str[ADDRTOT_BUF+sizeof("PLUTO_MY_SOURCEIP=")+4],
            myclient_str[SUBNETTOT_BUF],
            myclientnet_str[ADDRTOT_BUF],
            myclientmask_str[ADDRTOT_BUF],
            peer_str[ADDRTOT_BUF],
            peerid_str[IDTOA_BUF],
            peerclient_str[SUBNETTOT_BUF],
            peerclientnet_str[ADDRTOT_BUF],
            peerclientmask_str[ADDRTOT_BUF],
            secure_myid_str[IDTOA_BUF] = "",
            secure_peerid_str[IDTOA_BUF] = "",
            secure_peerca_str[IDTOA_BUF] = "",
            secure_xauth_username_str[IDTOA_BUF] = "";
	    
        ip_address ta;

	nexthop_str[0]='\0';
	if(addrbytesptr(&sr->this.host_nexthop, NULL)
	   && !isanyaddr(&sr->this.host_nexthop))
	{
	    char *n;
	    strcpy(nexthop_str, "PLUTO_NEXT_HOP='");
	    n = nexthop_str + strlen(nexthop_str);
	    addrtot(&sr->this.host_nexthop, 0,
		    n, sizeof(nexthop_str)-strlen(nexthop_str));
	    strncat(nexthop_str, "' ", sizeof(nexthop_str));
	}

        addrtot(&sr->this.host_addr, 0, me_str, sizeof(me_str));
        idtoa(&sr->this.id, myid_str, sizeof(myid_str));
        escape_metachar(myid_str, secure_myid_str, sizeof(secure_myid_str));
        subnettot(&sr->this.client, 0, myclient_str, sizeof(myclientnet_str));
        networkof(&sr->this.client, &ta);
        addrtot(&ta, 0, myclientnet_str, sizeof(myclientnet_str));
        maskof(&sr->this.client, &ta);
        addrtot(&ta, 0, myclientmask_str, sizeof(myclientmask_str));

        addrtot(&sr->that.host_addr, 0, peer_str, sizeof(peer_str));
        idtoa(&sr->that.id, peerid_str, sizeof(peerid_str));
        escape_metachar(peerid_str, secure_peerid_str, sizeof(secure_peerid_str));
        subnettot(&sr->that.client, 0, peerclient_str, sizeof(peerclientnet_str));
        networkof(&sr->that.client, &ta);
        addrtot(&ta, 0, peerclientnet_str, sizeof(peerclientnet_str));
        maskof(&sr->that.client, &ta);
        addrtot(&ta, 0, peerclientmask_str, sizeof(peerclientmask_str));
	
	secure_xauth_username_str[0]='\0';
	if (st != NULL && st->st_xauth_username) {
		size_t len;
	 	strcpy(secure_xauth_username_str, "PLUTO_XAUTH_USERNAME='");

		len = strlen(secure_xauth_username_str);
		remove_metachar(st->st_xauth_username
				,secure_xauth_username_str+len
				,sizeof(secure_xauth_username_str)-(len+2));
		strncat(secure_xauth_username_str, "'", sizeof(secure_xauth_username_str)-1);
	}

        srcip_str[0]='\0';
        if(addrbytesptr(&sr->this.host_srcip, NULL) != 0
           && !isanyaddr(&sr->this.host_srcip))
        {
            char *p;
            int   l;
            strncat(srcip_str, "PLUTO_MY_SOURCEIP=", sizeof(srcip_str));
            strncat(srcip_str, "'", sizeof(srcip_str));
            l = strlen(srcip_str);
            p = srcip_str + l;
            
            addrtot(&sr->this.host_srcip, 0, p, sizeof(srcip_str));
            strncat(srcip_str, "'", sizeof(srcip_str));
        }

        {
            struct pubkey_list *p;
            char peerca_str[IDTOA_BUF];

            for (p = pubkeys; p != NULL; p = p->next)
                {
                    struct pubkey *key = p->key;
                    int pathlen;
                    
                    if (key->alg == PUBKEY_ALG_RSA && same_id(&sr->that.id, &key->id)
                        && trusted_ca(key->issuer, sr->that.ca, &pathlen))
                        {
                            dntoa_or_null(peerca_str, IDTOA_BUF, key->issuer, "");
                            escape_metachar(peerca_str, secure_peerca_str, sizeof(secure_peerca_str));
                            break;
                        }
                }
        }

        if (-1 == snprintf(cmd, sizeof(cmd)
			   , "2>&1 "   /* capture stderr along with stdout */
			   "PLUTO_VERSION='1.1' "    /* change VERSION when interface spec changes */
			   "PLUTO_VERB='%s%s' "
			   "PLUTO_CONNECTION='%s' "
			   "%s"      /* possible PLUTO_NEXT_HOP */
			   "PLUTO_INTERFACE='%s' "
			   "PLUTO_ME='%s' "
			   "PLUTO_MY_ID='%s' "
			   "PLUTO_MY_CLIENT='%s' "
			   "PLUTO_MY_CLIENT_NET='%s' "
			   "PLUTO_MY_CLIENT_MASK='%s' "
			   "PLUTO_MY_PORT='%u' "
			   "PLUTO_MY_PROTOCOL='%u' "
			   "PLUTO_PEER='%s' "
			   "PLUTO_PEER_ID='%s' "
			   "PLUTO_PEER_CLIENT='%s' "
			   "PLUTO_PEER_CLIENT_NET='%s' "
			   "PLUTO_PEER_CLIENT_MASK='%s' "
			   "PLUTO_PEER_PORT='%u' "
			   "PLUTO_PEER_PROTOCOL='%u' "
			   "PLUTO_PEER_CA='%s' "
			   "PLUTO_CONN_POLICY='%s' "
			   "%s "
			   "%s "       /* PLUTO_MY_SRCIP */                    
			   "%s"        /* actual script */
			   , verb, verb_suffix
			   , c->name
			   , nexthop_str
			   , c->interface->ip_dev->id_vname
			   , me_str
			   , secure_myid_str
			   , myclient_str
			   , myclientnet_str
			   , myclientmask_str
			   , sr->this.port
			   , sr->this.protocol
			   , peer_str
			   , secure_peerid_str
			   , peerclient_str
			   , peerclientnet_str
			   , peerclientmask_str
			   , sr->that.port
			   , sr->that.protocol
			   , secure_peerca_str
			   , prettypolicy(c->policy)
			   , secure_xauth_username_str
			   , srcip_str
			   , sr->this.updown == NULL? DEFAULT_UPDOWN : sr->this.updown))
        {
            loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb, verb_suffix);
            return FALSE;
        }
    }

    DBG(DBG_CONTROL, DBG_log("executing %s%s: %s"
        , verb, verb_suffix, cmd));

    {
        /* invoke the script, catching stderr and stdout
         * It may be of concern that some file descriptors will
         * be inherited.  For the ones under our control, we
         * have done fcntl(fd, F_SETFD, FD_CLOEXEC) to prevent this.
         * Any used by library routines (perhaps the resolver or syslog)
         * will remain.
         */
	__sighandler_t savesig;
        FILE *f;

	savesig = signal(SIGCHLD, SIG_DFL);
        f = popen(cmd, "r");

        if (f == NULL)
        {
            loglog(RC_LOG_SERIOUS, "unable to popen %s%s command", verb, verb_suffix);
	    signal(SIGCHLD, savesig);
            return FALSE;
        }

        /* log any output */
        for (;;)
        {
            /* if response doesn't fit in this buffer, it will be folded */
            char resp[256];

            if (fgets(resp, sizeof(resp), f) == NULL)
            {
                if (ferror(f))
                {
                    log_errno((e, "fgets failed on output of %s%s command"
                        , verb, verb_suffix));
		    signal(SIGCHLD, savesig);
                    return FALSE;
                }
                else
                {
                    passert(feof(f));
                    break;
                }
            }
            else
            {
                char *e = resp + strlen(resp);

                if (e > resp && e[-1] == '\n')
                    e[-1] = '\0';       /* trim trailing '\n' */
                openswan_log("%s%s output: %s", verb, verb_suffix, resp);
            }
        }

        /* report on and react to return code */
        {
            int r = pclose(f);
	    signal(SIGCHLD, savesig);

            if (r == -1)
            {
                log_errno((e, "pclose failed for %s%s command"
                    , verb, verb_suffix));
                return FALSE;
            }
            else if (WIFEXITED(r))
            {
                if (WEXITSTATUS(r) != 0)
                {
                    loglog(RC_LOG_SERIOUS, "%s%s command exited with status %d"
                        , verb, verb_suffix, WEXITSTATUS(r));
                    return FALSE;
                }
            }
            else if (WIFSIGNALED(r))
            {
                loglog(RC_LOG_SERIOUS, "%s%s command exited with signal %d"
                    , verb, verb_suffix, WTERMSIG(r));
                return FALSE;
            }
            else
            {
                loglog(RC_LOG_SERIOUS, "%s%s command exited with unknown status %d"
                    , verb, verb_suffix, r);
                return FALSE;
            }
        }
    }
    return TRUE;
}

