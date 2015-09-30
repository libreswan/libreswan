/*
 * routines that are FreeBSD specific
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
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
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "socketwrapper.h"
#include "constants.h"
#include "lswlog.h"

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

/* for CIRCLEQ_ENTRY */
#include <sys/queue.h>

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

static const char *pluto_ifn[10];
static int pluto_ifn_roof = 0;

bool invoke_command(const char *verb, const char *verb_suffix, char *cmd)
{
	DBG(DBG_CONTROL, DBG_log("executing %s%s: %s",
				 verb, verb_suffix, cmd));

	{
		/* invoke the script, catching stderr and stdout
		 * It may be of concern that some file descriptors will
		 * be inherited.  For the ones under our control, we
		 * have done fcntl(fd, F_SETFD, FD_CLOEXEC) to prevent this.
		 * Any used by library routines (perhaps the resolver or syslog)
		 * will remain.
		 */
		sig_t savesig;
		FILE *f;

		savesig = signal(SIGCHLD, SIG_DFL);
		f = popen(cmd, "r");

		if (f == NULL) {
			loglog(RC_LOG_SERIOUS, "unable to popen %s%s command",
			       verb, verb_suffix);
			signal(SIGCHLD, savesig);
			return FALSE;
		}

		/* log any output */
		for (;; ) {
			/* if response doesn't fit in this buffer, it will be folded */
			char resp[256];

			if (fgets(resp, sizeof(resp), f) == NULL) {
				if (ferror(f)) {
					log_errno((e,
						   "fgets failed on output of %s%s command",
						   verb, verb_suffix));
					signal(SIGCHLD, savesig);
					return FALSE;
				} else {
					passert(feof(f));
					break;
				}
			} else {
				char *e = resp + strlen(resp);

				if (e > resp && e[-1] == '\n')
					e[-1] = '\0'; /* trim trailing '\n' */
				libreswan_log("%s%s output: %s", verb,
					      verb_suffix, resp);
			}
		}

		/* report on and react to return code */
		{
			int r = pclose(f);
			signal(SIGCHLD, savesig);

			if (r == -1) {
				log_errno((e, "pclose failed for %s%s command",
					   verb, verb_suffix));
				return FALSE;
			} else if (WIFEXITED(r)) {
				if (WEXITSTATUS(r) != 0) {
					loglog(RC_LOG_SERIOUS,
					       "%s%s command exited with status %d",
					       verb, verb_suffix, WEXITSTATUS(
						       r));
					return FALSE;
				}
			} else if (WIFSIGNALED(r)) {
				loglog(RC_LOG_SERIOUS,
				       "%s%s command exited with signal %d",
				       verb, verb_suffix, WTERMSIG(r));
				return FALSE;
			} else {
				loglog(RC_LOG_SERIOUS,
				       "%s%s command exited with unknown status %d",
				       verb, verb_suffix, r);
				return FALSE;
			}
		}
	}
	return TRUE;
}

struct raw_iface *find_raw_ifaces4(void)
{
	static const int on = TRUE;	/* by-reference parameter; constant, we hope */
	int j;	/* index into buf */
	struct ifconf ifconf;
	struct ifreq *buf = NULL;	/* for list of interfaces -- arbitrary limit */
	struct raw_iface *rifaces = NULL;
	int master_sock = safe_socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);	/* Get a UDP socket */

	/*
	 * Current upper bound on number of interfaces.
	 * Tricky: because this is a static, we won't have to start from
	 * 64 in subsequent calls.
	 */
	static int num = 64;	/* number of interfaces */

	/* get list of interfaces with assigned IPv4 addresses from system */

	if (master_sock == -1)
		exit_log_errno((e, "socket() failed in find_raw_ifaces4()"));

	if (setsockopt(master_sock, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&on, sizeof(on)) < 0)
		exit_log_errno((e, "setsockopt() in find_raw_ifaces4()"));

	/* bind the socket */
	{
		ip_address any;

		happy(anyaddr(AF_INET, &any));
		setportof(htons(pluto_port), &any);
		if (bind(master_sock, sockaddrof(&any),
			 sockaddrlenof(&any)) < 0)
			exit_log_errno((e,
					"bind() failed in find_raw_ifaces4()"));
	}

	/* a million interfaces is probably the maximum, ever... */
	for (; num < (1024 * 1024); num *= 2) {
		/* Get num local interfaces.  See netdevice(7). */
		ifconf.ifc_len = num * sizeof(struct ifreq);
		buf = realloc(buf, ifconf.ifc_len);
		if (buf == NULL) {
			exit_log_errno((e,
					"realloc of %d in find_raw_ifaces4()",
					ifconf.ifc_len));
		}
		memset(buf, 0xDF, ifconf.ifc_len);	/* stomp */
		ifconf.ifc_buf = (void *) buf;

		if (ioctl(master_sock, SIOCGIFCONF, &ifconf) == -1)
			exit_log_errno((e,
					"ioctl(SIOCGIFCONF) in find_raw_ifaces4()"));

		/* if we got back less than we asked for, we have them all */
		if (ifconf.ifc_len < (int)(sizeof(struct ifreq) * num))
			break;
	}

	/* Add an entry to rifaces for each interesting interface. */
	for (j = 0; (j + 1) * sizeof(struct ifreq) <= (size_t)ifconf.ifc_len;
	     j++) {
		struct raw_iface ri;
		const struct sockaddr_in *rs =
			(struct sockaddr_in *) &buf[j].ifr_addr;
		struct ifreq auxinfo;

		/* ignore all but AF_INET interfaces */
		if (rs->sin_family != AF_INET)
			continue; /* not interesting */

		/* build a NUL-terminated copy of the rname field */
		memcpy(ri.name, buf[j].ifr_name, IFNAMSIZ);
		ri.name[IFNAMSIZ] = '\0';

		/* ignore if our interface names were specified, and this isn't one */
		if (pluto_ifn_roof != 0) {
			int i;

			for (i = 0; i != pluto_ifn_roof; i++)
				if (streq(ri.name, pluto_ifn[i]))
					break;
			if (i == pluto_ifn_roof)
				continue; /* not found -- skip */
		}

		/* Find out stuff about this interface.  See netdevice(7). */
		zero(&auxinfo); /* paranoia */
		memcpy(auxinfo.ifr_name, buf[j].ifr_name, IFNAMSIZ);
		if (ioctl(master_sock, SIOCGIFFLAGS, &auxinfo) == -1) {
			exit_log_errno((e,
					"ioctl(SIOCGIFFLAGS) for %s in find_raw_ifaces4()",
					ri.name));
		}
		if (!(auxinfo.ifr_flags & IFF_UP))
			continue; /* ignore an interface that isn't UP */

		/* ignore unconfigured interfaces */
		if (rs->sin_addr.s_addr == 0)
			continue;

		happy(initaddr((const void *)&rs->sin_addr,
			       sizeof(struct in_addr),
			       AF_INET, &ri.addr));

		DBG(DBG_CONTROL, {
			ipstr_buf b;
			DBG_log("found %s with address %s",
				ri.name, ipstr(&ri.addr, &b));
		});
		ri.next = rifaces;
		rifaces = clone_thing(ri, "struct raw_iface");
	}

	free(buf);	/* was allocated via realloc() */
	close(master_sock);
	return rifaces;
}

/*
 * there is a BSD way to do this, probably SIOCGCONF
 */
struct raw_iface *find_raw_ifaces6(void)
{
	return NULL;
}

bool do_command_freebsd(struct connection *c, struct spd_route *sr,
			const char *verb, struct state *st)
{
	char cmd[2048]; /* arbitrary limit on shell command length */
	const char *verb_suffix;

	/* figure out which verb suffix applies */
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

	/* form the command string */
	{
		char
			nexthop_str[sizeof("PLUTO_NEXT_HOP='' ") +
				    ADDRTOT_BUF],
			me_str[ADDRTOT_BUF],
			myid_str[IDTOA_BUF],
			srcip_str[ADDRTOT_BUF + sizeof("PLUTO_MY_SOURCEIP=") +
				  4],
			myclient_str[SUBNETTOT_BUF],
			myclientnet_str[ADDRTOT_BUF],
			myclientmask_str[ADDRTOT_BUF],
			peerid_str[IDTOA_BUF],
			peerclient_str[SUBNETTOT_BUF],
			peerclientnet_str[ADDRTOT_BUF],
			peerclientmask_str[ADDRTOT_BUF],
			secure_myid_str[IDTOA_BUF] = "",
			secure_peerid_str[IDTOA_BUF] = "",
			secure_peerca_str[IDTOA_BUF] = "",
			secure_xauth_username_str[IDTOA_BUF] = "";

		ipstr_buf bme, bpeer;
		ip_address ta;

		nexthop_str[0] = '\0';
		if (addrbytesptr(&sr->this.host_nexthop, NULL) &&
		    !isanyaddr(&sr->this.host_nexthop)) {
			char *n = jam_str(nexthop_str, sizeof(nexthop_str), "PLUTO_NEXT_HOP='");

			addrtot(&sr->this.host_nexthop, 0,
				n, sizeof(nexthop_str) - (p-nexthop_str));
			add_str(nexthop_str, sizeof(nexthop_str), n, "' ");
		}

		idtoa(&sr->this.id, myid_str, sizeof(myid_str));
		escape_metachar(myid_str, secure_myid_str,
				sizeof(secure_myid_str));
		subnettot(&sr->this.client, 0, myclient_str,
			  sizeof(myclientnet_str));
		networkof(&sr->this.client, &ta);
		addrtot(&ta, 0, myclientnet_str, sizeof(myclientnet_str));
		maskof(&sr->this.client, &ta);
		addrtot(&ta, 0, myclientmask_str, sizeof(myclientmask_str));

		idtoa(&sr->that.id, peerid_str, sizeof(peerid_str));
		escape_metachar(peerid_str, secure_peerid_str,
				sizeof(secure_peerid_str));
		subnettot(&sr->that.client, 0, peerclient_str,
			  sizeof(peerclientnet_str));
		networkof(&sr->that.client, &ta);
		addrtot(&ta, 0, peerclientnet_str, sizeof(peerclientnet_str));
		maskof(&sr->that.client, &ta);
		addrtot(&ta, 0, peerclientmask_str,
			sizeof(peerclientmask_str));

		secure_xauth_username_str[0] = '\0';
		if (st != NULL && st->st_xauth_username[0] != '\0') {
			char *p = jam_str(secure_xauth_username_str, sizeof(secure_xauth_username_str), "PLUTO_XAUTH_USERNAME='");

			remove_metachar(st->st_xauth_username,
					p,
					sizeof(secure_xauth_username_str) - (p - secure_xauth_username_str) - 2);
			add_str(secure_xauth_username_str, sizeof(secure_xauth_username_str), p, "'");
		}

		srcip_str[0] = '\0';
		if (addrbytesptr(&sr->this.host_srcip, NULL) != 0 &&
		    !isanyaddr(&sr->this.host_srcip)) {
			char *p = jam_str(srcip_str, sizeof(srcip_str), "PLUTO_MY_SOURCEIP='");

			addrtot(&sr->this.host_srcip, 0, p, sizeof(srcip_str) - (p - srcip_str));
			add_str(srcip_str, sizeof(srcip_str), p, "'");
		}

		{
			struct pubkey_list *p;
			char peerca_str[IDTOA_BUF];

			for (p = pluto_pubkeys; p != NULL; p = p->next) {
				struct pubkey *key = p->key;
				int pathlen;

				if (key->alg == PUBKEY_ALG_RSA &&
				    same_id(&sr->that.id, &key->id) &&
				    trusted_ca(key->issuer, sr->that.ca,
					       &pathlen)) {
					dntoa_or_null(peerca_str, IDTOA_BUF,
						      key->issuer, "");
					escape_metachar(peerca_str,
							secure_peerca_str,
							sizeof(secure_peerca_str));
					break;
				}
			}
		}

		if (-1 == snprintf(cmd, sizeof(cmd),
				   "2>&1 "                      /* capture stderr along with stdout */
				   "PLUTO_VERSION='1.1' "       /* change VERSION when interface spec changes */
				   "PLUTO_VERB='%s%s' "
				   "PLUTO_CONNECTION='%s' "
				   "%s" /* possible PLUTO_NEXT_HOP */
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
				   "%s "        /* PLUTO_MY_SRCIP */
				   "%s",        /* actual script */
				   verb, verb_suffix,
				   c->name,
				   nexthop_str,
				   c->interface->ip_dev->id_vname,
				   ipstr(&sr->this.host_addr, &bme),
				   secure_myid_str,
				   myclient_str,
				   myclientnet_str,
				   myclientmask_str,
				   sr->this.port,
				   sr->this.protocol,
				   ipstr(&sr->that.host_addr, &bpeer),
				   secure_peerid_str,
				   peerclient_str,
				   peerclientnet_str,
				   peerclientmask_str,
				   sr->that.port,
				   sr->that.protocol,
				   secure_peerca_str,
				   prettypolicy(c->policy),
				   secure_xauth_username_str,
				   srcip_str,
				   sr->this.updown == NULL ?
					DEFAULT_UPDOWN : sr->this.updown)) {
			loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb,
			       verb_suffix);
			return FALSE;
		}
	}

	return invoke_command(verb, verb_suffix, cmd);
}

/* Called to handle --interface <ifname>
 * Semantics: if specified, only these (real) interfaces are considered.
 */
bool use_interface(const char *rifn)
{
	if (pluto_ifn_inst[0] == '\0')
		pluto_ifn_inst = clone_str(rifn, "genifn");

	if (pluto_ifn_roof >= (int)elemsof(pluto_ifn)) {
		return FALSE;
	} else {
		pluto_ifn[pluto_ifn_roof++] = rifn;
		return TRUE;
	}
}
