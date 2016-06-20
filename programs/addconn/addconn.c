/*
 * A program to read the configuration file and load a single conn
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Kim B. Heino <b@bbbs.net>
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
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <netinet/in.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <libreswan.h>
#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "lswconf.h"
#include "lswlog.h"
#include "whack.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/starterlog.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterwhack.h"
#include "ipsecconf/keywords.h"
#include "ipsecconf/parser-controls.h"

char *progname;
static int verbose = 0;

/* Buffer size for netlink query (~100 bytes) and replies.
 * If DST is specified, reply will be ~100 bytes.
 * If DST is not specified, full route table will be returned.
 * 16kB was too small for biggish router, so do 32kB.
 * TODO: This should be dynamic! Fix it in netlink_read_reply().
 * Note: due to our hack to dodge a bug in NLMSG_OK,
 * RTNL_BUFSIZE must be less than or equal to USHRT_MAX.
 */
#define RTNL_BUFSIZE 32768

/*
 * Initialize netlink query message.
 */
static
void netlink_query_init(char *msgbuf, sa_family_t family)
{
	struct nlmsghdr *nlmsg;
	struct rtmsg *rtmsg;

	/* Create request for route */
	memset(msgbuf, 0, RTNL_BUFSIZE);
	nlmsg = (struct nlmsghdr *)msgbuf;

	nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlmsg->nlmsg_flags = NLM_F_REQUEST;
	nlmsg->nlmsg_type = RTM_GETROUTE;
	nlmsg->nlmsg_seq = 0;
	nlmsg->nlmsg_pid = getpid();

	rtmsg = (struct rtmsg *)NLMSG_DATA(nlmsg);
	rtmsg->rtm_family = family;
	rtmsg->rtm_table = 0;
	rtmsg->rtm_protocol = 0;
	rtmsg->rtm_scope = 0;
	rtmsg->rtm_type = 0;
	rtmsg->rtm_src_len = 0;
	rtmsg->rtm_dst_len = 0;
	rtmsg->rtm_tos = 0;
}

/*
 * Add RTA_SRC or RTA_DST attribute to netlink query message.
 */
static
void netlink_query_add(char *msgbuf, int rta_type, ip_address *addr)
{
	struct nlmsghdr *nlmsg;
	struct rtmsg *rtmsg;
	struct rtattr *rtattr;
	int len, rtlen;
	void *p;

	nlmsg = (struct nlmsghdr *)msgbuf;
	rtmsg = (struct rtmsg *)NLMSG_DATA(nlmsg);

	/* Find first empty attribute slot */
	rtlen = RTM_PAYLOAD(nlmsg);
	rtattr = (struct rtattr *)RTM_RTA(rtmsg);
	while (RTA_OK(rtattr, rtlen))
		rtattr = RTA_NEXT(rtattr, rtlen);

	/* Add attribute */
	if (rtmsg->rtm_family == AF_INET) {
		len = 4;
		p = (void*)&addr->u.v4.sin_addr.s_addr;
	} else {
		len = 16;
		p = (void*)addr->u.v6.sin6_addr.s6_addr;
	}
	rtattr->rta_type = rta_type;
	rtattr->rta_len = sizeof(struct rtattr) + len; /* bytes */
	memmove(RTA_DATA(rtattr), p, len);
	if (rta_type == RTA_SRC)
		rtmsg->rtm_src_len = len * 8; /* bits */
	else
		rtmsg->rtm_dst_len = len * 8;
	nlmsg->nlmsg_len += rtattr->rta_len;
}

static
ssize_t netlink_read_reply(int sock, char *buf, unsigned int seqnum, __u32 pid)
{
	ssize_t msglen = 0;

	/* TODO: use dynamic buf */
	for (;;) {
		struct sockaddr_nl sa;
		ssize_t readlen;

		/* Read netlink message, verifying kernel origin. */
		do {
			socklen_t salen = sizeof(sa);

			readlen = recvfrom(sock, buf, RTNL_BUFSIZE - msglen, 0,
					(struct sockaddr *)&sa, &salen);
			if (readlen < 0 || salen != sizeof(sa))
				return -1;
		} while (sa.nl_pid != 0);

		/* Verify it's valid */
		struct nlmsghdr *nlhdr = (struct nlmsghdr *) buf;

		/*
		 * The cast to unsigned short is to dodge an error in
		 * netlink.h:NLMSG_OK() which triggers a GCC warning in recent
		 * versions of GCC (2014 August):
		 * error: comparison between signed and unsigned integer expressions
		 * Note: as long as RTNL_BUFSIZE <= USHRT_MAX, this is safe.
		 */
		if (!NLMSG_OK(nlhdr, (unsigned short)readlen) ||
			nlhdr->nlmsg_type == NLMSG_ERROR)
			return -1;

		/* Check if it is the last message */
		if (nlhdr->nlmsg_type == NLMSG_DONE)
			break;

		/* Not last, move read pointer */
		buf += readlen;
		msglen += readlen;

		/* all done if it's not a multi part */
		if ((nlhdr->nlmsg_flags & NLM_F_MULTI) == 0)
			break;

		/* all done if this is the one we were searching for */
		if (nlhdr->nlmsg_seq == seqnum &&
		    nlhdr->nlmsg_pid == pid)
			break;
	}

	return msglen;
}

/*
 * Send netlink query message and read reply.
 */
static
ssize_t netlink_query(char *msgbuf)
{
	int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

	if (sock < 0) {
		int e = errno;

		printf("create netlink socket failure: (%d: %s)\n", e, strerror(e));
		return -1;
	}

	/* Send request */
	struct nlmsghdr *nlmsg = (struct nlmsghdr *)msgbuf;

	if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
		int e = errno;

		printf("write netlink socket failure: (%d: %s)\n", e, strerror(e));
		return -1;
	}

	/* Read response */
	errno = 0;	/* in case failure does not set it */
	ssize_t len = netlink_read_reply(sock, msgbuf, 1, getpid());

	if (len < 0) {
		int e = errno;

		printf("read netlink socket failure: (%d: %s)\n", e, strerror(e));
		return -1;
	}
	close(sock);
	return len;
}

/*
 * Resolve interface's peer.
 * Return: 0 = ok, fill peer
 *         -1 = not found
 */
static
void resolve_ppp_peer(char *interface, sa_family_t family, char *peer)
{
	struct ifaddrs *ifap, *ifa;

	/* Get info about all interfaces */
	if (getifaddrs(&ifap) != 0)
		return;

	/* Find the right interface */
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
		if ((ifa->ifa_flags & IFF_POINTOPOINT) != 0 &&
			streq(ifa->ifa_name, interface)) {
			struct sockaddr *sa = ifa->ifa_ifu.ifu_dstaddr;

			if (sa != NULL && sa->sa_family == family &&
				getnameinfo(sa,
					((sa->sa_family == AF_INET) ?
						sizeof(struct sockaddr_in) :
						sizeof(struct sockaddr_in6)),
					peer, NI_MAXHOST,
					NULL, 0,
					NI_NUMERICHOST) == 0) {
				if (verbose) {
					printf("found peer %s to interface %s\n",
						peer,
						interface);
				}
				freeifaddrs(ifap);
				return;
			}
		}
	freeifaddrs(ifap);
}

/*
 * See if left->addr or left->next is %defaultroute and change it to IP.
 *
 * Returns:
 * -1: failure
 *  0: done
 *  1: please call again: more to do
 */
static int resolve_defaultroute_one(struct starter_end *host,
				struct starter_end *peer)
{
	/*
	 * "left="         == host->addrtype and host->addr
	 * "leftnexthop="  == host->nexttype and host->nexthop
	 */

	/* What kind of result are we seeking? */
	bool seeking_src = (host->addrtype == KH_DEFAULTROUTE);
	bool seeking_gateway = (host->nexttype == KH_DEFAULTROUTE);

	bool has_peer = (peer->addrtype == KH_IPADDR || peer->addrtype == KH_IPHOSTNAME);

	if (verbose)
		printf("\nseeking_src = %d, seeking_gateway = %d, has_peer = %d\n",
			seeking_src, seeking_gateway, has_peer);

	char msgbuf[RTNL_BUFSIZE];
	bool has_dst = FALSE;
	int query_again = 0;

	if (!seeking_src && !seeking_gateway)
		return 0;	/* this end already figured out */

	/* Fill netlink request */
	netlink_query_init(msgbuf, host->addr_family);
	if (host->nexttype == KH_IPADDR) {
		/*
		 * My nexthop (gateway) is specified.
		 * We need to figure out our source IP to get there.
		 */
		netlink_query_add(msgbuf, RTA_DST, &host->nexthop);
		has_dst = TRUE;
	} else if (has_peer) {
		/*
		 * Peer IP is specified.
		 * We may need to figure out source IP
		 * and gateway IP to get there.
		 */
		if (peer->addrtype == KH_IPHOSTNAME) {
			err_t er = ttoaddr(peer->strings[KSCF_IP], 0,
				AF_UNSPEC, &peer->addr);
			if (er != NULL)
				return -1;
		}

		netlink_query_add(msgbuf, RTA_DST, &peer->addr);
		has_dst = TRUE;
		if (seeking_src && seeking_gateway &&
			host->addr_family == AF_INET) {
			/*
			 * If we have only peer IP and no gateway/src we must
			 * do two queries:
			 * 1) find out gateway for dst
			 * 2) find out src for that gateway
			 * Doing both in one query returns src for dst.
			 *
			 * (IPv6 returns link-local for gateway so we can and
			 * do seek both in one query.)
			 */
			seeking_src = FALSE;
			query_again = 1;
		}
	}
	if (has_dst && host->addrtype == KH_IPADDR) {
		/* SRC works only with DST */
		netlink_query_add(msgbuf, RTA_SRC, &host->addr);
	}

	/*
	 * If we have for example host=%defaultroute + peer=%any
	 * (no destination) the netlink reply will be full routing table.
	 * We must do two queries:
	 * 1) find out default gateway
	 * 2) find out src for that default gateway
	 */
	if (!has_dst && seeking_src && seeking_gateway) {
		seeking_src = FALSE;
		query_again = 1;
	}
	if (seeking_gateway) {
		struct nlmsghdr *nlmsg = (struct nlmsghdr *)msgbuf;

		nlmsg->nlmsg_flags |= NLM_F_DUMP;
	}

	if (verbose)
		printf("seeking_src = %d, seeking_gateway = %d, has_dst = %d\n",
			seeking_src, seeking_gateway, has_dst);

	/* Send netlink get_route request */

	ssize_t len = netlink_query(msgbuf);

	if (len < 0)
		return -1;

	/* Parse reply */
	struct nlmsghdr *nlmsg = (struct nlmsghdr *)msgbuf;

	/*
	 * The cast to unsigned short is to dodge an error in
	 * netlink.h:NLMSG_OK() which triggers a GCC warning in recent
	 * versions of GCC (2014 August):
	 * error: comparison between signed and unsigned integer expressions
	 * Note: as long as RTNL_BUFSIZE <= USHRT_MAX, this is safe.
	 */
	for (; NLMSG_OK(nlmsg, (unsigned short)len); nlmsg = NLMSG_NEXT(nlmsg, len)) {
		char r_interface[IF_NAMESIZE+1];
		char r_source[ADDRTOT_BUF];
		char r_gateway[ADDRTOT_BUF];
		char r_destination[ADDRTOT_BUF];

		if (nlmsg->nlmsg_type == NLMSG_DONE)
			break;

		if (nlmsg->nlmsg_type == NLMSG_ERROR) {
			printf("netlink error\n");
			return -1;
		}

		/* ignore all but IPv4 and IPv6 */
		struct rtmsg *rtmsg = (struct rtmsg *) NLMSG_DATA(nlmsg);

		if (rtmsg->rtm_family != AF_INET &&
			rtmsg->rtm_family != AF_INET6)
			continue;

		/* Parse one route entry */
		zero(&r_interface);
		r_source[0] = r_gateway[0] = r_destination[0] = '\0';

		struct rtattr *rtattr = (struct rtattr *) RTM_RTA(rtmsg);
		int rtlen = RTM_PAYLOAD(nlmsg);

		while (RTA_OK(rtattr, rtlen)) {
			switch (rtattr->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int *)RTA_DATA(rtattr),
					r_interface);
				break;

			case RTA_PREFSRC:
				inet_ntop(rtmsg->rtm_family, RTA_DATA(rtattr),
					r_source, sizeof(r_source));
				break;

			case RTA_GATEWAY:
				inet_ntop(rtmsg->rtm_family, RTA_DATA(rtattr),
					r_gateway, sizeof(r_gateway));
				break;

			case RTA_DST:
				inet_ntop(rtmsg->rtm_family, RTA_DATA(rtattr),
					r_destination,
					sizeof(r_destination));
				break;
			}
			rtattr = RTA_NEXT(rtattr, rtlen);
		}

		/*
		 * Ignore if not main table.
		 * Ignore ipsecX or mastX interfaces.
		 */
		bool ignore = rtmsg->rtm_table != RT_TABLE_MAIN ||
			startswith(r_interface, "ipsec") ||
			startswith(r_interface, "mast");

		if (verbose) {
			printf("dst %s via %s dev %s src %s table %d%s\n",
				r_destination,
				r_gateway,
				r_interface,
				r_source, rtmsg->rtm_table,
				ignore ? " (ignored)" : "");
		}

		if (ignore)
			continue;

		if (seeking_src && r_source[0] != '\0') {
			err_t err = tnatoaddr(r_source, 0, rtmsg->rtm_family,
					&host->addr);

			if (err == NULL) {
				host->addrtype = KH_IPADDR;
				seeking_src = FALSE;
				if (verbose)
					printf("set addr: %s\n", r_source);
			} else if (verbose) {
				printf("unknown source results from kernel (%s): %s\n",
					r_source, err);
			}
		}

		if (seeking_gateway && r_destination[0] == '\0' &&
			(has_dst || r_source[0] == '\0')) {
			if (r_gateway[0] == '\0' && r_interface[0] != '\0') {
				/*
				 * Point-to-Point default gw without "via IP"
				 * Attempt to find r_gateway as the IP address
				 * on the interface.
				 */
				resolve_ppp_peer(r_interface, host->addr_family,
						 r_gateway);
			}
			if (r_gateway[0] != '\0') {
				err_t err = tnatoaddr(r_gateway, 0,
						rtmsg->rtm_family,
						&host->nexthop);

				if (err != NULL) {
					printf("unknown gateway results from kernel: %s\n",
						err);
				} else {
					/* Note: Use first even if multiple */
					host->nexttype = KH_IPADDR;
					seeking_gateway = FALSE;
					if (verbose)
						printf("set nexthop: %s\n",
							r_gateway);
				}
			}
		}
	}
	return query_again;
}

/*
 * See if conn's left or right is %defaultroute and resolve it.
 */
static
void resolve_defaultroute(struct starter_conn *conn)
{
	if (resolve_defaultroute_one(&conn->left, &conn->right) == 1)
		resolve_defaultroute_one(&conn->left, &conn->right);
	if (resolve_defaultroute_one(&conn->right, &conn->left) == 1)
		resolve_defaultroute_one(&conn->right, &conn->left);
}

static const char *usage_string = ""
	"Usage: addconn [--config file] [--rootdir dir] [--ctlbase socketfile]\n"
	"               [--varprefix prefix] [--noexport]\n"
	"               [--verbose]\n"
	"               [--configsetup]\n"
	"               [--liststack]\n"
	"               [--checkconfig]\n"
	"               [--addall] [--autoall]\n"
	"               [--listall] [--listadd] [--listroute] [--liststart]\n"
	"               [--listignore]\n"
	"               names\n";

static void usage(void)
{
	/* print usage */
	fputs(usage_string, stderr);
	exit(10);
}

static const struct option longopts[] =
{
	{ "config", required_argument, NULL, 'C' },
	{ "debug", no_argument, NULL, 'D' },
	{ "verbose", no_argument, NULL, 'D' },
	{ "addall", no_argument, NULL, 'a' },
	{ "autoall", no_argument, NULL, 'a' },
	{ "listall", no_argument, NULL, 'A' },
	{ "listadd", no_argument, NULL, 'L' },
	{ "listroute", no_argument, NULL, 'r' },
	{ "liststart", no_argument, NULL, 's' },
	{ "listignore", no_argument, NULL, 'i' },
	{ "varprefix", required_argument, NULL, 'P' },
	{ "ctlbase", required_argument, NULL, 'c' },
	{ "rootdir", required_argument, NULL, 'R' },
	{ "configsetup", no_argument, NULL, 'T' },
	{ "liststack", no_argument, NULL, 'S' },
	{ "checkconfig", no_argument, NULL, 'K' },
	{ "noexport", no_argument, NULL, 'N' },
	{ "help", no_argument, NULL, 'h' },
	/* obsoleted, eat and ignore for compatibility */
	{"defaultroute", required_argument, NULL, 'd'},
	{"defaultroutenexthop", required_argument, NULL, 'n'},

	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	int opt = 0;
	bool autoall = FALSE;
	int configsetup = 0;
	int checkconfig = 0;
	const char *export = "export"; /* display export before the foo=bar or not */
	bool
		dolist = FALSE,
		listadd = FALSE,
		listroute = FALSE,
		liststart = FALSE,
		listignore = FALSE,
		listall = FALSE,
		liststack = FALSE;
	char *configfile = NULL;
	const char *varprefix = "";
	int exit_status = 0;
	struct starter_conn *conn = NULL;
	const char *ctlbase = NULL;
	bool resolvip = TRUE; /* default to looking up names */

#if 0
	/* efence settings */
	extern int EF_PROTECT_BELOW;
	extern int EF_PROTECT_FREE;

	EF_PROTECT_BELOW = 1;
	EF_PROTECT_FREE = 1;
#endif

	progname = argv[0];
	rootdir[0] = '\0';

	tool_init_log();

	while ((opt = getopt_long(argc, argv, "", longopts, 0)) != EOF) {
		switch (opt) {
		case 'h':
			/* usage: */
			usage();
			break;

		case 'a':
			autoall = TRUE;
			break;

		case 'D':
			verbose++;
			lex_verbosity++;
			break;

		case 'T':
			configsetup++;	/* ??? is this not idempotent? */
			break;

		case 'K':
			checkconfig++;	/* ??? is this not idempotent? */
			break;

		case 'N':
			export = "";
			break;

		case 'C':
			configfile = clone_str(optarg, "config file name");
			break;

		case 'c':
			ctlbase = clone_str(optarg, "control base");
			break;

		case 'L':
			listadd = TRUE;
			dolist = TRUE;
			break;

		case 'r':
			listroute = TRUE;
			dolist = TRUE;
			break;

		case 's':
			liststart = TRUE;
			dolist = TRUE;
			break;

		case 'S':
			liststack = TRUE;
			dolist = TRUE;
			break;

		case 'i':
			listignore = TRUE;
			dolist = TRUE;
			break;

		case 'A':
			listall = TRUE;
			dolist = TRUE;
			break;

		case 'P':
			varprefix = optarg;
			break;

		case 'R':
			printf("setting rootdir=%s\n", optarg);
			jam_str(rootdir, sizeof(rootdir), optarg);
			break;

		case 'd':
		case 'n':
			printf("Warning: options --defaultroute and --defaultroutenexthop are obsolete and were ignored\n");
			break;

		default:
			usage();
		}
	}

	/* if nothing to add, then complain */
	if (optind == argc && !autoall && !dolist && !configsetup &&
		!checkconfig)
		usage();

	if (verbose > 3) {
		yydebug = 1;
	}

	char *confdir = IPSEC_CONFDIR;

	if (configfile == NULL) {
		/* ??? see code clone in programs/readwriteconf/readwriteconf.c */
		configfile = alloc_bytes(strlen(confdir) +
					 sizeof("/ipsec.conf"),
					 "conf file");

		/* calculate default value for configfile */
		strcpy(configfile, confdir);	/* safe: see allocation above */
		if (configfile[0] != '\0' && configfile[strlen(configfile) - 1] != '/')
			strcat(configfile, "/");	/* safe: see allocation above */
		strcat(configfile, "ipsec.conf");	/* safe: see allocation above */
	}

	if (verbose)
		printf("opening file: %s\n", configfile);

	starter_use_log(verbose != 0, TRUE, verbose == 0);

	if (configsetup || checkconfig || dolist) {
		/* skip if we have no use for them... causes delays */
		resolvip = FALSE;
	}

	struct starter_config *cfg = NULL;

	{
		err_t err = NULL;

		cfg = confread_load(configfile, &err, resolvip, ctlbase, configsetup);

		if (cfg == NULL) {
			fprintf(stderr, "cannot load config '%s': %s\n",
				configfile, err);
			exit(3);
		} else if (checkconfig) {
			confread_free(cfg);
			exit(0);
		}
	}

	if (autoall) {
		if (verbose)
			printf("loading all conns according to their auto= settings\n");

		/*
		 * Load all conns marked as auto=add or better.
		 * First, do the auto=route and auto=add conns to quickly
		 * get routes in place, then do auto=start as these can be
		 * slower.
		 * This mimics behaviour of the old _plutoload
		 */
		if (verbose)
			printf("  Pass #1: Loading auto=add, auto=route and auto=start connections\n");

		for (conn = cfg->conns.tqh_first;
			conn != NULL;
			conn = conn->link.tqe_next) {
			if (conn->desired_state == STARTUP_ADD ||
				conn->desired_state == STARTUP_ONDEMAND ||
				conn->desired_state == STARTUP_START) {
				if (verbose)
					printf(" %s", conn->name);
				resolve_defaultroute(conn);
				starter_whack_add_conn(cfg, conn);
			}
		}

		/*
		 * We loaded all connections. Now tell pluto to listen,
		 * then route the conns and resolve default route.
		 */
		starter_whack_listen(cfg);

		if (verbose)
			printf("  Pass #2: Routing auto=route and auto=start connections\n");

		for (conn = cfg->conns.tqh_first;
			conn != NULL;
			conn = conn->link.tqe_next) {
			if (conn->desired_state == STARTUP_ADD ||
				conn->desired_state == STARTUP_ONDEMAND ||
				conn->desired_state == STARTUP_START) {
				if (verbose)
					printf(" %s", conn->name);
				resolve_defaultroute(conn);
				if (conn->desired_state == STARTUP_ONDEMAND ||
				    conn->desired_state == STARTUP_START) {
					starter_whack_route_conn(cfg, conn);
				}
			}
		}

		if (verbose)
			printf("  Pass #3: Initiating auto=start connections\n");

		for (conn = cfg->conns.tqh_first;
			conn != NULL;
			conn = conn->link.tqe_next) {
			if (conn->desired_state == STARTUP_START) {
				if (verbose)
					printf(" %s", conn->name);
				starter_whack_initiate_conn(cfg, conn);
			}
		}

		if (verbose)
			printf("\n");
	} else {
		/* load named conns, regardless of their state */
		int connum;

		if (verbose)
			printf("loading named conns:");
		for (connum = optind; connum < argc; connum++) {
			char *connname = argv[connum];

			if (verbose)
				printf(" %s", connname);
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				if (streq(conn->name, connname)) {
					if (conn->state == STATE_ADDED) {
						printf("\nconn %s already added\n",
							conn->name);
					} else if (conn->state ==
						STATE_FAILED) {
						printf("\nconn %s did not load properly\n",
							conn->name);
					} else {
						resolve_defaultroute(conn);
						exit_status =
							starter_whack_add_conn(
								cfg,
								conn);
						conn->state = STATE_ADDED;
					}
					break;
				}
			}

			if (conn == NULL) {
				/*
				 * only if we don't find it, do we now look
				 * for aliases
				 */
				for (conn = cfg->conns.tqh_first;
					conn != NULL;
					conn = conn->link.tqe_next) {
					if (conn->strings_set[KSCF_CONNALIAS] &&
						lsw_alias_cmp(connname,
							conn->
							strings[KSCF_CONNALIAS]
							)) {
						if (conn->state ==
							STATE_ADDED) {
							printf("\nalias: %s conn %s already added\n",
								connname,
								conn->name);
						} else if (conn->state ==
							STATE_FAILED) {
							printf("\nalias: %s conn %s did not load properly\n",
								connname,
								conn->name);
						} else {
							resolve_defaultroute(
								conn);
							exit_status =
								starter_whack_add_conn(
									cfg,
									conn);
							conn->state =
								STATE_ADDED;
						}
						break;
					}
				}
			}

			if (conn == NULL) {
				exit_status++;
				if (!verbose) {
					printf("conn '%s': not found (tried aliases)\n",
						connname);
				} else {
					printf(" (notfound)\n");
				}
			}
		}
	}

	if (listall) {
		if (verbose)
			printf("listing all conns\n");
		for (conn = cfg->conns.tqh_first;
			conn != NULL;
			conn = conn->link.tqe_next)
			printf("%s ", conn->name);
		printf("\n");
	} else {
		if (listadd) {
			if (verbose)
				printf("listing all conns marked as auto=add\n");

			/* list all conns marked as auto=add */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				if (conn->desired_state == STARTUP_ADD)
					printf("%s ", conn->name);
			}
		}
		if (listroute) {
			if (verbose)
				printf("listing all conns marked as auto=route and auto=start\n");

			/*
			 * list all conns marked as auto=route or start or
			 * better
			 */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				if (conn->desired_state == STARTUP_START ||
					conn->desired_state == STARTUP_ONDEMAND)
					printf("%s ", conn->name);
			}
		}

		if (liststart && !listroute) {
			if (verbose)
				printf("listing all conns marked as auto=start\n");

			/* list all conns marked as auto=start */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				if (conn->desired_state == STARTUP_START)
					printf("%s ", conn->name);
			}
		}

		if (listignore) {
			if (verbose)
				printf("listing all conns marked as auto=ignore\n");

			/* list all conns marked as auto=start */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				if (conn->desired_state == STARTUP_IGNORE)
					printf("%s ", conn->name);
			}
			printf("\n");
		}
	}

	if (liststack) {
		const struct keyword_def *kd;

		for (kd = ipsec_conf_keywords_v2; kd->keyname != NULL; kd++) {
			if (strstr(kd->keyname, "protostack")) {
				if (cfg->setup.strings[kd->field]) {
					printf("%s\n",
						cfg->setup.strings[kd->field]);
				} else {
					/* implicit default */
					printf("netkey\n");
				}
			}
		}
		confread_free(cfg);
		exit(0);
	}

	if (configsetup) {
		const struct keyword_def *kd;

		printf("%s %sconfreadstatus=''\n", export, varprefix);
		for (kd = ipsec_conf_keywords_v2; kd->keyname != NULL; kd++) {
			if ((kd->validity & kv_config) == 0)
				continue;

			switch (kd->type) {
			case kt_string:
			case kt_filename:
			case kt_dirname:
			case kt_loose_enum:
				if (cfg->setup.strings[kd->field]) {
					printf("%s %s%s='%s'\n",
						export, varprefix, kd->keyname,
						cfg->setup.strings[kd->field]);
				}
				break;

			case kt_bool:
				printf("%s %s%s='%s'\n", export, varprefix,
					kd->keyname,
					cfg->setup.options[kd->field] ?
					"yes" : "no");
				break;

			case kt_list:
				printf("%s %s%s='",
					export, varprefix, kd->keyname);
				confwrite_list(stdout, "",
					cfg->setup.options[kd->field],
					kd);
				printf("'\n");
				break;

			case kt_obsolete:
				printf("# obsolete option '%s%s' ignored\n",
					varprefix, kd->keyname);
				break;

			default:
				if (cfg->setup.options[kd->field] ||
					cfg->setup.options_set[kd->field]) {
					printf("%s %s%s='%d'\n",
						export, varprefix, kd->keyname,
						cfg->setup.options[kd->field]);
				}
				break;
			}
		}
		confread_free(cfg);
		exit(0);
	}

	confread_free(cfg);
	exit(exit_status);
}
