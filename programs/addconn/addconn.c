/*
 * A program to read the configuration file and load a single conn
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
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

char *progname;
int verbose=0;
int warningsarefatal = 0;

/* Buffer size for netlink query (~100 bytes) and replies.
 * If DST is specified, reply will be ~100 bytes.
 * If DST is not specified, full route table will be returned.
 * 16kB was too small for biggish router, so do 32kB.
 * TODO: This should be dynamic! Fix it in netlink_read_reply().
 */
#define RTNL_BUFSIZE 32768

/*
 * Initialize netlink query message.
 */
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

int netlink_read_reply(int sock, char *buf, int seqnum, pid_t pid)
{
    struct nlmsghdr *nlhdr;
    int readlen = 0, msglen = 0;

    /* TODO: use dynamic buf */
    do {
	/* Read netlink message */
	readlen = recv(sock, buf, RTNL_BUFSIZE - msglen, 0);
	if (readlen < 0)
	    return -1;

	/* Verify it's valid */
	nlhdr = (struct nlmsghdr *) buf;
	if (NLMSG_OK(nlhdr, readlen) == 0 ||
	    nlhdr->nlmsg_type == NLMSG_ERROR)
	    return -1;

	/* Check if it is the last message */
	if (nlhdr->nlmsg_type == NLMSG_DONE)
	    break;

	/* Not last, move read pointer */
	buf += readlen;
	msglen += readlen;

	/* All done if it's not a multi part */
	if ((nlhdr->nlmsg_flags & NLM_F_MULTI) == 0)
	    break;
    } while (nlhdr->nlmsg_seq != seqnum || nlhdr->nlmsg_pid != pid);
    return msglen;
}

/*
 * Send netlink query message and read reply.
 */
int netlink_query(char *msgbuf)
{
    struct nlmsghdr *nlmsg;
    int sock;

    /* Create socket */
    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
	int e = errno;
	printf("create socket: (%d: %s)", e, strerror(e));
	return -1;
    }

    /* Send request */
    nlmsg = (struct nlmsghdr *)msgbuf;
    if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
	int e = errno;
	printf("write socket: (%d: %s)", e, strerror(e));
	return -1;
    }

    /* Read response */
    int len = netlink_read_reply(sock, msgbuf, 1, getpid());
    if (len < 0) {
	int e = errno;
	printf("read socket: (%d: %s)", e, strerror(e));
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
int resolve_ppp_peer(char *interface, sa_family_t family, char *peer)
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr *sa;

    /* Get info about all interfaces */
    if (getifaddrs(&ifap) != 0)
	return -1;

    /* Find the right interface */
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
	if ((ifa->ifa_flags & IFF_POINTOPOINT) != 0 &&
	    strcmp(ifa->ifa_name, interface) == 0) {
	    sa = ifa->ifa_ifu.ifu_dstaddr;
	    if (sa != NULL && sa->sa_family == family &&
		getnameinfo(sa, ((sa->sa_family == AF_INET) ?
				 sizeof(struct sockaddr_in) :
				 sizeof(struct sockaddr_in6)),
			    peer, NI_MAXHOST, NULL, 0,  NI_NUMERICHOST) == 0) {
		if (verbose)
		    printf("found peer %s to interface %s\n", peer, interface);
		freeifaddrs(ifap);
		return 0;
	    }
	}
    freeifaddrs(ifap);
    return -1;
}

/*
 * See if left->addr or left->next is %defaultroute and change it to IP.
 */
int resolve_defaultroute_one(struct starter_end *left,
			     struct starter_end *right)
{
    /* "left="         == left->addrtype + left->addr
     * "leftnexthop="  == left->nexttype + left->nexthop
     */

    /* What kind of result we want to parse? */
    int parse_src = (left->addrtype == KH_DEFAULTROUTE);
    int parse_gateway = (left->nexttype == KH_DEFAULTROUTE);
    if (parse_src == 0 && parse_gateway == 0)
	return 0;

    /* Fill netlink request */
    char msgbuf[RTNL_BUFSIZE];
    int has_dst = 0;
    netlink_query_init(msgbuf, left->addr_family);
    if (left->nexttype == KH_IPADDR) { /* My nexthop is specified */
	netlink_query_add(msgbuf, RTA_DST, &left->nexthop);
	has_dst = 1;
    } else if (right->addrtype == KH_IPADDR) { /* Peer IP is specified */
	netlink_query_add(msgbuf, RTA_DST, &right->addr);
	has_dst = 1;
    }
    if (has_dst && left->addrtype == KH_IPADDR) /* SRC works only with DST */
	netlink_query_add(msgbuf, RTA_SRC, &left->addr);

    /* If we have for example left=%defaultroute + right=%any, the netlink
     * reply will be full routing table. We just want default gateway for the
     * first run.
     */
    if (has_dst == 0) {
	struct nlmsghdr *nlmsg = (struct nlmsghdr *)msgbuf;
	nlmsg->nlmsg_flags |= NLM_F_DUMP;
        if (parse_gateway)
	    parse_src = 0;
    }
    if (verbose)
	printf("\nparse_src = %d, parse_gateway = %d, has_dst = %d\n",
	       parse_src, parse_gateway, has_dst);

    /* Send netlink get_route request */
    int len = netlink_query(msgbuf);
    if (len < 0)
	return -1;

    /* Parse reply */
    struct nlmsghdr *nlmsg = (struct nlmsghdr *)msgbuf;
    for (; NLMSG_OK(nlmsg, len); nlmsg = NLMSG_NEXT(nlmsg, len)) {
	struct rtmsg *rtmsg;
	struct rtattr *rtattr;
	int rtlen;
	char r_interface[IF_NAMESIZE];
	char r_source[ADDRTOT_BUF];
	char r_gateway[ADDRTOT_BUF];
	char r_destination[ADDRTOT_BUF];

	/* Check for IPv4 / IPv6 */
	rtmsg = (struct rtmsg *) NLMSG_DATA(nlmsg);
	if (rtmsg->rtm_family != AF_INET &&
	    rtmsg->rtm_family != AF_INET6)
	    continue;

	/* Parse one route entry */
	*r_interface = *r_source = *r_gateway = *r_destination = 0;
	rtattr = (struct rtattr *) RTM_RTA(rtmsg);
	rtlen = RTM_PAYLOAD(nlmsg);
	for (; RTA_OK(rtattr, rtlen); rtattr = RTA_NEXT(rtattr, rtlen)) {
	    switch (rtattr->rta_type) {
	    case RTA_OIF:
		if_indextoname(*(int *)RTA_DATA(rtattr), r_interface);
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
			  r_destination, sizeof(r_destination));
		break;
	    }
	}
	if (verbose)
	    printf("dst %s via %s dev %s src %s\n",
		   r_destination, r_gateway, r_interface, r_source);

	err_t err;
	if (parse_src && *r_source != 0) {
	    err = tnatoaddr(r_source, 0, rtmsg->rtm_family, &left->addr);
	    if (err == NULL) {
		left->addrtype = KH_IPADDR;
		parse_src = 0;
		if (verbose)
		    printf("set addr: %s\n", r_source);
	    } else if (verbose)
		printf("unknown source results from kernel: %s\n", err);
	}
	if (parse_gateway && *r_gateway == 0 && *r_interface != 0 &&
	    (has_dst || *r_source == 0)) {
	    /* Point-to-Point default gw without "via IP" */
	    resolve_ppp_peer(r_interface, left->addr_family, r_gateway);
	}
	if (parse_gateway && *r_gateway != 0 && (has_dst || *r_source == 0)) {
	    err = tnatoaddr(r_gateway, 0, rtmsg->rtm_family, &left->nexthop);
	    if (err == NULL) {
		left->nexttype = KH_IPADDR;
		parse_gateway = 0; /* Use first if multiple */
		if (verbose)
		    printf("set nexthop: %s\n", r_gateway);
	    } else if (verbose)
		printf("unknown gateway results from kernel: %s\n", err);
	}
    }

    /* If we parsed and found default_gateway, we must do the request again
     * to find out the source IP for that gateway.
     */
    return has_dst == 0 && parse_gateway == 0;
}

/*
 * See if conn's left or right is %defaultroute and resolve it.
 */
void resolve_defaultroute(struct starter_conn *conn)
{
    if (resolve_defaultroute_one(&conn->left, &conn->right) == 1)
	resolve_defaultroute_one(&conn->left, &conn->right);
    if (resolve_defaultroute_one(&conn->right, &conn->left) == 1)
	resolve_defaultroute_one(&conn->right, &conn->left);
}

static const char *usage_string = ""
    "Usage: addconn [--config file] [--rootdir dir] [--ctlbase socketfile] \n"
    "               [--varprefix prefix] [--noexport] \n"
    "               [--verbose] [--warningsfatal] \n"
    "               [--configsetup] \n"
    "               [--liststack] \n"
    "               [--checkconfig] \n"
    "               [--addall] [--autoall] \n"
    "               [--listall] [--listadd] [--listroute] [--liststart] [--listignore] \n"
    "               [--listall] [--listadd] [--listroute] [--liststart] [--listignore] \n"
    "               names\n";


static void usage(void)
{
    /* print usage */
    fputs(usage_string, stderr);
    exit(10);
}

extern char rootdir[PATH_MAX];       /* when evaluating paths, prefix this to them */

static struct option const longopts[] =
{
	{"config",              required_argument, NULL, 'C'},
	{"debug",               no_argument, NULL, 'D'},
	{"verbose",             no_argument, NULL, 'D'},
	{"warningsfatal",       no_argument, NULL, 'W'},
	{"addall",              no_argument, NULL, 'a'},
	{"autoall",             no_argument, NULL, 'a'},
	{"listall",             no_argument, NULL, 'A'},
	{"listadd",             no_argument, NULL, 'L'},
	{"listroute",           no_argument, NULL, 'r'},
	{"liststart",           no_argument, NULL, 's'},
	{"listignore",          no_argument, NULL, 'i'},
	{"varprefix",           required_argument, NULL, 'P'},
	{ "ctlbase",            required_argument, NULL, 'c' },
	{"rootdir",             required_argument, NULL, 'R'},
	{"configsetup",         no_argument, NULL, 'T'},
	{"liststack",           no_argument, NULL, 'S'},
	{"checkconfig",		no_argument, NULL, 'K'},
	{"noexport",		no_argument, NULL, 'N'},
	{"help",                no_argument, NULL, 'h'},
	{0, 0, 0, 0}
};



int
main(int argc, char *argv[])
{
    int opt = 0;
    int autoall = 0;
    int configsetup = 0;
    int checkconfig = 0;
    char *export ="export"; /* display export before the foo=bar or not */
    int listroute=0, liststart=0, listignore=0, listadd=0, listall=0, dolist=0,liststack=0;
    struct starter_config *cfg = NULL;
    err_t err = NULL;
    char *confdir = NULL;
    char *configfile = NULL;
    char *varprefix = "";
    int exit_status = 0;
    struct starter_conn *conn = NULL;
    char *ctlbase = NULL;
    bool resolvip = TRUE;  /* default to looking up names */

#if 0
    /* efence settings */
    extern int EF_PROTECT_BELOW;
    extern int EF_PROTECT_FREE;

    EF_PROTECT_BELOW=1;
    EF_PROTECT_FREE=1;
#endif


    progname = argv[0];
    rootdir[0]='\0';

    tool_init_log();

    while((opt = getopt_long(argc, argv, "", longopts, 0)) != EOF) {
	switch(opt) {
	case 'h':
	    /* usage: */
	    usage();
	    break;

	case 'a':
	    autoall=1;
	    break;

	case 'D':
	    verbose++;
	    break;

	case 'W':
	    warningsarefatal++;
	    break;

	case 'T':
	    configsetup++;
	    break;

	case 'K':
	    checkconfig++;
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
	    listadd=1;
	    dolist=1;
	    break;

	case 'r':
	    listroute=1;
	    dolist=1;
	    break;

	case 's':
	    liststart=1;
	    dolist=1;
	    break;

	case 'S':
	    liststack=1;
	    dolist=1;
	    break;

	case 'i':
	    listignore=1;
	    dolist=1;
	    break;

	case 'A':
	    listall=1;
	    dolist=1;
	    break;

	case 'P':
	    varprefix=optarg;
	    break;

	case 'R':
	    printf("setting rootdir=%s\n", optarg);
	    strncat(rootdir, optarg, sizeof(rootdir)-1);
	    break;

	default:
	    usage();
	}
    }

    /* if nothing to add, then complain */
    if(optind == argc && !autoall && !dolist && !configsetup && !checkconfig) {
	usage();
    }

    if(verbose > 3) {
	extern int yydebug;
	yydebug=1;
    }

    /* find config file */
    if(confdir == NULL)
    {
	confdir = IPSEC_CONFDIR;
    }

    if(!configfile) {
	configfile = alloc_bytes(strlen(IPSEC_CONF)+2,"conf file");

	/* calculate default value for configfile */
	configfile[0]='\0';
	strcpy(configfile, confdir);
	if(configfile[strlen(configfile)-1]!='/')
	{
	    strcat(configfile, "/");
	}
	strcat(configfile, "ipsec.conf");
    }

    if(verbose) {
	printf("opening file: %s\n", configfile);
    }

    starter_use_log (verbose, 1, verbose ? 0 : 1);

    err = NULL;      /* reset to no error */

    if(configsetup || checkconfig || dolist) {
	/* skip if we have no use for them... causes delays */
	resolvip=FALSE;
    }

    cfg = confread_load(configfile, &err, resolvip, ctlbase,configsetup);

    if(cfg == NULL) {
	fprintf(stderr, "can not load config '%s': %s\n",
		configfile, err);
	exit(3);
    }
    else if(checkconfig) {
	confread_free(cfg);
	exit(0);
    }

    if(autoall)
    {
	if(verbose) {
	    printf("loading all conns according to their auto= settings\n");
	}
	/*
	 * Load all conns marked as auto=add or better
	 * First, do the auto=route and auto=add conns to quickly get routes in
	 * place, then do auto=start as these can be slower. This mimics behaviour
	 * of the old _plutoload
	 */
	if(verbose) printf("  Pass #1: Loading auto=add, auto=route and auto=start connections\n");
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_ADD ||
		conn->desired_state == STARTUP_ROUTE ||
		conn->desired_state == STARTUP_START) {
		if(verbose) printf(" %s", conn->name);
		   resolve_defaultroute(conn);
		   starter_whack_add_conn(cfg, conn);
	    }
	    if (conn->desired_state == STARTUP_ROUTE) {
		starter_whack_route_conn(cfg,conn);
	    }
	}
	if(verbose) printf("  Pass #2: Initiating auto=start connections\n");
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_START) {
		if(verbose) printf(" %s", conn->name);
		   resolve_defaultroute(conn);
		   starter_whack_initiate_conn(cfg,conn);
	    }
	}
	if(verbose) printf("\n");

    } else {
	/* load named conns, regardless of their state */
	int   connum;

	if(verbose) {
	    printf("loading named conns:");
	}
	for(connum = optind; connum<argc; connum++) {
	    char *connname = argv[connum];

	    if(verbose) {
		printf(" %s", connname);
	    }
	    for(conn = cfg->conns.tqh_first;
		conn != NULL;
		conn = conn->link.tqe_next)
	    {
		if(strcmp(conn->name, connname)==0) {
		    if(conn->state == STATE_ADDED) {
			printf("\nconn %s already added\n", conn->name);
		    } else if(conn->state == STATE_FAILED) {
			printf("\nconn %s did not load properly\n", conn->name);
		    } else {
			resolve_defaultroute(conn);
			exit_status = starter_whack_add_conn(cfg, conn);
			conn->state = STATE_ADDED;
		    }
		    break;
		}
	    }

	    if(conn == NULL) {
		/* only if we don't find it, do we now look for aliases */

		for(conn = cfg->conns.tqh_first;
		    conn != NULL;
		    conn = conn->link.tqe_next)
		{
		    if(conn->strings_set[KSF_CONNALIAS]
		       && lsw_alias_cmp(connname
					, conn->strings[KSF_CONNALIAS])) {

			if(conn->state == STATE_ADDED) {
			    printf("\nalias: %s conn %s already added\n", connname, conn->name);
			} else if(conn->state == STATE_FAILED) {
			    printf("\nalias: %s conn %s did not load properly\n", connname, conn->name);
			} else {
			    resolve_defaultroute(conn);
			    exit_status = starter_whack_add_conn(cfg, conn);
			    conn->state = STATE_ADDED;
			}
			break;
		    }
		}
	    }

	    if(conn == NULL) {
		exit_status++;
		if(!verbose) {
		    printf("conn '%s': not found (tried aliases)\n", connname);
		} else {
		    printf(" (notfound)\n");
		}
	    }
	}
    }

     if(listall) {
	if(verbose) {
	    printf("listing all conns\n");
	}
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
 	    printf("%s ", conn->name);
	}
	printf("\n");
    } else {

      if(listadd) {
	if(verbose) {
	    printf("listing all conns marked as auto=add\n");
	}
	/* list all conns marked as auto=add */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_ADD) {
		printf("%s ", conn->name);
	    }
	}
      }
       if(listroute) {
	if(verbose) {
	    printf("listing all conns marked as auto=route and auto=start\n");
	}
	/* list all conns marked as auto=route or start or better */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_START
		|| conn->desired_state == STARTUP_ROUTE) {
		printf("%s ", conn->name);
	    }
	}
      }

       if(liststart && !listroute) {
	if(verbose) {
	    printf("listing all conns marked as auto=start\n");
	}
	/* list all conns marked as auto=start */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_START) {
		printf("%s ", conn->name);
	    }
	}
      }

       if(listignore) {
	if(verbose) {
	    printf("listing all conns marked as auto=ignore\n");
	}
	/* list all conns marked as auto=start */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_IGNORE) {
		printf("%s ", conn->name);
	    }
	}
       printf("\n");
       }
      }

    if(liststack) {
        struct keyword_def *kd;
	for(kd=ipsec_conf_keywords_v2; kd->keyname != NULL; kd++) {
	    if(strstr(kd->keyname,"protostack")) {
		if (cfg->setup.strings[kd->field]) {
			printf("%s\n", cfg->setup.strings[kd->field]);
		} else {
			printf("netkey\n"); /* implicit default */
		}
	    }

	}
	confread_free(cfg);
	exit(0);
    }

    if(configsetup) {
        struct keyword_def *kd;

	printf("%s %sconfreadstatus=''\n", export, varprefix);
	for(kd=ipsec_conf_keywords_v2; kd->keyname != NULL; kd++) {
	    if((kd->validity & kv_config)==0) continue;

	    switch(kd->type) {
	    case kt_string:
	    case kt_filename:
	    case kt_dirname:
	    case kt_loose_enum:
		if(cfg->setup.strings[kd->field]) {
		    printf("%s %s%s='%s'\n",
			   export, varprefix, kd->keyname,
			   cfg->setup.strings[kd->field]);
		}
		break;

	    case kt_bool:
		printf("%s %s%s='%s'\n", export, varprefix, kd->keyname,
		       cfg->setup.options[kd->field] ? "yes" : "no");
		break;

	    case kt_list:
		   printf("%s %s%s='",
		       export, varprefix, kd->keyname);
		   confwrite_list(stdout, "", cfg->setup.options[kd->field], kd);
		   printf("'\n");
		break;

	    case kt_obsolete:
		printf("# obsolete option '%s%s' ignored\n", varprefix, kd->keyname);
		break;

	    default:
		if(cfg->setup.options[kd->field] || cfg->setup.options_set[kd->field]) {
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

void exit_tool(int x)
{
  exit(x);
}

/*
 *
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 *
 */
