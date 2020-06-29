/*
 * addr_lookup: resolve_defaultroute_one() -- attempt to resolve a default route
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Kim B. Heino <b@bbbs.net>
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <net/if.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "constants.h"
#include "lswalloc.h"
#include "ipsecconf/confread.h"
#include "kernel_netlink_reply.h"
#include "addr_lookup.h"
#ifdef USE_DNSSEC
# include "dnssec.h"
#else
# include <netdb.h>
#endif
#include "ip_info.h"

static void resolve_point_to_point_peer(const char *interface,
					const struct ip_info *family,
					char *peer/*[ADDRTOT_BUF]*/,	/* result, if any */
					bool verbose)
{
	struct ifaddrs *ifap;

	/* Get info about all interfaces */
	if (getifaddrs(&ifap) != 0)
		return;

	/* Find the right interface, if any */
	for (const struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if ((ifa->ifa_flags & IFF_POINTOPOINT) != 0 &&
			streq(ifa->ifa_name, interface)) {
			struct sockaddr *sa = ifa->ifa_ifu.ifu_dstaddr;

			if (sa != NULL && sa->sa_family == family->af &&
				getnameinfo(sa,
					sa->sa_family == AF_INET ?
						sizeof(struct sockaddr_in) :
						sizeof(struct sockaddr_in6),
					peer, ADDRTOT_BUF,
					NULL, 0,
					NI_NUMERICHOST) == 0) {
				if (verbose) {
					printf("found peer %s to interface %s\n",
						peer,
						interface);
				}
				break;
			}
			/* in case failing getnameinfo set peer */
			*peer = '\0';
		}
	}
	freeifaddrs(ifap);
}

/*
 * Buffer size for netlink query (~100 bytes) and replies.
 * More memory will be allocated dynamically when needed for replies.
 * If DST is specified, reply will be ~100 bytes.
 * If DST is not specified, full route table will be returned.
 * On 64bit systems 100 route entries requires about 6KiB.
 *
 * When reading data from netlink the final packet in each recvfrom()
 * will be truncated if it doesn't fit to buffer. Netlink returns up
 * to 16KiB of data so always keep that much free.
 */
#define RTNL_BUFSIZE (NL_BUFMARGIN + 8192)

/*
 * Initialize netlink query message.
 */
static void netlink_query_init(char *msgbuf, sa_family_t family)
{
	struct nlmsghdr *nlmsg;
	struct rtmsg *rtmsg;

	/* Create request for route */
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
static void netlink_query_add(char *msgbuf, int rta_type, const ip_address *addr)
{
	struct nlmsghdr *nlmsg;
	struct rtmsg *rtmsg;
	struct rtattr *rtattr;
	int rtlen;

	nlmsg = (struct nlmsghdr *)msgbuf;
	rtmsg = (struct rtmsg *)NLMSG_DATA(nlmsg);

	/* Find first empty attribute slot */
	rtlen = RTM_PAYLOAD(nlmsg);
	rtattr = (struct rtattr *)RTM_RTA(rtmsg);
	while (RTA_OK(rtattr, rtlen))
		rtattr = RTA_NEXT(rtattr, rtlen);

	/* Add attribute */
	shunk_t bytes = address_as_shunk(addr);
	rtattr->rta_type = rta_type;
	rtattr->rta_len = sizeof(struct rtattr) + bytes.len; /* bytes */
	memmove(RTA_DATA(rtattr), bytes.ptr, bytes.len);
	if (rta_type == RTA_SRC)
		rtmsg->rtm_src_len = bytes.len * 8; /* bits */
	else
		rtmsg->rtm_dst_len = bytes.len * 8;
	nlmsg->nlmsg_len += rtattr->rta_len;
}

/*
 * Send netlink query message and read reply.
 */
static ssize_t netlink_query(char **pmsgbuf, size_t bufsize)
{
	int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

	if (sock < 0) {
		int e = errno;

		printf("create netlink socket failure: (%d: %s)\n", e, strerror(e));
		return -1;
	}

	/* Send request */
	struct nlmsghdr *nlmsg = (struct nlmsghdr *)*pmsgbuf;

	if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
		int e = errno;

		printf("write netlink socket failure: (%d: %s)\n", e, strerror(e));
		close(sock);
		return -1;
	}

	/* Read response */
	errno = 0;	/* in case failure does not set it */
	ssize_t len = netlink_read_reply(sock, pmsgbuf, bufsize, 1, getpid());

	if (len < 0)
		printf("read netlink socket failure: (%d: %s)\n",
			errno, strerror(errno));

	close(sock);
	return len;
}

/*
 * See if left->addr or left->next is %defaultroute and change it to IP.
 *
 * Returns:
 * -1: failure
 *  0: success
 *  1: please call again: more to do
 */
int resolve_defaultroute_one(struct starter_end *host,
				struct starter_end *peer, bool verbose)
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
	if (!seeking_src && !seeking_gateway)
		return 0;	/* this end already figured out */

	/* msgbuf is dynamically allocated since the buffer may need to be grown */
	char *msgbuf = alloc_bytes(RTNL_BUFSIZE, "netlink query");

	bool has_dst = FALSE;
	int query_again = 0;

	/* Fill netlink request */
	netlink_query_init(msgbuf, host->host_family->af);
	if (host->nexttype == KH_IPADDR && peer->host_family == &ipv4_info) {
		/*
		 * My nexthop (gateway) is specified.
		 * We need to figure out our source IP to get there.
		 */

		/*
		 * AA_2019 Why use nexthop and not peer->addr to look up src address
		 * the lore is there is (old) bug when looking up IPv4 src
		 * IPv6 with gateway link local address will return link local
		 * address and not the global address
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
#ifdef USE_DNSSEC
			err_t er = ttoaddr_num(peer->strings[KSCF_IP], 0,
				AF_UNSPEC, &peer->addr);
			if (er != NULL) {
				/* not numeric, so resolve it */
				if (!unbound_resolve(peer->strings[KSCF_IP],
							0, AF_INET,
							&peer->addr)) {
					if (!unbound_resolve(
							peer->strings[KSCF_IP],
							0, AF_INET6,
							&peer->addr)) {
						pfree(msgbuf);
						return -1;
					}
				}
			}
#else
			err_t er = ttoaddr(peer->strings[KSCF_IP], 0,
				AF_UNSPEC, &peer->addr);
			if (er != NULL) {
				pfree(msgbuf);
				return -1;
			}
#endif
		}

		netlink_query_add(msgbuf, RTA_DST, &peer->addr);
		has_dst = TRUE;
		if (seeking_src && seeking_gateway) {
			/*
			 * If we have only peer IP and no gateway/src we must
			 * do two queries:
			 * 1) find out gateway for dst
			 * 2) find out src for that gateway
			 * Doing both in one query returns src for dst.
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
	ssize_t len = netlink_query(&msgbuf, RTNL_BUFSIZE);

	if (len < 0) {
		pfree(msgbuf);
		return -1;
	}

	/* Parse reply */
	struct nlmsghdr *nlmsg = (struct nlmsghdr *)msgbuf;

	for (; NLMSG_OK(nlmsg, (size_t)len); nlmsg = NLMSG_NEXT(nlmsg, len)) {
		char r_interface[IF_NAMESIZE+1];
		char r_source[ADDRTOT_BUF];
		char r_gateway[ADDRTOT_BUF];
		char r_destination[ADDRTOT_BUF];

		if (nlmsg->nlmsg_type == NLMSG_DONE)
			break;

		if (nlmsg->nlmsg_type == NLMSG_ERROR) {
			printf("netlink error\n");
			pfree(msgbuf);
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

		if (seeking_gateway && r_destination[0] == '\0') {
			if (r_gateway[0] == '\0' && r_interface[0] != '\0') {
				/*
				 * Point-to-Point default gw without "via IP"
				 * Attempt to find r_gateway as the IP address
				 * on the interface.
				 */
				resolve_point_to_point_peer(r_interface, host->host_family,
							    r_gateway, verbose);
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
	pfree(msgbuf);
	return query_again;
}
