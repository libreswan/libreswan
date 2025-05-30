/*
 * addr_lookup: resolve_defaultroute_one() -- attempt to resolve a default route
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2021 Andrew Cagney
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

#include <linux/version.h>	/* RTA_UID hack */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <net/if.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>

#include "lsw_socket.h"

#include "constants.h"
#include "lswalloc.h"
#include "ipsecconf/confread.h"
#include "linux_netlink.h"
#include "addr_lookup.h"
#ifdef USE_DNSSEC
# include "dnssec.h"
#endif

#include "ip_info.h"
#include "lswlog.h"

static void resolve_point_to_point_peer(const char *interface,
					const struct ip_info *afi,
					ip_address *peer,
					struct verbose verbose)
{
	struct ifaddrs *ifap;

	/* Get info about all interfaces */
	if (getifaddrs(&ifap) != 0)
		return;

	/* Find the right interface, if any */
	for (const struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if ((ifa->ifa_flags & IFF_POINTOPOINT) == 0) {
			continue;
		}

		if (!streq(ifa->ifa_name, interface)) {
			continue;
		}

		struct sockaddr *sa = ifa->ifa_ifu.ifu_dstaddr;
		if (sa == NULL || sa->sa_family != afi->af) {
			continue;
		}

		err_t err = sockaddr_to_address_port(sa, afi->sockaddr_size,
						     peer, NULL/*ignore port*/);
		if (err != NULL) {
			verbose("interface %s had invalid sockaddr: %s",
				interface, err);
			continue;
		}

		address_buf ab;
		verbose("found peer %s to interface %s",
			str_address(peer, &ab), interface);
		break;
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
#define RTNL_BUFSIZE (LINUX_NETLINK_BUFSIZE + 8192)

/*
 * Initialize netlink query message.
 */

static struct nlmsghdr *netlink_query_init(const struct ip_info *afi,
					   char type, int flags,
					   struct verbose verbose)
{
	struct nlmsghdr *nlmsg = alloc_bytes(RTNL_BUFSIZE, "netlink query netlink_query_init()");
	struct rtmsg *rtmsg;

	nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlmsg->nlmsg_flags = flags;
	nlmsg->nlmsg_type = type;
	nlmsg->nlmsg_seq = 1;
	nlmsg->nlmsg_pid = getpid();

	rtmsg = (struct rtmsg *)NLMSG_DATA(nlmsg);
	rtmsg->rtm_family = afi->af;
	rtmsg->rtm_table = 0; /* RT_TABLE_MAIN doesn't seem to do much */
	rtmsg->rtm_protocol = 0;
	rtmsg->rtm_scope = 0;
	rtmsg->rtm_type = 0;
	rtmsg->rtm_src_len = 0;
	rtmsg->rtm_dst_len = 0;
	rtmsg->rtm_tos = 0;

	verbose("query %s%s%s%s",
		(type == RTM_GETROUTE ? "GETROUTE" : "?"),
		(flags & NLM_F_REQUEST ? "+REQUEST" : ""),
		/*NLM_F_DUMP==NLM_F_ROOT|NLM_F_MATCH*/
		(flags & NLM_F_ROOT ? "+ROOT" : ""),
		(flags & NLM_F_MATCH ? "+MATCH" : ""));

	return nlmsg;
}

/*
 * Add RTA_SRC or RTA_DST attribute to netlink query message.
 */
static void netlink_query_add(struct nlmsghdr *nlmsg, int rta_type,
			      const ip_address *addr, const char *what,
			      struct verbose verbose)
{
	struct rtmsg *rtmsg;
	struct rtattr *rtattr;
	int rtlen;

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

	address_buf ab;
	verbose("add RTA_%s %s (%s)",
		(rta_type == RTA_DST ? "DST" :
		 rta_type == RTA_GATEWAY ? "GATEWAY" :
		 rta_type == RTA_SRC ? "SRC" :
		 rta_type == RTA_PREFSRC ? "PREFSRC" :
		 "???"),
		str_address(addr, &ab), what);
}

/*
 * See if left->addr or left->next is %defaultroute and change it to IP.
 */

static const char *pa(const struct resolve_host *host, address_buf *buf)
{
	switch (host->type) {
	case KH_NOTSET: return "<not-set>";
	case KH_DEFAULTROUTE: return "<defaultroute>";
	case KH_ANY: return "<any>";
	case KH_IFACE: return host->name;
	case KH_OPPO: return "<oppo>";
	case KH_OPPOGROUP: return "<oppogroup>";
	case KH_GROUP: return "<group>";
	case KH_IPHOSTNAME: return host->name;
	case KH_IPADDR: return str_address(&host->addr, buf);
	default: return "<other>";
	}
}

enum resolve_status {
	RESOLVE_FAILURE = -1,
	RESOLVE_SUCCESS = 0,
	RESOLVE_PLEASE_CALL_AGAIN = 1,
};

struct linux_netlink_context {
	enum resolve_status status;
	const struct ip_info *host_afi;
	enum seeking { NOTHING, PREFSRC, GATEWAY, } seeking;
	struct resolve_end *host;
	struct resolve_end *peer;
};

static bool process_netlink_route(struct nlmsghdr *nlmsg,
				  struct linux_netlink_context *context,
				  struct verbose verbose)
{
	const struct ip_info *const host_afi = context->host_afi;
	if (context->status == RESOLVE_FAILURE) {

		if (PBAD(verbose.logger, nlmsg->nlmsg_type == NLMSG_DONE)) {
			return false;
		}

		if (PBAD(verbose.logger, nlmsg->nlmsg_type == NLMSG_ERROR)) {
			context->status = RESOLVE_FAILURE;
			return false;
		}

		/* ignore all but IPv4 and IPv6 */
		struct rtmsg *rtmsg = (struct rtmsg *) NLMSG_DATA(nlmsg);
		if (rtmsg->rtm_family != host_afi->af) {
			verbose("wrong family");
			return true;
		}

		/* Parse one route entry */

		char r_interface[IF_NAMESIZE+1];
		zero(&r_interface);
		ip_address src = unset_address;
		ip_address prefsrc = unset_address;
		ip_address gateway = unset_address;
		ip_address dst = unset_address;
		int priority = -1;
		signed char pref = -1;
		int table;
		const char *cacheinfo = "";
		const char *uid = "";

		struct rtattr *rtattr = (struct rtattr *) RTM_RTA(rtmsg);
		int rtlen = RTM_PAYLOAD(nlmsg);

		verbose("parsing route entry (RTA payloads)");
		verbose.level++;

		while (RTA_OK(rtattr, rtlen)) {
			const void *data = RTA_DATA(rtattr);
			unsigned len = RTA_PAYLOAD(rtattr);
			switch (rtattr->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int *)RTA_DATA(rtattr),
					       r_interface);
				break;
			case RTA_PREFSRC:
#define PARSE_ADDRESS(OUT, WHAT)					\
				{					\
					diag_t diag =			\
						data_to_address(data, len, \
								host_afi, OUT); \
					if (diag != NULL) {		\
						verbose("invalid RTA_%s from kernel: %s", \
							WHAT, str_diag(diag)); \
						pfree_diag(&diag);	\
					} else {			\
						address_buf ab;		\
						verbose("RTA_%s=%s",	\
							WHAT, str_address(OUT, &ab)); \
					}				\
				}
				PARSE_ADDRESS(&prefsrc, "PREFSRC");
				break;
			case RTA_GATEWAY:
				PARSE_ADDRESS(&gateway, "GATEWAY");
				break;
			case RTA_DST:
				PARSE_ADDRESS(&dst, "DST");
				break;
			case RTA_SRC:
				PARSE_ADDRESS(&src, "SRC");
				break;
#undef PARSE_ADDRESS
			case RTA_PRIORITY:
#define PARSE_NUMBER(OUT, WHAT)						\
				{					\
					if (len != sizeof(OUT)) {	\
						verbose("ignoring RTA_%s with wrong size %d", WHAT, len); \
					} else {			\
						memcpy(&OUT, data, len); \
						verbose("RTA_%s=%d", WHAT, OUT); \
					}				\
				}
				PARSE_NUMBER(priority, "PRIORITY");
				break;
			case RTA_PREF:
				PARSE_NUMBER(pref, "PREF");
				break;
			case RTA_TABLE:
				PARSE_NUMBER(table, "TABLE");
				break;
#undef PARSE_NUMBER
			case RTA_CACHEINFO:
				cacheinfo = " +cacheinfo";
				break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,16)
			case RTA_UID:
				/*
				 * XXX: Above kernel version matches
				 * when this code was added to this
				 * file and not when RTA_UID was added
				 * to the kernel herders.  That was:
				 *
				 *  commit 4fb74506838b3e34eaaebfcf90ebcd1fd52ab813
				 *  Merge: 0d53072aa42b e2d118a1cb5e
				 *  Author: David S. Miller <davem@davemloft.net>
				 *  Date:   Fri Nov 4 14:45:24 2016 -0400
				 *
				 *    Merge branch 'uid-routing'
				 *
				 * but who knows what that kernel
				 * version was.
				 *
				 * A sane kernel would include:
				 *
				 *   #define RTA_UID RTA_UID
				 *
				 * when adding the enum so that:
				 *
				 *   #ifdef RTA_ID
				 *
				 * could do the right thing.  Sigh.
				 */
				uid = " +uid";
				break;
#endif
			default:
				verbose("ignoring RTA type %d", rtattr->rta_type);
			}
			rtattr = RTA_NEXT(rtattr, rtlen);
		}

		/*
		 * Ignore if not main table.
		 * Ignore ipsecX or mastX interfaces.
		 *
		 * XXX: instead of rtm_table, should this be checking
		 * TABLE?
		 */
		address_buf sb, psb, db, gb;
		verbose("using src=%s prefsrc=%s gateway=%s dst=%s dev='%s' priority=%d pref=%d table=%d%s%s",
			str_address(&src, &sb),
			str_address(&prefsrc, &psb),
			str_address(&gateway, &gb),
			str_address(&dst, &db),
			(r_interface[0] ? r_interface : "?"),
			priority, pref,
			rtmsg->rtm_table,
			cacheinfo, uid);

		if (rtmsg->rtm_table != RT_TABLE_MAIN) {
			verbose("IGNORE: table %d is not main(%d)",
				rtmsg->rtm_table, RT_TABLE_MAIN);
			return true;
		}

		if (startswith(r_interface, "ipsec") ||
		    startswith(r_interface, "mast")) {
			verbose("IGNORE: interface %s", r_interface);
			return true;
		}

		switch (context->seeking) {
		case PREFSRC:
			if (!address_is_unset(&prefsrc)) {
				context->status = RESOLVE_SUCCESS;
				context->host->host.type = KH_IPADDR;
				context->host->host.addr = prefsrc;
				address_buf ab;
				verbose("found prefsrc(host_addr): %s",
					str_address(&context->host->host.addr, &ab));
			}
			break;
		case GATEWAY:
			if (address_is_unset(&dst)) {
				if (address_is_unset(&gateway) && r_interface[0] != '\0') {
					/*
					 * Point-to-Point default gw without
					 * "via IP".  Attempt to find gateway
					 * as the IP address on the interface.
					 */
					resolve_point_to_point_peer(r_interface,
								    context->host_afi,
								    &gateway, verbose);
				}
				if (!address_is_unset(&gateway)) {
					/*
					 * Note: Use first even if
					 * multiple.
					 *
					 * XXX: assume a gateway
					 * always requires a second
					 * call to get PREFSRC, code
					 * above will quickly return
					 * when it isn't.
					 */
					context->status = RESOLVE_PLEASE_CALL_AGAIN;
					context->host->nexthop.type = KH_IPADDR;
					context->host->nexthop.addr = gateway;
					address_buf ab;
					verbose("found gateway(host_nexthop): %s",
						str_address(&context->host->nexthop.addr, &ab));
				}
			}
			break;
		default:
			bad_case(context->seeking);
		}
	}
	return true;
}

static enum resolve_status resolve_defaultroute_one(struct resolve_end *host,
						    struct resolve_end *peer,
						    const struct ip_info *host_afi,
						    struct verbose verbose)
{
	/*
	 * "left="         == host->host.type and host->host.addr
	 * "leftnexthop="  == host->nexthop.type and host->nexthop.addr
	 */

	address_buf hb, gb, pb;
	verbose("resolving family=%s src=%s gateway=%s peer %s",
		(host_afi == NULL ? "<unset>" : host_afi->ip_name),
		pa(&host->host, &hb),
		pa(&host->nexthop, &gb),
		pa(&peer->host, &pb));
	verbose.level++;

	/*
	 * Can only resolve one at a time.
	 *
	 * XXX: OLD comments:
	 *
	 * If we have for example host=%defaultroute + peer=%any
	 * (no destination) the netlink reply will be full routing table.
	 * We must do two queries:
	 * 1) find out default gateway
	 * 2) find out src for that default gateway
	 *
	 * If we have only peer IP and no gateway/src we must
	 * do two queries:
	 * 1) find out gateway for dst
	 * 2) find out src for that gateway
	 * Doing both in one query returns src for dst.
	 */
	enum seeking seeking = (host->nexthop.type == KH_DEFAULTROUTE ? GATEWAY :
				host->host.type == KH_DEFAULTROUTE ? PREFSRC :
				NOTHING);
	verbose("seeking %s", (seeking == NOTHING ? "NOTHING" :
			    seeking == PREFSRC ? "PREFSRC" :
			    seeking == GATEWAY ? "GATEWAY" :
			    "?"));
	verbose.level++;
	if (seeking == NOTHING) {
		return RESOLVE_SUCCESS;	/* this end already figured out */
	}

	/*
	 * msgbuf is dynamically allocated since the buffer may need
	 * to be grown.
	 */
	struct nlmsghdr *msgbuf =
		netlink_query_init(host_afi, /*type*/RTM_GETROUTE,
				   (/*flags*/NLM_F_REQUEST |
				    (seeking == GATEWAY ? NLM_F_DUMP : 0)),
				   verbose);

	/*
	 * If known, add a destination address.  Either the peer, or
	 * the gateway.
	 */

	const bool has_peer = (peer->host.type == KH_IPADDR || peer->host.type == KH_IPHOSTNAME);
	bool added_dst;
	if (host->nexthop.type == KH_IPADDR && host_afi == &ipv4_info) {
		pexpect(seeking == PREFSRC);
		/*
		 * My nexthop (gateway) is specified.
		 * We need to figure out our source IP to get there.
		 */

		/*
		 * AA_2019 Why use nexthop and not peer->host.addr to look up src address?
		 * The lore is that there is an (old) bug when looking up IPv4 src
		 * IPv6 with gateway link local address will return link local
		 * address and not the global address.
		 */
		added_dst = true;
		netlink_query_add(msgbuf, RTA_DST, &host->nexthop.addr,
				  "host->nexthop.addr", verbose);
	} else if (has_peer) {
		/*
		 * Peer IP is specified.
		 * We may need to figure out source IP
		 * and gateway IP to get there.
		 *
		 * XXX: should this also update peer->host.type?
		 */
		pexpect(host_afi != NULL);
		if (peer->host.type == KH_IPHOSTNAME) {
#ifdef USE_DNSSEC
			/* try numeric first */
			err_t er = ttoaddress_num(shunk1(peer->host.name),
						  host_afi, &peer->host.addr);
			if (er != NULL) {
				/* not numeric, so resolve it */
				if (!unbound_resolve(peer->host.name,
						     host_afi, &peer->host.addr,
						     verbose.logger)) {
					pfree(msgbuf);
					return RESOLVE_FAILURE;
				}
			}
#else
			err_t er = ttoaddress_dns(shunk1(peer->host.name),
				 		  host_afi, &peer->host.addr);
			if (er != NULL) {
				pfree(msgbuf);
				return RESOLVE_FAILURE;
			}
#endif
		} else {
			pexpect(peer->host.type == KH_IPADDR);
		}
		added_dst = true;
		netlink_query_add(msgbuf, RTA_DST, &peer->host.addr,
				  "peer->host.addr", verbose);
	} else if (host->nexthop.type == KH_IPADDR &&
		   (peer->host.type == KH_GROUP ||
		    peer->host.type == KH_OPPOGROUP)) {
		added_dst = true;
		netlink_query_add(msgbuf, RTA_DST, &host->nexthop.addr,
				  "host->nexthop.addr peer=group", verbose);
	} else {
		added_dst = false;
	}

	if (added_dst && host->host.type == KH_IPADDR) {
		/* SRC works only with DST */
		pexpect(seeking == GATEWAY);
		netlink_query_add(msgbuf, RTA_SRC, &host->host.addr,
				  "host->host.addr", verbose);
	}

	/* Send netlink get_route request */
	struct linux_netlink_context context = {
		.status = RESOLVE_FAILURE,
		.host = host,
		.peer = peer,
		.host_afi = host_afi,
		.seeking = seeking,
	};

	verbose.level--;
	bool ok = linux_netlink_query(msgbuf, NETLINK_ROUTE,
				      process_netlink_route,
				      &context, verbose);
	if (!ok) {
		pfree(msgbuf);
		return RESOLVE_FAILURE;
	}

	verbose.level = 1;
	verbose("%s: src=%s gateway=%s",
		(context.status == RESOLVE_FAILURE ? "failure" :
		 context.status == RESOLVE_SUCCESS ? "success" :
		 context.status == RESOLVE_PLEASE_CALL_AGAIN ? "please-call-again" :
		 "???"),
		pa(&host->host, &hb),
		pa(&host->nexthop, &gb));
	pfree(msgbuf);
	return context.status;
}

enum route_status get_route(ip_address dest, struct ip_route *route,
			    struct logger *logger)
{
	/* let's re-discover local address */

	const struct ip_info *host_afi = address_info(dest);

	struct resolve_end this = {
		.host.type = KH_DEFAULTROUTE,
		.nexthop.type = KH_DEFAULTROUTE,
	};

	struct resolve_end that = {
		.host.type = KH_IPADDR,
	};

	struct verbose verbose = {
		.logger = logger,
		.rc_flags = DBGP(DBG_BASE) ? DEBUG_STREAM : LEMPTY,
		.level = 0,
	};

	/*
	 * mobike need two lookups. one for the gateway and the one
	 * for the source address.
	 */

	switch (resolve_defaultroute_one(&this, &that, host_afi, verbose)) {
	case RESOLVE_FAILURE:
		return ROUTE_GATEWAY_FAILED;
	case RESOLVE_SUCCESS:
		/* cannot happen */
		/* ??? original code treated this as failure */
		/* bad_case(0); */
		llog_pexpect(logger, HERE,
			     "unexpected SUCCESS from first resolve_defaultroute_one())");
		return ROUTE_FATAL;
	case RESOLVE_PLEASE_CALL_AGAIN: /* please call again: more to do */
		/* expected; so far only gateway resolved */
		break;
	}

	switch (resolve_defaultroute_one(&this, &that, host_afi, verbose)) {
	case RESOLVE_FAILURE:
		return ROUTE_SOURCE_FAILED;
	case RESOLVE_SUCCESS:
		break;
	case RESOLVE_PLEASE_CALL_AGAIN: /* please call again: more to do */
		/* cannot happen */
		/* ??? original code treated this as failure */
		/* bad_case(1); */
		llog_pexpect(logger, HERE,
			     "unexpected TRY AGAIN from second resolve_defaultroute_one()");
		return ROUTE_FATAL;
	}

	route->source = this.host.addr;
	route->gateway = this.nexthop.addr;
	return ROUTE_SUCCESS;
}

void resolve_default_route(struct resolve_end *host,
			   struct resolve_end *peer,
			   const struct ip_info *host_afi,
			   lset_t verbose_rc_flags,
			   struct logger *logger)
{
	struct verbose verbose = {
		.rc_flags = verbose_rc_flags,
		.logger = logger,
		.level = 0,
	};

	switch (resolve_defaultroute_one(host, peer, host_afi, verbose)) {
	case RESOLVE_FAILURE:
		return;
	case RESOLVE_SUCCESS:
		return;
	case RESOLVE_PLEASE_CALL_AGAIN:
		break;
	}

	resolve_defaultroute_one(host, peer, host_afi, verbose);
}
