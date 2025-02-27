/*
 * xfrmi interface related functions
 *
 * Copyright (C) 2018-2020 Antony Antony <antony@phenome.org>
 * Copyright (C) 2023 Brady Johnson <bradyallenjohnson@gmail.com>
 * Copyright (C) 2024 Andrew Cagney
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

#if !defined(linux) || !defined(USE_XFRM_INTERFACE) || !defined(KERNEL_XFRM)
# error this file should only compile on Linux when KERNEL_XFRM & USE_XFRM_INTERFACE are defined
#endif

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>
#include <net/if.h>

#define XFRMI_SUCCESS 0
#define XFRMI_FAILURE 1

/*
 * GRRR:
 *
 * GLIBC/Linux and MUSL/Linux define sockaddr_in et.al. in
 * <netinet/in.h>, and the generic network code uses this.
 * Unfortunately (cough) the Linux kernel headers also provide
 * definitions of those structures in <linux/in.h> et.al. which,
 * depending on header include order can result in conflicting
 * definitions.  For instance, if sockaddr_in is not defined,
 * <linux/xfrm.h> will include the definition in <linux/in.h> but that
 * will then clash with a later include of <netinet/in.h>.
 *
 * GLIBC/Linux has hacks on hacks to work-around this, not MUSL.
 * Fortunately, including <netinet/in.h> first will force the Linux
 * kernel headers to use that definition.
 *
 * XXX: include this before any other Linux kernel headers try to
 * include the conflicting definition.
 */
#include <netinet/in.h>
#include "linux/xfrm.h"		/* local (if configured) or system copy */

#include "linux_netlink.h"

#include "netlink_attrib.h"
#include "ipsec_interface.h"
#include "kernel_xfrm_interface.h"
#include "kernel_netlink_reply.h"
#include "kernel_netlink_query.h"
#include "kernel_ipsec_interface.h"

#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#if defined(USE_XFRM_INTERFACE_IFLA_HEADER)
/* kernel header linux/if_link.h < 4.19 may need this extra */
# include "if_link_extra.h"
#endif

#include "lswalloc.h"
#include "connections.h"
#include "ip_info.h"
#include "server.h" /* for struct iface_endpoint */
#include "iface.h"
#include "log.h"
#include "sparse_names.h"
#include "kernel.h"

#define IPSEC1_XFRM_IF_ID (1U)
#define IFINFO_REPLY_BUFFER_SIZE (32768 + NL_BUFMARGIN)
#define IP_ADDR_GLOBAL_SCOPE 0

struct nl_ifinfomsg_req {
	struct nlmsghdr n;
	struct ifinfomsg i;
	char data[NETLINK_REQ_DATA_SIZE];
	size_t maxlen;
};

struct nl_ifaddrmsg_req {
	struct nlmsghdr n;
	struct ifaddrmsg ifa;
	char data[NETLINK_REQ_DATA_SIZE];
	size_t maxlen;
};

struct linux_netlink_context {
	struct getaddr_context *getaddr;
	struct getlink_context *getlink;
};

/*
 * Perform a simple netlink operation.  Send the request; and only
 * look for immediate error responses (i.e., NLM_F_ACK is not set).
 *
 * Return 0 (XFRMI_SUCCESS) on success or non-zero (XFRMI_FAILURE) on
 * failure.  Later, if necessary, more detailed failure codes can be
 * returned.
 */

static bool ignore_response_processor(struct nlmsghdr *h,
				      struct linux_netlink_context *c,
				      struct verbose verbose)
{
	vdbg("ignoring %p %p", h, c);
	return true;
}

static bool simple_netlink_op(const struct nlmsghdr *req,
			      const char *context,
			      const char *if_name,
			      struct verbose verbose)
{
	vdbg("%s() %s %s", __func__, context, if_name);
	verbose.level++;

	if (!linux_netlink_query(req, NETLINK_ROUTE,
				 ignore_response_processor,
				 NULL, verbose)) {
		return false;
	}

	vdbg("%s() succeeded for %s %s", __func__, context, if_name);
	return true;
}

static struct nl_ifinfomsg_req init_nl_ifi(uint16_t type, uint16_t flags)
{
	struct nl_ifinfomsg_req req;
	zero(&req);
	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifinfomsg)));
	req.maxlen = req.n.nlmsg_len + sizeof(req.data);
	req.n.nlmsg_flags = flags;
	req.n.nlmsg_type = type;
	req.n.nlmsg_pid = getpid();
	req.i.ifi_family = AF_PACKET;
	return req;
}

static struct nl_ifaddrmsg_req init_ifaddrmsg_req(uint16_t type, uint16_t flags,
						  const char *if_name,
						  const struct ip_info *afi)
{
	struct nl_ifaddrmsg_req req = {
		.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifaddrmsg))),
		.maxlen = req.n.nlmsg_len + sizeof(req.data),
		.n.nlmsg_flags = flags,
		.n.nlmsg_type = type,
		.n.nlmsg_pid = getpid(),
		.ifa.ifa_index = if_nametoindex(if_name),
		.ifa.ifa_family = afi->af,
		.ifa.ifa_scope = IP_ADDR_GLOBAL_SCOPE,/*i.e., 0*/
	};

	return req;
}

static bool xfrm_ipsec_interface_up(const char *if_name, struct verbose verbose)
{
	vdbg("%s() if_name %s", __func__, if_name);
	verbose.level++;
	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_NEWLINK, NLM_F_REQUEST);
	req.i.ifi_change |= IFF_UP;
	req.i.ifi_flags |= IFF_UP;
	req.i.ifi_index = if_nametoindex(if_name);
	if (req.i.ifi_index == 0) {
		llog_error(verbose.logger, errno,
			   "%s() cannot find index of xfrm interface %s",
			   __func__, if_name);
		return false;
	}

	if (!simple_netlink_op(&req.n, __func__, if_name, verbose)) {
		return false;
	}

	return true;
}

static bool xfrm_ipsec_interface_del(const char *if_name, struct verbose verbose)
{
	vdbg("%s() if_name %s", __func__, if_name);
	verbose.level++;
	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_DELLINK, NLM_F_REQUEST);
	req.i.ifi_index = if_nametoindex(if_name);
	if (req.i.ifi_index == 0) {
		llog_error(verbose.logger, errno,
			   "%s() cannot find index of interface %s",
			   __func__, if_name);
		return false;
	}

	if (!simple_netlink_op(&req.n, __func__, if_name, verbose)) {
		return false;
	}

	return true;
}

static bool nl_newlink(const char *ipsec_if_name,
		       const uint32_t ipsec_if_id,
		       const char *physical_if_name,
		       struct verbose verbose)
{
	vdbg("%s() interface %s@%s id=%u",
	     __func__, ipsec_if_name, physical_if_name, ipsec_if_id);
	verbose.level++;

	struct nl_ifinfomsg_req req =
		init_nl_ifi(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);
	nl_addattrstrz(&req.n, req.maxlen, IFLA_IFNAME, ipsec_if_name);

	struct rtattr *linkinfo = nl_addattr_nest(&req.n, req.maxlen, IFLA_LINKINFO);
	{
		static const char link_kind[] = "xfrm";
		nl_addattr_l(&req.n, req.maxlen, IFLA_INFO_KIND,
			     link_kind, strlen(link_kind));

		struct rtattr *info_data = nl_addattr_nest(&req.n, req.maxlen, IFLA_INFO_DATA);
		{
			/*
			 * IFLA_XFRM_IF_ID was added to mainline kernel 4.19
			 * linux/if_link.h with older kernel headers 'make
			 * USE_XFRM_INTERFACE_IFLA_HEADER=true'
			 */
			nl_addattr32(&req.n, sizeof(req.data), IFLA_XFRM_IF_ID, ipsec_if_id);	/* see USE_XFRM_INTERFACE_IFLA_HEADER */

			/* e.g link id of the interface, eth0 */
			unsigned physical_if_index = if_nametoindex(physical_if_name);
			if (physical_if_index == 0) {
				llog_error(verbose.logger, errno,
					   "cannot find interface index for physical interface device %s", physical_if_name);
				return false;
			}
			nl_addattr32(&req.n, sizeof(req.data), IFLA_XFRM_LINK, physical_if_index);
		}
		nl_addattr_nest_end(&req.n, info_data);
	}
	nl_addattr_nest_end(&req.n, linkinfo);

	if (!simple_netlink_op(&req.n, __func__, ipsec_if_name, verbose)) {
		return false;
	}

	return true;
}

static bool xfrm_ipsec_interface_add(const char *if_name /*non-NULL*/,
				     const ipsec_interface_id_t if_id,
				     const struct iface_device *real_device,
				     struct verbose verbose)
{
	return nl_newlink(if_name, if_id, real_device->real_device_name, verbose);
}

static int ifaddrmsg_op(uint16_t type, uint16_t flags,
			const char *if_name, ip_cidr cidr,
			struct verbose verbose)
{
	const struct ip_info *afi = cidr_info(cidr);
	struct nl_ifaddrmsg_req req = init_ifaddrmsg_req(type, flags, if_name, afi);

	shunk_t bytes = cidr_as_shunk(&cidr);
	nl_addattr_l(&req.n, sizeof(req.data), IFA_LOCAL,   bytes.ptr, bytes.len);
	nl_addattr_l(&req.n, sizeof(req.data), IFA_ADDRESS, bytes.ptr, bytes.len);
	req.ifa.ifa_prefixlen = cidr_prefix_len(cidr);

	if (!simple_netlink_op(&req.n, __func__, if_name, verbose)) {
		return XFRMI_FAILURE;
	}

	return XFRMI_SUCCESS;
}

/* Add an IP address to an XFRMi interface using Netlink */
static bool xfrm_ipsec_interface_add_cidr(const char *if_name, ip_cidr cidr,
					  struct verbose verbose)
{
	return ifaddrmsg_op(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
			    if_name, cidr, verbose) == XFRMI_SUCCESS;
}

/* Delete an IP address from an XFRMi interface using Netlink */
static void xfrm_ipsec_interface_del_cidr(const char *if_name, ip_cidr cidr,
					  struct verbose verbose)
{
	ifaddrmsg_op(RTM_DELADDR, NLM_F_REQUEST,
		     if_name, cidr, verbose);
}

/*
 * Find or verify an ipsec-interface using netlink's GETLINK.
 */

struct getlink_context {
	struct ipsec_interface_match *match;

	struct {
		bool ok; /* final result true success */
		uint32 xfrm_link;
		uint32 xfrm_if_id;
	} result;
};

/* should either set .ok or .diag */

static diag_t check_ipsec_interface_linkinfo_data(const char *ipsec_if_name,
						  struct rtattr *attribute,
						  struct getlink_context *ifi_rsp,
						  struct verbose verbose)
{
	vdbg("%s() start %s", __func__, ipsec_if_name);
	verbose.level++;

	const struct rtattr *xfrm_link_attr = NULL;
	const struct rtattr *xfrm_if_id_attr = NULL;

	for (struct rtattr *nested_attrib = (struct rtattr *) RTA_DATA(attribute);
	     RTA_OK(nested_attrib, attribute->rta_len);
	     nested_attrib = RTA_NEXT(nested_attrib, attribute->rta_len)) {

		if (nested_attrib->rta_type == IFLA_XFRM_LINK) {
			vdbg("%s found IFLA_XFRM_LINK", ipsec_if_name);
			xfrm_link_attr = nested_attrib;
		}

		if (nested_attrib->rta_type == IFLA_XFRM_IF_ID) {
			vdbg("%s found IFLA_XFRM_IF_ID", ipsec_if_name);
			xfrm_if_id_attr = nested_attrib;
		}
	}

	/*
	 * An ipsec-interface must have a valid link (aka physical
	 * device).  If it doesn't return, caller will move onto the
	 * next one.
	 */

	if (xfrm_link_attr == NULL) {
		return diag("IFLA_XFRM_LINK attribute is missing");
	}

	/* XXX: portable? */
	uint32_t xfrm_link = *((const uint32_t *)RTA_DATA(xfrm_link_attr));
	if (xfrm_link == 0) {
		/* not good! see if_nametoindex() */
		return diag("IFLA_XFRM_LINK attribute is zero");
	}
	if (ifi_rsp->match->iface_if_index == 0) {
		vdbg("%s wildcard matched IFLA_XFRM_LINK %d", ipsec_if_name, xfrm_link);
	} else if (ifi_rsp->match->iface_if_index == xfrm_link) {
		vdbg("%s matched IFLA_XFRM_LINK %d to .iface_if_index %u",
		     ipsec_if_name, xfrm_link, ifi_rsp->match->iface_if_index);
	} else {
		char iface_buf[IFNAMSIZ] = "", link_buf[IFNAMSIZ] = "";
		const char *iface_name = if_indextoname(ifi_rsp->match->iface_if_index, iface_buf);
		const char *link_name = if_indextoname(xfrm_link, link_buf);
#if 0
		return diag("IFLA_XFRM_LINK attribute %s (%u) does not match expected iface_if_index %s (%u)",
		     (link_name == NULL ? "?" : link_name), xfrm_link,
		     (iface_name == NULL ? "?" : iface_name), ifi_rsp->match->iface_if_index);
#else
		llog(RC_LOG, verbose.logger,
		     "ipsec-interface %s linked to %s (%u) and not %s (%u)",
		     ipsec_if_name,
		     (link_name == NULL ? "?" : link_name), xfrm_link,
		     (iface_name == NULL ? "?" : iface_name), ifi_rsp->match->iface_if_index);
#endif
	}

	/*
	 * The device also needs its ID
	 */

	if (xfrm_if_id_attr == NULL) {
		return diag("IFLA_XFRM_IF_ID attribute is missing");
	}

	uint32_t xfrm_if_id = *((const uint32_t *)RTA_DATA(xfrm_if_id_attr));
	if (ifi_rsp->match->wildcard) {
		vdbg("%s wildcard matched xfrm_if_id %d", ipsec_if_name, xfrm_if_id);
	} else if (xfrm_if_id == ifi_rsp->match->ipsec_if_id) {
		vdbg("%s matched xfrm_if_id %d matched", ipsec_if_name, xfrm_if_id);
	} else {
		return diag("IFLA_XFRM_IF_ID attribute %u does not match ipsec-interface ID %u",
			    xfrm_if_id, ifi_rsp->match->ipsec_if_id);
	}

	/* if it came this far found what we looking for */
	vdbg("%s() %s setting .result = true; .xfrm_link=%d; .xfrm_if_id=%d",
	     __func__, ipsec_if_name,
	     ifi_rsp->result.xfrm_link, ifi_rsp->result.xfrm_if_id);
	jam_str(ifi_rsp->match->found, sizeof(ifi_rsp->match->found), ipsec_if_name);
	ifi_rsp->result.xfrm_link = xfrm_link;
	ifi_rsp->result.xfrm_if_id = xfrm_if_id;
	ifi_rsp->result.ok = true;
	return NULL; /* this one is good! */
}

static diag_t check_ipsec_interface_linkinfo(const char *if_name,
					     struct rtattr *attribute,
					     struct getlink_context *ifi_rsp,
					     struct verbose verbose)
{
	vdbg("%s() start", __func__);
	verbose.level++;

	struct rtattr *info_data_attr = NULL;
	struct rtattr *info_kind_attr = NULL;
	ssize_t len = attribute->rta_len;
	for (struct rtattr *nested_attrib = (struct rtattr *) RTA_DATA(attribute);
	     RTA_OK(nested_attrib, len);
	     nested_attrib = RTA_NEXT(nested_attrib, len)) {

		if (nested_attrib->rta_type == IFLA_INFO_KIND) {
			info_kind_attr = nested_attrib;
		}

		if (nested_attrib->rta_type == IFLA_INFO_DATA) {
			info_data_attr = nested_attrib;
		}
	}

	if (info_kind_attr == NULL) {
		return diag("IFLA_INFO_KIND attribute is missing");
	}

	const char *info_kind = RTA_DATA(info_kind_attr);
	if (!streq("xfrm", info_kind)) {
		return diag("IFLA_INFO_KIND attribute '%s' should be 'xfrm'", info_kind);
	}

	if (info_data_attr == NULL) {
		return diag("IFLA_INFO_DATA attribute is missing");
	}

	return check_ipsec_interface_linkinfo_data(if_name, info_data_attr,
						   ifi_rsp, verbose);
}

/*
 * Return TRUE when stumbling on; FALSE when stopping.
 */

static bool parse_getlink_newlink_response(struct nlmsghdr *nlmsg,
					   struct getlink_context *ifi_rsp,
					   struct verbose verbose)
{
	vdbg("%s() start", __func__);
	verbose.level++;

	struct rtattr *linkinfo_attr =  NULL;
	struct ifinfomsg *iface = NLMSG_DATA(nlmsg);
	int len = nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));
	const char *if_name = NULL;

	for (struct rtattr *attribute = IFLA_RTA(iface); RTA_OK(attribute, len);
	     attribute = RTA_NEXT(attribute, len)) {
		switch (attribute->rta_type) {
		case IFLA_IFNAME:
			/* XXX: is this guaranteed to be NUL
			 * terminated? */
			if_name =  (const char *) RTA_DATA(attribute); /* tmp */
			break;

		case IFLA_LINKINFO:
			linkinfo_attr = attribute;
			break;

		default:
			break;
		}
	}

	if (if_name == NULL) {
		vdbg("no if_name, stumbling on");
		return true; /* stumble on */
	}

	if (linkinfo_attr == NULL) {
		vdbg("no linkinfo_attr, stumbling on");
		return true; /* stumble on */
	}

	if (ifi_rsp->match->ipsec_if_name == NULL) {
		vdbg("wildcard: checking %s to see if it is an ipsec-interface", if_name);
	} else if (streq(ifi_rsp->match->ipsec_if_name, if_name)) {
		vdbg("exact: checking that %s is a valid ipsec-interface", if_name);
	} else {
		vdbg("%s is not the correct ipsec-interface, stumbling on", if_name);
		return true; /* stumble on */
	}

	diag_t d = check_ipsec_interface_linkinfo(if_name, linkinfo_attr,
						     ifi_rsp, verbose);

	if (ifi_rsp->result.ok) {
		vexpect(d == NULL);
		return false; /* success! so stop early */
	}

	if (ifi_rsp->match->wildcard) {
		vexpect(d != NULL);
		vdbg("wildcard %s invalid, %s, stumbling on", if_name, str_diag(d));
		pfree_diag(&d);
		return true; /* stumble on */
	}

	vdbg("matching ipsec-interface %s isn't valid, %s", if_name, str_diag(d));
	ifi_rsp->match->diag = diag("%s, check 'ip -d link show dev %s'", str_diag(d), if_name);
	pfree_diag(&d);
	return false; /* abort */

}

static bool parse_getlink_response(struct nlmsghdr *nlmsg,
				   struct linux_netlink_context *ctx,
				   struct verbose verbose)
{
	vdbg("%s() start", __func__);
	verbose.level++;

	if (nlmsg->nlmsg_type != RTM_NEWLINK) {
		vdbg("ignored message type %d length %d",
		     nlmsg->nlmsg_type, nlmsg->nlmsg_len);
		return true;
	}

	return parse_getlink_newlink_response(nlmsg, ctx->getlink, verbose);
}

static bool xfrm_ipsec_interface_match(struct ipsec_interface_match *match,
				       struct verbose verbose)
{
	struct getlink_context getlink = {
		.match = match,
	};

	struct linux_netlink_context ctx = {
		.getlink = &getlink,
	};

	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_GETLINK, (NLM_F_REQUEST | NLM_F_DUMP));

	if (!linux_netlink_query(&req.n, NETLINK_ROUTE,
				 parse_getlink_response,
				 &ctx, verbose)) {
		vdbg("%s() failed, linux_netlink_query() failed", __func__);
		return false;
	}

	if (!getlink.result.ok) {
		vexpect(match->wildcard != (match->diag != NULL));
		vdbg("%s() failed, no .result", __func__);
		return false;
	}

	vexpect(match->diag == NULL);
	char xfrm_link_name[IF_NAMESIZE];
	if_indextoname(getlink.result.xfrm_link, xfrm_link_name);
	vdbg("support found existing %s@%s (xfrm) .xfrm_if_id %d .xfrm_link %d",
	     match->found, xfrm_link_name,
	     getlink.result.xfrm_if_id, getlink.result.xfrm_link);
	return true;
}

/*
 * See if the specified CIDR is on the interface.
 */

struct getaddr_context {
	struct {
		unsigned ipsec_if_index;
		ip_cidr cidr;
	} match;

	struct {
		bool ok; /* final result true success */
	} result;
};

static bool parse_getaddr_newaddr_response(struct nlmsghdr *nlmsg,
					   struct getaddr_context *if_rsp,
					   struct verbose verbose)
{
	vdbg("%s() start", __func__);
	verbose.level++;

	struct ifaddrmsg *ifa = NLMSG_DATA(nlmsg);
	int len = nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));

	/* Only parse the IP, when the interface index matches */
	char if_name[IF_NAMESIZE] = "???";
	if_indextoname(ifa->ifa_index, if_name);
	if (ifa->ifa_index != if_rsp->match.ipsec_if_index) {
		vdbg("skipping %s, ifa_index %u did not match ipsec_if_index %u",
		     if_name, ifa->ifa_index, if_rsp->match.ipsec_if_index);
		return true; /* try again */
	}

	for (struct rtattr *attribute = IFA_RTA(ifa); RTA_OK(attribute, len);
	     attribute = RTA_NEXT(attribute, len)) {
		shunk_t attr = shunk2(RTA_DATA(attribute), RTA_PAYLOAD(attribute));

		/*
		 * Since we only have broadcast interfaces, it is safe
		 * to only use IFA_ADDRESS to get the local IPv4 or
		 * IPv6 address from the the xfrm interface.  Skip
		 * anything else.
		 */
		if (attribute->rta_type != IFA_ADDRESS) {
			vdbg("skipping %s attr type %d", if_name, attribute->rta_type);
			continue;
		}

		ip_cidr if_cidr;
		diag_t diag = hunk_to_cidr(attr, ifa->ifa_prefixlen,
					   aftoinfo(ifa->ifa_family),
					   &if_cidr);
		if (diag != NULL) {
			llog_pexpect(verbose.logger, HERE, "invalid XFRMI address: %s", str_diag(diag));
			pfree_diag(&diag);
			return false; /* disaster; stop processing */
		}

		if (!cidr_eq_cidr(if_cidr, if_rsp->match.cidr)) {
			cidr_buf cb;
			vdbg("skipping %s cidr %s", if_name, str_cidr(&if_cidr, &cb));
			continue;
		}

		cidr_buf cb;
		vdbg("interface %s has matching index %d and cidr %s",
		     if_name, ifa->ifa_index, str_cidr(&if_cidr, &cb));
		if_rsp->result.ok = true; /* found!!! */
		return false;  /* stop looking */
	}

	return true; /* try again */
}

static bool parse_getaddr_response(struct nlmsghdr *nlmsg,
				   struct linux_netlink_context *ctx,
				   struct verbose verbose)
{
	vdbg("%s() message type %d length %d",
	     __func__, nlmsg->nlmsg_type, nlmsg->nlmsg_len);
	verbose.level++;

	if (nlmsg->nlmsg_type != RTM_NEWADDR) {
		vdbg("ignored message");
		return true;
	}

	return parse_getaddr_newaddr_response(nlmsg, ctx->getaddr, verbose);
}

static bool xfrm_ipsec_interface_has_cidr(const char *ipsec_if_name,
					  ip_cidr search_cidr,
					  struct verbose verbose)
{
	/* first do a cheap check */
	vassert(ipsec_if_name != NULL);

	struct getaddr_context getaddr = {
		.match.ipsec_if_index = if_nametoindex(ipsec_if_name),
		.match.cidr = search_cidr,
	};

	if (vbad(getaddr.match.ipsec_if_index == 0)) {
		return NULL;
	}

	struct linux_netlink_context ctx = {
		.getaddr = &getaddr,
	};

	struct nl_ifaddrmsg_req req = init_ifaddrmsg_req(RTM_GETADDR,
							 (NLM_F_DUMP | NLM_F_REQUEST),
							 ipsec_if_name,
							 &unspec_ip_info);


	if (!linux_netlink_query(&req.n, NETLINK_ROUTE,
				 parse_getaddr_response,
				 &ctx, verbose)) {
		/* netlink error */
		llog_error(verbose.logger, 0/*no-errno*/,
			   "%s() request for all IPs failed", __func__);
		return false;
	}

	return getaddr.result.ok; /* found */
}

static err_t xfrm_iface_supported(struct verbose verbose)
{
	/*
	 * Use a wildcard check to match any existing ipsec-interface
	 * (for instance, a pre-existing "ipsec1").  If it succeeds
	 * (i.e., there is at least one ipsec-interface that is valid)
	 * then things are working.
	 *
	 * Note: this silently ignores invalid IPsec interfaces.
	 * Should it instead flag them?  It would mean carefully
	 * differentiating between several rejection cases.
	 */
	struct ipsec_interface_match wildcard_match = {
		.wildcard = true,
	};
	if (kernel_ipsec_interface_match(&wildcard_match, verbose)) {
		vdbg("existing xfrmi ipsec-interface %s found; ipsec-must be supported",
		     wildcard_match.found);
		return NULL; /* success: there is already xfrmi interface */
	}

	/*
	 * If the previous .supported() call failed, need to re-probe.
	 * For instance, "ipsec1" may have been present, but has since
	 * been deleted.
	 */

	/*
	 * Try building ipsec-interface device "ipsec1" bound to "lo".
	 * But only when the interface doesn't already exist.
	 *
	 * Interface ipsec0 can't be used as, on linux that gets remapped.
	 */

	const ipsec_interface_id_t ipsec_if_id = 1; /* NOT ZERO ON LINUX */
	const char ipsec_if_name[] = "ipsec1";
	unsigned int ipsec_if_index = if_nametoindex(ipsec_if_name);
	int e = errno; /* save error */

	if (ipsec_if_index != 0) {
		/*
		 * The device already exists so can't attempt
		 * insert/delete.
		 *
		 * Presumably the device is invalid.  If it was valid
		 * above match() call would have found and accepted
		 * it.  Find out by trying an exact match.
		 */
		struct ipsec_interface_match ipsec_match = {
			.ipsec_if_name = ipsec_if_name,
			.ipsec_if_id = ipsec_if_id,
		};
		if (!kernel_ipsec_interface_match(&ipsec_match, verbose)) {
			llog(RC_LOG, verbose.logger,
			     "ipsec-interface %s exists but is invalid, %s",
			     ipsec_match.found, str_diag(ipsec_match.diag));
			pfree_diag(&ipsec_match.diag);
			return "device name conflict in xfrm_iface_supported()";
		}
		llog(RC_LOG, verbose.logger,
		     "ipsec-interface %s isn't valid when it is? May be leftover from previous pluto?",
		     ipsec_if_name);
		return "device name conflict in xfrm_iface_supported()";
	}

	if (e != ENXIO && e != ENODEV) {
		/* The device lookup failed!?! */
		llog_error(verbose.logger, e,
			   "unexpected error in %s() while checking device %s",
			   __func__, ipsec_if_name);
		return "cannot decide xfrmi support. assumed no.";
	}

	/*
	 * The device doesn't exist, try to create ipsec1@lo and then
	 * delete it.
	 */

	static const char physical_if_name[] = "lo";
	if (if_nametoindex(physical_if_name) == 0) {
		/* possibly no need to panic: may be get smarter one
		 * day */
		return "could not find real device needed to test xfrmi support";
	}

	vdbg("trying to create the XFRMi ipsec-interface %s bound to %s",
	     ipsec_if_name, physical_if_name);
	if (!nl_newlink(ipsec_if_name, ipsec_if_id, physical_if_name, verbose)) {
		llog_error(verbose.logger, 0/*lost-error*/,
			   "xfrmi is not supported, failed to create ipsec-interface %s bound to %s",
			   ipsec_if_name, physical_if_name);
		/* xfrm_interface_support = -1; */
		return "xfrmi is not supported";
	}

	vdbg("checking the ipsec-interface %s bound to %s was created",
	     ipsec_if_name, physical_if_name);
	if (if_nametoindex(ipsec_if_name) == 0) {
		llog_error(verbose.logger, errno,
			   "cannot find test ipsec-interface %s bound to %s: ",
			   ipsec_if_name, physical_if_name);
		/*
		 * failed to create xfrmi device.
		 * assume kernel support is not enabled.
		 * build kernel with CONFIG_XFRM_INTERFACE=y
		 * to diagnose:
		 * 'ip link add ipsec1 type xfrm if_id 1 dev lo'
		 * 'ip -d link show dev ipsec1'
		 */
		/* xfrm_interface_support = -1; */
		return "missing CONFIG_XFRM_INTERFACE support in kernel";
	}

	vdbg("xfrmi supported, successfully created %s bound to %s; now deleting it",
	     ipsec_if_name, physical_if_name);
	kernel_ipsec_interface_del(ipsec_if_name, verbose); /* ignore return value??? */
	return NULL;
}

/*
 * During startup call this to see if there are any stale interface
 * lying around.
 */

static void xfrm_check_stale(struct verbose verbose)
{
	/*
	 * first check quick one do ipsec1 exist. later on add extensive checks
	 * "ip link show type xfrmi" would be better.
	 *  note when type foo is not supported would return success, 0
	 */

	ipsec_interface_buf ifb;
	const char *if_name = str_ipsec_interface_id(IPSEC1_XFRM_IF_ID, &ifb);

	unsigned int if_index = if_nametoindex(if_name);
	int e = errno;
	if (if_index != 0) {
		llog(RC_LOG, verbose.logger,
		     "found an unexpected interface %s if_index=%u From previous pluto run?",
		     if_name, if_index);
		return; /* ERROR */
	}

	if (e != ENXIO && e != ENODEV) {
		llog_error(verbose.logger, e,
			   "in %s() if_nametoindex('%s') failed: ",
			   __func__, if_name);
		return;
	}

	vdbg("no stale xfrmi interface '%s' found", if_name);
	return;
}

static err_t xfrm_ipsec_interface_init(struct verbose verbose)
{
	err_t e = xfrm_iface_supported(verbose);
	if (e != NULL) {
		return e;
	}

	xfrm_check_stale(verbose);
	return NULL;
}


void set_ike_mark_out(const struct connection *c, ip_endpoint *ike_remote)
{
	bool set_mark = false;
	const struct spds *spds = &c->child.spds;

	if (c->ipsec_interface == NULL) {
		return;
	}

	FOR_EACH_ITEM(spd, spds) {
		if (address_in_selector_range(spd->remote->host->addr, spd->remote->client))
			set_mark = true;
	}
	if (!set_mark)
		return; /* spds are outside ike remote end point */


	uint32_t mark_out;
	if (c->sa_marks.out.val != 0)
		mark_out = c->sa_marks.out.val;
	else
		mark_out = c->ipsec_interface->if_id;

	if (ike_remote->mark_out != 0)
		passert(ike_remote->mark_out == mark_out);

	ike_remote->mark_out = mark_out;
}

const struct kernel_ipsec_interface kernel_ipsec_interface_xfrm = {
	.name = "ipsec",
	/*
	 * For ipsec0 and XFRMi we need to map it to a different
	 * if_id.
	 */
	.map_if_id_zero = 16384,

	.has_cidr = xfrm_ipsec_interface_has_cidr,
	.add_cidr = xfrm_ipsec_interface_add_cidr,
	.del_cidr = xfrm_ipsec_interface_del_cidr,

	.up = xfrm_ipsec_interface_up,
	.add = xfrm_ipsec_interface_add,
	.del = xfrm_ipsec_interface_del,

	.match = xfrm_ipsec_interface_match,

	.init = xfrm_ipsec_interface_init,
};
