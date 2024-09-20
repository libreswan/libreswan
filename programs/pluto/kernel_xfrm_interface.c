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

struct ifinfo_response {
	struct ifinfo_req {
		const char *if_name;
		uint32_t xfrm_if_id;
		bool filter_xfrm_if_id /* because if_id can also be zero */;
	} filter_data;

	/* Which fields were matched while reading the NL response */
	struct ifinfo_match {
		bool name;
		bool kind /* aka type in, "ip link show type xfrm" */;
		bool xfrm_if_id /* xfrm if_id */;
	} matched;

	struct {
		bool ok; /* final result true success */
		uint32 dev_if_id;
		uint32 xfrm_if_id;
		char name[IF_NAMESIZE+1];
		struct ipsec_interface_address *if_ips;
	} result;
};

/* -1 missing; 0 uninitialized; 1 present */
static int xfrm_interface_support = 0;

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
			     const struct logger *logger)
{
	struct verbose verbose = {
		.logger = logger,
		.rc_flags = DBGP(DBG_BASE) ? DEBUG_STREAM : LEMPTY,
	};

	vdbg("%s() %s %s", __func__, context, if_name);

	if (!linux_netlink_query(req, NETLINK_ROUTE,
				 ignore_response_processor,
				 NULL, verbose)) {
		return false;
	}

	vdbg("%s() succeded for %s %s", __func__, context, if_name);
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

static int link_add_nl_msg(const char *if_name /*non-NULL*/,
			    const char *dev_name /*non-NULL*/,
			    const uint32_t if_id,
			    struct nl_ifinfomsg_req *req,
			    struct logger *logger)
{
	*req = init_nl_ifi(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);

	nl_addattrstrz(&req->n, req->maxlen, IFLA_IFNAME, if_name);

	struct rtattr *linkinfo = nl_addattr_nest(&req->n, req->maxlen, IFLA_LINKINFO);

	static const char link_type[] = "xfrm";
	nl_addattr_l(&req->n, req->maxlen, IFLA_INFO_KIND, link_type,
		     strlen(link_type));

	struct rtattr *xfrm_link = nl_addattr_nest(&req->n, req->maxlen,
						   IFLA_INFO_DATA);
	/*
	 * IFLA_XFRM_IF_ID was added to mainline kernel 4.19 linux/if_link.h
	 * with older kernel headers 'make USE_XFRM_INTERFACE_IFLA_HEADER=true'
	 */
	nl_addattr32(&req->n, sizeof(req->data), IFLA_XFRM_IF_ID, if_id);	/* see USE_XFRM_INTERFACE_IFLA_HEADER */

	if (dev_name != NULL) {
		/* e.g link id of the interface, eth0 */
		uint32_t dev_link_id = if_nametoindex(dev_name);
		if (dev_link_id == 0) {
			llog_error(logger, errno,
				   "cannot find interface index for device %s", dev_name);
			return XFRMI_FAILURE;
		}
		nl_addattr32(&req->n, sizeof(req->data), IFLA_XFRM_LINK, dev_link_id);
	}

	nl_addattr_nest_end(&req->n, xfrm_link);

	nl_addattr_nest_end(&req->n, linkinfo);

	return XFRMI_SUCCESS;
}

static bool ip_link_set_up(const char *if_name, struct logger *logger)
{
	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_NEWLINK, NLM_F_REQUEST);
	req.i.ifi_change |= IFF_UP;
	req.i.ifi_flags |= IFF_UP;
	req.i.ifi_index = if_nametoindex(if_name);
	if (req.i.ifi_index == 0) {
		llog_error(logger, errno,
			   "link_set_up_nl() cannot find index of xfrm interface %s",
			   if_name);
		return false;
	}

	if (!simple_netlink_op(&req.n, "ip_link_set_up", if_name, logger)) {
		return false;
	}

	return true;
}

static bool ip_link_del(const char *if_name, const struct logger *logger)
{
	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_DELLINK, NLM_F_REQUEST);
	req.i.ifi_index = if_nametoindex(if_name);
	if (req.i.ifi_index == 0) {
		llog_error(logger, errno, "ip_link_del() cannot find index of interface %s",
			   if_name);
		return false;
	}

	if (!simple_netlink_op(&req.n, "ip_link_del", if_name, logger)) {
		return false;
	}

	return true;
}

static bool ip_link_add(const char *if_name /*non-NULL*/,
			const char *dev_name /*non-NULL*/,
			const uint32_t if_id,
			struct logger *logger)
{
	ldbg(logger, "add xfrm interface %s@%s id=%u", if_name, dev_name, if_id);
	struct nl_ifinfomsg_req req;
	zero(&req);
	if (link_add_nl_msg(if_name, dev_name, if_id, &req, logger) != XFRMI_SUCCESS) {
		llog_error(logger, 0/*no-errno*/,
			   "link_add_nl_msg() creating netlink message failed");
		return false;
	}

	if (!simple_netlink_op(&req.n, "ip_link_add_xfrmi", if_name, logger)) {
		return false;
	}

	return true;
}

static int ifaddrmsg_op(uint16_t type, uint16_t flags,
			const char *if_name,
			const struct ipsec_interface_address *xfrmi_ipaddr,
			struct logger *logger)
{
	const struct ip_info *afi = cidr_info(xfrmi_ipaddr->if_ip);
	struct nl_ifaddrmsg_req req = init_ifaddrmsg_req(type, flags, if_name, afi);

	shunk_t bytes = cidr_as_shunk(&xfrmi_ipaddr->if_ip);
	nl_addattr_l(&req.n, sizeof(req.data), IFA_LOCAL,   bytes.ptr, bytes.len);
	nl_addattr_l(&req.n, sizeof(req.data), IFA_ADDRESS, bytes.ptr, bytes.len);
	req.ifa.ifa_prefixlen = cidr_prefix_len(xfrmi_ipaddr->if_ip);

	if (!simple_netlink_op(&req.n, __func__, if_name, logger)) {
		return XFRMI_FAILURE;
	}

	return XFRMI_SUCCESS;
}

/* Add an IP address to an XFRMi interface using Netlink */
static bool ip_addr_xfrmi_add(const char *if_name,
			      const struct ipsec_interface_address *xfrmi_ipaddr,
			      struct logger *logger)
{
	return ifaddrmsg_op(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
			    if_name, xfrmi_ipaddr, logger) == XFRMI_SUCCESS;
}

/* Delete an IP address from an XFRMi interface using Netlink */
static int ip_addr_xfrmi_del(const char *if_name,
			     const struct ipsec_interface_address *xfrmi_ipaddr,
			     struct logger *logger)
{
	return ifaddrmsg_op(RTM_DELADDR, NLM_F_REQUEST,
			    if_name, xfrmi_ipaddr, logger);
}

static bool parse_xfrm_linkinfo_data(struct rtattr *attribute, const char *if_name,
				     struct ifinfo_response *ifi_rsp, struct verbose verbose)
{
	vdbg("%s() start", __func__);
	verbose.level++;
	const struct rtattr *dev_if_id_attr = NULL;
	const struct rtattr *xfrm_if_id_attr = NULL;

	if (if_name == NULL) {
		llog_pexpect(verbose.logger, HERE, "NULL if_name");
		return false; /* abort */
	}

	for (struct rtattr *nested_attrib = (struct rtattr *) RTA_DATA(attribute);
	     RTA_OK(nested_attrib, attribute->rta_len);
	     nested_attrib = RTA_NEXT(nested_attrib, attribute->rta_len)) {

		if (nested_attrib->rta_type == IFLA_XFRM_LINK) {
			vdbg("%s() %s found IFLA_XFRM_LINK aka dev_if_id_attr",
			     __func__, if_name);
			dev_if_id_attr = nested_attrib;
		}

		if (nested_attrib->rta_type == IFLA_XFRM_IF_ID) {
			vdbg("%s() %s found IFLA_XFRM_IF_ID aka if_id_attr",
			     __func__, if_name);
			xfrm_if_id_attr = nested_attrib;
		}
	}

	if (dev_if_id_attr != NULL) {
		/* XXX: portable? */
		uint32_t dev_if_id = *((const uint32_t *)RTA_DATA(dev_if_id_attr));
		if (dev_if_id == 0) {
			/* not good! see if_nametoindex() */
			llog_error(verbose.logger, 0/*no-error*/,
				   "%s has an xfrm device ifindex (RTA_LINK) of 0", if_name);
			return true; /* stumble on */
		}
		ifi_rsp->result.dev_if_id = dev_if_id;
		vdbg("%s() %s setting .result.dev_if_id to %d",
		     __func__, if_name, dev_if_id);
	}

	if (xfrm_if_id_attr == NULL) {
		vdbg("%s() %s failed, xfrm_if_id_attr not found",
		     __func__, if_name);
		return false;
	}

	uint32_t xfrm_if_id = *((const uint32_t *)RTA_DATA(xfrm_if_id_attr));
	if (ifi_rsp->filter_data.filter_xfrm_if_id) {
		if (xfrm_if_id != ifi_rsp->filter_data.xfrm_if_id) {
			vdbg("%s() %s failed, xfrm_if_id %d did not match .filter_data.xfrm_if_id %d",
			     __func__, if_name, xfrm_if_id, ifi_rsp->filter_data.xfrm_if_id);
			return false;
		}

		vdbg("%s() %s xfrm_if_id %d matched; saving",
		     __func__, if_name, xfrm_if_id);
		ifi_rsp->result.xfrm_if_id = xfrm_if_id;
		ifi_rsp->matched.xfrm_if_id = true;
	} else {
		vdbg("%s() %s wildcard matched xfrm_if_id %d, setting .result.if_id",
		     __func__, if_name, xfrm_if_id);
		ifi_rsp->result.xfrm_if_id = xfrm_if_id;
	}

	/* trust kernel if_name != NULL */
	jam_str(ifi_rsp->result.name, sizeof(ifi_rsp->result.name), if_name);

	/* if it came this far found what we looking for */
	vdbg("%s() %s setting .result = true; .dev_if_id=%d; .if_id=%d .matched.xfrm_if_id=%s",
	     __func__, if_name,
	     ifi_rsp->result.dev_if_id,
	     ifi_rsp->result.xfrm_if_id, bool_str(ifi_rsp->matched.xfrm_if_id));
	ifi_rsp->result.ok = true;
	return true;
}

static bool parse_link_info_xfrm(struct rtattr *attribute, const char *if_name,
				 struct ifinfo_response *ifi_rsp,
				 struct verbose verbose)
{
	vdbg("%s() start", __func__);
	verbose.level++;
	struct rtattr *nested_attrib;
	struct rtattr *info_data_attr = NULL;
	ssize_t len = attribute->rta_len;
	for (nested_attrib = (struct rtattr *) RTA_DATA(attribute);
			RTA_OK(nested_attrib, len);
			nested_attrib = RTA_NEXT(nested_attrib, len)) {
		if (nested_attrib->rta_type == IFLA_INFO_KIND) {
			const char *kind_str = RTA_DATA(nested_attrib);
			if (streq("xfrm", kind_str)) {
				ifi_rsp->matched.kind = true;
			}
		}

		if (nested_attrib->rta_type == IFLA_INFO_DATA) {
			info_data_attr = nested_attrib;
		}
	}

	if (ifi_rsp->matched.kind && info_data_attr != NULL) {
		return parse_xfrm_linkinfo_data(info_data_attr, if_name, ifi_rsp, verbose);
	}

	return false;
}

static void parse_newlink_msg(struct nlmsghdr *nlmsg,
			      struct ifinfo_response *ifi_rsp,
			      struct verbose verbose)
{
	vdbg("%s() start", __func__);
	verbose.level++;

	struct rtattr *attribute;
	struct rtattr *linkinfo_attr =  NULL;
	struct ifinfomsg *iface = NLMSG_DATA(nlmsg);
	int len = nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));
	const char *if_name = NULL;

	for (attribute = IFLA_RTA(iface); RTA_OK(attribute, len); attribute = RTA_NEXT(attribute, len)) {
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
		vdbg("%s() no if_name", __func__);
		return;
	}

	if (linkinfo_attr == NULL) {
		vdbg("%s() no linkinfo_attr", __func__);
		return;
	}

	if (ifi_rsp->filter_data.if_name != NULL) {
		if (!streq(ifi_rsp->filter_data.if_name, if_name)) {
			vdbg("%s() if_name %s did not match %s",
			     __func__, if_name, ifi_rsp->filter_data.if_name);
		}
		/* name match requested and matched */
		ifi_rsp->matched.name = true;
	}

	if (!parse_link_info_xfrm(linkinfo_attr, if_name, ifi_rsp, verbose)) {
		vlog("%s() did not parse", __func__);
		return;
	}

	return;
}

static void parse_newaddr_msg(struct nlmsghdr *nlmsg,
			      struct ifinfo_response *if_rsp,
			      const struct logger *logger)
{
	struct ifaddrmsg *ifa = NLMSG_DATA(nlmsg);
	int len = nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));

	/* Only parse the IP, when the interface index matches */
	if (ifa->ifa_index != if_nametoindex(if_rsp->filter_data.if_name)) {
		char if_name_buf[IF_NAMESIZE];
		if_indextoname(ifa->ifa_index, if_name_buf);
		ldbg(logger, "%s() skipping non-matching message for if_name %s",
		     __func__, if_name_buf);
		return;
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
			ldbg(logger, "%s() skipping attr type %d",
			     __func__, attribute->rta_type);
			continue;
		}

		ip_cidr if_ip;
		diag_t diag = hunk_to_cidr(attr, ifa->ifa_prefixlen,
					   aftoinfo(ifa->ifa_family), &if_ip);
		if (diag != NULL) {
			llog_pexpect(logger, HERE, "invalid XFRMI address: %s", str_diag(diag));
			pfree_diag(&diag);
			return;
		}

		if (if_rsp->result.name[0] == '\0') {
			/* Does if_indextoname() guarantee NUL
			 * termination?  Perhaps.  It does assume
			 * IF_NAMESIZE buffer.  */
			if_indextoname(ifa->ifa_index, if_rsp->result.name);
		}

		alloc_ipsec_interface_address(&if_rsp->result.if_ips, if_ip);
		ldbg(logger, "%s() matching message for if_name %s and ifa_index %d; setting; result = true",
		     __func__, if_rsp->result.name, ifa->ifa_index);
		if_rsp->result.ok = true;
		return;
	}

	return;
}

struct linux_netlink_context {
	struct ifinfo_response *ifi_rsp;
};

static bool process_nlmsg(struct nlmsghdr *nlmsg,
			  struct linux_netlink_context *c,
			  struct verbose verbose)
{
	struct ifinfo_response *ifi_rsp = c->ifi_rsp;
	switch (nlmsg->nlmsg_type) {
	case RTM_NEWLINK:
		parse_newlink_msg(nlmsg, ifi_rsp, verbose);
		/* true here means continue scanning */
		return true;

	case RTM_NEWADDR:
		parse_newaddr_msg(nlmsg, ifi_rsp, verbose.logger);
		/* true here means continue scanning */
		return true;
	}

	vdbg("ignored message type %d length %d", nlmsg->nlmsg_type,
	     nlmsg->nlmsg_len);
	return true;
}

static bool find_xfrmi_interface(const char *if_name, /* optional */
				 uint32_t xfrm_if_id, /* 0 is wildcard */
				 struct verbose verbose)
{
	vdbg("%s() start", __func__);
	verbose.level++;

	/* first do a cheap existance check */
	if (if_name != NULL && if_nametoindex(if_name) == 0) {
		vdbg("%s() failed, if_nametoindex(%s) returned zero", __func__, if_name);
		return false;
	}

	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_GETLINK, (NLM_F_REQUEST | NLM_F_DUMP));

	struct ifinfo_response ifi_rsp = {
		.filter_data = {
			.if_name = if_name,
			.filter_xfrm_if_id = (xfrm_if_id > 0),
			.xfrm_if_id = xfrm_if_id,
		},
	};
	struct linux_netlink_context ctx = {
		.ifi_rsp = &ifi_rsp,
	};

	if (!linux_netlink_query(&req.n, NETLINK_ROUTE, process_nlmsg, &ctx, verbose)) {
		vdbg("%s() failed, linux_netlink_query() failed", __func__);
		return false;
	}

	if (!ifi_rsp.result.ok) {
		vdbg("%s() failed, no .result", __func__);
		return false;
	}

	/*
	 * XXX: this is old code.
	 *
	 * The call to if_indextoname() has been expected to work for
	 * many years but now 2024 doesn't.  Try to figure out why.
	 */
	char if_name_buf[IF_NAMESIZE];
	const char *name = if_indextoname(ifi_rsp.result.dev_if_id, if_name_buf);
	vdbg("%s() support found existing %s@%s (xfrm) .result.xfrm_if_id %d %s .result.dev_if_id %d",
	     __func__, ifi_rsp.result.name, name,
	     ifi_rsp.result.xfrm_if_id, bool_str(ifi_rsp.matched.xfrm_if_id),
	     ifi_rsp.result.dev_if_id);
	return true;
}

/* Get all of the IP addresses on an XFRMi interface using Netlink */
static struct ipsec_interface_address *ip_addr_xfrmi_get_all_ips(const char *if_name,
								 uint32_t xfrm_if_id,
								 struct logger *logger)
{
	/* first do a cheap check */
	PASSERT(logger, if_name != NULL);
	PEXPECT(logger, if_nametoindex(if_name) != 0);

	struct nl_ifaddrmsg_req req = init_ifaddrmsg_req(RTM_GETADDR, (NLM_F_DUMP | NLM_F_REQUEST),
							 if_name, &unspec_ip_info);

	struct ifinfo_response ifi_rsp = {
		.filter_data.if_name = if_name,
		.filter_data.xfrm_if_id = xfrm_if_id,
		.filter_data.filter_xfrm_if_id = (xfrm_if_id > 0),
	};

	struct linux_netlink_context ctx = {
		.ifi_rsp = &ifi_rsp,
	};
	struct verbose verbose = {
		.logger = logger,
		.rc_flags = (DBGP(DBG_BASE) ? DEBUG_STREAM : LEMPTY),
	};

	if (!linux_netlink_query(&req.n, NETLINK_ROUTE, process_nlmsg, &ctx, verbose)) {
		/* netlink error */
		llog_error(logger, 0/*no-errno*/,
			   "%s() request for all IPs failed", __func__);
		return NULL;
	}

	if (!ifi_rsp.result.ok) {
		ldbg(logger, "%s() no IPs found on interface; that's ok", __func__);
		return NULL;
	}

	return ifi_rsp.result.if_ips;
}

/* Wrapper function for ip_addr_xfrmi_get_all_ips() to find an IP on an
 * XFRMi interface.
 * Returns true if the IP address is found on the IF, false otherwise. */

static bool ip_addr_xfrmi_find_on_if(struct ipsec_interface *xfrmi,
				     ip_cidr *search_ip,
				     struct logger *logger)
{
	if (if_nametoindex(xfrmi->name) == 0) {
		llog_error(logger, errno, "device does not exist [%s]: ", xfrmi->name);
		return false;
	}

	struct ipsec_interface_address *if_ips =
		ip_addr_xfrmi_get_all_ips(xfrmi->name, xfrmi->if_id, logger);
	if (if_ips == NULL) {
		return false;
	}

	/* Iterate the IPs to find a match */
	bool found = false;
	for (struct ipsec_interface_address *x = if_ips; x != NULL; x = x->next) {
		if (cidr_eq_cidr(*search_ip, x->if_ip)) {
			found = true;
			break;
		}
	}

	free_ipsec_interface_address_list(if_ips, logger);
	return found;
}

static err_t ipsec1_support_test(const char *if_name /*non-NULL*/,
				 const char *dev_name /*non-NULL*/,
				 struct logger *logger)
{
	struct verbose verbose = {
		.logger = logger,
		.rc_flags = (DBGP(DBG_BASE) ? DEBUG_STREAM : LEMPTY),
	};
	vdbg("%s() start", __func__);
	verbose.level++;

	/* match any if_id */
	if (find_xfrmi_interface(NULL, 0, verbose)) {
		vdbg("%s() xfrmi interface found", __func__);
		return NULL; /* success: there is already xfrmi interface */
	}

	vdbg("%s() create and delete an xfrmi interface '%s@%s' to test xfrmi support",
	     __func__, if_name, dev_name);
	if (!ip_link_add(if_name, dev_name, IPSEC1_XFRM_IF_ID, logger)) {
		xfrm_interface_support = -1;
		vdbg("%s() xfrmi is not supported. failed to create %s@%s",
		     __func__, if_name, dev_name);
		return "xfrmi is not supported";
	} else {
		if (if_nametoindex(if_name) == 0) {
			llog_error(logger, errno, "cannot find device %s: ", if_name);

			/*
			 * failed to create xfrmi device.
			 * assume kernel support is not enabled.
			 * build kernel with CONFIG_XFRM_INTERFACE=y
			 * to diagnose:
			 * 'ip link add ipsec1 type xfrm if_id 1 dev lo'
			 * 'ip -d link show dev ipsec1'
			 */
			xfrm_interface_support = -1;
			return "missing CONFIG_XFRM_INTERFACE support in kernel";
		}
		vdbg("%s() xfrmi supported success creating %s@%s and delete it",
		     __func__, if_name, dev_name);
		ip_link_del(if_name, logger); /* ignore return value??? */
		xfrm_interface_support = 1; /* success */
	}

	return NULL;
}

static err_t xfrm_iface_supported(struct logger *logger)
{
	err_t err = NULL; /* success */

	if (xfrm_interface_support > 0) {
		return NULL;
	}

	/*
	 * If the previous probe failed, need to re-probe.  For
	 * instance, "ipsec0" could be missing the first time, but is
	 * than added manually.
	 */

	ipsec_interface_id_buf ifb;
	const char *if_name = str_ipsec_interface_id(IPSEC1_XFRM_IF_ID, &ifb); /* must-free */
	static const char lo[] = "lo";

	if (if_nametoindex(lo) == 0) {
		/* possibly no need to panic: may be get
		 * smarter one day */
		xfrm_interface_support = -1;
		return "Could not create find real device needed to test xfrmi support";
	}

	unsigned int if_id = if_nametoindex(if_name);
	int e = errno; /* save error */
	if (if_id == 0 && (e == ENXIO || e == ENODEV)) {
		err = ipsec1_support_test(if_name, lo, logger);
	} else if (if_id == 0) {
		llog_error(logger, e,
			   "unexpected error in xfrm_iface_supported() while checking device %s",
			   if_name);
		xfrm_interface_support = -1;
		err = "cannot decide xfrmi support. assumed no.";
	} else {
		/*
		 * may be more extensive checks?
		 * such if it is a xfrmi device or something else
		 */
		llog(RC_LOG, logger,
		     "conflict %s already exist cannot support xfrm-interface. May be leftover from previous pluto?",
		     if_name);
		xfrm_interface_support = -1;
		err = "device name conflict in xfrm_iface_supported()";
	}

	if (PBAD(logger, xfrm_interface_support < 0 && err == NULL)) {
		err = "may be missing CONFIG_XFRM_INTERFACE support in kernel";
	}

	return err;
}

static bool init_pluto_xfrmi(struct connection *c, uint32_t if_id, bool shared)
{
	c->ipsec_interface = find_ipsec_interface_by_id(if_id);
	if (c->ipsec_interface != NULL) {
		passert(c->ipsec_interface->shared == shared);
		ipsec_interface_addref(c->ipsec_interface, c->logger, HERE);
		return true;
	}

	ipsec_interface_id_buf ifb;
	const char *name = str_ipsec_interface_id(if_id, &ifb);
	alloc_ipsec_interface(if_id, shared, name, c);

	/*
	 * Query the XFRMi IF IPs from netlink and store them, only if
	 * the IF exists.
	 *
	 * Any IPs added now will have pluto_added=false.
	 *
	 * Any new IP created on this interface will be reference
	 * counted later in the call to add_ipsec_interface().
	 */
	if (if_nametoindex(name) == 0) {
		return true;
	}

	struct ipsec_interface_address *if_ips =
		ip_addr_xfrmi_get_all_ips(name, if_id, c->logger);

	if (if_ips == NULL) {
		ldbg(c->logger, "%s() no IP addresses", __func__);
		return true;
	}

	/*
	 * The interface was only just created above.  Hence .if_ips
	 * must be NULL.
	 */
	c->ipsec_interface->if_ips = if_ips;

	return true;
}

/* at start call this to see if there are any stale interface lying around. */
static void check_stale_xfrmi_interfaces(struct logger *logger)
{
	/*
	 * first check quick one do ipsec1 exist. later on add extensive checks
	 * "ip link show type xfrmi" would be better.
	 *  note when type foo is not supported would return success, 0
	 */

	ipsec_interface_id_buf ifb;
	const char *if_name = str_ipsec_interface_id(IPSEC1_XFRM_IF_ID, &ifb);

	unsigned int if_id = if_nametoindex(if_name);
	if (if_id != 0) {
		llog(RC_LOG, logger,
			    "found an unexpected interface %s if_id=%u From previous pluto run?",
			    if_name, if_id);
		return; /* ERROR */
	}
	if (errno == ENXIO || errno == ENODEV) {
		ldbg(logger, "no stale xfrmi interface '%s' found", if_name);
	} else {
		llog_error(logger, errno,
			   "failed stale_xfrmi_interfaces() call if_nametoindex('%s')", if_name);
		return;
	}
}

static void free_xfrmi_ipsec1(struct logger *logger)
{
	ipsec_interface_id_buf ifb;
	const char *if_name = str_ipsec_interface_id(IPSEC1_XFRM_IF_ID, &ifb);

	unsigned int if_id = if_nametoindex(if_name);
	if (if_id > 0) {
		ip_link_del(if_name, logger); /* ignore return value??? */
	}
}

void set_ike_mark_out(const struct connection *c, ip_endpoint *ike_remote)
{
	bool set_mark = false;
	const struct spds *spds = &c->child.spds;

	if (c->ipsec_interface == NULL || c->ipsec_interface->if_id == 0)
		return;

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

	.ip_addr_add = ip_addr_xfrmi_add,
	.ip_addr_del = ip_addr_xfrmi_del,
	.ip_addr_find_on_if = ip_addr_xfrmi_find_on_if,

	.ip_link_set_up = ip_link_set_up,
	.ip_link_add = ip_link_add,
	.ip_link_del = ip_link_del,

	.find_interface = find_xfrmi_interface,

	.init = init_pluto_xfrmi,
	.check_stale_ipsec_interfaces = check_stale_xfrmi_interfaces,
	.supported = xfrm_iface_supported,
	.shutdown = free_xfrmi_ipsec1,
};
