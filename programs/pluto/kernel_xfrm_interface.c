/*
 * xfrmi interface related functions
 *
 * Copyright (C) 2018-2020 Antony Antony <antony@phenome.org>
 * Copyright (C) 2023 Brady Johnson <bradyallenjohnson@gmail.com>
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
#include "kernel_xfrm_interface.h"
#include "kernel_netlink_reply.h"
#include "kernel_netlink_query.h"

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

#define IPSEC1_XFRM_IF_ID (1U)
#define IFINFO_REPLY_BUFFER_SIZE (32768 + NL_BUFMARGIN)
#define IP_ADDR_GLOBAL_SCOPE 0


static struct pluto_xfrmi *pluto_xfrm_interfaces;

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
		uint32_t dev_if_id /* if_id of the dev such as eth0 or lo */;
	} filter_data;

	/* Which fields were matched while reading the NL response */
	struct ifinfo_match {
		bool name;
		bool kind /* aka type in, "ip link show type xfrm" */;
		bool xfrm_if_id /* xfrm if_id */;
		bool dev_if_id;
	} matched;

	bool result; /* final result true success */

	struct pluto_xfrmi result_if;
};

/* -1 missing; 0 uninitialized; 1 present */
static int xfrm_interface_support = 0;

static bool stale_checked;
static uint32_t xfrm_interface_id = IPSEC1_XFRM_IF_ID; /* XFRMA_IF_ID && XFRMA_SET_MARK */

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

static int ip_link_set_up(const char *if_name, struct logger *logger)
{
	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_NEWLINK, NLM_F_REQUEST);
	req.i.ifi_change |= IFF_UP;
	req.i.ifi_flags |= IFF_UP;
	req.i.ifi_index = if_nametoindex(if_name);
	if (req.i.ifi_index == 0) {
		llog_error(logger, errno,
			   "link_set_up_nl() cannot find index of xfrm interface %s",
			   if_name);
		return XFRMI_FAILURE;
	}

	if (!simple_netlink_op(&req.n, "ip_link_set_up", if_name, logger)) {
		return XFRMI_FAILURE;
	}

	return XFRMI_SUCCESS;
}

static int ip_link_del(const char *if_name, const struct logger *logger)
{
	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_DELLINK, NLM_F_REQUEST);
	req.i.ifi_index = if_nametoindex(if_name);
	if (req.i.ifi_index == 0) {
		llog_error(logger, errno, "ip_link_del() cannot find index of interface %s",
			   if_name);
		return XFRMI_FAILURE;
	}

	if (!simple_netlink_op(&req.n, "ip_link_del", if_name, logger)) {
		return XFRMI_FAILURE;
	}

	return XFRMI_SUCCESS;
}

/* errno will be set on error: one caller will report it */
static int dev_exists_check(const char *dev_name /*non-NULL*/)
{
	if (if_nametoindex(dev_name) == 0) {
		return XFRMI_FAILURE;
	}

	return XFRMI_SUCCESS;
}

static int ip_link_add_xfrmi(const char *if_name /*non-NULL*/,
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
		return XFRMI_FAILURE;
	}

	if (!simple_netlink_op(&req.n, "ip_link_add_xfrmi", if_name, logger)) {
		return XFRMI_FAILURE;
	}

	return XFRMI_SUCCESS;
}

static int ifaddrmsg_op(uint16_t type, uint16_t flags,
			const char *if_name,
			const struct pluto_xfrmi_ipaddr *xfrmi_ipaddr,
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
static int ip_addr_xfrmi_add(const char *if_name,
			     const struct pluto_xfrmi_ipaddr *xfrmi_ipaddr,
			     struct logger *logger)
{
	return ifaddrmsg_op(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
			    if_name, xfrmi_ipaddr, logger);
}

/* Delete an IP address from an XFRMi interface using Netlink */
static int ip_addr_xfrmi_del(const char *if_name,
			     const struct pluto_xfrmi_ipaddr *xfrmi_ipaddr,
			     struct logger *logger)
{
	return ifaddrmsg_op(RTM_DELADDR, NLM_F_REQUEST,
			    if_name, xfrmi_ipaddr, logger);
}

/* Get the IP used for the XFRMi IF from the connection.
 * Return an ip_cidr object if found, unset_cidr otherwise. */
static ip_cidr get_xfrmi_ipaddr_from_conn(struct connection *c, struct logger *logger)
{
	const struct child_end_config *child_config = &(c->config->end[LEFT_END].child);

	if (child_config == NULL) {
		llog_error(logger, 0/*no-errno*/,
			   "get_xfrmi_ipaddr_from_conn() child_config is NULL");
		return unset_cidr;
	}

	if (child_config->ifaceip.is_set) {
		ldbg(logger,
			 "get_xfrmi_ipaddr_from_conn() taking IP from ifaceip param for xfrmi IF [%s] id [%d]",
			 c->xfrmi->name, c->xfrmi->if_id);

		return child_config->ifaceip;
	}

	FOR_EACH_ITEM(sip, &child_config->sourceip) {
		/* Use the first sourceip in the list that is set */
		if (sip->is_set) {
			ldbg(logger,
				 "get_xfrmi_ipaddr_from_conn() taking IP from sourceip param for xfrmi IF [%s] id [%d]",
				 c->xfrmi->name, c->xfrmi->if_id);
			return cidr_from_address(*sip);
		}
	}

	/* This is how the updown script previously got the source IP,
	 * especially for the road warrior configuration */
	FOR_EACH_ITEM(spd, &c->child.spds) {
		/* Use the first sourceip in the list that is set */
		ip_address spd_sourceip = spd_end_sourceip(spd->local);
		if (spd_sourceip.is_set) {
			ldbg(logger,
				"get_xfrmi_ipaddr_from_conn() taking IP from spd_end_sourceip() for xfrmi IF [%s] id [%d]",
				c->xfrmi->name, c->xfrmi->if_id);
			return cidr_from_address(spd_sourceip);
		}
	}

	ldbg(logger,
		 "get_xfrmi_ipaddr_from_conn() No IPs found on connection for xfrmi IF [%s] id [%d].",
		  c->xfrmi->name, c->xfrmi->if_id);

	return unset_cidr;
}

/* Create an internal XFRMi Interface IP address structure */
static struct pluto_xfrmi_ipaddr *create_xfrmi_ipaddr(struct pluto_xfrmi *xfrmi_if,
						      ip_cidr if_ip)
{
	if (xfrmi_if == NULL) {
		return NULL;
	}

	/* Create a new ref-counted xfrmi_ip_addr.
	 * The call to refcnt_alloc() counts as a reference */
	struct pluto_xfrmi_ipaddr *new_xfrmi_ipaddr =
			refcnt_alloc(struct pluto_xfrmi_ipaddr, HERE);
	new_xfrmi_ipaddr->next = NULL;
	new_xfrmi_ipaddr->pluto_added = false;
	new_xfrmi_ipaddr->if_ip = if_ip;

	if (xfrmi_if->if_ips == NULL) {
		xfrmi_if->if_ips = new_xfrmi_ipaddr;
		return new_xfrmi_ipaddr;
	}

	struct pluto_xfrmi_ipaddr *prev = NULL;
	struct pluto_xfrmi_ipaddr *xfrmi_ipaddr = xfrmi_if->if_ips;
	while (xfrmi_ipaddr != NULL) {
		prev = xfrmi_ipaddr;
		xfrmi_ipaddr = xfrmi_ipaddr->next;
	}
	prev->next = new_xfrmi_ipaddr;

	return new_xfrmi_ipaddr;
}

static struct pluto_xfrmi_ipaddr *find_xfrmi_ipaddr(struct pluto_xfrmi *xfrmi,
													ip_cidr *search_cidr,
													struct logger *logger)
{
	if (xfrmi == NULL) {
		llog_error(logger, 0/*no-errno*/,
			   "find_xfrmi_ipaddr() xfrmi is NULL");
		return NULL;
	}

	struct pluto_xfrmi_ipaddr *xfrmi_ipaddr;
	for (xfrmi_ipaddr = xfrmi->if_ips; xfrmi_ipaddr != NULL; xfrmi_ipaddr = xfrmi_ipaddr->next) {
		if (cidr_eq_cidr(xfrmi_ipaddr->if_ip, *search_cidr)) {
			cidr_buf cb;
			ldbg(logger, "%s() found IP [%s] for xfrmi IF [%s] id [%d]",
			     __func__,
			     str_cidr(&xfrmi_ipaddr->if_ip, &cb),
			     xfrmi->name, xfrmi->if_id);

			return xfrmi_ipaddr;
		}
	}

	ldbg(logger, "find_xfrmi_ipaddr() No internal IPs found.");

	return NULL;
}

static void free_xfrmi_ipaddr_list(struct pluto_xfrmi_ipaddr *xfrmi_ipaddr, struct logger *logger)
{
	struct pluto_xfrmi_ipaddr *xi = xfrmi_ipaddr;
	struct pluto_xfrmi_ipaddr *xi_next = NULL;

	while (xi != NULL) {
		/* step off IX */
		xi_next = xi->next;
		/*
		 * When the list is allocated with interface IPs not
		 * created by pluto, then they were never
		 * unreference'd, so we'll have to do it here
		 *
		 * XXX: since XI is non-NULL this must always be
		 * true?
		 *
		 * XXX: forcing the deletion of all references
		 * suggests that something elsewhere is leaking these?
		 */
		if (refcnt_peek(xi, logger) > 0) {
			struct pluto_xfrmi_ipaddr *xi_unref_result = NULL;
			do {
				/* delref_where() sets the pointer passed in to NULL
				 * delref_where() will return NULL until the refcount is 0 */
				struct pluto_xfrmi_ipaddr *xi_unref = xi;
				xi_unref_result = delref_where(&xi_unref, logger, HERE);
			} while(xi_unref_result == NULL);
		}
		pfreeany(xi);
		xi = xi_next;
	}
}

static void reference_xfrmi_ip(struct pluto_xfrmi *xfrmi, struct pluto_xfrmi_ipaddr *xfrmi_ipaddr)
{
	addref_where(xfrmi_ipaddr, HERE);
	dbg("reference xfrmi_ipaddr=%p name=%s if_id=%u refcount=%u (after)",
			xfrmi_ipaddr, xfrmi->name, xfrmi->if_id,
	    refcnt_peek(xfrmi_ipaddr, &global_logger));
}

static void unreference_xfrmi_ip(struct connection *c, struct logger *logger)
{
	ip_cidr conn_xfrmi_cidr = get_xfrmi_ipaddr_from_conn(c, logger);
	if (conn_xfrmi_cidr.is_set == false) {
		ldbg(logger,
			 "unreference_xfrmi_ip() No IP to unreference on xfrmi device [%s] id [%d]",
			 c->xfrmi->name, c->xfrmi->if_id);
		return;
	}

	/* Get the existing referenced IP */
	struct pluto_xfrmi_ipaddr *refd_xfrmi_ipaddr =
			find_xfrmi_ipaddr(c->xfrmi, &conn_xfrmi_cidr, logger);
	if (refd_xfrmi_ipaddr == NULL) {
		/* This should never happen */
		llog_error(logger, 0/*no-errno*/,
				   "unreference_xfrmi_ip() Unable to unreference IP on xfrmi device [%s] id [%d]",
				   c->xfrmi->name, c->xfrmi->if_id);
		return;
	}

	cidr_buf cb;
	ldbg(logger, "%s() xfrmi_ipaddr=%p name=%s if_id=%u IP [%s] refcount=%u (before).",
	     __func__,
	     refd_xfrmi_ipaddr, c->xfrmi->name, c->xfrmi->if_id,
	     str_cidr(&refd_xfrmi_ipaddr->if_ip, &cb),
	     refcnt_peek(refd_xfrmi_ipaddr, logger));

	/* Decrement the reference:
	 * - The pointer passed in will be set to NULL
	 * - Returns a pointer to the object when its the last one */
	struct pluto_xfrmi_ipaddr *xfrmi_ipaddr_unref = delref_where(&refd_xfrmi_ipaddr, logger, HERE);
	if (xfrmi_ipaddr_unref == NULL) {
		ldbg(logger, "unreference_xfrmi_ip() delref returned NULL, simple delref");
		return;
	}

	/* Remove the entry from the ip_ips list */
	if (c->xfrmi->if_ips == xfrmi_ipaddr_unref) {
		c->xfrmi->if_ips = xfrmi_ipaddr_unref->next;
	} else {
		struct pluto_xfrmi_ipaddr *prev = NULL;
		struct pluto_xfrmi_ipaddr *p = c->xfrmi->if_ips;

		while (p != NULL && p != xfrmi_ipaddr_unref) {
			cidr_buf cb;
			ldbg(logger, "p=%p xfrmi_ipaddr=%p IP [%s]",
			     p, xfrmi_ipaddr_unref,
			     str_cidr(&xfrmi_ipaddr_unref->if_ip, &cb));
			prev = p;
			p = p->next;
		}

		if (p == NULL) {
			cidr_buf cb;
			ldbg(logger, "p=%p xfrmi=%s if_id=%u IP [%s] not found in the list",
			     c->xfrmi, c->xfrmi->name, c->xfrmi->if_id,
			     str_cidr(&xfrmi_ipaddr_unref->if_ip, &cb));
		} else {
			prev->next = p->next;
		}
	}

	/* Check if the IP should be removed from the interface */
	if (xfrmi_ipaddr_unref->pluto_added) {
		ip_addr_xfrmi_del(c->xfrmi->name, xfrmi_ipaddr_unref, logger);
		cidr_buf cb;
		llog(RC_LOG, logger,
		     "delete ipsec-interface=%s if_id=%u IP [%s] added by pluto",
		     c->xfrmi->name, c->xfrmi->if_id,
		     str_cidr(&xfrmi_ipaddr_unref->if_ip, &cb));
	} else {
		cidr_buf cb;
		llog(RC_LOG, logger,
		     "cannot delete ipsec-interface=%s if_id=%u IP [%s], not created by pluto",
		     c->xfrmi->name, c->xfrmi->if_id,
		     str_cidr(&xfrmi_ipaddr_unref->if_ip, &cb));
	}

	/* Free the memory */
	pfreeany(xfrmi_ipaddr_unref);
}

static int parse_xfrm_linkinfo_data(struct rtattr *attribute, const char *if_name,
				    struct ifinfo_response *ifi_rsp,
				    struct verbose verbose)
{
	vdbg("%s() start", __func__);
	verbose.level++;
	struct rtattr *nested_attrib;
	const struct rtattr *dev_if_id_attr = NULL;
	const struct rtattr *if_id_attr = NULL;

	for (nested_attrib = (struct rtattr *) RTA_DATA(attribute);
			RTA_OK(nested_attrib, attribute->rta_len);
			nested_attrib = RTA_NEXT(nested_attrib,
				attribute->rta_len)) {
		if (nested_attrib->rta_type == IFLA_XFRM_LINK) {
			vdbg("%s() found IFLA_XFRM_LINK aka dev_if_id_attr", __func__);
			dev_if_id_attr = nested_attrib;
		}

		if (nested_attrib->rta_type == IFLA_XFRM_IF_ID) {
			vdbg("%s() found IFLA_XFRM_IF_ID aka if_id_attr", __func__);
			if_id_attr = nested_attrib;
		}
	}

	if (dev_if_id_attr != NULL) {
		uint32_t dev_if_id = *((const uint32_t *)RTA_DATA(dev_if_id_attr));
		ifi_rsp->result_if.dev_if_id = dev_if_id;
		vdbg("%s() setting .result_if.dev_if_id to %d", __func__, dev_if_id);
		if (dev_if_id == ifi_rsp->filter_data.dev_if_id) {
			vdbg("%s() dev_if_id %d matched .filter_data.dev_if_id %d; setting .matched.dev_if_id",
			     __func__, dev_if_id, ifi_rsp->filter_data.dev_if_id);
			ifi_rsp->matched.dev_if_id = true;
		}
	}

	if (if_id_attr == NULL) {
		vdbg("%s() failed, id_id_attr not found", __func__);
		return -1;
	}

	uint32_t xfrm_if_id = *((const uint32_t *)RTA_DATA(if_id_attr));
	if (ifi_rsp->filter_data.filter_xfrm_if_id) {
		if (xfrm_if_id == ifi_rsp->filter_data.xfrm_if_id) {
			vdbg("%s() xfrm_if_id %d matched .filter_data.xfrm_if_id %d; setting .matched.xfrm_if_id and .result_if.if_id",
			     __func__, xfrm_if_id, ifi_rsp->filter_data.xfrm_if_id);
			ifi_rsp->result_if.if_id = xfrm_if_id;
			ifi_rsp->matched.xfrm_if_id = true;
		} else {
			vdbg("%s() failed, xfrm_if_id %d did not match .filter_data.xfrm_if_id %d",
			     __func__, xfrm_if_id, ifi_rsp->filter_data.xfrm_if_id);
			return -2;
		}
	} else {
		vdbg("%s() wildcard matched xfrm_if_id %d, setting .result_if.if_id",
		     __func__, xfrm_if_id);
		ifi_rsp->result_if.if_id = xfrm_if_id;
	}

	/* trust kernel if_name != NULL */
	ifi_rsp->result_if.name = clone_str(if_name, "xfrmi name from kernel");

	/* if it came this far found what we looking for */
	vdbg("%s() succeeded; setting .result", __func__);
	ifi_rsp->result = true;
	return XFRMI_SUCCESS;
}

static int parse_link_info_xfrm(struct rtattr *attribute, const char *if_name,
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

	if (ifi_rsp->matched.kind && info_data_attr !=  NULL) {
		return parse_xfrm_linkinfo_data(info_data_attr, if_name, ifi_rsp, verbose);
	} else {
		return XFRMI_FAILURE;
	}
}

static int parse_nl_newlink_msg(struct nlmsghdr *nlmsg, struct ifinfo_response *ifi_rsp,
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
			if_name =  (char *) RTA_DATA(attribute); /* tmp */
			break;

		case IFLA_LINKINFO:
			linkinfo_attr = attribute;
			break;

		default:
			break;
		}
	}

	if (if_name == NULL)
		return XFRMI_FAILURE;

	if (linkinfo_attr == NULL)
		return XFRMI_FAILURE;

	if (ifi_rsp->filter_data.if_name != NULL) {
		if (streq(ifi_rsp->filter_data.if_name, if_name)) {
			/* name match requested and matched */
			ifi_rsp->matched.name = true;
		} else {
			return XFRMI_FAILURE;
		}
	}

	return parse_link_info_xfrm(linkinfo_attr, if_name, ifi_rsp, verbose);
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

		if (if_rsp->result_if.name == NULL) {
			/* Does if_indextoname() guarantee NUL
			 * termination?  Perhaps.  It does assume
			 * IF_NAMESIZE buffer.  */
			char if_name_buf[IF_NAMESIZE];
			if_indextoname(ifa->ifa_index, if_name_buf);
			/* This works even when IF_NAME_BUF lacks a
			 * terminating NUL. */
			if_rsp->result_if.name = clone_thing_as_string(if_name_buf, "parse_linkinfo_data");
		}

		create_xfrmi_ipaddr(&if_rsp->result_if, if_ip);
		ldbg(logger, "%s() matching message for if_name %s",
		     __func__, if_rsp->result_if.name);
		if_rsp->result = true;
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
		if (parse_nl_newlink_msg(nlmsg, ifi_rsp, verbose) == XFRMI_SUCCESS &&
		    ifi_rsp->result)
			return true;
		return true;

	case RTM_NEWADDR:
		parse_newaddr_msg(nlmsg, ifi_rsp, verbose.logger);
		return true;
	}

	vdbg("ignored message type %d length %d", nlmsg->nlmsg_type,
	     nlmsg->nlmsg_len);
	return true;
}

static int find_xfrmi_interface(const char *if_name, /* optional */
				 uint32_t xfrm_if_id,
				 struct logger *logger)
{
	struct verbose verbose = {
		.logger = logger,
		.rc_flags = (DBGP(DBG_BASE) ? DEBUG_STREAM : LEMPTY),
	};
	vdbg("%s() start", __func__);
	verbose.level++;

	/* first do a cheap check */
	if (if_name != NULL && dev_exists_check(if_name) != XFRMI_SUCCESS) {
		vdbg("%s() failed, if_nametoindex(%s) returned zero", __func__, if_name);
		return XFRMI_FAILURE;
	}

	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_GETLINK,
						  (NLM_F_REQUEST | NLM_F_DUMP));

	struct ifinfo_response ifi_rsp;
	zero(&ifi_rsp);

	ifi_rsp.filter_data.if_name = if_name;
	if (xfrm_if_id > 0) {/* we deal with only > 0 */
		ifi_rsp.filter_data.filter_xfrm_if_id = true;
	}
	ifi_rsp.filter_data.xfrm_if_id = xfrm_if_id;

	struct linux_netlink_context ctx = {
		.ifi_rsp = &ifi_rsp,
	};

	if (!linux_netlink_query(&req.n, NETLINK_ROUTE, process_nlmsg, &ctx, verbose)) {
		vdbg("%s() failed, linux_netlink_query() failed", __func__);
		return XFRMI_FAILURE;
	}

	if (ifi_rsp.result) {
		char if_name_buf[IF_NAMESIZE];
		if_indextoname(ifi_rsp.result_if.dev_if_id, if_name_buf);
		vdbg("%s() support found existing %s@%s (xfrm) .result_if.if_id %s %d .result_if.dev_if_id %s %d",
		     __func__, ifi_rsp.result_if.name, if_name_buf,
		     bool_str(ifi_rsp.matched.xfrm_if_id), ifi_rsp.result_if.if_id,
		     bool_str(ifi_rsp.matched.dev_if_id), ifi_rsp.result_if.dev_if_id);
		pfreeany(ifi_rsp.result_if.name);
		return XFRMI_SUCCESS;
	}

	pfreeany(ifi_rsp.result_if.name);

	return XFRMI_FAILURE;
}

static int find_any_xfrmi_interface(struct logger *logger)
{
	int retval = find_xfrmi_interface(NULL, 0, logger);
	if (retval != XFRMI_SUCCESS) {
		ldbg(logger, "%s no xfrmi interface found", __func__);
	}

	return retval;
}

/* Get all of the IP addresses on an XFRMi interface using Netlink */
static struct ifinfo_response *ip_addr_xfrmi_get_all_ips(struct pluto_xfrmi *xfrmi, struct logger *logger)
{
	/* first do a cheap check */
	if (xfrmi->name != NULL && dev_exists_check(xfrmi->name) != XFRMI_SUCCESS) {
		llog_error(logger, 0/*no-errno*/,
			   "ip_addr_xfrmi_get_all_ips device does not exist [%s]",
			   (xfrmi->name == NULL ? "NULL" : xfrmi->name));
		return NULL;
	}

	struct nl_ifaddrmsg_req req = init_ifaddrmsg_req(RTM_GETADDR, (NLM_F_DUMP | NLM_F_REQUEST),
							 xfrmi->name, &unspec_ip_info);

	struct ifinfo_response *ifi_rsp = alloc_bytes(sizeof(struct ifinfo_response), "ifinfo_response");
	zero(ifi_rsp);

	ifi_rsp->filter_data.if_name = xfrmi->name;
	if (xfrmi->if_id > 0) {/* we deal with only > 0 */
		ifi_rsp->filter_data.filter_xfrm_if_id = true;
	}
	ifi_rsp->filter_data.xfrm_if_id = xfrmi->if_id;

	struct linux_netlink_context ctx = {
		.ifi_rsp = ifi_rsp,
	};
	struct verbose verbose = {
		.logger = logger,
		.rc_flags = (DBGP(DBG_BASE) ? DEBUG_STREAM : LEMPTY),
	};
	if (!linux_netlink_query(&req.n, NETLINK_ROUTE, process_nlmsg, &ctx, verbose)) {
		pfree(ifi_rsp);
		return NULL;
	}

	return ifi_rsp;
}

/* Wrapper function for ip_addr_xfrmi_get_all_ips() to find an IP on an
 * XFRMi interface.
 * Returns true if the IP address is found on the IF, false otherwise. */
static bool ip_addr_xfrmi_find_on_if(struct pluto_xfrmi *xfrmi, ip_cidr *search_ip, struct logger *logger)
{
	struct ifinfo_response *ifi_rsp = ip_addr_xfrmi_get_all_ips(xfrmi, logger);

	if (ifi_rsp == NULL) {
		llog_error(logger, 0/*no-errno*/,
			   "ip_addr_xfrmi_find_on_if() ifinfo_response NULL");
		return false;
	}

	if (ifi_rsp->result != true) {
		ldbg(logger, "ip_addr_xfrmi_find_on_if() no IPs found on interface.");
		pfreeany(ifi_rsp->result_if.name);
		pfreeany(ifi_rsp);
		return false;
	}

	/* Iterate the IPs to find a match */
	struct pluto_xfrmi_ipaddr *x;
	for (x = ifi_rsp->result_if.if_ips; x != NULL; x = x->next) {
		if (cidr_eq_cidr(*search_ip, x->if_ip)) {
			free_xfrmi_ipaddr_list(ifi_rsp->result_if.if_ips, logger);
			pfreeany(ifi_rsp->result_if.name);
			pfreeany(ifi_rsp);
			return true;
		}
	}

	free_xfrmi_ipaddr_list(ifi_rsp->result_if.if_ips, logger);
	pfreeany(ifi_rsp->result_if.name);
	pfreeany(ifi_rsp);
	return false;
}

/* Wrapper function for ip_addr_xfrmi_get_all_ips() to query all of the
 * IPs on an XFRMi interface in Netlink and store them.
 * Returns XFRMI_SUCCESS if the IPs can be retrieved and stored,
 * XFRMI_FAILURE otherwise. */
static int ip_addr_xfrmi_store_ips(struct pluto_xfrmi *xfrmi, struct logger *logger)
{
	struct ifinfo_response *ifi_rsp = ip_addr_xfrmi_get_all_ips(xfrmi, logger);

	if (ifi_rsp == NULL) {
		llog_error(logger, 0/*no-errno*/,
			   "ip_addr_xfrmi_store_ips() ifinfo_response NULL");
		return XFRMI_FAILURE;
	}

	if (ifi_rsp->result != true) {
		ldbg(logger, "ip_addr_xfrmi_store_ips() no IPs found on interface.");
		pfreeany(ifi_rsp->result_if.name);
		pfreeany(ifi_rsp);
		/* No IPs on the interface is still a successful operation */
		return XFRMI_SUCCESS;
	}

	/* Notice: this function will only ever be called upon XFRMi interface setup
	 * and there will not be any existing interface IPs to merge here. */
	xfrmi->if_ips = ifi_rsp->result_if.if_ips;
	pfreeany(ifi_rsp->result_if.name);
	pfreeany(ifi_rsp);

	return XFRMI_SUCCESS;
}

static err_t ipsec1_support_test(const char *if_name /*non-NULL*/,
				 const char *dev_name /*non-NULL*/,
				 struct logger *logger)
{
	if (!find_any_xfrmi_interface(logger))
		return NULL; /* success: there is already xfrmi interface */

	ldbg(logger,
	     "create and delete an xfrmi interface '%s@%s' to test xfrmi support",
	     if_name, dev_name);
	if (ip_link_add_xfrmi(if_name, dev_name, xfrm_interface_id, logger) != XFRMI_SUCCESS) {
		xfrm_interface_support = -1;
		ldbg(logger, "xfrmi is not supported. failed to create %s@%s", if_name, dev_name);
		return "xfrmi is not supported";
	} else {
		if (dev_exists_check(if_name) != XFRMI_SUCCESS) {
			llog_error(logger, errno,
				   "cannot find device %s", if_name);

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
		ldbg(logger,
		     "xfrmi supported success creating %s@%s and delete it",
		     if_name, dev_name);
		ip_link_del(if_name, logger); /* ignore return value??? */
		xfrm_interface_support = 1; /* success */
	}

	return NULL;
}

/*
 * format the name of xfrmi interface. To maintain consistency
 * on longer names won't be truncated, instead passert.
 * The caller MUST free the string.
 */
static char *fmt_xfrmi_ifname(uint32_t if_id)
{
	char *if_name = alloc_things(char, IFNAMSIZ, "xfrmi name");
	/* remap if_id PLUTO_XFRMI_REMAP_IF_ID_ZERO to ipsec0 as special case */
	int n = snprintf(if_name, IFNAMSIZ, XFRMI_DEV_FORMAT,
		 if_id == PLUTO_XFRMI_REMAP_IF_ID_ZERO ? 0  : if_id);
	passert(n < IFNAMSIZ);
	return if_name;
}

err_t xfrm_iface_supported(struct logger *logger)
{
	err_t err = NULL; /* success */

	if (xfrm_interface_support == 0) {
		char *if_name = fmt_xfrmi_ifname(IPSEC1_XFRM_IF_ID);
		static const char lo[] = "lo";

		if (dev_exists_check(lo) != XFRMI_SUCCESS) {
			/* possibly no need to panic: may be get smarter one day */
			xfrm_interface_support = -1;
			pfreeany(if_name);
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
		pfreeany(if_name);
	}

	if (xfrm_interface_support < 0 && err == NULL)
		err = "may be missing CONFIG_XFRM_INTERFACE support in kernel";

	return err;
}

static struct pluto_xfrmi *find_pluto_xfrmi_interface(uint32_t if_id)
{
	struct pluto_xfrmi *h;
	struct pluto_xfrmi *ret = NULL;

	for (h = pluto_xfrm_interfaces;  h != NULL; h = h->next) {
		if (h->if_id == if_id) {
			ret = h;
			break;
		}
	}

	return ret;
}

static void new_pluto_xfrmi(uint32_t if_id, bool shared, char *name, struct connection *c)
{
	struct pluto_xfrmi **head = &pluto_xfrm_interfaces;
	/* Create a new ref-counted xfrmi, it is not added to system yet.
	 * The call to refcnt_alloc() counts as a reference */
	struct pluto_xfrmi *p = refcnt_alloc(struct pluto_xfrmi, HERE);
	p->if_id = if_id;
	p->name = name;
	c->xfrmi = p;
	p->next = *head;
	*head = p;
	c->xfrmi = p;
	c->xfrmi->shared = shared;
}

static int init_pluto_xfrmi(struct connection *c, uint32_t if_id, bool shared)
{
	c->xfrmi = find_pluto_xfrmi_interface(if_id);
	char *xfrmi_name = fmt_xfrmi_ifname(if_id);
	if (c->xfrmi == NULL) {
		/*
		if (!shared) {
			log_state(RC_LOG, st, "%s, index %u, xfrm interface exist will not shared",
				       xfrmi_name, if_id);
			return XFRMI_FAILURE;
		}
		*/
		new_pluto_xfrmi(if_id, shared, xfrmi_name, c);

		/* Query the XFRMi IF IPs from netlink and store them, only if the IF exists.
		 * Any IPs added now will have pluto_added=false.
		 * Any new IP created on this interface will be reference counted later
		 * in the call to add_xfrm_interface(). */
		if (dev_exists_check(xfrmi_name) == XFRMI_SUCCESS) {
			ip_addr_xfrmi_store_ips(c->xfrmi, c->logger);
		}
	} else {
		pfreeany(xfrmi_name);
		passert(c->xfrmi->shared == shared);
		reference_xfrmi(c);
	}

	return XFRMI_SUCCESS;
}

/* Only called by add_xfrm_interface() */
static bool add_xfrm_interface_ip(struct connection *c, ip_cidr *conn_xfrmi_cidr, struct logger *logger)
{
	/* Get the existing referenced IP, or create it if it doesn't exist */
	struct pluto_xfrmi_ipaddr *refd_xfrmi_ipaddr =
			find_xfrmi_ipaddr(c->xfrmi, conn_xfrmi_cidr, logger);
	if (refd_xfrmi_ipaddr == NULL) {
		/* This call will refcount the object */
		refd_xfrmi_ipaddr = create_xfrmi_ipaddr(c->xfrmi, *conn_xfrmi_cidr);
		cidr_buf cb;
		ldbg(logger,
		     "%s() created new pluto_xfrmi_ipaddr dev [%s] id [%d] IP [%s]",
		     __func__, c->xfrmi->name, c->xfrmi->if_id,
		     str_cidr(&refd_xfrmi_ipaddr->if_ip, &cb));
	} else {
		/* The IP already exists, reference count it */
		reference_xfrmi_ip(c->xfrmi, refd_xfrmi_ipaddr);
	}

	/* Check if the IP is already defined on the interface */
	bool ip_on_if = ip_addr_xfrmi_find_on_if(c->xfrmi, &(refd_xfrmi_ipaddr->if_ip), logger);
	if (ip_on_if == false) {
		refd_xfrmi_ipaddr->pluto_added = true;
		if (ip_addr_xfrmi_add(c->xfrmi->name, refd_xfrmi_ipaddr, logger) != XFRMI_SUCCESS) {
			llog_error(logger, 0/*no-errno*/,
					"Unable to add IP address to XFRMi interface %s xfrm_if_id %u.",
						c->xfrmi->name, c->xfrmi->if_id);
			return false;
		}
	}

	return true;
}

diag_t setup_xfrm_interface(struct connection *c, const char *ipsec_interface)
{
	ldbg(c->logger, "parsing ipsec-interface=%s", ipsec_interface);

	/*
	 * Danger; yn_option_names includes "0" and "1" but that isn't
	 * wanted here!  Hence yn_text_option_names.
	 */
	const struct sparse_name *yn = sparse_lookup(&yn_text_option_names, shunk1(ipsec_interface));
	if (yn != NULL && yn->value == YN_NO) {
		/* well that was pointless */
		ldbg(c->logger, "ipsec-interface=%s is no!", ipsec_interface);
		return NULL;
	}

	/* something other than ipsec-interface=no, check support */
	err_t err = xfrm_iface_supported(c->logger);
	if (err != NULL) {
		return diag("ipsec-interface=%s not supported: %s",
			    ipsec_interface, err);
	}

	uint32_t xfrm_if_id;
	if (yn != NULL) {
		PEXPECT(c->logger, yn->value == YN_YES);
		xfrm_if_id = 1; /* YES means 1 */
	} else {
		uintmax_t value;
		err_t e = shunk_to_uintmax(shunk1(ipsec_interface), /*cursor*/NULL,
					   /*base*/10, &value);
		if (e != NULL) {
			return diag("ipsec-interface=%s invalid: %s", ipsec_interface, e);
		}

		if (value >= UINT32_MAX) {
			return diag("ipsec-interface=%s is too big", ipsec_interface);
		}

		if (value == 0) {
			ldbg(c->logger, "remap ipsec0");
			/* XXX: why? */
			xfrm_if_id = PLUTO_XFRMI_REMAP_IF_ID_ZERO;
		} else {
			xfrm_if_id = value;
		}
	}

	bool shared = true;
	ldbg(c->logger, "ipsec-interface=%s parsed to %"PRIu32, ipsec_interface, xfrm_if_id);

	/* always success for now */
	if (init_pluto_xfrmi(c, xfrm_if_id, shared) != XFRMI_SUCCESS) {
		return diag("setting up ipsec-interface=%s failed", ipsec_interface);
	}

	return NULL;
}

/* Return true on success, false on failure */
bool add_xfrm_interface(struct connection *c, struct logger *logger)
{
	passert(c->xfrmi->name != NULL);
	passert(c->iface->real_device_name != NULL);

	if (dev_exists_check(c->xfrmi->name) != XFRMI_SUCCESS) {
		if (ip_link_add_xfrmi(c->xfrmi->name,
				      c->iface->real_device_name,
				      c->xfrmi->if_id,
				      logger) != XFRMI_SUCCESS) {
			return false;
		}

		c->xfrmi->pluto_added = true;
	} else {
		/* device exists: match name, type xfrmi, and xfrm_if_id */
		if (find_xfrmi_interface(c->xfrmi->name, c->xfrmi->if_id, logger) != XFRMI_SUCCESS) {
			/* found wrong device abort adding */
			llog_error(logger, 0/*no-errno*/,
				   "device %s exist and do not match expected type xfrm or xfrm_if_id %u. check 'ip -d link show dev %s'",
				   c->xfrmi->name, c->xfrmi->if_id, c->xfrmi->name);
			return false;
		}
	}

	/*
	 * Get the IP to use on the XFRMi interface from the connection.
	 * - If it doesn't exist, nothing to add to the interface
	 */
	ip_cidr conn_xfrmi_cidr = get_xfrmi_ipaddr_from_conn(c, logger);
	if (conn_xfrmi_cidr.is_set == false) {
		ldbg(logger,
				"No IP to set on xfrmi device [%s] id [%d]",
				c->xfrmi->name, c->xfrmi->if_id);
	} else {
		if (!add_xfrm_interface_ip(c, &conn_xfrmi_cidr, logger)) {
			return false;
		}
	}

	return (ip_link_set_up(c->xfrmi->name, logger) == XFRMI_SUCCESS);
}

/* at start call this to see if there are any stale interface lying around. */
void stale_xfrmi_interfaces(struct logger *logger)
{
	if (stale_checked)
		return; /* possibly from second whack listen */

	stale_checked = true; /* do not re-enter */

	/*
	 * first check quick one do ipsec1 exist. later on add extensive checks
	 * "ip link show type xfrmi" would be better.
	 *  note when type foo is not supported would return success, 0
	 */

	char if_name[IFNAMSIZ];
	snprintf(if_name, sizeof(if_name), XFRMI_DEV_FORMAT, IPSEC1_XFRM_IF_ID); /* first one ipsec1 */

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

void free_xfrmi_ipsec1(struct logger *logger)
{
	char if_name[IFNAMSIZ];
	snprintf(if_name, sizeof(if_name), XFRMI_DEV_FORMAT, IPSEC1_XFRM_IF_ID); /* global ipsec1 */
	unsigned int if_id = if_nametoindex(if_name);

	if (if_id > 0) {
		ip_link_del(if_name, logger); /* ignore return value??? */
	}
}

void reference_xfrmi(struct connection *c)
{
	struct logger *logger = c->logger;
	addref_where(c->xfrmi, HERE);
	ldbg(logger, "reference xfrmi=%p name=%s if_id=%u refcount=%u (after)", c->xfrmi,
	     c->xfrmi->name, c->xfrmi->if_id,
	     refcnt_peek(c->xfrmi, c->logger));
}

void unreference_xfrmi(struct connection *c)
{
	struct logger *logger = c->logger;
	PASSERT(logger, c->xfrmi != NULL);

	ldbg(logger, "unreference xfrmi=%p name=%s if_id=%u refcount=%u (before).",
	     c->xfrmi, c->xfrmi->name, c->xfrmi->if_id,
	     refcnt_peek(c->xfrmi, c->logger));

	unreference_xfrmi_ip(c, logger);

	struct pluto_xfrmi *xfrmi = delref_where(&c->xfrmi, logger, HERE);
	if (xfrmi != NULL) {
		struct pluto_xfrmi **pp;
		struct pluto_xfrmi *p;
		for (pp = &pluto_xfrm_interfaces; (p = *pp) != NULL; pp = &p->next) {
			if (p == xfrmi) {
				*pp = p->next;
				if (xfrmi->pluto_added) {
					ip_link_del(xfrmi->name, logger);
					llog(RC_LOG, logger,
					     "delete ipsec-interface=%s if_id=%u added by pluto",
					     xfrmi->name, xfrmi->if_id);
				} else {
					ldbg(logger,
					     "skipping delete ipsec-interface=%s if_id=%u, never added pluto",
					     xfrmi->name, xfrmi->if_id);
				}
				/* Free the IPs that were already on the interface (not added by pluto)
				 * and added as such in: init_pluto_xfrmi()->ip_addr_xfrmi_store_ips() */
				free_xfrmi_ipaddr_list(xfrmi->if_ips, logger);
				pfreeany(xfrmi->name);
				pfreeany(xfrmi);
				return;
			}
			ldbg(logger, "p=%p xfrmi=%p", p, xfrmi);
		}
		ldbg(logger, "p=%p xfrmi=%s if_id=%u not found in the list", xfrmi,
		     xfrmi->name, xfrmi->if_id);
	}
}

void set_ike_mark_out(const struct connection *c, ip_endpoint *ike_remote)
{
	bool set_mark = false;
	const struct spds *spds = &c->child.spds;

	if (c->xfrmi == NULL || c->xfrmi->if_id == 0)
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
		mark_out = c->xfrmi->if_id;

	if (ike_remote->mark_out != 0)
		passert(ike_remote->mark_out == mark_out);

	ike_remote->mark_out = mark_out;
}
