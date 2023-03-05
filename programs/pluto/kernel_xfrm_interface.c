/*
 * xfrmi interface related functions
 *
 * Copyright (C) 2018-2020 Antony Antony <antony@phenome.org>
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
#include "server.h" /* for struct iface_endpoint */
#include "iface.h"
#include "log.h"

#define IPSEC1_XFRM_IF_ID (1U)
#define IFINFO_REPLY_BUFFER_SIZE (32768 + NL_BUFMARGIN)


static struct pluto_xfrmi *pluto_xfrm_interfaces;

struct nl_ifinfomsg_req {
	struct nlmsghdr n;
	struct ifinfomsg i;
	char data[NETLINK_REQ_DATA_SIZE];
	size_t maxlen;
};

struct ifinfo_response {
	struct ifinfo_req {
		const char *if_name;
		uint32_t xfrm_if_id;
		bool filter_xfrm_if_id /* because if_id can be zero too */;
		uint32_t dev_if_id /* if_id of the dev such as eth0 or lo */;
	} req;

	struct ifinfo_match {
		bool name;
		bool kind /* aka type in, "ip link show type xfrm" */;
		bool xfrm_if_id /* xfrm if_id */;
		bool dev_if_id;
	} match;

	bool result; /* final result true success */

	struct pluto_xfrmi result_if;
};

/* -1 missing; 0 uninitialized; 1 present */
static int xfrm_interface_support = 0;

static bool stale_checked;
static uint32_t xfrm_interface_id = IPSEC1_XFRM_IF_ID; /* XFRMA_IF_ID && XFRMA_SET_MARK */

/* Forward declaration */
static void free_xfrmi(void *object, const struct logger *logger, where_t where);

/* Return 0 (XFRMI_SUCCESS) on success or non-zero (XFRMI_FAILURE) on failure.
 * Later, if necessary, more detailed failure codes can be returned. */
static int nl_query_small_resp(const struct nlmsghdr *req,
			       const char *context,
			       const char *if_name,
			       const struct logger *logger)
{
	int nl_fd = nl_send_query(req, NETLINK_ROUTE, logger);
	if (nl_fd < 0) {
		/* errno already logged (without context, unfortunately) */
		return XFRMI_FAILURE;
	}

	int retval = XFRMI_SUCCESS;
	struct sockaddr_nl addr;
	socklen_t alen = sizeof(addr);
	struct nlm_resp rsp;
	ssize_t r = recvfrom(nl_fd, &rsp, sizeof(rsp), 0,
			(struct sockaddr *)&addr, &alen);

	if (r < 0) {
		if (errno == EAGAIN) {
			/* ??? this treatment looks suspect */
			dbg("xfrmi got EAGAIN (Resource Currently not available); ignore?? nl_query_small_resp() for %s() dev %s",
				context, if_name);
			/* pretend all is well */
		} else {
			llog_error(logger, errno,
				   "in nl_query_small_resp() for %s() dev %s",
				   context, if_name);
			passert(errno > 0);
			retval = XFRMI_FAILURE;
		}
	} else if (r < (ssize_t)sizeof(struct nlmsghdr)) {
		/* ??? this treatment looks suspect */
		/* a runt packet. Odd. */
		/* pretend all is well */
	} else if (rsp.n.nlmsg_type == NLMSG_ERROR) {
		/* The packet is an error packet: rsp.u.e.error is a negative errno value */
		passert(rsp.u.e.error < 0);
		llog_error(logger, -rsp.u.e.error,
			   "NLMSG_ERROR in nl_query_small_resp() for %s() dev %s",
			   context, if_name);
		retval = XFRMI_FAILURE;
	} else {
		/* ??? this treatment looks suspect */
		/* an ordinary message: ignore! */
	}

	close(nl_fd);
	return retval;
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

	return nl_query_small_resp(&req.n, "ip_link_set_up", if_name, logger);
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

	return nl_query_small_resp(&req.n, "ip_link_del", if_name, logger);
}

static int ip_link_add_xfrmi(const char *if_name /*non-NULL*/,
			      const char *dev_name /*non-NULL*/,
			      const uint32_t if_id,
			      struct logger *logger)
{
	dbg("add xfrm interface %s@%s id=%u", if_name, dev_name, if_id);
	struct nl_ifinfomsg_req req;
	zero(&req);
	if (link_add_nl_msg(if_name, dev_name, if_id, &req, logger) != XFRMI_SUCCESS) {
		llog_error(logger, 0/*no-errno*/,
			   "link_add_nl_msg() creating netlink message failed");
		return XFRMI_FAILURE;
	}

	return nl_query_small_resp(&req.n, "ip_kink_add_xfrmi", if_name, logger);
}

/* errno will be set on error: one caller will report it */
static int dev_exists_check(const char *dev_name /*non-NULL*/)
{
	if (if_nametoindex(dev_name) == 0) {
		return XFRMI_FAILURE;
	}

	return XFRMI_SUCCESS;
}

static int parse_xfrm_linkinfo_data(struct rtattr *attribute, const char *if_name,
	       struct ifinfo_response *ifi_rsp)
{
	struct rtattr *nested_attrib;
	const struct rtattr *dev_if_id_attr = NULL;
	const struct rtattr *if_id_attr = NULL;

	for (nested_attrib = (struct rtattr *) RTA_DATA(attribute);
			RTA_OK(nested_attrib, attribute->rta_len);
			nested_attrib = RTA_NEXT(nested_attrib,
				attribute->rta_len)) {
		if (nested_attrib->rta_type == IFLA_XFRM_LINK)
			dev_if_id_attr = nested_attrib;

		if (nested_attrib->rta_type == IFLA_XFRM_IF_ID)
			if_id_attr = nested_attrib;
	}

	if (dev_if_id_attr != NULL) {
		uint32_t dev_if_id = *((const uint32_t *)RTA_DATA(dev_if_id_attr));
		if (ifi_rsp->match.dev_if_id) {
			if (dev_if_id == ifi_rsp->req.dev_if_id) {
				ifi_rsp->result_if.dev_if_id = dev_if_id;
				ifi_rsp->match.dev_if_id = true;
			} else {
				return -1;
			}
		} else {
			ifi_rsp->result_if.dev_if_id = dev_if_id;
		}
	}

	if (if_id_attr == NULL)
		return -1;

	uint32_t xfrm_if_id = *((const uint32_t *)RTA_DATA(if_id_attr));
	if (ifi_rsp->req.filter_xfrm_if_id) {
		if (xfrm_if_id == ifi_rsp->req.xfrm_if_id) {
			ifi_rsp->result_if.if_id = xfrm_if_id;
			ifi_rsp->match.xfrm_if_id = true;
		} else {
			return -2;
		}
	} else {
		ifi_rsp->result_if.if_id = xfrm_if_id;
	}

	/* trust kernel if_name != NULL */
	ifi_rsp->result_if.name = clone_str(if_name, "xfrmi name from kernel");

	/* if it came this far found what we looking for */
	ifi_rsp->result = true;

	return XFRMI_SUCCESS;
}

static int parse_link_info_xfrm(struct rtattr *attribute, const char *if_name, struct ifinfo_response *ifi_rsp)
{
	struct rtattr *nested_attrib;
	struct rtattr *info_data_attr = NULL;
	ssize_t len = attribute->rta_len;
	for (nested_attrib = (struct rtattr *) RTA_DATA(attribute);
			RTA_OK(nested_attrib, len);
			nested_attrib = RTA_NEXT(nested_attrib, len)) {
		if (nested_attrib->rta_type == IFLA_INFO_KIND) {
			const char *kind_str = RTA_DATA(nested_attrib);
			if (streq("xfrm", kind_str))
				ifi_rsp->match.kind = true;
		}

		if (nested_attrib->rta_type == IFLA_INFO_DATA)
			info_data_attr = nested_attrib;
	}

	if (ifi_rsp->match.kind && info_data_attr !=  NULL) {
		return parse_xfrm_linkinfo_data(info_data_attr, if_name, ifi_rsp);
	} else {
		return XFRMI_FAILURE;
	}
}

static int parse_nl_newlink_msg(struct nlmsghdr *nlmsg, struct ifinfo_response *ifi_rsp)
{
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

	if (ifi_rsp->req.if_name != NULL) {
		if (streq(ifi_rsp->req.if_name, if_name)) {
			/* name match requested and matched */
			ifi_rsp->match.name = true;
		} else {
			return XFRMI_FAILURE;
		}
	}

	return parse_link_info_xfrm(linkinfo_attr, if_name, ifi_rsp);
}

static void process_nlmsgs(char *msgbuf,  ssize_t len, struct ifinfo_response *ifi_rsp)
{
	int i = 0;
	int ignored = 0;
	int red_msg_size = 0;
	struct nlmsghdr *nlmsg = (struct nlmsghdr *)msgbuf;

	for (; NLMSG_OK(nlmsg, (size_t)len); nlmsg = NLMSG_NEXT(nlmsg, len)) {
		switch (nlmsg->nlmsg_type) {
		case NLMSG_DONE:
			dbg("NLMSG_DONE: RTM_NEWLINK messages %d ignored %d. Bytes %d", i, ignored, red_msg_size);
			return;

		case NLMSG_ERROR:
			dbg("ERROR: NLMSG_ERROR netlink %d ignored %d. Bytes %d",
				i, ignored, red_msg_size);
			return;

		case RTM_NEWLINK:
			i++;
			red_msg_size += nlmsg->nlmsg_len;
			dbg("RTM_NEWLINK: netlink %d ignored %d. Bytes %d", i, ignored, red_msg_size);
			if (parse_nl_newlink_msg(nlmsg, ifi_rsp) == XFRMI_SUCCESS && ifi_rsp->result)
				return;
			break;

		case 0:
			dbg("INFO: NOOP? message type %d length %d", nlmsg->nlmsg_type,
				nlmsg->nlmsg_len);
			ignored++;
			break;

		default:
			printf("INFO: ignored message type %d length %d", nlmsg->nlmsg_type,
			nlmsg->nlmsg_len);
			ignored++;
			break;
		}
	}
}

static int find_xfrmi_interface(const char *if_name, /* optional */
				 uint32_t xfrm_if_id,
				 struct logger *logger)
{
	/* first do a cheap check */
	if (if_name != NULL && dev_exists_check(if_name) != XFRMI_SUCCESS) {
		return XFRMI_FAILURE;
	}

	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_GETLINK,
			(NLM_F_REQUEST | NLM_F_DUMP));

	int nl_fd = nl_send_query(&req.n, NETLINK_ROUTE, logger);

	if (nl_fd < 0) {
		llog_error(logger, 0/*no-errno*/,
			   "write to netlink socket failed");
		return XFRMI_FAILURE;
	}

	char *resp_msgbuf = alloc_bytes(IFINFO_REPLY_BUFFER_SIZE,
			"netlink ifiinfo query");
	ssize_t len = netlink_read_reply(nl_fd, &resp_msgbuf,
			IFINFO_REPLY_BUFFER_SIZE, 0, getpid());

	close(nl_fd);

	if (len < 0) {
		llog_error(logger, 0/*no-errno*/,
			   "netlink_read_reply() failed in find_any_xfrmi_interface()");
		pfreeany(resp_msgbuf);
		return XFRMI_FAILURE;
	}

	struct ifinfo_response ifi_rsp;
	zero(&ifi_rsp);

	ifi_rsp.req.if_name = if_name;
	if (xfrm_if_id > 0) {/* we deal with only > 0 */
		ifi_rsp.req.filter_xfrm_if_id = true;
	}
	ifi_rsp.req.xfrm_if_id = xfrm_if_id;

	process_nlmsgs(resp_msgbuf, len, &ifi_rsp);
	pfreeany(resp_msgbuf);

	if (ifi_rsp.result) {
		char if_name_buf[IF_NAMESIZE];
		if_indextoname(ifi_rsp.result_if.dev_if_id, if_name_buf);
		dbg("xfrmi support found existing %s@%s xfrm if_id 0x%x",
				ifi_rsp.result_if.name, if_name_buf, ifi_rsp.result_if.if_id);
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
		dbg("%s no xfrmi interface found", __func__);
	}

	return retval;
}

static err_t ipsec1_support_test(const char *if_name /*non-NULL*/,
				 const char *dev_name /*non-NULL*/,
				 struct logger *logger)
{
	if (!find_any_xfrmi_interface(logger))
		return NULL; /* success: there is already xfrmi interface */

	dbg("create and delete an xfrmi interface '%s@%s' to test xfrmi support",
			if_name, dev_name);
	if (ip_link_add_xfrmi(if_name, dev_name, xfrm_interface_id, logger) != XFRMI_SUCCESS) {
		xfrm_interface_support = -1;
		dbg("xfrmi is not supported. failed to create %s@%s", if_name, dev_name);
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
		dbg("xfrmi supported success creating %s@%s and delete it",
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
			llog(RC_LOG_SERIOUS, logger,
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
	struct pluto_xfrmi *p = refcnt_alloc(struct pluto_xfrmi, free_xfrmi, HERE);
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
	} else {
		pfreeany(xfrmi_name);
		passert(c->xfrmi->shared == shared);
		reference_xfrmi(c);
	}

	return XFRMI_SUCCESS;
}

bool setup_xfrm_interface(struct connection *c, uint32_t xfrm_if_id)
{
	if (xfrm_if_id == 0) {
		dbg("remap ipsec0");
		xfrm_if_id = PLUTO_XFRMI_REMAP_IF_ID_ZERO;
	}

	bool shared = true;

	if (xfrm_if_id == yn_yes)
		xfrm_if_id = IPSEC1_XFRM_IF_ID;
	/*
	} else if (shunk_strcaseeq(ifid, "unique")) {
		// unique or <id> for each connection
		shared = false;
		log_state(RC_LOG, st, "iface_id = unique is not supported yet shared=%d", shared);
		return false;
	*/

	/* always success for now */
	return (init_pluto_xfrmi(c, xfrm_if_id, shared) == XFRMI_SUCCESS);
}

/* Return true on success, false on failure */
bool add_xfrm_interface(struct connection *c, struct logger *logger)
{
	passert(c->xfrmi->name != NULL);
	passert(c->interface->ip_dev->id_rname != NULL);

	if (dev_exists_check(c->xfrmi->name) != XFRMI_SUCCESS) {
		if (ip_link_add_xfrmi(c->xfrmi->name,
				      c->interface->ip_dev->id_rname,
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

	return (ip_link_set_up(c->xfrmi->name, logger) == XFRMI_SUCCESS);
}

/* This function is a callback that will be called by refcnt reaches 0 */
static void free_xfrmi(void *object, const struct logger *logger, where_t where)
{
	struct pluto_xfrmi *xfrmi = (struct pluto_xfrmi *) object;
	struct pluto_xfrmi **pp;
	struct pluto_xfrmi *p;

	for (pp = &pluto_xfrm_interfaces; (p = *pp) != NULL; pp = &p->next) {
		if (p == xfrmi) {
			*pp = p->next;
			if (xfrmi->pluto_added) {
				ip_link_del(xfrmi->name, logger);
				llog(RC_LOG, logger,
				     "delete ipsec-interface=%s if_id=%u added by pluto"PRI_WHERE"",
				     xfrmi->name, xfrmi->if_id, pri_where(where));
			} else {
				llog(RC_LOG, logger,
				     "cannot delete ipsec-interface=%s if_id=%u, not created by pluto",
				     xfrmi->name, xfrmi->if_id);
			}
			pfreeany(xfrmi->name);
			pfreeany(xfrmi);
			return;
		}
		ldbg(logger, "p=%p xfrmi=%p", p, xfrmi);
	}
	ldbg(logger, "p=%p xfrmi=%s if_id=%u not found in the list", xfrmi,
	     xfrmi->name, xfrmi->if_id);
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
		llog(RC_LOG_SERIOUS, logger,
			    "found an unexpected interface %s if_id=%u From previous pluto run?",
			    if_name, if_id);
		return; /* ERROR */
	}
	if (errno == ENXIO || errno == ENODEV) {
		dbg("no stale xfrmi interface '%s' found", if_name);
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
	addref(c->xfrmi);
	dbg("reference xfrmi=%p name=%s if_id=%u refcount=%u (after)", c->xfrmi,
			c->xfrmi->name, c->xfrmi->if_id,
			refcnt_peek(&(c->xfrmi->refcnt)));
}

void unreference_xfrmi(struct connection *c)
{
	passert(c->xfrmi != NULL);

	ldbg(c->logger, "unreference xfrmi=%p name=%s if_id=%u refcount=%u (before).",
	     c->xfrmi, c->xfrmi->name, c->xfrmi->if_id,
	     refcnt_peek(&(c->xfrmi->refcnt)));

	delref(&c->xfrmi, c->logger);
}
