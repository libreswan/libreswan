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

#if !defined(linux) || !defined(USE_XFRM_INTERFACE) || !defined(XFRM_SUPPORT)
# error this file should only compile on Linux when XFRM_SUPPORT & USE_XFRM_INTERFACE are defined
#endif

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>
#include <net/if.h>

#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#if defined(USE_XFRM_INTERFACE_IFLA_HEADER)
/* kernel header linux/if_link.h < 4.19 may need this extra */
# include "if_link_extra.h"
#endif

#include "lswalloc.h"
#include "netlink_attrib.h"
#include "lswlog.h"
#include "connections.h"
#include "server.h" /* for struct iface_port */
#include "kernel_xfrm_interface.h"
#include "kernel_netlink_reply.h"
#include "kernel_netlink_query.h"
#include "iface.h"

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
		char *if_name;
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

static int xfrm_interface_support;
static bool stale_checked;
static uint32_t xfrm_interface_id = IPSEC1_XFRM_IF_ID; /* XFRMA_IF_ID && XFRMA_SET_MARK */

static bool nl_query_small_resp(struct nlmsghdr *req, int protocol, struct nlm_resp *rsp)
{
	int nl_fd = nl_send_query(req, protocol);
	if (nl_fd < 0)
		return true;

	struct sockaddr_nl addr;
	ssize_t r;
	socklen_t alen = sizeof(addr);
	for (;;) {
		r = recvfrom(nl_fd, &rsp, sizeof(rsp), 0,
				(struct sockaddr *)&addr, &alen);
		if (r < 0) {
			if (errno == EAGAIN) {
				//AA_2019 fix this xxx
				dbg("xfrmi go EAGAIN Resource Currently not available ignore?? %s", __func__);
				break;
			} else {
				LOG_ERRNO(errno, " in nl_query_small_resp() reading");
				close(nl_fd);
				return true;
			}
		}
	}

	close(nl_fd);

	return false;
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

static bool link_add_nl_msg(const char *if_name,
		const char *dev_name, const uint32_t if_id,
		struct nl_ifinfomsg_req *req)
{

	char link_type[] = "xfrm";
	*req = init_nl_ifi(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);

	nl_addattrstrz(&req->n, req->maxlen, IFLA_IFNAME, if_name);

	struct rtattr *linkinfo;
	linkinfo = nl_addattr_nest(&req->n, req->maxlen, IFLA_LINKINFO);
	nl_addattr_l(&req->n, req->maxlen, IFLA_INFO_KIND, link_type,
			strlen(link_type));

	struct rtattr *xfrm_link = nl_addattr_nest(&req->n, req->maxlen, IFLA_INFO_DATA);
	/*
	 * IFLA_XFRM_IF_ID was added to mainline kernel 4.19 linux/if_link.h
	 * with older kernel headers 'make USE_XFRM_INTERFACE_IFLA_HEADER=true'
	 */
	nl_addattr32(&req->n, 1024, IFLA_XFRM_IF_ID, if_id);

	if (dev_name != NULL) {
		uint32_t dev_link_id; /* e.g link id of the interface, eth0 */
		dev_link_id = if_nametoindex(dev_name);
		if (dev_link_id != 0) {
			nl_addattr32(&req->n, 1024, IFLA_XFRM_LINK, dev_link_id);
		} else {
			LOG_ERRNO(errno, "Can not find interface index for device %s",
					dev_name);
			return true;
		}
	}

	nl_addattr_nest_end(&req->n, xfrm_link);

	nl_addattr_nest_end(&req->n, linkinfo);

	return false;
}

bool ip_link_set_up(const char *if_name, struct logger *logger)
{
	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_NEWLINK, NLM_F_REQUEST);
	req.i.ifi_change |= IFF_UP;
	req.i.ifi_flags |= IFF_UP;
	req.i.ifi_index = if_nametoindex(if_name);
	if (req.i.ifi_index == 0) {
		log_errno(logger, errno,
			  "link_set_up_nl() can not find index of xfrm interface %s",
			  if_name);
		return true;
	}

	struct nlm_resp nl_rsp;
	if (nl_query_small_resp(&req.n, NETLINK_ROUTE, &nl_rsp)) {
		log_message(RC_FATAL, logger, "ERROR:ip_link_set_up() netlink query dev %s", if_name);

	} else {
		/* netlink query succeeded. check NL response */
		if (nl_rsp.n.nlmsg_type == NLMSG_ERROR) {
			log_message(RC_INFORMATIONAL, logger, "deleting interface %s failed", if_name);
			return true;
		}
	}
	return false;
}

static bool ip_link_del(const char *if_name, struct logger *logger)
{
	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_DELLINK, NLM_F_REQUEST);
	req.i.ifi_index = if_nametoindex(if_name);
	if (req.i.ifi_index == 0) {
		log_errno(logger, errno, "ip_link_del() can not find index of interface %s",
			  if_name);
		return true;
	}

	struct nlm_resp nl_rsp;
	if (nl_query_small_resp(&req.n, NETLINK_ROUTE, &nl_rsp)) {
		log_message(RC_FATAL, logger,
			    "ERROR: ip_link_del() deleting xfrmi interface %s failed", if_name);

	} else {
		/* netlink query succeeded. Lets check NL response */
		if (nl_rsp.n.nlmsg_type == NLMSG_ERROR) {
			log_message(RC_INFORMATIONAL, logger,
				    "WARNING: ip_link_del() deleting interface %s failed", if_name);

			return true;
		}
	}
	return false;
}

static bool ip_link_add_xfrmi(const char *if_name, const char *dev_name, const uint32_t if_id,
			      struct logger *logger)
{
	dbg("add xfrm interface %s@%s id=%u", if_name, dev_name, if_id);
	struct nl_ifinfomsg_req req;
	zero(&req);
	if (link_add_nl_msg(if_name, dev_name, if_id, &req)) {
		log_message(RC_FATAL, logger,
			    "ERROR: nl_query_small_resp() creating netlink message failed");
		return true;
	}

	struct nlm_resp nl_rsp;
	if (nl_query_small_resp(&req.n, NETLINK_ROUTE, &nl_rsp)) {
		log_message(RC_FATAL, logger,
			    "ERROR: nl_query_small_resp() netlink query failed");

	} else {
		/* netlink query succeeded. check NL response */
		if (nl_rsp.n.nlmsg_type == NLMSG_ERROR &&
				nl_rsp.u.e.error == -ENOPROTOOPT) {
			log_message(RC_FATAL, logger,
				    "CONFIG_XFRM_INTERFACE fail got ENOPROTOOPT");
			return true;
		}
	}

	return false;
}

static bool dev_exist_check(const char *dev_name, bool quiet)
{
	unsigned int if_id = 0;
	if (dev_name != NULL)
		if_id = if_nametoindex(dev_name);
	if (if_id == 0) {
		if (!quiet)
			LOG_ERRNO(errno, "FATAL can not find device %s",
					dev_name);
		return true;
	}
	return false;
}

static bool parse_xfrm_linkinfo_data(struct rtattr *attribute, char *if_name,
	       struct ifinfo_response *ifi_rsp)
{
	struct rtattr *nested_attrib;
	struct rtattr *dev_if_id_attr = NULL;
	struct rtattr *if_id_attr = NULL;

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
		uint32_t dev_if_id = *((uint32_t *)RTA_DATA(dev_if_id_attr));
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

	uint32_t xfrm_if_id = *((uint32_t *)RTA_DATA(if_id_attr));
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

	return 0;
}

static int parse_link_info_xfrm(struct rtattr *attribute, char *if_name, struct ifinfo_response *ifi_rsp)
{
	struct rtattr *nested_attrib;
	struct rtattr *info_data_attr = NULL;
	ssize_t len = attribute->rta_len;
	for (nested_attrib = (struct rtattr *) RTA_DATA(attribute);
			RTA_OK(nested_attrib, len);
			nested_attrib = RTA_NEXT(nested_attrib, len)) {
		if (nested_attrib->rta_type == IFLA_INFO_KIND) {
			char *kind_str = RTA_DATA(nested_attrib);
			if (!strcmp("xfrm", kind_str))
				ifi_rsp->match.kind = true;
		}

		if (nested_attrib->rta_type == IFLA_INFO_DATA)
			info_data_attr = nested_attrib;
	}

	if (ifi_rsp->match.kind && info_data_attr !=  NULL)
		return parse_xfrm_linkinfo_data(info_data_attr, if_name, ifi_rsp);
	else
		return -1;
}

static int parse_nl_newlink_msg(struct nlmsghdr *nlmsg, struct ifinfo_response *ifi_rsp)
{
	struct rtattr *attribute;
	struct rtattr *linkinfo_attr =  NULL;
	struct ifinfomsg *iface = NLMSG_DATA(nlmsg);
	int len = nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));
	char *if_name = NULL;

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
		return -1;

	if (linkinfo_attr == NULL)
		return -1;

	if (ifi_rsp->req.if_name != NULL) {
		if (streq(ifi_rsp->req.if_name, if_name)) {
			/* name match requested and matched */
			ifi_rsp->match.name = true;
		} else {
			return -1;
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
			if (parse_nl_newlink_msg(nlmsg, ifi_rsp) == 0 && ifi_rsp->result)
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

static bool find_xfrmi_interface(char *if_name, uint32_t xfrm_if_id)
{
	if (if_name != NULL) {
		/* this is name based check first to do a simple check */
		if (dev_exist_check(if_name, true /* ignore error */))
			return true /* error */;
	}

	struct nl_ifinfomsg_req req = init_nl_ifi(RTM_GETLINK,
			(NLM_F_REQUEST | NLM_F_DUMP));

	int nl_fd = nl_send_query(&req.n, NETLINK_ROUTE);

	if (nl_fd < 0) {
		loglog(RC_LOG_SERIOUS, "ERROR write to netlink socket failed");
		return true;
	}

	char *resp_msgbuf = alloc_bytes(IFINFO_REPLY_BUFFER_SIZE,
			"netlink ifiinfo query");
	ssize_t len = netlink_read_reply(nl_fd,  &resp_msgbuf,
			IFINFO_REPLY_BUFFER_SIZE, 0, getpid());
	if (len < 0) {
		loglog(RC_LOG_SERIOUS, "ERROR find_any_xfrmi_interface() received %d", nl_fd);
		close(nl_fd);
		return true;
	}

	close(nl_fd);

	struct ifinfo_response ifi_rsp;
	zero(&ifi_rsp);

	ifi_rsp.req.if_name = if_name;
	if (xfrm_if_id > 0) /* we deal with only > 0 */
		ifi_rsp.req.filter_xfrm_if_id = true;
	ifi_rsp.req.xfrm_if_id = xfrm_if_id;


	process_nlmsgs(resp_msgbuf, len, &ifi_rsp);
	pfreeany(resp_msgbuf);

	if (ifi_rsp.result) {
		char if_name[IF_NAMESIZE];
		if_indextoname(ifi_rsp.result_if.dev_if_id, if_name);
		dbg("xfrmi support found existing %s@%s xfrm if_id 0x%x",
				ifi_rsp.result_if.name, if_name, ifi_rsp.result_if.if_id);
		pfreeany(ifi_rsp.result_if.name);
		return false; /* success */
	}

	pfreeany(ifi_rsp.result_if.name);

	return true;
}

static bool find_any_xfrmi_interface(void)
{

	if (find_xfrmi_interface(NULL, 0)) {
		dbg("%s no xfrmi interface found", __func__);
		return true;
	}
	return false;
}

static err_t ipsec1_support_test(const char *if_name, const char *dev_name,
				 struct logger *logger)
{
	if (!find_any_xfrmi_interface())
		return NULL; /* success there is already xfrmi interefaces */

	dbg("create and delete an xfrmi interrace '%s@%s' to test xfrmi support",
			if_name, dev_name);
	if (ip_link_add_xfrmi(if_name, dev_name, xfrm_interface_id, logger)) {
		xfrm_interface_support = -1;
		dbg("xfrmi is not supported. failed to create %s@%s", if_name, dev_name);
	} else {
		if (dev_exist_check(if_name, false /* log error */)) {
			/*
			 * faled. assume kernel support is not enabled.
			 * ip link add ipsec1 type xfrm xfrmi-id 6 dev eth0
			 * can be quiet when kernel has no CONFIG_XFRM_INTERFACE=no
			 */
			xfrm_interface_support = -1;
			return "missing CONFIG_XFRM_INTERFACE support in kernel";
		}
		dbg("xfrmi supported success creating %s@%s",
				if_name, dev_name);
		ip_link_del(if_name, logger); /* ignore return value??? */
		xfrm_interface_support = 1; /* success */
	}

	return NULL;
}

/*
 * format the name of xfrmi interface. To maintain consistency
 * on longer names won't be truncated, instead passert.
 */
static char *fmt_xfrmi_ifname(uint32_t if_id)
{
	char *if_name = alloc_things(char, IFNAMSIZ, "xfrmi name");
	int n  = snprintf(if_name, IFNAMSIZ, XFRMI_DEV_FORMAT, if_id);
	passert(n < IFNAMSIZ);
	return if_name;
}

err_t xfrm_iface_supported(struct logger *logger)
{
	err_t err = NULL; /* success */

	if (xfrm_interface_support == 0) {
		char *if_name = fmt_xfrmi_ifname(IPSEC1_XFRM_IF_ID);
		char lo[]  = "lo";

		if (dev_exist_check(lo, true /* ignore error */)) {
			/* possibly no need to pancic may be get smarter one day */
			xfrm_interface_support = -1;
			pfreeany(if_name);
			return "Could not create find real device needed to test xfrmi support";
		}

		unsigned int if_id = if_nametoindex(if_name);
		int e = errno; /* save error */
		if (if_id == 0 && (e == ENXIO || e == ENODEV)) {
			err = ipsec1_support_test(if_name, lo, logger);
		} else if (if_id == 0) {
			log_errno(logger, e,
				  "FATAL unexpected error in xfrm_iface_supported() while checking device %s",
				  if_name);
			xfrm_interface_support = -1;
			err = "can not decide xfrmi support. assumed no.";
		} else {
			/*
			 * may be more extensive checks?
			 * such if it is a xfrmi device or something else
			 */
			log_message(RC_LOG_SERIOUS, logger,
				    "conflict %s already exist can not support xfrm-interface. May be leftover from previous pluto?",
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
	/* create a new xfrmi it is not added to system yet */
	struct pluto_xfrmi *p = alloc_thing(struct pluto_xfrmi, "new xfrmi interface");
	p->if_id = if_id;
	p->name = name;
	c->xfrmi = p;
	reference_xfrmi(c);
	p->next = *head;
	*head = p;
	c->xfrmi = p;
	c->xfrmi->shared = shared;
}

static bool init_pluto_xfrmi(struct connection *c, uint32_t if_id, bool shared)
{
	c->xfrmi = find_pluto_xfrmi_interface(if_id);
	char *xfrmi_name = fmt_xfrmi_ifname(if_id);
	if (c->xfrmi == NULL) {
		/*
		if (!shared) {
			libreswan_log("%s, index %u, xfrm interface exist will not shared",
				       xfrmi_name, if_id);
			return true;
		}
		*/
		new_pluto_xfrmi(if_id, shared, xfrmi_name, c);
	} else {
		passert(c->xfrmi->shared == shared);
		reference_xfrmi(c);
	}

	return false;
}

bool setup_xfrm_interface(struct connection *c, uint32_t xfrm_if_id)
{


	if (xfrm_if_id == yn_no)
		return true;

	bool shared = true;

	if (xfrm_if_id == yn_yes)
		xfrm_if_id = IPSEC1_XFRM_IF_ID;
	/*
	} else if (shunk_strcaseeq(ifid, "unique")) {
		// unique or <id> for each connection
		shared = false;
		libreswan_log("iface_id = unique is not supported yet shared=%d", shared);
		return false;
	*/

	return init_pluto_xfrmi(c, xfrm_if_id, shared);
}

bool add_xfrmi(struct connection *c, struct logger *logger)
{
	if (dev_exist_check(c->xfrmi->name, true /* ignore error */)) {
		if (ip_link_add_xfrmi(c->xfrmi->name,
					c->interface->ip_dev->id_rname,
				      c->xfrmi->if_id,
				      logger))
			return true;
		c->xfrmi->pluto_added = true;
	} else { /* device exist match name, type xfrmi, and xfrm_if_id */
		if (find_xfrmi_interface(c->xfrmi->name, c->xfrmi->if_id)) {
			/* found wrong device abort adding */
			log_message(RC_LOG_SERIOUS, logger,
				    "ERROR device %s exist and do not match expected type xfrm or xfrm_if_id %u. check 'ip -d link show dev %s'", c->xfrmi->name, c->xfrmi->if_id, c->xfrmi->name);
			return true;
		}
	}

	if (ip_link_set_up(c->xfrmi->name, logger))
		return true;
	return false;
}

static void free_xfrmi(struct pluto_xfrmi *xfrmi, struct logger *logger)
{
	struct pluto_xfrmi **pp;
	struct pluto_xfrmi *p;

	if (xfrmi == NULL)
		return;
	for (pp = &pluto_xfrm_interfaces; (p = *pp) != NULL; pp = &p->next) {
		if (p == xfrmi) {
			*pp = p->next;
			if (xfrmi->pluto_added)  {
				ip_link_del(xfrmi->name, logger);
				log_message(RC_LOG, logger,
					    "delete ipsec-interface=%s if_id=%u added by pluto", xfrmi->name, xfrmi->if_id);
			} else {

				log_message(RC_LOG, logger,
					    "can not delete ipsec-interface=%s if_id=%u, not created by pluto", xfrmi->name, xfrmi->if_id);
			}
			pfreeany(xfrmi->name);
			pfreeany(xfrmi);
			return;
		}
		dbg("p=%p xfrmi=%p", p, xfrmi);
	}
	dbg("p=%p xfrmi=%s if_id=%u not found in the list", xfrmi,
			xfrmi->name, xfrmi->if_id);
}

/* at start call this to see if there are any stale interface lying around. */
void stale_xfrmi_interfaces(void)
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
		loglog(RC_LOG_SERIOUS, "found an unexpected interface %s if_id=%u From previous pluto run?",
				if_name, if_id);
		return; /* ERROR */
	}
	if (errno == ENXIO || errno == ENODEV) {
		dbg("no stale xfrmi interface '%s' found", if_name);
	} else {
		LOG_ERRNO(errno, "failed stale_xfrmi_interfaces() call if_nametoindex('%s')", if_name);
		return;
	}
}

void free_xfrmi_ipsec1(struct logger *logger)
{
	char if_name[IFNAMSIZ];
	snprintf(if_name, sizeof(if_name), XFRMI_DEV_FORMAT, IPSEC1_XFRM_IF_ID); /* global ipsec1 */
	unsigned int if_id = if_nametoindex(if_name);

	if (if_id > 0)
		ip_link_del(if_name, logger); /* ignore return value??? */
}

void reference_xfrmi(struct connection *c)
{
	c->xfrmi->refcount++;
	dbg("reference xfrmi=%p name=%s if_id=%u refcount=%u (after)", c->xfrmi,
			c->xfrmi->name, c->xfrmi->if_id, c->xfrmi->refcount);
}

void unreference_xfrmi(struct connection *c, struct logger *logger)
{
	passert(c->xfrmi->refcount > 0);
	c->xfrmi->refcount--;

	dbg("unreference xfrmi=%p name=%s if_id=%u refcount=%u (after) %s",
			c->xfrmi, c->xfrmi->name,
			c->xfrmi->if_id, c->xfrmi->refcount,
			c->xfrmi->refcount == 0 ? "delete interface." : ".");
	if (c->xfrmi->refcount == 0)
		free_xfrmi(c->xfrmi, logger);
}
