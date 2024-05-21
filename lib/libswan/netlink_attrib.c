/*
 * netlink attributes to message, for libreswan
 *
 * Copyright (C) 2018-2020 Antony Antony <antony@phenome.org>
 * A part of this came from iproute2 lib/libnetlink.c
 * Authors:     Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
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

#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>

#include "lswlog.h"
#include "netlink_attrib.h"

#define RTA_TAIL(rta) ((struct rtattr *) (((void *) (rta)) + \
			RTA_ALIGN((rta)->rta_len)))

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

void nl_addattr_l(struct nlmsghdr *n, const unsigned short maxlen,
		  const unsigned short type, const void *data, int alen)
{
	unsigned short len = RTA_LENGTH(alen);

	passert(NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) <= maxlen);

	struct rtattr *rta = NLMSG_TAIL(n);

	rta->rta_type = type;
	rta->rta_len = len;
	if (alen != 0) {
		memcpy(RTA_DATA(rta), data, alen);
	}
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
}

struct rtattr *nl_addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	nl_addattr_l(n, maxlen, type, NULL, 0);
	return nest;
}

void nl_addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
}

void nl_addattrstrz(struct nlmsghdr *n, int maxlen, int type, const char *str /*non-NULL*/)
{
	nl_addattr_l(n, maxlen, type, str, strlen(str)+1);
}

void nl_addattr32(struct nlmsghdr *n, int maxlen, int type, const uint32_t data)
{
	nl_addattr_l(n, maxlen, type, &data, sizeof(uint32_t));
}

const struct nlattr *nl_getattr(const struct nlmsghdr *n, size_t *offset)
{
	struct nlattr *attr = (void *)n + NLMSG_HDRLEN + NLMSG_ALIGN(*offset);
	struct nlattr *tail = (void *)n + NLMSG_ALIGN(n->nlmsg_len);

	if (attr == tail) {
		return NULL;
	}

	*offset += NLA_ALIGN(attr->nla_len);
	return attr;
}

const char *nl_getattrvalstrz(const struct nlmsghdr *n,
			      const struct nlattr *attr)
{
	struct nlattr *tail = (void *)n + NLMSG_ALIGN(n->nlmsg_len);

	ptrdiff_t len = (void *)tail - (void *)attr;
	if (len < (ptrdiff_t)sizeof(struct nlattr) ||
	    attr->nla_len <= sizeof(struct nlattr) ||
	    attr->nla_len > len ||
	    !memchr(attr + NLA_HDRLEN, '\0', attr->nla_len - NLA_HDRLEN)) {
		return NULL;
	}

	return (void *)attr + NLA_HDRLEN;
}
