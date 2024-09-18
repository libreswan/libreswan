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

#include "passert.h"

#include "ipsec_interface.h"

#include "kernel.h"			/* for kernel_ops */
#include "kernel_ipsec_interface.h"
#include "log.h"
#include "verbose.h"
#include "iface.h"

static struct pluto_xfrmi *pluto_xfrm_interfaces;

/*
 * Format the name of the IPsec interface.
 *
 * To maintain consistency on longer names won't be truncated, instead
 * passert.
 */

size_t jam_ipsec_interface_id(struct jambuf *buf, uint32_t if_id)
{
	/* remap if_id PLUTO_XFRMI_REMAP_IF_ID_ZERO to ipsec0 as special case */
	size_t s = jam(buf, "%s%"PRIu32, kernel_ops->ipsec_interface->name,
		       if_id == kernel_ops->ipsec_interface->map_if_id_zero ? 0  : if_id);

	/* guarentee buf, including trailing NULL fits in IFNAMSIZE */
	passert(s < IFNAMSIZ);
	return s;
}

char *str_ipsec_interface_id(uint32_t if_id, ipsec_interface_id_buf *buf)
{
	struct jambuf jb = ARRAY_AS_JAMBUF(buf->buf);
	jam_ipsec_interface_id(&jb, if_id);
	return buf->buf;
}

/*
 * Create an internal XFRMi Interface IP address structure.
 */

struct pluto_xfrmi_ipaddr *create_xfrmi_ipaddr(struct pluto_xfrmi *xfrmi_if,
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

struct pluto_xfrmi_ipaddr *find_xfrmi_ipaddr(struct pluto_xfrmi *xfrmi,
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

void free_xfrmi_ipaddr_list(struct pluto_xfrmi_ipaddr *xfrmi_ipaddr, struct logger *logger)
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

void reference_xfrmi_ip(struct pluto_xfrmi *xfrmi, struct pluto_xfrmi_ipaddr *xfrmi_ipaddr)
{
	addref_where(xfrmi_ipaddr, HERE);
	dbg("reference xfrmi_ipaddr=%p name=%s if_id=%u refcount=%u (after)",
			xfrmi_ipaddr, xfrmi->name, xfrmi->if_id,
	    refcnt_peek(xfrmi_ipaddr, &global_logger));
}

void unreference_xfrmi_ip(const struct connection *c, struct logger *logger)
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
		kernel_ops->ipsec_interface->ip_addr_del(c->xfrmi->name, xfrmi_ipaddr_unref, logger);
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

/*
 * Get the IP used for the XFRMi IF from the connection.
 *
 * Return an ip_cidr object if found, unset_cidr otherwise.
 */
ip_cidr get_xfrmi_ipaddr_from_conn(const struct connection *c, struct logger *logger)
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


/* Only called by add_xfrm_interface() */
static bool add_xfrm_interface_ip(const struct connection *c, ip_cidr *conn_xfrmi_cidr, struct logger *logger)
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
	bool ip_on_if = kernel_ops->ipsec_interface->ip_addr_find_on_if(c->xfrmi, &(refd_xfrmi_ipaddr->if_ip),
									logger);
	if (ip_on_if == false) {
		refd_xfrmi_ipaddr->pluto_added = true;
		if (!kernel_ops->ipsec_interface->ip_addr_add(c->xfrmi->name, refd_xfrmi_ipaddr, logger)) {
			llog_error(logger, 0/*no-errno*/,
					"Unable to add IP address to XFRMi interface %s xfrm_if_id %u.",
						c->xfrmi->name, c->xfrmi->if_id);
			return false;
		}
	}

	return true;
}

/* Return true on success, false on failure */

bool add_xfrm_interface(const struct connection *c, struct logger *logger)
{
	struct verbose verbose = {
		.logger = logger,
		.rc_flags = (DBGP(DBG_BASE) ? DEBUG_STREAM : LEMPTY),
	};
	passert(c->xfrmi->name != NULL);
	passert(c->iface->real_device_name != NULL);

	if (if_nametoindex(c->xfrmi->name) == 0) {
		if (!kernel_ops->ipsec_interface->ip_link_add(c->xfrmi->name,
							      c->iface->real_device_name,
							      c->xfrmi->if_id,
							      logger)) {
			return false;
		}

		c->xfrmi->pluto_added = true;
	} else {
		/*
		 * Device exists: try to match name, type xfrmi, and
		 * xfrm_if_id.
		 */
		if (!kernel_ops->ipsec_interface->find_interface(c->xfrmi->name, c->xfrmi->if_id, verbose)) {
			/* found wrong device abort adding */
			llog_error(logger, 0/*no-errno*/,
				   "device %s exists but do not match expected type, XFRM if_id %u, or XFRM device is invalid; check 'ip -d link show dev %s'",
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

	return kernel_ops->ipsec_interface->ip_link_set_up(c->xfrmi->name, logger);
}

void remove_xfrm_interface(const struct connection *c, struct logger *logger)
{
	PASSERT(logger, c->xfrmi != NULL);

	unreference_xfrmi_ip(c, logger);
}

struct pluto_xfrmi *find_pluto_xfrmi_interface(uint32_t if_id)
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

void new_pluto_xfrmi(uint32_t if_id, bool shared, const char *name, struct connection *c)
{
	struct pluto_xfrmi **head = &pluto_xfrm_interfaces;
	/* Create a new ref-counted xfrmi, it is not added to system yet.
	 * The call to refcnt_alloc() counts as a reference */
	struct pluto_xfrmi *p = refcnt_alloc(struct pluto_xfrmi, HERE);
	p->if_id = if_id;
	p->name = clone_str(name, "xfrmi name");
	c->xfrmi = p;
	p->next = *head;
	*head = p;
	c->xfrmi = p;
	c->xfrmi->shared = shared;
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

	struct pluto_xfrmi *xfrmi = delref_where(&c->xfrmi, logger, HERE);
	if (xfrmi != NULL) {
		struct pluto_xfrmi **pp;
		struct pluto_xfrmi *p;
		for (pp = &pluto_xfrm_interfaces; (p = *pp) != NULL; pp = &p->next) {
			if (p == xfrmi) {
				*pp = p->next;
				if (xfrmi->pluto_added) {
					kernel_ops->ipsec_interface->ip_link_del(xfrmi->name, logger);
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
