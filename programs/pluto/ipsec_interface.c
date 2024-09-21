/* ipsec-interface= structures, for libreswan
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
#include "sparse_names.h"

#include "ipsec_interface.h"

#include "kernel.h"			/* for kernel_ops */
#include "kernel_ipsec_interface.h"
#include "log.h"
#include "verbose.h"
#include "iface.h"

static ip_cidr get_connection_ipsec_interface_cidr(const struct connection *c,
						   struct verbose verbose);

static struct ipsec_interface_address **find_ipsec_interface_address_ptr(struct ipsec_interface *ipsecif,
									 ip_cidr cidr,
									 struct verbose verbose);

static struct ipsec_interface *ipsec_interfaces;

/*
 * Format the name of the IPsec interface.
 *
 * To maintain consistency on longer names won't be truncated, instead
 * passert.
 */

size_t jam_ipsec_interface_id(struct jambuf *buf, uint32_t if_id)
{
	/* remap if_id to ipsec0 as special case */
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
 * Create an internal ipsec_interface_address address structure.
 */

struct ipsec_interface_address *alloc_ipsec_interface_address(struct ipsec_interface_address **ptr,
							      ip_cidr cidr)
{
	/* Create a new ref-counted xfrmi_ip_addr.
	 * The call to refcnt_alloc() counts as a reference */
	struct ipsec_interface_address *new_address =
		refcnt_alloc(struct ipsec_interface_address, HERE);
	new_address->pluto_added = false;
	new_address->if_ip = cidr;
	new_address->next = *ptr;
	*ptr = new_address;
	return new_address;
}

/* returns indirect pointer to struct, or insertion point */

struct ipsec_interface_address **find_ipsec_interface_address_ptr(struct ipsec_interface *ipsecif,
								  ip_cidr search_cidr,
								  struct verbose verbose)
{
	PASSERT(verbose.logger, ipsecif != NULL);

	struct ipsec_interface_address **address = &ipsecif->if_ips;
	for (; (*address) != NULL; address = &(*address)->next) {
		if (cidr_eq_cidr((*address)->if_ip, search_cidr)) {
			cidr_buf cb;
			vdbg("%s() found CIDR %s for ipsec-interface %s ID %d",
			     __func__,
			     str_cidr(&(*address)->if_ip, &cb),
			     ipsecif->name, ipsecif->if_id);

			return address;
		}
	}

	cidr_buf cb;
	vdbg("%s() no CIDR matching %s found",
	     __func__, str_cidr(&search_cidr, &cb));
	return address;
}

void free_ipsec_interface_address_list(struct ipsec_interface_address *xfrmi_ipaddr,
				       const struct logger *logger)
{
	struct ipsec_interface_address *xi = xfrmi_ipaddr;
	struct ipsec_interface_address *xi_next = NULL;

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
			struct ipsec_interface_address *xi_unref_result = NULL;
			do {
				/* delref_where() sets the pointer passed in to NULL
				 * delref_where() will return NULL until the refcount is 0 */
				struct ipsec_interface_address *xi_unref = xi;
				xi_unref_result = delref_where(&xi_unref, logger, HERE);
			} while(xi_unref_result == NULL);
		}
		pfreeany(xi);
		xi = xi_next;
	}
}

/*
 * Get the CIDR to used for the ipsec-interface from the connection.
 *
 * Return an ip_cidr object if found, unset_cidr otherwise.
 */
ip_cidr get_connection_ipsec_interface_cidr(const struct connection *c,
					    struct verbose verbose)
{
	const struct child_end_config *child_config = &(c->local->config->child);

	if (cidr_is_specified(child_config->ipsec_interface_ip)) {
		cidr_buf cb;
		vdbg("%s() taking CIDR from interface-ip=%s for ipsec-interface %s ID %d",
		     __func__, str_cidr(&child_config->ipsec_interface_ip, &cb),
		     c->ipsec_interface->name, c->ipsec_interface->if_id);

		return child_config->ipsec_interface_ip;
	}

	FOR_EACH_ITEM(sip, &child_config->sourceip) {
		/* Use the first sourceip in the list that is set */
		if (sip->is_set) {
			address_buf ab;
			vdbg("%s() taking CIDR from sourceip=%s for ipsec-interface %s ID %d",
			     __func__, str_address(sip, &ab),
			     c->ipsec_interface->name, c->ipsec_interface->if_id);
			return cidr_from_address(*sip);
		}
	}

	/* This is how the updown script previously got the source IP,
	 * especially for the road warrior configuration */
	FOR_EACH_ITEM(spd, &c->child.spds) {
		/* Use the first sourceip in the list that is set */
		ip_address spd_sourceip = spd_end_sourceip(spd->local);
		if (spd_sourceip.is_set) {
			address_buf ab;
			vdbg("%s() taking CIDR from spd_end_sourceip(spd->local) %s for ipsec-interface %s ID %d",
			     __func__, str_address(&spd_sourceip, &ab),
			     c->ipsec_interface->name, c->ipsec_interface->if_id);
			return cidr_from_address(spd_sourceip);
		}
	}

	vdbg("%s() no CIDR found on connection for ipsec-interface %s id %d",
	     __func__, c->ipsec_interface->name, c->ipsec_interface->if_id);

	return unset_cidr;
}

static bool add_kernel_ipsec_interface_address(const struct connection *c,
					       ip_cidr conn_cidr,
					       struct logger *logger)
{
	cidr_buf cb;
	VERBOSE(logger, "%s", str_cidr(&conn_cidr, &cb));

	/*
	 * Get the existing referenced IP, or create it if it doesn't
	 * exist.
	 */
	struct ipsec_interface_address **conn_address_ptr =
			find_ipsec_interface_address_ptr(c->ipsec_interface, conn_cidr, verbose);
	struct ipsec_interface_address *conn_address = (*conn_address_ptr);
	if (conn_address == NULL) {
		/* This call will refcount the object */
		conn_address = alloc_ipsec_interface_address(conn_address_ptr, conn_cidr);
		cidr_buf cb;
		vdbg("%s() created new ipsec_interface_address %s for ipsec-interface %s ID %d",
		     __func__, str_cidr(&conn_address->if_ip, &cb),
		     c->ipsec_interface->name, c->ipsec_interface->if_id);
	} else {
		/* The CIDR already exists, reference count it */
		addref_where(conn_address, HERE);
	}

	/*
	 * Check if the IP is already defined on the interface.
	 *
	 * If it isn't add it, and flag it as such (pluto will need to
	 * delete it).
	 */
	if (!kernel_ops->ipsec_interface->ip_addr_if_has_cidr(c->ipsec_interface->name,
							      conn_address->if_ip,
							      verbose)) {
		conn_address->pluto_added = true;
		if (!kernel_ops->ipsec_interface->ip_addr_add(c->ipsec_interface->name,
							      conn_address, verbose)) {
			cidr_buf cb;
			llog_error(verbose.logger, 0/*no-errno*/,
				   "unable to add CIDR %s to ipsec-interface %s ID %u",
				   str_cidr(&conn_address->if_ip, &cb),
				   c->ipsec_interface->name, c->ipsec_interface->if_id);
			return false;
		}
	}

	return true;
}

/* Return true on success, false on failure */

bool add_kernel_ipsec_interface(const struct connection *c, struct logger *logger)
{
	VERBOSE(logger, "...");

	if (c->ipsec_interface == NULL) {
		vlog("skipped; connection ipsec-interface=no");
		return true;
	}

	if (c->ipsec_interface->if_id == 0) {
		vlog("skipped; connection ipsec-interface=0");
		return true;
	}

	passert(c->ipsec_interface->name != NULL);
	passert(c->iface->real_device_name != NULL);

	if (if_nametoindex(c->ipsec_interface->name) == 0) {
		if (!kernel_ops->ipsec_interface->ip_link_add(c->ipsec_interface->name,
							      c->ipsec_interface->if_id,
							      c->iface, verbose)) {
			return false;
		}

		c->ipsec_interface->pluto_added = true;
	} else {
		/*
		 * Device exists: check that it matches IPSEC_IF_NAME
		 * and IPSEC_IF_ID.
		 */
		struct ip_link_match match = {
			.ipsec_if_name = c->ipsec_interface->name,
			.ipsec_if_id = c->ipsec_interface->if_id,
			.wildcard = false,
		};
		if (!kernel_ops->ipsec_interface->ip_link_match(&match, verbose)) {
			/* .NAME isn't suitable */
			llog_error(verbose.logger, 0/*no-errno*/,
				   "device %s exists but do not match expected type, ipsec-interface %u, or XFRM device is invalid; check 'ip -d link show dev %s'",
				   c->ipsec_interface->name, c->ipsec_interface->if_id, c->ipsec_interface->name);
			return false;
		}
	}

	/*
	 * Get the IP to use on the ipsec-interface from the
	 * connection.
	 *
	 * - If it doesn't exist, nothing to add to the interface
	 */
	ip_cidr conn_cidr = get_connection_ipsec_interface_cidr(c, verbose);
	if (cidr_is_specified(conn_cidr)) {
		if (!add_kernel_ipsec_interface_address(c, conn_cidr, logger)) {
			return false;
		}
	} else {
		vdbg("no CIDR to set on ipsec-interface %s ID %d",
		     c->ipsec_interface->name, c->ipsec_interface->if_id);
	}

	/* make certain that the interface is up */
	return kernel_ops->ipsec_interface->ip_link_up(c->ipsec_interface->name, verbose);
}

static void remove_kernel_ipsec_interface_address(const struct connection *c,
						  ip_cidr conn_cidr,
						  struct logger *logger)
{
	cidr_buf cb;
	VERBOSE(logger, "removing %s", str_cidr(&conn_cidr, &cb));

	/*
	 * Use that to find the address structure.
	 */
	struct ipsec_interface_address **conn_address_ptr =
			find_ipsec_interface_address_ptr(c->ipsec_interface, conn_cidr, verbose);
	if ((*conn_address_ptr) == NULL) {
		/* This should never happen */
		cidr_buf cb;
		llog_pexpect(logger, HERE,
			     "unable to unreference CIDR %s on ipsec-interface %s ID %d",
			     str_cidr(&conn_cidr, &cb),
			     c->ipsec_interface->name, c->ipsec_interface->if_id);
		return;
	}

	vdbg("%s() addressr=%p name=%s if_id=%u IP [%s] refcount=%u (before)",
	     __func__,
	     (*conn_address_ptr), c->ipsec_interface->name, c->ipsec_interface->if_id,
	     str_cidr(&(*conn_address_ptr)->if_ip, &cb),
	     refcnt_peek((*conn_address_ptr), logger));

	/*
	 * Decrement the reference:
	 *
	 * - The pointer CONN_ADDRESS passed in will be set to NULL
	 *
	 * - Returns a pointer to the object to be deleted when its
         *   the last one.
	 */
	struct ipsec_interface_address *tmp_address = (*conn_address_ptr);
	struct ipsec_interface_address *conn_address = delref_where(&tmp_address, logger, HERE);
	if (conn_address == NULL) {
		vdbg("%s() delref returned NULL, simple delref", __func__);
		return;
	}

	/* Remove the entry from the ip_ips list */
	(*conn_address_ptr) = conn_address->next;

	/* Check if the IP should be removed from the interface */
	if (conn_address->pluto_added) {
		kernel_ops->ipsec_interface->ip_addr_del(c->ipsec_interface->name,
							 conn_address, verbose);
		cidr_buf cb;
		llog(RC_LOG, logger,
		     "delete ipsec-interface=%s if_id=%u IP [%s] added by pluto",
		     c->ipsec_interface->name, c->ipsec_interface->if_id,
		     str_cidr(&conn_cidr, &cb));
	} else {
		cidr_buf cb;
		llog(RC_LOG, logger,
		     "cannot delete ipsec-interface=%s if_id=%u IP [%s], not created by pluto",
		     c->ipsec_interface->name, c->ipsec_interface->if_id,
		     str_cidr(&conn_cidr, &cb));
	}

	/* Free the memory */
	pfreeany(conn_address);
}

void remove_kernel_ipsec_interface(const struct connection *c, struct logger *logger)
{
	VERBOSE(logger, "...");

	if (c->ipsec_interface == NULL) {
		vlog("skipped; connection ipsec-interface=no");
		return;
	}

	if (c->ipsec_interface->if_id == 0) {
		vlog("skipped; connection ipsec-interface=0 (previously installed)");
		return;
	}

	/*
	 * Find the IP address assigned to the connection.
	 */
	ip_cidr conn_cidr = get_connection_ipsec_interface_cidr(c, verbose);
	if (conn_cidr.is_set == false) {
		vdbg("no CIDR to unreference on ipsec-interface %s ID %d",
		     c->ipsec_interface->name, c->ipsec_interface->if_id);
		return;
	}

	remove_kernel_ipsec_interface_address(c, conn_cidr, logger);
}

static struct ipsec_interface *find_ipsec_interface_by_id(uint32_t if_id)
{
	struct ipsec_interface *h;
	struct ipsec_interface *ret = NULL;

	for (h = ipsec_interfaces;  h != NULL; h = h->next) {
		if (h->if_id == if_id) {
			ret = h;
			break;
		}
	}

	return ret;
}

static struct ipsec_interface *alloc_ipsec_interface(const char *name, uint32_t if_id)
{
	struct ipsec_interface **head = &ipsec_interfaces;
	/*
	 * Create a new ref-counted ipsec_interface, it is not added
	 * to system yet.  The call to refcnt_alloc() counts as the
	 * first reference.
	 */
	struct ipsec_interface *p = refcnt_alloc(struct ipsec_interface, HERE);
	p->if_id = if_id;
	p->name = clone_str(name, "ipsec_interface name");
	/* add to known interfaces */
	p->next = *head;
	*head = p;
	return p;
}

struct ipsec_interface *ipsec_interface_addref(struct ipsec_interface *ipsec_if,
					       struct logger *logger UNUSED, where_t where)
{
	return addref_where(ipsec_if, where);
}

void ipsec_interface_delref(struct ipsec_interface **ipsec_if,
			    struct logger *logger, where_t where)
{
	VERBOSE(logger, "%p", *ipsec_if);

	struct ipsec_interface *ipsec_interface = delref_where(ipsec_if, logger, where);
	if (ipsec_interface != NULL) {
		/* last reference (ignoring list entry) */
		for (struct ipsec_interface **pp = &ipsec_interfaces;
		     (*pp) != NULL; pp = &(*pp)->next) {
			if ((*pp) == ipsec_interface) {
				/* unlink */
				(*pp) = (*pp)->next;
				/* delete*/
				if (ipsec_interface->pluto_added) {
					kernel_ops->ipsec_interface->ip_link_del(ipsec_interface->name, verbose);
					llog(RC_LOG, logger,
					     "delete ipsec-interface=%s if_id=%u added by pluto",
					     ipsec_interface->name, ipsec_interface->if_id);
				} else {
					vdbg("skipping delete ipsec-interface=%s if_id=%u, never added pluto",
					     ipsec_interface->name, ipsec_interface->if_id);
				}
				/*
				 * Free the IPs that were already on
				 * the interface (not added by
				 * pluto).
				 */
				free_ipsec_interface_address_list(ipsec_interface->if_ips, logger);
				pfreeany(ipsec_interface->name);
				pfreeany(ipsec_interface);
				return;
			}
			vdbg("(*pp)=%p ipsec_interface=%p", (*pp), ipsec_interface);
		}
		llog_pexpect(logger, where,
			     "%p ipsec-interface=%s if_id=%u not found in the list",
			     ipsec_interface, ipsec_interface->name, ipsec_interface->if_id);
	}
}

diag_t add_connection_ipsec_interface(struct connection *c, const char *ipsec_interface)
{
	VERBOSE(c->logger, "adding %s", ipsec_interface);

	/*
	 * Danger; yn_option_names includes "0" and "1" but that isn't
	 * wanted here!  Hence yn_text_option_names.
	 */
	const struct sparse_name *yn = sparse_lookup(&yn_text_option_names,
						     shunk1(ipsec_interface));
	if (yn != NULL && yn->value == YN_NO) {
		/* well that was pointless */
		vdbg("ipsec-interface=%s is no!", ipsec_interface);
		return NULL;
	}

	/*
	 * Note: check for kernel support after YN check; this way
	 * ipsec-interface=no is silently ignored.
	 */
	if (kernel_ops->ipsec_interface == NULL) {
		return diag("ipsec-interface is not implemented by %s",
			    kernel_ops->interface_name);
	}

	if (kernel_ops->ipsec_interface->supported == NULL) {
		return diag("ipsec-interface=%s is not implemented by %s",
			    ipsec_interface, kernel_ops->interface_name);
	}

	/* something other than ipsec-interface=no, check support */
	err_t err = kernel_ops->ipsec_interface->supported(verbose);
	if (err != NULL) {
		return diag("ipsec-interface=%s not supported: %s",
			    ipsec_interface, err);
	}

	uint32_t if_id;
	if (yn != NULL) {
		PEXPECT(c->logger, yn->value == YN_YES);
		if_id = 1; /* YES means 1 */
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

		if (value == 0 &&
		    kernel_ops->ipsec_interface->map_if_id_zero != 0) {
			vdbg("remap ipsec0 to %"PRIu32" because VTI allowed zero but XFRMi does not",
			     kernel_ops->ipsec_interface->map_if_id_zero);
			if_id = kernel_ops->ipsec_interface->map_if_id_zero;
		} else {
			if_id = value;
		}
	}

	vdbg("ipsec-interface=%s parsed to %"PRIu32, ipsec_interface, if_id);

	/* check if interface is already used by pluto */

	struct ipsec_interface *ipsec_iface = find_ipsec_interface_by_id(if_id);
	if (ipsec_iface != NULL) {
		c->ipsec_interface = ipsec_interface_addref(ipsec_iface, c->logger, HERE);
		return NULL;
	}

	/*
	 * Create a new ipsec-interface structure (but don't yet
	 * install in the kernel) or probe it.
	 */

	ipsec_interface_id_buf ifb;
	const char *name = str_ipsec_interface_id(if_id, &ifb);
	c->ipsec_interface = alloc_ipsec_interface(name, if_id);

	return NULL;
}

void check_stale_ipsec_interfaces(struct logger *logger)
{
	if (kernel_ops->ipsec_interface->check_stale_ipsec_interfaces != NULL) {
		kernel_ops->ipsec_interface->check_stale_ipsec_interfaces(logger);
	}
}

void shutdown_kernel_ipsec_interface(struct logger *logger)
{
	VERBOSE(logger, "...");
	if (kernel_ops->ipsec_interface->shutdown != NULL) {
		kernel_ops->ipsec_interface->shutdown(verbose);
	}
}
