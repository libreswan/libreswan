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

#include <errno.h>

#include "passert.h"
#include "sparse_names.h"

#include "ipsec_interface.h"
#include "kernel.h"
#include "kernel_ipsec_interface.h"
#include "log.h"
#include "verbose.h"
#include "iface.h"

struct ipsec_interface_address *alloc_ipsec_interface_address(struct ipsec_interface_address **ptr,
							      ip_cidr if_ip);
void free_ipsec_interface_address_list(struct ipsec_interface_address *ipsec_ifaddr,
				       const struct logger *logger);

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

static unsigned unmap_id(ipsec_interface_id_t ipsec_if_id)
{
	if (ipsec_if_id == kernel_ops->ipsec_interface->map_if_id_zero) {
		return 0;
	}
	return ipsec_if_id;
}

size_t jam_ipsec_interface_id(struct jambuf *buf, ipsec_interface_id_t ipsec_if_id)
{
	/* Map the IPSEC_IF_ID back to the name's number, when
	 * needed */
	unsigned id = unmap_id(ipsec_if_id);
	size_t s = jam(buf, "%s%u", kernel_ops->ipsec_interface->name, id);
	if (id != ipsec_if_id) {
		jam(buf, "[%u]", ipsec_if_id);
	}
	return s;
}

const char *str_ipsec_interface_id(ipsec_interface_id_t if_id,
				   ipsec_interface_buf *buf)
{
	struct jambuf jb = ARRAY_AS_JAMBUF(buf->buf);
	jam_ipsec_interface_id(&jb, if_id);
	return buf->buf;
}

size_t jam_ipsec_interface(struct jambuf *buf,
			   const struct ipsec_interface *ipsec_if)
{
	if (ipsec_if == NULL) {
		return jam_string(buf, "<null>");
	}

	size_t s = 0;
	/* ipsecN[M] */
	s += jam_ipsec_interface_id(buf, ipsec_if->if_id);
	/* @eth0 */
	if (ipsec_if->physical[0] != '\0') {
		s += jam_string(buf, "@");
		s += jam_string(buf, ipsec_if->physical);
	}
	return s;
}

const char *str_ipsec_interface(const struct ipsec_interface *ipsec_if,
				ipsec_interface_buf *buf)
{
	struct jambuf jb = ARRAY_AS_JAMBUF(buf->buf);
	jam_ipsec_interface(&jb, ipsec_if);
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

struct ipsec_interface_address **find_ipsec_interface_address_ptr(struct ipsec_interface *ipsec_if,
								  ip_cidr search_cidr,
								  struct verbose verbose)
{
	PASSERT(verbose.logger, ipsec_if != NULL);

	struct ipsec_interface_address **address = &ipsec_if->if_ips;
	for (; (*address) != NULL; address = &(*address)->next) {
		if (cidr_eq_cidr((*address)->if_ip, search_cidr)) {
			cidr_buf cb;
			ipsec_interface_buf ib;
			vdbg("found %s for ipsec-interface %s",
			     str_cidr(&(*address)->if_ip, &cb),
			     str_ipsec_interface(ipsec_if, &ib));

			return address;
		}
	}

	cidr_buf cb;
	vdbg("no CIDR matching %s found", str_cidr(&search_cidr, &cb));
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
		ipsec_interface_buf ib;
		vdbg("using interface-ip=%s for ipsec-interface %s",
		     str_cidr(&child_config->ipsec_interface_ip, &cb),
		     str_ipsec_interface(c->ipsec_interface, &ib));

		return child_config->ipsec_interface_ip;
	}

	FOR_EACH_ITEM(sip, &child_config->sourceip) {
		/* Use the first sourceip in the list that is set */
		if (sip->is_set) {
			address_buf ab;
			ipsec_interface_buf ib;
			vdbg("using sourceip=%s for ipsec-interface %s",
			     str_address(sip, &ab),
			     str_ipsec_interface(c->ipsec_interface, &ib));
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
			ipsec_interface_buf ib;
			vdbg("using spd_end_sourceip(spd->local) %s for ipsec-interface %s",
			     str_address(&spd_sourceip, &ab),
			     str_ipsec_interface(c->ipsec_interface, &ib));
			return cidr_from_address(spd_sourceip);
		}
	}

	ipsec_interface_buf ib;
	vdbg("no CIDR found on connection for ipsec-interface %s",
	     str_ipsec_interface(c->ipsec_interface, &ib));

	return unset_cidr;
}

static bool add_kernel_ipsec_interface_address_1(const struct connection *c,
						 struct verbose verbose)
{
	/*
	 * Get the IP to use on the ipsec-interface from the
	 * connection.
	 *
	 * If it doesn't exist, nothing to add to the interface; but
	 * still UP it.
	 *
	 * XXX: this is pretty broken: the code assumes there's a
	 * single IPv4 xor IPv6 address but both and even more should
	 * be allowed.
	 */
	ip_cidr conn_cidr = get_connection_ipsec_interface_cidr(c, verbose);
	if (!cidr_is_specified(conn_cidr)) {
		vdbg("no CIDR to set on ipsec-interface %s ID %d",
		     c->ipsec_interface->name, c->ipsec_interface->if_id);
		return true;
	}

	/*
	 * See if the ipsec-interface already has the address; if it
	 * does, up it's refcnt.
	 *
	 * XXX: this is pretty broken: the connection should be
	 * tracking the addresses being added so it can easily remove
	 * them (currently it relies on a second
	 * get_connection_ipsec_interface_cidr9) call and that is
	 * using dynamic values.
	 */
	struct ipsec_interface_address **conn_address_ptr =
			find_ipsec_interface_address_ptr(c->ipsec_interface, conn_cidr, verbose);
	struct ipsec_interface_address *conn_address = (*conn_address_ptr);
	if (conn_address != NULL) {
		cidr_buf cb;
		ipsec_interface_buf ib;
		vdbg("ipsec-interface %s already has %s, adding a reference for this connection",
		     str_ipsec_interface(c->ipsec_interface, &ib),
		     str_cidr(&conn_cidr, &cb));
		addref_where(conn_address, HERE);
		if (!kernel_ipsec_interface_has_cidr(c->ipsec_interface->name,
						     conn_address->if_ip,
						     verbose)) {
			cidr_buf cb;
			llog_pexpect(verbose.logger, HERE,
				     "ipsec-interface %s ID %u has %s but the kernel interface does not!?!",
				     c->ipsec_interface->name, c->ipsec_interface->if_id,
				     str_cidr(&conn_cidr, &cb));
		}
		return true;
	}

	/*
	 * Create the new address and, if necessary, add it to the
	 * interface.
	 */

	conn_address = alloc_ipsec_interface_address(conn_address_ptr, conn_cidr);

	if (kernel_ipsec_interface_has_cidr(c->ipsec_interface->name,
					    conn_address->if_ip,
					    verbose)) {
		cidr_buf cb;
		vdbg("ipsec-interface %s ID %u already has %s",
		     c->ipsec_interface->name, c->ipsec_interface->if_id,
		     str_cidr(&conn_address->if_ip, &cb));
		conn_address->pluto_added = false; /* redundant */
		return true;
	}

	conn_address->pluto_added = true;
	if (!kernel_ipsec_interface_add_cidr(c->ipsec_interface->name,
					     conn_address->if_ip, verbose)) {
		cidr_buf cb;
		llog_error(verbose.logger, 0/*no-errno*/,
			   "unable to add CIDR %s to ipsec-interface %s ID %u",
			   str_cidr(&conn_address->if_ip, &cb),
			   c->ipsec_interface->name, c->ipsec_interface->if_id);
		return false;
	}

	return true;
}

bool add_kernel_ipsec_interface_address(const struct connection *c,
					struct logger *logger)
{
	VERBOSE(logger, "...");

	if (c->ipsec_interface == NULL) {
		vlog("skipped; connection ipsec-interface=no");
		return true;
	}

	if (vbad(c->iface == NULL) ||
	    vbad(c->iface->real_device_name == NULL)) {
		return false;
	}

	if (!add_kernel_ipsec_interface_address_1(c, verbose)) {
		return false;
	}

	/* make certain that the interface is up */
	return kernel_ipsec_interface_up(c->ipsec_interface->name, verbose);
}

/* Return true on success, false on failure */

bool add_kernel_ipsec_interface(const struct connection *c,
				const struct iface_device *local_iface,
				ip_address remote_address,
				struct logger *logger)
{
	VERBOSE(logger, "...");

	if (c->ipsec_interface == NULL) {
		vlog("skipped; connection ipsec-interface=no");
		return true;
	}

	vassert(c->ipsec_interface->name != NULL);
	/* Note: during orient c->iface is bogus */
	vassert(local_iface->real_device_name != NULL);

	bool created;
	if (if_nametoindex(c->ipsec_interface->name) == 0) {
		if (!kernel_ipsec_interface_add(c->ipsec_interface->name,
						c->ipsec_interface->if_id,
						local_iface, remote_address,
						verbose)) {
			return false;
		}

		c->ipsec_interface->pluto_added = true;
		created = true;
	} else {
		/*
		 * Device exists: check that it matches IPSEC_IF_NAME
		 * and IPSEC_IF_ID and has a valid LINK.
		 *
		 * Note: pluto may have added this device during an
		 * earlier call.
		 */
		struct ipsec_interface_match match = {
			.ipsec_if_name = c->ipsec_interface->name,
			.ipsec_if_id = c->ipsec_interface->if_id,
			.iface_if_index = if_nametoindex(local_iface->real_device_name),
			.wildcard = false,
		};
		if (vbad(match.iface_if_index == 0)) {
			return false;
		}
		if (!kernel_ipsec_interface_match(&match, verbose)) {
			/* .NAME isn't suitable */
			ipsec_interface_buf ib;
			llog_error(verbose.logger, 0/*no-errno*/,
				   "existing ipsec-interface %s is not valid: %s",
				   str_ipsec_interface(c->ipsec_interface, &ib),
				   str_diag(match.diag));
			pfree_diag(&match.diag);
			return false;
		}
		created = false;
	}

	/*
	 * Save the name for logging.  Should take a reference to
	 * iface but that will end up wrong when there's a re-orient
	 * since it isn't triggering a kernel ipsec-interface update.
	 */
	jam_str(c->ipsec_interface->physical, sizeof(c->ipsec_interface->physical),
		c->iface->real_device_name);

	if (created) {
		ipsec_interface_buf ib;
		vdbg("added ipsec-interface %s",
		     str_ipsec_interface(c->ipsec_interface, &ib));
	} else {
		ipsec_interface_buf ib;
		vdbg("linked ipsec-interface %s",
		     str_ipsec_interface(c->ipsec_interface, &ib));
	}

	return true;
}

void del_kernel_ipsec_interface_address(const struct connection *c,
					struct logger *logger)
{

	VERBOSE(logger, "...");

	if (c->ipsec_interface == NULL) {
		vlog("skipped; connection ipsec-interface=no");
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
	cidr_buf cb;
	vlog("removing %s", str_cidr(&conn_cidr, &cb));

	/*
	 * Use that to find the address structure.
	 */
	struct ipsec_interface_address **conn_address_ptr =
			find_ipsec_interface_address_ptr(c->ipsec_interface, conn_cidr, verbose);
	if ((*conn_address_ptr) == NULL) {
		/* This should never happen */
		cidr_buf cb;
		ipsec_interface_buf ib;
		llog_pexpect(logger, HERE,
			     "can't remove %s, not assigned to ipsec-interface %s",
			     str_cidr(&conn_cidr, &cb),
			     str_ipsec_interface(c->ipsec_interface, &ib));
		return;
	}

	ipsec_interface_buf ib;
	vdbg("addressr=%p ipsec-interface %s IP [%s] refcount=%u (before)",
	     (*conn_address_ptr),
	     str_ipsec_interface(c->ipsec_interface, &ib),
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
		kernel_ipsec_interface_del_cidr(c->ipsec_interface->name,
						conn_address->if_ip, verbose);
		cidr_buf cb;
		ipsec_interface_buf ib;
		llog(RC_LOG, logger,
		     "delete ipsec-interface %s IP [%s] added by pluto",
		     str_ipsec_interface(c->ipsec_interface, &ib),
		     str_cidr(&conn_cidr, &cb));
	} else {
		cidr_buf cb;
		ipsec_interface_buf ib;
		llog(RC_LOG, logger,
		     "cannot delete ipsec-interface %s IP [%s], not created by pluto",
		     str_ipsec_interface(c->ipsec_interface, &ib),
		     str_cidr(&conn_cidr, &cb));
	}

	/* Free the memory */
	pfreeany(conn_address);
}

static struct ipsec_interface *find_ipsec_interface_by_id(ipsec_interface_id_t if_id)
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

static struct ipsec_interface *alloc_ipsec_interface(ipsec_interface_id_t ipsec_if_id)
{
	/*
	 * Create a new ref-counted ipsec_interface, it is not added
	 * to system yet.  The call to refcnt_alloc() counts as the
	 * first reference.
	 */
	struct ipsec_interface *p = refcnt_alloc(struct ipsec_interface, HERE);
	p->if_id = ipsec_if_id;
	/* unmap the ID and then generate the name; can't use str*id()
	 * function above as that appends [] */
	int l = snprintf(p->name, sizeof(p->name), "%s%u",
			 kernel_ops->ipsec_interface->name,
			 unmap_id(ipsec_if_id));
	passert(l < IFNAMSIZ);
	/* add to known interfaces */
	p->next = ipsec_interfaces;
	ipsec_interfaces = p;
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
					kernel_ipsec_interface_del(ipsec_interface->name,
								   verbose);
					ipsec_interface_buf ib;
					llog(RC_LOG, logger,
					     "delete ipsec-interface %s added by pluto",
					     str_ipsec_interface(ipsec_interface, &ib));
				} else {
					ipsec_interface_buf ib;
					vdbg("skipping delete ipsec-interface %s, never added pluto",
					     str_ipsec_interface(ipsec_interface, &ib));
				}
				/*
				 * Free the IPs that were already on
				 * the interface (not added by
				 * pluto).
				 */
				free_ipsec_interface_address_list(ipsec_interface->if_ips, logger);
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

diag_t parse_ipsec_interface(struct config *config,
			     const char *ipsec_interface,
			     struct logger *logger)
{
	VERBOSE(logger, "adding %s to config", ipsec_interface);

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

	/* something other than ipsec-interface=no, check support */
	err_t err = kernel_ipsec_interface_supported(verbose);
	if (err != NULL) {
		return diag("ipsec-interface=%s not supported: %s",
			    ipsec_interface, err);
	}

	ipsec_interface_id_t if_id;
	if (yn != NULL) {
		vexpect(yn->value == YN_YES);
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
			vdbg("remap ipsec0 to %u because VTI allowed zero but XFRMi does not",
			     kernel_ops->ipsec_interface->map_if_id_zero);
			if_id = kernel_ops->ipsec_interface->map_if_id_zero;
		} else {
			if_id = value;
		}
	}

	ipsec_interface_buf ib;
	vdbg("ipsec-interface=%s parsed to %s",
	     ipsec_interface, str_ipsec_interface_id(if_id, &ib));

	config->ipsec_interface.enabled = true;
	config->ipsec_interface.id = if_id;

	return NULL;
}

void add_ipsec_interface(struct connection *c)
{
	ipsec_interface_buf ifb;
	VERBOSE(c->logger, "adding %s to connection",
		str_ipsec_interface_id(c->config->ipsec_interface.id, &ifb));

	if (!vexpect(c->config->ipsec_interface.enabled)) {
		return;
	}

	/* check if interface is already used by pluto */

	struct ipsec_interface *ipsec_iface =
		find_ipsec_interface_by_id(c->config->ipsec_interface.id);
	if (ipsec_iface != NULL) {
		c->ipsec_interface = ipsec_interface_addref(ipsec_iface, c->logger, HERE);
		return;
	}

	/*
	 * Create a new ipsec-interface structure (but don't yet
	 * install in the kernel) or probe it.
	 */

	c->ipsec_interface = alloc_ipsec_interface(c->config->ipsec_interface.id);
}

void check_stale_ipsec_interfaces(struct logger *logger)
{
	VERBOSE(logger, "...");
	kernel_ipsec_interface_check_stale(verbose);
}

void shutdown_kernel_ipsec_interface(struct logger *logger)
{
	VERBOSE(logger, "...");
	kernel_ipsec_interface_shutdown(verbose);
}
