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

static ip_cidr get_connection_ipsec_interface_cidr(const struct connection *c,
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
 * Create an internal ipsec_interface_address address structure and
 * add it to the ipsec_interface.
 *
 * Caller must save reference somewhere.  On last delref, address is
 * removed from the ipsec_if list.
 */

static struct ipsec_interface_address *alloc_ipsec_interface_address(struct ipsec_interface *ipsec_if,
								     ip_cidr cidr)
{
	struct ipsec_interface_address *new_address =
		refcnt_alloc(struct ipsec_interface_address, HERE);
	new_address->pluto_added = false;
	new_address->if_ip = cidr;
	/* add to front */
	new_address->next = ipsec_if->if_ips;
	ipsec_if->if_ips = new_address;
	return new_address;
}

/* returns indirect pointer to struct, or insertion point */

static struct ipsec_interface_address *find_ipsec_interface_address(struct ipsec_interface *ipsec_if,
								     ip_cidr search_cidr,
								     struct verbose verbose)
{
	PASSERT(verbose.logger, ipsec_if != NULL);

	for (struct ipsec_interface_address *address = ipsec_if->if_ips;
	     address != NULL; address = address->next) {
		if (cidr_eq_cidr(address->if_ip, search_cidr)) {
			cidr_buf cb;
			ipsec_interface_buf ib;
			vdbg("found %s for ipsec-interface %s",
			     str_cidr(&address->if_ip, &cb),
			     str_ipsec_interface(ipsec_if, &ib));

			return address;
		}
	}

	cidr_buf cb;
	vdbg("no CIDR matching %s found", str_cidr(&search_cidr, &cb));
	return NULL;
}

static struct ipsec_interface_address *ipsec_interface_address_addref(struct ipsec_interface_address *address,
								      where_t where)
{
	return addref_where(address, where);
}

static void ipsec_interface_address_delref(struct ipsec_interface *ipsec_if,
					   struct ipsec_interface_address **ipsec_if_address,
					   struct verbose verbose)
{
	/*
	 * Decrement the reference:
	 *
	 * - The pointer IPSEC_IF_ADDRESS passed in will be set to
             NULL
	 *
	 * - Returns a pointer to the object to be deleted when its
         *   the last one.
	 */
	struct ipsec_interface_address *address = delref_where(ipsec_if_address, verbose.logger, HERE);
	if (address == NULL) {
		vdbg("%s() delref returned NULL, simple delref", __func__);
		return;
	}

	/*
	 * Find and remove the entry from the ipsec_if list.
	 */

	for (struct ipsec_interface_address **pp = &ipsec_if->if_ips;
	     (*pp) != NULL; pp = &(*pp)->next) {
		if ((*pp) == address) {

			/* Remove the entry from the ip_ips list */
			(*pp) = address->next;
			address->next = NULL;

			/* Check if the IP should be removed from the interface */
			if (address->pluto_added) {
				kernel_ipsec_interface_del_cidr(ipsec_if->name, address->if_ip, verbose);
				cidr_buf cb;
				ipsec_interface_buf ib;
				vlog("delete ipsec-interface %s IP [%s] added by pluto",
				     str_ipsec_interface(ipsec_if, &ib),
				     str_cidr(&address->if_ip, &cb));
			} else {
				cidr_buf cb;
				ipsec_interface_buf ib;
				vlog("cannot delete ipsec-interface %s IP [%s], not created by pluto",
				     str_ipsec_interface(ipsec_if, &ib),
				     str_cidr(&address->if_ip, &cb));
			}

			/* Free the memory */
			pfreeany(address);
			return;

		}
	}

	/*
	 * Should never happen.  The ipsec_if is always the last
	 * (uncounted) reference.
	 */
	cidr_buf cb;
	ipsec_interface_buf ib;
	llog_pexpect(verbose.logger, HERE,
		     "can't remove %s, not assigned to ipsec-interface %s",
		     str_cidr(&address->if_ip, &cb),
		     str_ipsec_interface(ipsec_if, &ib));
	/* drop it on the floor */
	return;
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

static bool add_kernel_ipsec_interface_address_1(struct connection *c,
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
	 * does, take an additional reference.
	 *
	 * XXX: this is pretty broken: the connection should be
	 * tracking the addresses being added so it can easily remove
	 * them (currently it relies on a second
	 * get_connection_ipsec_interface_cidr9) call and that is
	 * using dynamic values.
	 */
	struct ipsec_interface_address *address =
		find_ipsec_interface_address(c->ipsec_interface, conn_cidr, verbose);
	if (address != NULL) {
		cidr_buf cb;
		ipsec_interface_buf ib;
		vdbg("ipsec-interface %s already has %s, adding a reference from this connection",
		     str_ipsec_interface(c->ipsec_interface, &ib),
		     str_cidr(&conn_cidr, &cb));
		vexpect(c->ipsec_interface_address == NULL);
		c->ipsec_interface_address = ipsec_interface_address_addref(address, HERE);
		if (!kernel_ipsec_interface_has_cidr(c->ipsec_interface->name, address->if_ip,
						     verbose)) {
			cidr_buf cb;
			llog_pexpect(verbose.logger, HERE,
				     "ipsec-interface %s ID %u has %s but the kernel interface does not!?!",
				     c->ipsec_interface->name, c->ipsec_interface->if_id,
				     str_cidr(&address->if_ip, &cb));
		}
		return true;
	}

	/*
	 * Create the new address and, if necessary, add it to the
	 * interface.
	 */

	vexpect(c->ipsec_interface_address == NULL);
	c->ipsec_interface_address = alloc_ipsec_interface_address(c->ipsec_interface, conn_cidr);

	if (kernel_ipsec_interface_has_cidr(c->ipsec_interface->name,
					    c->ipsec_interface_address->if_ip,
					    verbose)) {
		cidr_buf cb;
		vdbg("ipsec-interface %s ID %u already has %s",
		     c->ipsec_interface->name, c->ipsec_interface->if_id,
		     str_cidr(&c->ipsec_interface_address->if_ip, &cb));
		c->ipsec_interface_address->pluto_added = false; /* redundant */
		return true;
	}

	c->ipsec_interface_address->pluto_added = true;
	if (!kernel_ipsec_interface_add_cidr(c->ipsec_interface->name,
					     c->ipsec_interface_address->if_ip,
					     verbose)) {
		cidr_buf cb;
		llog_error(verbose.logger, 0/*no-errno*/,
			   "unable to add CIDR %s to ipsec-interface %s ID %u",
			   str_cidr(&c->ipsec_interface_address->if_ip, &cb),
			   c->ipsec_interface->name, c->ipsec_interface->if_id);
		return false;
	}

	cidr_buf cb;
	ipsec_interface_buf ib;
	vlog("added %s to ipsec-interface %s",
	     str_cidr(&c->ipsec_interface_address->if_ip, &cb),
	     str_ipsec_interface(c->ipsec_interface, &ib));

	return true;
}

bool add_kernel_ipsec_interface_address(struct connection *c,
					struct logger *logger)
{
	VERBOSE_DBGP(DBG_BASE, logger, "...");

	if (c->ipsec_interface == NULL) {
		vdbg("skipped; no ipsec-interface");
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

void del_kernel_ipsec_interface_address(struct connection *c,
					struct logger *logger)
{

	VERBOSE_DBGP(DBG_BASE, logger, "...");

	if (c->ipsec_interface == NULL) {
		vdbg("skipped; no ipsec-interface");
		return;
	}

	if (c->ipsec_interface_address == NULL) {
		vdbg("skipped; no ipsec-interface-address to delete");
		return;
	}

	cidr_buf cb;
	vdbg("removing %s", str_cidr(&c->ipsec_interface_address->if_ip, &cb));
	ipsec_interface_address_delref(c->ipsec_interface, &c->ipsec_interface_address, verbose);
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
	VERBOSE_DBGP(DBG_BASE, logger, "%p", *ipsec_if);

	struct ipsec_interface *ipsec_interface = delref_where(ipsec_if, logger, where);
	if (ipsec_interface == NULL) {
		return;
	}

	/*
	 * Last reference (ignoring list entry); remove it from the
	 * list.
	 */
	for (struct ipsec_interface **pp = &ipsec_interfaces;
	     (*pp) != NULL; pp = &(*pp)->next) {
		if ((*pp) == ipsec_interface) {
			/* unlink */
			(*pp) = ipsec_interface->next;
			ipsec_interface->next = NULL;
			/*
			 * Any IP addresses should have
			 * already been released!
			 */
			vexpect(ipsec_interface->if_ips == NULL);
			/*
			 * Now release the interface.
			 */
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
			pfreeany(ipsec_interface);
			return;
		}
	}

	/*
	 * Should never happen, the ipsec_interfaces list always has
	 * the last (uncounted) reference.
	 */
	llog_pexpect(logger, where,
		     "%p ipsec-interface=%s if_id=%u not found in the list",
		     ipsec_interface, ipsec_interface->name, ipsec_interface->if_id);
}

diag_t parse_ipsec_interface(struct config *config,
			     const char *ipsec_interface,
			     struct logger *logger)
{
	VERBOSE_DBGP(DBG_BASE, logger, "adding %s to config", ipsec_interface);

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

bool add_ipsec_interface(struct connection *c,
			 const struct iface_device *iface)
{
	ipsec_interface_buf ifb;
	VERBOSE_DBGP(DBG_BASE, c->logger, "adding %s@%s to connection",
		     str_ipsec_interface_id(c->config->ipsec_interface.id, &ifb),
		     iface->real_device_name);

	if (vbad(!c->config->ipsec_interface.enabled) ||
	    vbad(c->ipsec_interface != NULL)) {
		return false;
	}

	/*
	 * Check if interface is already used by pluto.
	 *
	 * XXX This should also check that the linked iface is
	 * correct.
	 */

	struct ipsec_interface *ipsec_if =
		find_ipsec_interface_by_id(c->config->ipsec_interface.id);
	if (ipsec_if != NULL) {
		c->ipsec_interface = ipsec_interface_addref(ipsec_if, c->logger, HERE);
		return true;
	}

	char ipsec_if_name[IFNAMSIZ];
	snprintf(ipsec_if_name, IFNAMSIZ, "%s%u",
		 kernel_ops->ipsec_interface->name,
		 unmap_id(c->config->ipsec_interface.id));

	/*
	 * The device is missing, try to create it.
	 */

	if (if_nametoindex(ipsec_if_name) == 0) {
		if (!kernel_ipsec_interface_add(ipsec_if_name,
						c->config->ipsec_interface.id,
						iface, verbose)) {
			return false;
		}
		c->ipsec_interface = alloc_ipsec_interface(c->config->ipsec_interface.id);
		jam_str(c->ipsec_interface->physical, sizeof(c->ipsec_interface->physical),
			iface->real_device_name);
		c->ipsec_interface->pluto_added = true;
		ipsec_interface_buf ib;
		vlog("created ipsec-interface %s",
		     str_ipsec_interface(c->ipsec_interface, &ib));
		return true;
	}

	/*
	 * Device exists: check that it matches IPSEC_IF_NAME
	 * and IPSEC_IF_ID and has a valid LINK.
	 */

	struct ipsec_interface_match match = {
		.ipsec_if_name = ipsec_if_name,
		.ipsec_if_id = c->config->ipsec_interface.id,
		.iface_if_index = if_nametoindex(iface->real_device_name),
		.wildcard = false,
	};
	if (vbad(match.iface_if_index == 0)) {
		return false;
	}

	if (!kernel_ipsec_interface_match(&match, verbose)) {
		/* .NAME isn't suitable */
		llog_error(verbose.logger, 0/*no-errno*/,
			   "existing ipsec-interface %s is not valid: %s",
			   ipsec_if_name, str_diag(match.diag));
		pfree_diag(&match.diag);
		return false;
	}

	c->ipsec_interface = alloc_ipsec_interface(c->config->ipsec_interface.id);
	jam_str(c->ipsec_interface->physical, sizeof(c->ipsec_interface->physical),
		iface->real_device_name);
	ipsec_interface_buf ib;
	vdbg("using ipsec-interface %s", str_ipsec_interface(c->ipsec_interface, &ib));
	return true;
}

void check_stale_ipsec_interfaces(struct logger *logger)
{
	VERBOSE_DBGP(DBG_BASE, logger, "...");
	kernel_ipsec_interface_check_stale(verbose);
}
