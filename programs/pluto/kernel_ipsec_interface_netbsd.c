/* BSD's IPsec Interface, for libreswan
 *
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
 *
 */

#include "ip_info.h"
#include "reqid.h"

#include "ipsec_interface.h"
#include "kernel_ipsec_interface.h"
#include "iface.h"
#include "server_run.h"

#include "log.h"

static reqid_t reqid_base;

static bool netbsd_ipsec_interface_has_cidr(const char *ipsec_if_name,
					      ip_cidr cidr,
					      struct verbose verbose)
{
	cidr_buf cb;
	vlog("%s() always true %s %s", __func__, ipsec_if_name,
	     str_cidr(&cidr, &cb));
	return true;
}

/*
 * ifconfig ipsec0 inet 172.16.100.1/32 172.16.200.1
 * where 172.16.200.1 is the interface-ip / sourceip.
 */

static bool netbsd_ipsec_interface_add_cidr(const char *ipsec_if_name,
					      ip_cidr cidr,
					      struct verbose verbose)
{
	/* same scope as add[] */
	cidr_buf cb;
	address_buf ab;
	ip_address address = cidr_address(cidr);
	const struct ip_info *afi = cidr_info(cidr);
	const char *add[] = {
		"ifconfig",
		ipsec_if_name,
		afi->inet_name, /* "inet" or "inet6" */
		str_cidr(&cidr, &cb),
		str_address(&address, &ab),
		NULL,
	};
	return server_runv(add, verbose);
}

static void netbsd_ipsec_interface_del_cidr(const char *ipsec_if_name,
					      ip_cidr cidr UNUSED,
					      struct verbose verbose)
{
	/* same scope as add[] */
	cidr_buf cb;
	address_buf ab;
	ip_address address = cidr_address(cidr);
	const struct ip_info *afi = cidr_info(cidr);
	const char *delete[] = {
		"ifconfig",
		ipsec_if_name,
		"delete",
		afi->inet_name, /* "inet" or "inet6" */
		str_cidr(&cidr, &cb),
		str_address(&address, &ab),
		NULL,
	};
	server_runv(delete, verbose);
}

static bool netbsd_ipsec_interface_add(const char *ipsec_if_name,
					 const ipsec_interface_id_t ipsec_if_id UNUSED,
					 const struct iface_device *iface UNUSED,
					 struct verbose verbose)
{
	const char *create[] = {
		"ifconfig",
		ipsec_if_name,
		"create",
		NULL,
	};
	return server_runv(create, verbose);
}

static bool netbsd_ipsec_interface_up(const char *ipsec_if_name UNUSED,
					struct verbose verbose UNUSED)
{
	const char *up[] = {
		"ifconfig",
		ipsec_if_name,
		"up",
		NULL,
	};
	return server_runv(up, verbose);
}

static bool netbsd_ipsec_interface_del(const char *ipsec_if_name,
					 struct verbose verbose)
{
	const char *destroy[] = {
		"ifconfig",
		ipsec_if_name,
		"destroy",
		NULL,
	};
	return server_runv(destroy, verbose);
}

static bool netbsd_ipsec_interface_match(struct ipsec_interface_match *match UNUSED,
					   struct verbose verbose UNUSED)
{
	const char *run[] = {
		"ifconfig",
		match->ipsec_if_name,
		NULL,
	};
	bool ok = server_runv(run, verbose);
	if (ok) {
		jam_str(match->found, sizeof(match->found), match->ipsec_if_name);
	} else {
		match->diag = diag("not found");
	}
	return ok;
}

static err_t read_sysctl(const char *ctl, uintmax_t *value, struct verbose verbose)
{
	const char *sysctl[] = {
		"sysctl",
		"-n",
		ctl,
		NULL,
	};
	struct server_run result = server_runv_chunk(sysctl, null_shunk, verbose);
	if (result.status != 0) {
		return "sysctl exited with a non-zero status";
	}
	if (result.output.len == 0) {
		return "sysctl exited with no output";
	}
	shunk_t shunk = HUNK_AS_SHUNK(result.output);
	err_t e = shunk_to_uintmax(shunk, &shunk, 10, value);
	if (e != NULL) {
		return "sysctl output is non-numeric";
	}
	free_chunk_content(&result.output);
	return NULL;
}

static err_t netbsd_ipsec_interface_init(struct verbose verbose)
{
	err_t e;
	/* check net.ipsecif.use_fixed_reqid=1 */
	uintmax_t fixed;
	e = read_sysctl("net.ipsecif.use_fixed_reqid", &fixed, verbose);
	if (e != NULL) {
		return e;
	}
	if (fixed == 0) {
		return "net.ipsecif.use_fixed_reqid should be 1";
	}
	/* extract base */
	uintmax_t base;
	e = read_sysctl("net.ipsecif.reqid_base", &base, verbose);
	if (e != NULL) {
		return e;
	}
	if (base < 8192) {
		return "net.ipsecif.reqid_base is too small";
	}
	if (base >= 16384/*magic*/) {
		return "net.ipsecif.reqid_base is too big";
	}
	reqid_base = base;
	return NULL;
}

static reqid_t netbsd_ipsec_interface_reqid(ipsec_interface_id_t if_id,
					    struct verbose verbose)
{
	vdbg("()");
	return reqid_base + (if_id * 2);
}

const struct kernel_ipsec_interface kernel_ipsec_interface_ifconfig = {
	.name = "ipsec",

	.has_cidr = netbsd_ipsec_interface_has_cidr,
	.add_cidr = netbsd_ipsec_interface_add_cidr,
	.del_cidr = netbsd_ipsec_interface_del_cidr,

	.add = netbsd_ipsec_interface_add,
	.up = netbsd_ipsec_interface_up,
	.del = netbsd_ipsec_interface_del,

	.reqid = netbsd_ipsec_interface_reqid,

	.match = netbsd_ipsec_interface_match,
	.init = netbsd_ipsec_interface_init,

};
