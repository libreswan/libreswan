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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>

#include "ip_info.h"

#include "ipsec_interface.h"
#include "kernel_ipsec_interface.h"
#include "iface.h"

#include "log.h"

static bool run(const char *cmd[], struct verbose verbose)
{
	char command[LOG_WIDTH];
	struct jambuf buf[] = { ARRAY_AS_JAMBUF(command), };
	const char *sep = "";
	for (const char **c = cmd; *c != NULL; c++) {
		jam_string(buf, sep); sep = " ";
		jam_string(buf, *c);
	}
	llog(RC_LOG, verbose.logger, "command: %s", command);
	FILE *out = popen(command, "re");
	if (out == NULL) {
		llog_error(verbose.logger, errno, "command '%s' failed: ", command);
		return false;
	}
	while (true) {
		char buf[100];
		int n = fread(buf, sizeof(buf), 1, out);
		if (n > 0) {
			llog(RC_LOG, verbose.logger, "output: %*s", n, buf);
			continue;
		}
		if (feof(out) || ferror(out)) {
			const char *why = (feof(out) ? "eof" :
					   ferror(out) ? "error" :
					   "???");
			int wstatus = pclose(out);
			llog(RC_LOG, verbose.logger,
			     "%s: %d; exited %s(%d); signaled: %s(%d); stopped: %s(%d); core: %s",
			     why, wstatus,
			     bool_str(WIFEXITED(wstatus)), WEXITSTATUS(wstatus),
			     bool_str(WIFSIGNALED(wstatus)), WTERMSIG(wstatus),
			     bool_str(WIFSTOPPED(wstatus)), WSTOPSIG(wstatus),
			     bool_str(WCOREDUMP(wstatus)));
			break;
		}
	}
	return true;
}

static bool ifconfig_ipsec_interface_has_cidr(const char *ipsec_if_name UNUSED,
					      ip_cidr cidr UNUSED,
					      struct verbose verbose UNUSED)
{
	return false;
}

/*
 * ifconfig ipsec0 inet 172.16.100.1/32 172.16.200.1
 * where 172.16.200.1 is the interface-ip / sourceip.
 */

static bool ifconfig_ipsec_interface_add_cidr(const char *ipsec_if_name,
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
	return run(add, verbose);
}

static void ifconfig_ipsec_interface_del_cidr(const char *ipsec_if_name,
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
	run(delete, verbose);
}

static bool ifconfig_ipsec_interface_add(const char *ipsec_if_name,
					 const ipsec_interface_id_t ipsec_if_id UNUSED,
					 const struct iface_device *iface,
					 ip_address remote_address,
					 struct verbose verbose)
{
	const char *create[] = {
		"ifconfig",
		ipsec_if_name,
		"create",
		NULL,
	};
	if (!run(create, verbose)) {
		return false;
	}
	address_buf rab, lab; /* must be same scope as tunnel[] */
	const char *tunnel[] = {
		"ifconfig",
		ipsec_if_name,
		"tunnel",
		str_address(&iface->local_address, &lab),
		str_address(&remote_address, &rab),
		NULL,
	};
	return run(tunnel, verbose);
}

static bool ifconfig_ipsec_interface_up(const char *ipsec_if_name UNUSED,
					struct verbose verbose UNUSED)
{
	const char *up[] = {
		"ifconfig",
		ipsec_if_name,
		"up",
		NULL,
	};
	return run(up, verbose);
}

static bool ifconfig_ipsec_interface_del(const char *ipsec_if_name,
					 struct verbose verbose)
{
	const char *destroy[] = {
		"ifconfig",
		ipsec_if_name,
		"destroy",
		NULL,
	};
	return run(destroy, verbose);
}

static bool ifconfig_ipsec_interface_match(struct ipsec_interface_match *match UNUSED,
					   struct verbose verbose UNUSED)
{
	return false;
}

static void ifconfig_ipsec_interface_check_stale(struct verbose verbose UNUSED)
{
}

static err_t ifconfig_ipsec_interface_supported(struct verbose verbose UNUSED)
{
	return NULL;
}

static void ifconfig_ipsec_interface_shutdown(struct verbose verbose UNUSED)
{
}

const struct kernel_ipsec_interface kernel_ipsec_interface_ifconfig = {
#ifdef __OpenBSD__
	.name = "sec",
#else
	.name = "ipsec",
#endif

	.has_cidr = ifconfig_ipsec_interface_has_cidr,
	.add_cidr = ifconfig_ipsec_interface_add_cidr,
	.del_cidr = ifconfig_ipsec_interface_del_cidr,

	.add = ifconfig_ipsec_interface_add,
	.up = ifconfig_ipsec_interface_up,
	.del = ifconfig_ipsec_interface_del,

	.match = ifconfig_ipsec_interface_match,
	.check_stale = ifconfig_ipsec_interface_check_stale,
	.supported = ifconfig_ipsec_interface_supported,
	.shutdown = ifconfig_ipsec_interface_shutdown,

};
