/* test IP code, for libreswan
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2018 Andrew Cagney
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#include <stdio.h>

#include "constants.h"
#include "ip_address.h"
#include "stdlib.h"
#include "ipcheck.h"
#include "lswtool.h"
#include "lswalloc.h"		/* for leak_detective; */

unsigned fails;
enum have_dns have_dns = DNS_NO;

int main(int argc, char *argv[])
{
	leak_detective = true;
	log_ip = false; /* force sensitive */
	struct logger *logger = tool_logger(argc, argv);

	if (argc != 2) {
		fprintf(stderr, "usage: %s --dns={no,hosts-file,yes}\n", argv[0]);
		return 1;
	}

	/* only one option for now */
	const char *dns = argv[1];
	if (!eat(dns, "--dns")) {
		fprintf(stderr, "%s: unknown option '%s'\n",
			argv[0], argv[1]);
		return 1;
	}

	if (streq(dns, "=no")) {
		have_dns = DNS_NO;
	} else if (streq(dns, "=hosts-file") || streq(dns, "")) {
		have_dns = HAVE_HOSTS_FILE;
	} else if (streq(dns, "=yes")) {
		have_dns = DNS_YES;
	} else {
		fprintf(stderr, "%s: unknown --dns param '%s'\n",
			argv[0], dns);
		return 1;
	}

	ip_address_check();
	ip_endpoint_check();
	ip_range_check(logger);
	ip_subnet_check(logger);
	ip_said_check();
	ip_info_check();
	ip_protoport_check();
	ip_selector_check(logger);
	ip_sockaddr_check(logger);
	ip_port_check();
	ip_port_range_check();
	ip_cidr_check();
	ip_protocol_check();
	ip_packet_check();

	if (report_leaks(logger)) {
		fails++;
	}

	if (fails > 0) {
		fprintf(stderr, "TOTAL FAILURES: %d\n", fails);
		return 1;
	} else {
		return 0;
	}
}
