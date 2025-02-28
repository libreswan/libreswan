/* routecheck, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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
 */

#include <stdlib.h>
#include <getopt.h>

#include "lswtool.h"
#include "lswlog.h"
#include "addr_lookup.h"
#include "ip_address.h"
#include "ip_info.h"
#include "optarg.h"

enum opt {
	OPT_HELP = 'h',
	OPT_VERBOSE = 'v',
	OPT_DEBUG = 'd',
	OPT_IPv4 = '4',
	OPT_IPv6 = '6',
};

static struct optarg_family family;

static int show_source = false;
static int show_gateway = false;
static int show_destination = false;

const struct option optarg_options[] = {
	{ "source\0", no_argument, &show_source, true, },
	{ "gateway\0", no_argument, &show_gateway, true, },
	{ "destination\0", no_argument, &show_destination, true, },
	{ "debug\0", no_argument, NULL, OPT_DEBUG, },
	{ "ipv4\0", no_argument, NULL, OPT_IPv4, },
	{ "ipv6\0", no_argument, NULL, OPT_IPv6, },
	{ "verbose\0", no_argument, NULL, OPT_VERBOSE, },
	{ "help\0", no_argument, NULL, OPT_HELP, },
	{0},
};

static void usage(void)
{
	/* use stdout */
	optarg_usage(progname, "<destination>");
	fprintf(stdout, "\n");
	fprintf(stdout, "Prints:");
	fprintf(stdout, "\n");
	fprintf(stdout, "  <source-address> <gateway-address> <destination-address>");
	fprintf(stdout, "\n");
	fprintf(stdout, "for the given <destination>");
	fprintf(stdout, "\n");
	exit(1);
}

int main(int argc, char **argv)
{
	struct logger *logger = tool_logger(argc, argv);

	if (argc == 1) {
		usage();
	}

	while (true) {
		int c = optarg_getopt(logger, argc, argv, "vd46");
		if (c < 0) {
			break;
		}
		switch ((enum opt)c) {
		case OPT_DEBUG:
			optarg_debug(true);
			continue;
		case OPT_IPv4:
			optarg_family(&family, &ipv4_info);
			continue;
		case OPT_IPv6:
			optarg_family(&family, &ipv4_info);
			continue;
		case OPT_VERBOSE:
			optarg_verbose(logger, LEMPTY);
			continue;
		case OPT_HELP:
			usage();
			continue;
		}
		bad_case(c);
	}

	if (optind == argc) {
		llog(ERROR_STREAM, logger, "missing destination");
		exit(1);
	}

	if (optind + 1 < argc) {
		llog(ERROR_STREAM, logger, "extra parameter %s", argv[optind + 1]);
		exit(1);
	}

	if (!show_source && !show_gateway && !show_destination) {
		show_source = show_gateway = show_destination = true;
	}

	ip_address dst;
	err_t e = ttoaddress_dns(shunk1(argv[optind]), family.type, &dst);
	if (e != NULL) {
		llog(WHACK_STREAM, logger, "%s: %s", argv[1], e);
		exit(1);
	}

	struct ip_route route;
	switch (get_route(dst, &route, logger)) {
	case ROUTE_SUCCESS:
	{
		LLOG_JAMBUF(WHACK_STREAM|NO_PREFIX, logger, buf) {
			const char *sep = "";
			if (show_source) {
				jam_string(buf, sep); sep = " ";
				jam_address(buf, &route.source);
			}
			if (show_gateway) {
				jam_string(buf, sep); sep = " ";
				jam_address(buf, &route.gateway);
			}
			if (show_destination) {
				jam_string(buf, sep); sep = " ";
				jam_address(buf, &dst);
			}
		}
		exit(0);
	}
	case ROUTE_GATEWAY_FAILED:
	{
		address_buf ab;
		llog(ERROR_STREAM, logger, "%s: gateway failed",
		     str_address(&dst, &ab));
		exit(1);
	}
	case ROUTE_SOURCE_FAILED:
	{
		address_buf ab;
		llog(ERROR_STREAM, logger, "%s: source failed",
		     str_address(&dst, &ab));
		exit(1);
	}
	case ROUTE_FATAL:
	{
		address_buf ab;
		llog(ERROR_STREAM, logger, "%s: fatal",
		     str_address(&dst, &ab));
		exit(1);
	}
	}

	exit(1);
}
