/*
 * conversion from protocol/port string to protocol and port
 *
 * Copyright (C) 2002 Mario Strasser <mast@gmx.net>,
 *                    Zuercher Hochschule Winterthur,
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */
#include "internal.h"
#include "libreswan.h"

/*
 * ttoprotoport - converts from protocol/port string to protocol and port
 */
err_t ttoprotoport(src, src_len, proto, port, has_port_wildcard)
char *src;	/* input string */
size_t src_len;	/* length of input string, use strlen() if 0 */
u_int8_t *proto;	/* extracted protocol number */
u_int16_t *port;	/* extracted port number if it exists */
int *has_port_wildcard;	/* set if port is %any */
{
	char *end, *service_name;
	char proto_name[16];
	int proto_len;
	long int l;
	struct protoent *protocol;
	struct servent *service;
	int wildcard;

	/* get the length of the string */
	if (!src_len)
		src_len = strlen(src);

	/* locate delimiter '/' between protocol and port */
	end = strchr(src, '/');
	if (end != NULL) {
		proto_len = end - src;
		service_name = end + 1;
	} else {
		proto_len = src_len;
		service_name = src + src_len;
	}

	/* copy protocol name */
	memset(proto_name, '\0', sizeof(proto_name));
	memcpy(proto_name, src, proto_len);

	/* extract protocol by trying to resolve it by name */
	protocol = getprotobyname(proto_name);
	if (protocol != NULL) {
		*proto = protocol->p_proto;
	} else {	/* failed, now try it by number */
		l = strtol(proto_name, &end, 0);

		if (*proto_name && *end)
			return "<protocol> is neither a number nor a valid name";

		if (l < 0 || l > 0xff)
			return "<protocol> must be between 0 and 255";

		*proto = (u_int8_t)l;
	}

	/* is there a port wildcard? */
	wildcard = (strcmp(service_name, "%any") == 0);

	if (has_port_wildcard)
		*has_port_wildcard = wildcard;

	if (wildcard) {
		*port = 0;
		return NULL;
	}

	/* extract port by trying to resolve it by name */
	service = getservbyname(service_name, NULL);
	if (service != NULL) {
		*port = ntohs(service->s_port);
	} else {	/* failed, now try it by number */
		l = strtol(service_name, &end, 0);

		if (*service_name && *end)
			/*
			 * set port to 0, this is needed for protocols without
			 * port in the proposal, such as with GRE (protoport=47)
			 */
			l = 0;

		else if (l < 0 || l > 0xffff)
			return "<port> must be between 0 and 65535";

		*port = (u_int16_t)l;
	}
	return NULL;
}

#ifdef TTOPROTOPORT_MAIN

#include <stdio.h>

struct artab;
static void regress(char *pgm);

/*
 * main - convert first argument to hex, or run regression
 */
int main(int argc, char *argv[])
{
	char *pgm = argv[0];
	const char *oops;
	u_int8_t proto;
	u_int16_t port;
	int has_port_wildcard;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s {0x<hex>|0s<base64>|-r}\n", pgm);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress(pgm);	/* should not return */
		fprintf(stderr, "%s: regress() returned?!?\n", pgm);
		exit(1);
	}

	oops = ttoprotoport(argv[1], strlen(argv[1]),
			&proto, &port, &has_port_wildcard);

	if (oops != NULL) {
		fprintf(stderr, "%s: ttodata error `%s' in `%s'\n", pgm,
			oops, argv[1]);
		exit(1);
	}

	printf("%s -> %d/%d with %d\n",
		argv[1], proto, port, has_port_wildcard);

	exit(0);
}

struct artab {
	char *ascii;	/* NULL for end */
	int proto, port, wild;
} atodatatab[] = {
	/* { "", 0, 0, -1 }, */
	{ "tcp/%any", 6, 0, 1,  },
	{ NULL, 0, 0, 0, },
};

static void	/* should not return at all, in fact */
regress(pgm)
char *pgm;
{
	struct artab *r;
	int status = 0;

	for (r = atodatatab; r->ascii != NULL; r++) {
		u_int8_t proto;
		u_int16_t port;
		int has_port_wildcard;
		err_t err = ttoprotoport(r->ascii, strlen(r->ascii),
				&proto, &port, &has_port_wildcard);

		if (r->wild == -1) {
			if (err != NULL) {
				/* okay, error expected */
				continue;
			} else {
				printf("%s expected error, got none.\n",
					r->ascii);
				status = 1;
				continue;
			}
		}

		if (err != NULL) {
			printf("%s got error: %s\n", r->ascii, err);
			status = 1;
			continue;
		}

		if (proto != r->proto) {
			printf("%s expected proto %d, got %d\n", r->ascii,
				proto, r->proto);
			status = 1;
			continue;
		}

		if (port != r->port) {
			printf("%s expected port %d, got %d\n", r->ascii, port,
				r->port);
			status = 1;
			continue;
		}

		if (has_port_wildcard != r->wild) {
			printf("%s expected wild %d, got %d\n", r->ascii,
				has_port_wildcard, r->wild);
			status = 1;
			continue;
		}

		fflush(stdout);
	}
	exit(status);
}

#endif	/* TTODATA_MAIN */
