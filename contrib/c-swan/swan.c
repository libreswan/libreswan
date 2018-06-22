/*
 * Is connection encrypted? -utility.
 *
 * Copyright (C) 2018  Kim B. Heino <b@bbbs.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <getopt.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include "libreswan.h"
#include "swan.h"

#define COMMAND_BUFFER	65536	/* Max length of "ip xfrm" output */

/* Dummy logger to require less lib dependencies. */
int libreswan_log(const char *fmt, ...)
{
	return 0;
}

/* Run external command and return its output, NUL terminated. */
static char *run_command(char **params)
{
	int link[2];
	pid_t pid;
	char *buffer;

	if (pipe(link) == -1)
		return NULL;
	if ((pid = fork()) == -1)
		return NULL;

	if (pid == 0) {
		dup2(link[1], STDOUT_FILENO);
		close(link[0]);
		close(link[1]);
		execv(params[0], params);
		exit(0);
	}

	buffer = malloc(COMMAND_BUFFER);
	if (buffer == NULL)
		return NULL;

	close(link[1]);
	int nbytes = read(link[0], buffer, COMMAND_BUFFER - 1);
	wait(NULL);
	close(link[0]);
	if (nbytes < 0)
		nbytes = 0;
	buffer[nbytes] = 0;
	return buffer;
}

/* Split command output to NUL terminated words. */
static char *split_words(char *command_output)
{
	char *buffer, *from, *to;

	/* Worst case is "\n\n...", resulting 2 * input size */
	buffer = malloc(COMMAND_BUFFER * 2 + 2);
	if (buffer == NULL)
		return NULL;

	/* Split to words */
	from = command_output;
	to = buffer;
	if (from != NULL)
		while (*from != 0) {
			/* Skip " " and "\" */
			while (*from == ' ' || *from == '\t' || *from == '\\')
				from++;

			if (*from == '\n') {
				/* Copy "\n" as word */
				*(to++) = *(from++);

			} else {
				/* Copy word */
				while (*from > ' ' && *from != '\\')
					*(to++) = *(from++);
			}

			*(to++) = 0;
		}

	/* Add end marker */
	*(to++) = 0;
	*(to++) = 0;

	/* Free command output buffer */
	if (command_output != NULL)
		free(command_output);
	return buffer;
}

/* Get my source IP address */
static int get_source_ip(char *destination, char *source)
{
	char *output, *p;
	char *params[8];

	params[0] = "/sbin/ip";
	params[1] = "-oneline";
	params[2] = "route";
	params[3] = "get";
	params[4] = destination;
	params[5] = NULL;
	output = split_words(run_command(params));

	for (p = output; *p != 0; p += strlen(p) + 1) {
		if (strcmp(p, "src") == 0) {
			strncpy(source, p + strlen(p) + 1, IPLEN);
			source[IPLEN] = 0;
			break;
		}
	}

	free(output);
	if (*source == 0) {
		printf("Failed to detect source IP\n");
		return -1;
	}
	return 0;
}

/* Is address inside subnet+mask? */
static bool addr_in_mask(char *address_str, char *mask_str)
{
	ip_address address;
	ip_subnet mask;
	err_t err;

	err = ttoaddr(address_str, 0, AF_UNSPEC, &address);
	if (err)
		return false;
	err = ttosubnet(mask_str, 0, AF_UNSPEC, &mask);
	if (err)
		return false;
	return addrinsubnet(&address, &mask);
}

/* Get "ip xfrm" output */
static char *get_policy_list(void)
{
	char *output;
	char *params[8];

	params[0] = "/sbin/ip";
	params[1] = "-oneline";
	params[2] = "xfrm";
	params[3] = "policy";
	params[4] = "list";
	params[5] = NULL;

	output = split_words(run_command(params));
	return output;
}

/* Parse xfrm policy list */
static bool parse_policy_list(char *source, char *destination, char *xfrm, int debug)
{
	struct {
		char src[128];
		char dst[128];
		char dir[128];
		char priority[128];
		char proto[128];
		char reqid[128];
	} parsed;
	bool encrypted = false;
	int priority = 65536;
	char *keyword, *p;

	memset(&parsed, 0, sizeof(parsed));
	keyword = NULL;
	for (p = xfrm; *p != 0; p += strlen(p) + 1) {
		if (*p == '\n') {
			/* End of line - check it */
			int prio = atoi(parsed.priority);

			if (strcmp(parsed.dir, "out") == 0 &&
				strcmp(parsed.proto, "esp") == 0 &&
				prio > 0 &&
				prio < priority &&
				*parsed.src != 0 &&
				*parsed.dst != 0 &&
				addr_in_mask(source, parsed.src) &&
				addr_in_mask(destination, parsed.dst)) {
				/* Got match, update encrypted variable. */
				if (debug)
					printf("src %s dst %s dir %s priority %s proto %s reqid %s\n",
						parsed.src,
						parsed.dst,
						parsed.dir,
						parsed.priority,
						parsed.proto,
						parsed.reqid);
				priority = prio;
				encrypted = *parsed.reqid != 0 &&
					strcmp(parsed.reqid, "0") != 0;
			}

			memset(&parsed, 0, sizeof(parsed));
			keyword = NULL;

		} else if (keyword != NULL) {
			if (*keyword == 0) {
				strncpy(keyword, p, IPLEN);
				keyword[IPLEN] = 0;
			}
			keyword = NULL;

		} else if (strcmp(p, "src") == 0)
			keyword = parsed.src;
		else if (strcmp(p, "dst") == 0)
			keyword = parsed.dst;
		else if (strcmp(p, "dir") == 0)
			keyword = parsed.dir;
		else if (strcmp(p, "priority") == 0)
			keyword = parsed.priority;
		else if (strcmp(p, "proto") == 0)
			keyword = parsed.proto;
		else if (strcmp(p, "reqid") == 0)
			keyword = parsed.reqid;
	}
	return encrypted;
}

/* Connect to dest:port, ignore errors */
static void connect_to(char *destination, int port, int timeout)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	char port_str[16];
	int sock;
	fd_set fdset;
	struct timeval tv;

	/* Parse destination:port */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	sprintf(port_str, "%d", port);
	if (getaddrinfo(destination, port_str, &hints, &result) != 0)
		return;

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		/* Open non-blocking connection */
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1)
			continue;
		fcntl(sock, F_SETFL, O_NONBLOCK);
		connect(sock, rp->ai_addr, rp->ai_addrlen);

		/* Wait until timeout or connected */
		FD_ZERO(&fdset);
		FD_SET(sock, &fdset);
		tv.tv_sec = timeout;
		tv.tv_usec = 0;
		select(sock + 1, NULL, &fdset, NULL, &tv);
		close(sock);
	}
	freeaddrinfo(result);
}

/* Is connection encrypted? */
bool is_encrypted(char *destination, int port, char *source, int timeout,
		int debug)
{
	if (*source == 0 && get_source_ip(destination, source) == -1)
		return false;
	if (debug)
		printf("Checking %s to %s port %d\n", source, destination,
			port);
	if (port > 0)
		connect_to(destination, port, timeout);

	char *xfrm = get_policy_list();
	bool ret = parse_policy_list(source, destination, xfrm, debug);
	free(xfrm);
	return ret;
}
