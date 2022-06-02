/*
 * getpeercon_server: simple INET/INET6/UNIX socket getpeercon(3) test server
 *
 * compile: gcc -Wall -o getpeercon_server -lselinux getpeercon_server.c
 *
 * Copyright Paul Moore <paul@paul-moore.com>
 *
 * Paul Wouters <pwouters@redhat.com> added simplistic quit option. If
 * the server receives the text "quit" it will quit.
 */

/*
 * (c) Copyright Hewlett-Packard Development Company, L.P., 2008, 2010
 * (c) Copyright Red Hat, 2012
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <selinux/selinux.h>
#include <selinux/context.h>

#define UNIX_PATH_MAX 108
#define LISTEN_QUEUE 1
#define RECV_BUF_LEN 1024

/**
 * main
 */
static void usage(char *argv[])
{
	fprintf(stderr, "usage: %s [-d] <port|path>\n", argv[0]);
	exit(1);
}

int main(int argc, char *argv[])
{
	int rc;
	int srv_sock;
	const int true_const = 1;
	char *srv_sock_path = NULL;

	bool detach = false;
	int opt;
	while ((opt = getopt(argc, argv, "d")) != -1) {
		switch (opt) {
		case 'd':
			detach = true;
			break;
		default: /* '?' */
			usage(argv);
		}
	}

	if (optind != argc - 1) {
		usage(argv);
	}

	short srv_sock_port;
	srv_sock_port = atoi(argv[optind]);
	if (srv_sock_port == 0)
		srv_sock_path = argv[optind];

	{
		char *ctx;
		int rc = getcon(&ctx);

		fprintf(stderr, "-> running as %s\n",
			rc < 0 ? "NO_CONTEXT" : ctx);
		if (rc >= 0)
			freecon(ctx);
	}

	fprintf(stderr, "-> creating socket ... ");
	if (srv_sock_path == NULL)
		srv_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	else
		srv_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (srv_sock < 0) {
		fprintf(stderr, "socket(2) error: %s\n", strerror(errno));
		return 1;
	}
	rc = setsockopt(srv_sock,
			SOL_SOCKET, SO_REUSEADDR, &true_const, sizeof(true_const));
	if (rc < 0) {
		fprintf(stderr, "setsockopt(2) error: %s\n", strerror(errno));
		return 1;
	}
	fprintf(stderr, "ok\n");

	if (srv_sock_path == NULL) {
		struct sockaddr_in6 srv_sock_addr;

		fprintf(stderr, "-> listening on TCP port %d ... ",
			srv_sock_port);
		memset(&srv_sock_addr, 0, sizeof(srv_sock_addr));
		srv_sock_addr.sin6_family = AF_INET6;
#ifdef USE_SOCKADDR_LEN
		srv_sock_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
		memcpy(&srv_sock_addr.sin6_addr, &in6addr_any,
			sizeof(in6addr_any));
		srv_sock_addr.sin6_port = htons(srv_sock_port);
		rc = bind(srv_sock, (struct sockaddr *)&srv_sock_addr,
			  sizeof(srv_sock_addr));
	} else {
		struct sockaddr_un srv_sock_addr;

		fprintf(stderr, "-> listening on UNIX socket %s ... ",
			srv_sock_path);
		srv_sock_addr.sun_family = AF_UNIX;
#ifdef USE_SOCKADDR_LEN
#error how do we set srv_sock_addr.sun_len?
#endif
		/* make .sun_path both NUL-padded and NUL-terminated */
		strncpy(srv_sock_addr.sun_path, srv_sock_path, UNIX_PATH_MAX-1);
		srv_sock_addr.sun_path[UNIX_PATH_MAX - 1] = '\0';
		rc = bind(srv_sock, (struct sockaddr *)&srv_sock_addr,
			  sizeof(srv_sock_addr));
	}
	if (rc < 0) {
		fprintf(stderr, "bind(2) error: %s\n", strerror(errno));
		return 1;
	}

	rc = listen(srv_sock, LISTEN_QUEUE);
	if (rc < 0) {
		fprintf(stderr, "listen(2) error: %s\n", strerror(errno));
		return 1;
	} else
		fprintf(stderr, "ok\n");

	fprintf(stderr, "-> waiting ... ");
	fflush(stdout);

	if (detach) {
		fprintf(stderr, "\n");
		fflush(stdout);
		switch (fork()) {
		case 0: break; /* child */
		default: exit(0);
		}
	}

	/* loop forever */
	for (;;) {
		int cli_sock;
		struct sockaddr_storage cli_sock_saddr;
		struct sockaddr *const cli_sock_addr = (struct sockaddr *)&cli_sock_saddr;
		struct sockaddr_in6 *const cli_sock_6addr = (struct sockaddr_in6 *)&cli_sock_saddr;
		socklen_t cli_sock_addr_len;
		char cli_sock_addr_str[INET6_ADDRSTRLEN + 1];
		char *ctx;
		char *ctx_str;

		//fflush(stdout);
		memset(&cli_sock_saddr, 0, sizeof(cli_sock_saddr));
		cli_sock_addr_len = sizeof(cli_sock_saddr);
		cli_sock = accept(srv_sock, cli_sock_addr, &cli_sock_addr_len);
		if (cli_sock < 0) {
			fprintf(stderr, "accept(2) error: %s\n", strerror(errno));
			continue;
		}
		rc = getpeercon(cli_sock, &ctx);
		ctx_str = rc < 0 ? "NO_CONTEXT" : ctx;

		switch (cli_sock_saddr.ss_family) {
		case AF_INET6:
			if (IN6_IS_ADDR_V4MAPPED(&cli_sock_6addr->sin6_addr)) {
				inet_ntop(AF_INET,
					&cli_sock_6addr->sin6_addr.s6_addr32[3],
					cli_sock_addr_str, sizeof(cli_sock_addr_str));
			} else {
				inet_ntop(cli_sock_6addr->sin6_family,
					&cli_sock_6addr->sin6_addr,
					cli_sock_addr_str, sizeof(cli_sock_addr_str));
			}
			fprintf(stderr, "<- connect(%s,%s)\n",
				cli_sock_addr_str, ctx_str);
			break;

		case AF_UNIX:
			fprintf(stderr, "connect(UNIX,%s)\n", ctx_str);
			break;

		default:
			fprintf(stderr, "connect(%d,%s)\n",
				cli_sock_saddr.ss_family, ctx_str);
		}

		if (rc >= 0)
			freecon(ctx);

		for (;;) {
			char buffer[RECV_BUF_LEN + 1];

			rc = recv(cli_sock, buffer, sizeof(buffer) - 1, 0);
			if (rc < 0) {
				fprintf(stderr, "recv(2) error: %s\n", strerror(errno));
				break;
			} else if (rc == 0) {
				break;
			} else {
				buffer[rc] = '\0';
				/* ??? should this format include a \n? */
				printf("   %s", buffer);
				if (strcmp(buffer, "quit") == 0)
					break;
			}
		}
		close(cli_sock);
		fprintf(stderr, "-> connection closed\n");
	}

	return 0;
}
