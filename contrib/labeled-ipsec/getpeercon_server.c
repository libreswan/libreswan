/*
 * Simple INET/INET6/UNIX socket getpeercon() test server
 *
 * compile: gcc -o getpeercon_server -lselinux getpeercon_server.c
 *
 * Copyright Paul Moore <paul@paul-moore.com>
 * 
 * Paul Wouters <pwouters@redhat.com> added simplistic quit option. If
 * the server receives the text "quit" it will quit.
 *
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
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
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
int main(int argc, char *argv[])
{
	int rc;
	int srv_sock, cli_sock;
	int true = 1;
	struct sockaddr_storage cli_sock_saddr;
	struct sockaddr *cli_sock_addr;
	struct sockaddr_in6 *cli_sock_6addr;
	socklen_t cli_sock_addr_len;
	short srv_sock_port;
	char *srv_sock_path = NULL;
	char buffer[RECV_BUF_LEN];
	char cli_sock_addr_str[INET6_ADDRSTRLEN + 1];
	security_context_t ctx;
	char *ctx_str;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <port|path>\n", argv[0]);
		return 1;
	}
	srv_sock_port = atoi(argv[1]);
	if (srv_sock_port == 0)
		srv_sock_path = argv[1];

	rc = getcon(&ctx);
	if (rc < 0)
		ctx_str = strdup("NO_CONTEXT");
	else
		ctx_str = strdup(ctx);
	fprintf(stderr, "-> running as %s\n", ctx_str);
	free(ctx_str);

	fprintf(stderr, "-> creating socket ... ");
	if (srv_sock_path == NULL)
		srv_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	else
		srv_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (srv_sock < 0) {
		fprintf(stderr, "error: %d\n", srv_sock);
		return 1;
	}
	rc = setsockopt(srv_sock,
			SOL_SOCKET, SO_REUSEADDR, &true, sizeof(true));
	if (rc < 0) {
		fprintf(stderr, "error: %d\n", srv_sock);
		return 1;
	}
	fprintf(stderr, "ok\n");

	if (srv_sock_path == NULL) {
		struct sockaddr_in6 srv_sock_addr;

		fprintf(stderr, "-> listening on TCP port %d ... ",
			srv_sock_port);
		memset(&srv_sock_addr, 0, sizeof(srv_sock_addr));
		srv_sock_addr.sin6_family = AF_INET6;
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
		strncpy(srv_sock_addr.sun_path, srv_sock_path, UNIX_PATH_MAX);
		srv_sock_addr.sun_path[UNIX_PATH_MAX - 1] = '\0';
		rc = bind(srv_sock, (struct sockaddr *)&srv_sock_addr,
			  sizeof(srv_sock_addr));
	}
	if (rc < 0) {
		fprintf(stderr, "bind error: %d\n", rc);
		return 1;
	}

	rc = listen(srv_sock, LISTEN_QUEUE);
	if (rc < 0) {
		fprintf(stderr, "listen error: %d\n", rc);
		return 1;
	} else
		fprintf(stderr, "ok\n");

	cli_sock_addr = (struct sockaddr *)&cli_sock_saddr;
	cli_sock_6addr = (struct sockaddr_in6 *)&cli_sock_saddr;

	fprintf(stderr, "-> waiting ... ", srv_sock_port);
	fflush(stdout);
	/* loop forever */
	for (;;) {
		//fflush(stdout);
		memset(&cli_sock_saddr, 0, sizeof(cli_sock_saddr));
		cli_sock_addr_len = sizeof(cli_sock_saddr);
		cli_sock = accept(srv_sock, cli_sock_addr, &cli_sock_addr_len);
		if (cli_sock < 0) {
			fprintf(stderr, "error: %d\n", cli_sock);
			continue;
		}
		rc = getpeercon(cli_sock, &ctx);
		if (rc < 0)
			ctx_str = strdup("NO_CONTEXT");
		else
			ctx_str = strdup(ctx);
		switch (cli_sock_addr->sa_family) {
		case AF_INET6:
			if (IN6_IS_ADDR_V4MAPPED(&cli_sock_6addr->sin6_addr))
				inet_ntop(AF_INET,
				(void *)&cli_sock_6addr->sin6_addr.s6_addr32[3],
					  cli_sock_addr_str, INET_ADDRSTRLEN);
			else
				inet_ntop(cli_sock_addr->sa_family,
					  (void *)&cli_sock_6addr->sin6_addr,
					  cli_sock_addr_str, INET6_ADDRSTRLEN);
			fprintf(stderr, "<- connect(%s,%s)\n",
				cli_sock_addr_str, ctx_str);
			break;
		case AF_UNIX:
			fprintf(stderr, "connect(UNIX,%s)\n", ctx_str);
			break;
		default:
			fprintf(stderr, "connect(%d,%s)\n",
				cli_sock_addr->sa_family, ctx_str);
		}
		free(ctx_str);

		do {
			rc = recv(cli_sock, buffer, RECV_BUF_LEN, 0);
			if (rc < 0)
				fprintf(stderr, "error: %d\n", rc);
			else {
				buffer[rc] = '\0';
				if (rc > 1)
					printf("   %s", buffer);
				if (strncmp(buffer,"quit",4) == 0) 
					exit(0);
			}
		} while (rc > 0);
		close(cli_sock);
		fprintf(stderr, "-> connection closed\n");
	}

	return 0;
}
