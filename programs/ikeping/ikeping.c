/* send out an IKE "ping" packet.
 * Copyright (C) 2002 Michael Richardson
 * Copyright (C) 2002 D. Hugh Redelmeier.
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <poll.h>

#include <libreswan.h>
#include "socketwrapper.h"
#include "libreswan/pfkeyv2.h"

#include "constants.h"
#include <isakmp_hdr.h>

#include "natt_defines.h"

static int exchange_number;
static int major, minor, plen, ilen;
static const char *my_name;

static void help(void)
{
	fprintf(stderr,
		"Usage:\n\n"
		"%s"
		" [--listen]     causes IKEping to open a socket and reply to requests.\n"
		" [--verbose]    causes IKEping to hexdump all packets sent/received.\n"
		" [--ikeport <port-number>]      port to listen on/send from\n"
		" [--ikeaddress <address>]       address to listen on/send from\n"
		" [--inet]       just send/listen on IPv4 socket\n"
		" [--inet6]      just send/listen on IPv6 socket\n"
		" [--version]    just dump version number and exit\n"
		" [--nat-t]      enabled NONESP encapsulation on port\n"
		" [--exchangenum num]    use num instead of 244 for the exchange type.\n"
		" [--major num] use num as IKE major instead of 1.\n"
		" [--minor min] use num as IKE minor instead of 1.\n"
		" [--packetlength len] use len as actual packet length instead of real size.\n"
		" [--ikelength len] use len as ike header declared length instead of 0.\n"
		" [--wait seconds]    time to wait for replies, defaults to 3 seconds.\n"
		" host/port ...\n\n"
		"Libreswan %s\n",
		my_name,
		ipsec_version_code());
}

static void hton_ping(struct isakmp_hdr *ih)
{
#if 0
	u_int32_t *ihp;
	ihp = (u_int32_t *)ih;

	/* put it in network byte order. */
	/* cookies are byte viewed anyway */
	ihp[4] = htonl(ihp[4]);
#endif
	ih->isa_msgid  = htonl(ih->isa_msgid);
	ih->isa_length = htonl(ih->isa_length);
}

static void ntoh_ping(struct isakmp_hdr *ih)
{
#if 0
	u_int32_t *ihp;
	ihp = (u_int32_t *)ih;

	/* put it in network byte order. */
	/* cookies are byte viewed anyway */
	ihp[4] = ntohl(ihp[4]);
#endif
	ih->isa_msgid  = ntohl(ih->isa_msgid);
	ih->isa_length = ntohl(ih->isa_length);
}

/*
 * send an IKE ping echo
 *
 */
static void send_ping(int afamily,
		      int s,
		      ip_address *raddr,
		      int rport)
{
	struct isakmp_hdr ih;
	int i, raddrlen;

	raddrlen = 0;

	for (i = 0; i < COOKIE_SIZE; i++)
		ih.isa_icookie[i] = rand() & 0xff;

	for (i = 0; i < COOKIE_SIZE; i++)
		ih.isa_rcookie[i] = rand() & 0xff;

	ih.isa_np    = NOTHING_WRONG;
	ih.isa_version = (major << ISA_MAJ_SHIFT) | minor;
	ih.isa_xchg  = (exchange_number ?
			exchange_number : ISAKMP_XCHG_ECHOREQUEST_PRIVATE);
	ih.isa_flags = 0;
	ih.isa_msgid = rand();
	ih.isa_length = ilen ? ilen : 0;

	fprintf(stderr, "%s: IKE version octet:%d; exchange type:%d\n",
		my_name, ih.isa_version, ih.isa_xchg);

	switch (afamily) {
	case AF_INET:
		raddr->u.v4.sin_port = htons(rport);
		raddrlen = sizeof(raddr->u.v4);
		break;

	case AF_INET6:
		raddr->u.v6.sin6_port = htons(rport);
		raddrlen = sizeof(raddr->u.v6);
		break;
	}

	hton_ping(&ih);

	if (sendto(s, &ih, sizeof(ih), 0, (struct sockaddr *)raddr,
		   raddrlen) < 0) {
		perror("sendto");
		exit(5);
	}
}

/*
 * send an IKE ping reply
 *
 */
static void reply_packet(int s,
			 ip_address *dst_addr,
			 int dst_len,
			 struct isakmp_hdr *op)
{
	int i, len;

	for (i = 0; i < COOKIE_SIZE; i++) {
		int tmp = op->isa_icookie[i];

		op->isa_icookie[i] = op->isa_rcookie[i];
		op->isa_rcookie[i] = tmp;
	}

	op->isa_np    = NOTHING_WRONG;
	op->isa_version = (major << ISA_MAJ_SHIFT) | minor;
	op->isa_xchg  = ISAKMP_XCHG_ECHOREPLY_PRIVATE;
	op->isa_flags = 0;
	op->isa_msgid = rand();
	op->isa_length = ilen ? ilen : 0;

	hton_ping(op);

	len = sizeof(*op);
	if (plen != 0) {
		if (plen > len) {
			plen = len;
			fprintf(stderr, "%s: Packet length capped at %d - no more data",
				my_name, plen);
		}
	}
	if (sendto(s, op, plen, 0, (struct sockaddr *)dst_addr,
		   dst_len) < 0) {
		perror("sendto");
		exit(5);
	}
}

/*
 * receive and decode packet.
 *
 */
static void receive_ping(int afamily, int s, int reply, int natt)
{
	ip_address sender;
	struct isakmp_hdr ih;
	char rbuf[256];
	char buf[ADDRTOT_BUF];
	int n, rport;
	unsigned int sendlen;
	const char *xchg_name;
	int xchg;
	u_int32_t tmp_ic[2], tmp_rc[2];

	rport = 500;
	xchg  = 0;
	sendlen = sizeof(sender);
	n = recvfrom(s, rbuf, sizeof(rbuf),
		     0, (struct sockaddr *)&sender, (socklen_t *)&sendlen);

	memcpy(&ih, rbuf, sizeof(ih));
	if (natt) {
		/* need to skip 4 bytes! */
		if (rbuf[0] != 0x0 || rbuf[1] != 0x0 ||
		    rbuf[2] != 0x0 || rbuf[3] != 0x0) {
			printf("kernel failed to steal ESP packet (SPI=0x%02x%02x%02x%02x) of length %d\n",
				rbuf[0], rbuf[1], rbuf[2], rbuf[3],
				n);
			return;
		}

		/* otherwise, skip 4 bytes */
		memcpy(&ih, rbuf + 4, sizeof(ih));
	}

	addrtot(&sender, 0, buf, sizeof(buf));
	switch (afamily) {
	case AF_INET:
		rport = sender.u.v4.sin_port;
		break;

	case AF_INET6:
		rport = sender.u.v6.sin6_port;
		break;
	}

	if ((unsigned int)n < sizeof(ih)) {
		fprintf(stderr, "%s: read short packet (%d) from %s/%d\n",
			my_name, n, buf, rport);
		return;
	}

	/* translate from network byte order */
	ntoh_ping(&ih);

	if (ih.isa_xchg == ISAKMP_XCHG_ECHOREQUEST_PRIVATE  ||
	    (exchange_number != 0 && ih.isa_xchg == exchange_number)) {
		xchg_name = "echo-request-swan";
		xchg = ISAKMP_XCHG_ECHOREQUEST_PRIVATE;
	} else if (ih.isa_xchg == ISAKMP_XCHG_ECHOREPLY_PRIVATE ||
		   (exchange_number != 0 && ih.isa_xchg == exchange_number +
		    1)) {
		xchg_name = "echo-reply-swan";
	} else {
		xchg_name = "unknown";
	}

	printf("received %d(%s) packet from %s/%d of len: %d\n",
	       ih.isa_xchg, xchg_name, buf, ntohs(rport), n);

	/* questionable: printing each cookie as if it were two uint32 values in host order */
	memcpy(&tmp_ic, ih.isa_icookie, 2 * sizeof(u_int32_t));
	memcpy(&tmp_rc, ih.isa_rcookie, 2 * sizeof(u_int32_t));
	printf("\trcookie=%08x_%08x icookie=%08x_%08x msgid=%08x\n",
	       tmp_ic[0],
	       tmp_ic[1],
	       tmp_rc[0],
	       tmp_rc[1],
	       ih.isa_msgid);
	printf("\tnp=%03d  version=%d.%d    xchg=%s(%d)\n",
	       ih.isa_np,
	       ih.isa_version >> ISA_MAJ_SHIFT,
	       ih.isa_version & ISA_MIN_MASK,
	       xchg_name,
	       ih.isa_xchg);

	if (reply && xchg == ISAKMP_XCHG_ECHOREQUEST_PRIVATE)
		reply_packet(s, &sender, sendlen, &ih);
}

static const struct option long_opts[] = {
	/* name, has_arg, flag, val */
	{ "help",        no_argument, NULL, 'h' },
	{ "version",     no_argument, NULL, 'V' },
	{ "verbose",     no_argument, NULL, 'v' },
	{ "listen",      no_argument, NULL, 's' },
	{ "ikeport",     required_argument, NULL, 'p' },
	{ "ikeaddress",  required_argument, NULL, 'b' },
	{ "inet",        no_argument, NULL, '4' },
	{ "inet6",       no_argument, NULL, '6' },
	{ "nat-t",       no_argument, NULL, 'T' },
	{ "natt",        no_argument, NULL, 'T' },
	{ "exchangenum", required_argument, NULL, 'E' },
	{ "major", required_argument, NULL, 'M' },
	{ "ikelength", required_argument, NULL, 'L' },
	{ "packetlength", required_argument, NULL, 'l' },
	{ "wait",        required_argument, NULL, 'w' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	char *foo;
	const char *errstr;
	int s;
	int listen_only;
	int lport;
	int afamily;
	int pfamily;
	int c;
	int numSenders, numReceived;
	int natt;
	int waitTime;
	int verbose;
	ip_address laddr, raddr;
	char *afam = "";

	my_name = argv[0];
	afamily = AF_INET;
	pfamily = PF_INET;
	lport = 500;
	waitTime = 3 * 1000;
	verbose = 0;
	natt = 0;
	listen_only = 0;
	bzero(&laddr, sizeof(laddr));

	while ((c = getopt_long(argc, argv, "hVvsp:b:46E:M:m:L:l:w:", long_opts,
				0)) != EOF) {
		switch (c) {
		case 'h':               /* --help */
			help();
			return 0;       /* GNU coding standards say to stop here */

		case 'V':               /* --version */
			fprintf(stderr, "Libreswan %s %s\n",
				my_name, ipsec_version_code());
			return 0;       /* GNU coding standards say to stop here */

		case 'v':               /* --label <string> */
			verbose++;
			break;

		case 'T':
			natt++;
			break;

		case 'E':
			exchange_number = strtol(optarg, &foo, 0);
			if (optarg == foo || exchange_number < 0 ||
			    exchange_number > 255) {
				fprintf(stderr,
					"%s: Invalid exchange number '%s' (should be 0<=x<=255)\n",
					my_name, optarg);
				exit(1);
			}
			break;

		case 'M':
			major = strtol(optarg, &foo, 0);
			if (optarg == foo || major < 0 || major > 15) {
				fprintf(stderr,
					"%s: Invalid major number '%s' (should be 0<=x<=15)\n",
					my_name, optarg);
				exit(1);
			}
			break;

		case 'm':
			minor = strtol(optarg, &foo, 0);
			if (optarg == foo || minor < 0 || minor > 15) {
				fprintf(stderr,
					"%s: Invalid major minor '%s' (should be 0<=x<=15)\n",
					my_name, optarg);
				exit(1);
			}
			break;

		case 'L':
			ilen = strtol(optarg, &foo, 0);
			if (optarg == foo || ilen < 0) {
				fprintf(stderr,
					"%s: Invalid IKE length '%s' (should be positive)\n",
					my_name, optarg);
				exit(1);
			}
			break;

		case 'l':
			plen = strtol(optarg, &foo, 0);
			if (optarg == foo || plen < 0) {
				fprintf(stderr,
					"%s: Invalid Packet length '%s' (should be positive)\n",
					my_name, optarg);
				exit(1);
			}
			break;

		case 's':
			listen_only++;
			break;

		case 'p':
			lport = strtol(optarg, &foo, 0);
			if (optarg == foo || lport < 0 || lport > 65535) {
				fprintf(stderr,
					"%s: Invalid port number '%s' (should be 0<=x<65536)\n",
					my_name, optarg);
				exit(1);
			}
			break;

		case 'w':
			/* convert msec to sec */
			waitTime = strtol(optarg, &foo, 0) * 500;
			if (optarg == foo || waitTime < 0) {
				fprintf(stderr,
					"%s: Invalid waittime number '%s' (should be 0<=x)\n",
					my_name, optarg);
				exit(1);
			}
			break;

		case 'b':
			errstr = ttoaddr(optarg, strlen(optarg),
					 afamily, &laddr);
			if (errstr != NULL) {
				fprintf(stderr,
					"%s: Invalid local address '%s': %s\n",
					my_name, optarg, errstr);
				exit(1);
			}
			break;

		case '4':
			afamily = AF_INET;
			pfamily = PF_INET;
			afam = "IPv4";
			break;

		case '6':
			afamily = AF_INET6;
			pfamily = PF_INET6;
			afam = "IPv6";
			break;

		case '?':
			/* Unknown flag.  Diagnostic printed by getopt_long */
			return 1;

		default:
			fprintf(stderr, "%s internal error: unhandled option 0x%x\n",
				my_name, c);
			exit(1);
		}
	}

	s = safe_socket(pfamily, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0) {
		perror("socket");
		exit(3);
	}

	switch (afamily) {
	case AF_INET:
		laddr.u.v4.sin_family = AF_INET;
		laddr.u.v4.sin_port = htons(lport);
		if (bind(s, (struct sockaddr *)&laddr.u.v4,
			 sizeof(laddr.u.v4)) < 0) {
			perror("v4 bind");
			exit(5);
		}
		break;

	case AF_INET6:
		laddr.u.v6.sin6_family = AF_INET6;
		laddr.u.v6.sin6_port = htons(lport);
		if (bind(s, (struct sockaddr *)&laddr.u.v6,
			 sizeof(laddr.u.v6)) < 0) {
			perror("v6 bind");
			exit(5);
		}
		break;
	}

	if (natt) {
		int r;

		/* only support RFC method */
		int type = ESPINUDP_WITH_NON_ESP;
		r = setsockopt(s, SOL_UDP, UDP_ESPINUDP, &type, sizeof(type));
		if ((r < 0) && (errno == ENOPROTOOPT)) {
			fprintf(stderr,
				"%s NAT-Traversal: ESPINUDP(%d) not supported by kernel for family %s",
				my_name, type, afam);
		}
	}

	numSenders = 0;

	if (!listen_only) {
		while (optind < argc) {
			char *port;
			char *host;
			int dport = 500;
			ipstr_buf b;

			host = argv[optind];

			port = strchr(host, '/');
			if (port) {
				*port = '\0';
				port++;
				dport = strtol(port, &foo, 0);
				if (port == foo || dport < 0 || dport >
				    65535) {
					fprintf(stderr, "%s: Invalid port number '%s' "
						"(should be 0<=x<65536)\n",
						my_name, port);
					exit(1);
				}
			}

			errstr = ttoaddr(host, strlen(host),
					 afamily, &raddr);
			if (errstr != NULL) {
				fprintf(stderr,
					"%s: Invalid remote address '%s': %s\n",
					my_name, host, errstr);
				exit(1);
			}

			printf("Sending packet to %s/%d\n",
				ipstr(&raddr, &b), dport);

			send_ping(afamily, s, &raddr, dport);
			numSenders++;
			optind++;
		}
	}

	numReceived = 0;

	/* really should catch ^C and print stats on exit */
	while (numSenders > 0 || listen_only) {
		struct pollfd ready;
		int n;

		ready.fd = s;
		ready.events = POLLIN;

		n = poll(&ready, 1, waitTime);
		if (n < 0) {
			if (errno != EINTR) {
				perror("poll");
				exit(1);
			}
		}

		if (n == 0 && !listen_only)
			break;

		if (n == 1) {
			numReceived++;
			receive_ping(afamily, s, listen_only, natt);
		}
	}

	printf("%d packets sent, %d packets received. %d%% packet loss\n",
	       numSenders,
	       numReceived,
	       numSenders > 0 ? 100 - numReceived * 100 / numSenders : 0);
	exit(numSenders - numReceived);
}
