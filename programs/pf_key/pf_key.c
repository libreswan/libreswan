/*
 * @(#) pfkey socket manipulator/observer
 *
 * Copyright (C) 2001  Richard Guy Briggs  <rgb@freeswan.org>
 *                 and Michael Richardson  <mcr@freeswan.org>
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

/*
 * This program opens a pfkey socket or a file
 * and prints all messages that it sees.
 *
 * This can be used to diagnose problems.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>

#include <sys/socket.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdint.h>
#include <libreswan.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "socketwrapper.h"

char *progname;
uint32_t pfkey_seq = 0;
int pfkey_sock;

static void Usage(void)
{
	fprintf(stderr, "%s: Usage: %s [--help]\n"
		"\tby default listens for AH, ESP, IPIP and IPCOMP\n"
		"\t--daemon <file>     fork before printing, stuffing the PID in the file\n"
		"\t--dumpfile <file>   decode file of pfkey messages\n"
		"\t--encodefile <file> encode file of pfkey messages\n"
		"\t--esp               listen for ESP messages\n"
		"\t--ah                listen for AH messages\n"
		"\t--esp               listen for ESP messages\n"
		"\t--ipip              listen for IPIP messages\n"
		"\t--ipcomp            listen for IPCOMP messages\n",
		progname,
		progname);
	exit(1);
}

static void pfkey_register(uint8_t satype)
{
	/* for registering SA types that can be negotiated */
	int error = 0;
	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;

	pfkey_extensions_init(extensions);
	if ((error = pfkey_msg_hdr_build(&extensions[0],
					 SADB_REGISTER,
					 satype,
					 0,
					 ++pfkey_seq,
					 getpid()))) {
		fprintf(stderr,
			"%s: Trouble building message header, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}
	if ((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN))) {
		fprintf(stderr,
			"%s: Trouble building pfkey message, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}
	if (write(pfkey_sock, pfkey_msg,
		  pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN) !=
	    (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) {
		/* cleanup code here */
		fprintf(stderr, "%s: Trouble writing to channel PF_KEY.\n",
			progname);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}
	pfkey_extensions_free(extensions);
	pfkey_msg_free(&pfkey_msg);
}

int dienow;

static void controlC(int foo UNUSED)
{
	fflush(stdout);
	printf("%s: Exiting on signal 15\n", progname);
	fflush(stderr);
	exit(0);
}

int main(int argc, char *argv[])
{
	int opt;
	ssize_t readlen;
	unsigned char pfkey_buf[256];
	struct sadb_msg *msg;
	int fork_after_register;
	char *pidfilename;
	char *infilename;
	char *outfilename;

	static int ah_register;
	static int esp_register;
	static int ipip_register;
	static int ipcomp_register;

	static const struct option long_options[] =
	{
		{ "help",        no_argument, 0, 'h' },
		{ "daemon",      required_argument, 0, 'f' },
		{ "dumpfile",    required_argument, 0, 'd' },
		{ "encodefile",  required_argument, 0, 'e' },
		{ "ah",          no_argument, &ah_register, 1 },
		{ "esp",         no_argument, &esp_register, 1 },
		{ "ipip",        no_argument, &ipip_register, 1 },
		{ "ipcomp",      no_argument, &ipcomp_register, 1 },
	};

	ah_register   = 0;
	esp_register  = 0;
	ipip_register = 0;
	ipcomp_register = 0;
	dienow = 0;
	fork_after_register = 0;

	pidfilename = NULL;
	infilename  = NULL;
	outfilename = NULL;

	progname = argv[0];
	if (strrchr(progname, '/'))
		progname = strrchr(progname, '/') + 1;

	while ((opt = getopt_long(argc, argv, "hd:e:f:",
				  long_options, NULL)) !=  EOF) {
		switch (opt) {
		case 'f':
			pidfilename = optarg;
			fork_after_register = 1;
			break;

		case 'd':
			infilename = optarg;
			break;

		case 'e':
			outfilename = optarg;
			break;

		case 'h':
			Usage();
			break;
		case '0':
			/* it was a long option with a flag */
			break;
		}
	}

	if (infilename  == NULL &&
	    outfilename == NULL) {
		if ((pfkey_sock =
			     safe_socket(PF_KEY, SOCK_RAW, PF_KEY_V2) ) < 0) {
			fprintf(stderr,
				"%s: failed to open PF_KEY family socket: %s\n",
				progname, strerror(errno));
			exit(1);
		}

		if (ah_register == 0 &&
		    esp_register == 0 &&
		    ipip_register == 0 &&
		    ipcomp_register == 0) {
			ah_register = 1;
			esp_register = 1;
			ipip_register = 1;
			ipcomp_register = 1;
		}

		if (ah_register)
			pfkey_register(K_SADB_SATYPE_AH);
		if (esp_register)
			pfkey_register(K_SADB_SATYPE_ESP);
		if (ipip_register)
			pfkey_register(K_SADB_X_SATYPE_IPIP);
		if (ipcomp_register)
			pfkey_register(K_SADB_X_SATYPE_COMP);

		if (fork_after_register) {
			/*
			 * to aid in regression testing, we offer to register
			 * everything first, and then we fork. As part of this
			 * we write the PID of the new process to a file
			 * provided.
			 */
			int pid;
			FILE *pidfile;

			fflush(stdout);
			fflush(stderr);

			pid = fork();
			if (pid != 0) {
				/* in parent! */
				exit(0);
			}

			if ((pidfile = fopen(pidfilename, "w")) == NULL) {
				perror(pidfilename);
			} else {
				fprintf(pidfile, "%d", getpid());
				fclose(pidfile);
			}
		}
	} else if (infilename != NULL) {
		pfkey_sock = open(infilename, O_RDONLY);
		if (pfkey_sock < 0) {
			fprintf(stderr, "%s: failed to open %s: %s\n",
				progname, infilename, strerror(errno));
			exit(1);
		}
	} else if (outfilename != NULL) {
		/* call encoder */
		exit(1);
	}

	signal(SIGINT,  controlC);
	signal(SIGTERM, controlC);

	while ((readlen = read(pfkey_sock, pfkey_buf, sizeof(pfkey_buf))) > 0)
	{
		msg = (struct sadb_msg *)pfkey_buf;

		/* first, see if we got enough for an sadb_msg */
		if ((size_t)readlen < sizeof(struct sadb_msg)) {
			printf("%s: runt packet of size: %d (<%lu)\n",
			       progname, (int)readlen,
			       (unsigned long)sizeof(struct sadb_msg));
			continue;
		}

		/* okay, we got enough for a message, print it out */
		printf("\npfkey v%d msg. type=%d(%s) seq=%d len=%d pid=%d errno=%d satype=%d(%s)\n",
			msg->sadb_msg_version,
			msg->sadb_msg_type,
			pfkey_v2_sadb_type_string(msg->sadb_msg_type),
			msg->sadb_msg_seq,
			msg->sadb_msg_len,
			msg->sadb_msg_pid,
			msg->sadb_msg_errno,
			msg->sadb_msg_satype,
			satype2name(msg->sadb_msg_satype));

		if ((size_t)readlen != msg->sadb_msg_len *
		    IPSEC_PFKEYv2_ALIGN) {
			printf("%s: packet size read from socket=%d doesn't equal sadb_msg_len %d * %u; message not decoded\n",
				progname,
				(int) readlen,
				msg->sadb_msg_len,
				(int) IPSEC_PFKEYv2_ALIGN);
			continue;
		}

		pfkey_print(msg, stdout);
	}
	printf("%s: exited normally\n", progname);
	exit(0);
}

