/*
 * @(#) pfkey socket manipulator/observer
 *
 * Copyright (C) 2001  Richard Guy Briggs  <rgb@freeswan.org>
 *                 and Michael Richardson  <mcr@freeswan.org>
 * Copyright (C) 2003 Michael Richardson <mcr@freeswan.org>
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include <inttypes.h>		/* for PRI* */
#include <sys/socket.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdint.h>

#include "libreswan.h"
#include "libreswan/pfkeyv2.h"
#include "libreswan/pfkey.h"

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

static void pfkey_print(struct sadb_msg *msg, FILE *out)
{
	unsigned len;
	struct sadb_ext *se;

	fprintf(out,
		"version=%u type=%u errno=%u satype=%u len=%u seq=%u pid=%u ",
		msg->sadb_msg_version,
		msg->sadb_msg_type,
		msg->sadb_msg_errno,
		msg->sadb_msg_satype,
		msg->sadb_msg_len,
		msg->sadb_msg_seq,
		msg->sadb_msg_pid);

	len = IPSEC_PFKEYv2_LEN(msg->sadb_msg_len);
	len -= sizeof(struct sadb_msg);

	se = (struct sadb_ext *) &msg[1];

	while (len > sizeof(struct sadb_ext)) {
		/* in units of IPSEC_PFKEYv2_ALIGN bytes */
		uint16_t ext_len = se->sadb_ext_len;
		/* in units of bytes */
		unsigned elen = IPSEC_PFKEYv2_LEN(ext_len);
		uint16_t ext_type = se->sadb_ext_type;
		const char *too_small_for = NULL;

		fprintf(out, "{ext=%u len=%u ", ext_type, ext_len);

		/* make sure that there is enough left */
		if (elen > len) {
			fprintf(out, "short-packet(%u<%u) ", len, elen);

			/*
			 * truncate ext_len it to match len
			 *
			 * partial words are ignored
			 */
			ext_len = IPSEC_PFKEYv2_WORDS(len);
			elen = IPSEC_PFKEYv2_LEN(ext_len);
			ext_type = SADB_X_EXT_DEBUG;	/* force plain dump */
		}

		if (elen < sizeof(struct sadb_ext)) {
			fprintf(out, "ext_len (%u) too small for sadb_ext header ",
				ext_len);
			break;
		}

		/* okay, decode what we know */
		switch (ext_type) {
		case SADB_EXT_SA:
			if (elen < sizeof(struct k_sadb_sa)) {
				too_small_for = "struct k_sadb_sa";
			} else {
				struct k_sadb_sa *sa = (struct k_sadb_sa *)se;
				fprintf(out,
					"spi=%08x replay=%u state=%u auth=%u encrypt=%u flags=%08x ref=%08x}",
					sa->sadb_sa_spi,
					sa->sadb_sa_replay,
					sa->sadb_sa_state,
					sa->sadb_sa_auth,
					sa->sadb_sa_encrypt,
					sa->sadb_sa_flags,
					sa->sadb_x_sa_ref);
			}
			break;

		case SADB_X_EXT_ADDRESS_SRC_FLOW:
		case SADB_X_EXT_ADDRESS_DST_FLOW:
		case SADB_X_EXT_ADDRESS_SRC_MASK:
		case SADB_X_EXT_ADDRESS_DST_MASK:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_SRC:
			if (elen < sizeof(struct sadb_address)) {
				too_small_for = "struct sadb_address";
			} else {
				struct sadb_address *addr =
					(struct sadb_address *) se;
				int alen =
					IPSEC_PFKEYv2_LEN(
						addr->sadb_address_len) -
					sizeof(struct sadb_address);
				unsigned char *bytes =
					(unsigned char *)&addr[1];

				fprintf(out, "proto=%u prefixlen=%u addr=0x",
					addr->sadb_address_proto,
					addr->sadb_address_prefixlen);

				while (alen > 0) {
					fprintf(out, "%02x", *bytes);
					bytes++;
					alen--;
				}
				fprintf(out, " } ");
			}
			break;

		case SADB_X_EXT_PROTOCOL:
			if (elen < sizeof(struct sadb_protocol)) {
				too_small_for = "struct sadb_protocol";
			} else {
				struct sadb_protocol *sp =
					(struct sadb_protocol *) se;
				fprintf(out,
					"proto=%u direction=%u flags=%u } ",
					sp->sadb_protocol_proto,
					sp->sadb_protocol_direction,
					sp->sadb_protocol_flags);
			}
			break;

		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
			if (elen < sizeof(struct sadb_lifetime)) {
				too_small_for = "struct sadb_lifetime";
			} else {
				struct sadb_lifetime *life =
					(struct sadb_lifetime *)se;

				fprintf(out,
					"allocations=%u bytes=%" PRIu64
					" addtime=%" PRIu64
					" usetime=%" PRIu64
#ifdef NOT_YET
					" packets=%u"
#endif /* NOT_YET */
					,
					life->sadb_lifetime_allocations,
					life->sadb_lifetime_bytes,
					life->sadb_lifetime_addtime,
					life->sadb_lifetime_usetime
#ifdef NOT_YET
					, life->sadb_x_lifetime_packets
#endif /* NOT_YET */
					);
				fprintf(out, " } ");
			}
			break;

		case SADB_EXT_RESERVED:
		case SADB_EXT_ADDRESS_PROXY:
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
		case SADB_EXT_SENSITIVITY:
		case SADB_EXT_PROPOSAL:
		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
		case SADB_EXT_SPIRANGE:
		case SADB_X_EXT_KMPRIVATE:
		case SADB_X_EXT_SATYPE2:
		case SADB_X_EXT_SA2:
		case SADB_X_EXT_ADDRESS_DST2:
		case SADB_X_EXT_DEBUG:	/* also used in malformed case */
		default:
		{
			unsigned int count = elen - sizeof(struct sadb_ext);
			unsigned char *bytes = (unsigned char *)&se[1];

			fprintf(out, "bytes=0x");
			while (count > 0) {
				fprintf(out, "%02x", *bytes);
				bytes++;
				count--;
			}
			fprintf(out, " } ");
		}
		break;
		}

		if (too_small_for != NULL)
			fprintf(out, "too small for %s ", too_small_for);

		/* skip to next extension header */
		se = (struct sadb_ext *) ((unsigned char *) se + elen);
		len -= elen;
	}

	if (len > 0)
		fprintf(out, "%u bytes left over", len);

	fprintf(out, "\n");
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
		if (readlen < (ssize_t)sizeof(struct sadb_msg)) {
			printf("%s: runt packet of size: %zd (<%zu)\n",
			       progname, readlen,
			       sizeof(struct sadb_msg));
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

