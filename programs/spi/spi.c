/*
 * All-in-one program to set Security Association parameters
 * Copyright (C) 1996  John Ioannidis.
 * Copyright (C) 1997, 1998, 1999, 2000, 2001, 2002, 2017  Richard Guy Briggs <rgb@tricolour.ca>
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 Paul Wouters <paul@libreswan.org>
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

#include <asm/types.h>
#include <sys/types.h>
#include <sys/ioctl.h>
/* #include <linux/netdevice.h> */
#include <net/if.h>
/* #include <linux/types.h> */ /* new */
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

/* #include <sys/socket.h> */

#include <netinet/in.h>
#include <arpa/inet.h>
/* #include <linux/ip.h> */
#include <netdb.h>

#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#include <libreswan.h>
#include <signal.h>
#include <sys/socket.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "constants.h"

#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_ipe4.h"
#include "libreswan/ipsec_ah.h"
#include "libreswan/ipsec_esp.h"
#include "libreswan/ipsec_sa.h"  /* IPSEC_SAREF_NULL */
#include <libreswan/pfkey_debug.h> /* PF_KEY_DEBUG_PARSE_MAX */

#include "lswlog.h"
#include "lswtool.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "kernel_sadb.h"
#include "pfkey_help.h"
#include "ip_address.h"

struct encap_msghdr *em;

const char *progname;
bool debug = FALSE;
bool get = FALSE;
int dumpsaref = 0;
int saref_him = 0;
int saref_me  = 0;
char *command;
char scratch[2];
unsigned char *iv = NULL, *enckey = NULL, *authkey = NULL;
size_t ivlen = 0, enckeylen = 0, authkeylen = 0;
ip_address edst, dst, src;
int address_family = 0;
unsigned char proto = 0;
int alg = 0;

#include <assert.h>
const char *alg_string = NULL;          /* algorithm string */
struct proposal_info *esp_info = NULL;       /* esp info from 1st (only) element */
int proc_read_ok = 0;                   /* /proc/net/pf_key_support read ok */

unsigned long replay_window = 0;
char sa[SATOT_BUF];

int pfkey_sock;
uint32_t pfkey_seq = 0;
enum life_severity {
	life_soft = 0,
	life_hard = 1,
	life_maxsever = 2
};
enum life_type {
	life_alloc = 0,
	life_bytes = 1,
	life_addtime = 2,
	life_usetime = 3,
	life_packets = 4,
	life_maxtype = 5
};

static const char *usage_string =
	"Usage:\n"
	"	in the following, <SA> is: --af <inet | inet6> --edst <dstaddr> --spi <spi> --proto <proto>\n"
	"                               OR: --said <proto><.|:><spi>@<dstaddr>\n"
	"                         <life> is: --life <soft|hard>-<allocations|bytes|addtime|usetime|packets>=<value>[,...]\n"
	"spi --clear\n"
	"spi --help\n"
	"spi --version\n"
	"spi\n"
	"spi --del <SA>\n"
	"spi --ip4 <SA> --src <encap-src> --dst <encap-dst>\n"
	"spi --ip6 <SA> --src <encap-src> --dst <encap-dst>\n"
	"spi --ah <algo> <SA> [<life> ][ --replay_window <replay_window> ] --authkey <key>\n"
	"	where <algo> is one of:	hmac-md5-96 | hmac-sha1-96 | something-loaded\n"
	"spi --esp <algo> <SA> [<life> ][ --replay_window <replay-window> ] --enckey <ekey> --authkey <akey>\n"
	"	where <algo> is one of:	3des-md5-96 | 3des-sha1-96\n | something-loaded"
	"	also, --natt will enable UDP encapsulation, and --sport/--dport will set\n"
	"        the source/destination UDP ports.\n"
	"spi --esp <algo> <SA> [<life> ][ --replay_window <replay-window> ] --enckey <ekey>\n"
	"	where <algo> is:	3des\n"
	"spi --comp <algo> <SA>\n"
	"	where <algo> is:	deflate | lzs\n"
	"[ --sarefme=XXX ]  set the saref to use for this SA\n"
	"[ --sarefhim=XXX ] set the saref to use for paired SA\n"
	"[ --dumpsaref ] show the saref allocated\n"
	"[ --outif=XXX ] set the outgoing interface to use\n"
	"[ --debug ] is optional to any spi command.\n"
	"[ --get ] show the current lifetime stats for the <SA>.\n"
	"[ --label <label> ] is optional to any spi command.\n"
	"[ --listenreply ]   is optional, and causes the command to stick\n"
	"                    around and listen to what the PF_KEY socket says.\n";

static void usage(const char *s, FILE *f)
{
	/* s argument is actually ignored, at present */
	fprintf(f, "%s:%s", s, usage_string);
	exit(-1);
}

static bool parse_life_options(uint32_t life[life_maxsever][life_maxtype],
		       char *life_opt[life_maxsever][life_maxtype],
		       char *myoptarg)
{
	char *optargp = myoptarg;
	char *endptr;

	do {
		int life_severity, life_type;
		char *optargt = optargp;

		if (eat(optargp, "soft")) {
			life_severity = life_soft;
		} else if (eat(optargp, "hard")) {
			life_severity = life_hard;
		} else {
			fprintf(stderr,
				"%s: missing lifetime severity in %s\n",
				progname,
				optargt);
			usage(progname, stderr);
			return TRUE;
		}
		if (debug) {
			fprintf(stdout,
				"%s: debug: life_severity=%d (%s)\n",
				progname,
				life_severity,
				optargt);
		}
		if (*optargp++ != '-') {
			fprintf(stderr,
				"%s: expected '-' after severity of lifetime parameter to --life option.\n",
				progname);
			usage(progname, stderr);
			return TRUE;
		}
		if (debug) {
			fprintf(stdout,
				"%s: debug: optargt=\"%s\", optargp=\"%s\"\n",
				progname,
				optargt,
				optargp);
		}
		if (eat(optargp, "allocations")) {
			life_type = life_alloc;
		} else if (eat(optargp, "bytes")) {
			life_type = life_bytes;
		} else if (eat(optargp, "addtime")) {
			life_type = life_addtime;
		} else if (eat(optargp, "usetime")) {
			life_type = life_usetime;
		} else if (eat(optargp, "packets")) {
			life_type = life_packets;
		} else {
			fprintf(stderr,
				"%s: missing lifetime type after '-' in %s\n",
				progname,
				optargt);
			usage(progname, stderr);
			return TRUE;
		}
		if (debug) {
			fprintf(stdout,
				"%s: debug: life_type=%d\n",
				progname,
				life_type);
		}
		if (life_opt[life_severity][life_type] != NULL) {
			fprintf(stderr,
				"%s: Error, lifetime parameter redefined:%s, already defined as:0p%p\n",
				progname,
				optargt,
				life_opt[life_severity][life_type]);
			return TRUE;
		}
		if (*optargp++ != '=') {
			fprintf(stderr,
				"%s: expected '=' after type of lifetime parameter to --life option.\n",
				progname);
			usage(progname, stderr);
			return TRUE;
		}
		if (debug) {
			fprintf(stdout,
				"%s: debug: optargt=0p%p, optargt+strlen(optargt)=0p%p, optargp=0p%p, strlen(optargp)=%d\n",
				progname,
				optargt,
				optargt + strlen(optargt),
				optargp,
				(int)strlen(optargp));
		}
		if (optargp[0] == '\0') {
			fprintf(stderr,
				"%s: expected value after '=' in --life option. optargt=0p%p, optargt+strlen(optargt)=0p%p, optargp=0p%p\n",
				progname,
				optargt,
				optargt + strlen(optargt),
				optargp);
			usage(progname, stderr);
			return TRUE;
		}

		errno = 0;
		life[life_severity][life_type] = strtoul(optargp, &endptr, 0);

		if (errno != 0 || optargp == endptr) {
			fprintf(stderr,
				"%s: Invalid number for lifetime option parameter %s in parameter string \"%s\"\n",
				progname,
				myoptarg,
				optargp);
			return TRUE;
		}

		switch (*endptr) {
		case '\0':
		case ',':
		case ' ':
			break;	/* OK */
		default:
			/*
			 * clang 3.4: warning: Null pointer passed as an argument to a 'nonnull' parameter
			 * This is about the strlen(myoptarg).
			 * It seems wrong.
			 */
			fprintf(stderr,
				"%s: Invalid character='%c' at offset %d in lifetime option parameter: '%s', parameter string is %d characters long, %d valid value characters found.\n",
				progname,
				*endptr,
				(int)(endptr - myoptarg),
				myoptarg,
				(int)strlen(myoptarg),
				(int)(strcspn(optargp, ", ") - 1));
			return TRUE;
		}
		life_opt[life_severity][life_type] = optargt;
		if (debug) {
			fprintf(stdout, "%s lifetime %s set to %" PRIu32 ".\n",
				progname, optargt,
				life[life_severity][life_type]);
		}
		optargp = endptr + 1;
	} while (*endptr != '\0');

	return FALSE;
}

static const struct option longopts[] =
{
	{ "ah", 1, 0, 'H' },
	{ "esp", 1, 0, 'P' },
	{ "comp", 1, 0, 'Z' },
	{ "ip4", 0, 0, '4' },
	{ "ip6", 0, 0, '6' },
	{ "del", 0, 0, 'd' },

	{ "authkey", 1, 0, 'A' },
	{ "enckey", 1, 0, 'E' },
	{ "edst", 1, 0, 'e' },
	{ "spi", 1, 0, 's' },
	{ "proto", 1, 0, 'p' },
	{ "af", 1, 0, 'a' },
	{ "replay_window", 1, 0, 'w' },
	{ "iv", 1, 0, 'i' },
	{ "dst", 1, 0, 'D' },
	{ "src", 1, 0, 'S' },
	{ "natt",  1, 0, 'N' },
	{ "dport", 1, 0, 'F' },
	{ "sport", 1, 0, 'G' },
	{ "said", 1, 0, 'I' },

	{ "help", 0, 0, 'h' },
	{ "version", 0, 0, 'v' },
	{ "clear", 0, 0, 'c' },
	{ "label", 1, 0, 'l' },
	{ "debug", 0, 0, 'g' },
	{ "life", 1, 0, 'f' },
	{ "outif",     required_argument, NULL, 'O' },
	{ "saref",     required_argument, NULL, 'b' },
	{ "sarefme",   required_argument, NULL, 'b' },
	{ "sarefhim",  required_argument, NULL, 'B' },
	{ "saref_me",  required_argument, NULL, 'b' },
	{ "saref_him", required_argument, NULL, 'B' },
	{ "dumpsaref", no_argument,       NULL, 'r' },
	{ "listenreply", 0, 0, 'R' },
	{ "get",	no_argument,       NULL, 't' },
	{ 0, 0, 0, 0 }
};

static bool pfkey_build(int error,
			const char *description,
			const char *text_said,
			struct sadb_ext *extensions[K_SADB_EXT_MAX + 1])
{
	if (error == 0) {
		return TRUE;
	} else {
		loglog(RC_LOG_SERIOUS, "building of %s %s failed, code %d",
		       description, text_said, error);
		pfkey_extensions_free(extensions);
		return FALSE;
	}
}

/*
 * Load kernel_alg arrays from /proc
 * Only used in manual mode from programs/spi/spi.c
 */
static bool kernel_alg_proc_read(void)
{
	int satype;
	int supp_exttype;
	int alg_id, ivlen, minbits, maxbits;
	char name[20];
	struct sadb_alg sadb_alg;
	char buf[128];
	FILE *fp = fopen("/proc/net/pf_key_supported", "r");

	if (fp == NULL)
		return FALSE;

	kernel_alg_init();
	while (fgets(buf, sizeof(buf), fp)) {
		if (buf[0] != ' ')	/* skip titles */
			continue;
		sscanf(buf, "%d %d %d %d %d %d %s",
			&satype, &supp_exttype,
			&alg_id, &ivlen,
			&minbits, &maxbits, name);
		switch (satype) {
		case SADB_SATYPE_ESP:
			switch (supp_exttype) {
			case SADB_EXT_SUPPORTED_AUTH:
			case SADB_EXT_SUPPORTED_ENCRYPT:
				sadb_alg.sadb_alg_id = alg_id;
				sadb_alg.sadb_alg_ivlen = ivlen;
				sadb_alg.sadb_alg_minbits = minbits;
				sadb_alg.sadb_alg_maxbits = maxbits;
				sadb_alg.sadb_alg_reserved = 0;
				kernel_add_sadb_alg(satype, supp_exttype,
						    &sadb_alg);
				break;
			}
			break;
		default:
			break;
		}
	}
	fclose(fp);
	return TRUE;
}

/*
 * This policy disables both IKEv1 and IKEv2 checks so all algorithms
 * are valid.
 */

const struct proposal_policy policy = {
	.ikev1 = false,
	.ikev2 = false,
	.alg_is_ok = kernel_alg_is_ok,
};

static int decode_esp(char *algname)
{
	char err_buf[256] = "";	/* ??? big enough? */
	int esp_alg;

	struct alg_info_esp *alg_info = alg_info_esp_create_from_str(&policy, algname,
								     err_buf, sizeof(err_buf));

	if (alg_info != NULL) {
		int esp_ealg_id, esp_aalg_id;

		esp_alg = XF_OTHER_ALG;
		if (alg_info->ai.alg_info_cnt > 1) {
			fprintf(stderr, "%s: Invalid encryption algorithm '%s' "
				"follows '--esp' option: lead too many(%d) "
				"transforms\n",
				progname, algname,
				alg_info->ai.alg_info_cnt);
			exit(1);
		}
		alg_string = algname;
		esp_info = &alg_info->ai.proposals[0];
		if (debug) {
			fprintf(stdout,
				"%s: alg_info: cnt=%d ealg[0]=%d aalg[0]=%d\n",
				progname,
				alg_info->ai.alg_info_cnt,
				esp_info->encrypt->common.id[IKEv1_ESP_ID],
				esp_info->integ->common.id[IKEv1_ESP_ID]);
		}
		esp_ealg_id = esp_info->encrypt->common.id[IKEv1_ESP_ID];
		esp_aalg_id = esp_info->integ->common.id[IKEv1_ESP_ID];
		if (kernel_alg_proc_read()) {
			proc_read_ok++;

			if (!kernel_alg_encrypt_ok(esp_info->encrypt)) {
				fprintf(stderr, "%s: ESP encryptalg=%d (\"%s\") "
					"not present\n",
					progname,
					esp_ealg_id,
					enum_name(&esp_transformid_names,
						  esp_ealg_id));
				exit(1);
			}

			if (!kernel_alg_integ_ok(esp_info->integ)) {
				/* ??? this message looks badly worded */
				fprintf(stderr, "%s: ESP authalg=%d (\"%s\") - alg not present\n",
					progname, esp_aalg_id,
					enum_name(&auth_alg_names,
						  esp_aalg_id));
				exit(1);
			}
		}
	} else {
		fprintf(stderr,
			"%s: Invalid encryption algorithm '%s' follows '--esp' option %s\n",
			progname, algname, err_buf);
		exit(1);
	}
	return esp_alg;
}

static void decode_blob(const char *optarg, const char *name, unsigned char **pp, size_t *lp)
{
	char err_buf[TTODATAV_BUF];
	size_t len;
	/*
	 * err_t ttodatav(const char *src, size_t srclen, int base,
	 *                char *dst, size_t dstlen, size_t *lenp,
	 *                char *errp, size_t errlen, int flags);
	 */
	err_t ugh = ttodatav(optarg, 0, 0, NULL, 0, &len, err_buf, sizeof(err_buf), 0);

	if (ugh != NULL) {
		fprintf(stderr,
			"%s: malformed %s: %s\n",
			progname, name, ugh);
		exit(1);
	}
	*pp = malloc(len);
	if (*pp == NULL) {
		fprintf(stderr,
			"%s: Memory allocation error for %s.\n",
			progname, name);
		exit(1);
	}
	ugh = ttodatav(optarg, 0, 0, (char *)*pp, len, lp, err_buf, sizeof(err_buf), 0);
	assert(ugh == NULL);
}

static void emit_lifetime(const char *extname, uint16_t exttype, struct sadb_ext *extensions[K_SADB_EXT_MAX + 1],
	char *lo[life_maxtype], uint32_t l[life_maxtype])
{
	if (lo[life_alloc] != NULL ||
	    lo[life_bytes] != NULL ||
	    lo[life_addtime] != NULL ||
	    lo[life_usetime] != NULL ||
	    lo[life_packets] != NULL) {
		int error = pfkey_lifetime_build(
			&extensions[exttype],
			exttype,
			l[life_alloc],
			l[life_bytes],
			l[life_addtime],
			l[life_usetime],
			l[life_packets]);

		if (error != 0)
		{
			fprintf(stderr,
				"%s: Trouble building %s extension, error=%d.\n",
				progname, extname, error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if (debug) {
			fprintf(stdout,
				"%s: %s extension assembled.\n",
				progname, extname);
		}
	}
}

int main(int argc, char *argv[])
{
	tool_init_log(argv[0]);
	/* force pfkey logging */
	pfkey_error_func = pfkey_debug_func = printf;

	__u32 spi = 0;
	int c;
	ip_said said;
	const char *error_s;
	char ipsaid_txt[SATOT_BUF];

	int outif = 0;
	int error = 0;
	ssize_t io_error;
	int argcount = argc;
	pid_t mypid;
	int listenreply = 0;

	unsigned char authalg, encryptalg;
	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;
	char *edst_opt, *spi_opt, *proto_opt, *af_opt, *said_opt, *dst_opt,
		*src_opt;
	uint32_t natt;
	uint16_t sport, dport;
	uint32_t life[life_maxsever][life_maxtype];
	char *life_opt[life_maxsever][life_maxtype];
	struct stat sts;
	struct sadb_builds sab;

	mypid = getpid();
	natt = 0;
	sport = 0;
	dport = 0;

	zero(&said);	/* OK: no pointer fields */
	edst_opt = spi_opt = proto_opt = af_opt = said_opt = dst_opt =
		src_opt = NULL;
	{
		int i, j;

		for (i = 0; i < life_maxsever; i++) {
			for (j = 0; j < life_maxtype; j++) {
				life_opt[i][j] = NULL;
				life[i][j] = 0;
			}
		}
	}

	while ((c = getopt_long(argc, argv,
				"" /*"H:P:Z:46dcA:E:e:s:a:w:i:D:S:hvgl:+:f:t"*/,
				longopts, 0)) != EOF) {
		unsigned long u;
		err_t ugh;

		switch (c) {
		case 't':
			get = TRUE;
			argcount--;
			alg = XF_GET;
			if (debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					progname,
					alg);
			}
			break;

		case 'g':
			debug = TRUE;
			pfkey_lib_debug = PF_KEY_DEBUG_PARSE_MAX;
			/* paul: this is a plutoism? cur_debugging = 0xffffffff; */
			argcount--;
			break;

		case 'R':
			listenreply = 1;
			argcount--;
			break;

		case 'r':
			dumpsaref = 1;
			argcount--;
			break;

		case 'b':  /* set the SAref to use */
			ugh = ttoulb(optarg, 0, 0, INT_MAX, &u);
			if (ugh != NULL) {
				fprintf(stderr,
					"%s: Invalid SAREFi parameter \"%s\": %s\n",
					progname, optarg, ugh);
				exit(1);
			}
			saref_me = u;
			argcount--;
			break;

		case 'B':  /* set the SAref to use for outgoing packets */
			ugh = ttoulb(optarg, 0, 0, INT_MAX, &u);
			if (ugh != NULL) {
				fprintf(stderr,
					"%s: Invalid SAREFo parameter \"%s\": %s\n",
					progname, optarg, ugh);
				exit(1);
			}
			saref_him = u;
			argcount--;
			break;

		case 'O':  /* set interface from which packet should arrive */
			ugh = ttoulb(optarg, 0, 0, INT_MAX, &u);
			if (ugh != NULL) {
				fprintf(stderr,
					"%s: Invalid outif parameter \"%s\": %s\n",
					progname, optarg, ugh);
				exit(1);
			}
			outif = u;
			argcount--;
			break;

		case 'l':
		{
			static const char combine_fmt[] = "%s --label %s";
			size_t room = strlen(argv[0]) +
					  sizeof(combine_fmt) +
					  strlen(optarg);

			char *progname = malloc(room);
			snprintf(progname, room, combine_fmt,
				 argv[0],
				 optarg);
			tool_init_log(progname);

			argcount -= 2;
			break;
		}
		case 'H':
			if (alg != 0) {
				fprintf(stderr,
					"%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear'  options permitted.\n",
					progname);
				exit(1);
			}
			if (streq(optarg, "hmac-md5-96")) {
				alg = XF_AHHMACMD5;
			} else if (streq(optarg, "hmac-sha1-96")) {
				alg = XF_AHHMACSHA1;
			} else {
				fprintf(stderr,
					"%s: Unknown authentication algorithm '%s' follows '--ah' option.\n",
					progname, optarg);
				exit(1);
			}
			if (debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					progname,
					alg);
			}
			break;

		case 'P':
			if (alg != 0) {
				fprintf(stderr,
					"%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear'  options permitted.\n",
					progname);
				exit(1);
			}

			alg = decode_esp(optarg);

			if (debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					progname,
					alg);
			}
			break;

		case 'Z':
			if (alg != 0) {
				fprintf(stderr,
					"%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear'  options permitted.\n",
					progname);
				exit(1);
			}
			if (streq(optarg, "deflate")) {
				alg = XF_COMPDEFLATE;
			} else if (streq(optarg, "lzs")) {
				alg = XF_COMPLZS;
			} else {
				fprintf(stderr,
					"%s: Unknown compression algorithm '%s' follows '--comp' option.\n",
					progname, optarg);
				exit(1);
			}
			if (debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					progname,
					alg);
			}
			break;

		case '4':
			if (alg != 0) {
				fprintf(stderr,
					"%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear' options permitted.\n",
					progname);
				exit(1);
			}
			alg = XF_IP4;
			address_family = AF_INET;
			if (debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					progname,
					alg);
			}
			break;

		case '6':
			if (alg != 0) {
				fprintf(stderr,
					"%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear' options permitted.\n",
					progname);
				exit(1);
			}
			alg = XF_IP6;
			address_family = AF_INET6;
			if (debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					progname,
					alg);
			}
			break;

		case 'd':
			if (alg != 0) {
				fprintf(stderr,
					"%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear'  options permitted.\n",
					progname);
				exit(1);
			}
			alg = XF_DEL;
			if (debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					progname,
					alg);
			}
			break;

		case 'c':
			if (alg != 0) {
				fprintf(stderr,
					"%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear'  options permitted.\n",
					progname);
				exit(1);
			}
			alg = XF_CLR;
			if (debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					progname,
					alg);
			}
			break;

		case 'e':
			if (said_opt != NULL) {
				fprintf(stderr,
					"%s: Error, EDST parameter redefined:%s, already defined in SA:%s\n",
					progname, optarg, said_opt);
				exit(1);
			}
			if (edst_opt != NULL) {
				fprintf(stderr,
					"%s: Error, EDST parameter redefined:%s, already defined as:%s\n",
					progname, optarg, edst_opt);
				exit(1);
			}
			error_s = ttoaddr_num(optarg, 0, address_family, &edst);
			if (error_s != NULL) {
				if (error_s) {
					fprintf(stderr,
						"%s: Error, %s converting --edst argument:%s\n",
						progname, error_s, optarg);
					exit(1);
				}
			}
			edst_opt = optarg;
			if (debug) {
				ipstr_buf b;

				fprintf(stdout, "%s: edst=%s.\n",
					progname,
					ipstr(&edst, &b));
			}
			break;

		case 's':
			if (said_opt != NULL) {
				fprintf(stderr,
					"%s: Error, SPI parameter redefined:%s, already defined in SA:%s\n",
					progname, optarg, said_opt);
				exit(1);
			}
			if (spi_opt != NULL) {
				fprintf(stderr,
					"%s: Error, SPI parameter redefined:%s, already defined as:%s\n",
					progname, optarg, spi_opt);
				exit(1);
			}
			ugh = ttoulb(optarg, 0, 0, 0xFFFFFFFFul, &u);
			if (ugh == NULL && u < 0x100)
				ugh = "0 - 0xFF are reserved";
			if (ugh != NULL) {
				fprintf(stderr,
					"%s: Invalid SPI parameter \"%s\": %s\n",
					progname, optarg, ugh);
				exit(1);
			}
			spi = u;
			spi_opt = optarg;
			break;

		case 'p':
			if (said_opt != NULL) {
				fprintf(stderr,
					"%s: Error, PROTO parameter redefined:%s, already defined in SA:%s\n",
					progname, optarg, said_opt);
				exit(1);
			}
			if (proto_opt != NULL) {
				fprintf(stderr,
					"%s: Error, PROTO parameter redefined:%s, already defined as:%s\n",
					progname, optarg, proto_opt);
				exit(1);
			}
			if (streq(optarg, "ah")) {
				proto = SA_AH;
			} else if (streq(optarg, "esp")) {
				proto = SA_ESP;
			} else if (streq(optarg, "tun")) {
				proto = SA_IPIP;
			} else if (streq(optarg, "comp")) {
				proto = SA_COMP;
			} else {
				fprintf(stderr,
					"%s: Invalid PROTO parameter: %s\n",
					progname, optarg);
				exit(1);
			}
			proto_opt = optarg;
			break;

		case 'a':
			if (said_opt != NULL) {
				fprintf(stderr,
					"%s: Error, ADDRESS FAMILY parameter redefined:%s, already defined in SA:%s\n",
					progname, optarg, said_opt);
				exit(1);
			}
			if (af_opt != NULL) {
				fprintf(stderr,
					"%s: Error, ADDRESS FAMILY parameter redefined:%s, already defined as:%s\n",
					progname, optarg, af_opt);
				exit(1);
			}
			if (streq(optarg, "inet")) {
				address_family = AF_INET;
			} else if (streq(optarg, "inet6")) {
				address_family = AF_INET6;
			} else {
				fprintf(stderr,
					"%s: Invalid ADDRESS FAMILY parameter: %s.\n",
					progname, optarg);
				exit(1);
			}
			/* currently we ensure that all addresses belong to the same address family */
			anyaddr(address_family, &dst);
			anyaddr(address_family, &edst);
			anyaddr(address_family, &src);
			af_opt = optarg;
			break;

		case 'I':
			if (said_opt != NULL) {
				fprintf(stderr,
					"%s: Error, SAID parameter redefined:%s, already defined in SA:%s\n",
					progname, optarg, said_opt);
				exit(1);
			}
			if (proto_opt != NULL) {
				fprintf(stderr,
					"%s: Error, PROTO parameter redefined in SA:%s, already defined as:%s\n",
					progname, optarg, proto_opt);
				exit(1);
			}
			if (edst_opt != NULL) {
				fprintf(stderr,
					"%s: Error, EDST parameter redefined in SA:%s, already defined as:%s\n",
					progname, optarg, edst_opt);
				exit(1);
			}
			if (spi_opt != NULL) {
				fprintf(stderr,
					"%s: Error, SPI parameter redefined in SA:%s, already defined as:%s\n",
					progname, optarg, spi_opt);
				exit(1);
			}
			error_s = ttosa(optarg, 0, &said);
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Error, %s converting --sa argument:%s\n",
					progname, error_s, optarg);
				exit(1);
			}
			if (debug) {
				satot(&said, 0, ipsaid_txt,
				      sizeof(ipsaid_txt));
				fprintf(stdout, "%s: said=%s.\n",
					progname,
					ipsaid_txt);
			}
			/* init the src and dst with the same address family */
			if (address_family == 0) {
				address_family = addrtypeof(&said.dst);
			} else if (address_family != addrtypeof(&said.dst)) {
				fprintf(stderr,
					"%s: Error, specified address family (%d) is different that of SAID: %s\n",
					progname, address_family, optarg);
				exit(1);
			}
			anyaddr(address_family, &dst);
			anyaddr(address_family, &edst);
			anyaddr(address_family, &src);
			said_opt = optarg;
			break;

		case 'A':
			decode_blob(optarg, "Authentication Key", &authkey, &authkeylen);
			break;

		case 'E':
			decode_blob(optarg, "Encryption Key", &enckey, &enckeylen);
			break;

		case 'w':
		{
			err_t ugh = ttoul(optarg, 0, 0, &replay_window);

			if (ugh != NULL) {
				fprintf(stderr,
					"%s: Invalid replay_window parameter: %s\n",
					progname, ugh);
				exit(1);
			}
			if (!(1 <= replay_window && replay_window <= 64)) {
				fprintf(stderr,
					"%s: Failed -- Illegal window size: arg=%s, replay_window=%lu, must be 1 <= size <= 64.\n",
					progname, optarg, replay_window);
				exit(1);
			}
		}
			break;

		case 'i':
			decode_blob(optarg, "IV", &iv, &ivlen);
			break;

		case 'D':
			if (dst_opt != NULL) {
				fprintf(stderr,
					"%s: Error, DST parameter redefined:%s, already defined as:%s\n",
					progname, optarg, dst_opt);
				exit(1);
			}
			error_s = ttoaddr_num(optarg, 0, address_family, &dst);
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Error, %s converting --dst argument:%s\n",
					progname, error_s, optarg);
				exit(1);
			}
			dst_opt = optarg;
			if (debug) {
				ipstr_buf b;

				fprintf(stdout, "%s: dst=%s.\n",
					progname,
					ipstr(&dst, &b));
			}
			break;

		case 'F':  /* src port */
			{
				unsigned long u;
				err_t ugh = ttoulb(optarg, 0, 0, 0xFFFF, &u);

				if (ugh != NULL) {
					fprintf(stderr,
						"%s: Invalid source port parameter \"%s\": %s\n",
						progname, optarg, ugh);
					exit(1);
				}
				sport = u;
			}
			break;

		case 'G':  /* dst port */
			{
				unsigned long u;
				err_t ugh = ttoulb(optarg, 0, 0, 0xFFFF, &u);

				if (ugh != NULL) {
					fprintf(stderr,
						"%s: Invalid destination port parameter \"%s\": %s\n",
						progname, optarg, ugh);
					exit(1);
				}
				dport = u;
			}
			break;

		case 'N':  /* nat-type */
			if (strcaseeq(optarg, "nonesp")) {
				natt = ESPINUDP_WITH_NON_ESP;
			} else if (strcaseeq(optarg, "none")) {
				natt = 0;
			} else {
				/* ??? what does this do?  Where is it documented? */
				unsigned long u;
				err_t ugh = ttoulb(optarg, 0, 0, 0xFFFFFFFFul, &u);

				if (ugh != NULL) {
					fprintf(stderr,
						"%s: Invalid character in natt parameter \"%s\": %s\n",
						progname, optarg, ugh);
					exit(1);
				}
				natt = u;
			}
			break;

		case 'S':
			if (src_opt != NULL) {
				fprintf(stderr,
					"%s: Error, SRC parameter redefined:%s, already defined as:%s\n",
					progname, optarg, src_opt);
				exit(1);
			}
			error_s = ttoaddr_num(optarg, 0, address_family, &src);
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Error, %s converting --src argument:%s\n",
					progname, error_s, optarg);
				exit(1);
			}
			src_opt = optarg;
			if (debug) {
				ipstr_buf b;

				fprintf(stdout, "%s: src=%s.\n",
					progname,
					ipstr(&src, &b));
			}
			break;

		case 'h':
			usage(progname, stdout);
			exit(0);

		case '?':
			usage(progname, stderr);
			exit(1);

		case 'v':
			fprintf(stdout, "%s, %s\n", progname,
				ipsec_version_code());
			exit(1);

		case 'f':
			if (parse_life_options(life,
					       life_opt,
					       optarg) != 0)
				exit(1);
			break;

		default:
			fprintf(stderr,
				"%s: unrecognized option '%c', update option processing.\n",
				progname, c);
			exit(1);
		}
	}
	if (debug) {
		fprintf(stdout, "%s: All options processed.\n",
			progname);
	}

	if (stat("/proc/net/pfkey", &sts) == 0) {
		fprintf(stderr,
			"%s: NETKEY does not use the ipsec spi command. Use 'ip xfrm' instead.\n",
			progname);
		exit(1);
	}

	if (argcount == 1) {
		int ret = 1;

		if ((stat("/proc/net/ipsec_spi", &sts)) != 0) {
			fprintf(stderr,
				"%s: No spi - no IPsec support in kernel (are the modules loaded?)\n",
				progname);
		} else {
			ret = system("cat /proc/net/ipsec_spi");
			ret = ret != -1 &&
			      WIFEXITED(ret) ? WEXITSTATUS(ret) : 1;
		}
		exit(ret);
	}

	switch (alg) {
	case XF_OTHER_ALG:
		/* validate keysizes */
		if (proc_read_ok) {
			{
				size_t keylen = enckeylen * 8;
				size_t minbits = encrypt_min_key_bit_length(esp_info->encrypt);
				size_t maxbits = encrypt_max_key_bit_length(esp_info->encrypt);
				/*
				 * if explicit keylen told in encrypt
				 * algo, eg "aes128" check actual
				 * keylen "equality"
				 */
				if (esp_info->enckeylen &&
				    esp_info->enckeylen != keylen) {
					fprintf(stderr, "%s: invalid encryption keylen=%d, "
						"required %d by encrypt algo string=\"%s\"\n",
						progname,
						(int)keylen,
						(int)esp_info->enckeylen,
						alg_string);
					exit(1);
				}
				/* thanks DES for this sh*t */
				if (minbits > keylen || maxbits < keylen) {
					fprintf(stderr, "%s: invalid encryption keylen=%d, "
						"must be between %d and %d bits\n",
						progname,
						(int)keylen,
						(int)minbits,
						(int)maxbits);
					exit(1);
				}
			}
			{
				size_t keylen = authkeylen * 8;
				size_t minbits = esp_info->integ->integ_keymat_size * 8;
				size_t maxbits = esp_info->integ->integ_keymat_size * 8;
				if (minbits > keylen || maxbits < keylen) {
					fprintf(stderr, "%s: invalid auth keylen=%d, "
						"must be between %d and %d bits\n",
						progname,
						(int)keylen,
						(int)minbits,
						(int)maxbits);
					exit(1);
				}
			}
		}
		/*
		 * ??? this break was added in a2791fda77a5cfcc6bc992fbc5019f4448112f88
		 * It is likely correct, but we're not sure.
		 * Luckily this code is probably never used.
		 */
		break;
	case XF_IP4:
	case XF_IP6:
	case XF_DEL:
	case XF_COMPDEFLATE:
	case XF_COMPLZS:
	case XF_GET:
		if (said_opt == NULL) {
			if (isanyaddr(&edst)) {
				fprintf(stderr,
					"%s: SA destination not specified.\n",
					progname);
				exit(1);
			}
			if (spi == 0) {
				fprintf(stderr, "%s: SA SPI not specified.\n",
					progname);
				exit(1);
			}
			if (proto == 0) {
				fprintf(stderr,
					"%s: SA PROTO not specified.\n",
					progname);
				exit(1);
			}
			initsaid(&edst, htonl(spi), proto, &said);
		} else {
			proto = said.proto;
			spi = ntohl(said.spi);
			edst = said.dst;
		}
		if ((address_family != 0) &&
		    (address_family != addrtypeof(&said.dst))) {
			fprintf(stderr,
				"%s: Defined address family and address family of SA missmatch.\n",
				progname);
			exit(1);
		}

		if (debug) {
			fprintf(stdout, "%s: SA valid.\n",
				progname);
		}
		break;
	case XF_CLR:
		break;
	default:
		fprintf(stderr,
			"%s: No action chosen.  See '%s --help' for usage.\n",
			progname, progname);
		exit(1);
	}

	switch (alg) {
	case XF_CLR:
	case XF_DEL:
	case XF_IP4:
	case XF_IP6:
	case XF_COMPDEFLATE:
	case XF_COMPLZS:
	case XF_OTHER_ALG:
	case XF_GET:
		break;
	default:
		fprintf(stderr,
			"%s: No action chosen.  See '%s --help' for usage.\n",
			progname, progname);
		exit(1);
	}
	if (debug) {
		fprintf(stdout, "%s: Algorithm ok.\n",
			progname);
	}

	pfkey_sock = pfkey_open_sock_with_error();
	if (pfkey_sock < 0)
		exit(1);

	/* Build an SADB_ADD message to send down. */
	/* It needs <base, SA, address(SD), key(AE)> minimum. */
	/*   Lifetime(HS) could be added before addresses. */
	pfkey_extensions_init(extensions);

	error = pfkey_msg_hdr_build(&extensions[0],
				    alg == XF_DEL ? SADB_DELETE :
					alg == XF_CLR ? SADB_FLUSH :
					    alg == XF_GET ? SADB_GET :
					    SADB_ADD,
				    proto2satype(proto),
				    0,
				    ++pfkey_seq,
				    mypid);
	if (error != 0) {
		fprintf(stderr,
			"%s: Trouble building message header, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}

	switch (alg) {
	case XF_OTHER_ALG:
		authalg = esp_info->integ->integ_ikev1_ah_transform;
		if (debug) {
			fprintf(stdout, "%s: debug: authalg=%d\n",
				progname, authalg);
		}
		break;
	default:
		authalg = SADB_AALG_NONE;
	}
	switch (alg) {
	case XF_COMPDEFLATE:
		encryptalg = SADB_X_CALG_DEFLATE;
		break;
	case XF_COMPLZS:
		encryptalg = SADB_X_CALG_LZS;
		break;
	case XF_OTHER_ALG:
		encryptalg = esp_info->encrypt->common.id[IKEv1_ESP_ID];
		if (debug) {
			fprintf(stdout, "%s: debug: encryptalg=%d\n",
				progname, encryptalg);
		}
		break;
	default:
		encryptalg = SADB_EALG_NONE;
	}
	/* IE: pfkey_msg->sadb_msg_type == SADB_FLUSH */
	if (!(alg == XF_CLR)) {
		sab.sa_base.sadb_sa_len        = 0;
		sab.sa_base.sadb_sa_exttype    = SADB_EXT_SA;
		sab.sa_base.sadb_sa_spi        = htonl(spi);
		sab.sa_base.sadb_sa_replay     = replay_window;
		sab.sa_base.sadb_sa_state      = K_SADB_SASTATE_MATURE;
		sab.sa_base.sadb_sa_auth       = authalg;
		sab.sa_base.sadb_sa_encrypt    = encryptalg;
		sab.sa_base.sadb_sa_flags      = 0;
		sab.sa_base.sadb_x_sa_ref      = IPSEC_SAREF_NULL;
		sab.sa_base.sadb_x_reserved[0] = 0;
		sab.sa_base.sadb_x_reserved[1] = 0;
		sab.sa_base.sadb_x_reserved[2] = 0;
		sab.sa_base.sadb_x_reserved[3] = 0;

		error = pfkey_sa_builds(&extensions[SADB_EXT_SA], sab);
		if (error != 0) {
			fprintf(stderr,
				"%s: Trouble building sa extension, error=%d.\n",
				progname, error);
			pfkey_extensions_free(extensions);
			exit(1);
		}

		if (saref_me || saref_him) {
			error = pfkey_saref_build(&extensions[
							  K_SADB_X_EXT_SAREF],
						  saref_me, saref_him);
			if (error) {
				fprintf(stderr,
					"%s: Trouble building saref extension, error=%d.\n",
					progname, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
		}

		if (outif != 0) {
			error = pfkey_outif_build(&extensions[
							   SADB_X_EXT_PLUMBIF],
						  outif);
			if (error != 0) {
				fprintf(stderr,
					"%s: Trouble building outif extension, error=%d.\n",
					progname, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
		}

		if (debug) {
			fprintf(stdout,
				"%s: extensions[0]=0p%p previously set with msg_hdr.\n",
				progname,
				extensions[0]);
		}
		if (debug) {
			fprintf(stdout,
				"%s: assembled SA extension, pfkey msg authalg=%d encalg=%d.\n",
				progname,
				authalg,
				encryptalg);
		}

		if (debug) {
			int i, j;

			for (i = 0; i < life_maxsever; i++) {
				for (j = 0; j < life_maxtype; j++) {
					fprintf(stdout,
						"%s: i=%d, j=%d, life_opt[%d][%d]=0p%p, life[%d][%d]=%d\n",
						progname,
						i, j, i, j, life_opt[i][j], i, j,
						life[i][j]);
				}
			}
		}

		emit_lifetime("lifetime_s", SADB_EXT_LIFETIME_SOFT, extensions, life_opt[life_soft], life[life_soft]);
		emit_lifetime("lifetime_h", SADB_EXT_LIFETIME_HARD, extensions, life_opt[life_hard], life[life_hard]);

		if (debug) {
			ipstr_buf b;

			fprintf(stdout,
				"%s: assembling address_s extension (%s).\n",
				progname, ipstr(&src, &b));
		}

		error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_SRC],
					    SADB_EXT_ADDRESS_SRC,
					    0,
					    0,
					    sockaddrof(&src));
		if (error != 0) {
			ipstr_buf b;

			fprintf(stderr,
				"%s: Trouble building address_s extension (%s), error=%d.\n",
				progname, ipstr(&src, &b), error);
			pfkey_extensions_free(extensions);
			exit(1);
		}

		error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_DST],
					    SADB_EXT_ADDRESS_DST,
					    0,
					    0,
					    sockaddrof(&edst));
		if (error != 0) {
			ipstr_buf b;

			fprintf(stderr,
				"%s: Trouble building address_d extension (%s), error=%d.\n",
				progname, ipstr(&edst, &b), error);
			pfkey_extensions_free(extensions);
			exit(1);
		}

		switch (alg) {
		/*	Allow no auth ... after all is local root decision 8)  */
		case XF_OTHER_ALG:
			if (authalg == 0)
				break;
			error = pfkey_key_build(&extensions[SADB_EXT_KEY_AUTH],
						SADB_EXT_KEY_AUTH,
						authkeylen * 8,
						authkey);
			if (error != 0) {
				fprintf(stderr,
					"%s: Trouble building key_a extension, error=%d.\n",
					progname, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
			if (debug) {
				fprintf(stdout,
					"%s: key_a extension assembled.\n",
					progname);
			}
			break;
		default:
			break;
		}

		switch (alg) {
		case XF_OTHER_ALG:
			if (enckeylen == 0) {
				if (debug)
					fprintf(stdout, "%s: key not provided (NULL alg?).\n",
						progname);
				break;

			}
			error = pfkey_key_build(&extensions[SADB_EXT_KEY_ENCRYPT],
						SADB_EXT_KEY_ENCRYPT,
						enckeylen * 8,
						enckey);
			if (error != 0) {
				fprintf(stderr,
					"%s: Trouble building key_e extension, error=%d.\n",
					progname, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
			if (debug) {
				fprintf(stdout,
					"%s: key_e extension assembled.\n",
					progname);
			}
			break;
		default:
			break;
		}
	}

	if (natt != 0) {
		bool success;

		int err;

		err = pfkey_x_nat_t_type_build(&extensions[
							 K_SADB_X_EXT_NAT_T_TYPE],
					       natt);
		success = pfkey_build(err,
				      "pfkey_nat_t_type Add ESP SA",
				      ipsaid_txt, extensions);
		if (!success)
			return FALSE;

		if (debug)
			fprintf(stderr, "setting natt_type to %d\n", natt);

		if (sport != 0) {
			err = pfkey_x_nat_t_port_build(
					&extensions[K_SADB_X_EXT_NAT_T_SPORT],
					K_SADB_X_EXT_NAT_T_SPORT,
					sport);
			success = pfkey_build(err,
					      "pfkey_nat_t_sport Add ESP SA",
					      ipsaid_txt, extensions);
			if (debug)
				fprintf(stderr, "setting natt_sport to %d\n",
					sport);
			if (!success)
				return FALSE;
		}

		if (dport != 0) {
			err = pfkey_x_nat_t_port_build(
					&extensions[K_SADB_X_EXT_NAT_T_DPORT],
					K_SADB_X_EXT_NAT_T_DPORT,
					dport);
			success = pfkey_build(err,
					      "pfkey_nat_t_dport Add ESP SA",
					      ipsaid_txt, extensions);
			if (debug)
				fprintf(stderr, "setting natt_dport to %d\n",
					dport);
			if (!success)
				return FALSE;
		}
	}

	if (debug) {
		fprintf(stdout, "%s: assembling pfkey msg....\n",
			progname);
	}
	error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN);
	if (error != 0) {
		fprintf(stderr,
			"%s: Trouble building pfkey message, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}
	if (debug) {
		fprintf(stdout, "%s: assembled.\n",
			progname);
	}
	if (debug) {
		fprintf(stdout, "%s: writing pfkey msg.\n",
			progname);
	}
	io_error = write(pfkey_sock,
			 pfkey_msg,
			 pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN);
	if (io_error < 0) {
		fprintf(stderr, "%s: pfkey write failed (errno=%d): ",
			progname, errno);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		switch (errno) {
		case EACCES:
			fprintf(stderr, "access denied.  ");
			if (getuid() == 0)
				fprintf(stderr,
					"Check permissions.  Should be 600.\n");


			else
				fprintf(stderr,
					"You must be root to open this file.\n");


			break;
		case EUNATCH:
			fprintf(stderr,
				"Netlink not enabled OR KLIPS not loaded.\n");
			break;
		case EBUSY:
			fprintf(stderr,
				"KLIPS is busy.  Most likely a serious internal error occurred in a previous command.  Please report as much detail as possible to development team.\n");
			break;
		case EINVAL:
			fprintf(stderr,
				"Invalid argument, check kernel log messages for specifics.\n");
			break;
		case ENODEV:
			fprintf(stderr, "KLIPS not loaded or enabled.\n");
			fprintf(stderr, "No device?!?\n");
			break;
		case ENOBUFS:
			fprintf(stderr, "No kernel memory to allocate SA.\n");
			break;
		case ESOCKTNOSUPPORT:
			fprintf(stderr,
				"Algorithm support not available in the kernel.  Please compile in support.\n");
			break;
		case EEXIST:
			fprintf(stderr,
				"SA already in use.  Delete old one first.\n");
			break;
		case ENOENT:
			fprintf(stderr,
				"device does not exist.  See Libreswan installation procedure.\n");
			break;
		case ENXIO:
		case ESRCH:
			fprintf(stderr,
				"SA does not exist.  Cannot delete.\n");
			break;
		case ENOSPC:
			fprintf(stderr,
				"no room in kernel SAref table.  Cannot process request.\n");
			break;
		case ESPIPE:
			fprintf(stderr,
				"kernel SAref table internal error.  Cannot process request.\n");
			break;
		default:
			fprintf(stderr,
				"Unknown socket write error %d (%s).  Please report as much detail as possible to development team.\n",
				errno, strerror(errno));
		}
		exit(1);
	} else if (io_error !=
		   (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) {
		fprintf(stderr, "%s: pfkey write truncated to %d bytes\n",
			progname, (int)io_error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}

	if (debug) {
		fprintf(stdout, "%s: pfkey command written to socket.\n",
			progname);
	}

	if (pfkey_msg != NULL) {
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
	}
	if (debug) {
		fprintf(stdout, "%s: pfkey message buffer freed.\n",
			progname);
	}
	if (authkey != NULL) {
		memset(authkey, 0, authkeylen);
		free(authkey);
	}
	if (enckey != NULL) {
		memset(enckey, 0, enckeylen);
		free(enckey);
	}
	if (iv != NULL) {
		memset(iv, 0, ivlen);
		free(iv);
	}

	if (listenreply || saref_me || dumpsaref || get) {
		ssize_t readlen;
		unsigned char pfkey_buf[PFKEYv2_MAX_MSGSIZE];

		while ((readlen = read(pfkey_sock, pfkey_buf,
				     sizeof(pfkey_buf))) > 0) {
			struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
			pfkey_extensions_init(extensions);
			pfkey_msg = (struct sadb_msg *)pfkey_buf;

			/* first, see if we got enough for an sadb_msg */
			if ((size_t)readlen < sizeof(struct sadb_msg)) {
				if (debug) {
					printf("%s: runt packet of size: %zd (<%zu)\n",
						progname, readlen,
						sizeof(struct sadb_msg));
				}
				continue;
			}

			/* okay, we got enough for a message, print it out */
			if (debug) {
				printf("%s: pfkey v%d msg received. type=%d(%s) seq=%d len=%d pid=%d errno=%d satype=%d(%s)\n",
					progname,
					pfkey_msg->sadb_msg_version,
					pfkey_msg->sadb_msg_type,
					pfkey_v2_sadb_type_string(pfkey_msg->
								  sadb_msg_type),
					pfkey_msg->sadb_msg_seq,
					pfkey_msg->sadb_msg_len,
					pfkey_msg->sadb_msg_pid,
					pfkey_msg->sadb_msg_errno,
					pfkey_msg->sadb_msg_satype,
					satype2name(pfkey_msg->sadb_msg_satype));
			}

			if (readlen !=
			    (ssize_t)(pfkey_msg->sadb_msg_len *
				      IPSEC_PFKEYv2_ALIGN)) {
				if (debug) {
					printf("%s: packet size read from socket=%d doesn't equal sadb_msg_len %u * %u; message not decoded\n",
						progname,
						(int)readlen,
						(unsigned)pfkey_msg->sadb_msg_len,
						(unsigned)IPSEC_PFKEYv2_ALIGN);
				}
				continue;
			}

			if (pfkey_msg_parse(pfkey_msg, NULL, extensions,
					    EXT_BITS_OUT)) {
				if (debug) {
					printf("%s: unparseable PF_KEY message.\n",
						progname);
				}
				continue;
			}

			if (debug) {
				printf("%s: parseable PF_KEY message.\n",
					progname);
			}
			if ((pid_t)pfkey_msg->sadb_msg_pid == mypid) {
				if (saref_me || dumpsaref) {
					struct sadb_x_saref *s =
						(struct sadb_x_saref *)
						extensions[
							K_SADB_X_EXT_SAREF];

					if (s != NULL) {
						printf("%s: saref=%d/%d\n",
						       progname,
						       s->sadb_x_saref_me,
						       s->sadb_x_saref_him);
					}
				}
				if (get) {
					struct sadb_lifetime *s =
						(struct sadb_lifetime *)
						extensions[
							K_SADB_EXT_LIFETIME_CURRENT];

					if (s != NULL) {
						printf("%s: lifetime_current=%u(allocations)/%" PRIu64 "(bytes)/%" PRIu64 "(addtime)/%" PRIu64 "(usetime)"
#ifdef NOT_YET
						       "/%d(packets)"
#endif /* NOT_YET */
						       "\n",
						       progname,
						       s->sadb_lifetime_allocations,
						       s->sadb_lifetime_bytes,
						       s->sadb_lifetime_addtime,
						       s->sadb_lifetime_usetime
#ifdef NOT_YET
						       , s->sadb_x_lifetime_packets
#endif /* NOT_YET */
							);
					}
				}
				break;
			}
		}
	}
	(void) close(pfkey_sock);  /* close the socket */
	if (debug || listenreply)
		printf("%s: exited normally\n", progname);
	exit(0);
}
