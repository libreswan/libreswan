/* Pluto main program
 * Copyright (C) 1997      Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
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
 * Modifications to use OCF interface written by
 * Daniel Djamaludin <danield@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <resolv.h>

#include <libreswan.h>

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "sysdep.h"
#include "constants.h"
#include "lswconf.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "ac.h"
#include "connections.h"        /* needs id.h */
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "server.h"
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "keys.h"
#include "secrets.h"
#include "adns.h"       /* needs <resolv.h> */
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "rnd.h"
#include "state.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "fetch.h"
#include "timer.h"
#include "ipsecconf/confread.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h"     /* requires sha1.h and md5.h */
#include "vendor.h"
#include "pluto_crypt.h"

#include "virtual.h"	/* needs connections.h */

#include "nat_traversal.h"

#include "lswcrypto.h"

#ifndef IPSECDIR
#define IPSECDIR "/etc/ipsec.d"
#endif

#include <nss.h>
#include <nspr.h>

#include "fips.h"

#ifdef HAVE_LIBCAP_NG
# include <cap-ng.h>
#endif

#ifdef HAVE_LABELED_IPSEC
# include "security_selinux.h"
#endif

#ifdef USE_LINUX_AUDIT
# include <libaudit.h>
#endif

const char *ctlbase = "/var/run/pluto";
char *pluto_listen = NULL;
static bool fork_desired = TRUE;

/* used for 'ipsec status' */
static char *ipsecconf = NULL;
static char *ipsecdir = NULL;

libreswan_passert_fail_t libreswan_passert_fail = passert_fail;

/** usage - print help messages
 *
 * @param mess String - alternate message to print
 */
static void usage(const char *mess)
{
	if (mess != NULL && *mess != '\0')
		fprintf(stderr, "%s\n", mess);
	fprintf(stderr,
		"Usage: pluto"
		" [--help]"
		" [--version]"
		" \\\n\t"
		"[--config <filename>]"
		"[--vendorid <vendorid>]"
		" [--nofork]"
		" [--stderrlog]"
		" [--logfile <filename>]"
		" [--plutostderrlogtime]"
		" [--force_busy]"
		" [--nocrsend]"
		" [--strictcrlpolicy]"
		" [--crlcheckinterval]"
		" [--uniqueids]"
		" [--use-klips]"
		" [--use-netkey]"
		" [--use-mast]"
		" [--use-bsdkame]"
		" [--use-nostack]"     /* old --no_klips */
		" \\\n\t"
		"[--interface <ifname|ifaddr>]"
		" [--ikeport <port-number>]"
		" [--natikeport <port-number>]"
		"[--listen <ifaddr>]"
		" \\\n\t"
		"[--ctlbase <path>]"
		" \\\n\t"
		"[--perpeerlogbase <path>] [--perpeerlog]"
		" \\\n\t"
		"[--coredir <dirname>] [--noretransmits]"
		"[--statsbin <filename>]"
		" \\\n\t"
		"[--secretsfile <secrets-file>]"
		" [--ipsecdir <ipsec-dir>]"
		" \\\n\t"
		"[--adns <pathname>]"
		"[--nhelpers <number>]"
#ifdef HAVE_LABELED_IPSEC
		" \\\n\t"
		"[--secctx_attr_value <number>]"
#endif
		" \\\n\t"
		"[--debug-none]"
		" [--debug-all]"
		" \\\n\t"
		"[--debug-raw]"
		" [--debug-crypt]"
		" [--debug-crypto]"
		" [--debug-parsing]"
		" [--debug-emitting]"
		" \\\n\t"
		"[--debug-control]"
		"[--debug-lifecycle]"
		" [--debug-kernel]"
		" [--debug-x509]"
		" [--debug-dns]"
		" [--debug-oppo]"
		" [--debug-oppoinfo]"
		" [--debug-dpd]"
		" [ --debug-private]"
		" [ --debug-pfkey]"
		" [ --debug-nat-t]"
		" \\\n\t"
		"[--nat_traversal] [--keep_alive <delay_sec>]"
		" \\\n\t"
		"[--disable_port_floating]"
		" \\\n\t"
		"[--virtual_private <network_list>]"
		"\n"
		"Libreswan %s\n",
		ipsec_version_code());
	exit(mess == NULL ? 0 : 1); /* not exit_pluto because we are not initialized yet */
}

/* string naming compile-time options that have interop implications */
static const char compile_time_interop_options[] = ""
#ifdef NETKEY_SUPPORT
					    " XFRM(netkey)"
#endif
#ifdef KLIPS
					    " KLIPS"
#endif
#ifdef KLIPSMAST
					    " MAST"
#endif

#ifdef HAVE_NO_FORK
					    " NO_FORK"
#endif
#ifdef HAVE_BROKEN_POPEN
					    " BROKEN_POPEN"
#endif
#ifndef OPENSSL
					    " NSS"
#endif
#ifdef DNSSEC
					    " DNSSEC"
#endif
#ifdef FIPS_CHECK
					    " FIPS_CHECK"
#endif
#ifdef HAVE_LABELED_IPSEC
					    " LABELED_IPSEC"
#endif
#ifdef HAVE_LIBCAP_NG
					    " LIBCAP_NG"
#endif
#ifdef USE_LINUX_AUDIT
					    " LINUX_AUDIT"
#endif
#ifdef XAUTH_HAVE_PAM
					    " XAUTH_PAM"
#endif
#ifdef HAVE_NM
					    " NETWORKMANAGER"
#endif
#ifdef LEAK_DETECTIVE
					    " LEAK_DETECTIVE"
#endif
#ifdef HAVE_OCF
					    " OCF"
#endif
#ifdef KLIPS_MAST
					    " KLIPS_MAST"
#endif
#ifdef LIBCURL
					    " CURL(non-NSS)"
#endif
#ifdef LDAP_VER
					    " LDAP(non-NSS)"
#endif
;

/* lock file support
 * - provides convenient way for scripts to find Pluto's pid
 * - prevents multiple Plutos competing for the same port
 * - same basename as unix domain control socket
 * NOTE: will not take account of sharing LOCK_DIR with other systems.
 */

static char pluto_lock[sizeof(ctl_addr.sun_path)] =
	DEFAULT_CTLBASE LOCK_SUFFIX;
static bool pluto_lock_created = FALSE;

/** create lockfile, or die in the attempt */
static int create_lock(void)
{
	int fd;

	if (mkdir(ctlbase, 0755) != 0) {
		if (errno != EEXIST) {
			fprintf(stderr,
				"pluto: unable to create lock dir: \"%s\": %s\n",
				ctlbase, strerror(errno));
			exit_pluto(10);
		}
	}

	fd = open(pluto_lock, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
		  S_IRUSR | S_IRGRP | S_IROTH);

	if (fd < 0) {
		if (errno == EEXIST) {
			/* if we did not fork, then we do't really need the pid to control, so wipe it */
			if (!fork_desired) {
				if (unlink(pluto_lock) == -1) {
					fprintf(stderr,
						"pluto: lock file \"%s\" already exists and could not be removed (%d %s)\n",
						pluto_lock, errno,
						strerror(errno));
					exit_pluto(10);
				} else {
					/* lock file removed, try creating it again */
					return create_lock();
				}
			} else {
				fprintf(stderr,
					"pluto: lock file \"%s\" already exists\n",
					pluto_lock);
				exit_pluto(10);
			}
		} else {
			fprintf(stderr,
				"pluto: unable to create lock file \"%s\" (%d %s)\n",
				pluto_lock, errno, strerror(errno));
			exit_pluto(1);
		}
	}
	pluto_lock_created = TRUE;
	return fd;
}

/** fill_lock - Populate the lock file with pluto's PID
 *
 * @param lockfd File Descriptor for the lock file
 * @param pid PID (pid_t struct) to be put into the lock file
 * @return bool True if successful
 */
static bool fill_lock(int lockfd, pid_t pid)
{
	char buf[30];   /* holds "<pid>\n" */
	int len = snprintf(buf, sizeof(buf), "%u\n", (unsigned int) pid);
	bool ok = len > 0 && write(lockfd, buf, len) == len;

	close(lockfd);
	return ok;
}

/** delete_lock - Delete the lock file
 *
 */
static void delete_lock(void)
{
	if (pluto_lock_created) {
		delete_ctl_socket();
		unlink(pluto_lock); /* is noting failure useful? */
	}
}

/* parser.l and keywords.c need these global variables */
/* FIXME: move them to confread_load() parameters */
int verbose = 0;
int warningsarefatal = 0;

/** Read config file. exit() on error. */
static struct starter_config *read_cfg_file(char *configfile)
{
	struct starter_config *cfg = NULL;
	err_t err = NULL;

	cfg = confread_load(configfile, &err, FALSE, NULL, TRUE);
	if (cfg == NULL)
		usage(err);
	return cfg;
}

/** Helper function for config file mapper: set string option value */
static void set_cfg_string(char **target, char *value)
{
	/* Do nothing if value is unset. */
	if (value == NULL || *value == 0)
		return;

	/* Don't free previous target, it might be statically set. */
	*target = strdup(value);
}

static void pluto_init_nss(char *confddir)
{
	char buf[100];

	snprintf(buf, sizeof(buf), "%s", confddir);
	loglog(RC_LOG_SERIOUS, "nss directory plutomain: %s", buf);
	SECStatus nss_init_status = NSS_Init(buf);
	if (nss_init_status != SECSuccess) {
		loglog(RC_LOG_SERIOUS, "NSS readonly initialization failed (err %d)\n",
		       PR_GetError());
		exit_pluto(10);
	} else {
		libreswan_log("NSS Initialized");
		PK11_SetPasswordFunc(getNSSPassword);
	}
}

/** by default the CRL policy is lenient */
bool strict_crl_policy = FALSE;

/** by default pluto does not check crls dynamically */
long crl_check_interval = 0;

/** by default pluto sends no cookies in ikev2 or ikev1 aggrmode */
bool force_busy = FALSE;

/* whether or not to use klips */
enum kernel_interface kern_interface = USE_NETKEY; /* new default */

#ifdef HAVE_LABELED_IPSEC
u_int16_t secctx_attr_value = SECCTX;
#endif

/* pulled from main for show_setup_plutomain() */
static const struct lsw_conf_options *oco;
static char *coredir;
static char *pluto_vendorid;
static int nhelpers = -1;

int main(int argc, char **argv)
{
	int lockfd;

	/*
	 * We read the intentions for how to log from command line options
	 * and the config file. Then we prepare to be able to log, but until
	 * then log to stderr (better then nothing). Once we are ready to
	 * actually do loggin according to the methods desired, we set the
	 * variables for those methods
	 */
	bool log_to_stderr_desired = FALSE;
	bool log_to_file_desired = FALSE;

	coredir = NULL;

	/* set up initial defaults that need a cast */
	pluto_shared_secrets_file =
		DISCARD_CONST(char *, SHARED_SECRETS_FILE);

	/** Overridden by nat_traversal= in ipsec.conf */
	bool nat_traversal = FALSE;
	bool nat_t_spf = TRUE; /* support port floating */
	unsigned int keep_alive = 0;

	/** Overridden by virtual_private= in ipsec.conf */
	char *virtual_private = NULL;
#ifdef LEAK_DETECTIVE
	leak_detective = 1;
#else
	leak_detective = 0;
#endif

#ifdef HAVE_LIBCAP_NG
	/*
	 * Drop capabilities - this generates a false positive valgrind warning
	 * See: http://marc.info/?l=linux-security-module&m=125895232029657
	 */
	capng_clear(CAPNG_SELECT_BOTH);

	capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE | CAPNG_PERMITTED,
		      CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW,
		      CAP_IPC_LOCK, CAP_AUDIT_WRITE,
		      CAP_SETGID, CAP_SETUID, /* for google authenticator pam */
		      -1);
	/* our children must be able to CAP_NET_ADMIN to change routes.
	 */
	capng_updatev(CAPNG_ADD, CAPNG_BOUNDING_SET, CAP_NET_ADMIN, CAP_DAC_READ_SEARCH, -1); /* DAC needed for google authenticator pam */
	capng_apply(CAPNG_SELECT_BOTH);
#endif

	libreswan_passert_fail = passert_fail;

	if (getenv("PLUTO_WAIT_FOR_GDB"))
		sleep(120);

	/* handle arguments */
	for (;; ) {
#       define DBG_OFFSET 256
		static const struct option long_opts[] = {
			/* name, has_arg, flag, val */
			{ "help", no_argument, NULL, 'h' },
			{ "version", no_argument, NULL, 'v' },
			{ "config", required_argument, NULL, 'z' },
			{ "nofork", no_argument, NULL, 'd' },
			{ "stderrlog", no_argument, NULL, 'e' },
			{ "logfile", required_argument, NULL, 'g' },
			{ "plutostderrlogtime", no_argument, NULL, 't' },
			{ "noklips", no_argument, NULL, 'n' },
			{ "use-nostack",  no_argument, NULL, 'n' },
			{ "use-none",     no_argument, NULL, 'n' },
			{ "force_busy", no_argument, NULL, 'D' },
			{ "strictcrlpolicy", no_argument, NULL, 'r' },
			{ "crlcheckinterval", required_argument, NULL, 'x' },
			{ "uniqueids", no_argument, NULL, 'u' },
			{ "useklips",  no_argument, NULL, 'k' },
			{ "use-klips",  no_argument, NULL, 'k' },
			{ "use-auto",  no_argument, NULL, 'G' },
			{ "usenetkey", no_argument, NULL, 'K' },
			{ "use-netkey", no_argument, NULL, 'K' },
			{ "use-mast",   no_argument, NULL, 'M' },
			{ "use-mastklips",   no_argument, NULL, 'M' },
			{ "use-bsdkame",   no_argument, NULL, 'F' },
			{ "interface", required_argument, NULL, 'i' },
			{ "listen", required_argument, NULL, 'L' },
			{ "ikeport", required_argument, NULL, 'p' },
			{ "natikeport", required_argument, NULL, 'q' },
			{ "ctlbase", required_argument, NULL, 'b' },
			{ "secretsfile", required_argument, NULL, 's' },
			{ "perpeerlogbase", required_argument, NULL, 'P' },
			{ "perpeerlog", no_argument, NULL, 'l' },
			{ "noretransmits", no_argument, NULL, 'R' },
			{ "coredir", required_argument, NULL, 'C' },
			{ "dumpdir", required_argument, NULL, 'C' }, /* alias for coredir */
			{ "statsbin", required_argument, NULL, 'S' },
			{ "ipsecdir", required_argument, NULL, 'f' },
			{ "ipsec_dir", required_argument, NULL, 'f' },
			{ "foodgroupsdir", required_argument, NULL, 'f' },
			{ "adns", required_argument, NULL, 'a' },
			{ "nat_traversal", no_argument, NULL, '1' },
			{ "keep_alive", required_argument, NULL, '2' },
			{ "force_keepalive", no_argument, NULL, '3' }, /* obsolete, ignored */
			{ "disable_port_floating", no_argument, NULL, '4' },
			{ "debug-nat_t", no_argument, NULL, '5' },
			{ "debug-nattraversal", no_argument, NULL, '5' },
			{ "debug-nat-t", no_argument, NULL, '5' },
			{ "virtual_private", required_argument, NULL, '6' },
			{ "nhelpers", required_argument, NULL, 'j' },
#ifdef HAVE_LABELED_IPSEC
			{ "secctx_attr_value", required_argument, NULL, 'w' },
#endif
			{ "debug-none", no_argument, NULL, 'N' },
			{ "debug-all", no_argument, NULL, 'A' },

			{ "debug-raw", no_argument, NULL, DBG_RAW_IX +
			  DBG_OFFSET },
			{ "debug-crypt", no_argument, NULL, DBG_CRYPT_IX +
			  DBG_OFFSET },
			{ "debug-crypto", no_argument, NULL, DBG_CRYPT_IX +
			  DBG_OFFSET },
			{ "debug-parsing", no_argument, NULL, DBG_PARSING_IX +
			  DBG_OFFSET },
			{ "debug-emitting", no_argument, NULL, DBG_EMITTING_IX +
			  DBG_OFFSET },
			{ "debug-control", no_argument, NULL, DBG_CONTROL_IX +
			  DBG_OFFSET },
			{ "debug-lifecycle", no_argument, NULL, DBG_LIFECYCLE_IX +
			  DBG_OFFSET },
			{ "debug-kernel", no_argument, NULL, DBG_KERNEL_IX +
			  DBG_OFFSET },
			{ "debug-dns", no_argument, NULL, DBG_DNS_IX +
			  DBG_OFFSET },
			{ "debug-oppo", no_argument, NULL, DBG_OPPO_IX +
			  DBG_OFFSET },
			{ "debug-oppoinfo", no_argument, NULL, DBG_OPPOINFO_IX +
			  DBG_OFFSET },
			{ "debug-controlmore", no_argument, NULL,
			  DBG_CONTROLMORE_IX + DBG_OFFSET },
			{ "debug-dpd", no_argument, NULL, DBG_DPD_IX +
			  DBG_OFFSET },
			{ "debug-x509", no_argument, NULL, DBG_X509_IX +
			  DBG_OFFSET },
			{ "debug-private", no_argument, NULL, DBG_PRIVATE_IX +
			  DBG_OFFSET },
			{ "debug-pfkey", no_argument, NULL, DBG_PFKEY_IX +
			  DBG_OFFSET },

			/* for backwards compatibility */
			{ "debug-klips", no_argument, NULL, DBG_KERNEL_IX +
			  DBG_OFFSET },
			{ "debug-netkey", no_argument, NULL, DBG_KERNEL_IX +
			  DBG_OFFSET },

			{ "impair-delay-adns-key-answer", no_argument, NULL,
			  IMPAIR_DELAY_ADNS_KEY_ANSWER_IX + DBG_OFFSET },
			{ "impair-delay-adns-txt-answer", no_argument, NULL,
			  IMPAIR_DELAY_ADNS_TXT_ANSWER_IX + DBG_OFFSET },
			{ "impair-bust-mi2", no_argument, NULL,
			  IMPAIR_BUST_MI2_IX + DBG_OFFSET },
			{ "impair-bust-mr2", no_argument, NULL,
			  IMPAIR_BUST_MR2_IX + DBG_OFFSET },
			{ "impair-sa-creation", no_argument, NULL,
			  IMPAIR_SA_CREATION_IX + DBG_OFFSET },
			{ "impair-die-oninfo", no_argument, NULL,
			  IMPAIR_DIE_ONINFO_IX + DBG_OFFSET },
			{ "impair-jacob-two-two", no_argument, NULL,
			  IMPAIR_JACOB_TWO_TWO_IX + DBG_OFFSET },
			{ "impair-major-version-bump", no_argument, NULL,
			  IMPAIR_MAJOR_VERSION_BUMP_IX + DBG_OFFSET },
			{ "impair-minor-version-bump", no_argument, NULL,
			  IMPAIR_MINOR_VERSION_BUMP_IX + DBG_OFFSET },
			{ "impair-retransmits", no_argument, NULL,
			  IMPAIR_RETRANSMITS_IX + DBG_OFFSET },
			{ "impair-send-bogus-isakmp-flag", no_argument, NULL,
			  IMPAIR_SEND_BOGUS_ISAKMP_FLAG_IX + DBG_OFFSET },
			{ "impair-send-ikev2-ke", no_argument, NULL,
			  IMPAIR_SEND_IKEv2_KE_IX + DBG_OFFSET },
			{ 0, 0, 0, 0 }
		};
		/* Note: we don't like the way short options get parsed
		 * by getopt_long, so we simply pass an empty string as
		 * the list.  It could be "hvdenp:l:s:" "NARXPECK".
		 */
		int c = getopt_long(argc, argv, "", long_opts, NULL);

		/** Note: "breaking" from case terminates loop */
		switch (c) {
		case EOF: /* end of flags */
			break;

		case 0: /* long option already handled */
			continue;

		case ':':       /* diagnostic already printed by getopt_long */
		case '?':       /* diagnostic already printed by getopt_long */
			usage("");
			break;  /* not actually reached */

		case 'h':       /* --help */
			usage(NULL);
			break;  /* not actually reached */

		case 'C': /* --coredir */
			coredir = clone_str(optarg, "coredir");
			continue;

		case 'S': /* --statsdir */
			pluto_stats_binary = clone_str(optarg, "statsbin");
			continue;

		case 'v': /* --version */
			printf("%s%s\n", ipsec_version_string(),
			       compile_time_interop_options);
			exit(0);        /* not exit_pluto because we are not initialized yet */
			break;          /* not actually reached */

		case 'j':               /* --nhelpers */
			if (optarg == NULL || !isdigit(optarg[0]))
				usage("missing number of pluto helpers");

			{
				char *endptr;
				long count = strtol(optarg, &endptr, 0);

				if (*endptr != '\0' || endptr == optarg ||
				    count < -1)
					usage("<nhelpers> must be a positive number, 0 or -1");


				nhelpers = count;
			}
			continue;

#ifdef HAVE_LABELED_IPSEC
		case 'w': /* --secctx_attr_value*/
			if (optarg == NULL || !isdigit(optarg[0]))
				usage("missing (positive integer) value of secctx_attr_value (needed only if using labeled ipsec)");


			{
				char *endptr;
				long value = strtol(optarg, &endptr, 0);

				if (*endptr != '\0' || endptr == optarg ||
				    (value != SECCTX && value != 10) )
					usage("<secctx_attr_value> must be a positive number (32001 by default, 10 for backward compatibility, or any other future number assigned by IANA)");


				secctx_attr_value = (u_int16_t)value;
			}
			continue;
#endif

		case 'd': /* --nofork*/
			fork_desired = FALSE;
			continue;

		case 'e': /* --stderrlog */
			log_to_stderr_desired = TRUE;
			continue;

		case 'g': /* --logfile */
			pluto_log_file = optarg;
			log_to_file_desired = TRUE;
			continue;

		case 't': /* --plutostderrlogtime */
			log_with_timestamp = TRUE;
			continue;

		case 'G': /* --use-auto */
			libreswan_log(
				"The option --use-auto is obsoleted, falling back to  --use-netkey\n");
			kern_interface = USE_NETKEY;
			continue;

		case 'k': /* --use-klips */
			kern_interface = USE_KLIPS;
			continue;

		case 'L': /* --listen ip_addr */
		{
			ip_address lip;
			err_t e = ttoaddr(optarg, 0, 0, &lip);

			if (e) {
				libreswan_log(
					"invalid listen argument ignored: %s\n",
					e);
			} else {
				pluto_listen =
					clone_str(optarg, "pluto_listen");
				libreswan_log(
					"bind() will be filtered for %s\n",
					pluto_listen);
			}
		}
			continue;

		case 'M': /* --use-mast */
			kern_interface = USE_MASTKLIPS;
			continue;

		case 'F': /* --use-bsdkame */
			kern_interface = USE_BSDKAME;
			continue;

		case 'K': /* --use-netkey */
			kern_interface = USE_NETKEY;
			continue;

		case 'n': /* --use-nostack */
			kern_interface = NO_KERNEL;
			continue;

		case 'D': /* --force_busy */
			force_busy = TRUE;
			continue;

		case 'r': /* --strictcrlpolicy */
			strict_crl_policy = TRUE;
			continue;

		case 'R':
			no_retransmits = TRUE;
			continue;

		case 'x': /* --crlcheckinterval <time>*/
			if (optarg == NULL || !isdigit(optarg[0]))
				usage("missing interval time");

			{
				char *endptr;
				long interval = strtol(optarg, &endptr, 0);

				if (*endptr != '\0' || endptr == optarg ||
				    interval <= 0)
					usage("<interval-time> must be a positive number");


				crl_check_interval = interval;
			}
			continue;

		case 'u': /* --uniqueids */
			uniqueIDs = TRUE;
			continue;

		case 'i': /* --interface <ifname|ifaddr> */
			if (!use_interface(optarg))
				usage("too many --interface specifications");
			continue;

		/*
		 * This option does not really work, as this is the "left"
		 * site only, you also need --to --ikeport again later on
		 * It will result in: yourport -> 500, still not bypassing filters
		 */
		case 'p': /* --ikeport <portnumber> */
			if (optarg == NULL || !isdigit(optarg[0]))
				usage("missing port number");
			{
				char *endptr;
				long port = strtol(optarg, &endptr, 0);

				if (*endptr != '\0' || endptr == optarg ||
				    port <= 0 || port > 0x10000)
					usage("<port-number> must be a number between 1 and 65535");


				pluto_port = port;
			}
			continue;

		case 'q': /* --natikeport <portnumber> */
			if (optarg == NULL || !isdigit(optarg[0]))
				usage("missing port number");
			{
				char *endptr;
				long port = strtol(optarg, &endptr, 0);

				if (*endptr != '\0' || endptr == optarg ||
				    port <= 0 || port > 0x10000)
					usage("<port-number> must be a number between 1 and 65535");


				pluto_natt_float_port = port;
			}
			continue;

		case 'b': /* --ctlbase <path> */
			ctlbase = optarg;
			if (snprintf(ctl_addr.sun_path,
				     sizeof(ctl_addr.sun_path),
				     "%s%s", ctlbase, CTL_SUFFIX) == -1)
				usage("<path>" CTL_SUFFIX " too long for sun_path");


			if (snprintf(info_addr.sun_path,
				     sizeof(info_addr.sun_path),
				     "%s%s", ctlbase, INFO_SUFFIX) == -1)
				usage("<path>" INFO_SUFFIX " too long for sun_path");


			if (snprintf(pluto_lock, sizeof(pluto_lock),
				     "%s%s", ctlbase, LOCK_SUFFIX) == -1)
				usage("<path>" LOCK_SUFFIX " must fit");
			continue;

		case 's': /* --secretsfile <secrets-file> */
			pluto_shared_secrets_file = optarg;
			continue;

		case 'f': /* --ipsecdir <ipsec-dir> */
			(void)lsw_init_ipsecdir(optarg);
			/* Keep a copy of the filename so we can show it in ipsec status */
			ipsecdir = clone_str(optarg, "ipsecdir filename");
			continue;

		case 'a': /* --adns <pathname> */
			pluto_adns_option = optarg;
			continue;

		case 'N': /* --debug-none */
			base_debugging = DBG_NONE;
			continue;

		case 'A': /* --debug-all */
			base_debugging = DBG_ALL;
			continue;

		case 'P': /* --perpeerlogbase */
			base_perpeer_logdir = optarg;
			continue;

		case 'l':
			log_to_perpeer = TRUE;
			continue;

		case '1': /* --nat_traversal */
			nat_traversal = TRUE;
			continue;
		case '2': /* --keep_alive */
			keep_alive = atoi(optarg);
			continue;
		case '3': /* --force_keepalive has been obsoleted */
			libreswan_log(
				"Ignored obsoleted option --force_keepalive");
			continue;
		case '4': /* --disable_port_floating */
			nat_t_spf = FALSE;
			continue;
		case '5': /* --debug-nat_t */
			base_debugging |= DBG_NATT;
			continue;
		case '6': /* --virtual_private */
			virtual_private = optarg;
			continue;

		case 'z': /* --config */
		{
			/* Keep a copy of the filename so we can show it in ipsec status */
			ipsecconf = clone_str(optarg, "ipsecconf filename");

			/* Config struct to variables mapper. This will overwrite
			 * all previously set options. Keep this in the same order as
			 * long_opts[] is.
			 */
			struct starter_config *cfg = read_cfg_file(optarg);

			set_cfg_string(&pluto_log_file,
				       cfg->setup.strings[KSF_PLUTOSTDERRLOG]);

			fork_desired = cfg->setup.options[KBF_PLUTOFORK]; /* plutofork= */
			log_with_timestamp =
				cfg->setup.options[KBF_PLUTOSTDERRLOGTIME];
			force_busy = cfg->setup.options[KBF_FORCEBUSY];
			strict_crl_policy =
				cfg->setup.options[KBF_STRICTCRLPOLICY];
			crl_check_interval =
				cfg->setup.options[KBF_CRLCHECKINTERVAL];
			uniqueIDs = cfg->setup.options[KBF_UNIQUEIDS];
			/*
			 * We don't check interfaces= here because that part has been dealt
			 * with in _stackmanager before we started
			 */

			set_cfg_string(&pluto_listen,
				       cfg->setup.strings[KSF_LISTEN]);

			pluto_port = cfg->setup.options[KBF_IKEPORT]; /* --ikeport */
			/* no config option: ctlbase */
			set_cfg_string(&pluto_shared_secrets_file,
				       cfg->setup.strings[KSF_SECRETSFILE]);                 /* --secrets */
			if (cfg->setup.strings[KSF_IPSECDIR] != NULL &&
			    *cfg->setup.strings[KSF_IPSECDIR] != 0) {
				lsw_init_ipsecdir(cfg->setup.strings[KSF_IPSECDIR]);       /* --ipsecdir */
				/* Keep a copy of the filename so we can show it in ipsec status */
				ipsecdir = alloc_bytes(strlen(cfg->setup.strings[KSF_IPSECDIR])+1,
							"ipsecdir filename");
				strncpy(ipsecdir,cfg->setup.strings[KSF_IPSECDIR],
					strlen(cfg->setup.strings[KSF_IPSECDIR]));
				}
			set_cfg_string(&base_perpeer_logdir,
				       cfg->setup.strings[KSF_PERPEERDIR]);     /* --perpeerlogbase */
			log_to_perpeer = cfg->setup.options[KBF_PERPEERLOG];    /* --perpeerlog */
			no_retransmits = !cfg->setup.options[KBF_RETRANSMITS];  /* --noretransmits */
			set_cfg_string(&coredir, cfg->setup.strings[KSF_DUMPDIR]); /* --dumpdir */
			set_cfg_string(&pluto_vendorid, cfg->setup.strings[KSF_MYVENDORID]); /* --vendorid */
			/* no config option: pluto_adns_option */

			if (cfg->setup.strings[KSF_STATSBINARY] != NULL) {
				set_cfg_string(&pluto_stats_binary, /* --statsbinary */
					       cfg->setup.strings[KSF_STATSBINARY]);
				if (access(pluto_stats_binary, X_OK) == 0) {
					libreswan_log("statsbinary set to %s", pluto_stats_binary);
				} else {
					libreswan_log("statsbinary '%s' ignored - file does not exist or is not executable",
						      pluto_stats_binary);
					pluto_stats_binary = NULL;
				}
			}

			pluto_natt_float_port =
				cfg->setup.options[KBF_NATIKEPORT];
			nat_traversal = cfg->setup.options[KBF_NATTRAVERSAL];
			keep_alive = cfg->setup.options[KBF_KEEPALIVE];
			nat_t_spf =
				!cfg->setup.options[KBF_DISABLEPORTFLOATING];

			set_cfg_string(&virtual_private,
				       cfg->setup.strings[KSF_VIRTUALPRIVATE]);

			nhelpers = cfg->setup.options[KBF_NHELPERS];
#ifdef HAVE_LABELED_IPSEC
			secctx_attr_value = cfg->setup.options[KBF_SECCTX];
#endif
			base_debugging = cfg->setup.options[KBF_PLUTODEBUG];
			char *protostack = cfg->setup.strings[KSF_PROTOSTACK];
			if (protostack == NULL || *protostack == 0) {
				kern_interface = USE_NETKEY;
			} else if (streq(protostack, "none")) {
				kern_interface = NO_KERNEL;
			} else if (streq(protostack, "auto")) {
				libreswan_log(
					"The option protostack=auto is obsoleted, falling back to protostack=netkey\n");
				kern_interface = USE_NETKEY;
			} else if (streq(protostack, "klips")) {
				kern_interface = USE_KLIPS;
			} else if (streq(protostack, "mast")) {
				kern_interface = USE_MASTKLIPS;
			} else if (streq(protostack, "netkey") ||
				   streq(protostack, "native")) {
				kern_interface = USE_NETKEY;
			} else if (streq(protostack, "bsd") ||
				   streq(protostack, "kame") ||
				   streq(protostack, "bsdkame")) {
				kern_interface = USE_BSDKAME;
			} else if (streq(protostack, "win2k")) {
				kern_interface = USE_WIN2K;
			}

			confread_free(cfg);
			continue;
		}

		default:
			if (DBG_OFFSET <= c && c < DBG_OFFSET + IMPAIR_roof_IX) {
				base_debugging |= LELEM(c - DBG_OFFSET);
				continue;
			}
#       undef DBG_OFFSET
			bad_case(c);
		}
		break;
	}
	if (optind != argc)
		usage("unexpected argument");
	reset_debugging();

#ifdef HAVE_NO_FORK
	fork_desired = FALSE;
	nhelpers = 0;
#endif

	/* default coredir to location compatible with SElinux */
	if (!coredir)
		coredir = clone_str("/var/run/pluto", "coredir");
	if (chdir(coredir) == -1) {
		int e = errno;
		libreswan_log("pluto: chdir() do dumpdir failed (%d: %s)\n",
			      e, strerror(e));
	}

	oco = lsw_init_options();
	lockfd = create_lock();

	/* select between logging methods */

	if (log_to_stderr_desired || log_to_file_desired)
		log_to_syslog = FALSE;
	if (!log_to_stderr_desired)
		log_to_stderr = FALSE;

#if 0
	if (kernel_ops->set_debug)
		(*kernel_ops->set_debug)(cur_debugging, DBG_log, DBG_log);

#endif

	/** create control socket.
	 * We must create it before the parent process returns so that
	 * there will be no race condition in using it.  The easiest
	 * place to do this is before the daemon fork.
	 */
	{
		err_t ugh = init_ctl_socket();

		if (ugh != NULL) {
			fprintf(stderr, "pluto: %s", ugh);
			exit_pluto(1);
		}
	}

	/* If not suppressed, do daemon fork */

	if (fork_desired) {
		{
			pid_t pid = fork();

			if (pid < 0) {
				int e = errno;

				fprintf(stderr, "pluto: fork failed (%d %s)\n",
					errno, strerror(e));
				exit_pluto(1);
			}

			if (pid != 0) {
				/* parent: die, after filling PID into lock file.
				 * must not use exit_pluto: lock would be removed!
				 */
				exit(fill_lock(lockfd, pid) ? 0 : 1);
			}
		}

		if (setsid() < 0) {
			int e = errno;

			fprintf(stderr,
				"setsid() failed in main(). Errno %d: %s\n",
				errno, strerror(e));
			exit_pluto(1);
		}
	} else {
		/* no daemon fork: we have to fill in lock file */
		(void) fill_lock(lockfd, getpid());
		if (isatty(fileno(stdout))) {
			fprintf(stdout, "Pluto initialized\n");
			fflush(stdout);
		}
	}

	/** Close everything but ctl_fd and (if needed) stderr.
	 * There is some danger that a library that we don't know
	 * about is using some fd that we don't know about.
	 * I guess we'll soon find out.
	 */
	{
		int i;

		for (i = getdtablesize() - 1; i >= 0; i--) /* Bad hack */
			if ((!log_to_stderr || i != 2) &&
			    i != ctl_fd)
				close(i);

		/* make sure that stdin, stdout, stderr are reserved */
		if (open("/dev/null", O_RDONLY) != 0)
			lsw_abort();
		if (dup2(0, 1) != 1)
			lsw_abort();
		if (!log_to_stderr && dup2(0, 2) != 2)

			lsw_abort();
	}

	init_constants();
	pluto_init_log();
	pluto_init_nss(oco->confddir);

#ifdef FIPS_CHECK
	/*
	 * FIPS Kernel mode: fips=1 kernel boot parameter
	 * FIPS Product mode: dracut-fips is installed
	 *
	 * When FIPS Product mode and FIPS Kernel mode, abort on hmac failure.
	 * Otherwise, just complain about failures.
	 *
	 * Product Mode detected with FIPSPRODUCTCHECK in Makefile.inc
	 */

	{

	int fips_kernel = libreswan_fipskernel();
	int fips_product = libreswan_fipsproduct();
	int fips_mode = libreswan_fipsmode();
	int fips_files_check_ok = FIPSCHECK_verify_files(fips_package_files);

	if (fips_mode == -1) {
                        loglog(RC_LOG_SERIOUS, "ABORT: FIPS mode could not be determined");
                        exit_pluto(10);
	}

	if (fips_product == 1)
		libreswan_log("FIPS Product detected (%s)", FIPSPRODUCTCHECK);

	if (fips_kernel == 1)
		libreswan_log("FIPS Kernel Mode detected");

	if (!fips_files_check_ok) {
		loglog(RC_LOG_SERIOUS, "FIPS HMAC integrity verification FAILURE");
		/*
		 * We ignore fips=1 kernel mode if we are not a 'fips product'
		 */
                if (fips_product && fips_kernel) {
                        loglog(RC_LOG_SERIOUS, "ABORT: FIPS product and kernel in FIPS mode");
                        exit_pluto(10);
                } else if (fips_product) {
                        libreswan_log("FIPS: FIPS product but kernel mode disabled - continuing");
                } else if (fips_kernel) {
                        libreswan_log("FIPS: not a FIPS product, kernel mode ignored - continuing");
                } else {
                        libreswan_log("FIPS: not a FIPS product and kernel not in FIPS mode - continuing");
		}
	} else {
		libreswan_log("FIPS HMAC integrity verification test passed");
	}

	if (fips_mode) {
		libreswan_log("FIPS: pluto daemon running in FIPS mode");
	} else {
		libreswan_log("FIPS: pluto daemon NOT running in FIPS mode");
	}

	}
#else
	libreswan_log("FIPS HMAC integrity support [disabled]");
#endif

#ifdef HAVE_LIBCAP_NG
	libreswan_log("libcap-ng support [enabled]");
#else
	libreswan_log("libcap-ng support [disabled]");
#endif

#ifdef USE_LINUX_AUDIT
	libreswan_log("Linux audit support [enabled]");
	/* test and log if audit is enabled on the system */
	int audit_fd, rc;
	audit_fd = audit_open();
	if (audit_fd < 0) {
		if (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT) {
			loglog(RC_LOG_SERIOUS,
			       "Warning: kernel has no audit support");
		} else {
			loglog(RC_LOG_SERIOUS,
			       "FATAL (SOON): audit_open() failed : %s", strerror(
				       errno));
			/* temp disabled exit_pluto(10); */
		}
	}
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_START, NULL,
				    "starting pluto daemon", NULL, -1, NULL,
				    NULL, NULL, 1);
	close(audit_fd);
	if (rc < 0) {
		loglog(RC_LOG_SERIOUS,
		       "FATAL: audit_log_acct_message failed: %s",
		       strerror(errno));
		exit_pluto(10);
	}
#else
	libreswan_log("Linux audit support [disabled]");
#endif

	{
		const char *vc = ipsec_version_code();
		libreswan_log("Starting Pluto (Libreswan Version %s%s) pid:%u",
			      vc, compile_time_interop_options, getpid());

		if (vc[2] == 'g' && vc[3] == 'i' && vc[4] == 't') {
			/*
			 * when people build RPMs from GIT, make sure they
			 * get blamed appropriately, and that we get some way
			 * to identify who did it, and when they did it.
			 */
			libreswan_log(
				"@(#) built on "__DATE__
				":" __TIME__ " by " BUILDER);
		}
	}

	if (coredir)
		libreswan_log("core dump dir: %s", coredir);
	if (pluto_shared_secrets_file)
		libreswan_log("secrets file: %s", pluto_shared_secrets_file);

#ifdef LEAK_DETECTIVE
	libreswan_log("LEAK_DETECTIVE support [enabled]");
#else
	libreswan_log("LEAK_DETECTIVE support [disabled]");
#endif

#ifdef HAVE_OCF
	if (access("/dev/crypto", R_OK | W_OK) != -1)
		libreswan_log("OCF support for IKE via /dev/crypto [enabled]");
	else
		libreswan_log("OCF support for IKE via /dev/crypto [failed:%s]",
				strerror(errno));
#else
	libreswan_log("OCF support for IKE [disabled]");
#endif

	/* Check for SAREF support */
#ifdef KLIPS_MAST
#include <ipsec_saref.h>
	{
		int e, sk, saref;
		saref = 1;
		errno = 0;

		sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		e = setsockopt(sk, IPPROTO_IP, IP_IPSEC_REFINFO, &saref,
			       sizeof(saref));
		if (e == -1 )
			libreswan_log("SAref support [disabled]: %s",
				      strerror(errno));
		else
			libreswan_log("SAref support [enabled]");
		errno = 0;
		e = setsockopt(sk, IPPROTO_IP, IP_IPSEC_BINDREF, &saref,
			       sizeof(saref));
		if (e == -1 )
			libreswan_log("SAbind support [disabled]: %s", strerror(
					      errno));
		else
			libreswan_log("SAbind support [enabled]");

		close(sk);
	}
#endif

	libreswan_log("NSS crypto [enabled]");

#ifdef XAUTH_HAVE_PAM
	libreswan_log("XAUTH PAM support [enabled]");
#else
	libreswan_log("XAUTH PAM support [disabled]");
#endif

/** Log various impair-* functions if they were enabled */

	if (DBGP(IMPAIR_BUST_MI2))
		libreswan_log("Warning: IMPAIR_BUST_MI2 enabled");
	if (DBGP(IMPAIR_BUST_MR2))
		libreswan_log("Warning: IMPAIR_BUST_MR2 enabled");
	if (DBGP(IMPAIR_SA_CREATION))
		libreswan_log("Warning: IMPAIR_SA_CREATION enabled");
	if (DBGP(IMPAIR_JACOB_TWO_TWO))
		libreswan_log("Warning: IMPAIR_JACOB_TWO_TWO enabled");
	if (DBGP(IMPAIR_DIE_ONINFO))
		libreswan_log("Warning: IMPAIR_DIE_ONINFO enabled");
	if (DBGP(IMPAIR_MAJOR_VERSION_BUMP))
		libreswan_log("Warning: IMPAIR_MAJOR_VERSION_BUMP enabled");
	if (DBGP(IMPAIR_MINOR_VERSION_BUMP))
		libreswan_log("Warning: IMPAIR_MINOR_VERSION_BUMP enabled");
	if (DBGP(IMPAIR_RETRANSMITS))
		libreswan_log("Warning: IMPAIR_RETRANSMITS enabled");
	if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG))
		libreswan_log("Warning: IMPAIR_SEND_BOGUS_ISAKMP_FLAG enabled");
	if (DBGP(IMPAIR_SEND_IKEv2_KE))
		libreswan_log("Warning: IMPAIR_SEND_IKEv2_KE enabled");


	if (DBGP(IMPAIR_DELAY_ADNS_KEY_ANSWER))
		libreswan_log("Warning: IMPAIR_DELAY_ADNS_KEY_ANSWER enabled");


	if (DBGP(IMPAIR_DELAY_ADNS_TXT_ANSWER))
		libreswan_log("Warning: IMPAIR_DELAY_ADNS_TXT_ANSWER enabled");


/** Initialize all of the various features */

	init_nat_traversal(nat_traversal, keep_alive, nat_t_spf);

	init_virtual_ip(virtual_private);
	/* obsoletd by nss code init_rnd_pool(); */
	init_timer();
	init_secret();
	init_states();
	init_connections();
	init_crypto();
	init_crypto_helpers(nhelpers);
	load_lswcrypto();
	init_demux();
	init_kernel();
	init_adns();
	init_id();
	init_vendorid();

#if defined(LIBCURL) || defined(LDAP_VER)
	init_fetch();
#endif

	/* loading X.509 CA certificates from disk (/etc/ipsec.d/cacerts/) */
	load_authcerts("CA cert", oco->cacerts_dir, AUTH_CA);

#if 0
	/* unused */
	/* loading X.509 AA certificates */
	load_authcerts("AA cert", oco->aacerts_dir, AUTH_AA);
#endif

	/*Loading CA certs from NSS DB*/
	load_authcerts_from_nss("CA cert",  AUTH_CA);

	/* loading X.509 CRLs - must happen after CAs are loaded */
	load_crls();
	/* loading attribute certificates from disk (should prob be removed) */
	load_acerts();

#ifdef HAVE_LABELED_IPSEC
	init_avc();
#endif

	daily_log_event();
	call_server();
	return -1; /* Shouldn't ever reach this */
}

/* leave pluto, with status.
 * Once child is launched, parent must not exit this way because
 * the lock would be released.
 *
 *  0 OK
 *  1 general discomfort
 * 10 lock file exists
 */
void exit_pluto(int status)
{
	reset_globals(); /* needed because we may be called in odd state */
	free_preshared_secrets();
	free_remembered_public_keys();
	delete_every_connection();

	/* free memory allocated by initialization routines.  Please don't
	   forget to do this. */

#if defined(LIBCURL) || defined(LDAP_VER)
	free_crl_fetch();       /* free chain of crl fetch requests */
#endif
	free_authcerts();       /* free chain of X.509 authority certificates */
	free_crls();            /* free chain of X.509 CRLs */
	free_acerts();          /* free chain of X.509 attribute certificates */

	lsw_conf_free_oco();    /* free global_oco containing path names */

	free_myFQDN();          /* free myid FQDN */

	free_ifaces();          /* free interface list from memory */
	stop_adns();            /* Stop async DNS process (if running) */
	free_md_pool();         /* free the md pool */
	NSS_Shutdown();
	delete_lock();          /* delete any lock files */
#ifdef LEAK_DETECTIVE
	report_leaks();         /* report memory leaks now, after all free()s */
#endif /* LEAK_DETECTIVE */
	close_log();            /* close the logfiles */
	exit(status);           /* exit, with our error code */
}

void show_setup_plutomain()
{
	whack_log(RC_COMMENT, "config setup options:");     /* spacer */
	whack_log(RC_COMMENT, " ");     /* spacer */
        whack_log(RC_COMMENT, "configdir=%s, configfile=%s, secrets=%s, ipsecdir=%s, "
		  "dumpdir=%s, statsbin=%s",
		oco->confdir,
		oco->conffile,
		pluto_shared_secrets_file,
		oco->confddir,
		coredir,
		pluto_stats_binary ? pluto_stats_binary : "unset");

	whack_log(RC_COMMENT, "sbindir=%s, libdir=%s, libexecdir=%s",
		IPSEC_SBINDIR ,
		IPSEC_LIBDIR ,
		IPSEC_EXECDIR );

	whack_log(RC_COMMENT, "pluto_version=%s, pluto_vendorid=%s",
		ipsec_version_code(),
		ipsec_version_vendorid());

        whack_log(RC_COMMENT, "nhelpers=%d, uniqueids=%s, retransmits=%s, force_busy=%s",
		nhelpers,
		uniqueIDs ? "yes" : "no",
		no_retransmits ? "no" : "yes",
		force_busy ? "yes" : "no");

        whack_log(RC_COMMENT, "ikeport=%d, strictcrlpolicy=%s, crlcheckinterval=%lu, listen=%s",
		pluto_port,
		strict_crl_policy ? "yes" : "no",
		crl_check_interval,
		pluto_listen ? pluto_listen : "<any>");

#ifdef HAVE_LABELED_IPSEC
        whack_log(RC_COMMENT, "secctx_attr_value=%d", secctx_attr_value);
#else
        whack_log(RC_COMMENT, "secctx_attr_value=<unsupported>");
#endif
}

