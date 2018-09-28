/*
 * Pluto main program
 *
 * Copyright (C) 1997      Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2016 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2016 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2016, 2018 Andrew Cagney
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

#include <pthread.h> /* Must be the first include file */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>	/* for unlink(), write(), close(), access(), et.al. */

#include "lswconf.h"
#include "lswfips.h"
#include "lswnss.h"
#include "defs.h"
#include "nss_ocsp.h"
#include "server.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "peerlog.h"
#include "keys.h"
#include "secrets.h"    /* for free_remembered_public_keys() */
#include "rnd.h"
#include "fetch.h"
#include "ipsecconf/confread.h"
#include "crypto.h"
#include "vendor.h"
#include "pluto_crypt.h"
#include "enum_names.h"
#include "virtual.h"	/* needs connections.h */
#include "state_db.h"	/* for init_state_db() */
#include "nat_traversal.h"
#include "ike_alg.h"

#ifndef IPSECDIR
#define IPSECDIR "/etc/ipsec.d"
#endif

#ifdef HAVE_LIBCAP_NG
# include <cap-ng.h>	/* from libcap-ng devel */
#endif

#ifdef HAVE_LABELED_IPSEC
# include "security_selinux.h"
#endif

# include "pluto_sd.h"

#ifdef USE_DNSSEC
#include "dnssec.h"
#endif

static const char *pluto_name;	/* name (path) we were invoked with */

static pthread_t main_thread;

bool in_main_thread(void)
{
	return pthread_equal(pthread_self(), main_thread);
}

static char *rundir = NULL;
char *pluto_listen = NULL;
static bool fork_desired = USE_FORK || USE_DAEMON;
static bool selftest_only = FALSE;

#ifdef FIPS_CHECK
# include <fipscheck.h> /* from fipscheck devel */
static const char *fips_package_files[] = { IPSEC_EXECDIR "/pluto", NULL };
#endif

/* pulled from main for show_setup_plutomain() */
static const struct lsw_conf_options *oco;
static char *coredir;
static int pluto_nss_seedbits;
static int nhelpers = -1;
static bool do_dnssec = FALSE;
static char *pluto_dnssec_rootfile = NULL;
static char *pluto_dnssec_trusted = NULL;

static char *ocsp_uri = NULL;
static char *ocsp_trust_name = NULL;
static int ocsp_timeout = OCSP_DEFAULT_TIMEOUT;
static int ocsp_method = OCSP_METHOD_GET;
static int ocsp_cache_size = OCSP_DEFAULT_CACHE_SIZE;
static int ocsp_cache_min_age = OCSP_DEFAULT_CACHE_MIN_AGE;
static int ocsp_cache_max_age = OCSP_DEFAULT_CACHE_MAX_AGE;

static void free_pluto_main(void)
{
	/* Some values can be NULL if not specified as pluto argument */
	pfree(coredir);
	pfreeany(pluto_stats_binary);
	pfreeany(pluto_listen);
	pfree(pluto_vendorid);
	pfreeany(ocsp_uri);
	pfreeany(ocsp_trust_name);
	pfreeany(peerlog_basedir);
	pfreeany(curl_iface);
	pfreeany(pluto_log_file);
	pfreeany(pluto_dnssec_rootfile);
	pfreeany(pluto_dnssec_trusted);
	pfreeany(rundir);
}

/*
 * invocation_fail - print diagnostic and usage hint message and exit
 *
 * @param mess String - diagnostic message to print
 */
static void invocation_fail(err_t mess)
{
	if (mess != NULL)
		fprintf(stderr, "%s\n", mess);
	fprintf(stderr, "For usage information: %s --help\n"
		"Libreswan %s\n",
		pluto_name, ipsec_version_code());
	/* not exit_pluto because we are not initialized yet */
	exit(1);
}

/* string naming compile-time options that have interop implications */
static const char compile_time_interop_options[] = ""
#ifdef NETKEY_SUPPORT
	" XFRM(netkey)"
#endif
#ifdef KLIPS
	" KLIPS"
#endif
#ifdef KLIPS_MAST
	" MAST"
#endif

#if USE_FORK
	" FORK"
#endif
#if USE_VFORK
	" VFORK"
#endif
#if USE_DAEMON
	" DAEMON"
#endif
#if USE_PTHREAD_SETSCHEDPRIO
	" PTHREAD_SETSCHEDPRIO"
#endif
#if defined __GNUC__ && defined __EXCEPTIONS
	" GCC_EXCEPTIONS"
#endif
#ifdef HAVE_BROKEN_POPEN
	" BROKEN_POPEN"
#endif
	" NSS"
#ifdef USE_DNSSEC
	" DNSSEC"
#endif
#ifdef USE_SYSTEMD_WATCHDOG
	" SYSTEMD_WATCHDOG"
#endif
#ifdef FIPS_CHECK
	" FIPS_CHECK"
#endif
#ifdef HAVE_LABELED_IPSEC
	" LABELED_IPSEC"
#endif
#ifdef HAVE_SECCOMP
	" SECCOMP"
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
#ifdef KLIPS_MAST
	" KLIPS_MAST"
#endif
#ifdef LIBCURL
	" CURL(non-NSS)"
#endif
#ifdef LIBLDAP
	" LDAP(non-NSS)"
#endif
;

static char pluto_lock[sizeof(ctl_addr.sun_path)] =
	DEFAULT_RUNDIR "/pluto.pid";

static bool pluto_lock_created = FALSE;

/* create lockfile, or die in the attempt */
static int create_lock(void)
{
	int fd;

	if (mkdir(rundir, 0755) != 0) {
		if (errno != EEXIST) {
			fprintf(stderr,
				"pluto: FATAL: unable to create lock dir: \"%s\": %s\n",
				rundir, strerror(errno));
			exit_pluto(PLUTO_EXIT_LOCK_FAIL);
		}
	}

	fd = open(pluto_lock, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
		S_IRUSR | S_IRGRP | S_IROTH);

	if (fd < 0) {
		if (errno == EEXIST) {
			/*
			 * if we did not fork, then we do't really need
			 * the pid to control, so wipe it
			 */
			if (!fork_desired) {
				if (unlink(pluto_lock) == -1) {
					fprintf(stderr,
						"pluto: FATAL: lock file \"%s\" already exists and could not be removed (%d %s)\n",
						pluto_lock, errno,
						strerror(errno));
					exit_pluto(PLUTO_EXIT_LOCK_FAIL);
				} else {
					/*
					 * lock file removed,
					 * try creating it again
					 */
					return create_lock();
				}
			} else {
				fprintf(stderr,
					"pluto: FATAL: lock file \"%s\" already exists\n",
					pluto_lock);
				exit_pluto(PLUTO_EXIT_LOCK_FAIL);
			}
		} else {
			fprintf(stderr,
				"pluto: FATAL: unable to create lock file \"%s\" (%d %s)\n",
				pluto_lock, errno, strerror(errno));
			exit_pluto(PLUTO_EXIT_LOCK_FAIL);
		}
	}
	pluto_lock_created = TRUE;
	return fd;
}

/*
 * fill_lock - Populate the lock file with pluto's PID
 *
 * @param lockfd File Descriptor for the lock file
 * @param pid PID (pid_t struct) to be put into the lock file
 * @return bool True if successful
 */
static bool fill_lock(int lockfd, pid_t pid)
{
	char buf[30];	/* holds "<pid>\n" */
	int len = snprintf(buf, sizeof(buf), "%u\n", (unsigned int) pid);
	bool ok = len > 0 && write(lockfd, buf, len) == len;

	close(lockfd);
	return ok;
}

/*
 * delete_lock - Delete the lock file
 */
static void delete_lock(void)
{
	if (pluto_lock_created) {
		delete_ctl_socket();
		unlink(pluto_lock);	/* is noting failure useful? */
	}
}

/*
 * parser.l and keywords.c need these global variables
 * FIXME: move them to confread_load() parameters
 */
int verbose = 0;

/* Read config file. exit() on error. */
static struct starter_config *read_cfg_file(char *configfile)
{
	struct starter_config *cfg = NULL;
	starter_errors_t errl = { NULL };

	cfg = confread_load(configfile, &errl, NULL /* ctl_addr.sun_path? */, TRUE);
	if (cfg == NULL) {
		/*
		 * note: incovation_fail never returns so we will have
		 * a leak of errl.errors
		 */
		invocation_fail(errl.errors);
	}

	if (errl.errors != NULL) {
		fprintf(stderr, "pluto --config '%s', ignoring: %s\n",
			configfile, errl.errors);
		pfree(errl.errors);
	}

	return cfg;
}

/*
 * Helper function for config file mapper: set string option value.
 * Values passed in are expected to have been allocated using our
 * own functions.
 */
static void set_cfg_string(char **target, char *value)
{
	/* Do nothing if value is unset. */
	if (value == NULL || *value == '\0')
		return;

	/* Don't free previous target, it might be statically set. */
	*target = clone_str(value, "(ignore) set_cfg_string item");
}

/*
 * This function MUST NOT be used for anything else!
 * It is used to seed the NSS PRNG based on --seedbits pluto argument
 * or the seedbits= * config setup option in ipsec.conf.
 * Everything else that needs random MUST use get_rnd_bytes()
 * This function MUST NOT be changed to use /dev/urandom.
 */
static void get_bsi_random(size_t nbytes, unsigned char *buf)
{
	size_t ndone;
	int dev;
	ssize_t got;
	const char *device = "/dev/random";

	dev = open(device, 0);
	if (dev < 0) {
		loglog(RC_LOG_SERIOUS, "could not open %s (%s)\n",
			device, strerror(errno));
		exit_pluto(PLUTO_EXIT_NSS_FAIL);
	}

	ndone = 0;
		DBG(DBG_CONTROL, DBG_log("need %d bits random for extra seeding of the NSS PRNG",
			(int) nbytes * BITS_PER_BYTE));

	while (ndone < nbytes) {
		got = read(dev, buf + ndone, nbytes - ndone);
		if (got < 0) {
			loglog(RC_LOG_SERIOUS, "read error on %s (%s)\n",
				device, strerror(errno));
			exit_pluto(PLUTO_EXIT_NSS_FAIL);
		}
		if (got == 0) {
			loglog(RC_LOG_SERIOUS, "EOF on %s!?!\n",  device);
			exit_pluto(PLUTO_EXIT_NSS_FAIL);
		}
		ndone += got;
	}
	close(dev);
	DBG(DBG_CONTROL, DBG_log("read %zu bytes from /dev/random for NSS PRNG",
		nbytes));
}

static bool pluto_init_nss(char *nssdir)
{
	SECStatus rv;

	/* little lie, lsw_nss_setup doesn't have logging */
	loglog(RC_LOG_SERIOUS, "NSS DB directory: sql:%s", nssdir);

	lsw_nss_buf_t err;
	if (!lsw_nss_setup(nssdir, LSW_NSS_READONLY, lsw_nss_get_password, err)) {
		loglog(RC_LOG_SERIOUS, "%s", err);
		return FALSE;
	}

	libreswan_log("NSS initialized");

	/*
	 * This exists purely to make the BSI happy.
	 * We do not inflict this on other users
	 */
	if (pluto_nss_seedbits != 0) {
		int seedbytes = BYTES_FOR_BITS(pluto_nss_seedbits);
		unsigned char *buf = alloc_bytes(seedbytes, "TLA seedmix");

		get_bsi_random(seedbytes, buf); /* much TLA, very blocking */
		rv = PK11_RandomUpdate(buf, seedbytes);
		libreswan_log("seeded %d bytes into the NSS PRNG", seedbytes);
		passert(rv == SECSuccess);
		messupn(buf, seedbytes);
		pfree(buf);
	}

	return TRUE;
}

/* 0 is special and default: do not check crls dynamically */
deltatime_t crl_check_interval = DELTATIME_INIT(0);

#ifdef HAVE_LABELED_IPSEC
/*
 * Attribute Type "constant" for Security Context
 *
 * ??? NOT A CONSTANT!
 * Originally, we assigned the value 10, but that properly belongs to ECN_TUNNEL.
 * We then assigned 32001 which is in the private range RFC 2407.
 * Unfortunately, we feel we have to support 10 as an option for backward
 * compatibility.
 * This variable specifies (globally!!) which we support: 10 or 32001.
 * ??? surely that makes migration to 32001 all or nothing.
 */
uint16_t secctx_attr_type = SECCTX;
#endif

/*
 * Table of Pluto command-line options.
 *
 * For getopt_long(3), but with twists.
 *
 * We never find that letting getopt set an option makes sense
 * so flag is always NULL.
 *
 * Trick: we split each "name" string with an explicit '\0'.
 * Before the '\0' is the option name, as seen by getopt_long.
 * After the '\0' is meta-information:
 * - _ means: obsolete due to _ in name: replace _ with -
 * - > means: obsolete spelling; use spelling from rest of string
 * - ! means: obsolete and ignored (no replacement)
 * - anything else is a description of the options argument (printed by --help)
 *   If it starts with ^, that means start a newline in the --help output.
 *
 * The table should be ordered to maximize the clarity of --help.
 *
 */

enum {
	OPT_OFFSET = 256, /* larger than largest char */
	OPT_DEBUG,
	OPT_IMPAIR,
	OPT_DNSSEC_ROOTKEY_FILE,
	OPT_DNSSEC_TRUSTED,
};

static const struct option long_opts[] = {
	/* name, has_arg, flag, val */
	{ "help\0", no_argument, NULL, 'h' },
	{ "version\0", no_argument, NULL, 'v' },
	{ "config\0<filename>", required_argument, NULL, 'z' },
	{ "nofork\0", no_argument, NULL, '0' },
	{ "stderrlog\0", no_argument, NULL, 'e' },
	{ "logfile\0<filename>", required_argument, NULL, 'g' },
#ifdef USE_DNSSEC
	{ "dnssec-rootkey-file\0<filename>", required_argument, NULL,
		OPT_DNSSEC_ROOTKEY_FILE },
	{ "dnssec-trusted\0<filename>", required_argument, NULL,
		OPT_DNSSEC_TRUSTED },
#endif
	{ "log-no-time\0", no_argument, NULL, 't' }, /* was --plutostderrlogtime */
	{ "log-no-append\0", no_argument, NULL, '7' },
	{ "log-no-ip\0", no_argument, NULL, '<' },
	{ "force_busy\0_", no_argument, NULL, 'D' },	/* _ */
	{ "force-busy\0", no_argument, NULL, 'D' },
	{ "force-unlimited\0", no_argument, NULL, 'U' },
	{ "crl-strict\0", no_argument, NULL, 'r' },
	{ "crl_strict\0", no_argument, NULL, 'r' }, /* _ */
	{ "ocsp-strict\0", no_argument, NULL, 'o' },
	{ "ocsp_strict\0", no_argument, NULL, 'o' }, /* _ */
	{ "ocsp-enable\0", no_argument, NULL, 'O' },
	{ "ocsp_enable\0", no_argument, NULL, 'O' }, /* _ */
	{ "ocsp-uri\0", required_argument, NULL, 'Y' },
	{ "ocsp_uri\0", required_argument, NULL, 'Y' }, /* _ */
	{ "ocsp-timeout\0", required_argument, NULL, 'T' },
	{ "ocsp_timeout\0", required_argument, NULL, 'T' }, /* _ */
	{ "ocsp-trustname\0", required_argument, NULL, 'J' },
	{ "ocsp_trustname\0", required_argument, NULL, 'J' }, /* _ */
	{ "ocsp-cache-size\0", required_argument, NULL, 'E' },
	{ "ocsp-cache-min-age\0", required_argument, NULL, 'G' },
	{ "ocsp-cache-max-age\0", required_argument, NULL, 'H' },
	{ "ocsp-method\0", required_argument, NULL, 'B' },
	{ "crlcheckinterval\0", required_argument, NULL, 'x' },
	{ "uniqueids\0", no_argument, NULL, 'u' },
	{ "no-dnssec\0", no_argument, NULL, 'R' },
	{ "noklips\0>use-nostack", no_argument, NULL, 'n' },	/* redundant spelling */
	{ "nokernel\0>use-nostack", no_argument, NULL, 'n' },	/* redundant spelling */
	{ "use-nostack\0",  no_argument, NULL, 'n' },
	{ "use-none\0>use-nostack", no_argument, NULL, 'n' },	/* redundant spelling */
	{ "useklips\0>use-klips",  no_argument, NULL, 'k' },	/* redundant spelling */
	{ "use-klips\0",  no_argument, NULL, 'k' },
	{ "use-auto\0>use-netkey",  no_argument, NULL, 'K' },   /* redundant spelling (sort of) */
	{ "usenetkey\0>use-netkey", no_argument, NULL, 'K' },	/* redundant spelling */
	{ "use-netkey\0", no_argument, NULL, 'K' },
	{ "use-mast\0",   no_argument, NULL, 'M' },
	{ "use-mastklips\0",   no_argument, NULL, 'M' },
	{ "use-bsdkame\0",   no_argument, NULL, 'F' },
	{ "interface\0<ifname|ifaddr>", required_argument, NULL, 'i' },
	{ "curl-iface\0<ifname|ifaddr>", required_argument, NULL, 'Z' },
	{ "curl_iface\0<ifname|ifaddr>", required_argument, NULL, 'Z' }, /* _ */
	{ "curl-timeout\0<secs>", required_argument, NULL, 'I' },
	{ "curl-timeout\0<secs>", required_argument, NULL, 'I' }, /* _ */
	{ "listen\0<ifaddr>", required_argument, NULL, 'L' },
	{ "ikeport\0<port-number>", required_argument, NULL, 'p' },
	{ "ike-socket-bufsize\0<buf-size>", required_argument, NULL, 'W' },
	{ "ike-socket-no-errqueue\0", no_argument, NULL, '1' },
	{ "nflog-all\0<group-number>", required_argument, NULL, 'G' },
	{ "natikeport\0<port-number>", required_argument, NULL, 'q' },
	{ "rundir\0<path>", required_argument, NULL, 'b' }, /* was ctlbase */
	{ "ctlbase\0<path>", required_argument, NULL, 'b' }, /* backwards compatibility */
	{ "secretsfile\0<secrets-file>", required_argument, NULL, 's' },
	{ "perpeerlogbase\0<path>", required_argument, NULL, 'P' },
	{ "perpeerlog\0", no_argument, NULL, 'l' },
	{ "coredir\0>dumpdir", required_argument, NULL, 'C' },	/* redundant spelling */
	{ "dumpdir\0<dirname>", required_argument, NULL, 'C' },
	{ "statsbin\0<filename>", required_argument, NULL, 'S' },
	{ "ipsecdir\0<ipsec-dir>", required_argument, NULL, 'f' },
	{ "ipsec_dir\0>ipsecdir", required_argument, NULL, 'f' },	/* redundant spelling; _ */
	{ "foodgroupsdir\0>ipsecdir", required_argument, NULL, 'f' },	/* redundant spelling */
	{ "nssdir\0<path>", required_argument, NULL, 'd' },	/* nss-tools use -d */
	{ "nat_traversal\0!", no_argument, NULL, 'h' },	/* obsolete; _ */
	{ "keep_alive\0_", required_argument, NULL, '2' },	/* _ */
	{ "keep-alive\0<delay_secs>", required_argument, NULL, '2' },
	{ "force_keepalive\0!", no_argument, NULL, 'h' },	/* obsolete; _ */
	{ "disable_port_floating\0!", no_argument, NULL, 'h' },	/* obsolete; _ */
	{ "virtual_private\0_", required_argument, NULL, '6' },	/* _ */
	{ "virtual-private\0<network_list>", required_argument, NULL, '6' },
	{ "nhelpers\0<number>", required_argument, NULL, 'j' },
	{ "expire-shunt-interval\0<secs>", required_argument, NULL, '9' },
	{ "seedbits\0<number>", required_argument, NULL, 'c' },
#ifdef HAVE_LABELED_IPSEC
	/* ??? really an attribute type, not a value */
	{ "secctx_attr_value\0_", required_argument, NULL, 'w' },	/* obsolete name; _ */
	{ "secctx-attr-value\0<number>", required_argument, NULL, 'w' },	/* obsolete name */
	{ "secctx-attr-type\0<number>", required_argument, NULL, 'w' },
#endif
#ifdef HAVE_SECCOMP
	{ "seccomp-enabled\0", no_argument, NULL, '3' },
	{ "seccomp-tolerant\0", no_argument, NULL, '4' },
#endif
	{ "vendorid\0<vendorid>", required_argument, NULL, 'V' },

	{ "selftest\0", no_argument, NULL, '5' },

	{ "leak-detective\0", no_argument, NULL, 'X' },
	{ "debug-none\0^", no_argument, NULL, 'N' },
	{ "debug-all\0", no_argument, NULL, 'A' },
	{ "debug\0", required_argument, NULL, OPT_DEBUG, },
	{ "impair\0", required_argument, NULL, OPT_IMPAIR, },

	{ 0, 0, 0, 0 }
};

/* print full usage (from long_opts[]) */
static void usage(void)
{
	const struct option *opt;
	char line[72];
	size_t lw;

	snprintf(line, sizeof(line), "Usage: %s", pluto_name);
	lw = strlen(line);

	for (opt = long_opts; opt->name != NULL; opt++) {
		const char *nm = opt->name;
		const char *meta = nm + strlen(nm) + 1;
		bool force_nl = FALSE;
		char chunk[sizeof(line) - 1];
		int cw;

		switch (*meta) {
		case '_':
		case '>':
		case '!':
			/* ignore these entries */
			break;
		case '^':
			force_nl = TRUE;
			meta++;	/* eat ^ */
			/* FALL THROUGH */
		default:
			if (*meta == '\0')
				snprintf(chunk, sizeof(chunk),  "[--%s]", nm);
			else
				snprintf(chunk, sizeof(chunk),  "[--%s %s]", nm, meta);
			cw = strlen(chunk);

			if (force_nl || lw + cw + 2 >= sizeof(line)) {
				fprintf(stderr, "%s\n", line);
				line[0] = '\t';
				lw = 1;
			} else {
				line[lw++] = ' ';
			}
			passert(lw + cw + 1 < sizeof(line));
			strcpy(&line[lw], chunk);
			lw += cw;
		}
	}

	fprintf(stderr, "%s\n", line);

	fprintf(stderr, "Libreswan %s\n", ipsec_version_code());
	/* not exit_pluto because we are not initialized yet */
	exit(0);
}

#ifdef USE_DNSSEC
static void set_dnssec_file_names (struct starter_config *cfg)
{
	if (cfg->setup.strings[KSF_PLUTO_DNSSEC_ROOTKEY_FILE][0] != '\0') {
		pfreeany(pluto_dnssec_rootfile);
		set_cfg_string(&pluto_dnssec_rootfile,
				cfg->setup.strings[KSF_PLUTO_DNSSEC_ROOTKEY_FILE]);
	} else  {
		/* unset the global one config file unset it */
		pfreeany(pluto_dnssec_rootfile);
		pluto_dnssec_rootfile = NULL;
	}
	if (cfg->setup.strings[KSF_PLUTO_DNSSEC_ANCHORS] != NULL &&
			cfg->setup.strings[KSF_PLUTO_DNSSEC_ANCHORS][0] != '\0') {
		set_cfg_string(&pluto_dnssec_trusted,
				cfg->setup.strings[KSF_PLUTO_DNSSEC_ANCHORS]);
	}
}
#endif

int main(int argc, char **argv)
{
	/*
	 * Identify the main thread.
	 *
	 * Also used as a reserved thread for code wanting to
	 * determine if it is running on an aux thread.
	 */
	main_thread = pthread_self();

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

	{
		int i;

		/* MUST BE BEFORE ANY allocs */
		for (i = 1; i < argc; ++i) {
			if (streq(argv[i], "--leak-detective"))
				leak_detective = TRUE;
		}
	}

	pluto_name = argv[0];

	coredir = clone_str(DEFAULT_RUNDIR, "coredir in main()");
	rundir = clone_str(DEFAULT_RUNDIR, "rundir");
	pluto_vendorid = clone_str(ipsec_version_vendorid(), "vendorid in main()");
#ifdef USE_DNSSEC
	pluto_dnssec_rootfile = clone_str(DEFAULT_DNSSEC_ROOTKEY_FILE, "root.key file");
#endif

	deltatime_t keep_alive = DELTATIME_INIT(0);

	/* Overridden by virtual_private= in ipsec.conf */
	char *virtual_private = NULL;

	/* handle arguments */
	for (;; ) {
		/*
		 * Note: we don't like the way short options get parsed
		 * by getopt_long, so we simply pass an empty string as
		 * the list.  It could be "hvdenp:l:s:" "NARXPECK".
		 */
		int longindex = -1;
		int c = getopt_long(argc, argv, "", long_opts, &longindex);
		const char *optname = NULL;
		err_t ugh = NULL;	/* complaint from case */
		unsigned long u = 0;	/* scratch for case */

		if (longindex != -1) {
			const char *optmeta;
			optname = long_opts[longindex].name;

			optmeta = optname + strlen(optname) + 1;	/* after '\0' */
			switch (optmeta[0]) {
			case '_':
				libreswan_log("warning: option \"--%s\" with '_' in its name is obsolete; use '-'",
					optname);
				break;
			case '>':
				libreswan_log("warning: option \"--%s\" is obsolete; use \"--%s\"",
					optname, optmeta + 1);
				break;
			case '!':
				libreswan_log("warning: option \"--%s\" is obsolete; ignored",
					optname);
				continue;	/* ignore it! */
			}
		}

		/* Note: "breaking" from case terminates loop */
		switch (c) {
		case EOF:	/* end of flags */
			break;

		case 0:
			/*
			 * Long option already handled by getopt_long.
			 * Not currently used since we always set flag to NULL.
			 */
			continue;

		case ':':	/* diagnostic already printed by getopt_long */
		case '?':	/* diagnostic already printed by getopt_long */
			invocation_fail(NULL);
			break;

		case 'h':	/* --help */
			usage();
			break;	/* not actually reached */

		case 'X':	/* --leak-detective */
			/*
			 * This flag was already processed at the start of main()
			 * because leak_detective must be immutable from before
			 * the first alloc().
			 * If this option is specified, we must have already
			 * set it at the start of main(), so assert it.
			 */
			passert(leak_detective);
			continue;

		case 'C':	/* --coredir */
			pfree(coredir);
			coredir = clone_str(optarg, "coredir via getopt");
			continue;

		case 'V':	/* --vendorid */
			pfree(pluto_vendorid);
			pluto_vendorid = clone_str(optarg, "pluto_vendorid via getopt");
			continue;

		case 'S':	/* --statsdir */
			pfreeany(pluto_stats_binary);
			pluto_stats_binary = clone_str(optarg, "statsbin");
			continue;

		case 'v':	/* --version */
			printf("%s%s\n", ipsec_version_string(),
				compile_time_interop_options);
			/* not exit_pluto because we are not initialized yet */
			exit(0);
			break;	/* not actually reached */

		case 'j':	/* --nhelpers */
			if (streq(optarg, "-1")) {
				nhelpers = -1;
			} else {
				ugh = ttoulb(optarg, 0, 10, 1000, &u);
				if (ugh != NULL)
					break;

				nhelpers = u;
			}
			continue;
		case 'c':	/* --seedbits */
			pluto_nss_seedbits = atoi(optarg);
			if (pluto_nss_seedbits == 0) {
				printf("pluto: seedbits must be an integer > 0");
				/* not exit_pluto because we are not initialized yet */
				exit(PLUTO_EXIT_NSS_FAIL);
			}
			continue;

#ifdef HAVE_LABELED_IPSEC
		case 'w':	/* --secctx-attr-type */
			ugh = ttoulb(optarg, 0, 0, 0xFFFF, &u);
			if (ugh != NULL)
				break;
			if (u != SECCTX && u != ECN_TUNNEL_or_old_SECCTX) {
				ugh = "must be a positive 32001 (default) or 10 (for backward compatibility)";
				break;
			}
			secctx_attr_type = u;
			continue;
#endif

		case '0':	/* --nofork*/
			fork_desired = FALSE;
			continue;

		case 'e':	/* --stderrlog */
			log_to_stderr_desired = TRUE;
			continue;

		case 'g':	/* --logfile */
			pluto_log_file = clone_str(optarg, "pluto_log_file");
			log_to_file_desired = TRUE;
			continue;
#ifdef USE_DNSSEC
		case OPT_DNSSEC_ROOTKEY_FILE:	/* --dnssec-rootkey-file */
			if (optarg[0] != '\0') {
				pfree(pluto_dnssec_rootfile);
				pluto_dnssec_rootfile = clone_str(optarg,
						"dnssec_rootkey_file");
			}
			continue;

		case OPT_DNSSEC_TRUSTED:	/* --dnssec-trusted */
			pluto_dnssec_trusted = clone_str(optarg, "pluto_dnssec_trusted");
			continue;
#endif  /* USE_DNSSEC */

		case 't':	/* --log-no-time */
			log_with_timestamp = FALSE;
			continue;

		case '7':	/* --log-no-append */
			log_append = FALSE;
			continue;

		case '<':	/* --log-no-ip */
			log_ip = FALSE;
			continue;

		case '8':	/* --drop-oppo-null */
			pluto_drop_oppo_null = TRUE;
			continue;

		case '9':	/* --expire-bare-shunt <interval> */
		{
			unsigned long d = 0;
			ugh = ttoulb(optarg, 0, 10, 1000, &d);
			if (ugh != NULL)
				break;
			bare_shunt_interval = deltatime(d);
			continue;
		}

		case 'k':	/* --use-klips */
			kern_interface = USE_KLIPS;
			continue;

		case 'L':	/* --listen ip_addr */
		{
			ip_address lip;
			err_t e = ttoaddr_num(optarg, 0, AF_UNSPEC, &lip);

			if (e != NULL) {
				/*
				 *??? should we continue on failure?
				 * If not, use ugh mechanism.
				 */
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

		case 'M':	/* --use-mast */
			kern_interface = USE_MASTKLIPS;
			continue;

		case 'F':	/* --use-bsdkame */
			kern_interface = USE_BSDKAME;
			continue;

		case 'K':	/* --use-netkey */
			kern_interface = USE_NETKEY;
			continue;

		case 'n':	/* --use-nostack */
			kern_interface = NO_KERNEL;
			continue;

		case 'D':	/* --force-busy */
			pluto_ddos_mode = DDOS_FORCE_BUSY;
			continue;
		case 'U':	/* --force-unlimited */
			pluto_ddos_mode = DDOS_FORCE_UNLIMITED;
			continue;

#ifdef HAVE_SECCOMP
		case '3':	/* --seccomp-enabled */
			pluto_seccomp_mode = SECCOMP_ENABLED;
			continue;
		case '4':	/* --seccomp-tolerant */
			pluto_seccomp_mode = SECCOMP_TOLERANT;
			continue;
#endif

		case 'Z':	/* --curl-iface */
			curl_iface = clone_str(optarg, "curl_iface");
			continue;

		case 'I':	/* --curl-timeout */
			ugh = ttoulb(optarg, 0, 10, 0xFFFF, &u);
			if (ugh != NULL)
				break;
			if (u <= 0) {
				ugh = "must not be < 1";
				break;
			}
			curl_timeout = u;
			continue;

		case 'r':	/* --strictcrlpolicy */
			crl_strict = TRUE;
			continue;

		case 'x':	/* --crlcheckinterval <seconds> */
			ugh = ttoulb(optarg, 0, 10, (unsigned long) TIME_T_MAX, &u);
			if (ugh != NULL)
				break;
			crl_check_interval = deltatime(u);
			continue;

		case 'o':
			ocsp_strict = TRUE;
			continue;

		case 'O':
			ocsp_enable = TRUE;
			continue;

		case 'Y':
			ocsp_uri = clone_str(optarg, "ocsp_uri");
			continue;

		case 'J':
			ocsp_trust_name = clone_str(optarg, "ocsp_trust_name");
			continue;

		case 'T':	/* --ocsp_timeout <seconds> */
			ugh = ttoulb(optarg, 0, 10, 0xFFFF, &u);
			if (ugh != NULL)
				break;
			if (u == 0) {
				ugh = "must not be 0";
				break;
			}
			ocsp_timeout = u;
			continue;

		case 'E':	/* --ocsp-cache-size <entries> */
			ugh = ttoulb(optarg, 0, 10, 0xFFFF, &u);
			if (ugh != NULL)
				break;
			ocsp_cache_size = u;
			continue;

		case 'G':	/* --ocsp-cache-min-age <seconds> */
			ugh = ttoulb(optarg, 0, 10, 0xFFFF, &u);
			if (ugh != NULL)
				break;
			ocsp_cache_min_age = u;
			continue;

		case 'H':	/* --ocsp-cache-max-age <seconds> */
			ugh = ttoulb(optarg, 0, 10, 0xFFFF, &u);
			if (ugh != NULL)
				break;
			ocsp_cache_max_age = u;
			continue;

		case 'B':	/* --ocsp-method get|post */
			if (streq(optarg, "post")) {
				ocsp_method = OCSP_METHOD_POST;
			} else {
				if (streq(optarg, "get")) {
					ocsp_method = OCSP_METHOD_GET;
				} else {
					ugh = "ocsp-method is either 'post' or 'get'";
					break;
				}
			}
			continue;

		case 'u':	/* --uniqueids */
			uniqueIDs = TRUE;
			continue;

		case 'R':	/* --no-dnssec */
			do_dnssec = FALSE;
			continue;

		case 'i':	/* --interface <ifname|ifaddr> */
			if (!use_interface(optarg)) {
				ugh = "too many --interface specifications";
				break;
			}
			continue;

		/*
		 * This option does not really work, as this is the "left"
		 * site only, you also need --to --ikeport again later on
		 * It will result in: yourport -> 500, still not bypassing
		 * filters
		 */
		case 'p':	/* --ikeport <portnumber> */
			ugh = ttoulb(optarg, 0, 10, 0xFFFF, &u);
			if (ugh != NULL)
				break;
			if (u == 0) {
				ugh = "must not be 0";
				break;
			}
			pluto_port = u;
			continue;

		case '1':	/* --ike-socket-no-errqueue */
			pluto_sock_errqueue = FALSE;
			continue;

		case 'W':	/* --ike-socket-bufsize <bufsize> */
			ugh = ttoulb(optarg, 0, 10, 0xFFFF, &u);
			if (ugh != NULL)
				break;
			if (u == 0) {
				ugh = "must not be 0";
				break;
			}
			pluto_sock_bufsize = u;
			continue;

		case 'q':	/* --natikeport <portnumber> */
			ugh = ttoulb(optarg, 0, 10, 0xFFFF, &u);
			if (ugh != NULL)
				break;
			if (u == 0) {
				ugh = "must not be 0";
				break;
			}
			pluto_nat_port = u;
			continue;

		case 'b':	/* --rundir <path> */
			/*
			 * ??? work to be done here:
			 *
			 * snprintf returns the required space if there
			 * isn't enough, not -1.
			 * -1 indicates another kind of error.
			 */
			if (snprintf(ctl_addr.sun_path,
					sizeof(ctl_addr.sun_path),
					"%s/pluto.ctl", optarg) == -1) {
				ugh = "--rundir argument is invalid for sun_path socket";
				break;
			}

			if (snprintf(pluto_lock, sizeof(pluto_lock),
					"%s/pluto.pid", optarg) == -1) {
				ugh = "--rundir ctl_addr.sun_path is invalid for sun_path socket";
				break;
			}
			pfreeany(rundir);
			rundir = clone_str(optarg, "rundir");
			continue;

		case 's':	/* --secretsfile <secrets-file> */
			lsw_conf_secretsfile(optarg);
			continue;

		case 'f':	/* --ipsecdir <ipsec-dir> */
			lsw_conf_confddir(optarg);
			continue;

		case 'd':	/* --nssdir <path> */
			lsw_conf_nssdir(optarg);
			continue;

		case 'N':	/* --debug-none */
			base_debugging = DBG_NONE;
			continue;

		case 'A':	/* --debug-all */
			base_debugging = DBG_ALL;
			continue;

		case 'P':	/* --perpeerlogbase */
			peerlog_basedir = clone_str(optarg, "peerlog_basedir");
			continue;

		case 'l':	/* --perpeerlog */
			log_to_perpeer = TRUE;
			continue;

		case '2':	/* --keep-alive <delay_secs> */
			ugh = ttoulb(optarg, 0, 10, secs_per_day, &u);
			if (ugh != NULL)
				break;
			keep_alive = deltatime(u);
			continue;

		case '5':	/* --selftest */
			selftest_only = TRUE;
			log_to_stderr_desired = TRUE;
			fork_desired = FALSE;
			continue;

		case '6':	/* --virtual-private */
			virtual_private = clone_str(optarg, "virtual_private");
			continue;

		case 'z':	/* --config */
		{
			/*
			 * Config struct to variables mapper. This will
			 * overwrite all previously set options. Keep this
			 * in the same order as long_opts[] is.
			 */
			struct starter_config *cfg = read_cfg_file(optarg);

			/* leak */
			set_cfg_string(&pluto_log_file,
				cfg->setup.strings[KSF_PLUTOSTDERRLOG]);
#ifdef USE_DNSSEC
			set_dnssec_file_names(cfg);
#endif

			if (pluto_log_file != NULL)
				log_to_syslog = FALSE;
			/* plutofork= no longer supported via config file */
			log_with_timestamp =
				cfg->setup.options[KBF_PLUTOSTDERRLOGTIME];
			log_append = cfg->setup.options[KBF_PLUTOSTDERRLOGAPPEND];
			log_ip = cfg->setup.options[KBF_PLUTOSTDERRLOGIP];
			pluto_drop_oppo_null = cfg->setup.options[KBF_DROP_OPPO_NULL];
			pluto_ddos_mode = cfg->setup.options[KBF_DDOS_MODE];
#ifdef HAVE_SECCOMP
			pluto_seccomp_mode = cfg->setup.options[KBF_SECCOMP];
#endif
			if (cfg->setup.options[KBF_FORCEBUSY]) {
				/* force-busy is obsoleted, translate to ddos-mode= */
				pluto_ddos_mode = cfg->setup.options[KBF_DDOS_MODE] = DDOS_FORCE_BUSY;
			}
			/* ddos-ike-threshold and max-halfopen-ike */
			pluto_ddos_threshold = cfg->setup.options[KBF_DDOS_IKE_THRESHOLD];
			pluto_max_halfopen = cfg->setup.options[KBF_MAX_HALFOPEN_IKE];

			crl_strict = cfg->setup.options[KBF_CRL_STRICT];

			pluto_shunt_lifetime = deltatime(cfg->setup.options[KBF_SHUNTLIFETIME]);

			ocsp_enable = cfg->setup.options[KBF_OCSP_ENABLE];
			ocsp_strict = cfg->setup.options[KBF_OCSP_STRICT];
			ocsp_timeout = cfg->setup.options[KBF_OCSP_TIMEOUT];
			ocsp_method = cfg->setup.options[KBF_OCSP_METHOD];
			ocsp_cache_size = cfg->setup.options[KBF_OCSP_CACHE_SIZE];
			ocsp_cache_min_age = cfg->setup.options[KBF_OCSP_CACHE_MIN];
			ocsp_cache_max_age = cfg->setup.options[KBF_OCSP_CACHE_MAX];

			set_cfg_string(&ocsp_uri,
				       cfg->setup.strings[KSF_OCSP_URI]);
			set_cfg_string(&ocsp_trust_name,
				       cfg->setup.strings[KSF_OCSP_TRUSTNAME]);

			crl_check_interval = deltatime(
				cfg->setup.options[KBF_CRL_CHECKINTERVAL]);
			uniqueIDs = cfg->setup.options[KBF_UNIQUEIDS];
#ifdef USE_DNSSEC
			do_dnssec = cfg->setup.options[KBF_DO_DNSSEC];
#else
			do_dnssec = FALSE;
#endif
			/*
			 * We don't check interfaces= here because that part
			 * has been dealt with in _stackmanager before we
			 * started
			 */
			set_cfg_string(&pluto_listen,
				cfg->setup.strings[KSF_LISTEN]);

			/* --ikeport */
			pluto_port = cfg->setup.options[KBF_IKEPORT];

			/* --ike-socket-bufsize */
			pluto_sock_bufsize = cfg->setup.options[KBF_IKEBUF];
			pluto_sock_errqueue = cfg->setup.options[KBF_IKE_ERRQUEUE];

			/* --nflog-all */
			/* only causes nflog nmber to show in ipsec status */
			pluto_nflog_group = cfg->setup.options[KBF_NFLOG_ALL];

			/* only causes nflog nmber to show in ipsec status */
			pluto_xfrmlifetime = cfg->setup.options[KBF_XFRMLIFETIME];

			/* no config option: rundir */
			/* --secrets */
			if (cfg->setup.strings[KSF_SECRETSFILE] &&
			    *cfg->setup.strings[KSF_SECRETSFILE]) {
				lsw_conf_secretsfile(cfg->setup.strings[KSF_SECRETSFILE]);
			}
			if (cfg->setup.strings[KSF_IPSECDIR] != NULL &&
				*cfg->setup.strings[KSF_IPSECDIR] != 0) {
				/* --ipsecdir */
				lsw_conf_confddir(cfg->setup.strings[KSF_IPSECDIR]);
			}

			if (cfg->setup.strings[KSF_NSSDIR] != NULL &&
				*cfg->setup.strings[KSF_NSSDIR] != 0) {
				/* --nssdir <path> */
				lsw_conf_nssdir(cfg->setup.strings[KSF_NSSDIR]);
			}

			/* --perpeerlog */
			log_to_perpeer = cfg->setup.options[KBF_PERPEERLOG];
			if (log_to_perpeer) {
				/* --perpeerlogbase */
				if (cfg->setup.strings[KSF_PERPEERDIR]) {
					set_cfg_string(&peerlog_basedir,
						cfg->setup.strings[KSF_PERPEERDIR]);
				} else {
					peerlog_basedir = clone_str("/var/log/pluto/", "perpeer_logdir");
				}
			}

			if (cfg->setup.strings[KSF_CURLIFACE]) {
				pfreeany(curl_iface);
				/* curl-iface= */
				curl_iface = clone_str(cfg->setup.strings[KSF_CURLIFACE],
						"curl-iface= via --config");
			}

			if (cfg->setup.options[KBF_CURLTIMEOUT])
				curl_timeout = cfg->setup.options[KBF_CURLTIMEOUT];

			if (cfg->setup.strings[KSF_DUMPDIR]) {
				pfree(coredir);
				/* dumpdir= */
				coredir = clone_str(cfg->setup.strings[KSF_DUMPDIR],
						"coredir via --config");
			}
			/* --vendorid */
			if (cfg->setup.strings[KSF_MYVENDORID]) {
				pfree(pluto_vendorid);
				pluto_vendorid = clone_str(cfg->setup.strings[KSF_MYVENDORID],
						"pluto_vendorid via --config");
			}

			if (cfg->setup.strings[KSF_STATSBINARY] != NULL) {
				if (access(cfg->setup.strings[KSF_STATSBINARY], X_OK) == 0) {
					pfreeany(pluto_stats_binary);
					/* statsbin= */
					pluto_stats_binary = clone_str(cfg->setup.strings[KSF_STATSBINARY], "statsbin via --config");
					libreswan_log("statsbinary set to %s", pluto_stats_binary);
				} else {
					libreswan_log("statsbinary= '%s' ignored - file does not exist or is not executable",
						pluto_stats_binary);
				}
			}

			pluto_nss_seedbits = cfg->setup.options[KBF_SEEDBITS];
			pluto_nat_port =
				cfg->setup.options[KBF_NATIKEPORT];
			keep_alive = deltatime(cfg->setup.options[KBF_KEEPALIVE]);

			set_cfg_string(&virtual_private,
				cfg->setup.strings[KSF_VIRTUALPRIVATE]);

			nhelpers = cfg->setup.options[KBF_NHELPERS];
#ifdef HAVE_LABELED_IPSEC
			secctx_attr_type = cfg->setup.options[KBF_SECCTX];
#endif
			base_debugging = cfg->setup.options[KBF_PLUTODEBUG];

			char *protostack = cfg->setup.strings[KSF_PROTOSTACK];

			if (protostack == NULL || *protostack == '\0') {
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

		case OPT_DEBUG:
		{
			lmod_t mod = empty_lmod;
			if (lmod_arg(&mod, &debug_lmod_info, optarg)) {
				base_debugging = lmod(base_debugging, mod);
			} else {
				libreswan_log("unrecognized --debug '%s' option ignored",
					      optarg);
			}
			continue;
		}

		case OPT_IMPAIR:
		{
			lmod_t mod = empty_lmod;
			if (lmod_arg(&mod, &impair_lmod_info, optarg)) {
				base_debugging = lmod(base_debugging, mod);
			} else {
				libreswan_log("unrecognized --impair '%s' option ignored",
					      optarg);
			}
			continue;
		}

		default:
			bad_case(c);
		}
		/* if ugh is set, bail with diagnostic */
		if (ugh != NULL) {
			char mess[200];

			if (longindex == -1) {
				snprintf(mess, sizeof(mess), "unknown option: %s",
					ugh);
			} else if (optarg == NULL) {
				snprintf(mess, sizeof(mess), "--%s option: %s",
					optname, ugh);
			} else {
				snprintf(mess, sizeof(mess), "--%s \"%s\" option: %s",
					optname, optarg, ugh);
			}
			invocation_fail(mess);
		}
		break;
	}
	if (optind != argc)
		invocation_fail("unexpected argument");
	reset_debugging();

	if (chdir(coredir) == -1) {
		int e = errno;

		libreswan_log("pluto: warning: chdir(\"%s\") to dumpdir failed (%d: %s)",
			coredir, e, strerror(e));
	}

	oco = lsw_init_options();

	if (!selftest_only)
		lockfd = create_lock();
	else
		lockfd = 0;

	/* select between logging methods */

	if (log_to_stderr_desired || log_to_file_desired)
		log_to_syslog = FALSE;
	if (!log_to_stderr_desired)
		log_to_stderr = FALSE;

	/*
	 * create control socket.
	 * We must create it before the parent process returns so that
	 * there will be no race condition in using it.  The easiest
	 * place to do this is before the daemon fork.
	 */
	if (!selftest_only) {
		err_t ugh = init_ctl_socket();

		if (ugh != NULL) {
			fprintf(stderr, "pluto: FATAL: %s", ugh);
			exit_pluto(PLUTO_EXIT_SOCKET_FAIL);
		}
	}

	/* If not suppressed, do daemon fork */
	if (fork_desired) {
#if USE_DAEMON
		if (daemon(TRUE, TRUE) < 0) {
			fprintf(stderr, "pluto: FATAL: daemon failed (%d %s)\n",
				errno, strerror(errno));
			exit_pluto(PLUTO_EXIT_FORK_FAIL);
		}
		/*
		 * Parent just exits, so need to fill in our own PID
		 * file.  This is racy, since the file won't be
		 * created until after the parent has exited.
		 *
		 * Since "ipsec start" invokes pluto with --nofork, it
		 * is probably safer to leave this feature disabled
		 * then implement it using the daemon call.
		 */
		(void) fill_lock(lockfd, getpid());
#elif USE_FORK
		{
			pid_t pid = fork();

			if (pid < 0) {
				int e = errno;

				fprintf(stderr, "pluto: FATAL: fork failed (%d %s)\n",
					errno, strerror(e));
				exit_pluto(PLUTO_EXIT_FORK_FAIL);
			}

			if (pid != 0) {
				/*
				 * parent: die, after filling PID into lock
				 * file.
				 * must not use exit_pluto: lock would be
				 * removed!
				 */
				exit(fill_lock(lockfd, pid) ? 0 : 1);
			}
		}
#else
		fprintf(stderr, "pluto: FATAL: fork/daemon not supported\n");
		exit_pluto(PLUTO_EXIT_FORK_FAIL);
#endif
		if (setsid() < 0) {
			int e = errno;

			fprintf(stderr,
				"FATAL: setsid() failed in main(). Errno %d: %s\n",
				errno, strerror(e));
			exit_pluto(PLUTO_EXIT_FAIL);
		}
	} else {
		/* no daemon fork: we have to fill in lock file */
		(void) fill_lock(lockfd, getpid());

		if (isatty(fileno(stdout))) {
			fprintf(stdout, "Pluto initialized\n");
			fflush(stdout);
		}
	}

	/*
	 * Close everything but ctl_fd and (if needed) stderr.
	 * There is some danger that a library that we don't know
	 * about is using some fd that we don't know about.
	 * I guess we'll soon find out.
	 */
	{
		int i;

		for (i = getdtablesize() - 1; i >= 0; i--)	/* Bad hack */
			if ((!log_to_stderr || i != 2) &&
				i != ctl_fd)
				close(i);

		/* make sure that stdin, stdout, stderr are reserved */
		passert(open("/dev/null", O_RDONLY) == 0);
		passert(dup2(0, 1) == 1);
		passert(log_to_stderr || dup2(0, 2) == 2);
	}

	init_constants();
	init_pluto_constants();

	pluto_init_log();

#ifdef FIPS_CHECK
	/*
	 * Probe FIPS support.  Part #1 of #2.
	 *
	 * This needs to occur very early, after pluto's log has been
	 * initialized so that the result gets written to a file.
	 *
	 * This call is what triggers the FIPS Product: et.al. log
	 * messages.
	 */
	enum lsw_fips_mode pluto_fips_mode = lsw_get_fips_mode();
	if (pluto_fips_mode == LSW_FIPS_ON) {
		/*
		 * clear out --debug-crypt if set
		 *
		 * impairs are also not allowed but cannot come in via
		 * ipsec.conf, only whack
		 */
		if (base_debugging & DBG_PRIVATE) {
			base_debugging &= ~DBG_PRIVATE;
			loglog(RC_LOG_SERIOUS, "FIPS mode: debug-private disabled as such logging is not allowed");
		}
	}
	if (IMPAIR(FORCE_FIPS)) {
		libreswan_log("Forcing FIPS checks to true to emulate FIPS mode");
		lsw_set_fips_mode(LSW_FIPS_ON);
	}
#endif

	if (!pluto_init_nss(oco->nssdir)) {
		loglog(RC_LOG_SERIOUS, "FATAL: NSS initialization failure");
		exit_pluto(PLUTO_EXIT_NSS_FAIL);
	}
	libreswan_log("NSS crypto library initialized");

	if (ocsp_enable) {
		if (!init_nss_ocsp(ocsp_uri, ocsp_trust_name,
			ocsp_timeout, ocsp_strict, ocsp_cache_size,
			ocsp_cache_min_age, ocsp_cache_min_age,
			(ocsp_method == OCSP_METHOD_POST))) {
			loglog(RC_LOG_SERIOUS, "Initializing NSS OCSP failed");
			exit_pluto(PLUTO_EXIT_NSS_FAIL);
		} else {
			libreswan_log("NSS OCSP started");
		}
	}

#ifdef FIPS_CHECK
	/*
	 * Probe FIPS support.  Part #2 of #2.
	 *
	 * Now that NSS is initialized, need to verify it matches the
	 * mode pluto is in.
	 */
	libreswan_log("FIPS HMAC integrity support [enabled]");
	{
		bool nss_fips_mode = PK11_IsFIPS();

		/*
		 * Now verify the consequences.  Always run the tests
		 * as combinations such as NSS in fips mode but as out
		 * of it could be bad.
		 */
		switch (pluto_fips_mode) {
		case LSW_FIPS_UNKNOWN:
			loglog(RC_LOG_SERIOUS, "ABORT: pluto FIPS mode could not be determined");
			exit_pluto(PLUTO_EXIT_FIPS_FAIL);
			break;
		case LSW_FIPS_ON:
			libreswan_log("FIPS mode enabled for pluto daemon");
			if (nss_fips_mode) {
				libreswan_log("NSS library is running in FIPS mode");
			} else {
				loglog(RC_LOG_SERIOUS, "ABORT: pluto in FIPS mode but NSS library is not");
				exit_pluto(PLUTO_EXIT_FIPS_FAIL);
			}
			break;
		case LSW_FIPS_OFF:
			libreswan_log("FIPS mode disabled for pluto daemon");
			if (nss_fips_mode) {
				loglog(RC_LOG_SERIOUS, "Warning: NSS library is running in FIPS mode");
			}
			break;
		case LSW_FIPS_UNSET:
		default:
			bad_case(pluto_fips_mode);
		}

		/* always run hmac check so we can print diagnostic */
		bool fips_files = FIPSCHECK_verify_files(fips_package_files);

		if (fips_files) {
			libreswan_log("FIPS HMAC integrity verification self-test passed");
		} else {
			loglog(RC_LOG_SERIOUS, "FIPS HMAC integrity verification self-test FAILED");
		}
		if (pluto_fips_mode == LSW_FIPS_ON && !fips_files) {
			exit_pluto(PLUTO_EXIT_FIPS_FAIL);
		}
	}
#else
	libreswan_log("FIPS HMAC integrity support [disabled]");
#endif

#ifdef HAVE_LIBCAP_NG
	/*
	 * Drop capabilities - this generates a false positive valgrind warning
	 * See: http://marc.info/?l=linux-security-module&m=125895232029657
	 *
	 * We drop these after creating the pluto socket or else we can't
	 * create a socket if the parent dir is non-root (eg openstack)
	 */
	capng_clear(CAPNG_SELECT_BOTH);

	capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE | CAPNG_PERMITTED,
		CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW,
		CAP_IPC_LOCK, CAP_AUDIT_WRITE,
		/* for google authenticator pam */
		CAP_SETGID, CAP_SETUID,
		CAP_DAC_READ_SEARCH,
		-1);
	/*
	 * We need to retain some capabilities for our children (updown):
	 * CAP_NET_ADMIN to change routes
	 * (we also need it for some setsockopt() calls in main process)
	 * CAP_NET_RAW for iptables -t mangle
	 * CAP_DAC_READ_SEARCH for pam / google authenticator
	 *
	 */
	capng_updatev(CAPNG_ADD, CAPNG_BOUNDING_SET, CAP_NET_ADMIN, CAP_NET_RAW,
			CAP_DAC_READ_SEARCH, -1);
	capng_apply(CAPNG_SELECT_BOTH);
	libreswan_log("libcap-ng support [enabled]");
#else
	libreswan_log("libcap-ng support [disabled]");
#endif

#ifdef USE_LINUX_AUDIT
	linux_audit_init();
#else
	libreswan_log("Linux audit support [disabled]");
#endif

	{
		const char *vc = ipsec_version_code();
		libreswan_log("Starting Pluto (Libreswan Version %s%s) pid:%u",
			vc, compile_time_interop_options, getpid());
	}

	libreswan_log("core dump dir: %s", coredir);
	if (oco->secretsfile && *oco->secretsfile)
		libreswan_log("secrets file: %s", oco->secretsfile);

	libreswan_log(leak_detective ?
		"leak-detective enabled" : "leak-detective disabled");

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
			libreswan_log("SAbind support [disabled]: %s",
				strerror(errno));
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

	/*
	 * Log impair-* functions that were enabled
	 */
	for (long e = next_enum(&impair_names, -1);
	     e >= 0; e = next_enum(&impair_names, e)) {
		unsigned bit = e;
		if (DBGP(LELEM(bit))) {
			const char *name = enum_name(&impair_names, bit);
			libreswan_log("Warning: %s enabled", name);
		}
	}

/* Initialize all of the various features */

	init_state_db();

	init_nat_traversal(keep_alive);

	init_virtual_ip(virtual_private);
	/* obsoleted by nss code init_rnd_pool(); */
	init_event_base();
	init_secret();
	init_states();
	init_connections();
	init_ike_alg();
	test_ike_alg();

	if (selftest_only) {
		/*
		 * skip pluto_exit()
		 * Not all components were initialized and
		 * no lock files were created.
		 */
		exit(PLUTO_EXIT_OK);
	}

	init_crypto_helpers(nhelpers);
	init_demux();
	init_kernel();
	init_vendorid();
#if defined(LIBCURL) || defined(LIBLDAP)
	init_fetch();
#endif
#ifdef HAVE_LABELED_IPSEC
	init_avc();
#endif
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd_init();
#endif

#ifdef USE_DNSSEC
	if (!unbound_event_init(get_pluto_event_base(), do_dnssec,
		pluto_dnssec_rootfile, pluto_dnssec_trusted)) {
			exit_pluto(PLUTO_EXIT_UNBOUND_FAIL);
	}
#endif

	call_server();
	return -1;	/* Shouldn't ever reach this */
}

volatile bool exiting_pluto = false;

/*
 * leave pluto, with status.
 * Once child is launched, parent must not exit this way because
 * the lock would be released.
 *
 *  0 OK
 *  1 general discomfort
 * 10 lock file exists
 */
void exit_pluto(int status)
{
	/*
	 * Tell the world, well actually all the threads, that pluto
	 * is exiting and they should quit.  Even if pthread_cancel()
	 * weren't buggy, using it correctly would be hard, so use
	 * this instead.
	 *
	 * XXX: All threads need to be told to quit before things like
	 * NSS can be closed.  So a TODO is to join those threads.
	 */
	exiting_pluto = true;

	/* needed because we may be called in odd state */
	reset_globals();
 #ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_STOPPING, status);
 #endif
	free_preshared_secrets();
	free_remembered_public_keys();
	delete_every_connection();

	/*
	 * free memory allocated by initialization routines.  Please don't
	 * forget to do this.
	 */

#if defined(LIBCURL) || defined(LIBLDAP)
	free_crl_fetch();	/* free chain of crl fetch requests */
#endif

	lsw_conf_free_oco();	/* free global_oco containing path names */

	free_ifaces();	/* free interface list from memory */
	free_md_pool();	/* free the md pool */
	lsw_nss_shutdown();
	delete_lock();	/* delete any lock files */
	free_virtual_ip();	/* virtual_private= */
	free_pluto_event_list(); /* no libevent evnts beyond this point */
	free_pluto_main();	/* our static chars */

#ifdef USE_DNSSEC
	unbound_ctx_free();
#endif

	/* report memory leaks now, after all free_* calls */
	if (leak_detective)
		report_leaks();
	close_log();	/* close the logfiles */
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_EXIT, status);
#endif
	exit(status);	/* exit, with our error code */
}

void show_setup_plutomain(void)
{
	whack_log(RC_COMMENT, "config setup options:");	/* spacer */
	whack_log(RC_COMMENT, " ");	/* spacer */
	whack_log(RC_COMMENT, "configdir=%s, configfile=%s, secrets=%s, ipsecdir=%s",
		oco->confdir,
		oco->conffile,
		oco->secretsfile,
		oco->confddir);

	whack_log(RC_COMMENT, "nssdir=%s, dumpdir=%s, statsbin=%s",
		oco->nssdir,
		coredir,
		pluto_stats_binary == NULL ? "unset" :  pluto_stats_binary);

#ifdef USE_DNSSEC
	whack_log(RC_COMMENT, "dnssec-rootkey-file=%s, dnssec-trusted=%s",
		pluto_dnssec_rootfile == NULL ? "<unset>" : pluto_dnssec_rootfile,
		pluto_dnssec_trusted == NULL ? "<unset>" : pluto_dnssec_trusted);
#endif

	whack_log(RC_COMMENT, "sbindir=%s, libexecdir=%s",
		IPSEC_SBINDIR,
		IPSEC_EXECDIR);

	whack_log(RC_COMMENT, "pluto_version=%s, pluto_vendorid=%s",
		ipsec_version_code(),
		pluto_vendorid);

	whack_log(RC_COMMENT,
		"nhelpers=%d, uniqueids=%s, "
		"dnssec-enable=%s, "
		"perpeerlog=%s, logappend=%s, logip=%s, shuntlifetime=%jds, xfrmlifetime=%jds",
		nhelpers,
		bool_str(uniqueIDs),
		bool_str(do_dnssec),
		log_to_perpeer ? peerlog_basedir : "no",
		bool_str(log_append),
		bool_str(log_ip),
		deltasecs(pluto_shunt_lifetime),
		(intmax_t) pluto_xfrmlifetime
	);

	whack_log(RC_COMMENT,
		"ddos-cookies-threshold=%d, ddos-max-halfopen=%d, ddos-mode=%s",
		pluto_max_halfopen,
		pluto_ddos_threshold,
		(pluto_ddos_mode == DDOS_AUTO) ? "auto" :
			(pluto_ddos_mode == DDOS_FORCE_BUSY) ? "busy" : "unlimited");

	whack_log(RC_COMMENT,
		"ikeport=%d, ikebuf=%d, msg_errqueue=%s, strictcrlpolicy=%s, crlcheckinterval=%jd, listen=%s, nflog-all=%d",
		pluto_port,
		pluto_sock_bufsize,
		bool_str(pluto_sock_errqueue),
		bool_str(crl_strict),
		deltasecs(crl_check_interval),
		pluto_listen != NULL ? pluto_listen : "<any>",
		pluto_nflog_group
		);

	whack_log(RC_COMMENT,
		"ocsp-enable=%s, ocsp-strict=%s, ocsp-timeout=%d, ocsp-uri=%s",
		bool_str(ocsp_enable),
		bool_str(ocsp_strict),
		ocsp_timeout,
		ocsp_uri != NULL ? ocsp_uri : "<unset>"
		);
	whack_log(RC_COMMENT,
		"ocsp-trust-name=%s",
		ocsp_trust_name != NULL ? ocsp_trust_name : "<unset>"
		);

	whack_log(RC_COMMENT,
		"ocsp-cache-size=%d, ocsp-cache-min-age=%d, ocsp-cache-max-age=%d, ocsp-method=%s",
		ocsp_cache_size, ocsp_cache_min_age, ocsp_cache_max_age,
		ocsp_method == OCSP_METHOD_GET ? "get" : "post"
		);

#ifdef HAVE_LABELED_IPSEC
	whack_log(RC_COMMENT, "secctx-attr-type=%d", secctx_attr_type);
#else
	whack_log(RC_COMMENT, "secctx-attr-type=<unsupported>");
#endif
}

