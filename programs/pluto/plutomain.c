/* Pluto main program
 *
 * Copyright (C) 1997      Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2016 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2016 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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
#include <unistd.h>	/* for unlink(), write(), close(), access(), et.al. */

#include "optarg.h"
#include "sparse_names.h"
#include "deltatime.h"
#include "timescale.h"
#include "lswversion.h"
#include "lswconf.h"
#include "fips_mode.h"
#include "lswnss.h"
#include "defs.h"
#include "x509_ocsp.h"
#include "server_fork.h"		/* for init_server_fork() */
#include "server.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "log_limiter.h"	/* for init_log_limiter() */
#include "keys.h"
#include "secrets.h"    /* for free_remembered_public_keys() */
#include "hourly.h"
#include "ipsecconf/confread.h"
#include "crypto.h"
#include "vendorid.h"
#include "enum_names.h"
#include "virtual_ip.h"
#include "state_db.h"		/* for init_state_db() */
#include "connection_db.h"	/* for init_connection_db() */
#include "spd_db.h"	/* for init_spd_route_db() */
#include "nat_traversal.h"
#include "ike_alg.h"
#include "ikev2_redirect.h"
#include "root_certs.h"		/* for init_root_certs() */
#include "ikev1_states.h"	/* for init_ikev1_states() */
#include "ikev2_states.h"	/* for init_ikev2_states() */
#include "crypt_symkey.h"	/* for init_crypt_symkey() */
#include "ddns.h"		/* for init_ddns() */
#include "x509_crl.h"		/* for free_crl_queue() */
#include "iface.h"		/* for pluto_listen; */
#include "kernel_info.h"	/* for init_kernel_interface() */
#include "server_pool.h"
#include "show.h"
#include "enum_names.h"		/* for init_enum_names() */
#include "ipsec_interface.h"	/* for config_ipsec_interface()/init_ipsec_interface() */

#ifndef IPSECDIR
#define IPSECDIR "/etc/ipsec.d"
#endif

#ifdef HAVE_LIBCAP_NG
# include <cap-ng.h>	/* rpm:libcap-ng-devel deb:libcap-ng-dev */
#endif

#include "labeled_ipsec.h"		/* for init_labeled_ipsec() */

# include "pluto_sd.h"		/* for pluto_sd_init() */

#ifdef USE_DNSSEC
#include "dnssec.h"
#endif

#ifdef USE_SECCOMP
#include "pluto_seccomp.h"
#endif

static pthread_t main_thread;

bool in_main_thread(void)
{
	return pthread_equal(pthread_self(), main_thread);
}

static char *rundir = NULL;
static bool fork_desired = USE_FORK || USE_DAEMON;
static bool selftest_only = false;

/* pulled from main for show_setup_plutomain() */
static const struct lsw_conf_options *oco;
static char *coredir;
static char *conffile;
static int pluto_nss_seedbits;
static int nhelpers = -1;
static bool do_dnssec = false;
static char *pluto_dnssec_rootkey_file = NULL;
static char *pluto_dnssec_trusted = NULL;

static char *pluto_lock_filename = NULL;
static bool pluto_lock_created = false;


/* Overridden by virtual_private= in ipsec.conf */
static char *virtual_private = NULL;

void free_pluto_main(void)
{
	/* Some values can be NULL if not specified as pluto argument */
	pfree(pluto_lock_filename);
	pfree(coredir);
	pfree(conffile);
	pfreeany(pluto_stats_binary);
	pfreeany(pluto_listen);
	pfree(pluto_vendorid);
	pfreeany(x509_ocsp.uri);
	pfreeany(x509_ocsp.trust_name);
	pfreeany(x509_crl.curl_iface);
	pfreeany(pluto_dnssec_rootkey_file);
	pfreeany(pluto_dnssec_trusted);
	pfreeany(rundir);
	free_global_redirect_dests();
	pfreeany(virtual_private);
}

/* string naming compile-time options that have interop implications */
static const char compile_time_interop_options[] = ""
	" IKEv2"
#ifdef USE_IKEv1
	" IKEv1"
#endif
#ifdef KERNEL_PFKEYV2
	" PFKEYV2"
#endif
#ifdef KERNEL_XFRM
	" XFRM"
#endif
#ifdef USE_XFRM_INTERFACE
	" XFRMI"
#endif
	" esp-hw-offload"
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
	" (IPsec profile)"
#ifdef USE_NSS_KDF
	" (NSS-KDF)"
#else
	" (native-KDF)"
#endif
#ifdef USE_DNSSEC
	" DNSSEC"
#endif
#ifdef USE_SYSTEMD_WATCHDOG
	" SYSTEMD_WATCHDOG"
#endif
#ifdef HAVE_LABELED_IPSEC
	" LABELED_IPSEC"
	" (SELINUX)"
#endif
#ifdef USE_SECCOMP
	" SECCOMP"
#endif
#ifdef HAVE_LIBCAP_NG
	" LIBCAP_NG"
#endif
#ifdef USE_LINUX_AUDIT
	" LINUX_AUDIT"
#endif
#ifdef USE_PAM_AUTH
	" AUTH_PAM"
#endif
#ifdef HAVE_NM
	" NETWORKMANAGER"
#endif
#ifdef USE_LIBCURL
	" CURL(non-NSS)"
#endif
#ifdef USE_LDAP
	" LDAP(non-NSS)"
#endif
#ifdef USE_EFENCE
	" EFENCE"
#endif
#ifdef USE_IPTABLES
	" IPTABLES"
#endif
#ifdef USE_NFTABLES
	" NFTABLES"
#endif
#ifdef USE_CAT
	" CAT"
#endif
#ifdef USE_NFLOG
	" NFLOG"
#endif
#ifdef USE_CISCO_SPLIT
	" CISCO_SPLIT"
#endif
;

/* create lockfile, or die in the attempt */
static int create_lock(struct logger *logger)
{
	if (mkdir(rundir, 0755) != 0) {
		if (errno != EEXIST) {
			fatal_errno(PLUTO_EXIT_LOCK_FAIL, logger, errno,
				    "unable to create lock dir: \"%s\"", rundir);
		}
	}

	unsigned attempt;
	for (attempt = 0; attempt < 2; attempt++) {
		int fd = open(pluto_lock_filename, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
			      S_IRUSR | S_IRGRP | S_IROTH);
		if (fd >= 0) {
			pluto_lock_created = true;
			return fd;
		}
		if (errno != EEXIST) {
			fatal_errno(PLUTO_EXIT_LOCK_FAIL, logger, errno,
				    "unable to create lock file \"%s\"", pluto_lock_filename);
		}
		if (fork_desired) {
			fatal(PLUTO_EXIT_LOCK_FAIL, logger,
			      "lock file \"%s\" already exists", pluto_lock_filename);
		}
		/*
		 * if we did not fork, then we don't really need the pid to
		 * control, so wipe it
		 */
		if (unlink(pluto_lock_filename) == -1) {
			fatal_errno(PLUTO_EXIT_LOCK_FAIL, logger, errno,
				    "lock file \"%s\" already exists and could not be removed",
				    pluto_lock_filename);
		}
		/*
		 * lock file removed, try creating it
		 * again ...
		 */
	}
	fatal(PLUTO_EXIT_LOCK_FAIL, logger, "lock file \"%s\" could not be created after %u attempts",
	      pluto_lock_filename, attempt);
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
void delete_lock(void)
{
	if (pluto_lock_created) {
		delete_ctl_socket();
		unlink(pluto_lock_filename);	/* is noting failure useful? */
	}
}

/* Read config file. exit() on error. */
static struct starter_config *read_cfg_file(char *configfile, struct logger *logger)
{
	struct starter_config *cfg = NULL;

	/* "config setup" only */
	cfg = confread_load(configfile, true, logger, 0/*no-verbosity*/);
	if (cfg == NULL) {
		/* details already logged */
		optarg_fatal(logger, "cannot load config file '%s'\n", configfile);
	}

	return cfg;
}

/*
 * Helper function for config file mapper: set string option value.
 * Values passed in are expected to have been allocated using our
 * own functions.
 */

static void replace_value(char **target, const char *value)
{
	pfreeany(*target);
	*target = clone_str(value, __func__);
}

static void replace_when_cfg_setup(char **target, const struct starter_config *cfg,
				   enum keywords field)
{
	/* Do nothing if value is unset. */
	const char *value = cfg->setup[field].string;
	if (value == NULL || *value == '\0')
		return;
	replace_value(target, value);
}

/*
 * This function MUST NOT be used for anything else!
 * It is used to seed the NSS PRNG based on --seedbits pluto argument
 * or the seedbits= * config setup option in ipsec.conf.
 * Everything else that needs random MUST use get_rnd_bytes()
 * This function MUST NOT be changed to use /dev/urandom.
 */
static void get_bsi_random(size_t nbytes, unsigned char *buf, struct logger *logger)
{
	size_t ndone;
	int dev;
	ssize_t got;
	const char *device = "/dev/random";

	dev = open(device, 0);
	if (dev < 0) {
		fatal_errno(PLUTO_EXIT_NSS_FAIL, logger, errno,
			    "could not open %s", device);
	}

	ndone = 0;
	dbg("need %d bits random for extra seeding of the NSS PRNG",
	    (int) nbytes * BITS_IN_BYTE);

	while (ndone < nbytes) {
		got = read(dev, buf + ndone, nbytes - ndone);
		if (got < 0) {
			fatal_errno(PLUTO_EXIT_NSS_FAIL, logger, errno,
				    "read error on %s", device);
		}
		if (got == 0) {
			fatal(PLUTO_EXIT_NSS_FAIL, logger, "EOF on %s!?!\n",  device);
		}
		ndone += got;
	}
	close(dev);
	dbg("read %zu bytes from /dev/random for NSS PRNG", nbytes);
}

static void pluto_init_nss(const char *nssdir, struct logger *logger)
{
	init_nss(nssdir, (struct nss_flags) { .open_readonly = true}, logger);
	llog(RC_LOG, logger, "NSS crypto library initialized");

	/*
	 * This exists purely to make the BSI happy.
	 * We do not inflict this on other users
	 */
	if (pluto_nss_seedbits != 0) {
		int seedbytes = BYTES_FOR_BITS(pluto_nss_seedbits);
		unsigned char *buf = alloc_bytes(seedbytes, "TLA seedmix");

		get_bsi_random(seedbytes, buf, logger); /* much TLA, very blocking */
		SECStatus rv = PK11_RandomUpdate(buf, seedbytes);
		llog(RC_LOG, logger, "seeded %d bytes into the NSS PRNG", seedbytes);
		passert(rv == SECSuccess);
		messupn(buf, seedbytes);
		pfree(buf);
	}
}

/*
 * Table of Pluto command-line options.
 *
 * For getopt_long(3), but with twists.
 *
 * We never find that letting getopt set an option makes sense
 * so flag is always NULL.
 *
 * Trick:
 *
 * Each "name" string is split by an explicit '\0'.  Before the '\0'
 * is the option name, as seen by getopt_long.  After the '\0' is
 * meta-information where:
 *
 * - _ means: obsolete due to _ in name: replace _ with -
 * - > means: obsolete spelling; use spelling from rest of string
 * - ! means: obsolete and ignored (no replacement)
 * - anything else is a description of the options argument (printed by --help)
 *   If it starts with ^, that means start a newline in the --help output.
 *
 * The table should be ordered to maximize the clarity of --help.
 */

enum opt {
	OPT_EFENCE_PROTECT = 256, /* larger than a character */
	OPT_DEBUG,
	OPT_IMPAIR,
	OPT_DNSSEC_ROOTKEY_FILE,
	OPT_DNSSEC_TRUSTED,
	OPT_HELP,
	OPT_CONFIG,
	OPT_VERSION,
	OPT_NOFORK,
	OPT_STDERRLOG,
	OPT_LOGFILE,
	OPT_LOG_NO_TIME,
	OPT_LOG_NO_APPEND,
	OPT_LOG_NO_IP,
	OPT_LOG_NO_AUDIT,
	OPT_DROP_OPPO_NULL,
	OPT_FORCE_BUSY,
	OPT_FORCE_UNLIMITED,
	OPT_CRL_STRICT,
	OPT_OCSP_STRICT,
	OPT_OCSP_ENABLE,
	OPT_OCSP_URI,
	OPT_OCSP_TIMEOUT,
	OPT_OCSP_TRUSTNAME,
	OPT_OCSP_CACHE_SIZE,
	OPT_OCSP_CACHE_MIN_AGE,
	OPT_OCSP_CACHE_MAX_AGE,
	OPT_OCSP_METHOD,
	OPT_CRLCHECKINTERVAL,
	OPT_UNIQUEIDS,
	OPT_NO_DNSSEC,
	OPT_USE_PFKEYV2,
	OPT_USE_XFRM,
	OPT_INTERFACE,
	OPT_CURL_IFACE,
	OPT_CURL_TIMEOUT, /* legacy, don't replace */
	OPT_LISTEN,
	OPT_LISTEN_TCP,
	OPT_NO_LISTEN_UDP,
	OPT_IKE_SOCKET_BUFSIZE,
	OPT_IKE_SOCKET_NO_ERRQUEUE,
#ifdef USE_NFLOG
	OPT_NFLOG_ALL,
#endif
	OPT_RUNDIR,
	OPT_SECRETSFILE,
	OPT_GLOBAL_REDIRECT,
	OPT_GLOBAL_REDIRECT_TO,
	OPT_DUMPDIR,
	OPT_STATSBIN,
	OPT_IPSECDIR,
	OPT_NSSDIR,
	OPT_KEEP_ALIVE,
	OPT_VIRTUAL_PRIVATE,
	OPT_NHELPERS,
	OPT_EXPIRE_SHUNT_INTERVAL,
	OPT_SEEDBITS,
	OPT_IKEV1_SECCTX_ATTR_TYPE,
	OPT_IKEV1_REJECT,
	OPT_IKEV1_DROP,
	OPT_SECCOMP_ENABLED,
	OPT_SECCOMP_TOLERANT,
	OPT_VENDORID,
	OPT_SELFTEST,
	OPT_LEAK_DETECTIVE,
	OPT_DEBUG_NONE,
	OPT_DEBUG_ALL,
};

const struct option optarg_options[] = {
	/* name, has_arg, flag, val */
	{ "help\0", no_argument, NULL, OPT_HELP },
	{ "version\0", no_argument, NULL, OPT_VERSION },
	{ "config\0<filename>", required_argument, NULL, OPT_CONFIG },
	{ "nofork\0", no_argument, NULL, OPT_NOFORK },
	{ "stderrlog\0", no_argument, NULL, OPT_STDERRLOG },
	{ "logfile\0<filename>", required_argument, NULL, OPT_LOGFILE },
#ifdef USE_DNSSEC
	{ "dnssec-rootkey-file\0<filename>", required_argument, NULL, OPT_DNSSEC_ROOTKEY_FILE },
	{ "dnssec-trusted\0<filename>", required_argument, NULL, OPT_DNSSEC_TRUSTED },
#endif
	{ "log-no-time\0", no_argument, NULL, OPT_LOG_NO_TIME }, /* was --plutostderrlogtime */
	{ "log-no-append\0", no_argument, NULL, OPT_LOG_NO_APPEND },
	{ "log-no-ip\0", no_argument, NULL, OPT_LOG_NO_IP },
	{ "log-no-audit\0", no_argument, NULL, OPT_LOG_NO_AUDIT },
	{ "force-busy\0", no_argument, NULL, OPT_FORCE_BUSY },
	{ "force-unlimited\0", no_argument, NULL, OPT_FORCE_UNLIMITED },
	{ "crl-strict\0", no_argument, NULL, OPT_CRL_STRICT },
	{ "ocsp-strict\0", no_argument, NULL, OPT_OCSP_STRICT },
	{ "ocsp-enable\0", no_argument, NULL, OPT_OCSP_ENABLE },
	{ "ocsp-uri\0", required_argument, NULL, OPT_OCSP_URI },
	{ "ocsp-timeout\0", required_argument, NULL, OPT_OCSP_TIMEOUT },
	{ "ocsp-trustname\0", required_argument, NULL, OPT_OCSP_TRUSTNAME },
	{ "ocsp-cache-size\0", required_argument, NULL, OPT_OCSP_CACHE_SIZE },
	{ "ocsp-cache-min-age\0", required_argument, NULL, OPT_OCSP_CACHE_MIN_AGE },
	{ "ocsp-cache-max-age\0", required_argument, NULL, OPT_OCSP_CACHE_MAX_AGE },
	{ "ocsp-method\0", required_argument, NULL, OPT_OCSP_METHOD },
	{ "crlcheckinterval\0", required_argument, NULL, OPT_CRLCHECKINTERVAL },
	{ "uniqueids\0", no_argument, NULL, OPT_UNIQUEIDS },
	{ "no-dnssec\0", no_argument, NULL, OPT_NO_DNSSEC },
#ifdef KERNEL_PFKEYV2
	{ "use-pfkeyv2\0",   no_argument, NULL, OPT_USE_PFKEYV2 },
#endif
#ifdef KERNEL_XFRM
	{ "use-xfrm\0", no_argument, NULL, OPT_USE_XFRM },
#endif
	{ "interface"METAOPT_OBSOLETE"<ifname|ifaddr>", required_argument, NULL, OPT_INTERFACE }, /* reserved; not implemented */
	{ "curl-iface\0<ifname|ifaddr>", required_argument, NULL, OPT_CURL_IFACE },
	{ "curl-timeout\0<secs>", required_argument, NULL, OPT_CURL_TIMEOUT }, /* legacy */
	{ "listen\0<ifaddr>", required_argument, NULL, OPT_LISTEN },
	{ "listen-tcp\0", no_argument, NULL, OPT_LISTEN_TCP },
	{ "no-listen-udp\0", no_argument, NULL, OPT_NO_LISTEN_UDP },
	{ "ike-socket-bufsize\0<bytes>", required_argument, NULL, OPT_IKE_SOCKET_BUFSIZE },
	{ "ike-socket-no-errqueue\0", no_argument, NULL, OPT_IKE_SOCKET_NO_ERRQUEUE },
#ifdef USE_NFLOG
	{ "nflog-all\0<group-number>", required_argument, NULL, OPT_NFLOG_ALL },
#endif
	{ "rundir\0<path>", required_argument, NULL, OPT_RUNDIR }, /* was ctlbase */
	{ "secretsfile\0<secrets-file>", required_argument, NULL, OPT_SECRETSFILE },
	{ "global-redirect\0", required_argument, NULL, OPT_GLOBAL_REDIRECT},
	{ "global-redirect-to\0", required_argument, NULL, OPT_GLOBAL_REDIRECT_TO},
	{ "coredir\0>dumpdir", required_argument, NULL, OPT_DUMPDIR },	/* redundant spelling */
	{ "dumpdir\0<dirname>", required_argument, NULL, OPT_DUMPDIR },
	{ "statsbin\0<filename>", required_argument, NULL, OPT_STATSBIN },
	{ "ipsecdir\0<ipsec-dir>", required_argument, NULL, OPT_IPSECDIR },
	{ "foodgroupsdir\0>ipsecdir", required_argument, NULL, OPT_IPSECDIR },	/* redundant spelling */
	{ "nssdir\0<path>", required_argument, NULL, OPT_NSSDIR },	/* nss-tools use -d */
	{ "keep-alive\0<delay_secs>", required_argument, NULL, OPT_KEEP_ALIVE },
	{ "virtual-private\0<network_list>", required_argument, NULL, OPT_VIRTUAL_PRIVATE },
	{ "nhelpers\0<number>", required_argument, NULL, OPT_NHELPERS },
	{ "expire-shunt-interval\0<secs>", required_argument, NULL, OPT_EXPIRE_SHUNT_INTERVAL },
	{ "seedbits\0<number>", required_argument, NULL, OPT_SEEDBITS },
	/* really an attribute type, not a value */
	{ "ikev1-secctx-attr-type\0<number>", required_argument, NULL, OPT_IKEV1_SECCTX_ATTR_TYPE },
	{ "ikev1-reject\0", no_argument, NULL, OPT_IKEV1_REJECT },
	{ "ikev1-drop\0", no_argument, NULL, OPT_IKEV1_DROP },
#ifdef USE_SECCOMP
	{ "seccomp-enabled\0", no_argument, NULL, OPT_SECCOMP_ENABLED },
	{ "seccomp-tolerant\0", no_argument, NULL, OPT_SECCOMP_TOLERANT },
#endif
	{ "vendorid\0<vendorid>", required_argument, NULL, OPT_VENDORID },

	{ "selftest\0", no_argument, NULL, OPT_SELFTEST },

	{ "leak-detective\0", no_argument, NULL, OPT_LEAK_DETECTIVE },
	{ "efence-protect\0", no_argument, NULL, OPT_EFENCE_PROTECT, },
	{ "drop-oppo-null", no_argument, NULL, OPT_DROP_OPPO_NULL, },
	{ "debug-none"METAOPT_NEWLINE, no_argument, NULL, OPT_DEBUG_NONE },
	{ "debug-all\0", no_argument, NULL, OPT_DEBUG_ALL },
	{ "debug\0", required_argument, NULL, OPT_DEBUG, },
	{ "impair\0", required_argument, NULL, OPT_IMPAIR, },

	{ 0, 0, 0, 0 }
};

/*
 * HACK: check UGH, and if it is bad, log it along with the option.
 */

static void check_err(struct logger *logger, err_t ugh)
{
	if (ugh != NULL) {
		optarg_fatal(logger, "%s", ugh);
	}
}

static void check_diag(struct logger *logger, diag_t d)
{
	if (d != NULL) {
		optarg_fatal(logger, "%s", str_diag(d));
	}
}

static void check_conf(diag_t d, const char *conf, struct logger *logger)
{
	if (d == NULL) {
		return;
	}

	/*
	 * Not exit_pluto() or fatal() as pluto isn't yet up and
	 * running?
	 */
	PEXPECT(logger, conffile != NULL);
	LLOG_JAMBUF(RC_LOG, logger, buf) {
		if (conffile != NULL) {
			jam_string(buf, conffile);
			jam_string(buf, ": ");
		}
		jam_string(buf, "configuration ");
		jam_string(buf, conf);
		jam_string(buf, " invalid: ");
		jam_diag(buf, d);
	}
	exit(PLUTO_EXIT_FAIL);
}

static diag_t deltatime_ok(deltatime_t timeout, int lower, int upper)
{
	if (lower >= 0 && deltatime_cmp(timeout, <, deltatime(lower))) {
		return diag("too small, less than %us", lower);
	}
	if (upper >= 0 && deltatime_cmp(timeout, >, deltatime(upper))) {
		return diag("too big, more than %us", upper);
	}
	return NULL;
}

#ifdef USE_DNSSEC
static void set_dnssec_file_names (struct starter_config *cfg)
{
	/*
	 * The default config value is DEFAULT_DNSSEC_ROOTKEY_FILE,
	 * and not NULL, so always replace; but only with something
	 * non empty.
	 */
	pfreeany(pluto_dnssec_rootkey_file);
	if (cfg->setup[KSF_PLUTO_DNSSEC_ROOTKEY_FILE].string[0] != '\0') {
		pluto_dnssec_rootkey_file = clone_str(cfg->setup[KSF_PLUTO_DNSSEC_ROOTKEY_FILE].string, __func__);
	}
	replace_when_cfg_setup(&pluto_dnssec_trusted, cfg, KSF_PLUTO_DNSSEC_ANCHORS);
}
#endif

#ifdef USE_EFENCE
extern int EF_PROTECT_BELOW;
extern int EF_PROTECT_FREE;
#endif

int main(int argc, char **argv)
{
	/*
	 * DANGER!
	 *
	 * Some options MUST be processed before the first malloc()
	 * call, so scan for them here:
	 *
	 * - leak-detective is immutable, it must come before the
	 *   first malloc()
	 *
	 * - efence-protect seems to be less strict, but enabling it
	 *   early must be a good thing (TM) right?
	 */
	for (int i = 1; i < argc; ++i) {
		if (streq(argv[i], "--leak-detective")) {
			leak_detective = true;
			continue;
		}
#ifdef USE_EFENCE
		if (streq(argv[i], "--efence-protect")) {
			EF_PROTECT_BELOW = 1;
			EF_PROTECT_FREE = 1;
			continue;
		}
#endif
	}

	/*
	 * Start with the program name as the logger prefix with
	 * things going to stderr.
	 *
	 * At this point the global log structures are set up to log
	 * to stdout/stderr.
	 *
	 * The next step is to read the intentions for how to log from
	 * command line options and the config file. Then we prepare
	 * to be able to log, but until then log to stderr (better
	 * then nothing).  Once we are ready to actually do logging
	 * according to the methods desired, we set the variables for
	 * those methods
	 */

	argv[0] = "ipsec pluto";
	struct logger *logger = init_log(argv[0]);	/* must free */

	struct log_param log_param = {
		.log_with_timestamp = true,
	};

	/*
	 * More sanity checks.
	 */
	kernel_ops = kernel_stacks[0];
	PASSERT(logger, kernel_ops != NULL);

	/*
	 * Identify the main thread.
	 *
	 * Also used as a reserved thread for code wanting to
	 * determine if it is running on an aux thread.
	 */
	main_thread = pthread_self();

	/*
	 * Make memory management easier by always allocating some of
	 * the globals.
	 */
	conffile = clone_str(IPSEC_CONF, "conffile in main()");
	coredir = clone_str(IPSEC_RUNDIR, "coredir in main()");
	rundir = clone_str(IPSEC_RUNDIR, "rundir");
	pluto_vendorid = clone_str(ipsec_version_vendorid(), "vendorid in main()");
#ifdef USE_DNSSEC
	pluto_dnssec_rootkey_file = clone_str(DEFAULT_DNSSEC_ROOTKEY_FILE, "root.key file");
#endif
	pluto_lock_filename = clone_str(IPSEC_RUNDIR "/pluto.pid", "lock file");
	deltatime_t keep_alive = {0}; /* aka unset */

	/* handle arguments */
	for (;; ) {

		/*
		 * Note: we don't like the way short options get
		 * parsed by getopt_long, so we simply pass an empty
		 * string as the list.  It could be "hvdenp:l:s:"
		 * "NARXPECK".
		 */
		int c = optarg_getopt(logger, argc, argv, "");
		if (c < 0) {
			break;
		}

		switch ((enum opt)c) {

		case OPT_HELP:	/* --help */
			/* writes to STDOUT so <<| more>> works */
			optarg_usage("ipsec pluto", "", "");

		case OPT_LEAK_DETECTIVE:	/* --leak-detective */
			/*
			 * This flag was already processed at the start of main()
			 * because leak_detective must be immutable from before
			 * the first alloc().
			 * If this option is specified, we must have already
			 * set it at the start of main(), so assert it.
			 */
			passert(leak_detective);
			continue;

		case OPT_DUMPDIR:	/* --dumpdir */
			pfree(coredir);
			coredir = clone_str(optarg, "coredir via getopt");
			continue;

		case OPT_VENDORID:	/* --vendorid */
			pfree(pluto_vendorid);
			pluto_vendorid = clone_str(optarg, "pluto_vendorid via getopt");
			continue;

		case OPT_STATSBIN:	/* --statsdir */
			pfreeany(pluto_stats_binary);
			pluto_stats_binary = clone_str(optarg, "statsbin");
			continue;

		case OPT_VERSION:	/* --version */
			printf("%s%s\n", ipsec_version_string(), /* ok */
			       compile_time_interop_options);
			/* not exit_pluto because we are not initialized yet */
			exit(PLUTO_EXIT_OK);

		case OPT_NHELPERS:	/* --nhelpers */
			if (streq(optarg, "-1")) {
				/* use number of CPUs */
				nhelpers = -1;
			} else {
				uintmax_t u = optarg_uintmax(logger);
				/* arbitrary */
				if (u > 1000) {
					optarg_fatal(logger, "too big, more than 1000");
				}
				nhelpers = u; /* no loss; within INT_MAX */
			}
			continue;

		case OPT_SEEDBITS:	/* --seedbits */
			pluto_nss_seedbits = optarg_uintmax(logger);
			if (pluto_nss_seedbits == 0) {
				optarg_fatal(logger, "seedbits must be an integer > 0");
			}
			continue;

		case OPT_IKEV1_SECCTX_ATTR_TYPE:	/* --secctx-attr-type */
			llog(RC_LOG, logger, "--secctx-attr-type not supported");
			continue;

		case OPT_IKEV1_REJECT:	/* --ikev1-reject */
			pluto_ikev1_pol = GLOBAL_IKEv1_REJECT;
			continue;

		case OPT_IKEV1_DROP:	/* --ikev1-drop */
			pluto_ikev1_pol = GLOBAL_IKEv1_DROP;
			continue;

		case OPT_NOFORK:	/* --nofork*/
			fork_desired = false;
			continue;

		case OPT_STDERRLOG:	/* --stderrlog */
			log_param.log_to_stderr = true;
			continue;

		case OPT_LOGFILE:	/* --logfile */
			replace_value(&log_param.log_to_file, optarg);
			continue;

#ifdef USE_DNSSEC
		case OPT_DNSSEC_ROOTKEY_FILE:	/* --dnssec-rootkey-file */
			/*
			 * The default config value is
			 * DEFAULT_DNSSEC_ROOTKEY_FILE, and not NULL,
			 * so always replace; but only with something
			 * non empty.
			 */
			pfreeany(pluto_dnssec_rootkey_file);
			if (optarg[0] != '\0') {
				pluto_dnssec_rootkey_file = clone_str(optarg, "dnssec-rootkey-file");
			}
			continue;
#endif  /* USE_DNSSEC */

#ifdef USE_DNSSEC
		case OPT_DNSSEC_TRUSTED:	/* --dnssec-trusted */
			replace_value(&pluto_dnssec_trusted, optarg);
			continue;
#endif  /* USE_DNSSEC */

		case OPT_LOG_NO_TIME:	/* --log-no-time */
			log_param.log_with_timestamp = false;
			continue;

		case OPT_LOG_NO_APPEND:	/* --log-no-append */
			log_param.append = false;
			continue;

		case OPT_LOG_NO_IP:	/* --log-no-ip */
			log_ip = false;
			continue;

		case OPT_LOG_NO_AUDIT:	/* --log-no-audit */
			log_to_audit = false;
			continue;

		case OPT_DROP_OPPO_NULL:	/* --drop-oppo-null */
			pluto_drop_oppo_null = true;
			continue;

		case OPT_EXPIRE_SHUNT_INTERVAL:	/* --expire-shunt-interval <interval> */
			bare_shunt_interval = optarg_deltatime(logger, TIMESCALE_SECONDS);
			check_diag(logger, deltatime_ok(bare_shunt_interval, 1, 1000));
			continue;

		case OPT_LISTEN:	/* --listen ip_addr */
		{
			ip_address lip;
			err_t e = ttoaddress_num(shunk1(optarg), NULL/*UNSPEC*/, &lip);

			if (e != NULL) {
				/*
				 * ??? should we continue on failure?
				 */
				llog(RC_LOG, logger,
					    "invalid listen argument ignored: %s\n", e);
				continue;
			}

			replace_value(&pluto_listen, optarg);
			llog(RC_LOG, logger,
			     "bind() will be filtered for %s", pluto_listen);
			continue;
		}

		case OPT_USE_PFKEYV2:	/* --use-pfkeyv2 */
#ifdef KERNEL_PFKEYV2
			kernel_ops = &pfkeyv2_kernel_ops;
#else
			llog(RC_LOG, logger, "--use-pfkeyv2 not supported");
#endif
			continue;

		case OPT_USE_XFRM:	/* --use-netkey */
#ifdef KERNEL_XFRM
			kernel_ops = &xfrm_kernel_ops;
#else
			llog(RC_LOG, logger, "--use-xfrm not supported");
#endif
			continue;

		case OPT_FORCE_BUSY:	/* --force-busy */
			pluto_ddos_mode = DDOS_FORCE_BUSY;
			continue;
		case OPT_FORCE_UNLIMITED:	/* --force-unlimited */
			pluto_ddos_mode = DDOS_FORCE_UNLIMITED;
			continue;

#ifdef USE_SECCOMP
		case OPT_SECCOMP_ENABLED:	/* --seccomp-enabled */
			pluto_seccomp_mode = SECCOMP_ENABLED;
			continue;
		case OPT_SECCOMP_TOLERANT:	/* --seccomp-tolerant */
			pluto_seccomp_mode = SECCOMP_TOLERANT;
			continue;
#endif

		case OPT_CURL_IFACE:	/* --curl-iface */
			replace_value(&x509_crl.curl_iface, optarg);
			continue;

		case OPT_CURL_TIMEOUT:	/* --curl-timeout */
			x509_crl.timeout = optarg_deltatime(logger, TIMESCALE_SECONDS);
#define CRL_TIMEOUT_OK deltatime_ok(x509_crl.timeout, 1, 1000)
			check_diag(logger, CRL_TIMEOUT_OK);
			continue;

		case OPT_CRL_STRICT:	/* --crl-strict */
			x509_crl.strict = true;
			continue;

		case OPT_CRLCHECKINTERVAL:	/* --crlcheckinterval <seconds> */
			x509_crl.check_interval = optarg_deltatime(logger, TIMESCALE_SECONDS);
			continue;

		case OPT_OCSP_STRICT:
			x509_ocsp.strict = true;
			continue;

		case OPT_OCSP_ENABLE:
			x509_ocsp.enable = true;
			continue;

		case OPT_OCSP_URI:
			replace_value(&x509_ocsp.uri, optarg);
			continue;

		case OPT_OCSP_TRUSTNAME:
			replace_value(&x509_ocsp.trust_name, optarg);
			continue;

		case OPT_OCSP_TIMEOUT:	/* --ocsp-timeout <seconds> */
			x509_ocsp.timeout = optarg_deltatime(logger, TIMESCALE_SECONDS);
#define OCSP_TIMEOUT_OK deltatime_ok(x509_ocsp.timeout, 1, 1000)
			check_diag(logger, OCSP_TIMEOUT_OK);
			continue;

		case OPT_OCSP_CACHE_SIZE:	/* --ocsp-cache-size <entries> */
		{
			uintmax_t u;
			check_err(logger, shunk_to_uintmax(shunk1(optarg), NULL/*all*/,
							   0/*any-base*/, &u));
			/* Why 64k? UDP payload size? */
			if (u > 0xffff) {
				optarg_fatal(logger, "too big, more than 0xffff");
			}
			x509_ocsp.cache_size = u; /* no loss; within INT_MAX */
			continue;
		}

		case OPT_OCSP_CACHE_MIN_AGE:	/* --ocsp-cache-min-age <seconds> */
			x509_ocsp.cache_min_age = optarg_deltatime(logger, TIMESCALE_SECONDS);
#define OCSP_CACHE_MIN_AGE_OK deltatime_ok(x509_ocsp.cache_min_age, 1, -1)
			check_diag(logger, OCSP_CACHE_MIN_AGE_OK);
			continue;

		case OPT_OCSP_CACHE_MAX_AGE:	/* --ocsp-cache-max-age <seconds> */
			/*
			 * NSS uses 0 for unlimited and -1 for
			 * disabled.  We use 0 for disabled, and a
			 * large number for unlimited.
			 */
			x509_ocsp.cache_max_age = optarg_deltatime(logger, TIMESCALE_SECONDS);
#define OCSP_CACHE_MAX_AGE_OK deltatime_ok(x509_ocsp.cache_max_age, 0, -1)
			check_diag(logger, OCSP_CACHE_MAX_AGE_OK);
			continue;

		case OPT_OCSP_METHOD:	/* --ocsp-method get|post */
			x509_ocsp.method = optarg_sparse(logger, 0, &ocsp_method_names);
			continue;

		case OPT_UNIQUEIDS:	/* --uniqueids */
			uniqueIDs = true;
			continue;

		case OPT_NO_DNSSEC:	/* --no-dnssec */
			do_dnssec = false;
			continue;

		case OPT_INTERFACE:	/* --interface <ifname|ifaddr> */
			continue;

#ifdef USE_NFLOG
		case OPT_NFLOG_ALL:	/* --nflog-all <group-number> */
			pluto_nflog_group = optarg_uintmax(logger);
			continue;
#endif

		case OPT_IKE_SOCKET_NO_ERRQUEUE:	/* --ike-socket-no-errqueue */
			pluto_sock_errqueue = false;
			continue;

		case OPT_IKE_SOCKET_BUFSIZE:	/* --ike-socket-bufsize <bufsize> */
			pluto_sock_bufsize = optarg_udp_bufsize(logger);
			continue;

		case OPT_NO_LISTEN_UDP:	/* --no-listen-udp */
			pluto_listen_udp = false;
			continue;

		case OPT_LISTEN_TCP:	/* --listen-tcp */
			pluto_listen_tcp = true;
			continue;

		case OPT_RUNDIR:	/* --rundir <path> */
		{
			int n = snprintf(ctl_addr.sun_path, sizeof(ctl_addr.sun_path),
					 "%s/pluto.ctl", optarg);
			if (n < 0 || n >= (ssize_t)sizeof(ctl_addr.sun_path)) {
				optarg_fatal(logger, "argument is invalid for sun_path socket");
			}

			pfree(pluto_lock_filename);
			pluto_lock_filename = alloc_printf("%s/pluto.pid", optarg);
			pfreeany(rundir);
			rundir = clone_str(optarg, "rundir");
			continue;
		}

		case OPT_SECRETSFILE:	/* --secretsfile <secrets-file> */
			lsw_conf_secretsfile(optarg);
			continue;

		case OPT_IPSECDIR:	/* --ipsecdir <ipsec-dir> */
			lsw_conf_confddir(optarg, logger);
			continue;

		case OPT_NSSDIR:	/* --nssdir <path> */
			lsw_conf_nssdir(optarg, logger);
			continue;

		case OPT_DEBUG_NONE:	/* --debug-none */
			cur_debugging = DBG_NONE;
			continue;

		case OPT_DEBUG_ALL:	/* --debug-all */
			cur_debugging = DBG_ALL;
			continue;

		case OPT_GLOBAL_REDIRECT_TO:	/* --global-redirect-to */
		{
			ip_address rip;
			check_err(logger, ttoaddress_dns(shunk1(optarg), NULL/*UNSPEC*/, &rip));
			set_global_redirect_dests(optarg);
			llog(RC_LOG, logger,
			     "all IKE_SA_INIT requests will from now on be redirected to: %s\n",
			     optarg);
			continue;
		}

		case OPT_GLOBAL_REDIRECT:	/* --global-redirect */
		{
			if (streq(optarg, "yes")) {
				global_redirect = GLOBAL_REDIRECT_YES;
			} else if (streq(optarg, "no")) {
				global_redirect = GLOBAL_REDIRECT_NO;
			} else if (streq(optarg, "auto")) {
				global_redirect = GLOBAL_REDIRECT_AUTO;
			} else {
				llog(RC_LOG, logger,
				     "invalid option argument for global-redirect (allowed arguments: yes, no, auto)");
			}
			continue;
		}

		case OPT_KEEP_ALIVE:	/* --keep-alive <delay_secs> */
			keep_alive = optarg_deltatime(logger, TIMESCALE_SECONDS);
			continue;

		case OPT_SELFTEST:	/* --selftest */
			selftest_only = true;
			log_param.log_to_stderr = true;
			log_param.log_with_timestamp = false;
			fork_desired = false;
			continue;

		case OPT_VIRTUAL_PRIVATE:	/* --virtual-private */
			replace_value(&virtual_private, optarg);
			continue;

		case OPT_CONFIG:	/* --config */
		{
			/*
			 * Config struct to variables mapper.  This
			 * will overwrite all previously set options.
			 *
			 * Keep this in the same order as
			 * optarg_options[] is.
			 */
			pfree(conffile);
			conffile = clone_str(optarg, "conffile via getopt");
			/* may not return */
			struct starter_config *cfg = read_cfg_file(conffile, logger);

			replace_when_cfg_setup(&log_param.log_to_file, cfg, KSF_LOGFILE);
#ifdef USE_DNSSEC
			set_dnssec_file_names(cfg);
#endif

			/* plutofork= no longer supported via config file */
			log_param.log_with_timestamp = cfg->setup[KBF_LOGTIME].option;
			log_param.append = cfg->setup[KBF_LOGAPPEND].option;
			log_ip = cfg->setup[KBF_LOGIP].option;
			log_to_audit = cfg->setup[KBF_AUDIT_LOG].option;
			pluto_drop_oppo_null = cfg->setup[KBF_DROP_OPPO_NULL].option;
			pluto_ddos_mode = cfg->setup[KBF_DDOS_MODE].option;
			pluto_ikev1_pol = cfg->setup[KBF_GLOBAL_IKEv1].option;
#ifndef USE_IKEv1
			if (pluto_ikev1_pol != GLOBAL_IKEv1_DROP) {
				llog(RC_LOG, logger, "ignoring ikev1-policy= as IKEv1 support is not compiled in. Incoming IKEv1 packets will be dropped");
				pluto_ikev1_pol = GLOBAL_IKEv1_DROP;
			}
#endif
#ifdef USE_SECCOMP
			pluto_seccomp_mode = cfg->setup[KBF_SECCOMP].option;
#endif
			if (cfg->setup[KBF_FORCEBUSY].option) {
				/* force-busy is obsoleted, translate to ddos-mode= */
				pluto_ddos_mode = cfg->setup[KBF_DDOS_MODE].option = DDOS_FORCE_BUSY;
			}
			/* ddos-ike-threshold and max-halfopen-ike */
			pluto_ddos_threshold = cfg->setup[KBF_DDOS_IKE_THRESHOLD].option;
			pluto_max_halfopen = cfg->setup[KBF_MAX_HALFOPEN_IKE].option;

			x509_crl.strict = cfg->setup[KBF_CRL_STRICT].option;

			if (cfg->setup[KBF_SHUNTLIFETIME].set) {
				pluto_shunt_lifetime = cfg->setup[KBF_SHUNTLIFETIME].deltatime;
			}

			x509_ocsp.enable = cfg->setup[KBF_OCSP_ENABLE].option;
			x509_ocsp.strict = cfg->setup[KBF_OCSP_STRICT].option;
			if (cfg->setup[KBF_OCSP_TIMEOUT_SECONDS].set) {
				x509_ocsp.timeout = cfg->setup[KBF_OCSP_TIMEOUT_SECONDS].deltatime;
				check_conf(OCSP_TIMEOUT_OK, "ocsp-timeout", logger);
			}
			if (cfg->setup[KBF_OCSP_METHOD].set) {
				x509_ocsp.method = cfg->setup[KBF_OCSP_METHOD].option;
			}
			x509_ocsp.cache_size = cfg->setup[KBF_OCSP_CACHE_SIZE].option;
			if (cfg->setup[KBF_OCSP_CACHE_MIN_AGE_SECONDS].set) {
				x509_ocsp.cache_min_age = cfg->setup[KBF_OCSP_CACHE_MIN_AGE_SECONDS].deltatime;
				check_conf(OCSP_CACHE_MIN_AGE_OK, "ocsp-cache-min-age", logger);
			}
			if (cfg->setup[KBF_OCSP_CACHE_MAX_AGE_SECONDS].set) {
				x509_ocsp.cache_max_age = cfg->setup[KBF_OCSP_CACHE_MAX_AGE_SECONDS].deltatime;
				check_conf(OCSP_CACHE_MAX_AGE_OK, "ocsp-cache-max-age", logger);
			}

			replace_when_cfg_setup(&x509_ocsp.uri, cfg, KSF_OCSP_URI);
			replace_when_cfg_setup(&x509_ocsp.trust_name, cfg, KSF_OCSP_TRUSTNAME);

			char *tmp_global_redirect = cfg->setup[KSF_GLOBAL_REDIRECT].string;
			if (tmp_global_redirect == NULL || streq(tmp_global_redirect, "no")) {
				/* NULL means it is not specified so default is no */
				global_redirect = GLOBAL_REDIRECT_NO;
			} else if (streq(tmp_global_redirect, "yes")) {
				global_redirect = GLOBAL_REDIRECT_YES;
			} else if (streq(tmp_global_redirect, "auto")) {
				global_redirect = GLOBAL_REDIRECT_AUTO;
			} else {
				global_redirect = GLOBAL_REDIRECT_NO;
				llog(RC_LOG, logger, "unknown argument for global-redirect option");
			}

			x509_crl.check_interval = cfg->setup[KBF_CRL_CHECKINTERVAL].deltatime;
			uniqueIDs = cfg->setup[KBF_UNIQUEIDS].option;
#ifdef USE_DNSSEC
			do_dnssec = cfg->setup[KBF_DO_DNSSEC].option;
#else
			do_dnssec = false;
#endif
			/*
			 * We don't check interfaces= here, should we?
			 * This was hack because we had _stackmanager?
			 */
			replace_when_cfg_setup(&pluto_listen, cfg, KSF_LISTEN);

			/* ike-socket-bufsize= */
			pluto_sock_bufsize = cfg->setup[KBF_IKEBUF].option;
			pluto_sock_errqueue = cfg->setup[KBF_IKE_ERRQUEUE].option;

			/* listen-tcp= / listen-udp= */
			pluto_listen_tcp = cfg->setup[KBF_LISTEN_TCP].option;
			pluto_listen_udp = cfg->setup[KBF_LISTEN_UDP].option;

#ifdef USE_NFLOG
			/* nflog-all= */
			/* only causes nflog number to show in ipsec status */
			pluto_nflog_group = cfg->setup[KBF_NFLOG_ALL].option;
#endif

#ifdef XFRM_LIFETIME_DEFAULT
			pluto_xfrmlifetime = cfg->setup[KBF_XFRMLIFETIME].option;
#endif

			/* no config option: rundir */
			/* secretsfile= */
			if (cfg->setup[KSF_SECRETSFILE].string &&
			    *cfg->setup[KSF_SECRETSFILE].string) {
				lsw_conf_secretsfile(cfg->setup[KSF_SECRETSFILE].string);
			}
			if (cfg->setup[KSF_IPSECDIR].string != NULL &&
			    *cfg->setup[KSF_IPSECDIR].string != 0) {
				/* ipsecdir= */
				lsw_conf_confddir(cfg->setup[KSF_IPSECDIR].string, logger);
			}

			if (cfg->setup[KSF_NSSDIR].string != NULL &&
			    *cfg->setup[KSF_NSSDIR].string != 0) {
				/* nssdir= */
				lsw_conf_nssdir(cfg->setup[KSF_NSSDIR].string, logger);
			}

			if (cfg->setup[KSF_CURLIFACE].string) {
				replace_value(&x509_crl.curl_iface, cfg->setup[KSF_CURLIFACE].string);
			}

			if (cfg->setup[KBF_CRL_TIMEOUT_SECONDS].set) {
				x509_crl.timeout = cfg->setup[KBF_CRL_TIMEOUT_SECONDS].deltatime;
				check_conf(CRL_TIMEOUT_OK, "crl-timeout", logger);
				/* checked below */
			}

			if (cfg->setup[KSF_DUMPDIR].string) {
				pfree(coredir);
				/* dumpdir= */
				coredir = clone_str(cfg->setup[KSF_DUMPDIR].string,
						    "coredir via --config");
			}
			/* vendorid= */
			if (cfg->setup[KSF_MYVENDORID].string) {
				pfree(pluto_vendorid);
				pluto_vendorid = clone_str(cfg->setup[KSF_MYVENDORID].string,
							   "pluto_vendorid via --config");
			}

			if (cfg->setup[KSF_STATSBINARY].string != NULL) {
				if (access(cfg->setup[KSF_STATSBINARY].string, X_OK) == 0) {
					pfreeany(pluto_stats_binary);
					/* statsbin= */
					pluto_stats_binary = clone_str(cfg->setup[KSF_STATSBINARY].string, "statsbin via --config");
					llog(RC_LOG, logger, "statsbinary set to %s", pluto_stats_binary);
				} else {
					llog(RC_LOG, logger, "statsbinary= '%s' ignored - file does not exist or is not executable",
						    pluto_stats_binary);
				}
			}

			pluto_nss_seedbits = cfg->setup[KBF_SEEDBITS].option;
			keep_alive = cfg->setup[KBF_KEEP_ALIVE].deltatime;

			replace_when_cfg_setup(&virtual_private, cfg, KSF_VIRTUALPRIVATE);

			set_global_redirect_dests(cfg->setup[KSF_GLOBAL_REDIRECT_TO].string);

			config_ipsec_interface(cfg->setup[KWYN_IPSEC_INTERFACE_MANAGED].option, logger);

			nhelpers = cfg->setup[KBF_NHELPERS].option;
			cur_debugging = cfg->setup[KW_DEBUG].option;

			char *protostack = cfg->setup[KSF_PROTOSTACK].string;
			passert(kernel_ops == kernel_stacks[0]); /*default*/

			if (protostack != NULL && protostack[0] != '\0') {
				kernel_ops = NULL;
				for (const struct kernel_ops *const *stack = kernel_stacks;
				     *stack != NULL; stack++) {
					const struct kernel_ops *ops = *stack;
					for (const char **name =ops->protostack_names;
					     *name != NULL; name++) {
						if (strcaseeq((*name), protostack)) {
							kernel_ops = ops;
							break;
						}
					}
				}
				if (kernel_ops == NULL) {
					kernel_ops = kernel_stacks[0];
					llog(RC_LOG, logger,
					     "protostack=%s ignored, using protostack=%s",
					     protostack, kernel_ops->protostack_names[0]);
				}
			}

			if (cfg->setup[KSF_EXPIRE_SHUNT_INTERVAL].set) {
				bare_shunt_interval = cfg->setup[KSF_EXPIRE_SHUNT_INTERVAL].deltatime;
				check_diag(logger, deltatime_ok(bare_shunt_interval, 1, 1000));
			}

			confread_free(cfg);
			continue;
		}

		case OPT_EFENCE_PROTECT:
#ifdef USE_EFENCE
			/*
			 * This flag was already processed at the
			 * start of main().  While it isn't immutable,
			 * having it apply to all mallocs() is
			 * presumably better.
			 */
			passert(EF_PROTECT_BELOW);
			passert(EF_PROTECT_FREE);
#else
			llog(RC_LOG, logger, "efence support is not enabled; option --efence-protect ignored");
#endif
			continue;

		case OPT_DEBUG:
		{
			lmod_t mod = empty_lmod;
			if (lmod_arg(&mod, &debug_lmod_info, optarg, true/*enable*/)) {
				cur_debugging = lmod(cur_debugging, mod);
			} else {
				llog(RC_LOG, logger, "unrecognized --debug '%s' option ignored",
					    optarg);
			}
			continue;
		}

		case OPT_IMPAIR:
		{
			struct whack_impair impairment;
			switch (parse_impair(optarg, &impairment, true, logger)) {
			case IMPAIR_OK:
				if (!process_impair(&impairment, NULL, true, logger)) {
					optarg_fatal(logger, "not valid from the command line");
				}
				continue;
			case IMPAIR_ERROR:
				/* parse_impair() printed error */
				exit(PLUTO_EXIT_FAIL);
			case IMPAIR_HELP:
				/* parse_impair() printed error */
				exit(PLUTO_EXIT_OK);
			}
			continue;
		}

		default:
			bad_case(c);
		}
	}

	/*
	 * Anything (aka an argument) after all options consumed?
	 */
	if (optind != argc) {
		llog(RC_LOG, logger, "unexpected trailing argument: %s", argv[optind]);
		/* not exit_pluto because we are not initialized yet */
		exit(PLUTO_EXIT_FAIL);
	}

	/*
	 * Create the lock file before things fork.
	 *
	 * From now on fatal_error() needs to be called as that clears
	 * out the locks.
	 */

	int lockfd;
	if (selftest_only) {
		llog(RC_LOG, logger, "selftest: skipping lock");
		lockfd = 0;
	} else {
		lockfd = create_lock(logger);
	}

	/*
	 * Create control socket before things fork.
	 *
	 * From now on fatal_error() needs to be called as that clears
	 * out the socket.
	 *
	 * We must create it before the parent process returns so that
	 * there will be no race condition in using it.  The easiest
	 * place to do this is before the daemon fork.
	 */
	if (selftest_only) {
		llog(RC_LOG, logger, "selftest: skipping control socket");
	} else {
		diag_t d = init_ctl_socket(logger);
		if (d != NULL) {
			fatal(PLUTO_EXIT_SOCKET_FAIL, logger, "%s", str_diag(d));
		}
	}

	/*
	 * If not suppressed, do daemon fork.
	 *
	 * Use logger which points at stdout!
	 */
	if (selftest_only) {
		llog(RC_LOG, logger, "selftest: skipping fork");
	} else if (fork_desired) {
#if USE_DAEMON
		if (daemon(true, true) < 0) {
			fatal_errno(PLUTO_EXIT_FORK_FAIL, logger, "daemon failed");
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
				fatal_errno(PLUTO_EXIT_FORK_FAIL, logger, errno, "fork failed");
			}

			if (pid == 0) {
				/*
				 * parent fills in the PID.
				 */
				close(lockfd);
			} else {
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
		fatal(PLUTO_EXIT_FORK_FAIL, logger, "fork/daemon not supported; specify --nofork");
#endif
		if (setsid() < 0) {
			fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
				    "setsid() failed in main()");
		}
	} else {
		/* no daemon fork: we have to fill in lock file */
		(void) fill_lock(lockfd, getpid());

		if (isatty(fileno(stdout)) && !log_param.log_to_stderr) {
			/*
			 * Last gasp; from now on everything goes to
			 * the file/syslog.
			 */
			fprintf(stdout, "Pluto is starting ...\n");
			fflush(stdout);
		}

	}

	/*
	 * Detach STDIN/STDOUT and, when debugging, go through the
	 * possibly large list of file descriptors and verify that
	 * only the expected ones are open.  STDERR is detached later
	 * when the logger is switched.
	 *
	 * (Debugging was set while loading the config file above).
	 */

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	PASSERT(logger, open("/dev/null", O_RDONLY) == STDIN_FILENO);
	PASSERT(logger, dup2(0, STDOUT_FILENO) == STDOUT_FILENO);

	if (DBGP(DBG_BASE)) {
		for (int fd = getdtablesize() - 1; fd >= 0; fd--) {
			if (fd == ctl_fd ||
			    fd == STDIN_FILENO ||
			    fd == STDOUT_FILENO ||
			    fd == STDERR_FILENO) {
				continue;
			}
			struct stat s;
			if (fstat(fd, &s) == 0) {
				/*
				 * Not a pexpect(), this happens when
				 * running under FAKETIME.
				 */
				llog(RC_LOG, logger, "unexpected open file descriptor %d", fd);
			}
		}
	}

	/*
	 * Switch to the real FILE/STDERR/SYSLOG logger.
	 */

	switch_log(log_param, &logger);

	/*
	 * Forking done; logging enabled.  Time to announce things to
	 * the world.
	 */
	llog(RC_LOG, logger, "Starting Pluto (Libreswan Version %s%s) pid:%u",
	     ipsec_version_code(), compile_time_interop_options, getpid());

	init_kernel_info(logger);

	llog(RC_LOG, logger, "core dump dir: %s", coredir);
	if (chdir(coredir) == -1) {
		int e = errno;
		llog(RC_LOG, logger, "pluto: warning: chdir(\"%s\") to dumpdir failed (%d: %s)",
		     coredir, e, strerror(e));
	}

	oco = lsw_init_options();
	if (oco->secretsfile && *oco->secretsfile) {
		llog(RC_LOG, logger, "secrets file: %s", oco->secretsfile);
	}

	init_enum_names();
	init_pluto_constants();

#ifdef USE_IKEv1
	init_ikev1_states(logger);
#endif
	init_ikev2_states(logger);
	init_states();
	state_db_init(logger);
	connection_db_init(logger);
	spd_db_init(logger);

	pluto_init_nss(oco->nssdir, logger);
	if (is_fips_mode()) {
		/*
		 * clear out --debug-crypt if set
		 *
		 * impairs are also not allowed but cannot come in via
		 * ipsec.conf, only whack
		 */
		if (cur_debugging & DBG_PRIVATE) {
			cur_debugging &= ~DBG_PRIVATE;
			llog(RC_LOG, logger, "FIPS mode: debug-private disabled as such logging is not allowed");
		}
		/*
		 * clear out --debug-crypt if set
		 *
		 * impairs are also not allowed but cannot come in via
		 * ipsec.conf, only whack
		 */
		if (cur_debugging & DBG_CRYPT) {
			cur_debugging &= ~DBG_CRYPT;
			llog(RC_LOG, logger, "FIPS mode: debug-crypt disabled as such logging is not allowed");
		}
	}

	init_crypt_symkey(logger);

	/*
	 * If impaired, force the mode change; and verify the
	 * consequences.  Always run the tests as combinations such as
	 * NSS in fips mode but as out of it could be bad.
	 */

	if (impair.force_fips) {
		llog(RC_LOG, logger, "IMPAIR: forcing FIPS checks to true to emulate FIPS mode");
		set_fips_mode(FIPS_MODE_ON);
	}

	bool nss_fips_mode = PK11_IsFIPS();
	if (is_fips_mode()) {
		llog(RC_LOG, logger, "FIPS mode enabled for pluto daemon");
		if (nss_fips_mode) {
			llog(RC_LOG, logger, "NSS library is running in FIPS mode");
		} else {
			fatal(PLUTO_EXIT_FIPS_FAIL, logger, "pluto in FIPS mode but NSS library is not");
		}
	} else {
		llog(RC_LOG, logger, "FIPS mode disabled for pluto daemon");
		if (nss_fips_mode) {
			llog(RC_LOG, logger, "Warning: NSS library is running in FIPS mode");
		}
	}

	if (x509_ocsp.enable) {
		llog(RC_LOG, logger, "NSS: OCSP [enabled]");
		/* may not return */
		diag_t d = init_x509_ocsp(logger);
		if (d != NULL) {
			fatal(PLUTO_EXIT_NSS_FAIL, logger,
			      "NSS: OCSP initialization failed: %s",
			      str_diag(d));
		}
	} else {
		llog(RC_LOG, logger, "NSS: OCSP [disabled]");
	}

#ifdef USE_NSS_KDF
	llog(RC_LOG, logger, "FIPS HMAC integrity support [not required]");
#else
	llog(RC_LOG, logger, "FIPS HMAC integrity support [not compiled in]");
#endif

#ifdef HAVE_LIBCAP_NG
	/*
	 * If we don't have the capability to drop capailities, do nothing.
	 *
	 * Drop capabilities - this generates a false positive valgrind warning
	 * See: http://marc.info/?l=linux-security-module&m=125895232029657
	 *
	 * We drop these after creating the pluto socket or else we can't
	 * create a socket if the parent dir is non-root (eg openstack)
	 *
	 * We need to retain some capabilities for our children (updown):
	 * CAP_NET_ADMIN to change routes
	 * (we also need it for some setsockopt() calls in main process)
	 * CAP_NET_RAW for iptables -t mangle
	 * CAP_DAC_READ_SEARCH for pam / google authenticator
	 * CAP_SETGID, CAP_SETUID for pam / google authenticator
	 */
	if (capng_get_caps_process() == -1) {
		llog(RC_LOG, logger, "failed to query pluto process for capng capabilities");
	} else {
		/* If we don't have CAP_SETPCAP, we cannot update the bounding set */
		capng_select_t set = CAPNG_SELECT_CAPS;
		if (capng_have_capability (CAPNG_EFFECTIVE, CAP_SETPCAP)) {
			set = CAPNG_SELECT_BOTH;
		}

		capng_clear(CAPNG_SELECT_BOTH);
		if (capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE | CAPNG_PERMITTED,
			CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW,
			CAP_IPC_LOCK, CAP_AUDIT_WRITE,
			CAP_SETGID, CAP_SETUID,
			CAP_DAC_READ_SEARCH,
			-1) != 0) {
				llog(RC_LOG, logger,
					"libcap-ng capng_updatev() failed for CAPNG_EFFECTIVE | CAPNG_PERMITTED");
		}

		if (capng_updatev(CAPNG_ADD, CAPNG_BOUNDING_SET, CAP_NET_ADMIN,
			CAP_NET_RAW, CAP_DAC_READ_SEARCH, CAP_SETPCAP,
			-1) != 0) {
				llog(RC_LOG, logger,
					"libcap-ng capng_updatev() failed for CAPNG_BOUNDING_SET");
		}

		int ret = capng_apply(set);
		if (ret != CAPNG_NONE) {
			llog(RC_LOG, logger,
				"libcap-ng capng_apply failed to apply changes, err=%d. see: man capng_apply",
				ret);
		}
	}

	llog(RC_LOG, logger, "libcap-ng support [enabled]");
#else
	llog(RC_LOG, logger, "libcap-ng support [disabled]");
#endif

#ifdef USE_LINUX_AUDIT
	linux_audit_init(log_to_audit, logger);
#else
	llog(RC_LOG, logger, "Linux audit support [disabled]");
#endif

	llog(RC_LOG, logger, leak_detective ?
	     "leak-detective enabled" : "leak-detective disabled");

	llog(RC_LOG, logger, "NSS crypto [enabled]");

#ifdef USE_PAM_AUTH
	llog(RC_LOG, logger, "XAUTH PAM support [enabled]");
#else
	llog(RC_LOG, logger, "XAUTH PAM support [disabled]");
#endif

	/*
	 * Log impair-* functions that were enabled
	 */
	if (have_impairments()) {
		LLOG_JAMBUF(RC_LOG, logger, buf) {
			jam(buf, "Warning: impairments enabled: ");
			jam_impairments(buf, "+");
		}
	}

/* Initialize all of the various features */

	init_server_fork(logger);
	init_server(logger);

	/* server initialized; timers can follow */
	init_log_limiter(logger);
	init_nat_traversal_timer(keep_alive, logger);
	init_ddns();

	init_virtual_ip(virtual_private, logger);

	enum yn_options ipsec_interface_managed = init_ipsec_interface(logger);
	llog(RC_LOG, logger, "IPsec Interface [%s]",
	     (ipsec_interface_managed == YN_UNSET ? "disabled" :
	      ipsec_interface_managed == YN_NO ? "unmanaged" :
	      ipsec_interface_managed == YN_YES ? "managed" :
	      "!?!"));

	/* require NSS */
	init_root_certs();
	init_secret_timer(logger);
	init_ike_alg(logger);
	test_ike_alg(logger);

	init_vendorid(logger);

	if (selftest_only) {
		/*
		 * skip pluto_exit()
		 *
		 * Not all components were initialized and no lock
		 * files were created.
		 */
		llog(RC_LOG, logger, "selftest: exiting pluto");
		exit(PLUTO_EXIT_OK);
	}

	start_server_helpers(nhelpers, logger);
	init_kernel(logger);
#if defined(USE_LIBCURL) || defined(USE_LDAP)
	bool crl_enabled = init_x509_crl_queue(logger);
	llog(RC_LOG, logger, "CRL fetch support [%s]",
	     (crl_enabled ? "enabled" : "disabled"));
#endif
	init_labeled_ipsec(logger);
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd_init(logger);
#endif

#ifdef USE_DNSSEC
	{
		diag_t d = unbound_event_init(get_pluto_event_base(), do_dnssec,
					      pluto_dnssec_rootkey_file, pluto_dnssec_trusted,
					      logger/*for-warnings*/);
		if (d != NULL) {
			fatal(PLUTO_EXIT_UNBOUND_FAIL, logger, "%s", str_diag(d));
		}
	}
#endif

	/*
	 * Initialize the stack probes so we have some control of order
	 * of the probes
	 */
	err_t msg;
	msg = kernel_ops->directional_ipsec_sa_is_enabled(logger);
	if (msg != NULL)
		llog(RC_LOG, logger, "kernel: directional ipsec SA error: %s", msg);
	else
		llog(RC_LOG, logger, "kernel: directional SA supported by kernel");

	msg = kernel_ops->iptfs_ipsec_sa_is_enabled(logger);
	if (msg != NULL)
		llog(RC_LOG, logger, "kernel: IPTFS ipsec SA error: %s", msg);
	else
		llog(RC_LOG, logger, "kernel: IPTFS SA supported by kernel");

	msg = kernel_ops->migrate_ipsec_sa_is_enabled(logger);
	if (msg != NULL)
		llog(RC_LOG, logger, "kernel: MIGRATE ipsec SA error: %s", msg);
	else
		llog(RC_LOG, logger, "kernel: MIGRATE SA supported by kernel");

	run_server(conffile, logger);
}

void show_setup_plutomain(struct show *s)
{
	show_separator(s);
	show(s, "config setup options:");
	show_separator(s);
	show(s, "configdir=%s, configfile=%s, secrets=%s, ipsecdir=%s",
		oco->confdir,
		conffile, /* oco contains only a copy of hardcoded default */
		oco->secretsfile,
		oco->confddir);

	show(s, "nssdir=%s, dumpdir=%s, statsbin=%s",
		oco->nssdir,
		coredir,
		pluto_stats_binary == NULL ? "unset" :  pluto_stats_binary);

#ifdef USE_DNSSEC
	show(s, "dnssec-rootkey-file=%s, dnssec-trusted=%s",
		     pluto_dnssec_rootkey_file == NULL ? "<unset>" : pluto_dnssec_rootkey_file,
		     pluto_dnssec_trusted == NULL ? "<unset>" : pluto_dnssec_trusted);
#endif

	show(s, "sbindir=%s, libexecdir=%s",
		IPSEC_SBINDIR,
		IPSEC_EXECDIR);

	show(s, "pluto_version=%s, pluto_vendorid=%s",
		ipsec_version_code(),
		pluto_vendorid);

	SHOW_JAMBUF(s, buf) {
		jam(buf, "nhelpers=%d", nhelpers);
		jam(buf, ", uniqueids=%s", bool_str(uniqueIDs));
		jam(buf, ", dnssec-enable=%s", bool_str(do_dnssec));
		jam(buf, ", shuntlifetime=%jds", deltasecs(pluto_shunt_lifetime));
#ifdef XFRM_LIFETIME_DEFAULT
		jam(buf, ", xfrmlifetime=%jds", (intmax_t) pluto_xfrmlifetime);
#endif
	}

	show_log(s);

	show(s,
		"ddos-cookies-threshold=%d, ddos-max-halfopen=%d, ddos-mode=%s, ikev1-policy=%s",
		pluto_ddos_threshold,
		pluto_max_halfopen,
		(pluto_ddos_mode == DDOS_AUTO) ? "auto" :
			(pluto_ddos_mode == DDOS_FORCE_BUSY) ? "busy" : "unlimited",
		pluto_ikev1_pol == GLOBAL_IKEv1_ACCEPT ? "accept" :
			pluto_ikev1_pol == GLOBAL_IKEv1_REJECT ? "reject" : "drop");

	show(s,
		"ikebuf=%d, msg_errqueue=%s, crl-strict=%s, crlcheckinterval=%jd, listen=%s, nflog-all=%d",
		pluto_sock_bufsize,
		bool_str(pluto_sock_errqueue),
		bool_str(x509_crl.strict),
		deltasecs(x509_crl.check_interval),
		pluto_listen != NULL ? pluto_listen : "<any>",
		pluto_nflog_group
		);

	show_x509_ocsp(s);

	SHOW_JAMBUF(s, buf) {
		jam_string(buf, "global-redirect=");
		jam_sparse(buf, &global_redirect_names, global_redirect);
		jam_string(buf, ", ");
		jam_string(buf, "global-redirect-to=");
		jam_string(buf, (strlen(global_redirect_to()) > 0 ? global_redirect_to() :
				 "<unset>"));
	}
}
