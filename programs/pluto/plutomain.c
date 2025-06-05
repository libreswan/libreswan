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
#include "config_setup.h"
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
#include "lock_file.h"
#include "ikev2_unsecured.h"	/* for pluto_drop_oppo_null; */
#include "ddos.h"

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

static bool fork_desired = USE_FORK || USE_DAEMON;
static bool selftest_only = false;

/* pulled from main for show_setup_plutomain() */

static char *conffile;

static struct {
	bool enable;
	const char *rootkey_file;
	const char *anchors;
} pluto_dnssec = {0}; /* see config_setup.[hc] for defaults */

void free_pluto_main(void)
{
	/* Some values can be NULL if not specified as pluto argument */
	pfree(conffile);
	free_global_redirect_dests();
	free_config_setup();
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
;

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

static bool update_deltatime(deltatime_t *target,
			      deltatime_t value)
{
	/* Do nothing if value is unset. */
	if (value.is_set) {
		(*target) = value;
		return true;
	}
	return false;
}

static bool extract_config_deltatime(deltatime_t *target,
				     const struct starter_config *cfg,
				     enum config_setup_keyword field)
{
	return update_deltatime(target, cfg->setup->values[field].deltatime);
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
}

/*
 * This exists purely to make the BSI happy.  We do not inflict this
 * on other users
 */

static void init_seedbits(const struct config_setup *oco, struct logger *logger)
{
	uintmax_t seedbits = config_setup_option(oco, KBF_SEEDBITS);
	if (seedbits != 0) {
		int seedbytes = BYTES_FOR_BITS(seedbits);
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
	OPT_DEBUG_NONE,
	OPT_DEBUG_ALL,
	OPT_IMPAIR,
	OPT_DNSSEC_ROOTKEY_FILE,
	OPT_DNSSEC_ANCHORS,
	OPT_HELP,
	OPT_CONFIG,
	OPT_VERSION,
	OPT_NOFORK,
	OPT_STDERRLOG,
	OPT_LOGFILE,
	OPT_LOG_NO_TIME,
	OPT_LOG_NO_APPEND,
	OPT_LOG_NO_IP,
	OPT_LOGIP,
	OPT_LOG_NO_AUDIT,
	OPT_AUDIT_LOG,
	OPT_DROP_OPPO_NULL,

	OPT_DDOS_MODE,
	OPT_DDOS_IKE_THRESHOLD,
	OPT_MAX_HALFOPEN_IKE,
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
	OPT_LISTEN_UDP,
	OPT_NO_LISTEN_UDP,

	OPT_IKE_SOCKET_BUFSIZE,
	OPT_IKE_SOCKET_ERRQUEUE,
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

	OPT_SECCOMP,
	OPT_SECCOMP_ENABLED,
	OPT_SECCOMP_TOLERANT,

	OPT_VENDORID,
	OPT_SELFTEST,
	OPT_LEAK_DETECTIVE,
};

const struct option optarg_options[] = {
	/* name, has_arg, flag, val */
	{ OPT("help"), no_argument, NULL, OPT_HELP },
	{ OPT("version"), no_argument, NULL, OPT_VERSION },
	{ OPT("nofork"), no_argument, NULL, OPT_NOFORK },
	{ OPT("config", "<filename>"), required_argument, NULL, OPT_CONFIG },

	HEADING_OPT("  Configuration:"),
	{ OPT("rundir", "<dirname>"), required_argument, NULL, OPT_RUNDIR }, /* was ctlbase */
	{ OPT("secretsfile", "<secrets-file>"), required_argument, NULL, OPT_SECRETSFILE },
	{ REPLACE_OPT("coredir", "dumpdir", "3.9"), required_argument, NULL, OPT_DUMPDIR },	/* redundant spelling */
	{ OPT("dumpdir", "<dirname>"), required_argument, NULL, OPT_DUMPDIR },
	{ OPT("statsbin", "<filename>"), required_argument, NULL, OPT_STATSBIN },
	{ OPT("ipsecdir", "<dirname>"), required_argument, NULL, OPT_IPSECDIR },
	{ REPLACE_OPT("foodgroupsdir", "ipsecdir", "3.9"), required_argument, NULL, OPT_IPSECDIR },	/* redundant spelling */
	{ OPT("nssdir", "<dirname>"), required_argument, NULL, OPT_NSSDIR },	/* nss-tools use -d */
	{ OPT("nhelpers", "<number>"), required_argument, NULL, OPT_NHELPERS },
	{ OPT("leak-detective"), no_argument, NULL, OPT_LEAK_DETECTIVE },
	{ OPT("efence-protect"), no_argument, NULL, OPT_EFENCE_PROTECT, },

#ifdef USE_DNSSEC
	{ OPT("dnssec-rootkey-file", "<filename>"), required_argument, NULL, OPT_DNSSEC_ROOTKEY_FILE },
	{ OPT("dnssec-anchors", "<filename>"), required_argument, NULL, OPT_DNSSEC_ANCHORS },
	{ REPLACE_OPT("dnssec-trusted", "dnssec-anchors", "5.3"), required_argument, NULL, OPT_DNSSEC_ANCHORS },
#endif

	{ OPT("ddos-mode", "{auto,busy,unlimited}"), required_argument, NULL, OPT_DDOS_MODE },
	{ OPT("ddos-ike-threshold", "<count>"), required_argument, NULL, OPT_DDOS_IKE_THRESHOLD },
	{ OPT("max-halfopen-ike", "<count>"), required_argument, NULL, OPT_MAX_HALFOPEN_IKE },
	{ REPLACE_OPT("force-busy", "ddos-mode", "5.3"), no_argument, NULL, OPT_FORCE_BUSY },
	{ REPLACE_OPT("force-unlimited", "ddos-mode", "5.3"), no_argument, NULL, OPT_FORCE_UNLIMITED },

	{ OPT("uniqueids", "{YES,no}"), optional_argument, NULL, OPT_UNIQUEIDS },
	{ OPT("no-dnssec"), no_argument, NULL, OPT_NO_DNSSEC },
#ifdef KERNEL_PFKEYV2
	{ OPT("use-pfkeyv2"),   no_argument, NULL, OPT_USE_PFKEYV2 },
#endif
#ifdef KERNEL_XFRM
	{ OPT("use-xfrm"), no_argument, NULL, OPT_USE_XFRM },
#endif
	{ IGNORE_OPT("interface", "not-implemented", "<ifname|ifaddr>"), required_argument, NULL, OPT_INTERFACE }, /* reserved; not implemented */

	{ OPT("listen", "<ifaddr>"), required_argument, NULL, OPT_LISTEN },
	{ OPT("listen-tcp", "{yes,no}"), optional_argument, NULL, OPT_LISTEN_TCP },
	{ OPT("listen-udp", "{yes,no}"), optional_argument, NULL, OPT_LISTEN_UDP },
	{ REPLACE_OPT("no-listen-udp", "listen-udp", "5.3"), no_argument, NULL, OPT_NO_LISTEN_UDP },

	{ OPT("ike-socket-bufsize", "<bytes>"), required_argument, NULL, OPT_IKE_SOCKET_BUFSIZE },
	{ OPT("ike-socket-errqueue", "{yes,no}"), required_argument, NULL, OPT_IKE_SOCKET_ERRQUEUE },
	{ OPT("ike-socket-no-errqueue"), no_argument, NULL, OPT_IKE_SOCKET_NO_ERRQUEUE },
#ifdef USE_NFLOG
	{ OPT("nflog-all", "<group-number>"), required_argument, NULL, OPT_NFLOG_ALL },
#endif

	{ OPT("keep-alive", "<delay-seconds>"), required_argument, NULL, OPT_KEEP_ALIVE },
	{ OPT("virtual-private", "<network-list>"), required_argument, NULL, OPT_VIRTUAL_PRIVATE },
	{ OPT("expire-shunt-interval", "<seconds>"), required_argument, NULL, OPT_EXPIRE_SHUNT_INTERVAL },
	{ OPT("seedbits", "number"), required_argument, NULL, OPT_SEEDBITS },
	/* really an attribute type, not a value */
	{ OPT("ikev1-secctx-attr-type", "<number>"), required_argument, NULL, OPT_IKEV1_SECCTX_ATTR_TYPE },
	{ OPT("ikev1-reject"), no_argument, NULL, OPT_IKEV1_REJECT },
	{ OPT("ikev1-drop"), no_argument, NULL, OPT_IKEV1_DROP },
	{ OPT("vendorid", "vendorid>"), required_argument, NULL, OPT_VENDORID },
	{ OPT("drop-oppo-null"), optional_argument, NULL, OPT_DROP_OPPO_NULL, },

	HEADING_OPT("  Logging:"),
	{ OPT("logfile", "<filename>"), required_argument, NULL, OPT_LOGFILE },
	{ OPT("stderrlog"), no_argument, NULL, OPT_STDERRLOG },
	{ OPT("log-no-time"), no_argument, NULL, OPT_LOG_NO_TIME }, /* was --plutostderrlogtime */
	{ OPT("log-no-append"), no_argument, NULL, OPT_LOG_NO_APPEND },
	{ OPT("logip", "{YES,no}"), optional_argument, NULL, OPT_LOGIP },
	{ REPLACE_OPT("log-no-ip", "logip=no", "5.3"), no_argument, NULL, OPT_LOG_NO_IP },
	{ OPT("audit-log"), optional_argument, NULL, OPT_AUDIT_LOG },
	{ REPLACE_OPT("log-no-audit", "audit-log", "5.3"), no_argument, NULL, OPT_LOG_NO_AUDIT },

	HEADING_OPT("  Redirection:"),
	{ OPT("global-redirect", "{yes,no,auto}"), required_argument, NULL, OPT_GLOBAL_REDIRECT},
	{ OPT("global-redirect-to", "<destination>"), required_argument, NULL, OPT_GLOBAL_REDIRECT_TO},

#ifdef USE_SECCOMP
	HEADING_OPT("  Secure Computing:"),
	{ OPT("seccomp", "{enabled,disabled,tolerant}"), required_argument, NULL, OPT_SECCOMP },
	{ REPLACE_OPT("seccomp-enabled", "seccomp", "5.3"), no_argument, NULL, OPT_SECCOMP_ENABLED },
	{ REPLACE_OPT("seccomp-tolerant", "seccomp", "5.3"), no_argument, NULL, OPT_SECCOMP_TOLERANT },
#endif

	HEADING_OPT("  PKI X.509:"),
	{ OPT("ocsp-enable"), no_argument, NULL, OPT_OCSP_ENABLE },
	{ OPT("ocsp-strict"), no_argument, NULL, OPT_OCSP_STRICT },
	{ OPT("ocsp-uri", "<uri>"), required_argument, NULL, OPT_OCSP_URI },
	{ OPT("ocsp-timeout", "<seconds>"), required_argument, NULL, OPT_OCSP_TIMEOUT },
	{ OPT("ocsp-trustname", "<name>"), required_argument, NULL, OPT_OCSP_TRUSTNAME },
	{ OPT("ocsp-cache-size", "<bytes>"), required_argument, NULL, OPT_OCSP_CACHE_SIZE },
	{ OPT("ocsp-cache-min-age", "<seconds>"), required_argument, NULL, OPT_OCSP_CACHE_MIN_AGE },
	{ OPT("ocsp-cache-max-age", "<seconds>"), required_argument, NULL, OPT_OCSP_CACHE_MAX_AGE },
	{ OPT("ocsp-method", "<method>"), required_argument, NULL, OPT_OCSP_METHOD },
	{ OPT("crl-strict"), no_argument, NULL, OPT_CRL_STRICT },
	{ OPT("crlcheckinterval", "<seconds>"), required_argument, NULL, OPT_CRLCHECKINTERVAL },
	{ OPT("curl-iface", "<ifname>|<ifaddr>"), required_argument, NULL, OPT_CURL_IFACE },
	{ OPT("curl-timeout", "<seconds>"), required_argument, NULL, OPT_CURL_TIMEOUT }, /* legacy */

	HEADING_OPT("  Debuging:"),
	{ OPT("debug-none"), no_argument, NULL, OPT_DEBUG_NONE },
	{ OPT("debug-all"), no_argument, NULL, OPT_DEBUG_ALL },
	{ OPT("debug", "help|<debug-flags>"), required_argument, NULL, OPT_DEBUG, },
	{ OPT("impair", "help|<impairment>"), required_argument, NULL, OPT_IMPAIR, },
	{ OPT("selftest"), no_argument, NULL, OPT_SELFTEST },

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

static void update_optarg_deltatime(enum config_setup_keyword kw, struct logger *logger,
				   enum timescale timescale, int lower, int upper)
{
	deltatime_t time = optarg_deltatime(logger, timescale);
	check_diag(logger, deltatime_ok(time, lower, upper));
	update_setup_deltatime(kw, time);
}

static deltatime_t check_config_deltatime(const struct config_setup *oco,
					  enum config_setup_keyword kw,
					  struct logger *logger,
					  int lower, int upper, const char *name)
{
	deltatime_t time = config_setup_deltatime(oco, kw);
	if (time.is_set) {
		check_conf(deltatime_ok(time, lower, upper), name, logger);
	}
	return time;
}

#ifdef USE_EFENCE
extern int EF_PROTECT_BELOW;
extern int EF_PROTECT_FREE;
#endif

int main(int argc, char **argv)
{
	UNUSED diag_t d = NULL;
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
			update_setup_string(KSF_DUMPDIR, optarg_nonempty(logger));
			continue;

		case OPT_VENDORID:	/* --vendorid */
			update_setup_string(KSF_MYVENDORID, optarg_nonempty(logger));
			continue;

		case OPT_STATSBIN:	/* --statsbin */
			update_setup_string(KSF_STATSBIN, optarg_empty(logger));
			continue;

		case OPT_VERSION:	/* --version */
			printf("%s%s\n", ipsec_version_string(), /* ok */
			       compile_time_interop_options);
			/* not exit_pluto because we are not initialized yet */
			exit(PLUTO_EXIT_OK);

		case OPT_NHELPERS:	/* --nhelpers */
			update_setup_option(KBF_NHELPERS, optarg_uintmax(logger));
			continue;

		case OPT_SEEDBITS:	/* --seedbits */
		{
			/* Why not allow zero aka disable? */
			uintmax_t seedbits = optarg_uintmax(logger);
			if (seedbits == 0) {
				optarg_fatal(logger, "seedbits must be an integer > 0");
			}
			update_setup_option(KBF_SEEDBITS, seedbits);
			continue;
		}

		case OPT_IKEV1_SECCTX_ATTR_TYPE:	/* --secctx-attr-type */
			llog(RC_LOG, logger, "--secctx-attr-type not supported");
			continue;

		case OPT_IKEV1_REJECT:	/* --ikev1-reject */
			update_setup_option(KBF_IKEv1_POLICY, GLOBAL_IKEv1_REJECT);
			continue;

		case OPT_IKEV1_DROP:	/* --ikev1-drop */
			update_setup_option(KBF_IKEv1_POLICY, GLOBAL_IKEv1_DROP);
			continue;

		case OPT_NOFORK:	/* --nofork*/
			fork_desired = false;
			continue;

		case OPT_STDERRLOG:	/* --stderrlog */
			update_setup_yn(KYN_LOGSTDERR, YN_YES);
			continue;

		case OPT_LOGFILE:	/* --logfile */
			update_setup_string(KSF_LOGFILE, optarg_nonempty(logger));
			continue;

		case OPT_DNSSEC_ROOTKEY_FILE:	/* --dnssec-rootkey-file */
			/* reject '' */
			update_setup_string(KSF_DNSSEC_ROOTKEY_FILE,
					    optarg_nonempty(logger));
			continue;

		case OPT_DNSSEC_ANCHORS:	/* --dnssec-anchors */
			/* allow '', become NULL */
			update_setup_string(KSF_DNSSEC_ANCHORS,
					    optarg_empty(logger));
			continue;

		case OPT_LOG_NO_TIME:	/* --log-no-time */
			update_setup_yn(KYN_LOGTIME, YN_NO);
			continue;

		case OPT_LOG_NO_APPEND:	/* --log-no-append */
			update_setup_yn(KYN_LOGAPPEND, YN_NO);
			continue;

		case OPT_LOG_NO_IP:	/* --log-no-ip */
			update_setup_yn(KYN_LOGIP, YN_NO);
			continue;
		case OPT_LOGIP:
			update_setup_yn(KYN_LOGIP, optarg_yn(logger, YN_YES));
			continue;

		case OPT_LOG_NO_AUDIT:	/* --log-no-audit */
			update_setup_yn(KYN_AUDIT_LOG, YN_NO);
			continue;
		case OPT_AUDIT_LOG:
			update_setup_yn(KYN_AUDIT_LOG, optarg_yn(logger, YN_YES));
			continue;

		case OPT_DROP_OPPO_NULL:	/* --drop-oppo-null */
			update_setup_yn(KYN_DROP_OPPO_NULL, optarg_yn(logger, YN_YES));
			continue;

		case OPT_EXPIRE_SHUNT_INTERVAL:	/* --expire-shunt-interval <interval> */
		{
			deltatime_t interval = optarg_deltatime(logger, TIMESCALE_SECONDS);
#define EXPIRE_SHUNT_INTERVAL_RANGE 1, 1000
			check_diag(logger, deltatime_ok(interval, EXPIRE_SHUNT_INTERVAL_RANGE));
			update_setup_deltatime(KSF_EXPIRE_SHUNT_INTERVAL, interval);
			continue;
		}

		case OPT_LISTEN:	/* --listen ip_addr */
			/* Check syntax, so feedback is immediate. */
			optarg_address_num(logger, NULL);
			update_setup_string(KSF_LISTEN, optarg);
			continue;
		case OPT_LISTEN_TCP:	/* --listen-tcp */
			update_setup_yn(KYN_LISTEN_TCP, optarg_yn(logger, YN_YES));
			continue;
		case OPT_LISTEN_UDP:	/* --listen-udp */
			update_setup_yn(KYN_LISTEN_UDP, optarg_yn(logger, YN_YES));
			continue;
		case OPT_NO_LISTEN_UDP:	/* --no-listen-udp */
			update_setup_yn(KYN_LISTEN_UDP, YN_NO);
			continue;

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

		case OPT_DDOS_MODE:
			update_setup_option(KBF_DDOS_MODE,
					    optarg_sparse(logger, 0, &ddos_mode_names));
			continue;
		case OPT_DDOS_IKE_THRESHOLD:
			update_setup_option(KBF_DDOS_IKE_THRESHOLD,
					    optarg_uintmax(logger));
			continue;
		case OPT_MAX_HALFOPEN_IKE:
			update_setup_option(KBF_MAX_HALFOPEN_IKE,
					    optarg_uintmax(logger));
			continue;
		case OPT_FORCE_BUSY:	/* --force-busy */
			update_setup_option(KBF_DDOS_MODE, DDOS_FORCE_BUSY);
			continue;
		case OPT_FORCE_UNLIMITED:	/* --force-unlimited */
			update_setup_option(KBF_DDOS_MODE, DDOS_FORCE_UNLIMITED);
			continue;

#ifdef USE_SECCOMP
		case OPT_SECCOMP:		/* --seccomp={enabled,disabled,tolerant} */
			update_setup_option(KBF_SECCOMP, optarg_sparse(logger, SECCOMP_ENABLED, &seccomp_mode_names));
			continue;
		case OPT_SECCOMP_ENABLED:	/* --seccomp-enabled */
			update_setup_option(KBF_SECCOMP, SECCOMP_ENABLED);
			continue;
		case OPT_SECCOMP_TOLERANT:	/* --seccomp-tolerant */
			update_setup_option(KBF_SECCOMP, SECCOMP_TOLERANT);
			continue;
#endif

		case OPT_CURL_IFACE:	/* --curl-iface */
			update_setup_string(KSF_CURLIFACE, optarg_nonempty(logger));
			continue;
		case OPT_CURL_TIMEOUT:	/* --curl-timeout */
#define CRL_TIMEOUT_RANGE 1, 1000
			update_optarg_deltatime(KBF_CRL_TIMEOUT_SECONDS, logger,
						TIMESCALE_SECONDS, CRL_TIMEOUT_RANGE);
			continue;
		case OPT_CRL_STRICT:	/* --crl-strict */
			update_setup_yn(KYN_CRL_STRICT, YN_YES);
			continue;
		case OPT_CRLCHECKINTERVAL:	/* --crlcheckinterval <seconds> */
			update_setup_deltatime(KBF_CRL_CHECKINTERVAL,
					       optarg_deltatime(logger, TIMESCALE_SECONDS));
			continue;

		case OPT_OCSP_STRICT:
			update_setup_yn(KYN_OCSP_STRICT, YN_YES);
			continue;
		case OPT_OCSP_ENABLE:
			update_setup_yn(KYN_OCSP_ENABLE, YN_YES);
			continue;
		case OPT_OCSP_URI:
			update_setup_string(KSF_OCSP_URI, optarg_nonempty(logger));
			continue;
		case OPT_OCSP_TRUSTNAME:
			update_setup_string(KSF_OCSP_TRUSTNAME, optarg_nonempty(logger));
			continue;
		case OPT_OCSP_TIMEOUT:	/* --ocsp-timeout <seconds> */
#define OCSP_TIMEOUT_RANGE 1, 1000
			update_optarg_deltatime(KBF_OCSP_TIMEOUT_SECONDS, logger,
						TIMESCALE_SECONDS, OCSP_TIMEOUT_RANGE);
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
			update_setup_option(KBF_OCSP_CACHE_SIZE, u);
			continue;
		}
		case OPT_OCSP_CACHE_MIN_AGE:	/* --ocsp-cache-min-age <seconds> */
#define OCSP_CACHE_MIN_AGE_RANGE 1, -1
			update_optarg_deltatime(KBF_OCSP_CACHE_MIN_AGE_SECONDS, logger,
						TIMESCALE_SECONDS, OCSP_CACHE_MIN_AGE_RANGE);
			continue;
		case OPT_OCSP_CACHE_MAX_AGE:	/* --ocsp-cache-max-age <seconds> */
			/*
			 * NSS uses 0 for unlimited and -1 for
			 * disabled.  We use 0 for disabled, and a
			 * large number for unlimited.
			 */
#define OCSP_CACHE_MAX_AGE_RANGE 0, -1
			update_optarg_deltatime(KBF_OCSP_CACHE_MAX_AGE_SECONDS, logger,
						TIMESCALE_SECONDS, OCSP_CACHE_MAX_AGE_RANGE);
			continue;
		case OPT_OCSP_METHOD:	/* --ocsp-method get|post */
			update_setup_option(KBF_OCSP_METHOD, optarg_sparse(logger, 0, &ocsp_method_names));
			continue;

		case OPT_UNIQUEIDS:	/* --uniqueids */
			update_setup_yn(KYN_UNIQUEIDS, optarg_yn(logger, YN_YES));
			continue;

		case OPT_NO_DNSSEC:	/* --no-dnssec */
			update_setup_yn(KYN_DNSSEC_ENABLE, YN_NO);
			continue;

		case OPT_INTERFACE:	/* --interface <ifname|ifaddr> */
			continue;

#ifdef USE_NFLOG
		case OPT_NFLOG_ALL:	/* --nflog-all <group-number> */
			update_setup_option(KBF_NFLOG_ALL, optarg_uintmax(logger));
			continue;
#endif

		case OPT_IKE_SOCKET_ERRQUEUE:	/* --ike-socket-errqueue=... */
			update_setup_yn(KYN_IKE_SOCKET_ERRQUEUE, optarg_yn(logger, YN_YES));
			continue;
		case OPT_IKE_SOCKET_NO_ERRQUEUE:	/* --ike-socket-no-errqueue */
			update_setup_yn(KYN_IKE_SOCKET_ERRQUEUE, YN_YES);
			continue;
		case OPT_IKE_SOCKET_BUFSIZE:	/* --ike-socket-bufsize <bufsize> */
			update_setup_option(KBF_IKE_SOCKET_BUFSIZE, optarg_udp_bufsize(logger));
			continue;

		case OPT_RUNDIR:	/* --rundir <path> */
			update_setup_string(KSF_RUNDIR, optarg_nonempty(logger));
			continue;

		case OPT_SECRETSFILE:	/* --secretsfile <secrets-file> */
			/* allow empty */
			update_setup_string(KSF_SECRETSFILE, optarg_empty(logger));
			continue;

		case OPT_IPSECDIR:	/* --ipsecdir <ipsec-dir> */
			update_setup_string(KSF_IPSECDIR, optarg_nonempty(logger));
			continue;

		case OPT_NSSDIR:	/* --nssdir <path> */
			update_setup_string(KSF_NSSDIR, optarg_nonempty(logger));
			continue;

		case OPT_GLOBAL_REDIRECT:	/* --global-redirect */
			update_setup_option(KBF_GLOBAL_REDIRECT, optarg_sparse(logger, 0, &global_redirect_names));
			continue;
		case OPT_GLOBAL_REDIRECT_TO:	/* --global-redirect-to */
			/* force check; only allow one address ... */
			optarg_address_dns(logger, NULL/*unspec*/);
			/* then save string */
			update_setup_string(KSF_GLOBAL_REDIRECT_TO, optarg);
			continue;

		case OPT_KEEP_ALIVE:	/* --keep-alive <delay_secs> */
			update_setup_deltatime(KBF_KEEP_ALIVE, optarg_deltatime(logger, TIMESCALE_SECONDS));
			continue;

		case OPT_SELFTEST:	/* --selftest */
			selftest_only = true;
			fork_desired = false;
			update_setup_yn(KYN_LOGSTDERR, YN_YES);
			update_setup_yn(KYN_LOGTIME, YN_NO);
			continue;

		case OPT_VIRTUAL_PRIVATE:	/* --virtual-private */
			update_setup_string(KSF_VIRTUAL_PRIVATE, optarg);
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

			extract_config_deltatime(&pluto_shunt_lifetime, cfg, KBF_SHUNTLIFETIME);
			extract_config_deltatime(&pluto_expire_lifetime, cfg, KBF_EXPIRE_LIFETIME);

			config_ipsec_interface(cfg->setup->values[KYN_IPSEC_INTERFACE_MANAGED].option, logger);

			char *protostack = cfg->setup->values[KSF_PROTOSTACK].string;
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

		case OPT_DEBUG_NONE:	/* --debug-none */
			optarg_debug(OPTARG_DEBUG_NO);
			continue;
		case OPT_DEBUG_ALL:	/* --debug-all */
			optarg_debug(OPTARG_DEBUG_YES);
			continue;
		case OPT_DEBUG:
			optarg_debug(OPTARG_DEBUG_YES);
			continue;

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

	/* options processed save to obtain the setup */
	const struct config_setup *oco = config_setup_singleton();

	/* trash default; which is true */
	log_ip = config_setup_yn(oco, KYN_LOGIP);

	/* there's a rumor this is going away */
	pluto_uniqueIDs = config_setup_yn(oco, KYN_UNIQUEIDS);

	/* needs to be within range */
	deltatime_t expire_shunt_interval = check_config_deltatime(oco, KSF_EXPIRE_SHUNT_INTERVAL, logger,
							     EXPIRE_SHUNT_INTERVAL_RANGE,
							     "expire-shunt-interval");

	/* IKEv2 ignoring OPPO? */
	pluto_drop_oppo_null = config_setup_yn(oco, KYN_DROP_OPPO_NULL);

	/* redirect|to */

	init_global_redirect(config_setup_option(oco, KBF_GLOBAL_REDIRECT),
			     config_setup_string(oco, KSF_GLOBAL_REDIRECT_TO),
			     logger);

	/* ddos */
	init_ddos(oco, logger);

	/* listening et.al.? */
	init_ifaces(oco, logger);

	/*
	 * Extract/check x509 crl configuration before forking.
	 */

	x509_crl.curl_iface = config_setup_string(oco, KSF_CURLIFACE);
	x509_crl.strict = config_setup_yn(oco, KYN_CRL_STRICT);
	x509_crl.check_interval = config_setup_deltatime(oco, KBF_CRL_CHECKINTERVAL);
	x509_crl.timeout = check_config_deltatime(oco, KBF_CRL_TIMEOUT_SECONDS, logger,
						  CRL_TIMEOUT_RANGE, "crl-timeout");

	/*
	 * Extract/check X509 OCSP.
	 */

	x509_ocsp.enable = config_setup_yn(oco, KYN_OCSP_ENABLE);
	x509_ocsp.strict = config_setup_yn(oco, KYN_OCSP_STRICT);
	x509_ocsp.uri = config_setup_string(oco, KSF_OCSP_URI);
	x509_ocsp.trust_name = config_setup_string(oco, KSF_OCSP_TRUSTNAME);
	x509_ocsp.timeout = check_config_deltatime(oco, KBF_OCSP_TIMEOUT_SECONDS, logger,
						   OCSP_TIMEOUT_RANGE, "ocsp-timeout");
	x509_ocsp.cache_min_age = check_config_deltatime(oco, KBF_OCSP_CACHE_MIN_AGE_SECONDS, logger,
							 OCSP_CACHE_MIN_AGE_RANGE, "ocsp-cache-min-age");
	x509_ocsp.cache_max_age = check_config_deltatime(oco, KBF_OCSP_CACHE_MAX_AGE_SECONDS, logger,
							 OCSP_CACHE_MAX_AGE_RANGE, "ocsp-cache-max-age");
	x509_ocsp.method = config_setup_option(oco, KBF_OCSP_METHOD);
	x509_ocsp.cache_size = config_setup_option(oco, KBF_OCSP_CACHE_SIZE);

	/*
	 * Create the lock file before things fork.
	 *
	 * From now on fatal_error() needs to be called as that clears
	 * out the locks.
	 */

	int lockfd;
	if (selftest_only) {
		llog(RC_LOG, logger, "selftest: skipping lock");
		lockfd = -1;
	} else {
		lockfd = create_lock_file(oco, fork_desired, logger);
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
		/* may never return */
		init_ctl_socket(oco, logger);
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
		fill_and_close_lock_file(&lockfd, getpid());
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
				bool ok = fill_and_close_lock_file(&lockfd, pid);
				exit(ok ? 0 : 1);
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
		fill_and_close_lock_file(&lockfd, getpid());

		if (isatty(fileno(stdout)) && !config_setup_yn(oco, KYN_LOGSTDERR)) {
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
	 * (Debugging is enabled when either the config file sets
	 * LOG_PARAM.DEBUGGING, or a --debug option sets
	 * CUR_DEBUGGING.
	 */

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	PASSERT(logger, open("/dev/null", O_RDONLY) == STDIN_FILENO);
	PASSERT(logger, dup2(0, STDOUT_FILENO) == STDOUT_FILENO);

	lset_t new_debugging = config_setup_debugging(logger);
	if (cur_debugging || new_debugging) {
		check_open_fds(logger);
	}

	/*
	 * Switch to the real FILE/STDERR/SYSLOG logger (but first
	 * switch debugging flags when specified).
	 */

	switch_log(oco, &logger);

	/*
	 * Forking done; logging enabled.  Time to announce things to
	 * the world.
	 */

	llog(RC_LOG, logger, "Starting Pluto (Libreswan Version %s%s) pid:%u",
	     ipsec_version_code(), compile_time_interop_options, getpid());

	/*
	 * Enable debugging from the config file and announce it.
	 */
	cur_debugging = (new_debugging ? new_debugging : cur_debugging);
	if (cur_debugging) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, "debug: ");
			jam_lset_short(buf, &debug_names, "+", cur_debugging);
		}
	}
	if (have_impairments()) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, "impair: ");
			jam_impairments(buf, "+");
		}
	}

	init_kernel_info(logger);
	init_binlog(oco, logger);

	const char *coredir = config_setup_dumpdir();
	llog(RC_LOG, logger, "core dump dir: %s", coredir);
	if (chdir(coredir) == -1) {
		int e = errno;
		llog(RC_LOG, logger, "pluto: warning: chdir(\"%s\") to dumpdir failed (%d: %s)",
		     coredir, e, strerror(e));
	}

	const char *secretsfile = config_setup_secretsfile();
	if (secretsfile != NULL && strlen(secretsfile) > 0) {
		llog(RC_LOG, logger, "secrets file: %s", secretsfile);
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

	pluto_init_nss(config_setup_nssdir(), logger);
	init_seedbits(oco, logger);
	init_demux(oco, logger);

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
	llog(RC_LOG, logger, "FIPS HMAC integrity support [DISABLED]");
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
	bool audit_ok = linux_audit_init(config_setup_yn(oco, KYN_AUDIT_LOG), logger);
	llog(RC_LOG, logger, "Linux audit support [%s]",
	     (audit_ok ? "enabled" : "disabled"));
#else
	llog(RC_LOG, logger, "Linux audit support [DISABLED]");
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
	deltatime_t keep_alive = config_setup_deltatime(oco, KBF_KEEP_ALIVE);
	init_nat_traversal_timer(keep_alive, logger);
	init_ddns();

	const char *virtual_private = config_setup_string(oco, KSF_VIRTUAL_PRIVATE);
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

	start_server_helpers(config_setup_option(oco, KBF_NHELPERS), logger);

	init_kernel(logger, expire_shunt_interval);
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
	pluto_dnssec.enable = config_setup_yn(oco, KYN_DNSSEC_ENABLE);
	pluto_dnssec.rootkey_file = config_setup_string(oco, KSF_DNSSEC_ROOTKEY_FILE);
	pluto_dnssec.anchors = config_setup_string(oco, KSF_DNSSEC_ANCHORS);
	d = unbound_event_init(get_pluto_event_base(),
			       pluto_dnssec.enable,
			       pluto_dnssec.rootkey_file,
			       pluto_dnssec.anchors,
			       logger/*for-warnings*/);
	if (d != NULL) {
		fatal(PLUTO_EXIT_UNBOUND_FAIL, logger, "%s", str_diag(d));
	}
	llog(RC_LOG, logger, "DNSSEC support [%s]",
	     (pluto_dnssec.enable ? "enabled" : "disabled"));
#else
	llog(RC_LOG, logger, "DNSSEC support [not compiled in]");
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
	const struct config_setup *oco = config_setup_singleton();

	show_separator(s);
	show(s, "config setup options:");
	show_separator(s);
	show(s, "configdir=%s, configfile=%s, secrets=%s, ipsecdir=%s",
	     IPSEC_SYSCONFDIR,
		conffile, /* oco contains only a copy of hardcoded default */
	     config_setup_secretsfile(),
	     config_setup_ipsecdir());

	show(s, "nssdir=%s, dumpdir=%s, statsbin=%s",
	     config_setup_nssdir(),
	     config_setup_dumpdir(),
	     config_setup_string_or_unset(oco, KSF_STATSBIN, "unset"));

	SHOW_JAMBUF(s, buf) {
		jam(buf, "dnssec-enable=%s", bool_str(pluto_dnssec.enable));
		jam_string(buf, ", ");
		jam(buf, "dnssec-rootkey-file=%s",
		    (pluto_dnssec.rootkey_file == NULL ? "<unset>" : pluto_dnssec.rootkey_file));
		jam_string(buf, ", ");
		jam(buf, "dnssec-anchors=%s",
		    (pluto_dnssec.anchors == NULL ? "<unset>" : pluto_dnssec.anchors));
	}

	show(s, "sbindir=%s, libexecdir=%s",
		IPSEC_SBINDIR,
		IPSEC_EXECDIR);

	show(s, "pluto_version=%s, pluto_vendorid=%s",
	     ipsec_version_code(),
	     config_setup_vendorid());

	SHOW_JAMBUF(s, buf) {
		jam_string(buf, "nhelpers=");
		uintmax_t nhelpers = config_setup_option(oco, KBF_NHELPERS);
		if (nhelpers == UINTMAX_MAX) {
			jam_string(buf, "-1");
		} else {
			jam(buf, "%ju", nhelpers);
		}
		jam(buf, ", uniqueids=%s", bool_str(pluto_uniqueIDs));
		jam(buf, ", shuntlifetime=%jds", deltasecs(pluto_shunt_lifetime));
		jam(buf, ", expire-lifetime=%jds", deltasecs(pluto_expire_lifetime));
	}

	show_log(s);

	enum global_ikev1_policy ikev1_policy = config_setup_option(oco, KBF_IKEv1_POLICY);

	name_buf pb;
	name_buf mb;

	show(s,
	     "ddos-cookies-threshold=%ju, ddos-max-halfopen=%ju, ddos-mode=%s, ikev1-policy=%s",
	     config_setup_option(oco, KBF_DDOS_IKE_THRESHOLD),
	     config_setup_option(oco, KBF_MAX_HALFOPEN_IKE),
	     str_sparse_long(&ddos_mode_names, config_setup_option(oco, KBF_DDOS_MODE), &mb),
	     str_sparse_long(&global_ikev1_policy_names, ikev1_policy, &pb));

	/*
	 * Default global NFLOG group - 0 means no logging
	 *
	 * Note: variable is only used to display in `ipsec status`
	 * actual work is done outside pluto, by `ipsec checknflog`
	 * where it uses addconn to extract the value.  Look for
	 * NFGROUP= in ipsec.in.
	 *
	 * NFLOG group - 0 means no logging.
	 */
	uintmax_t nflog_all = config_setup_option(oco, KBF_NFLOG_ALL);

	show(s,
		"ikebuf=%d, msg_errqueue=%s, crl-strict=%s, crlcheckinterval=%jd, listen=%s, nflog-all=%ju",
		pluto_ike_socket_bufsize,
		bool_str(pluto_ike_socket_errqueue),
		bool_str(x509_crl.strict),
		deltasecs(x509_crl.check_interval),
		pluto_listen != NULL ? pluto_listen : "<any>",
		nflog_all
		);

	show_x509_ocsp(s);

	show_global_redirect(s);
}
