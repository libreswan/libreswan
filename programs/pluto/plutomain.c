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
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2016 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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
#include "lswfips.h"
#include "lswnss.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pluto_x509.h"
#include "nss_ocsp.h"
#include "certs.h"
#include "connections.h"	/* needs id.h */
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "server.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "keys.h"
#include "secrets.h"    /* for free_remembered_public_keys() */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "rnd.h"
#include "state.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "fetch.h"
#include "timer.h"
#include "ipsecconf/confread.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h"	/* requires sha1.h and md5.h */
#include "vendor.h"
#include "pluto_crypt.h"

#include "virtual.h"	/* needs connections.h */

#include "nat_traversal.h"

#include "cbc_test_vectors.h"
#include "ctr_test_vectors.h"

#ifndef IPSECDIR
#define IPSECDIR "/etc/ipsec.d"
#endif

#include <nss.h>
#include <nspr.h>

#ifdef HAVE_LIBCAP_NG
# include <cap-ng.h>	/* from libcap-ng devel */
#endif

#ifdef HAVE_LABELED_IPSEC
# include "security_selinux.h"
#endif

# include "pluto_sd.h"

static const char *pluto_name;	/* name (path) we were invoked with */

static const char *ctlbase = "/var/run/pluto";
char *pluto_listen = NULL;
static bool fork_desired = USE_FORK || USE_DAEMON;

#ifdef FIPS_CHECK
# include <fipscheck.h> /* from fipscheck devel */
static const char *fips_package_files[] = { IPSEC_EXECDIR "/pluto", NULL };
#endif

/* pulled from main for show_setup_plutomain() */
static const struct lsw_conf_options *oco;
static char *coredir;
static int pluto_nss_seedbits;
static int nhelpers = -1;

extern bool strict_crl_policy;
extern bool strict_ocsp_policy;
extern bool ocsp_enable;
extern char *curl_iface;
extern long curl_timeout;
extern bool pluto_drop_oppo_null;
extern int bare_shunt_interval;

static char *ocsp_default_uri = NULL;
static char *ocsp_trust_name = NULL;
static int ocsp_timeout = OCSP_DEFAULT_TIMEOUT;

libreswan_passert_fail_t libreswan_passert_fail = passert_fail;

static void free_pluto_main(void)
{
	/* Some values can be NULL if not specified as pluto argument */
	pfree(coredir);
	pfreeany(pluto_stats_binary);
	pfreeany(pluto_listen);
	pfree(pluto_vendorid);
}

/*
 * invocation_fail - print diagnostic and usage hint message and exit
 *
 * @param mess String - diagnostic message to print
 */
static void invocation_fail(const char *mess)
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
	" USE_FORK"
#endif
#if USE_VFORK
	" USE_VFORK"
#endif
#if USE_DAEMON
	" USE_DAEMON"
#endif
#if USE_PTHREAD_SETSCHEDPRIO
	" USE_PTHREAD_SETSCHEDPRIO"
#endif
#ifdef HAVE_BROKEN_POPEN
	" BROKEN_POPEN"
#endif
	" NSS"
#ifdef DNSSEC
	" DNSSEC"
#endif
#ifdef USE_SYSTEMD_WATCHDOG
	" USE_SYSTEMD_WATCHDOG"
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

/*
 * lock file support
 * - provides convenient way for scripts to find Pluto's pid
 * - prevents multiple Plutos competing for the same port
 * - same basename as unix domain control socket
 * NOTE: will not take account of sharing LOCK_DIR with other systems.
 */
static char pluto_lock[sizeof(ctl_addr.sun_path)] =
	DEFAULT_CTLBASE LOCK_SUFFIX;
static bool pluto_lock_created = FALSE;

/* create lockfile, or die in the attempt */
static int create_lock(void)
{
	int fd;

	if (mkdir(ctlbase, 0755) != 0) {
		if (errno != EEXIST) {
			fprintf(stderr,
				"pluto: FATAL: unable to create lock dir: \"%s\": %s\n",
				ctlbase, strerror(errno));
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
int warningsarefatal = 0;

/* Read config file. exit() on error. */
static struct starter_config *read_cfg_file(char *configfile)
{
	struct starter_config *cfg = NULL;
	err_t err = NULL;

	cfg = confread_load(configfile, &err, FALSE, NULL, TRUE);
	if (cfg == NULL)
		invocation_fail(err);
	return cfg;
}

/* Helper function for config file mapper: set string option value */
static void set_cfg_string(char **target, char *value)
{
	/* Do nothing if value is unset. */
	if (value == NULL || *value == '\0')
		return;

	/* Don't free previous target, it might be statically set. */
	*target = strdup(value);
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
		DBG(DBG_CONTROL,DBG_log("need %d bits random for extra seeding of the NSS PRNG",
			(int) nbytes * BITS_PER_BYTE));

	while (ndone < nbytes) {
		got = read(dev, buf + ndone, nbytes - ndone);
		if (got < 0) {
			loglog(RC_LOG_SERIOUS,"read error on %s (%s)\n",
				device, strerror(errno));
			exit_pluto(PLUTO_EXIT_NSS_FAIL);
		}
		if (got == 0) {
			loglog(RC_LOG_SERIOUS,"EOF on %s!?!\n",  device);
			exit_pluto(PLUTO_EXIT_NSS_FAIL);
		}
		ndone += got;
	}
	close(dev);
	DBG(DBG_CONTROL,DBG_log("read %zu bytes from /dev/random for NSS PRNG",
		nbytes));
}

static bool pluto_init_nss(char *nssdb)
{
	SECStatus rv;

	/* little lie, lsw_nss_setup doesn't have logging */
	loglog(RC_LOG_SERIOUS, "NSS DB directory: sql:%s", nssdb);

	lsw_nss_buf_t err;
	if (!lsw_nss_setup(nssdb, LSW_NSS_READONLY, lsw_nss_get_password, err)) {
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
		unsigned char *buf = alloc_bytes(seedbytes,"TLA seedmix");

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
deltatime_t crl_check_interval = { 0 };

/* whether or not to use klips */
enum kernel_interface kern_interface = USE_NETKEY;	/* new default */

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
u_int16_t secctx_attr_type = SECCTX;
#endif

/*
 * Table of Pluto command-line options.
 *
 * For getopt_ling(3), but with twists.
 *
 * We never find that letting getopt set an option makes sense
 * so flag is always NULL.
 *
 * Trick: we split the "name" string with a '\0'.
 * Before it is the option name, as seen by getopt_long.
 * After it is meta-information:
 * - _ means: obsolete due to _ in name: replace _ with -
 * - > means: obsolete spelling; use spelling from rest of string
 * - ! means: obsolete and ignored (no replacement)
 * - anything else is a description of the options argument (printed by --help)
 *   If it starts with ^, that means start a newline in the --help output.
 *
 * The table should be ordered to maximize the clarity of --help.
 *
 * val values free due to removal of options: '1', '3', '4'
 */

#define DBG_OFFSET 256
static const struct option long_opts[] = {
	/* name, has_arg, flag, val */
	{ "help\0", no_argument, NULL, 'h' },
	{ "version\0", no_argument, NULL, 'v' },
	{ "config\0<filename>", required_argument, NULL, 'z' },
	{ "nofork\0", no_argument, NULL, 'd' },
	{ "stderrlog\0", no_argument, NULL, 'e' },
	{ "logfile\0<filename>", required_argument, NULL, 'g' },
	{ "log-no-time\0", no_argument, NULL, 't' }, /* was --plutostderrlogtime */
	{ "log-no-append\0", no_argument, NULL, '7' },
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
	{ "crlcheckinterval\0", required_argument, NULL, 'x' },
	{ "uniqueids\0", no_argument, NULL, 'u' },
	{ "noklips\0>use-nostack", no_argument, NULL, 'n' },	/* redundant spelling */
	{ "use-nostack\0",  no_argument, NULL, 'n' },
	{ "use-none\0>use-nostack", no_argument, NULL, 'n' },	/* redundant spelling */
	{ "useklips\0>use-klips",  no_argument, NULL, 'k' },	/* redundant spelling */
	{ "use-klips\0",  no_argument, NULL, 'k' },
	{ "use-auto\0>use-netkey",  no_argument, NULL, 'K' },	/* rednundate spelling (sort of) */
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
	{ "nflog-all\0<group-number>", required_argument, NULL, 'G' },
	{ "natikeport\0<port-number>", required_argument, NULL, 'q' },
	{ "ctlbase\0<path>", required_argument, NULL, 'b' },
	{ "secretsfile\0<secrets-file>", required_argument, NULL, 's' },
	{ "perpeerlogbase\0<path>", required_argument, NULL, 'P' },
	{ "perpeerlog\0", no_argument, NULL, 'l' },
	{ "coredir\0>dumpdir", required_argument, NULL, 'C' },	/* redundant spelling */
	{ "dumpdir\0<dirname>", required_argument, NULL, 'C' },
	{ "statsbin\0<filename>", required_argument, NULL, 'S' },
	{ "ipsecdir\0<ipsec-dir>", required_argument, NULL, 'f' },
	{ "ipsec_dir\0>ipsecdir", required_argument, NULL, 'f' },	/* redundant spelling; _ */
	{ "foodgroupsdir\0>ipsecdir", required_argument, NULL, 'f' },	/* redundant spelling */
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
	{ "vendorid\0<vendorid>", required_argument, NULL, 'V' },

	{ "leak-detective\0", no_argument, NULL, 'X' },
	{ "debug-nat_t\0>debug-nattraversal", no_argument, NULL, '5' },	/* redundant spelling; _ */
	{ "debug-nat-t\0>debug-nattraversal", no_argument, NULL, '5' },	/* redundant spelling */
	{ "debug-nattraversal\0", no_argument, NULL, '5' },
	{ "debug-none\0^", no_argument, NULL, 'N' },
	{ "debug-all\0", no_argument, NULL, 'A' },

	/* --debug-* options (using D for shorthand) */
#define D(name, code) { "debug-" name, no_argument, NULL, (code) + DBG_OFFSET }
	D("raw\0", DBG_RAW_IX),
	D("crypt\0", DBG_CRYPT_IX),
	D("crypto\0>crypt", DBG_CRYPT_IX),	/* redundant spelling */
	D("parsing\0", DBG_PARSING_IX),
	D("emitting\0", DBG_EMITTING_IX),
	D("control\0", DBG_CONTROL_IX),
	D("lifecycle\0", DBG_LIFECYCLE_IX),
	D("kernel\0", DBG_KERNEL_IX),
	D("klips\0>kernel", DBG_KERNEL_IX),	/* redundant spelling */
	D("netkey\0>kernel", DBG_KERNEL_IX),	/* redundant spelling */
	D("dns\0", DBG_DNS_IX),
	D("oppo\0", DBG_OPPO_IX),
	D("oppoinfo\0", DBG_OPPOINFO_IX),
	D("controlmore\0", DBG_CONTROLMORE_IX),
	D("dpd\0", DBG_DPD_IX),
	D("x509\0", DBG_X509_IX),
	D("private\0", DBG_PRIVATE_IX),
	D("pfkey\0", DBG_PFKEY_IX),
#undef D

	/* --impair-* options (using I for shorthand) */
#define I(name, code) { "impair-" name, no_argument, NULL, (code) + DBG_OFFSET }
	I("bust-mi2\0", IMPAIR_BUST_MI2_IX),
	I("bust-mr2\0", IMPAIR_BUST_MR2_IX),
	I("sa-creation\0", IMPAIR_SA_CREATION_IX),
	I("die-oninfo\0", IMPAIR_DIE_ONINFO_IX),
	I("jacob-two-two\0", IMPAIR_JACOB_TWO_TWO_IX),
	I("major-version-bump\0", IMPAIR_MAJOR_VERSION_BUMP_IX),
	I("minor-version-bump\0", IMPAIR_MINOR_VERSION_BUMP_IX),
	I("retransmits\0", IMPAIR_RETRANSMITS_IX),
	I("send-bogus-isakmp-flag\0", IMPAIR_SEND_BOGUS_ISAKMP_FLAG_IX),
	I("send-bogus-payload-flag\0", IMPAIR_SEND_BOGUS_PAYLOAD_FLAG_IX),
	I("send-ikev2-ke\0", IMPAIR_SEND_IKEv2_KE_IX),
	I("send-key-size-check\0", IMPAIR_SEND_KEY_SIZE_CHECK_IX),
	I("send-no-delete\0", IMPAIR_SEND_NO_DELETE_IX),
	I("send-no-ikev2-auth\0", IMPAIR_SEND_NO_IKEV2_AUTH_IX),
	I("force-fips\0", IMPAIR_FORCE_FIPS_IX),
	I("send-zero-gx\0", IMPAIR_SEND_ZERO_GX_IX),
	I("send-bogus-dcookie\0", IMPAIR_SEND_BOGUS_DCOOKIE_IX),
#undef I
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


#if 0
/*
 * XXX: Can't use this call to get encrypt_desc struct encrypt_desc
 */
extern struct encrypt_desc algo_aes_cbc;
extern struct encrypt_desc algo_camellia_cbc;
extern struct encrypt_desc algo_aes_ctr;
#endif

int main(int argc, char **argv)
{
#if 0
	NSS_NoDB_Init(".");
	if (!test_aes_cbc(&algo_aes_cbc)) {
		printf("aes-cbc failed\n");
	}
	if (!test_camellia_cbc(&algo_camellia_cbc)) {
		printf("camellia-cbc failed\n");
	}
	if (!test_aes_ctr(&algo_aes_ctr)) {
		printf("aes-ctr failed\n");
	}
	exit(0);
#endif

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

	coredir = clone_str("/var/run/pluto", "coredir in main()");
	pluto_vendorid = clone_str(ipsec_version_vendorid(), "vendorid in main()");

	unsigned int keep_alive = 0;

	/* Overridden by virtual_private= in ipsec.conf */
	char *virtual_private = NULL;

	libreswan_passert_fail = passert_fail;

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
			coredir = clone_str(optarg, "pluto_vendorid via getopt");
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

		case 'd':	/* --nofork*/
			fork_desired = FALSE;
			continue;

		case 'e':	/* --stderrlog */
			log_to_stderr_desired = TRUE;
			continue;

		case 'g':	/* --logfile */
			pluto_log_file = optarg;
			log_to_file_desired = TRUE;
			continue;

		case 't':	/* --log-no-time */
			log_with_timestamp = FALSE;
			continue;

		case '7':	/* --log-no-append */
			log_append = FALSE;
			continue;

		case '8':	/* --drop-oppo-null */
			pluto_drop_oppo_null = TRUE;
			continue;

		case '9':	/* --expire-bare-shunt <interval> */
			ugh = ttoulb(optarg, 0, 10, 1000, &u);
			if (ugh != NULL)
				break;
			bare_shunt_interval = u;
			continue;

		case 'k':	/* --use-klips */
			kern_interface = USE_KLIPS;
			continue;

		case 'L':	/* --listen ip_addr */
		{
			ip_address lip;
			err_t e = ttoaddr(optarg, 0, AF_UNSPEC, &lip);

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

		case 'Z':	/* --curl-iface */
			curl_iface = optarg;
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
			strict_crl_policy = TRUE;
			continue;

		case 'o':
			strict_ocsp_policy = TRUE;
			continue;

		case 'O':
			ocsp_enable = TRUE;
			continue;

		case 'Y':
			ocsp_default_uri = optarg;
			continue;

		case 'J':
			ocsp_trust_name = optarg;
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

		case 'x':	/* --crlcheckinterval <seconds> */
			ugh = ttoulb(optarg, 0, 10, TIME_T_MAX, &u);
			if (ugh != NULL)
				break;
			crl_check_interval = deltatime(u);
			continue;

		case 'u':	/* --uniqueids */
			uniqueIDs = TRUE;
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

		case 'b':	/* --ctlbase <path> */
			/*
			 * ??? work to be done here:
			 *
			 * snprintf returns the required space if there
			 * isn't enough, not -1.
			 * -1 indicates another kind of error.
			 *
			 * This appears to be the only place where the
			 * ctlbase value is used yet it is set elsewhere.
			 * (This isn't clear -- it may be OK.)
			 */
			ctlbase = optarg;
			if (snprintf(ctl_addr.sun_path,
					sizeof(ctl_addr.sun_path),
					"%s%s", ctlbase, CTL_SUFFIX) == -1) {
				ugh = "<path>" CTL_SUFFIX " too long for sun_path";
				break;
			}

			if (snprintf(info_addr.sun_path,
					sizeof(info_addr.sun_path),
					"%s%s", ctlbase, INFO_SUFFIX) == -1) {
				ugh = "<path>" INFO_SUFFIX " too long for sun_path";
				break;
			}

			if (snprintf(pluto_lock, sizeof(pluto_lock),
					"%s%s", ctlbase, LOCK_SUFFIX) == -1) {
				ugh = "<path>" LOCK_SUFFIX " must fit";
				break;
			}
			continue;

		case 's':	/* --secretsfile <secrets-file> */
			lsw_conf_secretsfile(optarg);
			continue;

		case 'f':	/* --ipsecdir <ipsec-dir> */
			lsw_init_ipsecdir(optarg);
			continue;

		case 'N':	/* --debug-none */
			base_debugging = DBG_NONE;
			continue;

		case 'A':	/* --debug-all */
			base_debugging = DBG_ALL;
			continue;

		case 'P':	/* --perpeerlogbase */
			base_perpeer_logdir = optarg;
			continue;

		case 'l':	/* --perpeerlog */
			log_to_perpeer = TRUE;
			continue;

		case '2':	/* --keep-alive <delay_secs> */
			ugh = ttoulb(optarg, 0, 10, secs_per_day, &u);
			if (ugh != NULL)
				break;
			keep_alive = u;
			continue;

		case '5':	/* --debug-nat-t */
			base_debugging |= DBG_NATT;
			continue;
		case '6':	/* --virtual-private */
			virtual_private = optarg;
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
			if (pluto_log_file != NULL)
				log_to_syslog = FALSE;
			/* plutofork= no longer supported via config file */
			log_with_timestamp =
				cfg->setup.options[KBF_PLUTOSTDERRLOGTIME];
			log_append = cfg->setup.options[KBF_PLUTOSTDERRLOGAPPEND];
			pluto_drop_oppo_null = cfg->setup.options[KBF_DROP_OPPO_NULL];
			pluto_ddos_mode = cfg->setup.options[KBF_DDOS_MODE];
			if (cfg->setup.options[KBF_FORCEBUSY]) {
				/* force-busy is obsoleted, translate to ddos-mode= */
				pluto_ddos_mode = cfg->setup.options[KBF_DDOS_MODE] = DDOS_FORCE_BUSY;
			}
			/* ddos-ike-threshold and max-halfopen-ike */
			pluto_ddos_threshold = cfg->setup.options[KBF_DDOS_IKE_THRESHOLD];
			pluto_max_halfopen = cfg->setup.options[KBF_MAX_HALFOPEN_IKE];

			strict_crl_policy =
				cfg->setup.options[KBF_STRICTCRLPOLICY];

			pluto_shunt_lifetime = deltatime(cfg->setup.options[KBF_SHUNTLIFETIME]);

			strict_ocsp_policy =
				cfg->setup.options[KBF_STRICTOCSPPOLICY];

			ocsp_enable = cfg->setup.options[KBF_OCSPENABLE];

			set_cfg_string(&ocsp_default_uri,
				       cfg->setup.strings[KSF_OCSPURI]);

			ocsp_timeout = cfg->setup.options[KBF_OCSPTIMEOUT];

			set_cfg_string(&ocsp_trust_name,
				       cfg->setup.strings[KSF_OCSPTRUSTNAME]);

			crl_check_interval = deltatime(
				cfg->setup.options[KBF_CRLCHECKINTERVAL]);
			uniqueIDs = cfg->setup.options[KBF_UNIQUEIDS];
			/*
			 * We don't check interfaces= here because that part
			 * has been dealt with in _stackmanager before we
			 * started
			 */
			set_cfg_string(&pluto_listen,
				cfg->setup.strings[KSF_LISTEN]);

			/* --ikeport */
			pluto_port = cfg->setup.options[KBF_IKEPORT];

			/* --nflog-all */
			/* only causes nflog nmber to show in ipsec status */
			pluto_nflog_group = cfg->setup.options[KBF_NFLOG_ALL];

			/* only causes nflog nmber to show in ipsec status */
			pluto_xfrmlifetime = cfg->setup.options[KBF_XFRMLIFETIME];

			/* no config option: ctlbase */
			/* --secrets */
			if (cfg->setup.strings[KSF_SECRETSFILE] &&
			    *cfg->setup.strings[KSF_SECRETSFILE]) {
				lsw_conf_secretsfile(cfg->setup.strings[KSF_SECRETSFILE]);
			}
			if (cfg->setup.strings[KSF_IPSECDIR] != NULL &&
				*cfg->setup.strings[KSF_IPSECDIR] != 0) {
				/* --ipsecdir */
				lsw_init_ipsecdir(cfg->setup.strings[KSF_IPSECDIR]);
			}

			/* --perpeerlog */
			log_to_perpeer = cfg->setup.options[KBF_PERPEERLOG];
			if (log_to_perpeer) {
				/* --perpeerlogbase */
				if (cfg->setup.strings[KSF_PERPEERDIR]) {
					set_cfg_string(&base_perpeer_logdir,
						cfg->setup.strings[KSF_PERPEERDIR]);
				} else {
					base_perpeer_logdir = clone_str("/var/log/pluto/", "perpeer_logdir");
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

			/* no config option: pluto_adns_option */

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
			keep_alive = cfg->setup.options[KBF_KEEPALIVE];

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

		default:
			if (DBG_OFFSET <= c &&
			    c < DBG_OFFSET + IMPAIR_roof_IX) {
				base_debugging |= LELEM(c - DBG_OFFSET);
				continue;
			}
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
	lockfd = create_lock();

	/* select between logging methods */

	if (log_to_stderr_desired || log_to_file_desired)
		log_to_syslog = FALSE;
	if (!log_to_stderr_desired)
		log_to_stderr = FALSE;

#if 0
	if (kernel_ops->set_debug != NULL)
		(*kernel_ops->set_debug)(cur_debugging, DBG_log, DBG_log);

#endif

	/*
	 * create control socket.
	 * We must create it before the parent process returns so that
	 * there will be no race condition in using it.  The easiest
	 * place to do this is before the daemon fork.
	 */
	{
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
		if (open("/dev/null", O_RDONLY) != 0)
			lsw_abort();
		if (dup2(0, 1) != 1)
			lsw_abort();
		if (!log_to_stderr && dup2(0, 2) != 2)

			lsw_abort();
	}

	init_constants();
	init_pluto_constants();

	pluto_init_log();

	if (!pluto_init_nss(oco->nssdb)) {
		loglog(RC_LOG_SERIOUS, "FATAL: NSS initialization failure");
		exit_pluto(PLUTO_EXIT_NSS_FAIL);
	}
	libreswan_log("NSS crypto library initialized");

	if (ocsp_enable) {
		if (!init_nss_ocsp(ocsp_default_uri, ocsp_trust_name,
						     ocsp_timeout,
						     strict_ocsp_policy)) {
			loglog(RC_LOG_SERIOUS, "Initializing NSS OCSP failed");
			exit_pluto(PLUTO_EXIT_NSS_FAIL);
		} else {
			libreswan_log("NSS OCSP Enabled");
		}
	}

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
	 * CAP_NET_RAW for iptables -t mangle
	 * CAP_DAC_READ_SEARCH for pam / google authenticator
	 */
	capng_updatev(CAPNG_ADD, CAPNG_BOUNDING_SET, CAP_NET_ADMIN, CAP_NET_RAW,
			CAP_DAC_READ_SEARCH, -1);
	capng_apply(CAPNG_SELECT_BOTH);
	libreswan_log("libcap-ng support [enabled]");
#else
	libreswan_log("libcap-ng support [disabled]");
#endif

#ifdef FIPS_CHECK
	libreswan_log("FIPS HMAC integrity support [enabled]");
	/*
	 * FIPS mode requires two conditions to be true:
	 *  - FIPS Kernel mode: fips=1 kernel boot parameter
	 *  - FIPS Product mode: See FIPSPRODUCTCHECK in Makefile.inc
	 *     (in RHEL/Fedora, dracut-fips installs $FIPSPRODUCTCHECK)
	 *
	 * When FIPS mode, abort on self-check hmac failure. Otherwise, complain
	 */
	{
		if (DBGP(IMPAIR_FORCE_FIPS)) {
			libreswan_log("Forcing FIPS checks to true to emulate FIPS mode");
			lsw_set_fips_mode(LSW_FIPS_ON);
		}

		enum lsw_fips_mode pluto_fips_mode = lsw_get_fips_mode();
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

/* Log various impair-* functions if they were enabled */

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
	if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG))
		libreswan_log("Warning: IMPAIR_SEND_BOGUS_PAYLOAD_FLAG enabled");
	if (DBGP(IMPAIR_SEND_IKEv2_KE))
		libreswan_log("Warning: IMPAIR_SEND_IKEv2_KE enabled");
	if (DBGP(IMPAIR_SEND_KEY_SIZE_CHECK))
		libreswan_log("Warning: IMPAIR_SEND_KEY_SIZE_CHECK enabled");
	if (DBGP(IMPAIR_SEND_NO_DELETE))
		libreswan_log("Warning: IMPAIR_SEND_NO_DELETE enabled");
	if (DBGP(IMPAIR_FORCE_FIPS))
		libreswan_log("Warning: IMPAIR_FORCE_FIPS enabled");
	if (DBGP(IMPAIR_SEND_NO_IKEV2_AUTH))
		libreswan_log("Warning: IMPAIR_SEND_NO_IKEV2_AUTH enabled");
	if (DBGP(IMPAIR_SEND_ZERO_GX))
		libreswan_log("Warning: IMPAIR_SEND_ZERO_GX enabled");
	if (DBGP(IMPAIR_SEND_BOGUS_DCOOKIE))
		libreswan_log("Warning: IMPAIR_SEND_BOGUS_DCOOKIE enabled");

/* Initialize all of the various features */

	init_nat_traversal(keep_alive);

	init_virtual_ip(virtual_private);
	/* obsoleted by nss code init_rnd_pool(); */
	init_event_base();
	init_secret();
	init_states();
	init_connections();
	init_crypto();
	init_crypto_helpers(nhelpers);
	init_demux();
	init_kernel();
	init_id();
	init_vendorid();
#if defined(LIBCURL) || defined(LDAP_VER)
	init_fetch();
#endif
	load_crls();
#ifdef HAVE_LABELED_IPSEC
	init_avc();
#endif
	daily_log_event();
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd_init();
#endif

	call_server();
	return -1;	/* Shouldn't ever reach this */
}

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

#if defined(LIBCURL) || defined(LDAP_VER)
	free_crl_fetch();	/* free chain of crl fetch requests */
#endif

	lsw_conf_free_oco();	/* free global_oco containing path names */

	free_myFQDN();	/* free myid FQDN */

	free_ifaces();	/* free interface list from memory */
	free_md_pool();	/* free the md pool */
	lsw_nss_shutdown();
	delete_lock();	/* delete any lock files */
	free_virtual_ip();	/* virtual_private= */
	free_kernelfd();	/* stop listening to kernel FD, remove event */
	free_pluto_main();	/* our static chars */

	/* report memory leaks now, after all free_* calls */
	if (leak_detective)
		report_leaks();
	close_log();	/* close the logfiles */
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_EXIT,status);
#endif
	exit(status);	/* exit, with our error code */
}

void show_setup_plutomain(void)
{
	whack_log(RC_COMMENT, "config setup options:");	/* spacer */
	whack_log(RC_COMMENT, " ");	/* spacer */
	whack_log(RC_COMMENT,
		"configdir=%s, configfile=%s, secrets=%s, ipsecdir=%s, dumpdir=%s, statsbin=%s",
		oco->confdir,
		oco->conffile,
		oco->secretsfile,
		oco->confddir,
		coredir,
		pluto_stats_binary == NULL ? "unset" :  pluto_stats_binary);

	whack_log(RC_COMMENT, "sbindir=%s, libexecdir=%s",
		IPSEC_SBINDIR,
		IPSEC_EXECDIR);

	whack_log(RC_COMMENT, "pluto_version=%s, pluto_vendorid=%s",
		ipsec_version_code(),
		pluto_vendorid);

	whack_log(RC_COMMENT,
		"nhelpers=%d, uniqueids=%s, perpeerlog=%s, shuntlifetime=%lus, xfrmlifetime=%ds",
		nhelpers,
		uniqueIDs ? "yes" : "no",
		!log_to_perpeer ? "no" : base_perpeer_logdir,
		deltasecs(pluto_shunt_lifetime),
		pluto_xfrmlifetime
	);

	whack_log(RC_COMMENT,
		"ddos-cookies-threshold=%d, ddos-max-halfopen=%d, ddos-mode=%s",
		pluto_max_halfopen,
		pluto_ddos_threshold,
		(pluto_ddos_mode == DDOS_AUTO) ? "auto" :
			(pluto_ddos_mode == DDOS_FORCE_BUSY) ? "busy" : "unlimited");

	whack_log(RC_COMMENT,
		"ikeport=%d, strictcrlpolicy=%s, crlcheckinterval=%lu, listen=%s, nflog-all=%d",
		pluto_port,
		strict_crl_policy ? "yes" : "no",
		deltasecs(crl_check_interval),
		pluto_listen != NULL ? pluto_listen : "<any>",
		pluto_nflog_group
		);

#ifdef HAVE_LABELED_IPSEC
	whack_log(RC_COMMENT, "secctx-attr-type=%d", secctx_attr_type);
#else
	whack_log(RC_COMMENT, "secctx-attr-type=<unsupported>");
#endif
}

