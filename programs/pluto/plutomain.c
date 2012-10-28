/* Pluto main program
 * Copyright (C) 1997      Angelos D. Keromytis.
 * Copyright (C) 1998-2001 D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com> 
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com> 
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
#include "oswconf.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "ac.h"
#ifdef XAUTH_HAVE_PAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"  /* needs packet.h */
#include "server.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "keys.h"
#include "secrets.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "rnd.h"
#include "state.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "fetch.h"
#include "timer.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h"	/* requires sha1.h and md5.h */
#include "vendor.h"
#include "pluto_crypt.h"

#include "virtual.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#ifdef TPM
#include <tcl.h>
#include "tpm/tpm.h"
#endif

#include "oswcrypto.h"

#ifndef IPSECDIR
#define IPSECDIR "/etc/ipsec.d"
#endif

#include <nss.h>
#include <nspr.h>
#ifdef FIPS_CHECK
# include <fipscheck.h>
  /* hardcoded path needs fixing! */
# define IPSECLIBDIR "/usr/libexec/ipsec"
# define IPSECSBINDIR "/usr/sbin"
#endif

#ifdef HAVE_LIBCAP_NG
# include <cap-ng.h>
#endif

#ifdef HAVE_LABELED_IPSEC
# include "security_selinux.h"
#endif

const char *ctlbase = "/var/run/pluto";
char *pluto_listen = NULL;

#ifdef DEBUG
libreswan_passert_fail_t libreswan_passert_fail = passert_fail;
#endif

/** usage - print help messages
 *
 * @param mess String - alternate message to print
 */
static void
usage(const char *mess)
{
    if (mess != NULL && *mess != '\0')
	fprintf(stderr, "%s\n", mess);
    fprintf(stderr
	, "Usage: pluto"
	    " [--help]"
	    " [--version]"
	    " [--optionsfrom <filename>]"
	    " \\\n\t"
	    "[--nofork]"
	    " [--stderrlog]"
	    " [--plutostderrlogtime]"
	    " [--force_busy]"
	    " [--nocrsend]"
	    " [--strictcrlpolicy]"
	    " [--crlcheckinterval]"
	    " [--uniqueids]"
	    " [--use-auto]"
	    " [--use-klips]"
	    " [--use-netkey]"
	    " [--use-mast]"
	    " [--use-bsdkame]"
	    " [--use-nostack]"         /* old --no_klips */
	    " \\\n\t"
	    "[--interface <ifname|ifaddr>]"
	    " [--ikeport <port-number>]"
	    "[--listen <ifaddr>]"
	    " \\\n\t"
	    "[--ctlbase <path>]"
	    " \\\n\t"
	    "[--perpeerlogbase <path>] [--perpeerlog]"
	    " \\\n\t"
	    "[--coredir <dirname>] [--noretransmits]"
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
#ifdef DEBUG
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
	    " [--debug-klips]"
	    " [--debug-netkey]"
	    " [--debug-x509]"
	    " [--debug-dns]"
	    " [--debug-oppo]"
	    " [--debug-oppoinfo]"
	    " [--debug-dpd]"
	    " [ --debug-private]"
	    " [ --debug-pfkey]"
#endif
#ifdef NAT_TRAVERSAL
	    " [ --debug-nat-t]"
	    " \\\n\t"
	    "[--nat_traversal] [--keep_alive <delay_sec>]"
	    " \\\n\t"
            "[--force_keepalive] [--disable_port_floating]"
#endif
	   " \\\n\t"
	   "[--virtual_private <network_list>]"
	    "\n"
	"Libreswan %s\n"
	, ipsec_version_code());
    exit(mess == NULL? 0 : 1);	/* not exit_pluto because we are not initialized yet */
}


/* lock file support
 * - provides convenient way for scripts to find Pluto's pid
 * - prevents multiple Plutos competing for the same port
 * - same basename as unix domain control socket
 * NOTE: will not take account of sharing LOCK_DIR with other systems.
 */

static char pluto_lock[sizeof(ctl_addr.sun_path)] = DEFAULT_CTLBASE LOCK_SUFFIX;
static bool pluto_lock_created = FALSE;

/** create lockfile, or die in the attempt */
static int
create_lock(void)
{
    int fd;

    if(mkdir(ctlbase, 0755) != 0) {
	if(errno != EEXIST) {
	    fprintf(stderr, "pluto: unable to create lock dir: \"%s\": %s\n"
		    , ctlbase, strerror(errno));
	    exit_pluto(10);
	}
    }
	    
    fd = open(pluto_lock, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC
	      , S_IRUSR | S_IRGRP | S_IROTH);

    if (fd < 0)
    {
	if (errno == EEXIST)
	{
	    fprintf(stderr, "pluto: lock file \"%s\" already exists\n"
		, pluto_lock);
	    exit_pluto(10);
	}
	else
	{
	    fprintf(stderr
		, "pluto: unable to create lock file \"%s\" (%d %s)\n"
		, pluto_lock, errno, strerror(errno));
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
static bool
fill_lock(int lockfd, pid_t pid)
{
    char buf[30];	/* holds "<pid>\n" */
    int len = snprintf(buf, sizeof(buf), "%u\n", (unsigned int) pid);
    bool ok = len > 0 && write(lockfd, buf, len) == len;

    close(lockfd);
    return ok;
}

/** delete_lock - Delete the lock file
 *
 */ 
static void
delete_lock(void)
{
    if (pluto_lock_created)
    {
	delete_ctl_socket();
	unlink(pluto_lock);	/* is noting failure useful? */
    }
}

/** by default pluto sends certificate requests to its peers */
bool no_cr_send = FALSE;

/** by default the CRL policy is lenient */
bool strict_crl_policy = FALSE;

/** by default pluto does not check crls dynamically */
long crl_check_interval = 0;

/** by default pluto sends no cookies in ikev2 or ikev1 aggrmode */
bool force_busy = FALSE;

/* whether or not to use klips */
enum kernel_interface kern_interface = AUTO_PICK;

char **global_argv;
int    global_argc;
bool   log_to_stderr_desired = FALSE;
bool   log_with_timestamp_desired = FALSE;

#ifdef HAVE_LABELED_IPSEC
u_int16_t secctx_attr_value=SECCTX;
#endif

int
main(int argc, char **argv)
{
    bool fork_desired = TRUE;
    int lockfd;
    int nhelpers = -1;
    char *coredir;
    const struct osw_conf_options *oco;

    coredir = NULL;

#ifdef NAT_TRAVERSAL
    /** Overridden by nat_traversal= in ipsec.conf */
    bool nat_traversal = FALSE;
    bool nat_t_spf = TRUE;  /* support port floating */
    unsigned int keep_alive = 0;
    bool force_keepalive = FALSE;
#endif
    /** Overridden by virtual_private= in ipsec.conf */
    char *virtual_private = NULL;
#ifdef LEAK_DETECTIVE
    leak_detective=1;
#else
    leak_detective=0;
#endif

#ifdef HAVE_LIBCAP_NG
	/* Drop capabilities */
	capng_clear(CAPNG_SELECT_BOTH);
	capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED,
			CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW,
			CAP_IPC_LOCK, CAP_AUDIT_WRITE,
			-1);
	/* our children must be able to CAP_NET_ADMIN to change routes.
	 */
	capng_updatev(CAPNG_ADD, CAPNG_BOUNDING_SET,
			CAP_NET_ADMIN, -1);
	capng_apply(CAPNG_SELECT_BOTH);
#endif


    global_argv = argv;
    global_argc = argc;
#ifdef DEBUG
    libreswan_passert_fail = passert_fail;
#endif

    if(getenv("PLUTO_WAIT_FOR_GDB")) {
	sleep(120);
    }

    /* handle arguments */
    for (;;)
    {
#	define DBG_OFFSET 256
	static const struct option long_opts[] = {
	    /* name, has_arg, flag, val */
	    { "help", no_argument, NULL, 'h' },
	    { "version", no_argument, NULL, 'v' },
	    { "optionsfrom", required_argument, NULL, '+' },
	    { "nofork", no_argument, NULL, 'd' },
	    { "stderrlog", no_argument, NULL, 'e' },
	    { "plutostderrlogtime", no_argument, NULL, 't' },
	    { "noklips", no_argument, NULL, 'n' },
	    { "use-nostack",  no_argument, NULL, 'n' },
	    { "use-none",     no_argument, NULL, 'n' },
	    { "force_busy", no_argument, NULL, 'D' },
	    { "nocrsend", no_argument, NULL, 'c' },
	    { "strictcrlpolicy", no_argument, NULL, 'r' },
	    { "crlcheckinterval", required_argument, NULL, 'x'},
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
	    { "ctlbase", required_argument, NULL, 'b' },
	    { "secretsfile", required_argument, NULL, 's' },
	    { "foodgroupsdir", required_argument, NULL, 'f' },
	    { "perpeerlogbase", required_argument, NULL, 'P' },
	    { "perpeerlog", no_argument, NULL, 'l' },
	    { "noretransmits", no_argument, NULL, 'R' },
	    { "coredir", required_argument, NULL, 'C' },
	    { "ipsecdir", required_argument, NULL, 'f' },
	    { "ipsec_dir", required_argument, NULL, 'f' },
	    { "adns", required_argument, NULL, 'a' },
#ifdef NAT_TRAVERSAL
	    { "nat_traversal", no_argument, NULL, '1' },
	    { "keep_alive", required_argument, NULL, '2' },
	    { "force_keepalive", no_argument, NULL, '3' },
	    { "disable_port_floating", no_argument, NULL, '4' },
	    { "debug-nat_t", no_argument, NULL, '5' },
	    { "debug-nattraversal", no_argument, NULL, '5' },
	    { "debug-nat-t", no_argument, NULL, '5' },
#endif
	    { "virtual_private", required_argument, NULL, '6' },
	    { "nhelpers", required_argument, NULL, 'j' },
#ifdef HAVE_LABELED_IPSEC
	    { "secctx_attr_value", required_argument, NULL, 'w' },
#endif
#ifdef DEBUG
	    { "debug-none", no_argument, NULL, 'N' },
	    { "debug-all", no_argument, NULL, 'A' },

	    { "debug-raw", no_argument, NULL, DBG_RAW + DBG_OFFSET },
	    { "debug-crypt", no_argument, NULL, DBG_CRYPT + DBG_OFFSET },
	    { "debug-crypto", no_argument, NULL, DBG_CRYPT + DBG_OFFSET },
	    { "debug-parsing", no_argument, NULL, DBG_PARSING + DBG_OFFSET },
	    { "debug-emitting", no_argument, NULL, DBG_EMITTING + DBG_OFFSET },
	    { "debug-control", no_argument, NULL, DBG_CONTROL + DBG_OFFSET },
	    { "debug-lifecycle", no_argument, NULL, DBG_LIFECYCLE + DBG_OFFSET },
	    { "debug-klips", no_argument, NULL, DBG_KLIPS + DBG_OFFSET },
	    { "debug-netkey", no_argument, NULL, DBG_NETKEY + DBG_OFFSET },
	    { "debug-dns", no_argument, NULL, DBG_DNS + DBG_OFFSET },
	    { "debug-oppo", no_argument, NULL, DBG_OPPO + DBG_OFFSET },
	    { "debug-oppoinfo", no_argument, NULL, DBG_OPPOINFO + DBG_OFFSET },
	    { "debug-controlmore", no_argument, NULL, DBG_CONTROLMORE + DBG_OFFSET },
	    { "debug-dpd", no_argument, NULL, DBG_DPD + DBG_OFFSET },
            { "debug-x509", no_argument, NULL, DBG_X509 + DBG_OFFSET },
	    { "debug-private", no_argument, NULL, DBG_PRIVATE + DBG_OFFSET },
	    { "debug-pfkey", no_argument, NULL, DBG_PFKEY + DBG_OFFSET },

	    { "impair-delay-adns-key-answer", no_argument, NULL, IMPAIR_DELAY_ADNS_KEY_ANSWER + DBG_OFFSET },
	    { "impair-delay-adns-txt-answer", no_argument, NULL, IMPAIR_DELAY_ADNS_TXT_ANSWER + DBG_OFFSET },
	    { "impair-bust-mi2", no_argument, NULL, IMPAIR_BUST_MI2 + DBG_OFFSET },
	    { "impair-bust-mr2", no_argument, NULL, IMPAIR_BUST_MR2 + DBG_OFFSET },
	    { "impair-sa-creation", no_argument, NULL, IMPAIR_SA_CREATION + DBG_OFFSET },
	    { "impair-die-oninfo", no_argument, NULL, IMPAIR_DIE_ONINFO + DBG_OFFSET },
	    { "impair-jacob-two-two", no_argument, NULL, IMPAIR_JACOB_TWO_TWO + DBG_OFFSET },
	    { "impair-major-version-bump", no_argument, NULL, IMPAIR_MAJOR_VERSION_BUMP + DBG_OFFSET },
	    { "impair-minor-version-bump", no_argument, NULL, IMPAIR_MINOR_VERSION_BUMP + DBG_OFFSET },
	    { "impair-retransmits", no_argument, NULL, IMPAIR_RETRANSMITS + DBG_OFFSET },
	    { "impair-send-bogus-isakmp-flag", no_argument, NULL, IMPAIR_SEND_BOGUS_ISAKMP_FLAG + DBG_OFFSET },
#endif
	    { 0,0,0,0 }
	    };
	/* Note: we don't like the way short options get parsed
	 * by getopt_long, so we simply pass an empty string as
	 * the list.  It could be "hvdenp:l:s:" "NARXPECK".
	 */
	int c = getopt_long(argc, argv, "", long_opts, NULL);

	/** Note: "breaking" from case terminates loop */
	switch (c)
	{
	case EOF:	/* end of flags */
	    break;

	case 0: /* long option already handled */
	    continue;

	case ':':	/* diagnostic already printed by getopt_long */
	case '?':	/* diagnostic already printed by getopt_long */
	    usage("");
	    break;   /* not actually reached */

	case 'h':	/* --help */
	    usage(NULL);
	    break;	/* not actually reached */

	case 'C':
	    coredir = clone_str(optarg, "coredir");
	    break;

	case 'v':	/* --version */
	    {
		printf("%s%s\n", ipsec_version_string(),
				 compile_time_interop_options);
	    }
	    exit(0);	/* not exit_pluto because we are not initialized yet */
	    break;	/* not actually reached */

	case '+':	/* --optionsfrom <filename> */
	    optionsfrom(optarg, &argc, &argv, optind, stderr);
	    /* does not return on error */
	    continue;

	case 'j':	/* --nhelpers */
            if (optarg == NULL || !isdigit(optarg[0]))
                usage("missing number of pluto helpers");

            {
                char *endptr;
                long count = strtol(optarg, &endptr, 0);

                if (*endptr != '\0' || endptr == optarg
		    || count < -1)
                    usage("<nhelpers> must be a positive number, 0 or -1");
                nhelpers = count;
            }
	    continue;

#ifdef HAVE_LABELED_IPSEC
	case 'w':	/* --secctx_attr_value*/
	    if (optarg == NULL || !isdigit(optarg[0]))
		usage("missing (positive integer) value of secctx_attr_value (needed only if using labeled ipsec)");

	   {
                char *endptr;
                long value = strtol(optarg, &endptr, 0);

                if (*endptr != '\0' || endptr == optarg
                    || (value != SECCTX && value !=10) )
                    usage("<secctx_attr_value> must be a positive number (32001 by default, 10 for backward compatibility, or any other future number assigned by IANA)");
                 secctx_attr_value = (u_int16_t)value;
	   }
	   continue;
#endif

	case 'd':	/* --nofork*/
	    fork_desired = FALSE;
	    continue;

	case 'e':	/* --stderrlog */
	    log_to_stderr_desired = TRUE;
	    continue;

	case 't':	/* --plutostderrlogtime */
	    log_with_timestamp_desired = TRUE;
	    continue;

	case 'G':       /* --use-auto */
	    kern_interface = AUTO_PICK;
	    continue;

	case 'k':       /* --use-klips */
	    kern_interface = USE_KLIPS;
	    continue;

	case 'L':	/* --listen ip_addr */
	    {
	    ip_address lip;
	     err_t e = ttoaddr(optarg,0,0,&lip);
	    if(e) {
		libreswan_log("invalid listen argument ignored: %s\n",e);
	    } else {
		pluto_listen = clone_str(optarg, "pluto_listen");
		libreswan_log("bind() will be filtered for %s\n",pluto_listen);
	    }
            }
	   continue;

	case 'M':       /* --use-mast */
	    kern_interface = USE_MASTKLIPS;
	    continue;

	case 'F':       /* --use-bsdkame */
	    kern_interface = USE_BSDKAME;
	    continue;

	case 'K':       /* --use-netkey */
	    kern_interface = USE_NETKEY;
	    continue;

	case 'n':	/* --use-nostack */
	    kern_interface = NO_KERNEL;
	    continue;

	case 'D':	/* --force_busy */
	    force_busy = TRUE;
	    continue
	    ;

	case 'c':	/* --nocrsend */
	    no_cr_send = TRUE;
	    continue
	    ;

	case 'r':	/* --strictcrlpolicy */
	    strict_crl_policy = TRUE;
	    continue
	    ;

	case 'R':
	    no_retransmits = TRUE;
	    continue;

	case 'x':	/* --crlcheckinterval <time>*/
            if (optarg == NULL || !isdigit(optarg[0]))
                usage("missing interval time");

            {
                char *endptr;
                long interval = strtol(optarg, &endptr, 0);

                if (*endptr != '\0' || endptr == optarg
                || interval <= 0)
                    usage("<interval-time> must be a positive number");
                crl_check_interval = interval;
            }
	    continue
	    ;

	case 'u':	/* --uniqueids */
	    uniqueIDs = TRUE;
	    continue;

	case 'i':	/* --interface <ifname|ifaddr> */
	    if (!use_interface(optarg))
		usage("too many --interface specifications");
	    continue;

	/* 
	 * This option does not really work, as this is the "left"
	 * site only, you also need --to --ikeport again later on
	 * It will result in: yourport -> 500, still not bypassing filters
	 */
	case 'p':	/* --ikeport <portnumber> */
	    if (optarg == NULL || !isdigit(optarg[0]))
		usage("missing port number");
	    {
		char *endptr;
		long port = strtol(optarg, &endptr, 0);

		if (*endptr != '\0' || endptr == optarg
		|| port <= 0 || port > 0x10000)
		    usage("<port-number> must be a number between 1 and 65535");
		pluto_port = port;
	    }
	    continue;

	case 'b':	/* --ctlbase <path> */
	    ctlbase = optarg;
	    if (snprintf(ctl_addr.sun_path, sizeof(ctl_addr.sun_path)
			 , "%s%s", ctlbase, CTL_SUFFIX) == -1)
		usage("<path>" CTL_SUFFIX " too long for sun_path");
	    if (snprintf(info_addr.sun_path, sizeof(info_addr.sun_path)
			 , "%s%s", ctlbase, INFO_SUFFIX) == -1)
		usage("<path>" INFO_SUFFIX " too long for sun_path");
	    if (snprintf(pluto_lock, sizeof(pluto_lock)
			 , "%s%s", ctlbase, LOCK_SUFFIX) == -1)
		usage("<path>" LOCK_SUFFIX " must fit");
	    continue;

	case 's':	/* --secretsfile <secrets-file> */
	    pluto_shared_secrets_file = optarg;
	    continue;

	case 'f':	/* --ipsecdir <ipsec-dir> */
	    (void)osw_init_ipsecdir(optarg);
	    continue;

	case 'a':	/* --adns <pathname> */
	    pluto_adns_option = optarg;
	    continue;

#ifdef DEBUG
	case 'N':	/* --debug-none */
	    base_debugging = DBG_NONE;
	    continue;

	case 'A':	/* --debug-all */
	    base_debugging = DBG_ALL;
	    continue;
#endif

	case 'P':       /* --perpeerlogbase */
	    base_perpeer_logdir = optarg;
	    continue;

	case 'l':
	    log_to_perpeer = TRUE;
	    continue;

#ifdef NAT_TRAVERSAL
	case '1':	/* --nat_traversal */
	    nat_traversal = TRUE;
	    continue;
	case '2':	/* --keep_alive */
	    keep_alive = atoi(optarg);
	    continue;
	case '3':	/* --force_keepalive */
	    force_keepalive = TRUE;
	    continue;
	case '4':	/* --disable_port_floating */
	    nat_t_spf = FALSE;
	    continue;
#ifdef DEBUG
	case '5':	/* --debug-nat_t */
	    base_debugging |= DBG_NATT;
	    continue;
#endif
#endif
	case '6':	/* --virtual_private */
	    virtual_private = optarg;
	    continue;

	default:
#ifdef DEBUG
	    if (c >= DBG_OFFSET)
	    {
		base_debugging |= c - DBG_OFFSET;
		continue;
	    }
#	undef DBG_OFFSET
#endif
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
    if(!coredir) {
	coredir = clone_str("/var/run/pluto", "coredir");
    }
    if(chdir(coredir) == -1) {
	int e = errno;
	libreswan_log("pluto: chdir() do dumpdir failed (%d: %s)\n",
	   e, strerror(e));
    }

    oco = osw_init_options();
    lockfd = create_lock();

    /* select between logging methods */

    if (log_to_stderr_desired) {
	log_to_syslog = FALSE;
	if (log_with_timestamp_desired)
	   log_with_timestamp = TRUE;
    }
    else 
	log_to_stderr = FALSE;

#ifdef DEBUG
#if 0
    if(kernel_ops->set_debug) {
	(*kernel_ops->set_debug)(cur_debugging, DBG_log, DBG_log);
    }
#endif
#endif

    /** create control socket.
     * We must create it before the parent process returns so that
     * there will be no race condition in using it.  The easiest
     * place to do this is before the daemon fork.
     */
    {
	err_t ugh = init_ctl_socket();

	if (ugh != NULL)
	{
	    fprintf(stderr, "pluto: %s", ugh);
	    exit_pluto(1);
	}
    }

#ifdef IPSECPOLICY
    /* create info socket. */
    {
	err_t ugh = init_info_socket();

	if (ugh != NULL)
	{
	    fprintf(stderr, "pluto: %s", ugh);
	    exit_pluto(1);
	}
    }
#endif

    /* If not suppressed, do daemon fork */

    if (fork_desired)
    {
	{
	    pid_t pid = fork();

	    if (pid < 0)
	    {
		int e = errno;

		fprintf(stderr, "pluto: fork failed (%d %s)\n",
		    errno, strerror(e));
		exit_pluto(1);
	    }

	    if (pid != 0)
	    {
		/* parent: die, after filling PID into lock file.
		 * must not use exit_pluto: lock would be removed!
		 */
		exit(fill_lock(lockfd, pid)? 0 : 1);
	    }
	}

	if (setsid() < 0)
	{
	    int e = errno;

	    fprintf(stderr, "setsid() failed in main(). Errno %d: %s\n",
		errno, strerror(e));
	    exit_pluto(1);
	}
    }
    else
    {
	/* no daemon fork: we have to fill in lock file */
	(void) fill_lock(lockfd, getpid());
	fprintf(stdout, "Pluto initialized\n");
	fflush(stdout);
    }

    /** Close everything but ctl_fd and (if needed) stderr.
     * There is some danger that a library that we don't know
     * about is using some fd that we don't know about.
     * I guess we'll soon find out.
     */
    {
	int i;

	for (i = getdtablesize() - 1; i >= 0; i--)  /* Bad hack */
	    if ((!log_to_stderr || i != 2)
#ifdef IPSECPOLICY
	    && i != info_fd
#endif
	    && i != ctl_fd)
		close(i);

	/* make sure that stdin, stdout, stderr are reserved */
	if (open("/dev/null", O_RDONLY) != 0)
	    osw_abort();
	if (dup2(0, 1) != 1)
	    osw_abort();
	if (!log_to_stderr && dup2(0, 2) != 2)
	    osw_abort();
    }

    init_constants();
    pluto_init_log();

	char buf[100];
	snprintf(buf, sizeof(buf), "%s",oco->confddir);
	loglog(RC_LOG_SERIOUS,"nss directory plutomain: %s",buf);
	SECStatus nss_init_status= NSS_InitReadWrite(buf);
	if (nss_init_status != SECSuccess) {
	    loglog(RC_LOG_SERIOUS, "NSS initialization failed (err %d)\n", PR_GetError());
        exit_pluto(10);
	} else {
	    loglog(RC_LOG_SERIOUS, "NSS Initialized");
	    PK11_SetPasswordFunc(getNSSPassword);

#ifdef FIPS_CHECK
	const char *package_files[]= { IPSECLIBDIR"/setup",
				        IPSECLIBDIR"/addconn",
				        IPSECLIBDIR"/auto",
				        IPSECLIBDIR"/barf",
				        IPSECLIBDIR"/eroute",
  				        IPSECLIBDIR"/ikeping",
  				        IPSECLIBDIR"/initnss",
				        IPSECLIBDIR"/readwriteconf",
					IPSECLIBDIR"/_keycensor",
					IPSECLIBDIR"/klipsdebug",
					IPSECLIBDIR"/look",
					IPSECLIBDIR"/newhostkey",
					IPSECLIBDIR"/pf_key",
					IPSECLIBDIR"/_pluto_adns",
					IPSECLIBDIR"/_plutoload",
					IPSECLIBDIR"/_plutorun",
					IPSECLIBDIR"/ranbits",
					IPSECLIBDIR"/_realsetup",
					IPSECLIBDIR"/rsasigkey",
					IPSECLIBDIR"/pluto",
					IPSECLIBDIR"/_secretcensor",
					IPSECLIBDIR"/secrets",
					IPSECLIBDIR"/showhostkey",
					IPSECLIBDIR"/showpolicy",
					IPSECLIBDIR"/spi",
					IPSECLIBDIR"/spigrp",
					IPSECLIBDIR"/_startklips",
					IPSECLIBDIR"/_startnetkey",
					IPSECLIBDIR"/tncfg",
					IPSECLIBDIR"/_updown",
					IPSECLIBDIR"/_updown.klips",
					IPSECLIBDIR"/_updown.mast",
					IPSECLIBDIR"/_updown.netkey", 
					IPSECLIBDIR"/verify",
					IPSECLIBDIR"/whack",
					IPSECSBINDIR"/ipsec",
					NULL
					};

       if (Pluto_IsFIPS() && !FIPSCHECK_verify_files(package_files)) {
             loglog(RC_LOG_SERIOUS, "FIPS integrity verification test failed");
             exit_pluto(10);
        }
#endif

      }

    /* Note: some scripts may look for this exact message -- don't change
     * ipsec barf was one, but it no longer does.
     */
    {
	const char *vc = ipsec_version_code();
#ifdef PLUTO_SENDS_VENDORID
	const char *v = init_pluto_vendorid();
	libreswan_log("Starting Pluto (Libreswan Version %s%s; Vendor ID %s) pid:%u"
		     , vc, compile_time_interop_options, v, getpid());
#else
	libreswan_log("Starting Pluto (Libreswan Version %s%s) pid:%u"
		     , vc, compile_time_interop_options, getpid());
#endif
	if(Pluto_IsFIPS()) {
		libreswan_log("Pluto is running in FIPS mode");
	}

	if((vc[0]=='c' && vc[1]=='v' && vc[2]=='s') ||
	   (vc[2]=='g' && vc[3]=='i' && vc[4]=='t')) {
	    /*
	     * when people build RPMs from CVS or GIT, make sure they
	     * get blamed appropriately, and that we get some way to
	     * identify who did it, and when they did it. Use string concat,
	     * so that strings the binary can or classic SCCS "what", will find
	     * stuff too.
	     */
	    libreswan_log("@(#) built on "__DATE__":" __TIME__ " by " BUILDER);
	}
#if defined(USE_1DES)
	libreswan_log("WARNING: 1DES is enabled");
#endif
    }

    if(coredir) {
	libreswan_log("core dump dir: %s", coredir);
    }

#ifdef LEAK_DETECTIVE
	libreswan_log("LEAK_DETECTIVE support [enabled]");
#else
	libreswan_log("LEAK_DETECTIVE support [disabled]");
#endif

#ifdef HAVE_OCF
       {
        struct stat buf;
	errno=0;

	if( stat("/dev/crypto",&buf) != -1) 
		libreswan_log("OCF support for IKE via /dev/crypto [enabled]");
	else 
		libreswan_log("OCF support for IKE via /dev/crypto [failed:%s]", strerror(errno));
       }
#else
	libreswan_log("OCF support for IKE [disabled]");
#endif

   /* Check for SAREF support */
#ifdef KLIPS_MAST
#include <ipsec_saref.h>
    {
	int e, sk, saref;
	saref = 1;
	errno=0;

	sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	e = setsockopt(sk, IPPROTO_IP, IP_IPSEC_REFINFO, &saref, sizeof(saref));
	if (e == -1 ) {
		libreswan_log("SAref support [disabled]: %s" , strerror(errno));
	}
	else {
		libreswan_log("SAref support [enabled]");
	}
	errno=0;
	e = setsockopt(sk, IPPROTO_IP, IP_IPSEC_BINDREF, &saref, sizeof(saref));
	if (e == -1 ) {
		libreswan_log("SAbind support [disabled]: %s" , strerror(errno));
	}
	else {
		libreswan_log("SAbind support [enabled]");
	}


	close(sk);
    }
#endif

	libreswan_log("NSS crypto [enabled]");

#ifdef XAUTH_HAVE_PAM
	libreswan_log("XAUTH PAM support [enabled]");
#else
	libreswan_log("XAUTH PAM support [disabled]");
#endif

#ifdef HAVE_STATSD
	libreswan_log("HAVE_STATSD notification via /bin/libreswan-statsd enabled");
#else
	libreswan_log("HAVE_STATSD notification support [disabled]");
#endif


/** Log various impair-* functions if they were enabled */

    if(DBGP(IMPAIR_BUST_MI2))
	libreswan_log("Warning: IMPAIR_BUST_MI2 enabled");
    if(DBGP(IMPAIR_BUST_MR2))
	libreswan_log("Warning: IMPAIR_BUST_MR2 enabled");
    if(DBGP(IMPAIR_SA_CREATION))
	libreswan_log("Warning: IMPAIR_SA_CREATION enabled");
    if(DBGP(IMPAIR_JACOB_TWO_TWO))
	libreswan_log("Warning: IMPAIR_JACOB_TWO_TWO enabled");
    if(DBGP(IMPAIR_DIE_ONINFO))
	libreswan_log("Warning: IMPAIR_DIE_ONINFO enabled");
    if(DBGP(IMPAIR_MAJOR_VERSION_BUMP))
	libreswan_log("Warning: IMPAIR_MAJOR_VERSION_BUMP enabled");
    if(DBGP(IMPAIR_MINOR_VERSION_BUMP))
	libreswan_log("Warning: IMPAIR_MINOR_VERSION_BUMP enabled");
    if(DBGP(IMPAIR_RETRANSMITS))
	libreswan_log("Warning: IMPAIR_RETRANSMITS enabled");
    if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG))
	libreswan_log("Warning: IMPAIR_SEND_BOGUS_ISAKMP_FLAG enabled");
    if(DBGP(IMPAIR_DELAY_ADNS_KEY_ANSWER))
	libreswan_log("Warning: IMPAIR_DELAY_ADNS_KEY_ANSWER enabled");
    if(DBGP(IMPAIR_DELAY_ADNS_TXT_ANSWER))
	libreswan_log("Warning: IMPAIR_DELAY_ADNS_TXT_ANSWER enabled");

/** Initialize all of the various features */

#ifdef NAT_TRAVERSAL
    init_nat_traversal(nat_traversal, keep_alive, force_keepalive, nat_t_spf);
#endif

    init_virtual_ip(virtual_private);
    /* obsoletd by nss code init_rnd_pool(); */
    init_timer();
    init_secret();
    init_states();
    init_connections();
    init_crypto();
    init_crypto_helpers(nhelpers);
    load_oswcrypto();
    init_demux();
    init_kernel();
    init_adns();
    init_id();

#ifdef TPM
    init_tpm();
#endif

#if defined(LIBCURL) || defined(LDAP_VER)
    init_fetch();
#endif

    /* loading X.509 CA certificates */
    load_authcerts("CA cert", oco->cacerts_dir, AUTH_CA);
    /* loading X.509 AA certificates */
    load_authcerts("AA cert", oco->aacerts_dir, AUTH_AA);

    /* loading X.509 CRLs */
    load_crls();
    /* loading attribute certificates (experimental) */
    load_acerts();

    /*Loading CA certs from NSS DB*/
    load_authcerts_from_nss("CA cert",  AUTH_CA);

#ifdef HAVE_LABELED_IPSEC
    init_avc();
#endif

    daily_log_event();
    call_server();
    return -1;	/* Shouldn't ever reach this */
}

/* leave pluto, with status.
 * Once child is launched, parent must not exit this way because
 * the lock would be released.
 *
 *  0 OK
 *  1 general discomfort
 * 10 lock file exists
 */
void
exit_pluto(int status)
{
    reset_globals();	/* needed because we may be called in odd state */
    free_preshared_secrets();
    free_remembered_public_keys();
    delete_every_connection();

    /* free memory allocated by initialization routines.  Please don't
       forget to do this. */

#ifdef TPM
    free_tpm();
#endif

#if defined(LIBCURL) || defined(LDAP_VER)
    free_crl_fetch();          /* free chain of crl fetch requests */
#endif
    free_authcerts();          /* free chain of X.509 authority certificates */
    free_crls();               /* free chain of X.509 CRLs */
    free_acerts();             /* free chain of X.509 attribute certificates */

    osw_conf_free_oco();	/* free global_oco containing path names */

    free_myFQDN();	    /* free myid FQDN */

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

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
