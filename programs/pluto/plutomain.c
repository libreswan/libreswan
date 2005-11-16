/* Pluto main program
 * Copyright (C) 1997      Angelos D. Keromytis.
 * Copyright (C) 1998-2001 D. Hugh Redelmeier.
 * Copyright (C) 2003-2004 Xelerance Corporation
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
 * RCSID $Id: plutomain.c,v 1.102.2.4 2005/08/12 01:15:00 ken Exp $
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
#include <resolv.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */
#include <sys/queue.h>

#include <openswan.h>

#include <pfkeyv2.h>
#include <pfkey.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "paths.h"
#include "certs.h"
#include "ac.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
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
#include "ocsp.h"
#include "fetch.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h"	/* requires sha1.h and md5.h */
#include "vendor.h"
#include "pluto_crypt.h"

#ifdef VIRTUAL_IP
#include "virtual.h"
#endif

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#ifndef IPSECDIR
#define IPSECDIR "/etc/ipsec.d"
#endif

const char *ipsec_dir = IPSECDIR;
const char *ctlbase = "/var/run/pluto";

openswan_passert_fail_t openswan_passert_fail = passert_fail;

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
	    " [--use-nostack]"         /* old --no_klips */
	    " [--nocrsend]"
	    " [--strictcrlpolicy]"
	    " [--crlcheckinterval]"
	    " [--ocspuri]"
	    " [--uniqueids]"
	    " [--use-auto]"
	    " [--use-klips]"
	    " [--use-netkey]"
	    " \\\n\t"
	    "[--interface <ifname>]"
	    " [--ikeport <port-number>]"
	    " \\\n\t"
	    "[--ctlbase <path>]"
	    " \\\n\t"
	    "[--perpeerlogbase <path>] [--perpeerlog]"
	    " \\\n\t"
	    "[--secretsfile <secrets-file>]"
	    " [--ipsecdir <ipsec-dir>]"
	    " \\\n\t"
	    "[--adns <pathname>]"
	    "[--nhelpers <number>]"
#ifdef DEBUG
	    " \\\n\t"
	    "[--debug-none]"
	    " [--debug-all]"
	    " \\\n\t"
	    "[--debug-raw]"
	    " [--debug-crypt]"
	    " [--debug-parsing]"
	    " [--debug-emitting]"
	    " \\\n\t"
	    "[--debug-control]"
	    " [--debug-klips]"
	    " [--debug-dns]"
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
#ifdef VIRTUAL_IP
	   " \\\n\t"
	   "[--virtual_private <network_list>]"
#endif
	    "\n"
	"Openswan %s\n"
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

/* whether or not to use klips */
enum kernel_interface kern_interface = AUTO_PICK;

char **global_argv;
int    global_argc;

int
main(int argc, char **argv)
{
    bool fork_desired = TRUE;
    bool log_to_stderr_desired = FALSE;
    int lockfd;
    char* ocspuri = NULL;
    int nhelpers = -1;
    char *coredir;

#ifdef NAT_TRAVERSAL
    /** Overridden by nat_traversal= in ipsec.conf */
    bool nat_traversal = FALSE;
    bool nat_t_spf = TRUE;  /* support port floating */
    unsigned int keep_alive = 0;
    bool force_keepalive = FALSE;
#endif
#ifdef VIRTUAL_IP
    /** Overridden by virtual_private= in ipsec.conf */
    char *virtual_private = NULL;
#endif

    global_argv = argv;
    global_argc = argc;
    openswan_passert_fail = passert_fail;

    /* see if there is an environment variable */
    coredir = getenv("PLUTO_CORE_DIR");

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
	    { "noklips", no_argument, NULL, 'n' },
	    { "use-nostack",  no_argument, NULL, 'n' },
	    { "nocrsend", no_argument, NULL, 'c' },
	    { "strictcrlpolicy", no_argument, NULL, 'r' },
	    { "crlcheckinterval", required_argument, NULL, 'x'},
	    { "ocsprequestcert", required_argument, NULL, 'q'},
	    { "ocspuri", required_argument, NULL, 'o'},
	    { "uniqueids", no_argument, NULL, 'u' },
	    { "useklips",  no_argument, NULL, 'k' },
	    { "use-klips",  no_argument, NULL, 'k' },
	    { "use-auto",  no_argument, NULL, 'G' },
	    { "usenetkey", no_argument, NULL, 'K' },
	    { "use-netkey", no_argument, NULL, 'K' },
	    { "interface", required_argument, NULL, 'i' },
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
#ifdef USE_LWRES
	    { "lwdnsq", required_argument, NULL, 'a' },
#else /* !USE_LWRES */
	    { "adns", required_argument, NULL, 'a' },
#endif /* !USE_LWRES */
#ifdef NAT_TRAVERSAL
	    { "nat_traversal", no_argument, NULL, '1' },
	    { "keep_alive", required_argument, NULL, '2' },
	    { "force_keepalive", no_argument, NULL, '3' },
	    { "disable_port_floating", no_argument, NULL, '4' },
	    { "debug-nat_t", no_argument, NULL, '5' },
	    { "debug-nattraversal", no_argument, NULL, '5' },
	    { "debug-nat-t", no_argument, NULL, '5' },
#endif
#ifdef VIRTUAL_IP
	    { "virtual_private", required_argument, NULL, '6' },
#endif
	    { "nhelpers", required_argument, NULL, 'j' },
#ifdef DEBUG
	    { "debug-none", no_argument, NULL, 'N' },
	    { "debug-all]", no_argument, NULL, 'A' },

	    { "debug-raw", no_argument, NULL, DBG_RAW + DBG_OFFSET },
	    { "debug-crypt", no_argument, NULL, DBG_CRYPT + DBG_OFFSET },
	    { "debug-parsing", no_argument, NULL, DBG_PARSING + DBG_OFFSET },
	    { "debug-emitting", no_argument, NULL, DBG_EMITTING + DBG_OFFSET },
	    { "debug-control", no_argument, NULL, DBG_CONTROL + DBG_OFFSET },
	    { "debug-lifecycle", no_argument, NULL, DBG_LIFECYCLE + DBG_OFFSET },
	    { "debug-klips", no_argument, NULL, DBG_KLIPS + DBG_OFFSET },
	    { "debug-dns", no_argument, NULL, DBG_DNS + DBG_OFFSET },
	    { "debug-oppo", no_argument, NULL, DBG_OPPO + DBG_OFFSET },
	    { "debug-controlmore", no_argument, NULL, DBG_CONTROLMORE + DBG_OFFSET },
	    { "debug-dpd", no_argument, NULL, DBG_DPD + DBG_OFFSET },
	    { "debug-private", no_argument, NULL, DBG_PRIVATE + DBG_OFFSET },
	    { "debug-pfkey", no_argument, NULL, DBG_PFKEY + DBG_OFFSET },

	    { "impair-delay-adns-key-answer", no_argument, NULL, IMPAIR_DELAY_ADNS_KEY_ANSWER + DBG_OFFSET },
	    { "impair-delay-adns-txt-answer", no_argument, NULL, IMPAIR_DELAY_ADNS_TXT_ANSWER + DBG_OFFSET },
	    { "impair-bust-mi2", no_argument, NULL, IMPAIR_BUST_MI2 + DBG_OFFSET },
	    { "impair-bust-mr2", no_argument, NULL, IMPAIR_BUST_MR2 + DBG_OFFSET },
	    { "impair-jacob-two-two", no_argument, NULL, IMPAIR_JACOB_TWO_TWO + DBG_OFFSET },
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
		const char **sp = ipsec_copyright_notice();

		printf("%s%s\n", ipsec_version_string(),
				 compile_time_interop_options);
		for (; *sp != NULL; sp++)
		    puts(*sp);
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
                    usage("<interval-time> must be a positive number, 0 or -1");
                nhelpers = count;
            }
	    continue;

	case 'd':	/* --nofork*/
	    fork_desired = FALSE;
	    continue;

	case 'e':	/* --stderrlog */
	    log_to_stderr_desired = TRUE;
	    continue;

	case 'G':       /* --use-auto */
	    kern_interface = AUTO_PICK;
	    continue;

	case 'k':       /* --use-klips */
	    kern_interface = USE_KLIPS;
	    continue;

	case 'K':       /* --use-netkey */
	    kern_interface = USE_NETKEY;
	    continue;

	case 'n':	/* --use-nostack */
	    kern_interface = NO_KERNEL;
	    continue;

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

	case 'o':	/* --ocspuri */
	    ocspuri = optarg;
	    continue;

	case 'u':	/* --uniqueids */
	    uniqueIDs = TRUE;
	    continue;

	case 'i':	/* --interface <ifname> */
	    if (!use_interface(optarg))
		usage("too many --interface specifications");
	    continue;

	case 'p':	/* --port <portnumber> */
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
	    shared_secrets_file = optarg;
	    continue;

	case 'f':	/* --ipsecdir <ipsec-dir> */
	    ipsec_dir = optarg;
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
	case '5':	/* --debug-nat_t */
	    base_debugging |= DBG_NATT;
	    continue;
#endif
#ifdef VIRTUAL_IP
	case '6':	/* --virtual_private */
	    virtual_private = optarg;
	    continue;
#endif

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

    /* if a core dir was set, chdir there */
    if(coredir) {
	chdir(coredir);
    }

    lockfd = create_lock();

    /* select between logging methods */

    if (log_to_stderr_desired)
	log_to_syslog = FALSE;
    else
	log_to_stderr = FALSE;

    /* set the logging function of pfkey debugging */
#ifdef DEBUG
    pfkey_debug_func = DBG_log;
    pfkey_error_func = DBG_log;
#else
    pfkey_debug_func = NULL;
    pfkey_error_func = NULL;
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
	    abort();
	if (dup2(0, 1) != 1)
	    abort();
	if (!log_to_stderr && dup2(0, 2) != 2)
	    abort();
    }

    init_constants();
    pluto_init_log();

    /* Note: some scripts may look for this exact message -- don't change
     * ipsec barf was one, but it no longer does.
     */
    {
#ifdef PLUTO_SENDS_VENDORID
        const char *v = init_pluto_vendorid();
	const char *vc = ipsec_version_code();

        openswan_log("Starting Pluto (Openswan Version %s%s; Vendor ID %s)"
            , vc
            , compile_time_interop_options
            , v);
	if(vc[0]=='c' && vc[1]=='v' && vc[2]=='s') {
	    /*
	     * when people build RPMs from CVS, make sure they get blamed
	     * appropriately, and that we get some way to identify who
	     * did it, and when they did it. Use string concat, so that
	     * strings the binary can or classic SCCS "what", will find
	     * stuff too.
	     */
	    openswan_log("@(#) built on "__DATE__":"__TIME__":"BUILDER);
	}
#else
        openswan_log("Starting Pluto (Openswan Version %s%s)"
            , ipsec_version_code()
            , compile_time_interop_options);
#endif
    }

    if(coredir) {
	openswan_log("core dump dir: %s", coredir);
    }

/** Initialize all of the various features */

#ifdef NAT_TRAVERSAL
    init_nat_traversal(nat_traversal, keep_alive, force_keepalive, nat_t_spf);
#endif

#ifdef VIRTUAL_IP
    init_virtual_ip(virtual_private);
#endif
    init_rnd_pool();
    init_secret();
    init_states();
    init_connections();
    init_crypto();
    init_crypto_helpers(nhelpers);
    init_demux();
    init_kernel();
    init_adns();
    init_id();

#ifdef HAVE_THREADS
    init_fetch();
#endif

    ocsp_set_default_uri(ocspuri);

    /* loading X.509 CA certificates */
    load_authcerts("CA cert", CA_CERT_PATH, AUTH_CA);
    /* loading X.509 AA certificates */
    load_authcerts("AA cert", AA_CERT_PATH, AUTH_AA);
    /* loading X.509 OCSP certificates */
    load_authcerts("OCSP cert", OCSP_CERT_PATH, AUTH_OCSP);

    /* loading X.509 CRLs */
    load_crls();
    /* loading attribute certificates (experimental) */
    load_acerts();

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

#ifdef HAVE_THREADS
    free_crl_fetch();          /* free chain of crl fetch requests */
#endif
#ifdef HAVE_OCSP
    free_ocsp_fetch();         /* free chain of ocsp fetch requests */
#endif
    free_authcerts();          /* free chain of X.509 authority certificates */
    free_crls();               /* free chain of X.509 CRLs */
    free_acerts();             /* free chain of X.509 attribute certificates */
    free_ocsp();               /* free ocsp cache */

    free_ifaces();          /* free interface list from memory */
    stop_adns();            /* Stop async DNS process (if running) */
    free_md_pool();         /* free the md pool */
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
