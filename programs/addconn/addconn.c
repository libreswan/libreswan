/*
 * A program to read the configuration file and load a single conn
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 */

/*
 * This program performed synchronous DNS lookups via ttoaddr() and has been
 * converted to using libunbound in asyncrhonous mode
 * It should be rewriten to resolve/load connections asynchronously
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
/* #include <linux/netdevice.h> */
#include <net/if.h>
/* #include <linux/types.h> */ /* new */
#include <sys/stat.h>
#include <limits.h>
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
#include <libreswan.h>
#ifdef DNSSEC
# include "dnssec.h"
# include <unbound.h>
#endif
#include "sysdep.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswconf.h"
#include "oswlog.h"
#include "whack.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/starterlog.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterwhack.h"
#include "ipsecconf/keywords.h"

char *progname;
int verbose=0;
int warningsarefatal = 0;

static const char *usage_string = ""
    "Usage: addconn [--config file] \n"
    "               [--addall] [--listroute] [--liststart]\n"
    "               [--rootdir dir] \n"
    "               [--ctlbase socketfile] \n"
    "               [--configsetup] \n"
    "               {--checkconfig] \n"
    "               {--verbose] \n"
    "               [--defaultroute <addr>] [--defaultroutenexthop <addr>]\n"
    "               names\n";


static void usage(void)
{
    /* print usage */
    fputs(usage_string, stderr);
    exit(10);
}

extern char rootdir[PATH_MAX];       /* when evaluating paths, prefix this to them */

static struct option const longopts[] =
{
	{"config",              required_argument, NULL, 'C'},
	{"defaultroute",        required_argument, NULL, 'd'},
	{"defaultroutenexthop", required_argument, NULL, 'n'},
	{"debug",               no_argument, NULL, 'D'},
	{"verbose",             no_argument, NULL, 'D'},
	{"warningsfatal",       no_argument, NULL, 'W'},
	{"addall",              no_argument, NULL, 'a'},
	{"listroute",           no_argument, NULL, 'r'},
	{"liststart",           no_argument, NULL, 's'},
	{"varprefix",           required_argument, NULL, 'P'},
	{ "ctlbase",            required_argument, NULL, 'c' },
	{"search",              no_argument, NULL, 'S'},
	{"rootdir",             required_argument, NULL, 'R'},
	{"configsetup",         no_argument, NULL, 'T'},
	{"checkconfig",		no_argument, NULL, 'K'},
	{"help",                no_argument, NULL, 'h'},
	{0, 0, 0, 0}
};



int
main(int argc, char *argv[])
{
    int opt = 0;
    int all = 0;
    int search = 0;
    int typeexport = 0;
    int checkconfig = 0;
    int listroute=0, liststart=0;
    struct starter_config *cfg = NULL;
    err_t err = NULL;
    char *confdir = NULL;
    char *configfile = NULL;
    char *varprefix = "";
    int exit_status = 0;
    struct starter_conn *conn = NULL;
    char *defaultroute = NULL;
    char *defaultnexthop = NULL;
    char *ctlbase = NULL;
    bool resolvip = FALSE;
#ifdef DNSSEC
/* our unbound resolver */
struct ub_ctx *dnsctx = ub_ctx_create();
#endif

#if 0
    /* efence settings */
    extern int EF_PROTECT_BELOW;
    extern int EF_PROTECT_FREE;

    EF_PROTECT_BELOW=1;
    EF_PROTECT_FREE=1;
#endif


    progname = argv[0];
    rootdir[0]='\0';

    tool_init_log();

    while((opt = getopt_long(argc, argv, "", longopts, 0)) != EOF) {
	switch(opt) {
	case 'h':
	    /* usage: */
	    usage();
	    break;

	case 'a':
	    all=1;
	    break;

	case 'D':
	    verbose++;
	    break;

	case 'W':
	    warningsarefatal++;
	    break;

	case 'S':
	    search++;
	    break;

	case 'T':
	    typeexport++;
	    break;

	case 'K':
	    checkconfig++;
	    break;

	case 'C':
	    configfile = clone_str(optarg, "config file name");
	    break;

	case 'c':
	    ctlbase = clone_str(optarg, "control base");
	    break;

	case 'A':
	    all=1;
	    break;

	case 'r':
	    listroute=1;
	    break;

	case 's':
	    liststart=1;
	    break;

	case 'P':
	    varprefix=optarg;
	    break;

	case 'R':
	    printf("setting rootdir=%s\n", optarg);
	    strncat(rootdir, optarg, sizeof(rootdir)-1);
	    break;

	case 'd':
	    defaultroute=optarg;
	    break;

	case 'n':
	    defaultnexthop=optarg;
	    break;

	default:
	    usage();
	}
    }

    /* if nothing to add, then complain */
    if(optind == argc && !all && !listroute && !liststart && !search && !typeexport && !checkconfig) {
	usage();
    }

    if(verbose > 3) {
	extern int yydebug;
	yydebug=1;
    }

    /* find config file */
    confdir = getenv(IPSEC_CONFDIR_VAR);
    if(confdir == NULL)
    {
	confdir = IPSEC_CONFDIR;
    }

    if(!configfile) {
	configfile = alloc_bytes(strlen(confdir)+sizeof("/ipsec.conf")+2,"conf file");

	/* calculate default value for configfile */
	configfile[0]='\0';
	strcpy(configfile, confdir);
	if(configfile[strlen(configfile)-1]!='/')
	{
	    strcat(configfile, "/");
	}
	strcat(configfile, "ipsec.conf");
    }

    if(verbose) {
	printf("opening file: %s\n", configfile);
    }

    starter_use_log (verbose, 1, verbose ? 0 : 1);

    err = NULL;      /* reset to no error */
    resolvip=TRUE;   /* default to looking up names */

    if(typeexport || checkconfig || listroute || liststart || search) {
	/* but not if we have no use for them... might cause delays too! */
	resolvip=FALSE;
    }

#ifdef DNSSEC
    if(resolvip) {
	/* initialise our DNSSEC resolver context */
	if(!unbound_init(dnsctx)){
		fprintf(stderr,"unbound_init() failed, aborting\n");
		return 1;
	}
	if(verbose) {
	   fprintf(stderr,"unbound_init() called\n");
	}
    }
#endif

    cfg = confread_load(configfile, &err, resolvip, ctlbase,typeexport);

    if(cfg == NULL) {
	fprintf(stderr, "can not load config '%s': %s\n",
		configfile, err);
	exit(3);
    }
    else if(checkconfig) {
	confread_free(cfg);
	exit(0);
    }

    if(defaultroute) {
	char b[ADDRTOT_BUF];
	if (tnatoaddr(defaultroute, strlen(defaultroute), AF_INET, &cfg->dr) != NULL
	&& tnatoaddr(defaultroute, strlen(defaultroute), AF_INET6, &cfg->dr) != NULL) {

	   /* It's not an IPv4 or IPv6 address, try a dns lookup */
#ifdef DNSSEC
	   if(verbose) {
		printf("Calling unbound_resolve() for defaultroute value\n");
	   }
	   bool e = unbound_resolve(dnsctx, defaultroute, strlen(defaultroute), AF_INET, &cfg->dr);
	   if(!e) {
		e = unbound_resolve(dnsctx, defaultroute, strlen(defaultroute), AF_INET6, &cfg->dr);
	   }
	   if(!e) {
		printf("ignoring invalid defaultroute: %s\n", defaultroute);
#else
	   /* ttoaddr() ends up calling gethostbyname(), which does not support DNSSEC */
	   err_t ugh = ttoaddr(defaultroute, strlen(defaultroute), AF_INET, &cfg->dr);
	   if(ugh != NULL) {
		ugh = ttoaddr(defaultroute, strlen(defaultroute), AF_INET6, &cfg->dr);
	   }
	   if(ugh != NULL) {
		printf("ignoring invalid defaultroute: %s:%s\n", defaulroute, ugh);
#endif
	    defaultroute = NULL;
	    /* exit(4); */
	    } 
	}
	if(verbose) {
	   addrtot(&cfg->dr, 0, b, sizeof(b));
	   printf("default route is: %s\n", b);
	}
    }


    if(defaultnexthop) {
	char b[ADDRTOT_BUF];
	if (tnatoaddr(defaultnexthop, strlen(defaultnexthop), AF_INET, &cfg->dnh) != NULL
	&& tnatoaddr(defaultnexthop, strlen(defaultnexthop), AF_INET6, &cfg->dnh) != NULL) {

	   /* It's not an IPv4 or IPv6 address, try a dns lookup */
#ifdef DNSSEC
	   if(verbose) {
		printf("Calling unbound_resolve() for defaultnexthop value\n");
	   }
	   bool e = unbound_resolve(dnsctx, defaultnexthop, strlen(defaultnexthop), AF_INET, &cfg->dnh);
	   if(!e) {
		e = unbound_resolve(dnsctx, defaultnexthop, strlen(defaultnexthop), AF_INET6, &cfg->dnh);
	   }
	   if(!e) {
		printf("ignoring invalid defaultnexthop: %s\n", defaultnexthop);
#else
	   /* ttoaddr() ends up calling gethostbyname(), which does not support DNSSEC */
	   err_t ugh = ttoaddr(defaultnexthop, strlen(defaultnexthop), AF_INET, &cfg->dnh);
	   if(ugh != NULL) {
		ugh = ttoaddr(defaultnexthop, strlen(defaultnexthop), AF_INET6, &cfg->dnh);
	   }
	   if(ugh != NULL) {
		printf("ignoring invalid defaultnexthop: %s:%s\n", defaulroute, ugh);
#endif
	    defaultnexthop = NULL;
	    /* exit(4); */
	    } 
	}
	if(verbose) {
	   addrtot(&cfg->dnh, 0, b, sizeof(b));
	   printf("default route is: %s\n", b);
	}
    }

    if(all)
    {
	if(verbose) {
	    printf("loading all conns:");
	}
	/* load all conns marked as auto=add or better */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_ADD
		|| conn->desired_state == STARTUP_START
		|| conn->desired_state == STARTUP_ROUTE) {
		if(verbose) printf(" %s", conn->name);
		starter_whack_add_conn(cfg, conn);
	    }
	}
	if(verbose) printf("\n");
    } else if(listroute) {
	if(verbose) {
	    printf("listing all conns marked as auto=start\n");
	}
	/* list all conns marked as auto=route or start or better */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_START
		|| conn->desired_state == STARTUP_ROUTE) {
		printf("%s ", conn->name);
	    }
	}
	printf("\n");
    } else if(liststart) {
	/* list all conns marked as auto=start */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_START) {
		printf("%s ", conn->name);
	    }
	}
	printf("\n");
    } else if(search) {
	char *sep="";
	if((argc-optind) < 2 ) {
	    printf("%s_confreadstatus=failed\n", varprefix);
	    confread_free(cfg);
	    exit(3);
	}

	printf("%s_confreadstatus=\n", varprefix);
	printf("%s_confreadnames=\"",varprefix);

	/* find conn names that have value set */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    /* we recognize a limited set of values */
	    if(strcasecmp(argv[optind],"auto")==0 &&
	       strcasecmp(argv[optind+1],"manual")==0) {
		if(conn->manualkey) {
		    printf("%s%s", sep, conn->name);
		    sep=" ";
		}
	    }
	}
	printf("\"\n");
	confread_free(cfg);
	exit(0);

    } else if(typeexport) {
        struct keyword_def *kd;

	printf("export %sconfreadstatus=''\n", varprefix);
	for(kd=ipsec_conf_keywords_v2; kd->keyname != NULL; kd++) {
	    if((kd->validity & kv_config)==0) continue;

	    switch(kd->type) {
	    case kt_string:
	    case kt_filename:
	    case kt_dirname:
	    case kt_loose_enum:
		if(cfg->setup.strings[kd->field]) {
		    printf("export %s%s='%s'\n",
			   varprefix, kd->keyname,
			   cfg->setup.strings[kd->field]);
		}
		break;

	    case kt_bool:
		printf("export %s%s='%s'\n",
		       varprefix, kd->keyname,
		       cfg->setup.options[kd->field] ? "yes" : "no");
		break;

	    case kt_list:
		printf("export %s%s='",
		       varprefix, kd->keyname);
		confwrite_list(stdout, "", cfg->setup.options[kd->field], kd);
		printf("'\n");
		break;

	    case kt_obsolete:
		printf("# obsolete option '%s%s' ignored\n", varprefix, kd->keyname);
		break;

	    default:
		if(cfg->setup.options[kd->field] || cfg->setup.options_set[kd->field]) {
		    printf("export %s%s='%d'\n",
			   varprefix, kd->keyname,
			   cfg->setup.options[kd->field]);
		}
		break;
	    }
	}

	confread_free(cfg);
	exit(0);

    } else {
	/* load named conns, regardless of their state */
	int   connum;

	if(verbose) {
	    printf("loading named conns:");
	}
	for(connum = optind; connum<argc; connum++) {
	    char *connname = argv[connum];

	    if(verbose) {
		printf(" %s", connname);
	    }
	    for(conn = cfg->conns.tqh_first;
		conn != NULL;
		conn = conn->link.tqe_next)
	    {
		/* yes, let's make it case-insensitive */
		if(strcasecmp(conn->name, connname)==0) {
		    if(conn->state == STATE_ADDED) {
			printf("\nconn %s already added\n", conn->name);
		    } else if(conn->state == STATE_FAILED) {
			printf("\nconn %s did not load properly\n", conn->name);
		    } else {
			exit_status = starter_whack_add_conn(cfg, conn);
			conn->state = STATE_ADDED;
		    }
		    break;
		}
	    }

	    if(conn == NULL) {
		/* only if we don't find it, do we now look for aliases */

		for(conn = cfg->conns.tqh_first;
		    conn != NULL;
		    conn = conn->link.tqe_next)
		{
		    if(conn->strings_set[KSF_CONNALIAS]
		       && osw_alias_cmp(connname
					, conn->strings[KSF_CONNALIAS])) {

			if(conn->state == STATE_ADDED) {
			    printf("\nalias: %s conn %s already added\n", connname, conn->name);
			} else if(conn->state == STATE_FAILED) {
			    printf("\nalias: %s conn %s did not load properly\n", connname, conn->name);
			} else {
			    exit_status = starter_whack_add_conn(cfg, conn);
			    conn->state = STATE_ADDED;
			}
			break;
		    }
		}
	    }

	    if(conn == NULL) {
		exit_status++;
		if(!verbose) {
		    printf("conn '%s': not found (tried aliases)\n", connname);
		} else {
		    printf("(notfound)");
		}
	    }
	}
	if(verbose) printf("\n");
    }

#ifdef DNSSEC
	ub_ctx_delete(dnsctx);
#endif
    confread_free(cfg);
    exit(exit_status);
}

void exit_tool(int x)
{
  exit(x);
}

/*
 *
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 *
 */
