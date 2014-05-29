/* command interface to Pluto
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2003  D. Hugh Redelmeier.
 * Copyright (C) 2004-2008 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Shingo Yamawaki
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
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
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>

#include <libreswan.h>

#include "sysdep.h"
#include "socketwrapper.h"
#include "constants.h"
#include "lswlog.h"
#include "defs.h"
#include "whack.h"

/**
 * Print the 'ipsec --whack help' message
 */
static void help(void)
{
	fprintf(stderr,
		"Usage:\n\n"
		"all forms:"
		" [--ctlbase <path>]"
		" [--label <string>]"
		"\n\n"
		"help: whack"
		" [--help]"
		" [--version]"
		"\n\n"
		"connection: whack"
		" --name <connection_name>"
		" \\\n   "
		" --connalias <alias_names>"
		" \\\n   "
		" [--ipv4 | --ipv6]"
		" [--tunnelipv4 | --tunnelipv6]"
		" \\\n   "
		" (--host <ip-address> | --id <identity> | --cert <path>)"
		" \\\n   "
		" [--ca <distinguished name>]"
		" \\\n   "
		" [--nexthop <ip-address>]"
		" [--client <subnet> | --clientwithin <address range>]"
		" \\\n   "
		" [--ikeport <port-number>]"
		" [--srcip <ip-address>]"
		" \\\n   "
		" [--clientprotoport <protocol>/<port>]"
		" [--dnskeyondemand]"
		" \\\n   "
		" [--updown <updown>]"
		" \\\n   "
		" (--host <ip-address> | --id <identity>)"
		" \\\n   "
		" [--groups <access control groups>]"
		" [--cert <path>]"
		" [--ca <distinguished name>]"
		" [--sendcert]"
		" [--sendcerttype number]"
		" \\\n   "
		" [--nexthop <ip-address>]"
		" \\\n   "
		" [--client <subnet> | --clientwithin <address range>]"
		" \\\n   "
		" [--clientprotoport <protocol>/<port>]"
		" \\\n   "
		" [--dnskeyondemand]"
		" [--updown <updown>]"
		" \\\n   "
		" [--psk]"
		" [--rsasig]"
		" \\\n   "
		" [--encrypt]"
		" [--authenticate]"
		" [--compress]"
		" [--overlapip]"
		" [--tunnel]"
		" [--pfs]"
		" \\\n   "
		" [--pfsgroup [modp1024] | [modp1536] | [modp2048] | [modp3072] | [modp4096] | [modp6144] | [modp8192]]"
		" \\\n   "
		" [--ikelifetime <seconds>]"
		" [--ipseclifetime <seconds>]"
		" \\\n   "
		" [--reykeymargin <seconds>]"
		" [--reykeyfuzz <percentage>]"
		" \\\n   "
		" [--keyingtries <count>]"
		" \\\n   "
		" [--esp <esp-algos>]"
		" \\\n   "
		" [--remote-peer-type <cisco>]"
		" \\\n   "
		" [--mtu <mtu>]"
		" \\\n   "
		" [--priority <prio>] [--reqid <reqid>]"
		" \\\n   "

		" [--ikev1-disable]"
		" [--ikev2-allow]"
		" [--ikev2-propose]"
		" \\\n   "
		" [--allow-narrowing]"
		" [--sareftrack]"
		" [--sarefconntrack]"
		" \\\n   "
		" [--ikefrag-allow]"
		" [--ikefrag-force]"
		" [--no-ikepad]"
		" \\\n   "
#ifdef HAVE_NM
		"[--nm-configured]"
		" \\\n   "
#endif
#ifdef HAVE_LABELED_IPSEC
		"[--loopback] [--labeledipsec] [--policylabel <label>]"
		" \\\n   "
#endif
		"[--xauthby file|pam|alwaysok]"
		"[--xauthfail hard|soft]"
		" \\\n   "
		" [--dontrekey]"
		" [--aggrmode]"
		" [--initialcontact] [--cisco-unity]"
		" [--forceencaps] [--no-nat-keepalive]"
		" [--ikev1natt <both|rfc|drafts>"
		" \\\n   "
		" [--dpddelay <seconds> --dpdtimeout <seconds>]"
		" [--dpdaction (clear|hold|restart)]"
		" \\\n   "

		" [--xauthserver]"
		" [--xauthclient]"
		" [--modecfgserver]"
		" [--modecfgclient]"
		" [--modecfgpull]"
		" [--addresspool <network range>]"
		" [--modecfgdns1 <ip-address>]"
		" [--modecfgdns2 <ip-address>]"
		" [--modecfgdomain <dns-domain>]"
		" [--modecfgbanner <login banner>]"
		" \\\n   "
		" [--metric <metric>]"
		" \\\n   "
		" [--initiateontraffic|--pass|--drop|--reject]"
		" \\\n   "
		" [--failnone|--failpass|--faildrop|--failreject]"
		" \\\n   "
		" --to"
		"\n\n"
		"routing: whack"
		" (--route | --unroute)"
		" --name <connection_name>"
		"\n\n"
		"initiation:"
		"\n "
		" whack"
		" (--initiate | --terminate)"
		" --name <connection_name>"
		" [--asynchronous]"
		" [--xauthname name]"
		" [--xauthpass pass]"
		"\n\n"
		"opportunistic initiation: whack"
		" [--tunnelipv4 | --tunnelipv6]"
		" \\\n   "
		" --oppohere <ip-address>"
		" --oppothere <ip-address>"
		"\n\n"
		"delete: whack"
		" --delete"
		" --name <connection_name>"
		"\n\n"
		"deletestate: whack"
		" --deletestate <state_object_number>"
		" --crash <ip-address>"
		"\n\n"
		"pubkey: whack"
		" --keyid <id>"
		" [--addkey]"
		" [--pubkeyrsa <key>]"
		"\n\n"
		"myid: whack"
		" --myid <id>"
		"\n\n"
		"debug: whack [--name <connection_name>]"
		" \\\n   "
		" [--debug-none]"
		" [--debug-all]"
		" \\\n   "
		" [--debug-raw]"
		" [--debug-crypt]"
		" [--debug-parsing]"
		" [--debug-emitting]"
		" \\\n   "
		" [--debug-control]"
		" [--debug-controlmore]"
		" [--debug-dns]"
		" [--debug-pfkey]"
		" [--debug-dpd]"
		" \\\n   "
		" [--debug-nat-t]"
		" [--debug-x509]"
		" [--debug-oppo]"
		" [--debug-oppoinfo]"
		" \\\n   "
		" [--debug-private]"
		"\n\n"
		"testcases: [--whackrecord file] [--whackstoprecord]\n"
		"listen: whack"
		" (--listen | --unlisten)"
		"\n\n"
		"list: whack [--utc]"
		" [--checkpubkeys]"
		" [--listpubkeys]"
		" [--listcerts]"
		" [--listcacerts]"
		" \\\n   "
		" [--listacerts]"
		" [--listaacerts]"
		" \\\n   "
		" [--listgroups]"
		" [--listcrls]"

		" [--listpsks]"
		" [--listall]"
		"\n\n"

		"purge: whack"
		" [--listevents]"
		"\n\n"

		"reread: whack"
		" [--rereadsecrets]"
		" [--rereadcacerts]"
		" [--rereadaacerts]"
		" \\\n   "
		" [--rereadacerts]"

		" [--rereadcrls]"
		" [--rereadall]"
		"\n\n"
		"status: whack"
		" --status"
		"\n\n"
		"shutdown: whack"
		" --shutdown"
		"\n\n"
		"Libreswan %s\n",
		ipsec_version_code());
}

static const char *label = NULL;        /* --label operand, saved for diagnostics */

static const char *name = NULL;         /* --name operand, saved for diagnostics */

/** Print a string as a diagnostic, then exit whack unhappily
 *
 * @param mess The error message to print when exiting
 * @return void
 */
static void diag(const char *mess)
{
	if (mess != NULL) {
		fprintf(stderr, "whack error: ");
		if (label != NULL)
			fprintf(stderr, "%s ", label);
		if (name != NULL)
			fprintf(stderr, "\"%s\" ", name);
		fprintf(stderr, "%s\n", mess);
	}

	exit(RC_WHACK_PROBLEM);
}

/**
 * Conditially calls diag if ugh is set.
 * Prints second arg, if non-NULL, as quoted string
 *
 * @param ugh Error message
 * @param this Optional 2nd part of error message
 * @return void
 */
static void diagq(err_t ugh, const char *this)
{
	if (ugh != NULL) {
		if (this == NULL) {
			diag(ugh);
		} else {
			char buf[120]; /* arbitrary limit */

			snprintf(buf, sizeof(buf), "%s \"%s\"", ugh, this);
			diag(buf);
		}
	}
}

/**
 * complex combined operands return one of these enumerated values
 * Note: these become flags in an lset_t.  Since there are more than
 * 32, we partition them into:
 * - OPT_* options (most random options)
 * - LST_* options (list various internal data)
 * - DBGOPT_* option (DEBUG options)
 * - END_* options (End description options)
 * - CD_* options (Connection Description options)
 */
enum option_enums {
#   define OPT_FIRST1    OPT_CTLBASE	/* first normal option, range 1 */
	OPT_CTLBASE,
	OPT_NAME,
	OPT_CONNALIAS,

	OPT_CD,

	OPT_KEYID,
	OPT_ADDKEY,
	OPT_PUBKEYRSA,

	OPT_MYID,

	OPT_ROUTE,
	OPT_UNROUTE,

	OPT_INITIATE,
	OPT_TERMINATE,
	OPT_DELETE,
	OPT_DELETESTATE,
	OPT_LISTEN,
	OPT_UNLISTEN,

	OPT_REREADSECRETS,
	OPT_REREADCACERTS,
	OPT_REREADAACERTS,
	OPT_REREADACERTS,
	OPT_REREADCRLS,
	OPT_REREADALL,

	OPT_STATUS,
	OPT_SHUTDOWN,

	OPT_OPPO_HERE,
	OPT_OPPO_THERE,

#   define OPT_LAST1 OPT_OPPO_THERE  /* last "normal" option, range 1 */

#define OPT_FIRST2  OPT_ASYNC	/* first normal option, range 2 */

	OPT_ASYNC,

	OPT_DELETECRASH,
	OPT_XAUTHNAME,
	OPT_XAUTHPASS,
	OPT_WHACKRECORD,
	OPT_WHACKSTOPRECORD,

#define OPT_LAST2 OPT_WHACKSTOPRECORD /* last "normal" option, range 2 */

/* List options */

#   define LST_FIRST LST_UTC   /* first list option */
	LST_UTC,
	LST_CHECKPUBKEYS,
	LST_PUBKEYS,
	LST_CERTS,
	LST_CACERTS,
	LST_ACERTS,
	LST_AACERTS,
	LST_GROUPS,
	LST_CRLS,
	LST_CARDS,
	LST_PSKS,
	LST_EVENTS,
	LST_ALL,

#   define LST_LAST LST_ALL    /* last list option */

/* Connection End Description options */

#   define END_FIRST END_HOST   /* first end description */
	END_HOST,
	END_ID,
	END_CERT,
	END_CA,
	END_GROUPS,
	END_IKEPORT,
	END_NEXTHOP,
	END_CLIENT,
	END_CLIENTWITHIN,
	END_CLIENTPROTOPORT,
	END_DNSKEYONDEMAND,
	END_XAUTHNAME,
	END_XAUTHSERVER,
	END_XAUTHCLIENT,
	END_MODECFGCLIENT,
	END_MODECFGSERVER,
	END_ADDRESSPOOL,
	END_SENDCERT,
	END_SRCIP,
	END_UPDOWN,
	END_TUNDEV,

#define END_LAST  END_TUNDEV    /* last end description*/

/* Connection Description options -- segregated */

#   define CD_FIRST CD_TO       /* first connection description */
	CD_TO,

	CD_MODECFGDNS1,
	CD_MODECFGDNS2,
	CD_MODECFGDOMAIN,
	CD_MODECFGBANNER,
	CD_METRIC,
	CD_CONNMTU,
	CD_PRIORITY,
	CD_REQID,
	CD_TUNNELIPV4,
	CD_TUNNELIPV6,
	CD_CONNIPV4,
	CD_CONNIPV6,

	CD_IKELIFETIME,
	CD_IPSECLIFETIME,
	CD_RKMARGIN,
	CD_RKFUZZ,
	CD_KTRIES,
	CD_DPDDELAY,
	CD_DPDTIMEOUT,
	CD_DPDACTION,
	CD_FORCEENCAPS,
	CD_NO_NAT_KEEPALIVE,
	CD_IKEV1_NATT,
	CD_INITIAL_CONTACT,
	CD_CISCO_UNITY,
	CD_IKE,
	CD_PFSGROUP,
	CD_REMOTEPEERTYPE,
	CD_SHA2_TRUNCBUG,
	CD_NMCONFIGURED,
	CD_LOOPBACK,
	CD_LABELED_IPSEC,
	CD_POLICY_LABEL,
	CD_XAUTHBY,
	CD_XAUTHFAIL,
	CD_ESP,
#   define CD_LAST CD_ESP       /* last connection description */

/* Policy options
 *
 * Really part of Connection Description but too many bits
 * for cd_seen.
 */
#define CDP_FIRST	CDP_SHUNT

	/* multi-element policy flags */
	CDP_SHUNT,
	CDP_FAIL,

	/* The next range is for single-element policy options.
	 * It covers enum sa_policy_bits values.
	 */
	CDP_SINGLETON,
	/* large gap of unnamed values... */
	CDP_SINGLETON_LAST = CDP_SINGLETON + POLICY_IX_LAST,

#define CDP_LAST	CDP_SINGLETON_LAST

/* === end of correspondence with POLICY_* === */

	/* NOTE: these definitions must match DBG_* and IMPAIR_* in constants.h */

#   define DBGOPT_FIRST DBGOPT_NONE
	DBGOPT_NONE,
	DBGOPT_ALL,

	DBGOPT_elems,	/* this point on: DBGOPT single elements */

	DBGOPT_LAST = DBGOPT_elems + IMPAIR_roof_IX - 1,

#define	OPTION_ENUMS_LAST	DBGOPT_LAST
};

/* Carve up space for result from getop_long.
 * Stupidly, the only result is an int.
 * Numeric arg is bit immediately left of basic value.
 *
 */
#define OPTION_OFFSET   256     /* to get out of the way of letter options */
#define NUMERIC_ARG (1 << 11)   /* expect a numeric argument */
#define AUX_SHIFT   12          /* amount to shift for aux information */

static const struct option long_opts[] = {
#   define OO   OPTION_OFFSET
	/* name, has_arg, flag, val */

	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'v' },
	{ "label", required_argument, NULL, 'l' },

	{ "ctlbase", required_argument, NULL, OPT_CTLBASE + OO },
	{ "name", required_argument, NULL, OPT_NAME + OO },
	{ "connalias", required_argument, NULL, OPT_CONNALIAS + OO },

	{ "keyid", required_argument, NULL, OPT_KEYID + OO },
	{ "addkey", no_argument, NULL, OPT_ADDKEY + OO },
	{ "pubkeyrsa", required_argument, NULL, OPT_PUBKEYRSA + OO },

	{ "myid", required_argument, NULL, OPT_MYID + OO },

	{ "route", no_argument, NULL, OPT_ROUTE + OO },
	{ "ondemand", no_argument, NULL, OPT_ROUTE + OO }, /* alias */
	{ "unroute", no_argument, NULL, OPT_UNROUTE + OO },

	{ "initiate", no_argument, NULL, OPT_INITIATE + OO },
	{ "terminate", no_argument, NULL, OPT_TERMINATE + OO },
	{ "delete", no_argument, NULL, OPT_DELETE + OO },
	{ "deletestate", required_argument, NULL, OPT_DELETESTATE + OO +
	  NUMERIC_ARG },
	{ "crash", required_argument, NULL, OPT_DELETECRASH + OO },
	{ "listen", no_argument, NULL, OPT_LISTEN + OO },
	{ "unlisten", no_argument, NULL, OPT_UNLISTEN + OO },

	{ "rereadsecrets", no_argument, NULL, OPT_REREADSECRETS + OO },
	{ "rereadcacerts", no_argument, NULL, OPT_REREADCACERTS + OO },
	{ "rereadaacerts", no_argument, NULL, OPT_REREADAACERTS + OO },
	{ "rereadacerts", no_argument, NULL, OPT_REREADACERTS + OO },

	{ "rereadcrls", no_argument, NULL, OPT_REREADCRLS + OO },
	{ "rereadall", no_argument, NULL, OPT_REREADALL + OO },
	{ "status", no_argument, NULL, OPT_STATUS + OO },
	{ "shutdown", no_argument, NULL, OPT_SHUTDOWN + OO },
	{ "xauthname", required_argument, NULL, OPT_XAUTHNAME + OO },
	{ "xauthuser", required_argument, NULL, OPT_XAUTHNAME + OO },
	{ "xauthpass", required_argument, NULL, OPT_XAUTHPASS + OO },

	{ "oppohere", required_argument, NULL, OPT_OPPO_HERE + OO },
	{ "oppothere", required_argument, NULL, OPT_OPPO_THERE + OO },

	{ "asynchronous", no_argument, NULL, OPT_ASYNC + OO },

	/* list options */

	{ "utc", no_argument, NULL, LST_UTC + OO },
	{ "checkpubkeys", no_argument, NULL, LST_CHECKPUBKEYS + OO },
	{ "listpubkeys", no_argument, NULL, LST_PUBKEYS + OO },
	{ "listcerts", no_argument, NULL, LST_CERTS + OO },
	{ "listcacerts", no_argument, NULL, LST_CACERTS + OO },
	{ "listacerts", no_argument, NULL, LST_ACERTS + OO },
	{ "listaacerts", no_argument, NULL, LST_AACERTS + OO },
	{ "listgroups", no_argument, NULL, LST_GROUPS + OO },
	{ "listcrls", no_argument, NULL, LST_CRLS + OO },
	{ "listpsks", no_argument, NULL, LST_PSKS + OO },
	{ "listevents", no_argument, NULL, LST_EVENTS + OO },
	{ "listall", no_argument, NULL, LST_ALL + OO },

	/* options for an end description */

	{ "host", required_argument, NULL, END_HOST + OO },
	{ "id", required_argument, NULL, END_ID + OO },
	{ "cert", required_argument, NULL, END_CERT + OO },
	{ "ca", required_argument, NULL, END_CA + OO },
	{ "groups", required_argument, NULL, END_GROUPS + OO },
	{ "ikeport", required_argument, NULL, END_IKEPORT + OO + NUMERIC_ARG },
	{ "nexthop", required_argument, NULL, END_NEXTHOP + OO },
	{ "client", required_argument, NULL, END_CLIENT + OO },
	{ "clientwithin", required_argument, NULL, END_CLIENTWITHIN + OO },
	{ "clientprotoport", required_argument, NULL, END_CLIENTPROTOPORT +
	  OO },
	{ "dnskeyondemand", no_argument, NULL, END_DNSKEYONDEMAND + OO },
	{ "srcip",  required_argument, NULL, END_SRCIP + OO },
	{ "updown", required_argument, NULL, END_UPDOWN + OO },
	{ "tundev", required_argument, NULL, END_TUNDEV + OO + NUMERIC_ARG },

	/* options for a connection description */

	{ "to", no_argument, NULL, CD_TO + OO },

#define PS(o, p)	{ o, no_argument, NULL, CDP_SINGLETON + POLICY_##p##_IX + OO }
	PS("psk", PSK),
	PS("rsasig", RSASIG),

	PS("encrypt", ENCRYPT),
	PS("authenticate", AUTHENTICATE),
	PS("compress", COMPRESS),
	PS("overlapip", OVERLAPIP),
	PS("tunnel", TUNNEL),
	{ "tunnelipv4", no_argument, NULL, CD_TUNNELIPV4 + OO },
	{ "tunnelipv6", no_argument, NULL, CD_TUNNELIPV6 + OO },
	PS("pfs", PFS),
	{ "sha2_truncbug", no_argument, NULL, CD_SHA2_TRUNCBUG + OO },
	PS("aggrmode", AGGRESSIVE),

	PS("disablearrivalcheck", DISABLEARRIVALCHECK),

	{ "initiateontraffic", no_argument, NULL,
		CDP_SHUNT +(POLICY_SHUNT_TRAP >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },
	{ "pass", no_argument, NULL,
		CDP_SHUNT + (POLICY_SHUNT_PASS >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },
	{ "drop", no_argument, NULL,
		CDP_SHUNT + (POLICY_SHUNT_DROP >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },
	{ "reject", no_argument, NULL,
		CDP_SHUNT + (POLICY_SHUNT_REJECT >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },

	{ "failnone", no_argument, NULL,
		CDP_FAIL + (POLICY_FAIL_NONE >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },
	{ "failpass", no_argument, NULL,
		CDP_FAIL + (POLICY_FAIL_PASS >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },
	{ "faildrop", no_argument, NULL,
		CDP_FAIL + (POLICY_FAIL_DROP >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },
	{ "failreject", no_argument, NULL,
		CDP_FAIL + (POLICY_FAIL_REJECT >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },

	PS("dontrekey", DONT_REKEY),
	{ "forceencaps", no_argument, NULL, CD_FORCEENCAPS + OO },
	{ "no-nat_keepalive", no_argument, NULL,  CD_NO_NAT_KEEPALIVE },
	{ "ikev1_natt", required_argument, NULL, CD_IKEV1_NATT + OO },
	{ "initialcontact", no_argument, NULL,  CD_INITIAL_CONTACT },
	{ "cisco_unity", no_argument, NULL, CD_CISCO_UNITY },	/* obsolete _ */
	{ "cisco-unity", no_argument, NULL, CD_CISCO_UNITY },

	{ "dpddelay", required_argument, NULL, CD_DPDDELAY + OO + NUMERIC_ARG },
	{ "dpdtimeout", required_argument, NULL, CD_DPDTIMEOUT + OO + NUMERIC_ARG },
	{ "dpdaction", required_argument, NULL, CD_DPDACTION + OO },

	{ "xauth", no_argument, NULL, END_XAUTHSERVER + OO },
	{ "xauthserver", no_argument, NULL, END_XAUTHSERVER + OO },
	{ "xauthclient", no_argument, NULL, END_XAUTHCLIENT + OO },
	{ "xauthby", required_argument, NULL, CD_XAUTHBY + OO },
	{ "xauthfail", required_argument, NULL, CD_XAUTHFAIL + OO },
	PS("modecfgpull", MODECFG_PULL),
	{ "modecfgserver", no_argument, NULL, END_MODECFGSERVER + OO },
	{ "modecfgclient", no_argument, NULL, END_MODECFGCLIENT + OO },
	{ "addresspool", required_argument, NULL, END_ADDRESSPOOL + OO },
	{ "modecfgdns1", required_argument, NULL, CD_MODECFGDNS1 + OO },
	{ "modecfgdns2", required_argument, NULL, CD_MODECFGDNS2 + OO },
	{ "modecfgdomain", required_argument, NULL, CD_MODECFGDOMAIN + OO },
	{ "modecfgbanner", required_argument, NULL, CD_MODECFGBANNER + OO },
	{ "modeconfigserver", no_argument, NULL, END_MODECFGSERVER + OO },
	{ "modeconfigclient", no_argument, NULL, END_MODECFGCLIENT + OO },

	{ "metric", required_argument, NULL, CD_METRIC + OO + NUMERIC_ARG },
	{ "mtu", required_argument, NULL, CD_CONNMTU + OO + NUMERIC_ARG },
	{ "priority", required_argument, NULL, CD_PRIORITY + OO + NUMERIC_ARG },
	{ "reqid", required_argument, NULL, CD_REQID + OO + NUMERIC_ARG },
	{ "sendcert", required_argument, NULL, END_SENDCERT + OO },
	{ "ipv4", no_argument, NULL, CD_CONNIPV4 + OO },
	{ "ipv6", no_argument, NULL, CD_CONNIPV6 + OO },

	{ "ikelifetime", required_argument, NULL, CD_IKELIFETIME + OO + NUMERIC_ARG },
	{ "ipseclifetime", required_argument, NULL, CD_IPSECLIFETIME + OO + NUMERIC_ARG },
	{ "rekeymargin", required_argument, NULL, CD_RKMARGIN + OO + NUMERIC_ARG },
	{ "rekeywindow", required_argument, NULL, CD_RKMARGIN + OO +NUMERIC_ARG },                                                        /* OBSOLETE */
	{ "rekeyfuzz", required_argument, NULL, CD_RKFUZZ + OO + NUMERIC_ARG },
	{ "keyingtries", required_argument, NULL, CD_KTRIES + OO + NUMERIC_ARG },
	{ "ike",    required_argument, NULL, CD_IKE + OO },
	{ "ikealg", required_argument, NULL, CD_IKE + OO },
	{ "pfsgroup", required_argument, NULL, CD_PFSGROUP + OO },
	{ "esp", required_argument, NULL, CD_ESP + OO },
	{ "remote_peer_type", required_argument, NULL, CD_REMOTEPEERTYPE + OO },


	PS("ikev1-disable", IKEV1_DISABLE),
	PS("ikev2-allow", IKEV2_ALLOW),
	PS("ikev2-propose", IKEV2_PROPOSE),

	PS("allow-narrowing", IKEV2_ALLOW_NARROWING),

	PS("sareftrack", SAREF_TRACK),
	PS("sarefconntrack", SAREF_TRACK_CONNTRACK),

	PS("ikefrag-allow", IKE_FRAG_ALLOW),
	PS("ikefrag-force", IKE_FRAG_FORCE),
	PS("no-ikepad", NO_IKEPAD),
#undef PS


#ifdef HAVE_NM
	{ "nm_configured", no_argument, NULL, CD_NMCONFIGURED + OO },
#endif
#ifdef HAVE_LABELED_IPSEC
	{ "loopback", no_argument, NULL, CD_LOOPBACK + OO },
	{ "labeledipsec", no_argument, NULL, CD_LABELED_IPSEC + OO },
	{ "policylabel", required_argument, NULL, CD_POLICY_LABEL + OO },
#endif

	{ "debug-none", no_argument, NULL, DBGOPT_NONE + OO },
	{ "debug-all", no_argument, NULL, DBGOPT_ALL + OO },

#    define DO (DBGOPT_ALL + OO + 1)

	{ "debug-raw", no_argument, NULL, DBG_RAW_IX + DO },
	{ "debug-crypt", no_argument, NULL, DBG_CRYPT_IX + DO },
	{ "debug-parsing", no_argument, NULL, DBG_PARSING_IX + DO },
	{ "debug-emitting", no_argument, NULL, DBG_EMITTING_IX + DO },
	{ "debug-control", no_argument, NULL, DBG_CONTROL_IX + DO },
	{ "debug-lifecycle", no_argument, NULL, DBG_LIFECYCLE_IX + DO },
	{ "debug-kernel", no_argument, NULL, DBG_KERNEL_IX + DO },
	{ "debug-dns", no_argument, NULL, DBG_DNS_IX + DO },
	{ "debug-oppo", no_argument, NULL, DBG_OPPO_IX + DO },
	{ "debug-oppoinfo", no_argument, NULL, DBG_OPPOINFO_IX + DO },
	{ "debug-whackwatch",  no_argument, NULL, DBG_WHACKWATCH_IX + DO },
	{ "debug-controlmore", no_argument, NULL, DBG_CONTROLMORE_IX + DO },
	{ "debug-pfkey",   no_argument, NULL, DBG_PFKEY_IX + DO },
	{ "debug-nattraversal", no_argument, NULL, DBG_NATT_IX + DO },	/* ??? redundant spelling */
	{ "debug-natt",    no_argument, NULL, DBG_NATT_IX + DO },	/* ??? redundant spelling */
	{ "debug-nat_t",   no_argument, NULL, DBG_NATT_IX + DO },	/* obsolete _ */
	{ "debug-nat-t",   no_argument, NULL, DBG_NATT_IX + DO },
	{ "debug-x509",    no_argument, NULL, DBG_X509_IX + DO },
	{ "debug-dpd",     no_argument, NULL, DBG_DPD_IX + DO },
	{ "debug-private", no_argument, NULL, DBG_PRIVATE_IX + DO },

	{ "impair-delay-adns-key-answer", no_argument, NULL,
		IMPAIR_DELAY_ADNS_KEY_ANSWER_IX + DO },
	{ "impair-delay-adns-txt-answer", no_argument, NULL,
		IMPAIR_DELAY_ADNS_TXT_ANSWER_IX + DO },
	{ "impair-bust-mi2", no_argument, NULL, IMPAIR_BUST_MI2_IX + DO },
	{ "impair-bust-mr2", no_argument, NULL, IMPAIR_BUST_MR2_IX + DO },
	{ "impair-sa-fail",    no_argument, NULL, IMPAIR_SA_CREATION_IX + DO },
	{ "impair-die-oninfo", no_argument, NULL, IMPAIR_DIE_ONINFO_IX  + DO },
	{ "impair-jacob-two-two", no_argument, NULL,
		IMPAIR_JACOB_TWO_TWO_IX + DO },
	{ "impair-major-version-bump", no_argument, NULL,
		IMPAIR_MAJOR_VERSION_BUMP_IX + DO },
	{ "impair-minor-version-bump", no_argument, NULL,
		IMPAIR_MINOR_VERSION_BUMP_IX + DO },
	{ "impair-retransmits", no_argument, NULL, IMPAIR_RETRANSMITS_IX + DO },
	{ "impair-send-bogus-isakmp-flag", no_argument, NULL,
		IMPAIR_SEND_BOGUS_ISAKMP_FLAG_IX + DO },
	{ "impair-send-ikev2-ke", no_argument, NULL,
		IMPAIR_SEND_IKEv2_KE_IX + DO },
#    undef DO
	{ "whackrecord",     required_argument, NULL, OPT_WHACKRECORD + OO },
	{ "whackstoprecord", required_argument, NULL, OPT_WHACKSTOPRECORD +
	  OO },
#   undef OO
	{ 0, 0, 0, 0 }
};

static const char namechars[] = "abcdefghijklmnopqrstuvwxyz"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
struct sockaddr_un ctl_addr = {
	.sun_family = AF_UNIX,
	.sun_path   = DEFAULT_CTLBASE CTL_SUFFIX,
#if defined(HAS_SUN_LEN)
	.sun_len = sizeof(struct sockaddr_un),
#endif
};

/* ??? there seems to be no consequence for invalid life_time. */
static void check_life_time(deltatime_t life, time_t raw_limit,
			    const char *which,
			    const struct whack_message *msg)
{
	deltatime_t limit = deltatime(raw_limit);
	deltatime_t mint = deltatimescale(100 + msg->sa_rekey_fuzz, 100, msg->sa_rekey_margin);

	if (deltaless(limit, life)) {
		char buf[200]; /* arbitrary limit */

		snprintf(buf, sizeof(buf),
			 "%s [%ld seconds] must be less than %ld seconds",
			 which,
			 (long)deltasecs(life),
			 (long)deltasecs(limit));
		diag(buf);
	}
	if ((msg->policy & POLICY_DONT_REKEY) == LEMPTY && !deltaless(mint, life)) {
		char buf[200]; /* arbitrary limit */

		snprintf(buf, sizeof(buf),
			 "%s [%ld] must be greater than"
			 " rekeymargin*(100+rekeyfuzz)/100 [%ld*(100+%lu)/100 = %ld]",
			 which,
			 (long)deltasecs(life),
			 (long)deltasecs(msg->sa_rekey_margin),
			 msg->sa_rekey_fuzz,
			 (long)deltasecs(mint));
		diag(buf);
	}
}

static void update_ports(struct whack_message * m)
{
	int port;

	if (m->left.port != 0) {
		port = htons(m->left.port);
		setportof(port, &m->left.host_addr);
		setportof(port, &m->left.client.addr);
	}
	if (m->right.port != 0) {
		port = htons(m->right.port);
		setportof(port, &m->right.host_addr);
		setportof(port, &m->right.client.addr);
	}
}

static void check_end(struct whack_end *this, struct whack_end *that,
		      bool default_nexthop, sa_family_t caf, sa_family_t taf)
{
	if (caf != addrtypeof(&this->host_addr))
		diag("address family of host inconsistent");

	if (default_nexthop) {
		if (isanyaddr(&that->host_addr))
			diag("our nexthop must be specified when other host is a %any or %opportunistic");


		this->host_nexthop = that->host_addr;
	}

	if (caf != addrtypeof(&this->host_nexthop))
		diag("address family of nexthop inconsistent");

	if (this->has_client) {
		if (taf != subnettypeof(&this->client))
			diag("address family of client subnet inconsistent");
	} else {
		/* fill in anyaddr-anyaddr as (missing) client subnet */
		ip_address cn;

		diagq(anyaddr(caf, &cn), NULL);
		diagq(rangetosubnet(&cn, &cn, &this->client), NULL);
	}

	/* check protocol */
	if (this->protocol != that->protocol) {
		diagq("the protocol for leftprotoport and rightprotoport must be the same",
			NULL);
	}
}

static void send_reply(int sock, char *buf, ssize_t len)
{
	/* send the secret to pluto */
	if (write(sock, buf, len) != len) {
		int e = errno;

		fprintf(stderr, "whack: write() failed (%d %s)\n", e,
			strerror(e));
		exit(RC_WHACK_PROBLEM);
	}
}

/* This is a hack for initiating ISAKMP exchanges. */

int main(int argc, char **argv)
{
	struct whack_message msg;
	struct whackpacker wp;
	char esp_buf[256]; /* uses snprintf */
	lset_t
		opts1_seen = LEMPTY,
		opts2_seen = LEMPTY,
		lst_seen = LEMPTY,
		cd_seen = LEMPTY,
		cdp_seen = LEMPTY,
		end_seen = LEMPTY,
		end_seen_before_to = LEMPTY;
	const char
	*af_used_by = NULL,
	*tunnel_af_used_by = NULL;

	char xauthname[XAUTH_MAX_NAME_LENGTH];
	char xauthpass[XAUTH_MAX_PASS_LENGTH];
	int xauthnamelen = 0, xauthpasslen = 0;
	bool gotxauthname = FALSE, gotxauthpass = FALSE;
	const char *ugh;

	/* check division of numbering space */
	assert(OPTION_OFFSET + OPTION_ENUMS_LAST < NUMERIC_ARG);
	assert(OPT_LAST1 - OPT_FIRST1 < LELEM_ROOF);
	assert(OPT_LAST2 - OPT_FIRST2 < LELEM_ROOF);
	assert(LST_LAST - LST_FIRST < LELEM_ROOF);
	assert(END_LAST - END_FIRST < LELEM_ROOF);
	assert(CD_LAST - CD_FIRST < LELEM_ROOF);
	assert(IMPAIR_roof_IX <= LELEM_ROOF);

	zero(&msg);

	clear_end(&msg.right);  /* left set from this after --to */

	msg.name = NULL;
	msg.dnshostname = NULL;

	msg.keyid = NULL;
	msg.keyval.ptr = NULL;
	msg.esp = NULL;
	msg.ike = NULL;
	msg.pfsgroup = NULL;

	msg.remotepeertype = NON_CISCO;

	msg.sha2_truncbug = FALSE;

	/*Network Manager support*/
#ifdef HAVE_NM
	msg.nmconfigured = FALSE;
#endif

#ifdef HAVE_LABELED_IPSEC
	msg.loopback = FALSE;
	msg.labeled_ipsec = FALSE;
	msg.policy_label = NULL;
#endif

	msg.xauthby = XAUTHBY_FILE;
	msg.xauthfail = XAUTHFAIL_HARD;
	msg.modecfg_domain = NULL;
	msg.modecfg_banner = NULL;

	msg.sa_ike_life_seconds = deltatime(OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT);
	msg.sa_ipsec_life_seconds = deltatime(PLUTO_SA_LIFE_DURATION_DEFAULT);
	msg.sa_rekey_margin = deltatime(SA_REPLACEMENT_MARGIN_DEFAULT);
	msg.sa_rekey_fuzz = SA_REPLACEMENT_FUZZ_DEFAULT;
	msg.sa_keying_tries = SA_REPLACEMENT_RETRIES_DEFAULT;

	msg.addr_family = AF_INET;
	msg.tunnel_addr_family = AF_INET;

	for (;; ) {
		int long_index;
		unsigned long opt_whole = 0; /* numeric argument for some flags */

		/* Note: we don't like the way short options get parsed
		 * by getopt_long, so we simply pass an empty string as
		 * the list.  It could be "hp:d:c:o:eatfs" "NARXPECK".
		 */
		int c = getopt_long(argc, argv, "", long_opts, &long_index)
			- OPTION_OFFSET;
		int aux = 0;

		/* decode a numeric argument, if expected */
		if (0 <= c) {
			if (c & NUMERIC_ARG) {
				char *endptr;

				c -= NUMERIC_ARG;
				opt_whole = strtoul(optarg, &endptr, 0);

				if (*endptr != '\0' || endptr == optarg)
					diagq("badly formed numeric argument",
					      optarg);
			}
			if (c >= (1 << AUX_SHIFT)) {
				aux = c >> AUX_SHIFT;
				c -= aux << AUX_SHIFT;
			}
		}

		/* per-class option processing
		 *
		 * Mostly detection of repeated flags.
		 */
		if (OPT_FIRST1 <= c && c <= OPT_LAST1) {
			/* OPT_* options get added opts1_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c);

			if (opts1_seen & f)
				diagq("duplicated flag",
				      long_opts[long_index].name);
			opts1_seen |= f;
		} else if (OPT_FIRST2 <= c && c <= OPT_LAST2) {
			/* OPT_* options get added opts_seen2.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c);

			if (opts2_seen & f)
				diagq("duplicated flag",
				      long_opts[long_index].name);
			opts2_seen |= f;
		} else if (LST_FIRST <= c && c <= LST_LAST) {
			/* LST_* options get added lst_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c - LST_FIRST);

			if (lst_seen & f)
				diagq("duplicated flag",
				      long_opts[long_index].name);
			lst_seen |= f;
		}
		else if (DBGOPT_FIRST <= c && c <= DBGOPT_LAST) {
			/* DBGOPT_* options are treated separately to reduce
			 * potential members of opts1_seen.
			 */
			msg.whack_options = TRUE;
		}
		else if (END_FIRST <= c && c <= END_LAST) {
			/* END_* options are added to end_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c - END_FIRST);

			if (end_seen & f)
				diagq("duplicated flag",
				      long_opts[long_index].name);
			end_seen |= f;
			opts1_seen |= LELEM(OPT_CD);
		} else if (CD_FIRST <= c && c <= CD_LAST) {
			/* CD_* options are added to cd_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c - CD_FIRST);

			if (cd_seen & f)
				diagq("duplicated flag",
				      long_opts[long_index].name);
			cd_seen |= f;
			opts1_seen |= LELEM(OPT_CD);
		} else if (CDP_FIRST <= c && c <= CDP_LAST) {
			/* CDP_* options are added to cdp_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c - CDP_FIRST);

			if (cdp_seen & f)
				diagq("duplicated flag",
				      long_opts[long_index].name);
			cdp_seen |= f;
			opts1_seen |= LELEM(OPT_CD);
		}

		/* Note: "break"ing from switch terminates loop.
		 * most cases should end with "continue".
		 */
		switch (c) {
		case EOF - OPTION_OFFSET: /* end of flags */
			break;

		case 0 - OPTION_OFFSET: /* long option already handled */
			continue;

		case ':' - OPTION_OFFSET:       /* diagnostic already printed by getopt_long */
		case '?' - OPTION_OFFSET:       /* diagnostic already printed by getopt_long */
			diag(NULL);             /* print no additional diagnostic, but exit sadly */
			break;                  /* not actually reached */

		case 'h' - OPTION_OFFSET:       /* --help */
			help();
			return 0;               /* GNU coding standards say to stop here */

		case 'v' - OPTION_OFFSET:       /* --version */
		{
			printf("%s\n", ipsec_version_string());
		}
			return 0;               /* GNU coding standards say to stop here */

		case 'l' - OPTION_OFFSET:       /* --label <string> */
			label = optarg;         /* remember for diagnostics */
			continue;

		/* the rest of the options combine in complex ways */

		case OPT_CTLBASE: /* --port <ctlbase> */
			if (snprintf(ctl_addr.sun_path,
				     sizeof(ctl_addr.sun_path),
				     "%s%s", optarg, CTL_SUFFIX) == -1)
				diag("<ctlbase>" CTL_SUFFIX " must be fit in a sun_addr");


			continue;

		case OPT_NAME: /* --name <connection-name> */
			name = optarg;
			msg.name = optarg;
			continue;

		case OPT_KEYID:                 /* --keyid <identity> */
			msg.whack_key = TRUE;
			msg.keyid = optarg;     /* decoded by Pluto */
			continue;

		case OPT_MYID:                  /* --myid <identity> */
			msg.whack_myid = TRUE;
			msg.myid = optarg;      /* decoded by Pluto */
			continue;

		case OPT_ADDKEY: /* --addkey */
			msg.whack_addkey = TRUE;
			continue;

		case OPT_PUBKEYRSA: /* --pubkeyrsa <key> */
		{
			static char keyspace[RSA_MAX_ENCODING_BYTES];
			char mydiag_space[TTODATAV_BUF];
			ugh = ttodatav(optarg, 0, 0,
				       keyspace, sizeof(keyspace),
				       &msg.keyval.len, mydiag_space,
				       sizeof(mydiag_space),
				       TTODATAV_SPACECOUNTS);

			if (ugh != NULL) {
				char ugh_space[80]; /* perhaps enough space */

				snprintf(ugh_space, sizeof(ugh_space),
					 "RSA public-key data malformed (%s)",
					 ugh);
				diagq(ugh_space, optarg);
			}
			msg.pubkey_alg = PUBKEY_ALG_RSA;
			msg.keyval.ptr = (unsigned char *)keyspace;
		}
			continue;

		case OPT_ROUTE: /* --route */
			msg.whack_route = TRUE;
			continue;

		case OPT_UNROUTE: /* --unroute */
			msg.whack_unroute = TRUE;
			continue;

		case OPT_INITIATE: /* --initiate */
			msg.whack_initiate = TRUE;
			continue;

		case OPT_TERMINATE: /* --terminate */
			msg.whack_terminate = TRUE;
			continue;

		case OPT_DELETE: /* --delete */
			msg.whack_delete = TRUE;
			continue;

		case OPT_DELETESTATE: /* --deletestate <state_object_number> */
			msg.whack_deletestate = TRUE;
			msg.whack_deletestateno = opt_whole;
			continue;

		case OPT_DELETECRASH: /* --crash <ip-address> */
			msg.whack_crash = TRUE;
			diagq(ttoaddr(optarg, 0, msg.tunnel_addr_family,
				      &msg.whack_crash_peer), optarg);
			if (isanyaddr(&msg.whack_crash_peer)) {
				diagq("0.0.0.0 or 0::0 isn't a valid client address",
					optarg);
			}
			continue;

		case OPT_LISTEN: /* --listen */
			msg.whack_listen = TRUE;
			continue;

		case OPT_UNLISTEN: /* --unlisten */
			msg.whack_unlisten = TRUE;
			continue;

		case OPT_REREADSECRETS: /* --rereadsecrets */
		case OPT_REREADCACERTS: /* --rereadcacerts */
		case OPT_REREADAACERTS: /* --rereadaacerts */
		case OPT_REREADACERTS:  /* --rereadacerts */
		case OPT_REREADCRLS:    /* --rereadcrls */
			msg.whack_reread |= LELEM(c - OPT_REREADSECRETS);
			continue;

		case OPT_REREADALL: /* --rereadall */
			msg.whack_reread = REREAD_ALL;
			continue;

		case OPT_STATUS: /* --status */
			msg.whack_status = TRUE;
			continue;

		case OPT_SHUTDOWN: /* --shutdown */
			msg.whack_shutdown = TRUE;
			continue;

		case OPT_OPPO_HERE: /* --oppohere <ip-address> */
			tunnel_af_used_by = long_opts[long_index].name;
			diagq(ttoaddr(optarg, 0, msg.tunnel_addr_family,
				      &msg.oppo_my_client), optarg);
			if (isanyaddr(&msg.oppo_my_client)) {
				diagq("0.0.0.0 or 0::0 isn't a valid client address",
					optarg);
			}
			continue;

		case OPT_OPPO_THERE: /* --oppohere <ip-address> */
			tunnel_af_used_by = long_opts[long_index].name;
			diagq(ttoaddr(optarg, 0, msg.tunnel_addr_family,
				      &msg.oppo_peer_client), optarg);
			if (isanyaddr(&msg.oppo_peer_client)) {
				diagq("0.0.0.0 or 0::0 isn't a valid client address",
					optarg);
			}
			continue;

		case OPT_ASYNC:
			msg.whack_async = TRUE;
			continue;

		/* List options */

		case LST_UTC:   /* --utc */
			msg.whack_utc = TRUE;
			continue;

		case LST_PUBKEYS:       /* --listpubkeys */
		case LST_CERTS:         /* --listcerts */
		case LST_CACERTS:       /* --listcacerts */
		case LST_ACERTS:        /* --listacerts */
		case LST_AACERTS:       /* --listaacerts */
		case LST_GROUPS:        /* --listgroups */
		case LST_CRLS:          /* --listcrls */
		case LST_PSKS:          /* --listpsks */
		case LST_EVENTS:        /* --listevents */
			msg.whack_list |= LELEM(c - LST_PUBKEYS);
			continue;

		case LST_CHECKPUBKEYS: /* --checkpubkeys */
			msg.whack_list |= LELEM(LST_PUBKEYS - LST_PUBKEYS);
			msg.whack_check_pub_keys = TRUE;
			continue;

		case LST_ALL: /* --listall */
			msg.whack_list = LIST_ALL;
			continue;

		/* Connection Description options */

		case END_HOST: /* --host <ip-address> */
		{
			lset_t new_policy = LEMPTY;

			af_used_by = long_opts[long_index].name;
			diagq(anyaddr(msg.addr_family,
				      &msg.right.host_addr), optarg);
			if (streq(optarg, "%any")) {
			} else if (streq(optarg, "%opportunistic")) {
				/* always use tunnel mode; mark as opportunistic */
				new_policy |= POLICY_TUNNEL | POLICY_OPPORTUNISTIC;
			} else if (streq(optarg, "%group")) {
				/* always use tunnel mode; mark as group */
				new_policy |= POLICY_TUNNEL | POLICY_GROUP;
			} else if (streq(optarg, "%opportunisticgroup")) {
				/* always use tunnel mode; mark as opportunistic */
				new_policy |= POLICY_TUNNEL | POLICY_OPPORTUNISTIC |
					      POLICY_GROUP;
			} else {
				if (msg.left.id != NULL) {
					int strlength = 0;
					int n = 0;
					const char *cp;
					int dnshostname = 0;

					strlength = strlen(optarg);
					for (cp = optarg, n = strlength; n > 0;
					     cp++, n--) {
						if (strchr(namechars,
							   *cp) != NULL) {
							dnshostname = 1;
							break;
						}
					}
					if (dnshostname)
						msg.dnshostname = optarg;
					ttoaddr(optarg, 0, msg.addr_family,
						&msg.right.host_addr);
					/* we don't fail here.  pluto will re-check the DNS later */
				} else
				diagq(ttoaddr(optarg, 0, msg.addr_family,
					      &msg.right.host_addr), optarg);
			}

			msg.policy |= new_policy;

			if (new_policy & (POLICY_OPPORTUNISTIC | POLICY_GROUP)) {
				if (!LHAS(end_seen, END_CLIENT - END_FIRST)) {
					/* set host to 0.0.0 and --client to 0.0.0.0/0
					 * or IPV6 equivalent
					 */
					ip_address any;

					tunnel_af_used_by = optarg;
					diagq(anyaddr(msg.tunnel_addr_family,
						      &any), optarg);
					diagq(initsubnet(&any, 0, '0',
							 &msg.right.client),
					      optarg);
				}
				msg.right.has_client = TRUE;
			}
			if (new_policy & POLICY_GROUP) {
				/* client subnet must not be specified by user:
				 * it will come from the group's file.
				 */
				if (LHAS(end_seen, END_CLIENT - END_FIRST))
					diag("--host %group clashes with --client");


				end_seen |= LELEM(END_CLIENT - END_FIRST);
			}
			if (new_policy & POLICY_OPPORTUNISTIC)
				msg.right.key_from_DNS_on_demand = TRUE;
			continue;
		}

		case END_ID:                    /* --id <identity> */
			msg.right.id = optarg;  /* decoded by Pluto */
			continue;

		case END_SENDCERT:
			if (streq(optarg, "yes") || streq(optarg, "always")) {
				msg.right.sendcert = cert_alwayssend;
			} else if (streq(optarg,
					 "no") || streq(optarg, "never")) {
				msg.right.sendcert = cert_neversend;
			} else if (streq(optarg, "ifasked")) {
				msg.right.sendcert = cert_sendifasked;
			} else {
				diagq("whack sendcert value is not legal",
				      optarg);
				continue;
			}
			continue;

		case END_CERT:                          /* --cert <path> */
			msg.right.cert = optarg;        /* decoded by Pluto */
			continue;

		case END_CA:                    /* --ca <distinguished name> */
			msg.right.ca = optarg;  /* decoded by Pluto */
			continue;

		case END_GROUPS:                        /* --groups <access control groups> */
			msg.right.groups = optarg;      /* decoded by Pluto */
			continue;

		case END_IKEPORT: /* --ikeport <port-number> */
			if (opt_whole <= 0 || opt_whole >= 0x10000) {
				diagq("<port-number> must be a number between 1 and 65535",
					optarg);
			}
			msg.right.host_port = opt_whole;
			continue;

		case END_NEXTHOP: /* --nexthop <ip-address> */
			af_used_by = long_opts[long_index].name;
			if (streq(optarg, "%direct")) {
				diagq(anyaddr(msg.addr_family,
					      &msg.right.host_nexthop),
				      optarg);
			} else {
				diagq(ttoaddr(optarg, 0, msg.addr_family,
					      &msg.right.host_nexthop),
				      optarg);
			}
			continue;

		case END_SRCIP: /* --srcip <ip-address> */
			af_used_by = long_opts[long_index].name;
			diagq(ttoaddr(optarg, 0, msg.addr_family,
				      &msg.right.host_srcip), optarg);
			continue;

		case END_CLIENT: /* --client <subnet> */
			if (end_seen & LELEM(END_CLIENTWITHIN - END_FIRST))
				diag("--client conflicts with --clientwithin");


			tunnel_af_used_by = long_opts[long_index].name;
			if ( ((strlen(optarg) >= 6) &&
			      (strncmp(optarg, "vhost:", 6) == 0)) ||
			     ((strlen(optarg) >= 5) &&
			      (strncmp(optarg, "vnet:", 5) == 0)) ) {
				msg.right.virt = optarg;
			} else {
				diagq(ttosubnet(optarg, 0,
						msg.tunnel_addr_family,
						&msg.right.client), optarg);
				msg.right.has_client = TRUE;
			}
			msg.policy |= POLICY_TUNNEL; /* client => tunnel */
			continue;

		case END_CLIENTWITHIN: /* --clienwithin <address range> */
			if (end_seen & LELEM(END_CLIENT - END_FIRST))
				diag("--clientwithin conflicts with --client");


			tunnel_af_used_by = long_opts[long_index].name;
			diagq(ttosubnet(optarg, 0, msg.tunnel_addr_family,
					&msg.right.client), optarg);
			msg.right.has_client = TRUE;
			msg.right.has_client_wildcard = TRUE;
			continue;

		case END_CLIENTPROTOPORT: /* --clientprotoport <protocol>/<port> */
			diagq(ttoprotoport(optarg, 0, &msg.right.protocol,
					   &msg.right.port,
					   &msg.right.has_port_wildcard),
			      optarg);
			continue;

		case END_DNSKEYONDEMAND: /* --dnskeyondemand */
			msg.right.key_from_DNS_on_demand = TRUE;
			continue;

		case END_UPDOWN: /* --updown <updown> */
			msg.right.updown = optarg;
			continue;

		case END_TUNDEV: /* --tundev <mast#> */
			msg.right.tundev = opt_whole;
			continue;

		case CD_TO:     /* --to */
			/* process right end, move it to left, reset it */
			if (!LHAS(end_seen, END_HOST - END_FIRST))
				diag("connection missing --host before --to");
			msg.left = msg.right;
			clear_end(&msg.right);
			end_seen_before_to = end_seen;
			end_seen = LEMPTY;
			continue;

		case CDP_SINGLETON + POLICY_PSK_IX:                    /* --psk */
		case CDP_SINGLETON + POLICY_RSASIG_IX:                 /* --rsasig */
		case CDP_SINGLETON + POLICY_ENCRYPT_IX:                /* --encrypt */
		case CDP_SINGLETON + POLICY_AUTHENTICATE_IX:           /* --authenticate */
		case CDP_SINGLETON + POLICY_COMPRESS_IX:               /* --compress */
		case CDP_SINGLETON + POLICY_TUNNEL_IX:                 /* --tunnel */
		case CDP_SINGLETON + POLICY_PFS_IX:                    /* --pfs */
		case CDP_SINGLETON + POLICY_DISABLEARRIVALCHECK_IX:    /* --disablearrivalcheck */

		case CDP_SINGLETON + POLICY_DONT_REKEY_IX:             /* --donotrekey */

		case CDP_SINGLETON + POLICY_MODECFG_PULL_IX:            /* --modecfgpull */
		case CDP_SINGLETON + POLICY_AGGRESSIVE_IX:             /* --aggrmode */
		case CDP_SINGLETON + POLICY_OVERLAPIP_IX:              /* --overlapip */

		case CDP_SINGLETON + POLICY_IKEV1_DISABLE_IX:		/* --ikev1-disable */
		case CDP_SINGLETON + POLICY_IKEV2_ALLOW_IX:		/* --ikev2-allow */
		case CDP_SINGLETON + POLICY_IKEV2_PROPOSE_IX:		/* --ikev2-propose */

		case CDP_SINGLETON + POLICY_IKEV2_ALLOW_NARROWING_IX:	/* --allow-narrowing */

		case CDP_SINGLETON + POLICY_SAREF_TRACK_IX:		/* --sareftrack */
		case CDP_SINGLETON + POLICY_SAREF_TRACK_CONNTRACK_IX:	/* --sarefconntrack */

		case CDP_SINGLETON + POLICY_IKE_FRAG_ALLOW_IX:		/* --ikefrag-allow */
		case CDP_SINGLETON + POLICY_IKE_FRAG_FORCE_IX:		/* --ikefrag-force */
		case CDP_SINGLETON + POLICY_NO_IKEPAD_IX:		/* --no-ikepad */
			msg.policy |= LELEM(c - CDP_SINGLETON);
			continue;

		/* --initiateontraffic
		 * --pass
		 * --drop
		 * --reject
		 */
		case CDP_SHUNT:
			msg.policy = (msg.policy & ~POLICY_SHUNT_MASK) |
				     ((lset_t)aux << POLICY_SHUNT_SHIFT);
			continue;

		/* --failnone
		 * --failpass
		 * --faildrop
		 * --failreject
		 */
		case CDP_FAIL:
			msg.policy = (msg.policy & ~POLICY_FAIL_MASK) |
				     ((lset_t)aux << POLICY_FAIL_SHIFT);
			continue;

		case CD_IKELIFETIME: /* --ikelifetime <seconds> */
			msg.sa_ike_life_seconds = deltatime(opt_whole);
			continue;

		case CD_IPSECLIFETIME: /* --ipseclifetime <seconds> */
			msg.sa_ipsec_life_seconds = deltatime(opt_whole);
			continue;

		case CD_RKMARGIN: /* --rekeymargin <seconds> */
			msg.sa_rekey_margin = deltatime(opt_whole);
			continue;

		case CD_RKFUZZ: /* --rekeyfuzz <percentage> */
			msg.sa_rekey_fuzz = opt_whole;
			continue;

		case CD_KTRIES: /* --keyingtries <count> */
			msg.sa_keying_tries = opt_whole;
			continue;

		case CD_FORCEENCAPS:
			msg.forceencaps = TRUE;
			continue;

		case CD_NO_NAT_KEEPALIVE: /* --no-nat_keepalive */
			msg.nat_keepalive = FALSE;
			continue;

		case CD_IKEV1_NATT: /* --ikev1_natt */
			if ( streq(optarg, "both"))
				msg.ikev1_natt = natt_both;
			else if ( streq(optarg, "rfc"))
				msg.ikev1_natt = natt_rfc;
			else if ( streq(optarg, "drafts"))
				msg.ikev1_natt = natt_drafts;
			else
				diag("--ikev1-natt options are 'both', 'rfc' or 'drafts'");
			continue;

		case CD_INITIAL_CONTACT: /* --initialcontact */
			msg.initial_contact = TRUE;
			continue;

		case CD_CISCO_UNITY: /* --cisco-unity */
			msg.cisco_unity = TRUE;
			continue;

		case CD_DPDDELAY:
			msg.dpd_delay = deltatime(opt_whole);
			continue;

		case CD_DPDTIMEOUT:
			msg.dpd_timeout = deltatime(opt_whole);
			continue;

		case CD_DPDACTION:
			msg.dpd_action = 255;
			if ( streq(optarg, "clear"))
				msg.dpd_action = DPD_ACTION_CLEAR;
			else if ( streq(optarg, "hold"))
				msg.dpd_action = DPD_ACTION_HOLD;
			else if ( streq(optarg, "restart"))
				msg.dpd_action = DPD_ACTION_RESTART;
			else if ( streq(optarg, "restart_by_peer"))
				/* obsolete (not advertised) option for compatibility */
				msg.dpd_action = DPD_ACTION_RESTART;
			continue;

		case CD_IKE: /* --ike <ike_alg1,ike_alg2,...> */
			msg.ike = optarg;
			continue;

		case CD_PFSGROUP: /* --pfsgroup modpXXXX */
			msg.pfsgroup = optarg;
			continue;

		case CD_ESP: /* --esp <esp_alg1,esp_alg2,...> */
			msg.esp = optarg;
			continue;

		case CD_REMOTEPEERTYPE: /* --remote-peer-type  <cisco> */
			if (streq(optarg, "cisco"))
				msg.remotepeertype = CISCO;
			else
				msg.remotepeertype = NON_CISCO;
			continue;

		case CD_SHA2_TRUNCBUG: /* --sha2_truncbug */
			msg.sha2_truncbug = TRUE;
			continue;

#ifdef HAVE_NM
		case CD_NMCONFIGURED: /* --nm_configured */
			msg.nmconfigured = TRUE;
			continue;
#endif

#ifdef HAVE_LABELED_IPSEC
		case CD_LOOPBACK:
			msg.loopback = TRUE;
			continue;

		case CD_LABELED_IPSEC:
			msg.labeled_ipsec = TRUE;
			continue;

		case CD_POLICY_LABEL:
			msg.policy_label = optarg;
			continue;
#endif

		case CD_CONNIPV4:
			if (LHAS(cd_seen, CD_CONNIPV6 - CD_FIRST))
				diag("--ipv4 conflicts with --ipv6");

			/* Since this is the default, the flag is redundant.
			 * So we don't need to set msg.addr_family
			 * and we don't need to check af_used_by
			 * and we don't have to consider defaulting tunnel_addr_family.
			 */
			continue;

		case CD_CONNIPV6:
			if (LHAS(cd_seen, CD_CONNIPV4 - CD_FIRST))
				diag("--ipv6 conflicts with --ipv4");

			if (af_used_by != NULL)
				diagq("--ipv6 must precede", af_used_by);

			af_used_by = long_opts[long_index].name;
			msg.addr_family = AF_INET6;

			/* Consider defaulting tunnel_addr_family to AF_INET6.
			 * Do so only if it hasn't yet been specified or used.
			 */
			if (LDISJOINT(cd_seen,
				      LELEM(CD_TUNNELIPV4 -
					    CD_FIRST) |
				      LELEM(CD_TUNNELIPV6 - CD_FIRST)) &&
			    tunnel_af_used_by == NULL)
				msg.tunnel_addr_family = AF_INET6;
			continue;

		case CD_TUNNELIPV4:
			if (LHAS(cd_seen, CD_TUNNELIPV6 - CD_FIRST))
				diag("--tunnelipv4 conflicts with --tunnelipv6");


			if (tunnel_af_used_by != NULL)
				diagq("--tunnelipv4 must precede", af_used_by);


			msg.tunnel_addr_family = AF_INET;
			continue;

		case CD_TUNNELIPV6:
			if (LHAS(cd_seen, CD_TUNNELIPV4 - CD_FIRST))
				diag("--tunnelipv6 conflicts with --tunnelipv4");


			if (tunnel_af_used_by != NULL)
				diagq("--tunnelipv6 must precede", af_used_by);


			msg.tunnel_addr_family = AF_INET6;
			continue;

		case END_XAUTHSERVER: /* --xauthserver */
			msg.right.xauth_server = TRUE;
			continue;

		case END_XAUTHCLIENT: /* --xauthclient */
			msg.right.xauth_client = TRUE;
			continue;

		case OPT_XAUTHNAME: /* --xauthname */
			/* we can't tell if this is going to be --initiate, or
			 * if this is going to be an conn definition, so do
			 * both actions
			 */
			msg.right.xauth_name = optarg;
			gotxauthname = TRUE;
			xauthname[0] = '\0';
			strncat(xauthname, optarg, sizeof(xauthname) -
				strlen(xauthname) - 1);
			xauthnamelen = strlen(xauthname) + 1;
			continue;

		case OPT_XAUTHPASS:
			gotxauthpass = TRUE;
			xauthpass[0] = '\0';
			strncat(xauthpass, optarg, sizeof(xauthpass) -
				strlen(xauthpass) - 1);
			xauthpasslen = strlen(xauthpass) + 1;
			continue;

		case END_MODECFGCLIENT:
			msg.right.modecfg_client = TRUE;
			continue;

		case END_MODECFGSERVER:
			msg.right.modecfg_server = TRUE;
			continue;

		case END_ADDRESSPOOL:
			ttorange(optarg, 0, AF_INET, &msg.right.pool_range,
					TRUE);
			continue;

		case CD_MODECFGDNS1: /* --modecfgdns1 */
			af_used_by = long_opts[long_index].name;
			diagq(ttoaddr(optarg, 0, msg.addr_family,
				      &msg.modecfg_dns1), optarg);
			continue;

		case CD_MODECFGDNS2: /* --modecfgdns2 */
			af_used_by = long_opts[long_index].name;
			diagq(ttoaddr(optarg, 0, msg.addr_family,
				      &msg.modecfg_dns2), optarg);
			continue;

		case CD_MODECFGDOMAIN: /* --modecfgdomain */
			msg.modecfg_domain = strdup(optarg);
			continue;

		case CD_MODECFGBANNER: /* --modecfgbanner */
			msg.modecfg_banner = strdup(optarg);
			continue;

		case CD_XAUTHBY:
			if ( streq(optarg, "pam" )) {
				msg.xauthby = XAUTHBY_PAM;
				continue;
			} else if ( streq(optarg, "file" )) {
				msg.xauthby = XAUTHBY_FILE;
				continue;
			} else if ( streq(optarg, "alwaysok" )) {
				msg.xauthby = XAUTHBY_ALWAYSOK;
				continue;
			} else {
				fprintf(stderr,
					"whack: unknown xauthby method '%s' ignored",
					optarg);
			}
			continue;

		case CD_XAUTHFAIL:
			if ( streq(optarg, "hard" )) {
				msg.xauthfail = XAUTHFAIL_HARD;
				continue;
			} else if ( streq(optarg, "soft" )) {
				msg.xauthfail = XAUTHFAIL_SOFT;
				continue;
			} else {
				fprintf(stderr,
					"whack: unknown xauthfail method '%s' ignored",
					optarg);
			}
			continue;

		case CD_METRIC:
			msg.metric = opt_whole;
			continue;

		case CD_CONNMTU:
			msg.connmtu = opt_whole;
			continue;

		case CD_PRIORITY:
			msg.sa_priority = opt_whole;
			continue;

		case CD_REQID:
			msg.sa_reqid = opt_whole;
			continue;

		case OPT_WHACKRECORD:
			msg.string1 = strdup(optarg);
			msg.whack_options = TRUE;
			msg.opt_set = WHACK_STARTWHACKRECORD;
			break;

		case OPT_WHACKSTOPRECORD:
			msg.whack_options = TRUE;
			msg.opt_set = WHACK_STOPWHACKRECORD;
			break;

		case DBGOPT_NONE: /* --debug-none */
			msg.debugging = DBG_NONE;
			continue;

		case DBGOPT_ALL:                        /* --debug-all */
			msg.debugging |= DBG_ALL;       /* note: does not include PRIVATE */
			continue;

		default:
			/* DBG_* or IMPAIR_* flags */
			assert(DBGOPT_elems <= c && c < DBGOPT_elems + IMPAIR_roof_IX);
			msg.debugging |= LELEM(c - DBGOPT_elems);
			continue;
		}
		break;
	}

	if (optind != argc) {
		/* If you see this message unexpectedly, perhaps the
		 * case for the previous option ended with "break"
		 * instead of "continue"
		 */
		diagq("unexpected argument", argv[optind]);
	}

	/* For each possible form of the command, figure out if an argument
	 * suggests whether that form was intended, and if so, whether all
	 * required information was supplied.
	 */

	/* check opportunistic initiation simulation request */
	switch (opts1_seen & (LELEM(OPT_OPPO_HERE) | LELEM(OPT_OPPO_THERE))) {
	case LELEM(OPT_OPPO_HERE):
	case LELEM(OPT_OPPO_THERE):
		diag("--oppohere and --oppothere must be used together");
		/*NOTREACHED*/
	case LELEM(OPT_OPPO_HERE) | LELEM(OPT_OPPO_THERE):
		msg.whack_oppo_initiate = TRUE;
		if (LIN(cd_seen,
			LELEM(CD_TUNNELIPV4 -
			      CD_FIRST) | LELEM(CD_TUNNELIPV6 - CD_FIRST)))
			opts1_seen &= ~LELEM(OPT_CD);
		break;
	}

	/* check connection description */
	if (LHAS(opts1_seen, OPT_CD)) {
		if (!LHAS(cd_seen, CD_TO - CD_FIRST))
			diag("connection description option, but no --to");

		if (!LHAS(end_seen, END_HOST - END_FIRST))
			diag("connection missing --host after --to");

		if (isanyaddr(&msg.left.host_addr) &&
		    isanyaddr(&msg.right.host_addr))
			diag("hosts cannot both be 0.0.0.0 or 0::0");

		if (msg.policy & POLICY_OPPORTUNISTIC) {
			if ((msg.policy & (POLICY_PSK | POLICY_RSASIG)) !=
			    POLICY_RSASIG)
				diag("only RSASIG is supported for opportunism");


			if ((msg.policy & POLICY_PFS) == 0)
				diag("PFS required for opportunism");
			if ((msg.policy & POLICY_ENCRYPT) == 0)
				diag("encryption required for opportunism");
		}

		check_end(&msg.left, &msg.right,
			  !LHAS(end_seen_before_to, END_NEXTHOP - END_FIRST),
			  msg.addr_family, msg.tunnel_addr_family);

		check_end(&msg.right, &msg.left,
			  !LHAS(end_seen, END_NEXTHOP - END_FIRST),
			  msg.addr_family, msg.tunnel_addr_family);

		if (subnettypeof(&msg.left.client) !=
		    subnettypeof(&msg.right.client))
			diag("endpoints clash: one is IPv4 and the other is IPv6");


		if (NEVER_NEGOTIATE(msg.policy)) {
			/* we think this is just a shunt (because he didn't specify
			 * a host authentication method).  If he didn't specify a
			 * shunt type, he's probably gotten it wrong.
			 */
			if ((msg.policy & POLICY_SHUNT_MASK) ==
			    POLICY_SHUNT_TRAP)
				diag("non-shunt connection must have --psk or --rsasig or both");
		} else {
			/* not just a shunt: a real ipsec connection */
			if ((msg.policy & POLICY_ID_AUTH_MASK) == LEMPTY)
				diag("must specify --rsasig or --psk for a connection");


			if (!HAS_IPSEC_POLICY(msg.policy) &&
			    (msg.left.has_client || msg.right.has_client))
				diag("must not specify clients for ISAKMP-only connection");


		}

		msg.whack_connection = TRUE;
	}

	/* decide whether --name is mandatory or forbidden */
	if (!LDISJOINT(opts1_seen,
		       LELEM(OPT_ROUTE) | LELEM(OPT_UNROUTE) |
		       LELEM(OPT_INITIATE) | LELEM(OPT_TERMINATE) |
		       LELEM(OPT_DELETE) | LELEM(OPT_CD))) {
		if (!LHAS(opts1_seen, OPT_NAME))
			diag("missing --name <connection_name>");
	} else if (!msg.whack_options) {
		if (LHAS(opts1_seen, OPT_NAME))
			diag("no reason for --name");
	}

	if (!LDISJOINT(opts1_seen, LELEM(OPT_PUBKEYRSA) | LELEM(OPT_ADDKEY))) {
		if (!LHAS(opts1_seen, OPT_KEYID))
			diag("--addkey and --pubkeyrsa require --keyid");
	}

	if (!(msg.whack_connection || msg.whack_key || msg.whack_myid ||
	      msg.whack_delete || msg.whack_deletestate ||
	      msg.whack_initiate || msg.whack_oppo_initiate ||
	      msg.whack_terminate ||
	      msg.whack_route || msg.whack_unroute || msg.whack_listen ||
	      msg.whack_unlisten || msg.whack_list ||
	      msg.whack_reread || msg.whack_crash ||
	      msg.whack_status || msg.whack_options || msg.whack_shutdown))
		diag("no action specified; try --help for hints");

	if (msg.policy & POLICY_AGGRESSIVE) {
		if (msg.ike == NULL)
			diag("can not specify aggressive mode without ike= to set algorithm");


	}

	update_ports(&msg);

	/*
	 * Check for wild values
	 * Must never overflow: rekeymargin*(100+rekeyfuzz)/100
	 * We don't know the maximum value for a time_t, so we use INT_MAX
	 * ??? this should be checked wherever any of these is set in Pluto too.
	 */
	if (msg.sa_rekey_fuzz > INT_MAX - 100 ||
	    deltasecs(msg.sa_rekey_margin) > (time_t)(INT_MAX / (100 + msg.sa_rekey_fuzz)))
		diag("rekeymargin or rekeyfuzz values are so large that they cause oveflow");


	check_life_time(msg.sa_ike_life_seconds,
			OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM,
			"ikelifetime", &msg);

	check_life_time(msg.sa_ipsec_life_seconds, SA_LIFE_DURATION_MAXIMUM,
			"ipseclifetime", &msg);

	if (deltasecs(msg.dpd_delay) != 0 &&
	    deltasecs(msg.dpd_timeout) == 0)
		diag("dpddelay specified, but dpdtimeout is zero, both should be specified");

	if (deltasecs(msg.dpd_delay) == 0 &&
	    deltasecs(msg.dpd_timeout) != 0)
		diag("dpdtimeout specified, but dpddelay is zero, both should be specified");


	if (msg.dpd_action != DPD_ACTION_CLEAR &&
	    msg.dpd_action != DPD_ACTION_HOLD &&
	    msg.dpd_action != DPD_ACTION_RESTART) {
		diag("dpdaction can only be \"clear\", \"hold\" or \"restart\", defaulting to \"hold\"");
		msg.dpd_action = DPD_ACTION_HOLD;
	}

	if (msg.remotepeertype != CISCO &&
	    msg.remotepeertype != NON_CISCO) {
		diag("remote-peer-type can only be \"CISCO\" or \"NON_CISCO\" - defaulting to non-cisco mode");
		msg.remotepeertype = NON_CISCO; /*NON_CISCO=0*/
	}

	/* pack strings for inclusion in message */
	wp.msg = &msg;

	/* build esp message as esp="<esp>;<pfsgroup>" */
	if (msg.pfsgroup) {
		snprintf(esp_buf, sizeof(esp_buf), "%s;%s",
			 msg.esp ? msg.esp : "",
			 msg.pfsgroup ? msg.pfsgroup : "");
		msg.esp = esp_buf;
	}
	ugh = pack_whack_msg(&wp);
	if (ugh)
		diag(ugh);

	msg.magic = ((opts1_seen & ~(LELEM(OPT_SHUTDOWN) | LELEM(OPT_STATUS))) |
		     opts2_seen | lst_seen | cd_seen) != LEMPTY ||
		    msg.whack_options ?
		    WHACK_MAGIC : WHACK_BASIC_MAGIC;

	/* send message to Pluto */
	if (access(ctl_addr.sun_path, R_OK | W_OK) < 0) {
		int e = errno;

		switch (e) {
		case EACCES:
			fprintf(stderr,
				"whack: no right to communicate with pluto (access(\"%s\"))\n",
				ctl_addr.sun_path);
			break;
		case ENOENT:
			fprintf(stderr,
				"whack: Pluto is not running (no \"%s\")\n",
				ctl_addr.sun_path);
			break;
		default:
			fprintf(stderr,
				"whack: access(\"%s\") failed with %d %s\n",
				ctl_addr.sun_path, errno, strerror(e));
			break;
		}
		exit(RC_WHACK_PROBLEM);
	} else {
		int sock = safe_socket(AF_UNIX, SOCK_STREAM, 0);
		int exit_status = 0;
		ssize_t len = wp.str_next - (unsigned char *)&msg;

		if (sock == -1) {
			int e = errno;

			fprintf(stderr, "whack: socket() failed (%d %s)\n", e, strerror(
					e));
			exit(RC_WHACK_PROBLEM);
		}

		if (connect(sock, (struct sockaddr *)&ctl_addr,
			    offsetof(struct sockaddr_un,
				     sun_path) + strlen(ctl_addr.sun_path)) <
		    0) {
			int e = errno;

			fprintf(stderr,
				"whack:%s connect() for \"%s\" failed (%d %s)\n",
				e == ECONNREFUSED ? " is Pluto running? " : "",
				ctl_addr.sun_path, e, strerror(e));
			exit(RC_WHACK_PROBLEM);
		}

		if (write(sock, &msg, len) != len) {
			int e = errno;

			fprintf(stderr, "whack: write() failed (%d %s)\n", e, strerror(
					e));
			exit(RC_WHACK_PROBLEM);
		}

		/* for now, just copy reply back to stdout */

		{
			char buf[4097]; /* arbitrary limit on log line length */
			char *be = buf;

			for (;; ) {
				char *ls = buf;
				ssize_t rl =
					read(sock, be,
					     (buf + sizeof(buf) - 1) - be);

				if (rl < 0) {
					int e = errno;

					fprintf(stderr,
						"whack: read() failed (%d %s)\n", e,
						strerror(e));
					exit(RC_WHACK_PROBLEM);
				}
				if (rl == 0) {
					if (be != buf)
						fprintf(stderr,
							"whack: last line from pluto too long or unterminated\n");


					break;
				}

				be += rl;
				*be = '\0';

				for (;; ) {
					char *le = strchr(ls, '\n');

					if (le == NULL) {
						/* move last, partial line to start of buffer */
						memmove(buf, ls, be - ls);
						be -= ls - buf;
						break;
					}

					le++; /* include NL in line */
					if (write(STDOUT_FILENO, ls, le -
						  ls) != (le - ls)) {
						int e = errno;
						fprintf(stderr,
							"whack: write() failed to stdout(%d %s)\n", e,
							strerror(e));
					}

					/* figure out prefix number
					 * and how it should affect our exit status
					 */
					{
						unsigned long s =
							strtoul(ls, NULL, 10);

						switch (s) {
						case RC_COMMENT:
						case RC_LOG:
							/* ignore */
							break;
						case RC_SUCCESS:
							/* be happy */
							exit_status = 0;
							break;

						case RC_ENTERSECRET:
							if (!gotxauthpass) {
								xauthpasslen =
									whack_get_secret(
										xauthpass,
										sizeof(xauthpass));
							}
							send_reply(sock,
								   xauthpass,
								   xauthpasslen);
							break;

						case RC_XAUTHPROMPT:
							if (!gotxauthname) {
								xauthnamelen =
									whack_get_value(
										xauthname,
										sizeof(xauthname));
							}
							send_reply(sock,
								   xauthname,
								   xauthnamelen);
							break;

						/* case RC_LOG_SERIOUS: */
						default:
							if (msg.whack_async)
								exit_status =
									0;
							else
								exit_status =
									s;
							break;
						}
					}
					ls = le;
				}
			}
		}
		return exit_status;
	}
}
