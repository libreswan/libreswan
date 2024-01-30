/*
 * command interface to Pluto
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2003  D. Hugh Redelmeier.
 * Copyright (C) 2004-2008 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Shingo Yamawaki
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 * Copyright (C) 20212-2022 Paul Wouters <paul.wouters@aiven.io>
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>
#include <limits.h>	/* for INT_MAX */

#include "lsw_socket.h"

#include "ttodata.h"
#include "lswversion.h"
#include "lswtool.h"
#include "constants.h"
#include "lswlog.h"
#include "whack.h"
#include "ip_address.h"
#include "ip_info.h"
#include "timescale.h"

#include "ipsecconf/confread.h" /* for DEFAULT_UPDOWN */
/*
 * Print the 'ipsec --whack help' message
 */
static void help(void)
{
	fprintf(stderr,
		"Usage:\n"
		"\n"
		"all forms: [--rundir <path>] [--ctlsocket <file>] [--label <string>]\n"
		"\n"
		"help: whack [--help] [--version]\n"
		"\n"
		"connection: whack --name <connection_name> \\\n"
		"	--connalias <alias_names> \\\n"
		"	[--ipv4 | --ipv6] [--tunnelipv4 | --tunnelipv6] \\\n"
		"	(--host <ip-address> | --id <identity>) \\\n"
		"	[--ca <distinguished name>] \\\n"
		"	[--ikeport <port-number>] [--srcip <ip-address>] \\\n"
		"	[--vtiip <ip-address>/mask] \\\n"
		"	[--updown <updown>] \\\n"
		"	[--authby <psk | rsasig | rsa | ecdsa | null | eaponly>] \\\n"
		"	[--autheap <none | tls>] \\\n"
		"	[--groups <access control groups>] \\\n"
		"	[--cert <friendly_name> | --ckaid <ckaid>] \\\n"
		"	[--ca <distinguished name>] \\\n"
		"	[--sendca no|issuer|all] [--sendcert yes|always|no|never|ifasked] \\\n"
		"	[--nexthop <ip-address>] \\\n"
		"	[--client <subnet> \\\n"
		"	[--clientprotoport <protocol>/<port>] \\\n"
		"	[--dnskeyondemand] [--updown <updown>] \\\n"
		"	[--psk] | [--rsasig] | [--rsa-sha1] | [--rsa-sha2] | \\\n"
		"		[--rsa-sha2_256] | [--rsa-sha2_384 ] | [--rsa-sha2_512 ] | \\\n"
		"		[ --auth-null] | [--auth-never] \\\n"
		"	[--encrypt] [--authenticate] [--compress] [--sha2-truncbug] \\\n"
		"	[--ms-dh-downgrade] \\\n"
		"	[--overlapip] [--tunnel] \\\n"
		"	[--allow-cert-without-san-id] [--dns-match-id] \\\n"
		"	[--pfsgroup <modp1024 | modp1536 | modp2048 | \\\n"
		"		modp3072 | modp4096 | modp6144 | modp8192 \\\n"
		"		dh22 | dh23 | dh24>] \\\n"
		"	[--ike-lifetime <seconds>] [--ipsec-lifetime <seconds>] \\\n"
		"	[--ipsec-max-bytes <num>] [--ipsec-max-packets <num>] \\\n"
		"	[--rekeymargin <seconds>] [--rekeyfuzz <percentage>] \\\n"
		"	[--retransmit-timeout <seconds>] \\\n"
		"	[--retransmit-interval <msecs>] \\\n"
		"	[--send-redirect] [--redirect-to <ip>] \\\n"
		"	[--accept-redirect] [--accept-redirect-to <ip>] \\\n"
		"	[--replay-window <num>] \\\n"
		"	[--esp <esp-algos>] \\\n"
		"	[--remote-peer-type <cisco>] \\\n"
		"	[--mtu <mtu>] \\\n"
		"	[--priority <prio>] [--reqid <reqid>] \\\n"
		"	[--tfc <size>] [--send-no-esp-tfc] \\\n"
		"	[--ikev1 | --ikev2] \\\n"
		"	[--allow-narrowing] \\\n"
		"	[--fragmentation {yes,no,force}] [--no-ikepad]  \\\n"
		"	[--ikefrag-allow | --ikefrag-force] \\\n"
		"	[--esn ] [--no-esn] [--decap-dscp] [--encap-dscp] [--nopmtudisc] [--mobike] \\\n"
		"	[--tcp <no|yes|fallback>] --tcp-remote-port <port>\\\n"
#ifdef HAVE_NM
		"	[--nm-configured] \\\n"
#endif
#ifdef HAVE_LABELED_IPSEC
		"	[--policylabel <label>] \\\n"
#endif
		"	[--xauthby file|pam|alwaysok] [--xauthfail hard|soft] \\\n"
		"	[--dontrekey] [--aggressive] \\\n"
		"	[--initialcontact] [--cisco-unity] [--fake-strongswan] \\\n"
		"	[--encapsulation[={auto,yes,no}] [--no-nat-keepalive] \\\n"
		"	[--ikev1-natt <both|rfc|drafts>] [--no-nat_keepalive] \\\n"
		"	[--dpddelay <seconds> --dpdtimeout <seconds>] \\\n"
		"	[--xauthserver | --xauthclient] \\\n"
		"	[--modecfgserver | --modecfgclient] [--modecfgpull] \\\n"
		"	[--addresspool <network range>] \\\n"
		"	[--modecfgdns <ip-address, ip-address>  \\\n"
		"	[--modecfgdomains <dns-domain, dns-domain, ..>] \\\n"
		"	[--modecfgbanner <login banner>] \\\n"
		"	[--metric <metric>] \\\n"
#ifdef USE_NFLOG
		"	[--nflog-group <groupnum>] \\\n"
#endif
		"	[--conn-mark <mark/mask>] [--conn-mark-in <mark/mask>] \\\n"
		"	[--conn-mark-out <mark/mask>] \\\n"
		"	[--ipsec-interface <num>] \\\n"
		"	[--vti-interface <iface> ] [--vti-routing] [--vti-shared] \\\n"
		"	[--failnone | --failpass | --faildrop | --failreject] \\\n"
		"	[--negopass ] \\\n"
		"	[--donotrekey ] [--reauth ] \\\n"
		"	[--nic-offload <packet|crypto|no>] \\\n"
		"	--to\n"
		"\n"
		"routing: whack (--route | --unroute) --name <connection_name>\n"
		"\n"
		"initiation: whack (--initiate [--remote-host <ip or hostname>] | --terminate) \\\n"
		"	--name <connection_name> [--asynchronous] \\\n"
		"	[--username <name>] [--xauthpass <pass>]\n"
		"\n"
		"rekey: whack (--rekey-ike | --rekey-child) \\\n"
		"	--name <connection_name> [--asynchronous] \\\n"
		"\n"
		"active redirect: whack [--name <connection_name>] \\\n"
		"	--redirect-to <ip-address(es)> \n"
		"\n"
		"global redirect: whack --global-redirect yes|no|auto\n"
		"	--global-redirect-to <ip-address, dns-domain, ..> \n"
		"\n"
		"opportunistic initiation: whack [--tunnelipv4 | --tunnelipv6] \\\n"
		"	--oppohere <ip-address> --oppothere <ip-address> \\\n"
		"	--opposport <port> --oppodport <port> \\\n"
		"	[--oppoproto <protocol>]\n"
		"\n"
		"delete: whack --delete --name <connection_name>\n"
		"\n"
		"delete: whack --deleteid --name <id>\n"
		"\n"
		"deletestate: whack --deletestate <state_object_number>\n"
		"\n"
		"delete user: whack --deleteuser --name <user_name> \\\n"
		"	[--crash <ip-address>]\n"
		"\n"
		"pubkey: whack --keyid <id> [--addkey] [--pubkeyrsa <key>]\n"
		"\n"
		"debug: whack [--name <connection_name>] \\\n"
		"	[--debug help|none|<class>] \\\n"
		"	[--no-debug <class>] \\\n"
		"	[--impair help|list|none|<behaviour>]  \\\n"
		"	[--no-impair <behaviour>]\n"
		"\n"
		"listen: whack (--listen | --unlisten)\n"
		"\n"
		"socket buffers: whack --ike-socket-bufsize <bufsize>\n"
		"socket errqueue: whack --ike-socket-errqueue-toggle\n"
		"\n"
		"ddos-protection: whack (--ddos-busy | --ddos-unlimited | \\\n"
		"	--ddos-auto)\n"
		"\n"
		"list: whack [--utc] [--checkpubkeys] [--listpubkeys] [--listcerts] \\\n"
		"	[--listcacerts] [--listcrls] [--listpsks] [--listevents] [--listall]\n"
		"\n"
		"purge: whack --purgeocsp\n"
		"\n"
		"reread: whack [--fetchcrls] [--rereadcerts] [--rereadsecrets] [--rereadall]\n"
		"\n"
		"status: whack [--status] | [--briefstatus] | \\\n"
		"       [--addresspoolstatus] | [--connectionstatus] | [--briefconnectionstatus] | \\\n"
		"       [--fipsstatus] | [--processstatus] | [--shuntstatus] | [--trafficstatus] | \\\n"
		"	[--showstates]\n"
		"\n"
		"statistics: [--globalstatus] | [--clearstats]\n"
		"\n"
		"refresh dns: whack --ddns\n"
		"\n"
#ifdef USE_SECCOMP
		"testing: whack --seccomp-crashtest (CAREFUL!)\n"
		"\n"
#endif
		"shutdown: whack --shutdown [--leave-state]\n"
		"\n"
		"Libreswan %s\n",
		ipsec_version_code());
}

/* --label operand, saved for diagnostics */
static const char *label = NULL;

/* --name operand, saved for diagnostics */
static const char *name = NULL;

static const char *remote_host = NULL;

/*
 * Print a string as a diagnostic, then exit whack unhappily
 *
 * @param mess The error message to print when exiting
 * @return NEVER
 */
static void diagw(const char *mess) NEVER_RETURNS;

static void diagw(const char *mess)
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

/*
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
			diagw(ugh);
		} else {
			char buf[120];	/* arbitrary limit */

			snprintf(buf, sizeof(buf), "%s \"%s\"", ugh, this);
			diagw(buf);
		}
	}
}

/*
 * complex combined operands return one of these enumerated values
 * Note: these become flags in an lset_t.  Since there could be more
 * than lset_t could hold (currently 64), we partition them into:
 * - OPT_* options (most random options)
 * - LST_* options (list various internal data)
 * - DBGOPT_* option (DEBUG options)
 * - END_* options (End description options)
 * - CD_* options (Connection Description options)
 * - CDP_* options (Connection Description Policy bit options)
 */

enum opt_seen_ix {

#define BASIC_OPT_SEEN LELEM(BASIC_OPT_SEEN_IX)
	BASIC_OPT_SEEN_IX,	/* indicates an option from the
				 * {FIRST,LAST}_BASIC_OPT range was
				 * seen */
#define NORMAL_OPT_SEEN LELEM(NORMAL_OPT_SEEN_IX)
	NORMAL_OPT_SEEN_IX,	/* indicates an option from the
				 * {FIRST,LAST}_NORMAL_OPT range was
				 * seen */
#define CONN_OPT_SEEN LELEM(CONN_OPT_SEEN_IX)
	CONN_OPT_SEEN_IX,	/* indicates an option from the
				 * {FIRST,LAST}_CONN_OPT OR
				 * {FIRST,LAST}_END_OPT range was
				 * seen */
#define END_OPT_SEEN LELEM(END_OPT_SEEN_IX)
	END_OPT_SEEN_IX,	/* indicates an option from the
				 * {FIRST,LAST}_END_OPT range was
				 * seen */
#define DBGOPT_SEEN LELEM(DBGOPT_SEEN_IX)
	DBGOPT_SEEN_IX,		/* indicates that an option from the
				 * {FIRST,LAST}_DBGOPT range was
				 * seen. */
};

enum option_enums {

	OPT_HELP = 'h',
	OPT_VERSION = 'v',
	OPT_LABEL = 'l',

/*
 * Start the the non-ASCIC options at 256 so that they can't clash
 * with ASCII options.
 */

#define OPT_START 356

/*
 * Basic options - status and shutdown - are ment to work between
 * whack versions.  Look further down for where whack-magic is set.
 */

#define FIRST_BASIC_OPT		OPT_STATUS	/* first "basic" option */

	OPT_STATUS = OPT_START,	/* must be part of first group */
	OPT_SHUTDOWN,		/* must be part of first group */

#define LAST_BASIC_OPT		OPT_SHUTDOWN	/* last "basic" option */

/*
 * Normal options don't fall into the connection category (better
 * description? global?).
 */

#define FIRST_NORMAL_OPT	OPT_ASYNC	/* first "normal" option */

	OPT_ASYNC,

	OPT_RUNDIR,
	OPT_CTLSOCKET,
	OPT_NAME,
	OPT_REMOTE_HOST,
	OPT_CONNALIAS,

	OPT_DELETECRASH,
	OPT_USERNAME,
	OPT_XAUTHPASS,

	OPT_KEYID,
	OPT_ADDKEY,
	OPT_PUBKEYRSA,
	OPT_PUBKEYECDSA,

	OPT_ROUTE,
	OPT_UNROUTE,

	OPT_INITIATE,
	OPT_DOWN,
	OPT_DELETE,
	OPT_DELETEID,
	OPT_DELETESTATE,
	OPT_DELETEUSER,
	OPT_LISTEN,
	OPT_UNLISTEN,
	OPT_IKEBUF,
	OPT_IKE_MSGERR,

	OPT_REKEY_IKE,
	OPT_REKEY_CHILD,
	OPT_DELETE_IKE,
	OPT_DELETE_CHILD,
	OPT_DOWN_IKE,
	OPT_DOWN_CHILD,

	OPT_REDIRECT_TO,	/* either active or for connection */
	OPT_GLOBAL_REDIRECT,
	OPT_GLOBAL_REDIRECT_TO,

	OPT_DDOS_BUSY,
	OPT_DDOS_UNLIMITED,
	OPT_DDOS_AUTO,

	OPT_DDNS,

	OPT_REREADSECRETS,
	OPT_REREADCRLS,
	OPT_FETCHCRLS,
	OPT_REREADCERTS,
	OPT_REREADALL,

	OPT_PURGEOCSP,

	OPT_GLOBALSTATUS,
	OPT_CLEAR_STATS,
	OPT_LEAVE_STATE,
	OPT_TRAFFICSTATUS,
	OPT_SHUNTSTATUS,
	OPT_SHOW_STATES,
	OPT_ADDRESSPOOLSTATUS,
	OPT_BRIEFCONNECTIONSTATUS,
	OPT_CONNECTIONSTATUS,
	OPT_FIPSSTATUS,
	OPT_BRIEFSTATUS,
	OPT_PROCESSSTATUS,

#ifdef USE_SECCOMP
	OPT_SECCOMP_CRASHTEST,
#endif

	OPT_OPPO_HERE,
	OPT_OPPO_THERE,
	OPT_OPPO_PROTO,
	OPT_OPPO_SPORT,
	OPT_OPPO_DPORT,

	/* List options */

	LST_UTC,
	LST_CHECKPUBKEYS,
	LST_PUBKEYS,
	LST_CERTS,
	LST_CACERTS,
	LST_CRLS,
	LST_PSKS,
	LST_EVENTS,
	LST_ACERTS,
	LST_AACERTS,
	LST_GROUPS,
	LST_CARDS,
	LST_ALL,

#define LAST_NORMAL_OPT		LST_ALL		/* last "normal" option */

/*
 * Connection End Description options.
 *
 * These are accumulated in .right.  Then, at some point, --to is
 * encountered and .right is copied to .left and .right cleared and
 * things continue.
 */

#define FIRST_END_OPT		END_HOST	/* first end description */

	END_HOST,
	END_ID,
	END_CERT,
	END_CKAID,
	END_CA,
	END_GROUPS,
	END_IKEPORT,
	END_NEXTHOP,
	END_SUBNET,
	END_CLIENTPROTOPORT,
	END_DNSKEYONDEMAND,
	END_XAUTHNAME,
	END_XAUTHSERVER,
	END_XAUTHCLIENT,
	END_MODECFGCLIENT,
	END_MODECFGSERVER,
	END_ADDRESSPOOL,
	END_SENDCERT,
	END_SOURCEIP,
        END_INTERFACEIP,
	END_VTIIP,
	END_AUTHBY,
	END_AUTHEAP,
	END_UPDOWN,

#define LAST_END_OPT		END_UPDOWN	/* last end description*/

/*
 * Connection Description options.
 *
 * These are not end specific.
 */

#define FIRST_CONN_OPT		CD_TO		/* first connection description */

	CD_TO,

	CD_IKEv1,
	CD_IKEv2,

	CD_MODECFGDNS,
	CD_MODECFGDOMAINS,
	CD_MODECFGBANNER,
	CD_METRIC,
	CD_MTU,
	CD_PRIORITY,
	CD_TFC,
	CD_SEND_TFCPAD,
	CD_PFS,
	CD_REQID,
	CD_NFLOG_GROUP,
	CD_CONN_MARK_BOTH,
	CD_CONN_MARK_IN,
	CD_CONN_MARK_OUT,
	CD_VTI_INTERFACE,
	CD_VTI_ROUTING,
	CD_VTI_SHARED,
	CD_IPSEC_INTERFACE,
	CD_TUNNELIPV4,
	CD_TUNNELIPV6,
	CD_CONNIPV4,
	CD_CONNIPV6,

	CD_DONT_REKEY,
	CD_REAUTH,
	CD_RETRANSMIT_TIMEOUT,
	CD_RETRANSMIT_INTERVAL,
	CD_IKE_LIFETIME,
	CD_IPSEC_LIFETIME,
	CD_IPSEC_MAX_BYTES,
	CD_IPSEC_MAX_PACKETS,
	CD_REKEYMARGIN,
	CD_RKFUZZ,
	CD_KTRIES,
	CD_REPLAY_WINDOW,
	CD_DPDDELAY,
	CD_DPDTIMEOUT,
	CD_DPDACTION,
	CD_SEND_REDIRECT,
	CD_ACCEPT_REDIRECT,
	CD_ACCEPT_REDIRECT_TO,
	CD_ENCAPSULATION,
	CD_NO_NAT_KEEPALIVE,
	CD_IKEV1_NATT,
	CD_INITIAL_CONTACT,
	CD_CISCO_UNITY,
	CD_FAKE_STRONGSWAN,
	CD_MOBIKE,
	CD_IKE,
	CD_IKE_TCP,
	CD_IKE_TCP_REMOTE_PORT,
	CD_SEND_CA,
	CD_PFSGROUP,
	CD_REMOTE_PEER_TYPE,
	CD_SHA2_TRUNCBUG,
	CD_NM_CONFIGURED,
	CD_LABELED_IPSEC,
	CD_SEC_LABEL,
	CD_XAUTHBY,
	CD_XAUTHFAIL,
	CD_NIC_OFFLOAD,
	CD_IKEV2_ALLOW_NARROWING,
	CD_ESP,
	CD_INTERMEDIATE,
	CD_OVERLAPIP,
	CD_MS_DH_DOWNGRADE,
	CD_PFS_REKEY_WORKAROUND,
	CD_DNS_MATCH_ID,
	CD_IGNORE_PEER_DNS,
	CD_IKEPAD,
	CD_ALLOW_CERT_WITHOUT_SAN_ID,
	CD_MODECFGPULL,
	CD_AGGRESSIVE,
	CD_DECAP_DSCP,
	CD_ENCAP_DSCP,
	CD_NOPMTUDISC,
	CD_IKEFRAG_ALLOW,
	CD_IKEFRAG_FORCE,
	CD_FRAGMENTATION,
	CD_NO_ESN,
	CD_ESN,
	CD_COMPRESS,
	CD_TUNNEL,
	CD_TRANSPORT,
	CD_ENCRYPT,
	CD_AUTHENTICATE,
	CD_INITIATEONTRAFFIC,

	/*
	 * Connection proof-of-identity options that set .auth and
	 * .sighash_policy fields (yes the options are called authby,
	 * contradicting config files).
	 */

	OPT_AUTHBY_PSK,
	OPT_AUTHBY_AUTH_NEVER,
	OPT_AUTHBY_AUTH_NULL,
	OPT_AUTHBY_RSASIG, /* SHA1 and (for IKEv2) SHA2 */
	OPT_AUTHBY_RSA_SHA1,
	OPT_AUTHBY_RSA_SHA2,
	OPT_AUTHBY_RSA_SHA2_256,
	OPT_AUTHBY_RSA_SHA2_384,
	OPT_AUTHBY_RSA_SHA2_512,
	OPT_AUTHBY_ECDSA, /* no SHA1 support */
	OPT_AUTHBY_ECDSA_SHA2_256,
	OPT_AUTHBY_ECDSA_SHA2_384,
	OPT_AUTHBY_ECDSA_SHA2_512,

	/*
	 * Connection shunt policies.
	 */

	CDS_NEVER_NEGOTIATE,
	CDS_NEGOTIATION = CDS_NEVER_NEGOTIATE + SHUNT_POLICY_ROOF,
	CDS_FAILURE = CDS_NEGOTIATION + SHUNT_POLICY_ROOF,
	CDS_LAST = CDS_FAILURE + SHUNT_POLICY_ROOF - 1,

	/*
	 * Connection policy bits options.
	 *
	 * Really part of Connection Description but, seemingly,
	 * easier to manipulate as separate policy bits.
	 *
	 * XXX: I'm skeptical.
	 *
	 *
	 * The next range is for single-element policy options.
	 * It covers enum sa_policy_bits values.
	 */

	CDP_SINGLETON,
	/* large gap of unnamed values... */
	CDP_SINGLETON_LAST = CDP_SINGLETON + POLICY_IX_LAST,

	/* === end of correspondence with POLICY_* === */

#define LAST_CONN_OPT		CDP_SINGLETON_LAST	/* last connection description */

/*
 * Debug and impair options.
 *
 * Unlike the above, these are allowed to repeat (and probably play
 * other tricks).
 */

#define FIRST_DBGOPT		DBGOPT_NONE

	DBGOPT_NONE,
	DBGOPT_ALL,

	DBGOPT_DEBUG,
	DBGOPT_NO_DEBUG,
	DBGOPT_IMPAIR,
	DBGOPT_NO_IMPAIR,

#define LAST_DBGOPT		DBGOPT_NO_IMPAIR

#define	OPTION_ENUMS_LAST	LAST_DBGOPT
#define OPTION_ENUMS_ROOF	(OPTION_ENUMS_LAST+1)
};

int long_index;

static const struct option long_opts[] = {

	/* name, has_arg, flag, val */

	{ "help", no_argument, NULL, OPT_HELP },
	{ "version", no_argument, NULL, OPT_VERSION },
	{ "label", required_argument, NULL, OPT_LABEL },

	{ "rundir", required_argument, NULL, OPT_RUNDIR },
	{ "ctlbase", required_argument, NULL, OPT_RUNDIR }, /* backwards compat */
	{ "ctlsocket", required_argument, NULL, OPT_CTLSOCKET },
	{ "name", required_argument, NULL, OPT_NAME },
	{ "remote-host", required_argument, NULL, OPT_REMOTE_HOST },
	{ "connalias", required_argument, NULL, OPT_CONNALIAS },

	{ "keyid", required_argument, NULL, OPT_KEYID },
	{ "addkey", no_argument, NULL, OPT_ADDKEY },
	{ "pubkeyrsa", required_argument, NULL, OPT_PUBKEYRSA },

	{ "route", no_argument, NULL, OPT_ROUTE },
	{ "ondemand", no_argument, NULL, OPT_ROUTE },	/* alias */
	{ "unroute", no_argument, NULL, OPT_UNROUTE },

	{ "initiate", no_argument, NULL, OPT_INITIATE },
	{ "down", no_argument, NULL, OPT_DOWN },
	{ "terminate", no_argument, NULL, OPT_DOWN }, /* backwards compat */
	{ "delete", no_argument, NULL, OPT_DELETE },
	{ "deleteid", no_argument, NULL, OPT_DELETEID },
	{ "deletestate", required_argument, NULL, OPT_DELETESTATE },
	{ "deleteuser", no_argument, NULL, OPT_DELETEUSER },
	{ "crash", required_argument, NULL, OPT_DELETECRASH },
	{ "listen", no_argument, NULL, OPT_LISTEN },
	{ "unlisten", no_argument, NULL, OPT_UNLISTEN },
	{ "ike-socket-bufsize", required_argument, NULL, OPT_IKEBUF},
	{ "ike-socket-errqueue-toggle", no_argument, NULL, OPT_IKE_MSGERR },

	{ "redirect-to", required_argument, NULL, OPT_REDIRECT_TO },
	{ "global-redirect", required_argument, NULL, OPT_GLOBAL_REDIRECT },
	{ "global-redirect-to", required_argument, NULL, OPT_GLOBAL_REDIRECT_TO },

	{ "ddos-busy", no_argument, NULL, OPT_DDOS_BUSY },
	{ "ddos-unlimited", no_argument, NULL, OPT_DDOS_UNLIMITED },
	{ "ddos-auto", no_argument, NULL, OPT_DDOS_AUTO },

	{ "ddns", no_argument, NULL, OPT_DDNS },

	{ "rereadsecrets", no_argument, NULL, OPT_REREADSECRETS },
	{ "rereadcrls", no_argument, NULL, OPT_REREADCRLS }, /* obsolete */
	{ "rereadcerts", no_argument, NULL, OPT_REREADCERTS },
	{ "fetchcrls", no_argument, NULL, OPT_FETCHCRLS },
	{ "rereadall", no_argument, NULL, OPT_REREADALL },

	{ "purgeocsp", no_argument, NULL, OPT_PURGEOCSP },

	{ "clearstats", no_argument, NULL, OPT_CLEAR_STATS },

	{ "status", no_argument, NULL, OPT_STATUS },
	{ "globalstatus", no_argument, NULL, OPT_GLOBALSTATUS },
	{ "trafficstatus", no_argument, NULL, OPT_TRAFFICSTATUS },
	{ "shuntstatus", no_argument, NULL, OPT_SHUNTSTATUS },
	{ "addresspoolstatus", no_argument, NULL, OPT_ADDRESSPOOLSTATUS },
	{ "connectionstatus", no_argument, NULL, OPT_CONNECTIONSTATUS },
	{ "briefconnectionstatus", no_argument, NULL, OPT_BRIEFCONNECTIONSTATUS },
	{ "fipsstatus", no_argument, NULL, OPT_FIPSSTATUS },
	{ "briefstatus", no_argument, NULL, OPT_BRIEFSTATUS },
	{ "processstatus", no_argument, NULL, OPT_PROCESSSTATUS },
	{ "statestatus", no_argument, NULL, OPT_SHOW_STATES }, /* alias to catch typos */
	{ "showstates", no_argument, NULL, OPT_SHOW_STATES },

#ifdef USE_SECCOMP
	{ "seccomp-crashtest", no_argument, NULL, OPT_SECCOMP_CRASHTEST },
#endif
	{ "shutdown", no_argument, NULL, OPT_SHUTDOWN },
	{ "leave-state", no_argument, NULL, OPT_LEAVE_STATE },
	{ "username", required_argument, NULL, OPT_USERNAME },
	{ "xauthuser", required_argument, NULL, OPT_USERNAME }, /* old name */
	{ "xauthname", required_argument, NULL, OPT_USERNAME }, /* old name */
	{ "xauthpass", required_argument, NULL, OPT_XAUTHPASS },

	{ "oppohere", required_argument, NULL, OPT_OPPO_HERE },
	{ "oppothere", required_argument, NULL, OPT_OPPO_THERE },
	{ "oppoproto", required_argument, NULL, OPT_OPPO_PROTO },
	{ "opposport", required_argument, NULL, OPT_OPPO_SPORT },
	{ "oppodport", required_argument, NULL, OPT_OPPO_DPORT },

	{ "asynchronous", no_argument, NULL, OPT_ASYNC },

	{ "rekey-ike", no_argument, NULL, OPT_REKEY_IKE },
	{ "rekey-child", no_argument, NULL, OPT_REKEY_CHILD },
	{ "delete-ike", no_argument, NULL, OPT_DELETE_IKE },
	{ "delete-child", no_argument, NULL, OPT_DELETE_CHILD },
	{ "down-ike", no_argument, NULL, OPT_DOWN_IKE },
	{ "down-child", no_argument, NULL, OPT_DOWN_CHILD },

	/* list options */

	{ "utc", no_argument, NULL, LST_UTC },
	{ "checkpubkeys", no_argument, NULL, LST_CHECKPUBKEYS },
	{ "listpubkeys", no_argument, NULL, LST_PUBKEYS },
	{ "listcerts", no_argument, NULL, LST_CERTS },
	{ "listcacerts", no_argument, NULL, LST_CACERTS },
	{ "listcrls", no_argument, NULL, LST_CRLS },
	{ "listpsks", no_argument, NULL, LST_PSKS },
	{ "listevents", no_argument, NULL, LST_EVENTS },
	{ "listall", no_argument, NULL, LST_ALL },

	/* options for an end description */

	{ "host", required_argument, NULL, END_HOST },
	{ "id", required_argument, NULL, END_ID },
	{ "cert", required_argument, NULL, END_CERT },
	{ "ckaid", required_argument, NULL, END_CKAID },
	{ "ca", required_argument, NULL, END_CA },
	{ "groups", required_argument, NULL, END_GROUPS },
	{ "ikeport", required_argument, NULL, END_IKEPORT },
	{ "nexthop", required_argument, NULL, END_NEXTHOP },
	{ "client", required_argument, NULL, END_SUBNET },	/* alias / backward compat */
	{ "subnet", required_argument, NULL, END_SUBNET },
	{ "clientprotoport", required_argument, NULL, END_CLIENTPROTOPORT },
#ifdef USE_DNSSEC
	{ "dnskeyondemand", no_argument, NULL, END_DNSKEYONDEMAND },
#endif
	{ "sourceip",  required_argument, NULL, END_SOURCEIP },
	{ "srcip",  required_argument, NULL, END_SOURCEIP },	/* alias / backwards compat */
	{ "vtiip",  required_argument, NULL, END_VTIIP },
	{ "interfaceip", required_argument, NULL, END_INTERFACEIP },
	{ "authby",  required_argument, NULL, END_AUTHBY },
	{ "autheap",  required_argument, NULL, END_AUTHEAP },
	{ "updown", required_argument, NULL, END_UPDOWN },

	/* options for a connection description */

	{ "to", no_argument, NULL, CD_TO },

	/* option for cert rotation */

	{ "intermediate", optional_argument, NULL, CD_INTERMEDIATE },
#define PS(o, p)	{ o, no_argument, NULL, CDP_SINGLETON + POLICY_##p##_IX }
	{ "encrypt", no_argument, NULL, CD_ENCRYPT },
	{ "authenticate", no_argument, NULL, CD_AUTHENTICATE },
	{ "compress", optional_argument, NULL, CD_COMPRESS },
	{ "overlapip", optional_argument, NULL, CD_OVERLAPIP },
	{ "tunnel", no_argument, NULL, CD_TUNNEL, },
	{ "transport", no_argument, NULL, CD_TRANSPORT, },
	{ "tunnelipv4", no_argument, NULL, CD_TUNNELIPV4 },
	{ "tunnelipv6", no_argument, NULL, CD_TUNNELIPV6 },
	{ "ms-dh-downgrade", optional_argument, NULL, CD_MS_DH_DOWNGRADE },
	{ "pfs-rekey-workaround", optional_argument, NULL, CD_PFS_REKEY_WORKAROUND, },
	{ "dns-match-id", optional_argument, NULL, CD_DNS_MATCH_ID },
	{ "allow-cert-without-san-id", no_argument, NULL, CD_ALLOW_CERT_WITHOUT_SAN_ID },
	{ "sha2-truncbug", optional_argument, NULL, CD_SHA2_TRUNCBUG },
	{ "sha2_truncbug", no_argument, NULL, CD_SHA2_TRUNCBUG }, /* backwards compatibility */
	{ "aggressive", optional_argument, NULL, CD_AGGRESSIVE },
	{ "aggrmode", no_argument, NULL, CD_AGGRESSIVE }, /*  backwards compatibility */

	{ "initiateontraffic", no_argument, NULL, CD_INITIATEONTRAFFIC }, /* obsolete */

	{ "pass", no_argument, NULL, CDS_NEVER_NEGOTIATE + SHUNT_PASS },
	{ "drop", no_argument, NULL, CDS_NEVER_NEGOTIATE + SHUNT_DROP },
	{ "reject", no_argument, NULL, CDS_NEVER_NEGOTIATE + SHUNT_REJECT },

	{ "negopass", no_argument, NULL, CDS_NEGOTIATION + SHUNT_PASS },

	{ "failnone", no_argument, NULL, CDS_FAILURE + SHUNT_NONE },
	{ "failpass", no_argument, NULL, CDS_FAILURE + SHUNT_PASS },
	{ "faildrop", no_argument, NULL, CDS_FAILURE + SHUNT_DROP },
	{ "failreject", no_argument, NULL, CDS_FAILURE + SHUNT_REJECT },

	{ "dontrekey", no_argument, NULL, CD_DONT_REKEY, },
	{ "reauth", no_argument, NULL, CD_REAUTH, },
	{ "encaps", required_argument, NULL, CD_ENCAPSULATION },
	{ "encapsulation", optional_argument, NULL, CD_ENCAPSULATION },
	{ "no-nat_keepalive", no_argument, NULL,  CD_NO_NAT_KEEPALIVE },
	{ "ikev1_natt", required_argument, NULL, CD_IKEV1_NATT },	/* obsolete _ */
	{ "ikev1-natt", required_argument, NULL, CD_IKEV1_NATT },
	{ "initialcontact", no_argument, NULL,  CD_INITIAL_CONTACT },
	{ "cisco_unity", no_argument, NULL, CD_CISCO_UNITY },	/* obsolete _ */
	{ "cisco-unity", no_argument, NULL, CD_CISCO_UNITY },
	{ "fake-strongswan", no_argument, NULL, CD_FAKE_STRONGSWAN },
	{ "mobike", optional_argument, NULL, CD_MOBIKE },

	{ "dpddelay", required_argument, NULL, CD_DPDDELAY },
	{ "dpdtimeout", required_argument, NULL, CD_DPDTIMEOUT },
	{ "dpdaction", required_argument, NULL, CD_DPDACTION },
	{ "send-redirect", required_argument, NULL, CD_SEND_REDIRECT },
	{ "accept-redirect", required_argument, NULL, CD_ACCEPT_REDIRECT },
	{ "accept-redirect-to", required_argument, NULL, CD_ACCEPT_REDIRECT_TO },

	{ "xauth", no_argument, NULL, END_XAUTHSERVER },
	{ "xauthserver", no_argument, NULL, END_XAUTHSERVER },
	{ "xauthclient", no_argument, NULL, END_XAUTHCLIENT },
	{ "xauthby", required_argument, NULL, CD_XAUTHBY },
	{ "xauthfail", required_argument, NULL, CD_XAUTHFAIL },
	{ "modecfgpull", no_argument, NULL, CD_MODECFGPULL },
	{ "modecfgserver", no_argument, NULL, END_MODECFGSERVER },
	{ "modecfgclient", no_argument, NULL, END_MODECFGCLIENT },
	{ "addresspool", required_argument, NULL, END_ADDRESSPOOL },
	{ "modecfgdns", required_argument, NULL, CD_MODECFGDNS },
	{ "modecfgdomains", required_argument, NULL, CD_MODECFGDOMAINS },
	{ "modecfgbanner", required_argument, NULL, CD_MODECFGBANNER },
	{ "modeconfigserver", no_argument, NULL, END_MODECFGSERVER },
	{ "modeconfigclient", no_argument, NULL, END_MODECFGCLIENT },

	{ "metric", required_argument, NULL, CD_METRIC },
	{ "mtu", required_argument, NULL, CD_MTU },
	{ "priority", required_argument, NULL, CD_PRIORITY },
	{ "tfc", required_argument, NULL, CD_TFC },
	{ "send-no-esp-tfc", no_argument, NULL, CD_SEND_TFCPAD },
	{ "pfs", optional_argument, NULL, CD_PFS },
	{ "reqid", required_argument, NULL, CD_REQID },
#ifdef USE_NFLOG
	{ "nflog-group", required_argument, NULL, CD_NFLOG_GROUP },
#endif
	{ "conn-mark", required_argument, NULL, CD_CONN_MARK_BOTH },
	{ "conn-mark-in", required_argument, NULL, CD_CONN_MARK_IN },
	{ "conn-mark-out", required_argument, NULL, CD_CONN_MARK_OUT },
	{ "vti-iface", required_argument, NULL, CD_VTI_INTERFACE }, /* backward compat */
	{ "vti-interface", required_argument, NULL, CD_VTI_INTERFACE },
	{ "vti-routing", optional_argument, NULL, CD_VTI_ROUTING },
	{ "vti-shared", optional_argument, NULL, CD_VTI_SHARED },
	{ "ipsec-interface", required_argument, NULL, CD_IPSEC_INTERFACE },
	{ "sendcert", required_argument, NULL, END_SENDCERT },
	{ "sendca", required_argument, NULL, CD_SEND_CA },
	{ "ipv4", no_argument, NULL, CD_CONNIPV4 },
	{ "ipv6", no_argument, NULL, CD_CONNIPV6 },
	{ "ikelifetime", required_argument, NULL, CD_IKE_LIFETIME },
	{ "ipseclifetime", required_argument, NULL, CD_IPSEC_LIFETIME }, /* backwards compat */
	{ "ipsec-lifetime", required_argument, NULL, CD_IPSEC_LIFETIME },
	{ "ipsec-max-bytes", required_argument, NULL, CD_IPSEC_MAX_BYTES},
	{ "ipsec-max-packets", required_argument, NULL, CD_IPSEC_MAX_PACKETS},
	{ "retransmit-timeout", required_argument, NULL, CD_RETRANSMIT_TIMEOUT },
	{ "retransmit-interval", required_argument, NULL, CD_RETRANSMIT_INTERVAL },
	{ "rekeymargin", required_argument, NULL, CD_REKEYMARGIN },
	/* OBSOLETE */
	{ "rekeywindow", required_argument, NULL, CD_REKEYMARGIN },
	{ "rekeyfuzz", required_argument, NULL, CD_RKFUZZ },
	{ "keyingtries", required_argument, NULL, CD_KTRIES },
	{ "replay-window", required_argument, NULL, CD_REPLAY_WINDOW },
	{ "ike",    required_argument, NULL, CD_IKE },
	{ "ikealg", required_argument, NULL, CD_IKE },
	{ "pfsgroup", required_argument, NULL, CD_PFSGROUP },
	{ "esp", required_argument, NULL, CD_ESP },
	{ "remote-peer-type", required_argument, NULL, CD_REMOTE_PEER_TYPE },
	{ "nic-offload", required_argument, NULL, CD_NIC_OFFLOAD},

#define AB(NAME, ENUM) { NAME, no_argument, NULL, OPT_AUTHBY_##ENUM, }
	AB("psk", PSK),
	AB("auth-never", AUTH_NEVER),
	AB("auth-null", AUTH_NULL),
	AB("rsasig", RSASIG),
	AB("ecdsa", ECDSA),
	AB("ecdsa-sha2", ECDSA),
	AB("ecdsa-sha2_256", ECDSA_SHA2_256),
	AB("ecdsa-sha2_384", ECDSA_SHA2_384),
	AB("ecdsa-sha2_512", ECDSA_SHA2_512),
	AB("rsa-sha1", RSA_SHA1),
	AB("rsa-sha2", RSA_SHA2),
	AB("rsa-sha2_256", RSA_SHA2_256),
	AB("rsa-sha2_384", RSA_SHA2_384),
	AB("rsa-sha2_512", RSA_SHA2_512),
#undef AB

	{ "ikev1", no_argument, NULL, CD_IKEv1 },
	{ "ikev1-allow", no_argument, NULL, CD_IKEv1 }, /* obsolete name */
	{ "ikev2", no_argument, NULL, CD_IKEv2 },
	{ "ikev2-allow", no_argument, NULL, CD_IKEv2 }, /* obsolete name */
	{ "ikev2-propose", no_argument, NULL, CD_IKEv2 }, /* obsolete, map onto allow */

	{ "allow-narrowing", no_argument, NULL, CD_IKEV2_ALLOW_NARROWING, },
#ifdef AUTH_HAVE_PAM
	PS("ikev2-pam-authorize", IKEV2_PAM_AUTHORIZE),
#endif
	{ "ikefrag-allow", no_argument, NULL, CD_IKEFRAG_ALLOW }, /* obsolete name */
	{ "ikefrag-force", no_argument, NULL, CD_IKEFRAG_FORCE }, /* obsolete name */
	{ "fragmentation", required_argument, NULL, CD_FRAGMENTATION },

	{ "ikepad", no_argument, NULL, CD_IKEPAD },

	{ "no-esn", no_argument, NULL, CD_NO_ESN }, /* obsolete */
	{ "esn", optional_argument, NULL, CD_ESN },
	{ "decap-dscp", optional_argument, NULL, CD_DECAP_DSCP },
	{ "encap-dscp", optional_argument, NULL, CD_ENCAP_DSCP },
	{ "nopmtudisc", optional_argument, NULL, CD_NOPMTUDISC },
	{ "ignore-peer-dns", optional_argument, NULL, CD_IGNORE_PEER_DNS },
#undef PS

	{ "tcp", required_argument, NULL, CD_IKE_TCP },
	{ "tcp-remote-port", required_argument, NULL, CD_IKE_TCP_REMOTE_PORT },

#ifdef HAVE_NM
	{ "nm_configured", optional_argument, NULL, CD_NM_CONFIGURED }, /* backwards compat */
	{ "nm-configured", optional_argument, NULL, CD_NM_CONFIGURED },
#endif

	{ "policylabel", required_argument, NULL, CD_SEC_LABEL },

	{ "debug-none", no_argument, NULL, DBGOPT_NONE },
	{ "debug-all", no_argument, NULL, DBGOPT_ALL },
	{ "debug", required_argument, NULL, DBGOPT_DEBUG, },
	{ "no-debug", required_argument, NULL, DBGOPT_NO_DEBUG, },
	{ "impair", required_argument, NULL, DBGOPT_IMPAIR, },
	{ "no-impair", required_argument, NULL, DBGOPT_NO_IMPAIR, },

	{ 0, 0, 0, 0 }
};

/*
 * figure out an address family.
 */
struct family {
	const char *used_by;
	const struct ip_info *type;
};

static err_t opt_ttoaddress_num(struct family *family, ip_address *address)
{
	err_t err = ttoaddress_num(shunk1(optarg), family->type, address);
	if (err == NULL && family->type == NULL) {
		family->type = address_type(address);
		family->used_by = long_opts[long_index].name;
	}
	return err;
}

static err_t opt_ttoaddress_dns(struct family *family, ip_address *address)
{
	err_t err = ttoaddress_dns(shunk1(optarg), family->type, address);
	if (err == NULL && family->type == NULL) {
		family->type = address_type(address);
		family->used_by = long_opts[long_index].name;
	}
	return err;
}

static void opt_to_address(struct family *family, ip_address *address)
{
	diagq(opt_ttoaddress_dns(family, address), optarg);
}

static void opt_to_cidr(struct family *family, ip_cidr *cidr)
{
	diagq(ttocidr_num(shunk1(optarg), family->type, cidr), optarg);
	if (family->type == NULL) {
		family->type = cidr_type(cidr);
		family->used_by = long_opts[long_index].name;
	}
}

static const struct ip_info *get_address_family(struct family *family)
{
	if (family->type == NULL) {
		family->type = &ipv4_info;
		family->used_by = long_opts[long_index].name;
	}
	return family->type;
}

static ip_address get_address_any(struct family *family)
{
	return get_address_family(family)->address.unspec;
}

struct sockaddr_un ctl_addr = {
	.sun_family = AF_UNIX,
	.sun_path  = DEFAULT_CTL_SOCKET,
#ifdef USE_SOCKADDR_LEN
	.sun_len = sizeof(struct sockaddr_un),
#endif
};

static deltatime_t optarg_deltatime(const struct timescale *timescale)
{
	passert(long_opts[long_index].has_arg == required_argument);
	deltatime_t deltatime;
	diag_t diag = ttodeltatime(optarg, &deltatime, timescale);
	if (diag != NULL) {
		diagq(str_diag(diag), optarg);
	}
	return deltatime;
}

static uintmax_t optarg_uintmax(void)
{
	passert(long_opts[long_index].has_arg == required_argument);
	uintmax_t val;
	err_t err = shunk_to_uintmax(shunk1(optarg), NULL, /*base*/0, &val);
	if (err != NULL) {
		diagq(err, optarg);
	}
	return val;
}

/*
 * Lookup OPTARG in NAMES.
 *
 * When optional_argument OPTARG is missing, return OPTIONAL (pass
 * optional=0 when required_argument).
 */

static uintmax_t optarg_sparse(unsigned optional, const struct sparse_name names[])
{
	if (optarg == NULL) {
		passert(long_opts[long_index].has_arg == optional_argument);
		passert(optional != 0);
		return optional;
	}

	const struct sparse_name *name = sparse_lookup(names, optarg);
	if (name == NULL) {
		JAMBUF(buf) {
			const char *msg = jambuf_cursor(buf); /* hack */
			jam(buf, "unrecognized --%s '%s', valid arguments are: ",
			    long_opts[long_index].name, optarg);
			jam_sparse_names(buf, names, ", ");
			diagw(msg);
		}
	}
	return name->value;
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
	struct logger *logger = tool_logger(argc, argv);

	struct whack_message msg;
	struct whackpacker wp;
	char esp_buf[256];	/* uses snprintf */
	bool seen[OPTION_ENUMS_ROOF] = {0};
	lset_t opts_seen = LEMPTY;

	char xauthusername[MAX_XAUTH_USERNAME_LEN];
	char xauthpass[XAUTH_MAX_PASS_LENGTH];
	int usernamelen = 0;
	int xauthpasslen = 0;
	bool gotusername = false, gotxauthpass = false;
	const char *ugh;
	bool ignore_errors = false;

	zero(&msg);	/* ??? pointer fields might not be NULLed */

	clear_end("left", &msg.left);
	clear_end("right", &msg.right);
	struct whack_end *end = &msg.left;

	struct family host_family = { 0, };
	struct family child_family = { 0, };

	msg.from_whack = true;		/* use whack defaults */

	msg.name = NULL;
	msg.remote_host = NULL;
	msg.dnshostname = NULL;

	msg.keyid = NULL;
	msg.keyval.ptr = NULL;
	msg.esp = NULL;
	msg.ike = NULL;
	msg.pfsgroup = NULL;
	msg.nat_keepalive = true;

	msg.xauthby = XAUTHBY_FILE;
	msg.xauthfail = XAUTHFAIL_HARD;
	msg.modecfg_domains = NULL;
	msg.modecfg_dns = NULL;
	msg.modecfg_banner = NULL;

	msg.sa_ipsec_max_bytes = IPSEC_SA_MAX_OPERATIONS; /* max uint_64_t */
	msg.sa_ipsec_max_packets = IPSEC_SA_MAX_OPERATIONS; /* max uint_64_t */
	msg.sa_rekey_margin = deltatime(SA_REPLACEMENT_MARGIN_DEFAULT);
	msg.sa_rekeyfuzz_percent = SA_REPLACEMENT_FUZZ_DEFAULT;
	msg.keyingtries.set = false;
	/* whack cannot access kernel_ops->replay_window */
	msg.replay_window = IPSEC_SA_DEFAULT_REPLAY_WINDOW;
	msg.retransmit_timeout = deltatime(RETRANSMIT_TIMEOUT_DEFAULT);
	msg.retransmit_interval = deltatime_ms(RETRANSMIT_INTERVAL_DEFAULT_MS);

	msg.host_afi = NULL;
	msg.child_afi = NULL;

	msg.right.updown = DEFAULT_UPDOWN;
	msg.left.updown = DEFAULT_UPDOWN;

	msg.enable_tcp = 0; /* aka unset */;
	msg.tcp_remoteport = 0; /* aka unset */

	/* set defaults to ICMP PING request */
	msg.oppo.ipproto = IPPROTO_ICMP;
	msg.oppo.local.port = ip_hport(8);
	msg.oppo.remote.port = ip_hport(0);

	msg.dpd_action = DPD_ACTION_UNSET;

	for (;;) {

		/*
		 * Note: we don't like the way short options get parsed
		 * by getopt_long, so we simply pass an empty string as
		 * the list.  It could be "hp:d:c:o:eatfs" "NARXPECK".
		 */
		int c = getopt_long(argc, argv, "", long_opts, &long_index);

		/* end of flags? exit loop */
		if (c < 0) {
			break;
		}

		/*
		 * per-class option processing
		 *
		 * Mostly detection of repeated flags.
		 */
		if (FIRST_BASIC_OPT <= c && c <= LAST_BASIC_OPT) {
			/*
			 * OPT_* options get added to "opts_seen" and
			 * "seen[]".  Any repeated options are
			 * rejected.
			 */
			if (seen[c])
				diagq("duplicated flag",
				      long_opts[long_index].name);
			seen[c] = true;
			opts_seen |= BASIC_OPT_SEEN;
		} else if (FIRST_NORMAL_OPT <= c && c <= LAST_NORMAL_OPT) {
			/*
			 * OPT_* options in the above range get added
			 * to "seen[]".  Any repeated options are
			 * rejected.  The marker OPTS_SEEN_NORMAL is
			 * also added to "opts_seen".
			 */
			if (seen[c]) {
				diagq("duplicated flag",
				      long_opts[long_index].name);
			}
			seen[c] = true;
			opts_seen |= NORMAL_OPT_SEEN;
		} else if (FIRST_DBGOPT <= c && c <= LAST_DBGOPT) {
			/*
			 * DBGOPT_* options are treated separately.
			 * For instance, repeats are allowed.
			 */
#if 0
			seen[c] = true;
#endif
			opts_seen |= DBGOPT_SEEN;
		} else if (FIRST_END_OPT <= c && c <= LAST_END_OPT) {
			/*
			 * END_* options are added to seen[] but when
			 * --to is encountered, their range is
			 * scrubbed.  This way they can appear both
			 * before and after --to.
			 *
			 * To track that they appeared anywhere, the
			 * END_OPT_SEEN bit is also set.
			 *
			 * Since END options are also conn options,
			 * CONN_OPT_SEEN is also set.
			 */
			if (seen[c])
				diagq("duplicated flag",
				      long_opts[long_index].name);
			seen[c] = true;
			opts_seen |= END_OPT_SEEN;
			opts_seen |= CONN_OPT_SEEN;
		} else if (FIRST_CONN_OPT <= c && c <= LAST_CONN_OPT) {
			/*
			 * CD_* options are added to seen[].  Repeated
			 * options are rejected.
			 */
			if (seen[c])
				diagq("duplicated flag",
				      long_opts[long_index].name);
			seen[c] = true;
			opts_seen |= CONN_OPT_SEEN;
#if 0
		} else {
			/*
			 * Not yet as C could be EOF or a character.
			 */
			passert(bad option);
#endif
		}

		/*
		 * Note: all switches must "continue" the loop (or
		 * barf).
		 *
		 * Note: no "default:".  Instead missing cases fall
		 * off the end and hit the bad_case.
		 *
		 * XXX: should cast C to enum option_enums; can't
		 * because some ranges are missing.
		 */
		switch (c) {

		case 0:	/* long option already handled */
			continue;

		/* diagnostic already printed by getopt_long */
		case ':':
		/* diagnostic already printed by getopt_long */
		case '?':
			/* print no additional diagnostic, but exit sadly */
			diagw(NULL);
			/* not actually reached */
			break;

		case OPT_HELP:	/* --help */
			help();
			/* GNU coding standards say to stop here */
			return 0;

		case OPT_VERSION:	/* --version */
			printf("%s\n", ipsec_version_string());
			/* GNU coding standards say to stop here */
			return 0;

		case OPT_LABEL:	/* --label <string> */
			label = optarg;	/* remember for diagnostics */
			continue;

		/* the rest of the options combine in complex ways */

		case OPT_RUNDIR:	/* --rundir <dir> */
			if (snprintf(ctl_addr.sun_path,
				     sizeof(ctl_addr.sun_path),
				     "%s/pluto.ctl", optarg) == -1)
				diagw("Invalid rundir for sun_addr");

			continue;

		case OPT_CTLSOCKET:	/* --ctlsocket <file> */
			if (snprintf(ctl_addr.sun_path,
				     sizeof(ctl_addr.sun_path),
				     "%s", optarg) == -1)
				diagw("Invalid ctlsocket for sun_addr");

			continue;

		case OPT_NAME:	/* --name <connection-name> */
			name = optarg;
			msg.name = optarg;
			continue;

		case OPT_REMOTE_HOST:	/* --remote-host <ip or hostname> */
			remote_host = optarg;
			msg.remote_host = optarg;
			continue;

		case OPT_KEYID:	/* --keyid <identity> */
			msg.whack_key = true;
			msg.keyid = optarg;	/* decoded by Pluto */
			continue;

		case OPT_IKEBUF:	/* --ike-socket-bufsize <bufsize> */
		{
			uintmax_t opt_whole = optarg_uintmax();
			if (opt_whole < 1500) {
				diagw("Ignoring extremely unwise IKE buffer size choice");
			} else {
				msg.ike_buf_size = opt_whole;
				msg.whack_listen = true;
			}
			continue;
		}

		case OPT_IKE_MSGERR:	/* --ike-socket-errqueue-toggle */
			msg.ike_sock_err_toggle = true;
			msg.whack_listen = true;
			continue;

		case OPT_ADDKEY:	/* --addkey */
			msg.whack_addkey = true;
			continue;

		case OPT_PUBKEYRSA:	/* --pubkeyrsa <key> */
			if (msg.keyval.ptr != NULL)
				diagq("only one RSA public-key allowed", optarg);

			/* let msg.keyval leak */
			ugh = ttochunk(shunk1(optarg), 0, &msg.keyval);
			if (ugh != NULL) {
				/* perhaps enough space */
				char ugh_space[80];

				snprintf(ugh_space, sizeof(ugh_space),
					 "RSA public-key data malformed (%s)",
					 ugh);
				diagq(ugh_space, optarg);
			}
			msg.pubkey_alg = IPSECKEY_ALGORITHM_RSA;
			continue;

		case OPT_PUBKEYECDSA:	/* --pubkeyecdsa <key> */
			if (msg.keyval.ptr != NULL)
				diagq("only one ECDSA public-key allowed", optarg);

			/* let msg.keyval leak */
			ugh = ttochunk(shunk1(optarg), 0, &msg.keyval);
			if (ugh != NULL) {
				/* perhaps enough space */
				char ugh_space[80];

				snprintf(ugh_space, sizeof(ugh_space),
					 "ECDSA public-key data malformed (%s)",
					 ugh);
				diagq(ugh_space, optarg);
			}
			msg.pubkey_alg = IPSECKEY_ALGORITHM_ECDSA;
			continue;

		case OPT_ROUTE:	/* --route */
			msg.whack_route = true;
			continue;

		case OPT_UNROUTE:	/* --unroute */
			msg.whack_unroute = true;
			continue;

		case OPT_INITIATE:	/* --initiate */
			msg.whack_initiate = true;
			continue;

		case OPT_DOWN:	/* --down | --terminate */
			msg.whack_down = true;
			continue;

		case OPT_REKEY_IKE: /* --rekey-ike */
			msg.whack_sa = WHACK_REKEY_SA;
			msg.whack_sa_type = IKE_SA;
			continue;
		case OPT_REKEY_CHILD: /* --rekey-child */
			msg.whack_sa = WHACK_REKEY_SA;
			msg.whack_sa_type = CHILD_SA;
			continue;

		case OPT_DELETE_IKE: /* --delete-ike */
			msg.whack_sa = WHACK_DELETE_SA;
			msg.whack_sa_type = IKE_SA;
			continue;
		case OPT_DELETE_CHILD: /* --delete-child */
			msg.whack_sa = WHACK_DELETE_SA;
			msg.whack_sa_type = CHILD_SA;
			continue;

		case OPT_DOWN_IKE: /* --down-ike */
			msg.whack_sa = WHACK_DOWN_SA;
			msg.whack_sa_type = IKE_SA;
			continue;
		case OPT_DOWN_CHILD: /* --down-child */
			msg.whack_sa = WHACK_DOWN_SA;
			msg.whack_sa_type = CHILD_SA;
			continue;

		case OPT_DELETE:	/* --delete */
			msg.whack_delete = true;
			continue;

		case OPT_DELETEID: /* --deleteid --name <id> */
			msg.whack_deleteid = true;
			continue;

		case OPT_DELETESTATE: /* --deletestate <state_object_number> */
			msg.whack_deletestate = true;
			msg.whack_deletestateno = optarg_uintmax();
			continue;

		case OPT_DELETECRASH:	/* --crash <ip-address> */
			msg.whack_crash = true;
			opt_to_address(&host_family, &msg.whack_crash_peer);
			if (!address_is_specified(msg.whack_crash_peer)) {
				/* either :: or 0.0.0.0; unset rejected */
				address_buf ab;
				diagq("invalid --crash <address>",
				      str_address(&msg.whack_crash_peer, &ab));
			}
			continue;

		/* --deleteuser --name <xauthusername> */
		case OPT_DELETEUSER:
			msg.whack_deleteuser = true;
			continue;

		case OPT_REDIRECT_TO:	/* --redirect-to */
			/* either active, or or add */
			msg.redirect_to = strdup(optarg);
			continue;

		case OPT_GLOBAL_REDIRECT:	/* --global-redirect */
			if (streq(optarg, "yes")) {
				msg.global_redirect = GLOBAL_REDIRECT_YES;
			} else if (streq(optarg, "no")) {
				msg.global_redirect = GLOBAL_REDIRECT_NO;
			} else if (streq(optarg, "auto")) {
				msg.global_redirect = GLOBAL_REDIRECT_AUTO;
			} else {
				diagw("invalid option argument for --global-redirect (allowed arguments: yes, no, auto)");
			}
			continue;

		case OPT_GLOBAL_REDIRECT_TO:	/* --global-redirect-to */
			if (!strlen(optarg)) {
				msg.global_redirect_to = strdup("<none>");
			} else {
				msg.global_redirect_to = strdup(optarg);
			}
			continue;

		case OPT_DDOS_BUSY:	/* --ddos-busy */
			msg.whack_ddos = DDOS_FORCE_BUSY;
			continue;

		case OPT_DDOS_UNLIMITED:	/* --ddos-unlimited */
			msg.whack_ddos = DDOS_FORCE_UNLIMITED;
			continue;

		case OPT_DDOS_AUTO:	/* --ddos-auto */
			msg.whack_ddos = DDOS_AUTO;
			continue;

		case OPT_DDNS:	/* --ddns */
			msg.whack_ddns = true;
			continue;

		case OPT_LISTEN:	/* --listen */
			msg.whack_listen = true;
			continue;

		case OPT_UNLISTEN:	/* --unlisten */
			msg.whack_unlisten = true;
			continue;

		case OPT_REREADSECRETS:	/* --rereadsecrets */
			msg.whack_rereadsecrets = true;
			continue;
		case OPT_REREADCERTS:	/* --rereadcerts */
			msg.whack_rereadcerts = true;
			continue;
		case OPT_FETCHCRLS:	/* --fetchcrls */
			msg.whack_fetchcrls = true;
			continue;
		case OPT_REREADALL:	/* --rereadall */
			msg.whack_rereadsecrets = true;
			msg.whack_rereadcerts = true;
			msg.whack_fetchcrls = true;
			continue;
		case OPT_REREADCRLS:	/* --rereadcrls */
			fprintf(stderr, "whack warning: rereadcrls command obsoleted did you mean ipsec whack --fetchcrls\n");
			continue;

		case OPT_PURGEOCSP:	/* --purgeocsp */
			msg.whack_purgeocsp = true;
			continue;

		case OPT_STATUS:	/* --status */
			msg.whack_status = true;
			ignore_errors = true;
			continue;

		case OPT_GLOBALSTATUS:	/* --globalstatus */
			msg.whack_globalstatus = true;
			ignore_errors = true;
			continue;

		case OPT_CLEAR_STATS:	/* --clearstats */
			msg.whack_clear_stats = true;
			continue;

		case OPT_TRAFFICSTATUS:	/* --trafficstatus */
			msg.whack_trafficstatus = true;
			ignore_errors = true;
			continue;

		case OPT_SHUNTSTATUS:	/* --shuntstatus */
			msg.whack_shuntstatus = true;
			ignore_errors = true;
			continue;

		case OPT_ADDRESSPOOLSTATUS:	/* --addresspoolstatus */
			msg.whack_addresspoolstatus = true;
			ignore_errors = true;
			continue;

		case OPT_CONNECTIONSTATUS:	/* --connectionstatus */
			msg.whack_connectionstatus = true;
			ignore_errors = true;
			continue;

		case OPT_BRIEFCONNECTIONSTATUS:	/* --briefconnectionstatus */
			msg.whack_briefconnectionstatus = true;
			ignore_errors = true;
			continue;

		case OPT_FIPSSTATUS:	/* --fipsstatus */
			msg.whack_fipsstatus = true;
			ignore_errors = true;
			continue;

		case OPT_BRIEFSTATUS:	/* --briefstatus */
			msg.whack_briefstatus = true;
			ignore_errors = true;
			continue;

		case OPT_PROCESSSTATUS:	/* --processstatus */
			msg.whack_processstatus = true;
			ignore_errors = true;
			continue;

		case OPT_SHOW_STATES:	/* --showstates */
			msg.whack_showstates = true;
			ignore_errors = true;
			continue;
#ifdef USE_SECCOMP
		case OPT_SECCOMP_CRASHTEST:	/* --seccomp-crashtest */
			msg.whack_seccomp_crashtest = true;
			continue;
#endif

		case OPT_SHUTDOWN:	/* --shutdown */
			msg.whack_shutdown = true;
			continue;

		case OPT_LEAVE_STATE:	/* --leave-state */
			msg.whack_leave_state = true;
			continue;

		case OPT_OPPO_HERE:	/* --oppohere <ip-address> */
			opt_to_address(&child_family, &msg.oppo.local.address);
			if (!address_is_specified(msg.oppo.local.address)) {
				/* either :: or 0.0.0.0; unset rejected */
				address_buf ab;
				diagq("invalid --opphere <address>",
				      str_address(&msg.oppo.local.address, &ab));
			}
			continue;

		case OPT_OPPO_THERE:	/* --oppothere <ip-address> */
			opt_to_address(&child_family, &msg.oppo.remote.address);
			if (!address_is_specified(msg.oppo.remote.address)) {
				/* either :: or 0.0.0.0; unset rejected */
				address_buf ab;
				diagq("invalid --oppothere <address>",
				      str_address(&msg.oppo.remote.address, &ab));
			}
			continue;

		case OPT_OPPO_PROTO:	/* --oppoproto <protocol> */
			msg.oppo.ipproto = strtol(optarg, NULL, 0);
			continue;

		case OPT_OPPO_SPORT:	/* --opposport <port> */
			msg.oppo.local.port = ip_hport(strtol(optarg, NULL, 0));
			continue;

		case OPT_OPPO_DPORT:	/* --oppodport <port> */
			msg.oppo.remote.port = ip_hport(strtol(optarg, NULL, 0));
			continue;

		case OPT_ASYNC:	/* --asynchronous */
			msg.whack_async = true;
			continue;

		/* List options */

		case LST_UTC:	/* --utc */
			msg.whack_utc = true;
			continue;

		case LST_CERTS:	/* --listcerts */
		case LST_CACERTS:	/* --listcacerts */
		case LST_CRLS:	/* --listcrls */
		case LST_PSKS:	/* --listpsks */
		case LST_EVENTS:	/* --listevents */
			msg.whack_list |= LELEM(c - LST_PUBKEYS);
			ignore_errors = true;
			continue;

		case LST_PUBKEYS:	/* --listpubkeys */
			msg.whack_listpubkeys = true;
			ignore_errors = true;
			continue;

		case LST_CHECKPUBKEYS:	/* --checkpubkeys */
			msg.whack_checkpubkeys = true;
			ignore_errors = true;
			continue;

		case LST_ALL:	/* --listall */
			msg.whack_list = LIST_ALL;
			msg.whack_listpubkeys = true;
			ignore_errors = true;
			continue;

		/* Connection Description options */

		case END_HOST:	/* --host <ip-address> */
		{
			if (streq(optarg, "%any")) {
				end->host_addr = get_address_any(&host_family);
				end->host_type = KH_ANY;
			} else if (streq(optarg, "%opportunistic")) {
				/* always use tunnel mode; mark as opportunistic */
				msg.type = KS_TUNNEL;
				end->host_type = KH_OPPO;
				end->host_addr = get_address_any(&host_family);
				end->key_from_DNS_on_demand = true;
			} else if (streq(optarg, "%group")) {
				/* always use tunnel mode; mark as group */
				msg.type = KS_TUNNEL;
				end->host_type = KH_GROUP;
				end->host_addr = get_address_any(&host_family);
			} else if (streq(optarg, "%opportunisticgroup")) {
				/* always use tunnel mode; mark as opportunistic */
				msg.type = KS_TUNNEL;
				end->host_type = KH_OPPOGROUP;
				end->host_addr = get_address_any(&host_family);
				end->key_from_DNS_on_demand = true;
			} else if (msg.left.id != NULL && !streq(optarg, "%null")) {
				if (opt_ttoaddress_num(&host_family, &end->host_addr) == NULL) {
					/*
					 * we have a proper numeric IP
					 * address.
					 */
				} else {
					/*
					 * We assume that we have a DNS name.
					 * This logic matches confread.c.
					 * ??? it would be kind to check
					 * the syntax.
					 */
					msg.dnshostname = optarg;
					opt_ttoaddress_dns(&host_family, &end->host_addr);
					/*
					 * we don't fail here.  pluto
					 * will re-check the DNS later
					 */
				}
			} else {
				opt_to_address(&host_family, &end->host_addr);
			}

			if (end->host_type == KH_GROUP ||
			    end->host_type == KH_OPPOGROUP) {
				/*
				 * client subnet must not be specified
				 * by user: it will come from the
				 * group's file.
				 *
				 * Hence, for --host, pretend --subnet
				 * has also been seen.
				 */
				if (seen[END_SUBNET])
					diagw("--host %group clashes with --client");
				seen[END_SUBNET] = true;
			}
			continue;
		}

		case END_ID:	/* --id <identity> */
			end->id = optarg;	/* decoded by Pluto */
			continue;

		case END_SENDCERT:	/* --sendcert */
			if (streq(optarg, "yes") || streq(optarg, "always")) {
				end->sendcert = CERT_ALWAYSSEND;
			} else if (streq(optarg,
					 "no") || streq(optarg, "never")) {
				end->sendcert = CERT_NEVERSEND;
			} else if (streq(optarg, "ifasked")) {
				end->sendcert = CERT_SENDIFASKED;
			} else {
				diagq("whack sendcert value is not legal",
				      optarg);
				continue;
			}
			continue;

		case END_CERT:	/* --cert <path> */
			if (end->ckaid != NULL)
				diagw("only one --cert <nickname> or --ckaid <ckaid> allowed");
			end->cert = optarg;	/* decoded by Pluto */
			continue;

		case END_CKAID:	/* --ckaid <ckaid> */
			if (end->cert != NULL)
				diagw("only one --cert <nickname> or --ckaid <ckaid> allowed");
			/* try parsing it; the error isn't the most specific */
			const char *ugh = ttodata(optarg, 0, 16, NULL, 0, NULL);
			diagq(ugh, optarg);
			end->ckaid = optarg;	/* decoded by Pluto */
			continue;

		case END_CA:	/* --ca <distinguished name> */
			end->ca = optarg;	/* decoded by Pluto */
			continue;

		case END_GROUPS:	/* --groups <access control groups> */
			end->groups = optarg;	/* decoded by Pluto */
			continue;

		case END_IKEPORT:	/* --ikeport <port-number> */
		{
			uintmax_t opt_whole = optarg_uintmax();
			if (opt_whole <= 0 || opt_whole >= 0x10000) {
				diagq("<port-number> must be a number between 1 and 65535",
					optarg);
			}
			end->host_ikeport = opt_whole;
			continue;
		}

		case END_NEXTHOP:	/* --nexthop <ip-address> */
			if (streq(optarg, "%direct")) {
				end->host_nexthop = get_address_any(&host_family);
			} else {
				opt_to_address(&host_family, &end->host_nexthop);
			}
			continue;

		case END_SOURCEIP:	/* --sourceip <ip-address> */
			if (end->ifaceip.is_set == false) {
				diagw("only one --interfaceip <ip-address/mask> or --sourceip <ip-address> allowed");
			}
			end->sourceip = optarg;
			continue;

		case END_INTERFACEIP:	/* --interface-ip <ip-address/mask> */
			if (end->sourceip != NULL) {
				diagw("only one --sourceip <ip-address> or --interfaceip <ip-address/mask> allowed");
			}
			opt_to_cidr(&child_family, &end->ifaceip);
			continue;

		case END_VTIIP:	/* --vtiip <ip-address/mask> */
			opt_to_cidr(&child_family, &end->host_vtiip);
			continue;

		/*
		 * --authby secret | rsasig | rsa | ecdsa | null | eaponly
		 *  Note: auth-never cannot be asymmetrical
		 */
		case END_AUTHBY:
			if (streq(optarg, "psk"))
				end->auth = AUTH_PSK;
			else if (streq(optarg, "null"))
				end->auth = AUTH_NULL;
			else if (streq(optarg, "rsasig") || streq(optarg, "rsa"))
				end->auth = AUTH_RSASIG;
			else if (streq(optarg, "ecdsa"))
				end->auth = AUTH_ECDSA;
			else if (streq(optarg, "eaponly"))
				end->auth = AUTH_EAPONLY;
			else
				diagw("authby option is not one of psk, ecdsa, rsasig, rsa, null or eaponly");
			continue;

		case END_AUTHEAP:
			if (streq(optarg, "tls"))
				end->eap = IKE_EAP_TLS;
			else if (streq(optarg, "none"))
				end->eap = IKE_EAP_NONE;
			else diagw("--autheap option is not one of none, tls");
			continue;

		case END_SUBNET: /* --subnet <subnet> | --client <subnet> */
			if (startswith(optarg, "vhost:") ||
			    startswith(optarg, "vnet:")) {
				end->virt = optarg;
			} else {
				end->subnet = optarg;	/* decoded by Pluto */
			}
			msg.type = KS_TUNNEL;	/* client => tunnel */
			continue;

		/* --clientprotoport <protocol>/<port> */
		case END_CLIENTPROTOPORT:
			diagq(ttoprotoport(optarg, &end->protoport),
				optarg);
			continue;

		case END_DNSKEYONDEMAND:	/* --dnskeyondemand */
			end->key_from_DNS_on_demand = true;
			continue;

		case END_UPDOWN:	/* --updown <updown> */
			end->updown = optarg;
			continue;

		case CD_TO:	/* --to */
			/*
			 * Move .right to .left, so further END
			 * options.  Reset what was seen so more
			 * options can be added.
			 */
			if (!seen[END_HOST]) {
				diagw("connection missing --host before --to");
			}

			end = &msg.right;
			for (enum option_enums e = FIRST_END_OPT; e <= LAST_END_OPT; e++) {
				seen[e] = false;
			}
			continue;

		/* --ikev1 --ikev2 --ikev2-propose */
		case CD_IKEv1:
		case CD_IKEv2:
		{
			const enum ike_version ike_version = IKEv1 + c - CD_IKEv1;
			if (msg.ike_version != 0 && msg.ike_version != ike_version) {
				diagw("connection can no longer have --ikev1 and --ikev2");
			}
			msg.ike_version = ike_version;
			continue;
		}

		/* --allow-narrowing */
		case CD_IKEV2_ALLOW_NARROWING:
			msg.ikev2_allow_narrowing = YN_YES;
			continue;

		/* --donotrekey */
		case CD_DONT_REKEY:
			msg.rekey = YN_NO;
			continue;

		/* --rekey */
		case CD_REAUTH:
			msg.reauth = YN_YES;
			continue;

		case CD_COMPRESS:	/* --compress */
			msg.compress = optarg_sparse(YN_YES, yn_option_names);
			continue;

		case CD_TUNNEL:		/* --tunnel */
			msg.type = KS_TUNNEL;
			continue;

		case CD_TRANSPORT:	/* --transport */
			msg.type = KS_TRANSPORT;
			continue;

		case CD_ENCRYPT:	/* --encrypt */
			msg.phase2 = ENCAP_PROTO_ESP;
			continue;

		case CD_AUTHENTICATE:	/* --authenticate */
			msg.phase2 = ENCAP_PROTO_AH;
			continue;

		/* --no-esn */
		case CD_NO_ESN:
			msg.esn = (msg.esn == YNE_EITHER ? YNE_EITHER :
				   msg.esn == YNE_YES ? YNE_EITHER : YNE_NO);
			continue;
		/* --esn */
		case CD_ESN:
			msg.esn = optarg_sparse((msg.esn == YNE_EITHER ? YNE_EITHER :
						 msg.esn == YNE_NO ? YNE_EITHER : YNE_YES),
						yne_option_names);
			continue;

		/* --ikefrag-allow */
		case CD_IKEFRAG_ALLOW: /* obsolete name */
			if (msg.fragmentation == YNF_UNSET) {
				msg.fragmentation = YNF_YES;
			} else {
				passert(msg.fragmentation == YNF_YES ||
					msg.fragmentation == YNF_FORCE);
			}
			continue;
		/* --ikefrag-force */
		case CD_IKEFRAG_FORCE: /* obsolete name */
			msg.fragmentation = YNF_FORCE;
			continue;

		case CD_FRAGMENTATION: /* --fragmentation {yes,no,force} */
			msg.fragmentation = optarg_sparse(YNF_YES, ynf_option_names);
			continue;

		/* --nopmtudisc */
		case CD_NOPMTUDISC:
			msg.nopmtudisc = optarg_sparse(YN_YES, yn_option_names);
			continue;

		/* --decap-dscp */
		case CD_DECAP_DSCP:
			msg.decap_dscp = optarg_sparse(YN_YES, yn_option_names);
			continue;

		/* --encap-dscp */
		case CD_ENCAP_DSCP:
			msg.encap_dscp = optarg_sparse(YN_YES, yn_option_names);
			continue;

		/* --aggressive | --aggrmode */
		case CD_AGGRESSIVE:
			msg.aggressive = optarg_sparse(YN_YES, yn_option_names);
			continue;

		/* --modecfgpull */
		case CD_MODECFGPULL:
			msg.modecfgpull = YN_YES;
			continue;

		/* --allow-cert-without-san-id */
		case CD_ALLOW_CERT_WITHOUT_SAN_ID:
			msg.require_id_on_certificate = YN_NO;
			continue;

		/* --no-ikepad */
		case CD_IKEPAD:
			msg.ikepad = optarg_sparse(YN_YES, yn_option_names);
			continue;

		/* --ignore-peer-dns */
		case CD_IGNORE_PEER_DNS:
			msg.ignore_peer_dns = optarg_sparse(YN_YES, yn_option_names);
			continue;

		/* --dns-match-id */
		case CD_DNS_MATCH_ID:
			msg.dns_match_id = optarg_sparse(YN_YES, yn_option_names);
			continue;

		/* --ms-dh-downgrade */
		case CD_MS_DH_DOWNGRADE:
			msg.ms_dh_downgrade = optarg_sparse(YN_YES, yn_option_names);
			continue;

		case CD_PFS_REKEY_WORKAROUND:	/* --pfs-rekey-workaround[=yes] */
			msg.pfs_rekey_workaround = optarg_sparse(YN_YES, yn_option_names);
			continue;

		/* --overlapip */
		case CD_OVERLAPIP:
			msg.overlapip = optarg_sparse(YN_YES, yn_option_names);
			continue;

		/* --sha2-truncbug or --sha2_truncbug */
		case CD_SHA2_TRUNCBUG:
			msg.sha2_truncbug = optarg_sparse(YN_YES, yn_option_names);
			continue;

		case CD_INTERMEDIATE:		/* --intermediate[=yes] */
			msg.intermediate = optarg_sparse(YN_YES, yn_option_names);
			continue;

		/* --mobike */
		case CD_MOBIKE:
			msg.mobike = optarg_sparse(YN_YES, yn_option_names);
			continue;

		case CD_INITIATEONTRAFFIC:		/* --initiateontraffic */
			fprintf(stderr, "whack warning: --initiateontraffic is obsolete, did you mean --ondemand");
			continue;

		case CDS_NEVER_NEGOTIATE + SHUNT_PASS:	/* --pass */
		case CDS_NEVER_NEGOTIATE + SHUNT_DROP:	/* --drop */
		case CDS_NEVER_NEGOTIATE + SHUNT_REJECT:	/* --reject */
			msg.never_negotiate_shunt = c - CDS_NEVER_NEGOTIATE;
			continue;

		case CDS_NEGOTIATION + SHUNT_PASS:	/* --negopass */
			msg.negotiation_shunt = c - CDS_NEGOTIATION;
			continue;

		case CDS_FAILURE + SHUNT_NONE:		/* --failnone */
		case CDS_FAILURE + SHUNT_PASS:		/* --failpass */
		case CDS_FAILURE + SHUNT_DROP:		/* --faildrop */
		case CDS_FAILURE + SHUNT_REJECT:	/* --failreject */
			msg.failure_shunt = c - CDS_FAILURE;
			continue;

		case CD_RETRANSMIT_TIMEOUT:	/* --retransmit-timeout <seconds> */
			msg.retransmit_timeout = optarg_deltatime(&timescale_seconds);
			continue;

		case CD_RETRANSMIT_INTERVAL:	/* --retransmit-interval <milliseconds> (not seconds) */
			msg.retransmit_interval = optarg_deltatime(&timescale_milliseconds);
			continue;

		case CD_IKE_LIFETIME:	/* --ike-lifetime <seconds> */
			msg.ikelifetime = optarg_deltatime(&timescale_seconds);
			continue;

		case CD_IPSEC_LIFETIME:	/* --ipsec-lifetime <seconds> */
			msg.ipsec_lifetime = optarg_deltatime(&timescale_seconds);
			continue;

		case CD_IPSEC_MAX_BYTES:	/* --ipsec-max-bytes <bytes> */
			msg.sa_ipsec_max_bytes = optarg_uintmax(); /* TODO accept K/M/G/T etc */
			continue;

		case CD_IPSEC_MAX_PACKETS:	/* --ipsec-max-packets <packets> */
			msg.sa_ipsec_max_packets = optarg_uintmax(); /* TODO accept K/M/G/T etc */
			continue;

		case CD_REKEYMARGIN:	/* --rekeymargin <seconds> */
			msg.sa_rekey_margin = optarg_deltatime(&timescale_seconds);
			continue;

		case CD_RKFUZZ:	/* --rekeyfuzz <percentage> */
			msg.sa_rekeyfuzz_percent = optarg_uintmax();
			continue;

		case CD_KTRIES:	/* --keyingtries <count> */
			msg.keyingtries.set = true;
			msg.keyingtries.value = optarg_uintmax();
			continue;

		case CD_REPLAY_WINDOW: /* --replay-window <num> */
			/*
			 * Upper bound is determined by the kernel.
			 * Pluto will check against this when
			 * processing the message.  The value is
			 * relatively small.
			 */
			msg.replay_window = optarg_uintmax();
			continue;

		case CD_SEND_CA:	/* --sendca */
			if (streq(optarg, "issuer"))
				msg.send_ca = CA_SEND_ISSUER;
			else if (streq(optarg, "all"))
				msg.send_ca = CA_SEND_ALL;
			else
				msg.send_ca = CA_SEND_NONE;
			continue;

		case CD_ENCAPSULATION:	/* --encapsulation */
			msg.encapsulation = optarg_sparse(YNA_YES, yna_option_names);
			continue;

		case CD_NIC_OFFLOAD:  /* --nic-offload */
			msg.nic_offload = optarg_sparse(0, nic_offload_option_names);
			continue;

		case CD_NO_NAT_KEEPALIVE:	/* --no-nat_keepalive */
			msg.nat_keepalive = false;
			continue;

		case CD_IKEV1_NATT:	/* --ikev1-natt */
			msg.nat_ikev1_method = optarg_sparse(0, nat_ikev1_method_option_names);
			continue;

		case CD_INITIAL_CONTACT:	/* --initialcontact */
			msg.initial_contact = true;
			continue;

		case CD_CISCO_UNITY:	/* --cisco-unity */
			msg.cisco_unity = true;
			continue;

		case CD_FAKE_STRONGSWAN:	/* --fake-strongswan */
			msg.fake_strongswan = true;
			continue;

		case CD_DPDDELAY:	/* --dpddelay <seconds> */
			msg.dpd_delay = strdup(optarg);
			continue;

		case CD_DPDTIMEOUT:	/* --dpdtimeout <seconds> */
			msg.dpd_timeout = strdup(optarg);
			continue;

		case CD_DPDACTION:	/* --dpdaction */
			if (streq(optarg, "clear")) {
				msg.dpd_action = DPD_ACTION_CLEAR;
			} else if (streq(optarg, "hold")) {
				msg.dpd_action = DPD_ACTION_HOLD;
			} else if (streq(optarg, "restart")) {
				msg.dpd_action = DPD_ACTION_RESTART;
			} else if (streq(optarg, "restart_by_peer")) {
				/*
				 * obsolete (not advertised) option for
				 * compatibility
				 */
				msg.dpd_action = DPD_ACTION_RESTART;
			} else {
				diagw("dpdaction can only be \"clear\", \"hold\" or \"restart\"");
			}
			continue;

		case CD_SEND_REDIRECT:	/* --send-redirect */
			msg.send_redirect = optarg_sparse(0, yna_option_names);
			continue;

		case CD_ACCEPT_REDIRECT:	/* --accept-redirect */
			msg.accept_redirect = optarg_sparse(0, yn_option_names);
			continue;

		case CD_ACCEPT_REDIRECT_TO:	/* --accept-redirect-to */
			msg.accept_redirect_to = strdup(optarg);
			continue;

		case CD_IKE:	/* --ike <ike_alg1,ike_alg2,...> */
			msg.ike = optarg;
			continue;

		case CD_PFSGROUP:	/* --pfsgroup modpXXXX */
			msg.pfsgroup = optarg;
			continue;

		case CD_ESP:	/* --esp <esp_alg1,esp_alg2,...> */
			msg.esp = optarg;
			continue;

		case CD_REMOTE_PEER_TYPE:	/* --remote-peer-type <cisco> */
			if (streq(optarg, "cisco")) {
				msg.remote_peer_type = REMOTE_PEER_CISCO;
			} else {
				diagw("--remote-peer-type options are 'cisco'");
			}
			continue;

#ifdef HAVE_NM
		case CD_NM_CONFIGURED:		/* --nm-configured */
			msg.nm_configured = optarg_sparse(YN_YES, yn_option_names);
			continue;
#endif

		case CD_IKE_TCP: /* --tcp */
			if (streq(optarg, "yes"))
				msg.enable_tcp = IKE_TCP_ONLY;
			else if (streq(optarg, "no"))
				msg.enable_tcp = IKE_TCP_NO;
			else if (streq(optarg, "fallback"))
				msg.enable_tcp = IKE_TCP_FALLBACK;
			else
				diagw("--tcp-options are 'yes', 'no' or 'fallback'");
			continue;

		case CD_LABELED_IPSEC:	/* obsolete --labeledipsec */
			/* ignore */
			continue;

		case CD_SEC_LABEL:	/* --sec-label */
			/* we only support symmetric labels but put it in struct end */
			msg.sec_label = optarg;
			continue;


		/* RSASIG/ECDSA need more than a single policy bit */
		case OPT_AUTHBY_PSK:		/* --psk */
			msg.authby.psk = true;
			continue;
		case OPT_AUTHBY_AUTH_NEVER:	/* --auth-never */
			msg.authby.never = true;
			continue;
		case OPT_AUTHBY_AUTH_NULL:	/* --auth-null */
			msg.authby.null = true;
			continue;
		case OPT_AUTHBY_RSASIG: /* --rsasig */
			msg.authby.rsasig = true;
			msg.authby.rsasig_v1_5 = true;
			msg.sighash_policy |= POL_SIGHASH_SHA2_256;
			msg.sighash_policy |= POL_SIGHASH_SHA2_384;
			msg.sighash_policy |= POL_SIGHASH_SHA2_512;
			continue;
		case OPT_AUTHBY_RSA_SHA1: /* --rsa-sha1 */
			msg.authby.rsasig_v1_5 = true;
			continue;
		case OPT_AUTHBY_RSA_SHA2: /* --rsa-sha2 */
			msg.authby.rsasig = true;
			msg.sighash_policy |= POL_SIGHASH_SHA2_256;
			msg.sighash_policy |= POL_SIGHASH_SHA2_384;
			msg.sighash_policy |= POL_SIGHASH_SHA2_512;
			continue;
		case OPT_AUTHBY_RSA_SHA2_256:	/* --rsa-sha2_256 */
			msg.authby.rsasig = true;
			msg.sighash_policy |= POL_SIGHASH_SHA2_256;
			continue;
		case OPT_AUTHBY_RSA_SHA2_384:	/* --rsa-sha2_384 */
			msg.authby.rsasig = true;
			msg.sighash_policy |= POL_SIGHASH_SHA2_384;
			continue;
		case OPT_AUTHBY_RSA_SHA2_512:	/* --rsa-sha2_512 */
			msg.authby.rsasig = true;
			msg.sighash_policy |= POL_SIGHASH_SHA2_512;
			continue;

		case OPT_AUTHBY_ECDSA: /* --ecdsa and --ecdsa-sha2 */
			msg.authby.ecdsa = true;
			msg.sighash_policy |= POL_SIGHASH_SHA2_256;
			msg.sighash_policy |= POL_SIGHASH_SHA2_384;
			msg.sighash_policy |= POL_SIGHASH_SHA2_512;
			continue;
		case OPT_AUTHBY_ECDSA_SHA2_256:	/* --ecdsa-sha2_256 */
			msg.authby.ecdsa = true;
			msg.sighash_policy |= POL_SIGHASH_SHA2_256;
			continue;
		case OPT_AUTHBY_ECDSA_SHA2_384:	/* --ecdsa-sha2_384 */
			msg.authby.ecdsa = true;
			msg.sighash_policy |= POL_SIGHASH_SHA2_384;
			continue;
		case OPT_AUTHBY_ECDSA_SHA2_512:	/* --ecdsa-sha2_512 */
			msg.authby.ecdsa = true;
			msg.sighash_policy |= POL_SIGHASH_SHA2_512;
			continue;

		case CD_CONNIPV4:	/* --ipv4; mimic --ipv6 */
			if (host_family.type == &ipv4_info) {
				/* ignore redundant options */
				continue;
			}

			if (seen[CD_CONNIPV6]) {
				/* i.e., --ipv6 ... --ipv4 */
				diagw("--ipv4 conflicts with --ipv6");
			}

			if (host_family.used_by != NULL) {
				/* i.e., --host ::1 --ipv4; useful? wrong message? */
				diagq("--ipv4 must precede", host_family.used_by);
			}
			host_family.used_by = long_opts[long_index].name;
			host_family.type = &ipv4_info;
			continue;

		case CD_CONNIPV6:	/* --ipv6; mimic ipv4 */
			if (host_family.type == &ipv6_info) {
				/* ignore redundant options */
				continue;
			}

			if (seen[CD_CONNIPV4]) {
				/* i.e., --ipv4 ... --ipv6 */
				diagw("--ipv6 conflicts with --ipv4");
			}

			if (host_family.used_by != NULL) {
				/* i.e., --host 0.0.0.1 --ipv6; useful? wrong message? */
				diagq("--ipv6 must precede", host_family.used_by);
			}
			host_family.used_by = long_opts[long_index].name;
			host_family.type = &ipv6_info;
			continue;

		case CD_TUNNELIPV4:	/* --tunnelipv4 */
			if (seen[CD_TUNNELIPV6]) {
				diagw("--tunnelipv4 conflicts with --tunnelipv6");
			}
			if (child_family.used_by != NULL)
				diagq("--tunnelipv4 must precede", child_family.used_by);
			child_family.used_by = long_opts[long_index].name;
			child_family.type = &ipv4_info;
			continue;

		case CD_TUNNELIPV6:	/* --tunnelipv6 */
			if (seen[CD_TUNNELIPV4]) {
				diagw("--tunnelipv6 conflicts with --tunnelipv4");
			}
			if (child_family.used_by != NULL)
				diagq("--tunnelipv6 must precede", child_family.used_by);
			child_family.used_by = long_opts[long_index].name;
			child_family.type = &ipv6_info;
			continue;

		case END_XAUTHSERVER:	/* --xauthserver */
			end->xauth_server = true;
			continue;

		case END_XAUTHCLIENT:	/* --xauthclient */
			end->xauth_client = true;
			continue;

		case OPT_USERNAME:	/* --username, was --xauthname */
			/*
			 * we can't tell if this is going to be --initiate, or
			 * if this is going to be an conn definition, so do
			 * both actions
			 */
			end->xauth_username = optarg;
			gotusername = true;
			/* ??? why does this length include NUL? */
			usernamelen = jam_str(xauthusername, sizeof(xauthusername),
					optarg) -
				xauthusername + 1;
			continue;

		case OPT_XAUTHPASS:	/* --xauthpass */
			gotxauthpass = true;
			/* ??? why does this length include NUL? */
			xauthpasslen = jam_str(xauthpass, sizeof(xauthpass),
					optarg) -
				xauthpass + 1;
			continue;

		case END_MODECFGCLIENT:	/* --modeconfigclient */
			end->modecfg_client = true;
			continue;

		case END_MODECFGSERVER:	/* --modeconfigserver */
			end->modecfg_server = true;
			continue;

		case END_ADDRESSPOOL:	/* --addresspool */
			end->addresspool = strdup(optarg);
			continue;

		case CD_MODECFGDNS:	/* --modecfgdns */
			msg.modecfg_dns = strdup(optarg);
			continue;
		case CD_MODECFGDOMAINS:	/* --modecfgdomains */
			msg.modecfg_domains = strdup(optarg);
			continue;
		case CD_MODECFGBANNER:	/* --modecfgbanner */
			msg.modecfg_banner = strdup(optarg);
			continue;

		case CD_CONN_MARK_BOTH:      /* --conn-mark */
			msg.conn_mark_both = strdup(optarg);
			continue;
		case CD_CONN_MARK_IN:      /* --conn-mark-in */
			msg.conn_mark_in = strdup(optarg);
			continue;
		case CD_CONN_MARK_OUT:      /* --conn-mark-out */
			msg.conn_mark_out = strdup(optarg);
			continue;

		case CD_VTI_INTERFACE:      /* --vti-interface=IFACE */
			msg.vti_interface = strdup(optarg);
			continue;
		case CD_VTI_ROUTING:	/* --vti-routing[=yes|no] */
			msg.vti_routing = optarg_sparse(YN_YES, yn_option_names);
			continue;
		case CD_VTI_SHARED:	/* --vti-shared[=yes|no] */
			msg.vti_shared = optarg_sparse(YN_YES, yn_option_names);
			continue;

		case CD_IPSEC_INTERFACE:      /* --ipsec-interface=... */
			msg.ipsec_interface = strdup(optarg);
			continue;

		case CD_XAUTHBY:	/* --xauthby */
			if (streq(optarg, "file")) {
				msg.xauthby = XAUTHBY_FILE;
				continue;
#ifdef AUTH_HAVE_PAM
			} else if (streq(optarg, "pam")) {
				msg.xauthby = XAUTHBY_PAM;
				continue;
#endif
			} else if (streq(optarg, "alwaysok")) {
				msg.xauthby = XAUTHBY_ALWAYSOK;
				continue;
			} else {
				diagq("whack: unknown xauthby method", optarg);
			}
			continue;

		case CD_XAUTHFAIL:	/* --xauthfail */
			if (streq(optarg, "hard")) {
				msg.xauthfail = XAUTHFAIL_HARD;
				continue;
			} else if (streq(optarg, "soft")) {
				msg.xauthfail = XAUTHFAIL_SOFT;
				continue;
			} else {
				fprintf(stderr,
					"whack: unknown xauthfail method '%s' ignored\n",
					optarg);
			}
			continue;

		case CD_METRIC:	/* --metric */
			msg.metric = optarg_uintmax();
			continue;

		case CD_MTU:	/* --mtu */
			msg.mtu = optarg_uintmax();
			continue;

		case CD_PRIORITY:	/* --priority */
			msg.priority = optarg_uintmax();
			continue;

		case CD_TFC:	/* --tfc */
			msg.tfc = optarg_uintmax();
			continue;

		case CD_SEND_TFCPAD:	/* --send-no-esp-tfc */
			msg.send_no_esp_tfc = true;
			continue;

		case CD_PFS:	/* --pfs */
			msg.pfs = optarg_sparse(YN_YES, yn_option_names);
			continue;

		case CD_NFLOG_GROUP:	/* --nflog-group */
		{
			uintmax_t opt_whole = optarg_uintmax();
			if (opt_whole <= 0  ||
			    opt_whole > 65535) {
				char buf[120];

				snprintf(buf, sizeof(buf),
					"invalid nflog-group value - range must be 1-65535 \"%s\"",
					optarg);
				diagw(buf);
			}
			msg.nflog_group = opt_whole;
			continue;
		}

		case CD_REQID:	/* --reqid */
		{
			uintmax_t opt_whole = optarg_uintmax();
			if (opt_whole <= 0  ||
			    opt_whole > IPSEC_MANUAL_REQID_MAX) {
				char buf[120];

				snprintf(buf, sizeof(buf),
					"invalid reqid value - range must be 1-%u \"%s\"",
					IPSEC_MANUAL_REQID_MAX,
					optarg);
				diagw(buf);
			}

			msg.sa_reqid = opt_whole;
			continue;
		}

		case DBGOPT_NONE:	/* --debug-none (obsolete) */
			/*
			 * Clear all debug and impair options.
			 *
			 * This preserves existing behaviour where
			 * sequences like:
			 *
			 *     --debug-none
			 *     --debug-none --debug something
			 *
			 * force all debug/impair options to values
			 * defined by whack.
			 */
			msg.debugging = lmod_clr(msg.debugging, DBG_MASK);
			continue;

		case DBGOPT_ALL:	/* --debug-all (obsolete) */
			/*
			 * Set most debug options ('all' does not
			 * include PRIVATE which is cleared) and clear
			 * all impair options.
			 *
			 * This preserves existing behaviour where
			 * sequences like:
			 *
			 *     --debug-all
			 *     --debug-all --impair something
			 *
			 * force all debug/impair options to values
			 * defined by whack.
			 */
			msg.debugging = lmod_clr(msg.debugging, DBG_MASK);
			msg.debugging = lmod_set(msg.debugging, DBG_ALL);
			continue;

		case DBGOPT_DEBUG:	/* --debug */
		case DBGOPT_NO_DEBUG:	/* --no-debug */
		{
			bool enable = (c == DBGOPT_DEBUG);
			if (streq(optarg, "list") || streq(optarg, "help") || streq(optarg, "?")) {
				fprintf(stderr, "aliases:\n");
				for (struct lmod_alias *a = debug_lmod_info.aliases;
				     a->name != NULL; a++) {
					JAMBUF(buf) {
						jam(buf, "  %s: ", a->name);
						jam_lset_short(buf, debug_lmod_info.names, "+", a->bits);
						fprintf(stderr, PRI_SHUNK"\n",
							pri_shunk(jambuf_as_shunk(buf)));
					}
				}
				fprintf(stderr, "bits:\n");
				for (long e = next_enum(&debug_names, -1);
				     e != -1; e = next_enum(&debug_names, e)) {
					JAMBUF(buf) {
						jam(buf, "  ");
						jam_enum_short(buf, &debug_names, e);
						const char *help = enum_name(&debug_help, e);
						if (help != NULL) {
							jam(buf, ": ");
							jam_string(buf, help);
						}
						fprintf(stderr, PRI_SHUNK"\n",
							pri_shunk(jambuf_as_shunk(buf)));
					}
				}
				exit(1);
			} else if (!lmod_arg(&msg.debugging, &debug_lmod_info, optarg, enable)) {
				fprintf(stderr, "whack: unrecognized -%s-debug '%s' option ignored\n",
					enable ? "" : "-no", optarg);
			}
			continue;
		}

		case DBGOPT_IMPAIR:	/* --impair */
		case DBGOPT_NO_IMPAIR:	/* --no-impair */
		{
			bool enable = (c == DBGOPT_IMPAIR);
			unsigned old_len = msg.impairments.len++;
			realloc_things(msg.impairments.list,
				       old_len, msg.impairments.len, "impairments");
			switch (parse_impair(optarg, &msg.impairments.list[old_len],
					     enable, logger)) {
			case IMPAIR_OK:
				break;
			case IMPAIR_HELP:
				/* parse_impair() printed help */
				exit(0);
			case IMPAIR_ERROR:
				/* parse_impair() printed the error */
				exit(1);
			}
			continue;
		}
		}

		/*
		 * Since cases in above switch "continue" the loop;
		 * reaching here is BAD.
		 */
		bad_case(c);
	}

	if (msg.ike_version == 0) {
		/* no ike version specified, default to IKEv2 */
		msg.ike_version = IKEv2;
	}

	switch (msg.ike_version) {
	case IKEv1:
		if (msg.authby.ecdsa) {
			diagw("connection cannot specify --ecdsa and --ikev1");
		}
		/* delete any inherited sighash_poliyc from --rsasig including sha2 */
		msg.sighash_policy = LEMPTY;
		break;
	case IKEv2:
		break;
	}

	msg.child_afi = child_family.type;
	msg.host_afi = host_family.type;

	if (!authby_is_set(msg.authby)) {
		/*
		 * Since any option potentially setting SIGHASH bits
		 * always sets AUTHBY, check that.
		 *
		 * Mimic addconn's behaviour: specifying auth= (yes,
		 * whack calls it --authby) does not clear the
		 * policy_authby defaults.  That is left to pluto.
		 */
		msg.sighash_policy |= POL_SIGHASH_DEFAULTS;
	}

	if (optind != argc) {
		/*
		 * If you see this message unexpectedly, perhaps the
		 * case for the previous option ended with "break"
		 * instead of "continue"
		 */
		diagq("unexpected argument", argv[optind]);
	}

	/*
	 * For each possible form of the command, figure out if an argument
	 * suggests whether that form was intended, and if so, whether all
	 * required information was supplied.
	 */

	/* check opportunistic initiation simulation request */
	if (seen[OPT_OPPO_HERE] && seen[OPT_OPPO_THERE]) {
		msg.whack_oppo_initiate = true;
		/*
		 * When the only CD (connection description) option is
		 * TUNNELIPV[46] scrub that a connection description
		 * option was seen.
		 *
		 * The END options are easy to exclude, the generic
		 * conn options requires a brute force search.
		 */
		if ((opts_seen & CONN_OPT_SEEN) && !(opts_seen & END_OPT_SEEN)) {
			bool scrub = false;
			for (enum option_enums e = FIRST_CONN_OPT; e <= LAST_CONN_OPT; e++) {
				if (e != CD_TUNNELIPV4 &&
				    e != CD_TUNNELIPV6 &&
				    seen[e]) {
					scrub = false;
					break;
				}
			}
			if (scrub) {
				pexpect(opts_seen & CONN_OPT_SEEN);
				opts_seen &= ~CONN_OPT_SEEN;
			}
		}
	} else if (seen[OPT_OPPO_HERE] || seen[OPT_OPPO_THERE]) {
		diagw("--oppohere and --oppothere must be used together");
	}

	/* check connection description */
	if (opts_seen & CONN_OPT_SEEN) {
		if (!seen[CD_TO]) {
			diagw("connection description option, but no --to");
		}

		if (!seen[END_HOST]) {
			/* must be after --to as --to scrubs seen[END_*] */
			diagw("connection missing --host after --to");
		}

		if (msg.authby.never) {
			if (msg.never_negotiate_shunt == SHUNT_UNSET) {
				diagw("shunt connection must have shunt policy (eg --pass, --drop or --reject). Is this a non-shunt connection missing an authentication method such as --psk or --rsasig or --auth-null ?");
			}
		} else {
			/* not just a shunt: a real ipsec connection */
			if (!authby_is_set(msg.authby) &&
			    msg.left.auth == AUTH_NEVER &&
			    msg.right.auth == AUTH_NEVER)
				diagw("must specify connection authentication, eg --rsasig, --psk or --auth-null for non-shunt connection");
			/*
			 * ??? this test can never fail:
			 *	!NEVER_NEGOTIATE=>HAS_IPSEC_POLICY
			 * These interlocking tests should be redone.
			 */
			if (msg.never_negotiate_shunt != SHUNT_UNSET &&
			    (msg.left.subnet != NULL || msg.right.subnet != NULL))
				diagw("must not specify clients for ISAKMP-only connection");
		}

		msg.whack_add = true;
	}

	/*
	 * Decide whether --name is mandatory, optional, or forbidden.
	 */
	if (seen[OPT_ROUTE] ||
	    seen[OPT_UNROUTE] ||
	    seen[OPT_INITIATE] ||
	    seen[OPT_DOWN] ||
	    seen[OPT_DELETE] ||
	    seen[OPT_DELETEID] ||
	    seen[OPT_DELETEUSER] ||
	    seen[OPT_REKEY_IKE] ||
	    seen[OPT_REKEY_CHILD] ||
	    seen[OPT_DELETE_IKE] ||
	    seen[OPT_DELETE_CHILD] ||
	    seen[OPT_DOWN_IKE] ||
	    seen[OPT_DOWN_CHILD] ||
	    (opts_seen & CONN_OPT_SEEN)) {
		if (!seen[OPT_NAME]) {
			diagw("missing --name <connection_name>");
		}
	} else if (seen[OPT_NAME] &&
		   !seen[OPT_TRAFFICSTATUS] &&
		   !seen[OPT_CONNECTIONSTATUS] &&
		   !seen[OPT_BRIEFCONNECTIONSTATUS] &&
		   !seen[OPT_SHOW_STATES] &&
		   !seen[OPT_REDIRECT_TO]) {
		diagw("no reason for --name");
	}

	if (seen[OPT_REMOTE_HOST] && !seen[OPT_INITIATE]) {
		diagw("--remote-host can only be used with --initiate");
	}

	if (seen[OPT_PUBKEYRSA] || seen[OPT_ADDKEY]) {
		if (!seen[OPT_KEYID]) {
			diagw("--addkey and --pubkeyrsa require --keyid");
		}
	}

	if (!(msg.whack_add ||
	      msg.whack_key ||
	      msg.whack_delete ||
	      msg.whack_deleteid ||
	      msg.whack_deletestate ||
	      msg.whack_deleteuser ||
	      msg.redirect_to != NULL ||
	      msg.global_redirect ||
	      msg.global_redirect_to ||
	      msg.whack_initiate ||
	      msg.whack_oppo_initiate ||
	      msg.whack_down ||
	      msg.whack_route ||
	      msg.whack_unroute ||
	      msg.whack_listen ||
	      msg.whack_unlisten ||
	      msg.whack_list ||
	      msg.ike_buf_size ||
	      msg.whack_ddos != DDOS_undefined ||
	      msg.whack_ddns ||
	      msg.whack_rereadcerts ||
	      msg.whack_fetchcrls ||
	      msg.whack_rereadsecrets ||
	      msg.whack_crash ||
	      msg.whack_shuntstatus ||
	      msg.whack_status ||
	      msg.whack_globalstatus ||
	      msg.whack_trafficstatus ||
	      msg.whack_addresspoolstatus ||
	      msg.whack_connectionstatus ||
	      msg.whack_briefconnectionstatus ||
	      msg.whack_processstatus ||
	      msg.whack_fipsstatus ||
	      msg.whack_briefstatus ||
	      msg.whack_clear_stats ||
	      !lmod_empty(msg.debugging) ||
	      msg.impairments.len > 0 ||
	      msg.whack_shutdown ||
	      msg.whack_purgeocsp ||
	      msg.whack_seccomp_crashtest ||
	      msg.whack_showstates ||
	      msg.whack_sa ||
	      msg.whack_listpubkeys ||
	      msg.whack_checkpubkeys)) {
		diagw("no action specified; try --help for hints");
	}

	/* pack strings for inclusion in message */
	wp.msg = &msg;

	/* build esp message as esp="<esp>;<pfsgroup>" */
	if (msg.pfsgroup != NULL) {
		snprintf(esp_buf, sizeof(esp_buf), "%s;%s",
			 msg.esp != NULL ? msg.esp : "",
			 msg.pfsgroup != NULL ? msg.pfsgroup : "");
		msg.esp = esp_buf;
	}
	ugh = pack_whack_msg(&wp, logger);
	if (ugh != NULL)
		diagw(ugh);

	msg.magic = ((opts_seen & ~BASIC_OPT_SEEN) != LEMPTY ? WHACK_MAGIC :
		     WHACK_BASIC_MAGIC);

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
	}

	int sock = cloexec_socket(AF_UNIX, SOCK_STREAM, 0);
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
			     sun_path) + strlen(ctl_addr.sun_path)) < 0)
	{
		int e = errno;

		fprintf(stderr,
			"whack:%s connect() for \"%s\" failed (%d %s)\n",
			e == ECONNREFUSED ? " is Pluto running? " : "",
			ctl_addr.sun_path, e, strerror(e));
		exit(RC_WHACK_PROBLEM);
	}

	if (write(sock, &msg, len) != len) {
		int e = errno;

		fprintf(stderr, "whack: write() failed (%d %s)\n",
			e, strerror(e));
		exit(RC_WHACK_PROBLEM);
	}

	/* for now, just copy reply back to stdout */

	char buf[4097];	/* arbitrary limit on log line length */
	char *be = buf;

	for (;;) {
		char *ls = buf;
		ssize_t rl = read(sock, be, (buf + sizeof(buf) - 1) - be);

		if (rl < 0) {
			int e = errno;

			fprintf(stderr,
				"whack: read() failed (%d %s)\n",
				e, strerror(e));
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

		for (;;) {
			char *le = strchr(ls, '\n');

			if (le == NULL) {
				/*
				 * move last, partial line
				 * to start of buffer
				 */
				memmove(buf, ls, be - ls);
				be -= ls - buf;
				break;
			}
			le++;	/* include NL in line */

			/*
			 * figure out prefix number and how it should
			 * affect our exit status and printing
			 */
			char *lpe = NULL; /* line-prefix-end */
			unsigned long s = strtoul(ls, &lpe, 10);
			if (lpe == ls || *lpe != ' ') {
				/* includes embedded NL, see above */
				fprintf(stderr, "whack: log line missing NNN prefix: %*s",
					(int)(le - ls), ls);
#if 0
				ls = le;
				continue;
#else
				exit(RC_WHACK_PROBLEM);
#endif
			}

			ls = lpe + 1; /* skip NNN_ */

			if (write(STDOUT_FILENO, ls, le - ls) != (le - ls)) {
				int e = errno;

				fprintf(stderr,
					"whack: write() failed to stdout(%d %s)\n",
					e, strerror(e));
			}

			switch (s) {
			/* these logs are informational only */
			case RC_COMMENT:
			case RC_INFORMATIONAL:
			case RC_LOG:
			/* RC_LOG_SERIOUS is supposed to be here according to lswlog.h, but seems oudated? */
				/* ignore */
				break;
			case RC_SUCCESS:
				/* be happy */
				exit_status = 0;
				break;

			case RC_ENTERSECRET:
				if (!gotxauthpass) {
					xauthpasslen = whack_get_secret(xauthpass,
									sizeof(xauthpass));
				}
				send_reply(sock,
					   xauthpass,
					   xauthpasslen);
				break;

			case RC_USERPROMPT:
				if (!gotusername) {
					usernamelen = whack_get_value(xauthusername,
								      sizeof(xauthusername));
				}
				send_reply(sock,
					   xauthusername,
					   usernamelen);
				break;

			default:
				/*
				 * Only RC_ codes between
				 * RC_EXIT_FLOOR (RC_DUPNAME) and
				 * RC_EXIT_ROOF are errors
				 */
				if (s > 0 && (s < RC_EXIT_FLOOR || s >= RC_EXIT_ROOF))
					s = 0;
				exit_status = msg.whack_async ?
					0 : s;
				break;
			}

			ls = le;
		}
	}

	if (ignore_errors)
		return 0;

	return exit_status;
}
