/* command interface to Pluto
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
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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
#include <assert.h>
#include <limits.h>	/* for INT_MAX */

#include "lsw_socket.h"
#include "optarg.h"
#include "ttodata.h"
#include "lswversion.h"
#include "lswtool.h"
#include "constants.h"
#include "lswlog.h"
#include "whack.h"
#include "ip_address.h"
#include "ip_info.h"
#include "timescale.h"
#include "lswalloc.h"

/*
 * Print the 'ipsec --whack help' message on STDOUT, so it can be fed
 * to MORE, GREP, ...
 *
 * Since this was requested this isn't an error.
 */
static void help(void)
{
	fprintf(stdout,
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
		"	[--ikeport <port-number>] \\\n"
		"	[--sourceip <ip-address>] [--interface-ip <address>/<mask>]\\\n"
		"	[--vti <ip-address>/mask] \\\n"
		"	[--updown <updown>] \\\n"
		"	[--authby <psk | rsasig | rsa | ecdsa | null | eaponly>] \\\n"
		"	[--autheap <none | tls>] \\\n"
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
		"	[--tfc <size>] [--send-esp-tfc-padding-not-supported] \\\n"
		" [--reject-simultaneous-ike-auth] \\\n"
		"	[--iptfs[={yes,no}] \\\n"
		"         [--iptfs-fragmentation[={yes,no}]] \\\n"
		"         [--iptfs-packet-size <size>] \\\n"
		"	  [--iptfs-max-queue-size <size>] \\\n"
		"         [--iptfs-init-delay <s>] \\\n"
		"         [--iptfs-drop-time <s> ] \\\n"
		"	  [--iptfs-reorder-window <window>] \\\n"
		"	[--ikev1 | --ikev2] \\\n"
		"	[--narrowing {yes,no}] \\\n"
		"	[--fragmentation {yes,no,force}] [--no-ikepad]  \\\n"
		"	[--ikefrag-allow | --ikefrag-force] \\\n"
		"	[--esn ] [--no-esn] [--decap-dscp] [--encap-dscp] [--nopmtudisc] [--mobike] \\\n"
		"	[--tcp <no|yes|fallback>] --tcp-remote-port <port>\\\n"
		"	[--session-resumption[={yes,no}]] \\\n"
		"	[--nm-configured] \\\n"
#ifdef HAVE_LABELED_IPSEC
		"	[--policylabel <label>] \\\n"
#endif
		"	[--dontrekey] [--dont-share-lease] [--aggressive] \\\n"
		"	[--initial-contact[={yes,no}]] [--cisco-unity[={yes,no}]] [--fake-strongswan] \\\n"
		"	[--encapsulation[={auto,yes,no}] [--nat-keepalive {yes,no}] \\\n"
		"	[--ikev1-natt <both|rfc|drafts>] \\\n"
		"	[--dpddelay <seconds> --dpdtimeout <seconds>] \\\n"
		"	[--xauthby file|pam|alwaysok] [--xauthfail hard|soft] \\\n"
		"	[--xauthserver[={YES,no}]] [ --xauthclient[={YES,no}] ] \\\n"
		"	[--addresspool <network range>] \\\n"
		"	[--modecfgserver[={yes,no}] | --modecfgclient[={yes,no}]] [--modecfgpull[={yes,no}]] \\\n"
		"	[--modecfgdns <ip-address, ip-address>  \\\n"
		"	[--modecfgdomains <dns-domain, dns-domain, ..>] \\\n"
		"	[--modecfgbanner <login banner>] \\\n"
#ifdef USE_CAT
		"	[--cat[={yes,no}]] \\\n"
#endif
		"	[--metric <metric>] \\\n"
#ifdef USE_NFLOG
		"	[--nflog-group <groupnum>] \\\n"
#endif
		"	[--conn-mark <mark/mask>] [--conn-mark-in <mark/mask>] \\\n"
		"	[--conn-mark-out <mark/mask>] \\\n"
		"	[--ipsec-interface <num>] \\\n"
		"	[--vti-interface <iface> ] [--vti-routing] [--vti-shared] \\\n"
		"       [--pass | --drop]\\\n"
		"	[--failnone | --failpass | --faildrop]\\\n"
		"	[--negopass | --negohold]\\\n"
		"	[--reauth ] \\\n"
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
		"suspend: whack --suspend --name <connection_name>\n"
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
 * Conditionally calls diag if ugh is set.
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

static void whack_command(struct whack_message *wm, enum whack_command command)
{
	static unsigned last_index;
	if (wm->whack_command == 0) {
		wm->whack_command = command;
		last_index = optarg_index;
		return;
	}

	if (wm->whack_command == command) {
		/* for instance --oppo{here,there} */
		return;
	}

	fprintf(stderr, "whack error: conflicing command options '--%s' and '--%s'\n",
		optarg_options[last_index].name,
		optarg_options[optarg_index].name);
	exit(RC_WHACK_PROBLEM);
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
 */

enum opt_seen_ix {

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

enum opt {

	OPT_HELP = 'h',
	OPT_VERSION = 'v',
	OPT_LABEL = 'l',

/*
 * Start the the non-ASCIC options at 256 so that they can't clash
 * with ASCII options.
 */

#define OPT_START 256

/*
 * Normal options don't fall into the connection category (better
 * description? global?).
 */

#define FIRST_NORMAL_OPT	OPT_STATUS	/* first "normal" option */

	OPT_STATUS = OPT_START,
	OPT_SHUTDOWN,

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

	OPT_SUSPEND,

	OPT_INITIATE,
	OPT_DOWN,
	OPT_DELETE,
	OPT_DELETEID,
	OPT_DELETESTATE,
	OPT_DELETEUSER,

	OPT_LISTEN,
	OPT_UNLISTEN,
	OPT_IKE_SOCKET_BUFSIZE,
	OPT_IKE_SOCKET_ERRQUEUE,
	OPT_IKE_SOCKET_ERRQUEUE_TOGGLE,

	OPT_REKEY_IKE,
	OPT_REKEY_CHILD,
	OPT_DELETE_IKE,
	OPT_DELETE_CHILD,
	OPT_DOWN_IKE,
	OPT_DOWN_CHILD,

	OPT_REDIRECT_TO,	/* either active or for connection */
	OPT_GLOBAL_REDIRECT,
	OPT_GLOBAL_REDIRECT_TO,

	OPT_DDOS_MODE,
	OPT_DDOS_BUSY,
	OPT_DDOS_UNLIMITED,
	OPT_DDOS_AUTO,

	OPT_DDNS,

	OPT_REREADSECRETS,
	OPT_FETCHCRLS,
	OPT_REREADCERTS,
	OPT_REREADALL,

	OPT_PURGEOCSP,

	OPT_GLOBALSTATUS,
	OPT_CLEARSTATS,
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
	OPT_OPPO_LABEL,

	/* List options */

	LST_UTC,
	LST_CHECKPUBKEYS,
	LST_PUBKEYS = LST_CHECKPUBKEYS + 1 + LIST_PUBKEYS,
	LST_CERTS =   LST_CHECKPUBKEYS + 1 + LIST_CERTS,
	LST_CACERTS = LST_CHECKPUBKEYS + 1 + LIST_CACERTS,
	LST_CRLS =    LST_CHECKPUBKEYS + 1 + LIST_CRLS,
	LST_PSKS =    LST_CHECKPUBKEYS + 1 + LIST_PSKS,
	LST_EVENTS =  LST_CHECKPUBKEYS + 1 + LIST_EVENTS,
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
	END_IKEPORT,
	END_NEXTHOP,
	END_SUBNET,
	END_CLIENTPROTOPORT,
	END_DNSKEYONDEMAND,
	END_XAUTHSERVER,
	END_XAUTHCLIENT,
	END_MODECFGCLIENT,
	END_MODECFGSERVER,
	END_ADDRESSPOOL,
	END_SENDCERT,
	END_SOURCEIP,
        END_INTERFACE_IP,
	END_VTI,
	END_AUTH,
	END_AUTHEAP,
	END_CAT,
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
	CD_SEND_ESP_TFC_PADDING_NOT_SUPPORTED,
	CD_REJECT_SIMULTANEOUS_IKE_AUTH,
	CD_PFS,
	CD_REQID,
	CD_NFLOG_GROUP,
	CD_CONN_MARK,
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

	CD_IPTFS,
	CD_IPTFS_FRAGMENTATION,
	CD_IPTFS_PACKET_SIZE,
	CD_IPTFS_MAX_QUEUE_SIZE,
	CD_IPTFS_INIT_DELAY,
	CD_IPTFS_REORDER_WINDOW,
	CD_IPTFS_DROP_TIME,

	CD_RETRANSMIT_TIMEOUT,
	CD_RETRANSMIT_INTERVAL,
	CD_IKE_LIFETIME,
	CD_IPSEC_LIFETIME,
	CD_IPSEC_MAX_BYTES,
	CD_IPSEC_MAX_PACKETS,
	CD_REKEYMARGIN,
	CD_REKEYFUZZ,
	CD_REPLAY_WINDOW,
	CD_DPDDELAY,
	CD_DPDTIMEOUT,
	CD_OBSOLETE,
	CD_SEND_REDIRECT,
	CD_ACCEPT_REDIRECT,
	CD_ACCEPT_REDIRECT_TO,
	CD_ENCAPSULATION,
	CD_NO_NAT_KEEPALIVE,
	CD_NAT_KEEPALIVE,
	CD_IKEV1_NATT,
	CD_INITIAL_CONTACT,
	CD_CISCO_UNITY,
	CD_FAKE_STRONGSWAN,
	CD_MOBIKE,
	CD_SESSION_RESUMPTION,
	CD_IKE,
	CD_TCP,
	CD_TCP_REMOTE_PORT,
	CD_SENDCA,
	CD_REMOTE_PEER_TYPE,
	CD_SHA2_TRUNCBUG,
	CD_DONT_SHARE_LEASE,
	CD_NM_CONFIGURED,
	CD_LABELED_IPSEC,
	CD_SEC_LABEL,
	CD_XAUTHBY,
	CD_XAUTHFAIL,
	CD_NIC_OFFLOAD,
	CD_NARROWING,
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

	CDS_NEVER_NEGOTIATE_PASS,
	CDS_NEVER_NEGOTIATE_DROP,
	CDS_NEGOTIATION_PASS,
	CDS_NEGOTIATION_HOLD,
	CDS_FAILURE_NONE,
	CDS_FAILURE_PASS,
	CDS_FAILURE_DROP,

#define LAST_CONN_OPT		CDS_FAILURE_DROP	/* last connection description */

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

	DBGOPT_MAGIC,

#define LAST_DBGOPT		DBGOPT_MAGIC

#define	OPTION_ENUMS_LAST	LAST_DBGOPT
#define OPTION_ENUMS_ROOF	(OPTION_ENUMS_LAST+1)
};

const struct option optarg_options[] = {

	/* name, has_arg, flag, val */

	{ "help\0", no_argument, NULL, OPT_HELP },
	{ "version\0", no_argument, NULL, OPT_VERSION },
	{ "label\0", required_argument, NULL, OPT_LABEL },

	{ "rundir\0", required_argument, NULL, OPT_RUNDIR },
	{ "ctlbase\0", required_argument, NULL, OPT_RUNDIR }, /* backwards compat */
	{ "ctlsocket\0", required_argument, NULL, OPT_CTLSOCKET },
	{ "name\0", required_argument, NULL, OPT_NAME },
	{ "remote-host\0", required_argument, NULL, OPT_REMOTE_HOST },
	{ "connalias\0", required_argument, NULL, OPT_CONNALIAS },

	{ "keyid\0", required_argument, NULL, OPT_KEYID },
	{ "addkey\0", no_argument, NULL, OPT_ADDKEY },
	{ "pubkeyrsa\0", required_argument, NULL, OPT_PUBKEYRSA },

	{ "route\0", no_argument, NULL, OPT_ROUTE },
	{ "ondemand\0", no_argument, NULL, OPT_ROUTE },	/* alias */
	{ "unroute\0", no_argument, NULL, OPT_UNROUTE },

	{ "initiate\0", no_argument, NULL, OPT_INITIATE },
	{ "down\0", no_argument, NULL, OPT_DOWN },
	{ "terminate\0", no_argument, NULL, OPT_DOWN }, /* backwards compat */
	{ "delete\0", no_argument, NULL, OPT_DELETE },
	{ "deleteid\0", no_argument, NULL, OPT_DELETEID },
	{ "deletestate\0", required_argument, NULL, OPT_DELETESTATE },
	{ "deleteuser\0", no_argument, NULL, OPT_DELETEUSER },
	{ "crash\0", required_argument, NULL, OPT_DELETECRASH },

	{ OPT("listen"), no_argument, NULL, OPT_LISTEN },
	{ OPT("unlisten"), no_argument, NULL, OPT_UNLISTEN },
	{ OPT("ike-socket-bufsize", "<bytes>"), required_argument, NULL, OPT_IKE_SOCKET_BUFSIZE},
	{ OPT("ike-socket-errqueue", "{yes,no}"), required_argument, NULL, OPT_IKE_SOCKET_ERRQUEUE },
	{ REPLACE_OPT("ike-socket-errqueue-toggle","ike-socket-errqueue","5.3"), no_argument, NULL, OPT_IKE_SOCKET_ERRQUEUE_TOGGLE },

	{ "redirect-to\0", required_argument, NULL, OPT_REDIRECT_TO },
	{ "global-redirect\0", required_argument, NULL, OPT_GLOBAL_REDIRECT },
	{ "global-redirect-to\0", required_argument, NULL, OPT_GLOBAL_REDIRECT_TO },

	{ OPT("ddos-mode", "{busy,unlimited,auto}"), required_argument, NULL, OPT_DDOS_MODE },
	{ REPLACE_OPT("ddos-busy", "ddos-mode", "5.3"), no_argument, NULL, OPT_DDOS_BUSY },
	{ REPLACE_OPT("ddos-unlimited", "ddos-mode", "5.3"), no_argument, NULL, OPT_DDOS_UNLIMITED },
	{ REPLACE_OPT("ddos-auto", "ddos-mode", "5.3"), no_argument, NULL, OPT_DDOS_AUTO },

	{ "ddns\0", no_argument, NULL, OPT_DDNS },

	{ "rereadsecrets\0", no_argument, NULL, OPT_REREADSECRETS },
	{ FATAL_OPT("rereadcrls", "5.0"), no_argument, NULL, 0, }, /* obsolete */
	{ "rereadcerts\0", no_argument, NULL, OPT_REREADCERTS },
	{ "fetchcrls\0", no_argument, NULL, OPT_FETCHCRLS },
	{ "rereadall\0", no_argument, NULL, OPT_REREADALL },

	{ "purgeocsp\0", no_argument, NULL, OPT_PURGEOCSP },

	{ "clearstats\0", no_argument, NULL, OPT_CLEARSTATS },

	{ "status\0", no_argument, NULL, OPT_STATUS },
	{ "globalstatus\0", no_argument, NULL, OPT_GLOBALSTATUS },
	{ "trafficstatus\0", no_argument, NULL, OPT_TRAFFICSTATUS },
	{ "shuntstatus\0", no_argument, NULL, OPT_SHUNTSTATUS },
	{ "addresspoolstatus\0", no_argument, NULL, OPT_ADDRESSPOOLSTATUS },
	{ "connectionstatus\0", no_argument, NULL, OPT_CONNECTIONSTATUS },
	{ "briefconnectionstatus\0", no_argument, NULL, OPT_BRIEFCONNECTIONSTATUS },
	{ "fipsstatus\0", no_argument, NULL, OPT_FIPSSTATUS },
	{ "briefstatus\0", no_argument, NULL, OPT_BRIEFSTATUS },
	{ "processstatus\0", no_argument, NULL, OPT_PROCESSSTATUS },
	{ "statestatus\0", no_argument, NULL, OPT_SHOW_STATES }, /* alias to catch typos */
	{ "showstates\0", no_argument, NULL, OPT_SHOW_STATES },

#ifdef USE_SECCOMP
	{ "seccomp-crashtest\0", no_argument, NULL, OPT_SECCOMP_CRASHTEST },
#endif
	{ "shutdown\0", no_argument, NULL, OPT_SHUTDOWN },
	{ "leave-state\0", no_argument, NULL, OPT_LEAVE_STATE },
	{ "username\0", required_argument, NULL, OPT_USERNAME },
	{ "xauthuser\0", required_argument, NULL, OPT_USERNAME }, /* old name */
	{ "xauthname\0", required_argument, NULL, OPT_USERNAME }, /* old name */
	{ "xauthpass\0", required_argument, NULL, OPT_XAUTHPASS },

	{ OPT("oppohere", "<address>"), required_argument, NULL, OPT_OPPO_HERE },
	{ OPT("oppothere", "<address>"), required_argument, NULL, OPT_OPPO_THERE },
	{ OPT("oppoproto", "<protocol> (ICMP)"), required_argument, NULL, OPT_OPPO_PROTO },
	{ OPT("opposport", "<source-port> (0)"), required_argument, NULL, OPT_OPPO_SPORT },
	{ OPT("oppodport", "<destination-port> (8)"), required_argument, NULL, OPT_OPPO_DPORT },
	{ OPT("oppolabel", "<security-label>"), required_argument, NULL, OPT_OPPO_LABEL },

	{ "asynchronous\0", no_argument, NULL, OPT_ASYNC },

	{ "rekey-ike\0", no_argument, NULL, OPT_REKEY_IKE },
	{ "rekey-child\0", no_argument, NULL, OPT_REKEY_CHILD },
	{ "delete-ike\0", no_argument, NULL, OPT_DELETE_IKE },
	{ "delete-child\0", no_argument, NULL, OPT_DELETE_CHILD },
	{ "down-ike\0", no_argument, NULL, OPT_DOWN_IKE },
	{ "down-child\0", no_argument, NULL, OPT_DOWN_CHILD },

	{ "suspend\0", no_argument, NULL, OPT_SUSPEND, },
	{ "session-resumption\0", optional_argument, NULL, CD_SESSION_RESUMPTION, },

	/* list options */

	{ "utc\0", no_argument, NULL, LST_UTC },
	{ "checkpubkeys\0", no_argument, NULL, LST_CHECKPUBKEYS },
	{ "listpubkeys\0", no_argument, NULL, LST_PUBKEYS },
	{ "listcerts\0", no_argument, NULL, LST_CERTS },
	{ "listcacerts\0", no_argument, NULL, LST_CACERTS },
	{ "listcrls\0", no_argument, NULL, LST_CRLS },
	{ "listpsks\0", no_argument, NULL, LST_PSKS },
	{ "listevents\0", no_argument, NULL, LST_EVENTS },
	{ "listall\0", no_argument, NULL, LST_ALL },

	/* options for an end description */

	{ "host\0", required_argument, NULL, END_HOST },
	{ "id\0", required_argument, NULL, END_ID },
	{ "cert\0", required_argument, NULL, END_CERT },
	{ "ckaid\0", required_argument, NULL, END_CKAID },
	{ "ca\0", required_argument, NULL, END_CA },
	{ IGNORE_OPT("groups", "5.4"), required_argument, NULL, 0 },
	{ "ikeport\0", required_argument, NULL, END_IKEPORT },
	{ "nexthop\0", required_argument, NULL, END_NEXTHOP },
	{ "client\0", required_argument, NULL, END_SUBNET },	/* alias / backward compat */
	{ "subnet\0", required_argument, NULL, END_SUBNET },
	{ "clientprotoport\0", required_argument, NULL, END_CLIENTPROTOPORT },
#ifdef USE_DNSSEC
	{ "dnskeyondemand\0", no_argument, NULL, END_DNSKEYONDEMAND },
#endif
	{ "sourceip\0",  required_argument, NULL, END_SOURCEIP },
	{ "srcip\0",  required_argument, NULL, END_SOURCEIP },	/* alias / backwards compat */
	{ "interface-ip\0", required_argument, NULL, END_INTERFACE_IP },	/* match config */
	{ "interfaceip\0", required_argument, NULL, END_INTERFACE_IP },	/* alias / backward compat */
	{ OPT("auth", "{psk,null,rsasig,rsa,ecdsa,eaponly}"),  required_argument, NULL, END_AUTH },
	{ REPLACE_OPT("authby", "auth", "5.3"),  required_argument, NULL, END_AUTH },
	{ "autheap\0",  required_argument, NULL, END_AUTHEAP },
	{ "updown\0", required_argument, NULL, END_UPDOWN },

	/* options for a connection description */

	{ "to\0", no_argument, NULL, CD_TO },

	/* option for cert rotation */

	{ "intermediate\0", optional_argument, NULL, CD_INTERMEDIATE },
	{ "encrypt\0", no_argument, NULL, CD_ENCRYPT },
	{ "authenticate\0", no_argument, NULL, CD_AUTHENTICATE },
	{ "compress\0", optional_argument, NULL, CD_COMPRESS },
	{ "overlapip\0", optional_argument, NULL, CD_OVERLAPIP },
	{ "tunnel\0", no_argument, NULL, CD_TUNNEL, },
	{ "transport\0", no_argument, NULL, CD_TRANSPORT, },
	{ "tunnelipv4\0", no_argument, NULL, CD_TUNNELIPV4 },
	{ "tunnelipv6\0", no_argument, NULL, CD_TUNNELIPV6 },
	{ "ms-dh-downgrade\0", optional_argument, NULL, CD_MS_DH_DOWNGRADE },
	{ "pfs-rekey-workaround\0", optional_argument, NULL, CD_PFS_REKEY_WORKAROUND, },
	{ "dns-match-id\0", optional_argument, NULL, CD_DNS_MATCH_ID },
	{ "allow-cert-without-san-id\0", no_argument, NULL, CD_ALLOW_CERT_WITHOUT_SAN_ID },
	{ "sha2-truncbug\0", optional_argument, NULL, CD_SHA2_TRUNCBUG },
	{ "sha2_truncbug\0", no_argument, NULL, CD_SHA2_TRUNCBUG }, /* backwards compatibility */
	{ "dont-share-lease\0", optional_argument, NULL, CD_DONT_SHARE_LEASE },
	{ "aggressive\0", optional_argument, NULL, CD_AGGRESSIVE },
	{ "aggrmode\0", no_argument, NULL, CD_AGGRESSIVE }, /*  backwards compatibility */

	{ FATAL_OPT("initiateontraffic", ""), no_argument, NULL, 0, }, /* obsolete */

	{ "drop\0", no_argument, NULL, CDS_NEVER_NEGOTIATE_DROP },
	{ "pass\0", no_argument, NULL, CDS_NEVER_NEGOTIATE_PASS },
	{ "reject\0>drop", no_argument, NULL, CDS_NEVER_NEGOTIATE_DROP },

	{ "negodrop\0", no_argument, NULL, CDS_NEGOTIATION_HOLD },
	{ "negohold\0", no_argument, NULL, CDS_NEGOTIATION_HOLD },
	{ "negopass\0", no_argument, NULL, CDS_NEGOTIATION_PASS },

	{ "faildrop\0", no_argument, NULL, CDS_FAILURE_DROP },
	{ "failhold\0faildrop", no_argument, NULL, CDS_FAILURE_DROP },
	{ "failnone\0", no_argument, NULL, CDS_FAILURE_NONE },
	{ "failpass\0", no_argument, NULL, CDS_FAILURE_PASS },
	{ "failreject\0>faildrop", no_argument, NULL, CDS_FAILURE_DROP },

	{ "dontrekey\0", no_argument, NULL, CD_DONT_REKEY, },
	{ "reauth\0", no_argument, NULL, CD_REAUTH, },
	{ "encaps\0", required_argument, NULL, CD_ENCAPSULATION },
	{ "encapsulation\0", optional_argument, NULL, CD_ENCAPSULATION },

	{ "iptfs\0", optional_argument, NULL, CD_IPTFS, },
	{ "iptfs-fragmentation\0", optional_argument, NULL, CD_IPTFS_FRAGMENTATION, },
	{ "iptfs-packet-size\0", required_argument, NULL, CD_IPTFS_PACKET_SIZE },
	{ "iptfs-max-queue-size\0", required_argument, NULL, CD_IPTFS_MAX_QUEUE_SIZE },
	{ "iptfs-init-delay\0", required_argument, NULL, CD_IPTFS_INIT_DELAY },
	{ "iptfs-reorder-window\0", required_argument, NULL, CD_IPTFS_REORDER_WINDOW },
	{ "iptfs-drop-time\0", required_argument, NULL, CD_IPTFS_DROP_TIME },

	{ OPT("nat-keepalive", "YES|no"), required_argument, NULL,  CD_NAT_KEEPALIVE },
	{ REPLACE_OPT("no-nat_keepalive", "nat-keepalive", "5.3"), no_argument, NULL,  CD_NO_NAT_KEEPALIVE },
	{ REPLACE_OPT("no-nat-keepalive", "nat-keepalive", "5.3"), no_argument, NULL,  CD_NO_NAT_KEEPALIVE },
	{ "ikev1_natt\0", required_argument, NULL, CD_IKEV1_NATT },	/* obsolete _ */
	{ "ikev1-natt\0", required_argument, NULL, CD_IKEV1_NATT },
	{ REPLACE_OPT("initialcontact", "initial-contact", "5.3"), no_argument, NULL, CD_INITIAL_CONTACT },
	{ OPT("initial-contact", "yes|no"), optional_argument, NULL,  CD_INITIAL_CONTACT },
	{ OPT("cisco-unity", "yes|no"), optional_argument, NULL, CD_CISCO_UNITY },
	{ REPLACE_OPT("cisco_unity", "cisco-unity", "3.9"), no_argument, NULL, CD_CISCO_UNITY },	/* obsolete _ */
	{ "fake-strongswan\0", optional_argument, NULL, CD_FAKE_STRONGSWAN },
	{ "mobike\0", optional_argument, NULL, CD_MOBIKE },

	{ "dpddelay\0", required_argument, NULL, CD_DPDDELAY },
	{ "dpdtimeout\0", required_argument, NULL, CD_DPDTIMEOUT },
	{ "dpdaction\0", required_argument, NULL, CD_OBSOLETE },
	{ "send-redirect\0", required_argument, NULL, CD_SEND_REDIRECT },
	{ "accept-redirect\0", required_argument, NULL, CD_ACCEPT_REDIRECT },
	{ "accept-redirect-to\0", required_argument, NULL, CD_ACCEPT_REDIRECT_TO },

	{ REPLACE_OPT("xauth", "xauthserver", "5.3"), no_argument, NULL, END_XAUTHSERVER },
	{ OPT("xauthserver", "YES|no"), optional_argument, NULL, END_XAUTHSERVER },
	{ OPT("xauthclient", "YES|no"), optional_argument, NULL, END_XAUTHCLIENT },
	{ "xauthby\0", required_argument, NULL, CD_XAUTHBY },
	{ "xauthfail\0", required_argument, NULL, CD_XAUTHFAIL },
	{ "modecfgpull\0", optional_argument, NULL, CD_MODECFGPULL },
	{ "modecfgserver\0", optional_argument, NULL, END_MODECFGSERVER },
	{ "modecfgclient\0", optional_argument, NULL, END_MODECFGCLIENT },
	{ "cat\0", optional_argument, NULL, END_CAT },
	{ "addresspool\0", required_argument, NULL, END_ADDRESSPOOL },
	{ "modecfgdns\0", required_argument, NULL, CD_MODECFGDNS },
	{ "modecfgdomains\0", required_argument, NULL, CD_MODECFGDOMAINS },
	{ "modecfgbanner\0", required_argument, NULL, CD_MODECFGBANNER },
	{ "modeconfigserver\0", no_argument, NULL, END_MODECFGSERVER },
	{ "modeconfigclient\0", no_argument, NULL, END_MODECFGCLIENT },

	{ "metric\0", required_argument, NULL, CD_METRIC },
	{ "mtu\0", required_argument, NULL, CD_MTU },
	{ "priority\0", required_argument, NULL, CD_PRIORITY },
	{ "tfc\0", required_argument, NULL, CD_TFC },
	{ "send-esp-tfc-padding-not-supported\0yes|no", optional_argument, NULL, CD_SEND_ESP_TFC_PADDING_NOT_SUPPORTED },
	{ "send-no-esp-tfc\0", no_argument, NULL, CD_SEND_ESP_TFC_PADDING_NOT_SUPPORTED },
	{ "reject-simultaneous-ike-auth\0yes|no", optional_argument, NULL, CD_REJECT_SIMULTANEOUS_IKE_AUTH },
	{ "pfs\0", optional_argument, NULL, CD_PFS },
	{ "reqid\01-65535", required_argument, NULL, CD_REQID },
#ifdef USE_NFLOG
	{ "nflog-group\0", required_argument, NULL, CD_NFLOG_GROUP },
#endif
	{ "conn-mark\0", required_argument, NULL, CD_CONN_MARK },
	{ "conn-mark-in\0", required_argument, NULL, CD_CONN_MARK_IN },
	{ "conn-mark-out\0", required_argument, NULL, CD_CONN_MARK_OUT },
	{ REPLACE_OPT("vtiip", "vti", "5.3"),  required_argument, NULL, END_VTI }, /* backward compat */
	{ "vti\0",  required_argument, NULL, END_VTI },
	{ "vti-iface\0", required_argument, NULL, CD_VTI_INTERFACE }, /* backward compat */
	{ "vti-interface\0", required_argument, NULL, CD_VTI_INTERFACE },
	{ "vti-routing\0", optional_argument, NULL, CD_VTI_ROUTING },
	{ "vti-shared\0", optional_argument, NULL, CD_VTI_SHARED },
	{ "ipsec-interface\0", required_argument, NULL, CD_IPSEC_INTERFACE },
	{ "sendcert\0", required_argument, NULL, END_SENDCERT },
	{ "sendca\0", required_argument, NULL, CD_SENDCA },
	{ "ipv4\0", no_argument, NULL, CD_CONNIPV4 },
	{ "ipv6\0", no_argument, NULL, CD_CONNIPV6 },
	{ "ikelifetime\0", required_argument, NULL, CD_IKE_LIFETIME },
	{ "ipseclifetime\0", required_argument, NULL, CD_IPSEC_LIFETIME }, /* backwards compat */
	{ "ipsec-lifetime\0", required_argument, NULL, CD_IPSEC_LIFETIME },
	{ "ipsec-max-bytes\0", required_argument, NULL, CD_IPSEC_MAX_BYTES},
	{ "ipsec-max-packets\0", required_argument, NULL, CD_IPSEC_MAX_PACKETS},
	{ "retransmit-timeout\0", required_argument, NULL, CD_RETRANSMIT_TIMEOUT },
	{ "retransmit-interval\0", required_argument, NULL, CD_RETRANSMIT_INTERVAL },
	{ "rekeymargin\0", required_argument, NULL, CD_REKEYMARGIN },
	{ "rekeywindow\0", required_argument, NULL, CD_REKEYMARGIN },/* backward compat */
	{ "rekeyfuzz\0", required_argument, NULL, CD_REKEYFUZZ },
	{ IGNORE_OPT("keyingtries", "5.0"), required_argument, NULL, 0 },
	{ "replay-window\0", required_argument, NULL, CD_REPLAY_WINDOW },
	{ "ike\0",    required_argument, NULL, CD_IKE },
	{ "ikealg\0", required_argument, NULL, CD_IKE },
	{ FATAL_OPT("pfsgroup", "5.3"), required_argument, NULL, 0 },
	{ "esp\0", required_argument, NULL, CD_ESP },
	{ "remote-peer-type\0", required_argument, NULL, CD_REMOTE_PEER_TYPE },
	{ "nic-offload\0", required_argument, NULL, CD_NIC_OFFLOAD},

#define AB(NAME, ENUM) { NAME, no_argument, NULL, OPT_AUTHBY_##ENUM, }
	AB("psk\0", PSK),
	AB("auth-never\0", AUTH_NEVER),
	AB("auth-null\0", AUTH_NULL),
	AB("rsasig\0", RSASIG),
	AB("ecdsa\0", ECDSA),
	AB("ecdsa-sha2\0", ECDSA),
	AB("ecdsa-sha2_256\0", ECDSA_SHA2_256),
	AB("ecdsa-sha2_384\0", ECDSA_SHA2_384),
	AB("ecdsa-sha2_512\0", ECDSA_SHA2_512),
	AB("rsa-sha1\0", RSA_SHA1),
	AB("rsa-sha2\0", RSA_SHA2),
	AB("rsa-sha2_256\0", RSA_SHA2_256),
	AB("rsa-sha2_384\0", RSA_SHA2_384),
	AB("rsa-sha2_512\0", RSA_SHA2_512),
#undef AB

	{ "ikev1\0", no_argument, NULL, CD_IKEv1 },
	{ "ikev1-allow\0", no_argument, NULL, CD_IKEv1 }, /* obsolete name */
	{ "ikev2\0", no_argument, NULL, CD_IKEv2 },
	{ "ikev2-allow\0", no_argument, NULL, CD_IKEv2 }, /* obsolete name */
	{ "ikev2-propose\0", no_argument, NULL, CD_IKEv2 }, /* obsolete, map onto allow */

	{ "allow-narrowing\0", optional_argument, NULL, CD_NARROWING, }, /* undocumented but tested name */
	{ "narrowing\0", required_argument, NULL, CD_NARROWING, },
	{ "ikefrag-allow\0", no_argument, NULL, CD_IKEFRAG_ALLOW }, /* obsolete name */
	{ "ikefrag-force\0", no_argument, NULL, CD_IKEFRAG_FORCE }, /* obsolete name */
	{ "fragmentation\0", required_argument, NULL, CD_FRAGMENTATION },

	{ "ikepad\0", no_argument, NULL, CD_IKEPAD },

	{ "no-esn\0", no_argument, NULL, CD_NO_ESN }, /* obsolete */
	{ "esn\0", optional_argument, NULL, CD_ESN },
	{ "decap-dscp\0", optional_argument, NULL, CD_DECAP_DSCP },
	{ "encap-dscp\0", optional_argument, NULL, CD_ENCAP_DSCP },
	{ "nopmtudisc\0", optional_argument, NULL, CD_NOPMTUDISC },
	{ "ignore-peer-dns\0", optional_argument, NULL, CD_IGNORE_PEER_DNS },

	{ "tcp\0", required_argument, NULL, CD_TCP },
	{ "tcp-remote-port\0", required_argument, NULL, CD_TCP_REMOTE_PORT },

	{ REPLACE_OPT("nm_configured", "nm-configured", "4.0"), optional_argument, NULL, CD_NM_CONFIGURED }, /* backwards compat */
	{ OPT("nm-configured", "yes|NO"), optional_argument, NULL, CD_NM_CONFIGURED },

	{ "policylabel\0", required_argument, NULL, CD_SEC_LABEL },

	{ "debug-none\0", no_argument, NULL, DBGOPT_NONE },
	{ "debug-all\0", no_argument, NULL, DBGOPT_ALL },
	{ "debug\0", required_argument, NULL, DBGOPT_DEBUG, },
	{ "no-debug\0", required_argument, NULL, DBGOPT_NO_DEBUG, },
	{ "impair\0", required_argument, NULL, DBGOPT_IMPAIR, },
	{ "no-impair\0", required_argument, NULL, DBGOPT_NO_IMPAIR, },
	{ "magic\0", required_argument, NULL, DBGOPT_MAGIC, },

	{ 0, 0, 0, 0 }
};

static char *ctlsocket = NULL;

/* This is a hack for initiating ISAKMP exchanges. */

int main(int argc, char **argv)
{
	struct logger *logger = tool_logger(argc, argv);

	bool seen[OPTION_ENUMS_ROOF] = {0};
	lset_t opts_seen = LEMPTY;

	char xauthusername[MAX_XAUTH_USERNAME_LEN];
	char xauthpass[XAUTH_MAX_PASS_LENGTH];
	int usernamelen = 0;	/* includes '\0' */
	int xauthpasslen = 0;	/* includes '\0' */
	bool ignore_errors = false;

	struct optarg_family child_family = { 0, };

	char *authby = NULL;

	struct whack_message msg;
	init_whack_message(&msg, WHACK_FROM_WHACK);

	struct whack_end *end = &msg.end[LEFT_END];

	for (;;) {

		/*
		 * Note: we don't like the way short options get parsed
		 * by getopt_long, so we simply pass an empty string as
		 * the list.  It could be "hp:d:c:o:eatfs" "NARXPECK".
		 */
		int c = optarg_getopt(logger, argc, argv, "");
		if (c < 0) {
			break;
		}

		/*
		 * per-class option processing
		 *
		 * Mostly detection of repeated flags.
		 */
		if (FIRST_NORMAL_OPT <= c && c <= LAST_NORMAL_OPT) {
			/*
			 * OPT_* options in the above range get added
			 * to "seen[]".  Any repeated options are
			 * rejected.  The marker OPTS_SEEN_NORMAL is
			 * also added to "opts_seen".
			 */
			if (seen[c]) {
				optarg_fatal(logger, "duplicated flag");
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
			if (seen[c]) {
				optarg_fatal(logger, "duplicated flag");
			}
			seen[c] = true;
			opts_seen |= END_OPT_SEEN;
			opts_seen |= CONN_OPT_SEEN;
		} else if (FIRST_CONN_OPT <= c && c <= LAST_CONN_OPT) {
			/*
			 * CD_* options are added to seen[].  Repeated
			 * options are rejected.
			 */
			if (seen[c]) {
				optarg_fatal(logger, "duplicated flag");
			}
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
		 */
		switch ((enum opt)c) {

		case OPT_HELP:	/* --help */
			help();
			/* GNU coding standards say to stop here */
			exit(0);

		case OPT_VERSION:	/* --version */
			printf("%s\n", ipsec_version_string());
			/* GNU coding standards say to stop here */
			exit(0);

		case OPT_LABEL:	/* --label <string> */
			label = optarg;	/* remember for diagnostics */
			continue;

		/* the rest of the options combine in complex ways */

		case OPT_RUNDIR:	/* --rundir <dir> */
			pfreeany(ctlsocket);
			ctlsocket = alloc_printf("%s/pluto.ctl", optarg);
			continue;

		case OPT_CTLSOCKET:	/* --ctlsocket <file> */
			pfreeany(ctlsocket);
			ctlsocket = clone_str(optarg, "ctlsocket");
			continue;

		case OPT_NAME:	/* --name <connection-name> */
			name = optarg;
			msg.name = optarg;
			continue;

		case OPT_REMOTE_HOST:	/* --remote-host <ip or hostname> */
			remote_host = optarg;
			msg.remote_host = optarg;
			continue;

		case OPT_CONNALIAS:	/* --connalias name */
			msg.wm_connalias = optarg;
			continue;

		case OPT_KEYID:	/* --keyid <identity> */
			msg.whack_key = true;
			msg.keyid = optarg;	/* decoded by Pluto */
			continue;

		case OPT_ADDKEY:	/* --addkey */
			msg.whack_addkey = true;
			continue;

		case OPT_PUBKEYRSA:	/* --pubkeyrsa <key> */
			if (msg.pubkey != NULL) {
				diagq("only one RSA public-key allowed", optarg);
			}
			msg.pubkey = optarg;
			msg.pubkey_alg = IPSECKEY_ALGORITHM_RSA;
			continue;

		case OPT_PUBKEYECDSA:	/* --pubkeyecdsa <key> */
			if (msg.pubkey != NULL) {
				diagq("only one ECDSA public-key allowed", optarg);
			}
			msg.pubkey = optarg;
			msg.pubkey_alg = IPSECKEY_ALGORITHM_ECDSA;
			continue;

		case OPT_ROUTE:	/* --route */
			whack_command(&msg, WHACK_ROUTE);
			continue;

		case OPT_UNROUTE:	/* --unroute */
			whack_command(&msg, WHACK_UNROUTE);
			continue;

		case OPT_INITIATE:	/* --initiate */
			whack_command(&msg, WHACK_INITIATE);
			continue;

		case OPT_DOWN:	/* --down | --terminate */
			whack_command(&msg, WHACK_DOWN);
			continue;

		case OPT_REKEY_IKE: /* --rekey-ike */
			whack_command(&msg, WHACK_REKEY_IKE);
			continue;
		case OPT_REKEY_CHILD: /* --rekey-child */
			whack_command(&msg, WHACK_REKEY_CHILD);
			continue;

		case OPT_DELETE_IKE: /* --delete-ike */
			whack_command(&msg, WHACK_DELETE_IKE);
			continue;
		case OPT_DELETE_CHILD: /* --delete-child */
			whack_command(&msg, WHACK_DELETE_CHILD);
			continue;

		case OPT_DOWN_IKE: /* --down-ike */
			whack_command(&msg, WHACK_DOWN_IKE);
			continue;
		case OPT_DOWN_CHILD: /* --down-child */
			whack_command(&msg, WHACK_DOWN_CHILD);
			continue;

		case OPT_SUSPEND: /* --suspend */
			whack_command(&msg, WHACK_SUSPEND);
			continue;
		case CD_SESSION_RESUMPTION:
			msg.session_resumption = optarg_yn(logger, YN_YES);
			break;

		case OPT_DELETE:	/* --delete */
			whack_command(&msg, WHACK_DELETE);
			continue;

		case OPT_DELETEID: /* --deleteid --name <id> */
			whack_command(&msg, WHACK_DELETEID);
			continue;

		case OPT_DELETESTATE: /* --deletestate <state_object_number> */
			whack_command(&msg, WHACK_DELETESTATE);
			msg.whack_deletestateno = optarg_uintmax(logger);
			continue;

		case OPT_DELETECRASH:	/* --crash <ip-address> */
		{
			struct optarg_family any_family = { 0, };
			whack_command(&msg, WHACK_CRASH);
			msg.whack_crash_peer = optarg_address_dns(logger, &any_family);
			if (!address_is_specified(msg.whack_crash_peer)) {
				/* either :: or 0.0.0.0; unset already
				 * rejected */
				address_buf ab;
				optarg_fatal(logger, "invalid address %s",
					     str_address(&msg.whack_crash_peer, &ab));
			}
			continue;
		}

		/* --deleteuser --name <xauthusername> */
		case OPT_DELETEUSER:
			whack_command(&msg, WHACK_DELETEUSER);
			continue;

		case OPT_REDIRECT_TO:	/* --redirect-to */
			/* either active, or or add */
			/* .whack_command deciphered below */
			msg.wm_redirect_to = optarg;
			continue;

		case OPT_GLOBAL_REDIRECT:	/* --global-redirect */
			whack_command(&msg, WHACK_GLOBAL_REDIRECT);
			msg.global_redirect = optarg_sparse(logger, 0, &global_redirect_names);
			continue;

		case OPT_GLOBAL_REDIRECT_TO:	/* --global-redirect-to */
			whack_command(&msg, WHACK_GLOBAL_REDIRECT);
			msg.wm_redirect_to = optarg; /* could be empty string */
			continue;

		case OPT_DDOS_MODE:
			whack_command(&msg, WHACK_DDOS);
			msg.whack.ddos.mode = optarg_sparse(logger, 0, &ddos_mode_names);
			continue;
		case OPT_DDOS_BUSY:	/* --ddos-busy */
			whack_command(&msg, WHACK_DDOS);
			msg.whack.ddos.mode = DDOS_FORCE_BUSY;
			continue;
		case OPT_DDOS_UNLIMITED:	/* --ddos-unlimited */
			whack_command(&msg, WHACK_DDOS);
			msg.whack.ddos.mode = DDOS_FORCE_UNLIMITED;
			continue;
		case OPT_DDOS_AUTO:	/* --ddos-auto */
			whack_command(&msg, WHACK_DDOS);
			msg.whack.ddos.mode = DDOS_AUTO;
			continue;

		case OPT_DDNS:	/* --ddns */
			whack_command(&msg, WHACK_DDNS);
			continue;

		case OPT_LISTEN:	/* --listen */
			whack_command(&msg, WHACK_LISTEN);
			continue;
		case OPT_IKE_SOCKET_BUFSIZE:	/* --ike-socket-bufsize <bytes> */
			whack_command(&msg, WHACK_LISTEN); /*implied*/
			msg.whack.listen.ike_socket_bufsize = optarg_udp_bufsize(logger);
			continue;
		case OPT_IKE_SOCKET_ERRQUEUE:	/* --ike-socket-errqueue yes|no */
			whack_command(&msg, WHACK_LISTEN); /*implied*/
			msg.whack.listen.ike_socket_errqueue = optarg_yn(logger, YN_YES);
			continue;
		case OPT_IKE_SOCKET_ERRQUEUE_TOGGLE:	/* --ike-socket-errqueue-toggle */
			whack_command(&msg, WHACK_LISTEN); /*implied*/
			msg.whack.listen.ike_socket_errqueue_toggle = true;
			continue;

		case OPT_UNLISTEN:	/* --unlisten */
			whack_command(&msg, WHACK_UNLISTEN);
			continue;

		case OPT_REREADSECRETS:	/* --rereadsecrets */
			whack_command(&msg, WHACK_REREADSECRETS);
			continue;
		case OPT_REREADCERTS:	/* --rereadcerts */
			whack_command(&msg, WHACK_REREADCERTS);
			continue;
		case OPT_FETCHCRLS:	/* --fetchcrls */
			whack_command(&msg, WHACK_FETCHCRLS);
			continue;
		case OPT_REREADALL:	/* --rereadall */
			whack_command(&msg, WHACK_REREADALL);
			continue;

		case OPT_PURGEOCSP:	/* --purgeocsp */
			whack_command(&msg, WHACK_PURGEOCSP);
			continue;

		case OPT_STATUS:	/* --status */
			msg.basic.whack_status = true;
			ignore_errors = true;
			continue;

		case OPT_GLOBALSTATUS:	/* --globalstatus */
			whack_command(&msg, WHACK_GLOBALSTATUS);
			ignore_errors = true;
			continue;

		case OPT_CLEARSTATS:	/* --clearstats */
			whack_command(&msg, WHACK_CLEARSTATS);
			continue;

		case OPT_TRAFFICSTATUS:	/* --trafficstatus */
			whack_command(&msg, WHACK_TRAFFICSTATUS);
			ignore_errors = true;
			continue;

		case OPT_SHUNTSTATUS:	/* --shuntstatus */
			whack_command(&msg, WHACK_SHUNTSTATUS);
			ignore_errors = true;
			continue;

		case OPT_ADDRESSPOOLSTATUS:	/* --addresspoolstatus */
			whack_command(&msg, WHACK_ADDRESSPOOLSTATUS);
			ignore_errors = true;
			continue;

		case OPT_CONNECTIONSTATUS:	/* --connectionstatus */
			whack_command(&msg, WHACK_CONNECTIONSTATUS);
			ignore_errors = true;
			continue;

		case OPT_BRIEFCONNECTIONSTATUS:	/* --briefconnectionstatus */
			whack_command(&msg, WHACK_BRIEFCONNECTIONSTATUS);
			ignore_errors = true;
			continue;

		case OPT_FIPSSTATUS:	/* --fipsstatus */
			whack_command(&msg, WHACK_FIPSSTATUS);
			ignore_errors = true;
			continue;

		case OPT_BRIEFSTATUS:	/* --briefstatus */
			whack_command(&msg, WHACK_BRIEFSTATUS);
			ignore_errors = true;
			continue;

		case OPT_PROCESSSTATUS:	/* --processstatus */
			whack_command(&msg, WHACK_PROCESSSTATUS);
			ignore_errors = true;
			continue;

		case OPT_SHOW_STATES:	/* --showstates */
			whack_command(&msg, WHACK_SHOWSTATES);
			ignore_errors = true;
			continue;
#ifdef USE_SECCOMP
		case OPT_SECCOMP_CRASHTEST:	/* --seccomp-crashtest */
			whack_command(&msg, WHACK_SECCOMP_CRASHTEST);
			continue;
#endif

		case OPT_SHUTDOWN:	/* --shutdown */
			msg.basic.whack_shutdown = true;
			continue;
		case OPT_LEAVE_STATE:	/* --leave-state */
			/* see below; --shutdown is ignored */
			whack_command(&msg, WHACK_SHUTDOWN_LEAVE_STATE);
			continue;

		case OPT_OPPO_HERE:	/* --oppohere <ip-address> */
			whack_command(&msg, WHACK_ACQUIRE);
			msg.whack.acquire.local.address = optarg_address_dns(logger, &child_family);
			if (!address_is_specified(msg.whack.acquire.local.address)) {
				/* either :: or 0.0.0.0; unset already rejected */
				address_buf ab;
				optarg_fatal(logger, "invalid address %s",
					     str_address(&msg.whack.acquire.local.address, &ab));
			}
			continue;
		case OPT_OPPO_THERE:	/* --oppothere <ip-address> */
			whack_command(&msg, WHACK_ACQUIRE);
			msg.whack.acquire.remote.address = optarg_address_dns(logger, &child_family);
			if (!address_is_specified(msg.whack.acquire.remote.address)) {
				/* either :: or 0.0.0.0; unset already rejected */
				address_buf ab;
				optarg_fatal(logger, "invalid address %s",
					     str_address(&msg.whack.acquire.remote.address, &ab));
			}
			continue;
		case OPT_OPPO_PROTO:	/* --oppoproto <protocol> */
			whack_command(&msg, WHACK_ACQUIRE);
			msg.whack.acquire.ipproto = optarg_ipproto(logger);
			continue;
		case OPT_OPPO_SPORT:	/* --opposport <port> */
			whack_command(&msg, WHACK_ACQUIRE);
			msg.whack.acquire.local.port = optarg_port(logger);
			continue;
		case OPT_OPPO_DPORT:	/* --oppodport <port> */
			whack_command(&msg, WHACK_ACQUIRE);
			msg.whack.acquire.remote.port = optarg_port(logger);
			continue;
		case OPT_OPPO_LABEL:
			whack_command(&msg, WHACK_ACQUIRE);
			msg.whack.acquire.label = optarg;
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
		case LST_PUBKEYS:	/* --listpubkeys */
			whack_command(&msg, WHACK_LIST);
			msg.whack_list |= LELEM(c - LST_PUBKEYS);
			ignore_errors = true;
			continue;

		case LST_CHECKPUBKEYS:	/* --checkpubkeys */
			whack_command(&msg, WHACK_CHECKPUBKEYS);
			ignore_errors = true;
			continue;

		case LST_ALL:	/* --listall */
			whack_command(&msg, WHACK_LIST);
			msg.whack_list = LIST_ALL; /* most!?! */
			ignore_errors = true;
			continue;

		/* Connection Description options */

		case END_HOST:	/* --host <ip-address> */
			end->we_host = optarg;
			continue;

		case END_ID:	/* --id <identity> */
			end->we_id = optarg;	/* decoded by Pluto */
			continue;

		case END_SENDCERT:	/* --sendcert */
			end->we_sendcert = optarg;
			continue;

		case END_CERT:	/* --cert <path> */
			end->we_cert = optarg;	/* decoded by Pluto */
			continue;

		case END_CKAID:	/* --ckaid <ckaid> */
			end->we_ckaid = optarg;	/* decoded by Pluto */
			continue;

		case END_CA:	/* --ca <distinguished name> */
			end->we_ca = optarg;	/* decoded by Pluto */
			continue;

		case END_IKEPORT:	/* --ikeport <port-number> */
			end->we_ikeport = optarg;
			continue;

		case END_NEXTHOP:	/* --nexthop <ip-address> */
			end->we_nexthop = optarg;
			continue;

		case END_SOURCEIP:	/* --sourceip <ip-address> */
			end->we_sourceip = optarg;
			continue;

		case END_INTERFACE_IP:	/* --interface-ip <ip-address/mask> */
			end->we_interface_ip = optarg;
			continue;

		case END_VTI:	/* --vti <ip-address/mask> */
			end->we_vti = optarg;
			continue;

		/*
		 * --authby secret | rsasig | rsa | ecdsa | null | eaponly
		 *  Note: auth-never cannot be asymmetrical
		 */
		case END_AUTH:
			end->we_auth = optarg;
			continue;

		case END_AUTHEAP:
			end->we_autheap = optarg;
			continue;

		case END_SUBNET: /* --subnet <subnet> | --client <subnet> */
			end->we_subnet = optarg;	/* decoded by Pluto */
			msg.type = KS_TUNNEL;	/* client => tunnel */
			continue;

		/* --clientprotoport <protocol>/<port> */
		case END_CLIENTPROTOPORT:
			end->we_protoport = optarg;
			continue;

		case END_DNSKEYONDEMAND:	/* --dnskeyondemand */
		{
			/* map PUBKEY_DNSONDEMAND to %<ondemand> */
			name_buf sb;
			passert(sparse_short(&keyword_pubkey_names, PUBKEY_DNSONDEMAND, &sb));
			passert(sb.buf != sb.tmp);
			end->we_pubkey = sb.buf; /* points into keyword_pubkey_names */
			continue;
		}

		case END_UPDOWN:	/* --updown <updown> */
			end->we_updown = optarg;
			continue;

		case CD_TO:	/* --to */
			whack_command(&msg, WHACK_ADD);
			/*
			 * Move .right to .left, so further END
			 * options.  Reset what was seen so more
			 * options can be added.
			 */
			if (!seen[END_HOST]) {
				diagw("connection missing --host before --to");
			}

			end = &msg.end[RIGHT_END];
			for (enum opt e = FIRST_END_OPT; e <= LAST_END_OPT; e++) {
				seen[e] = false;
			}
			continue;

		/* --ikev1 --ikev2 --ikev2-propose */
		case CD_IKEv1:
			if (msg.wm_keyexchange != NULL) {
				diagw("connection can no longer have --ikev1 and --ikev2");
			}
			msg.wm_keyexchange = "IKEv1";
			continue;
		case CD_IKEv2:
			if (msg.wm_keyexchange != NULL) {
				diagw("connection can no longer have --ikev1 and --ikev2");
			}
			msg.wm_keyexchange = "IKEv2";
			continue;

		/* --allow-narrowing */
		case CD_NARROWING:
			msg.narrowing = optarg_yn(logger, YN_YES);
			continue;

		/* --dontrekey */
		case CD_DONT_REKEY:
			msg.rekey = YN_NO;
			continue;

		/* --rekey */
		case CD_REAUTH:
			msg.reauth = YN_YES;
			continue;

		case CD_IPTFS: /* --iptfs[={yes,no}] */
			msg.iptfs = optarg_yn(logger, YN_YES);
			continue;
		case CD_IPTFS_FRAGMENTATION: /* --iptfs-fragmentation={yes,no} */
			msg.iptfs_fragmentation = optarg_yn(logger, YN_YES);
			continue;
		case CD_IPTFS_PACKET_SIZE:	/* --iptfs-packet-size */
			msg.wm_iptfs_packet_size = optarg;
			continue;
		case CD_IPTFS_MAX_QUEUE_SIZE: /* --iptfs-max-queue-size */
			msg.wm_iptfs_max_queue_size = optarg;
			continue;
		case CD_IPTFS_DROP_TIME: /* --iptfs-drop-time */
			msg.iptfs_drop_time = optarg_deltatime(logger);
			continue;
		case CD_IPTFS_INIT_DELAY: /* --iptfs-init-delay */
			msg.iptfs_init_delay = optarg_deltatime(logger);
			continue;
		case CD_IPTFS_REORDER_WINDOW: /* --iptfs-reorder-window */
			msg.wm_iptfs_reorder_window = optarg;
			continue;

		case CD_COMPRESS:	/* --compress */
			msg.compress = optarg_yn(logger, YN_YES);
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
			msg.esn = optarg_yne(logger, (msg.esn == YNE_EITHER ? YNE_EITHER :
						      msg.esn == YNE_NO ? YNE_EITHER :
						      YNE_YES));
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
			msg.fragmentation = optarg_sparse(logger, YNF_YES, &ynf_option_names);
			continue;

		/* --nopmtudisc */
		case CD_NOPMTUDISC:
			msg.nopmtudisc = optarg_yn(logger, YN_YES);
			continue;

		/* --decap-dscp */
		case CD_DECAP_DSCP:
			msg.decap_dscp = optarg_yn(logger, YN_YES);
			continue;

		/* --encap-dscp */
		case CD_ENCAP_DSCP:
			msg.encap_dscp = optarg_yn(logger, YN_YES);
			continue;

		/* --aggressive | --aggrmode */
		case CD_AGGRESSIVE:
			msg.aggressive = optarg_yn(logger, YN_YES);
			continue;

		/* --allow-cert-without-san-id */
		case CD_ALLOW_CERT_WITHOUT_SAN_ID:
			msg.require_id_on_certificate = YN_NO;
			continue;

		/* --no-ikepad */
		case CD_IKEPAD:
			msg.ikepad = optarg_yna(logger, YNA_YES);
			continue;

		/* --ignore-peer-dns */
		case CD_IGNORE_PEER_DNS:
			msg.ignore_peer_dns = optarg_yn(logger, YN_YES);
			continue;

		/* --dns-match-id */
		case CD_DNS_MATCH_ID:
			msg.dns_match_id = optarg_yn(logger, YN_YES);
			continue;

		/* --ms-dh-downgrade */
		case CD_MS_DH_DOWNGRADE:
			msg.ms_dh_downgrade = optarg_yn(logger, YN_YES);
			continue;

		case CD_PFS_REKEY_WORKAROUND:	/* --pfs-rekey-workaround[=yes] */
			msg.pfs_rekey_workaround = optarg_yn(logger, YN_YES);
			continue;

		/* --overlapip */
		case CD_OVERLAPIP:
			msg.overlapip = optarg_yn(logger, YN_YES);
			continue;

		/* --sha2-truncbug or --sha2_truncbug */
		case CD_SHA2_TRUNCBUG:
			msg.sha2_truncbug = optarg_yn(logger, YN_YES);
			continue;

		/* --dont-share-lease */
		case CD_DONT_SHARE_LEASE:
			msg.share_lease = YN_NO;
			continue;

		case CD_INTERMEDIATE:		/* --intermediate[=yes] */
			msg.intermediate = optarg_yn(logger, YN_YES);
			continue;

		/* --mobike */
		case CD_MOBIKE:
			msg.mobike = optarg_yn(logger, YN_YES);
			continue;

		case CDS_NEVER_NEGOTIATE_PASS:	/* --pass */
			msg.never_negotiate_shunt = SHUNT_PASS;
			continue;
		case CDS_NEVER_NEGOTIATE_DROP:	/* --drop */
			msg.never_negotiate_shunt = SHUNT_DROP;
			continue;

		case CDS_NEGOTIATION_PASS:	/* --negopass */
			msg.negotiation_shunt = SHUNT_PASS;
			continue;
		case CDS_NEGOTIATION_HOLD:	/* --negohold */
			msg.negotiation_shunt = SHUNT_DROP;
			continue;

		case CDS_FAILURE_NONE:		/* --failnone */
			msg.failure_shunt = SHUNT_NONE;
			continue;
		case CDS_FAILURE_PASS:		/* --failpass */
			msg.failure_shunt = SHUNT_PASS;
			continue;
		case CDS_FAILURE_DROP:		/* --faildrop */
			msg.failure_shunt = SHUNT_DROP;
			continue;

		case CD_RETRANSMIT_TIMEOUT:	/* --retransmit-timeout <seconds> */
			msg.retransmit_timeout = optarg_deltatime(logger);
			continue;

		case CD_RETRANSMIT_INTERVAL:	/* --retransmit-interval <milliseconds> (not seconds) */
			msg.wm_retransmit_interval = optarg;
			continue;

		case CD_IKE_LIFETIME:	/* --ike-lifetime <seconds> */
			msg.ikelifetime = optarg_deltatime(logger);
			continue;

		case CD_IPSEC_LIFETIME:	/* --ipsec-lifetime <seconds> */
			msg.ipsec_lifetime = optarg_deltatime(logger);
			continue;

		case CD_IPSEC_MAX_BYTES:	/* --ipsec-max-bytes <bytes> */
			msg.wm_ipsec_max_bytes = optarg;
			continue;

		case CD_IPSEC_MAX_PACKETS:	/* --ipsec-max-packets <packets> */
			msg.wm_ipsec_max_packets = optarg; /* TODO accept K/M/G/T etc */
			continue;

		case CD_REKEYMARGIN:	/* --rekeymargin <seconds> */
			msg.rekeymargin = optarg_deltatime(logger);
			continue;

		case CD_REKEYFUZZ:	/* --rekeyfuzz <percentage> */
			msg.wm_rekeyfuzz = optarg;
			continue;

		case CD_REPLAY_WINDOW: /* --replay-window <num> */
			msg.wm_replay_window = optarg;
			continue;

		case CD_SENDCA:	/* --sendca */
			msg.wm_sendca = optarg;
			continue;

		case CD_ENCAPSULATION:	/* --encapsulation */
			msg.encapsulation = optarg_yna(logger, YNA_YES);
			continue;

		case CD_NIC_OFFLOAD:  /* --nic-offload */
			msg.nic_offload = optarg_sparse(logger, 0, &nic_offload_option_names);
			continue;

		case CD_NO_NAT_KEEPALIVE:	/* --no-nat-keepalive */
			msg.nat_keepalive = YN_NO;
			continue;
		case CD_NAT_KEEPALIVE:	/* --nat-keepalive {yes,no} */
			msg.nat_keepalive = optarg_yn(logger, YN_YES);
			continue;

		case CD_IKEV1_NATT:	/* --ikev1-natt */
			msg.nat_ikev1_method = optarg_sparse(logger, 0, &nat_ikev1_method_option_names);
			continue;

		case CD_INITIAL_CONTACT:	/* --initial-contact */
			msg.initial_contact = optarg_yn(logger, YN_YES);
			continue;

		case CD_CISCO_UNITY:	/* --cisco-unity */
			msg.wm_cisco_unity = (optarg == NULL ? "yes" : optarg);
			continue;

		case CD_FAKE_STRONGSWAN:	/* --fake-strongswan[=YES|NO] */
			msg.fake_strongswan = optarg_yn(logger, YN_YES);
			continue;

		case CD_DPDDELAY:	/* --dpddelay <seconds> */
			msg.wm_dpddelay = optarg;
			continue;

		case CD_DPDTIMEOUT:	/* --dpdtimeout <seconds> */
			msg.wm_dpdtimeout = optarg;
			continue;

		case CD_OBSOLETE:
			llog(RC_LOG, logger,
			     "obsolete --%s option ignored", optarg_options[optarg_index].name);
			continue;

		case CD_SEND_REDIRECT:	/* --send-redirect */
			msg.send_redirect = optarg_yna(logger, 0/*no-default*/);
			continue;

		case CD_ACCEPT_REDIRECT:	/* --accept-redirect */
			msg.accept_redirect = optarg_yn(logger, 0/*no-default*/);
			continue;

		case CD_ACCEPT_REDIRECT_TO:	/* --accept-redirect-to */
			msg.wm_accept_redirect_to = optarg;
			continue;

		case CD_IKE:	/* --ike <ike_alg1,ike_alg2,...> */
			msg.wm_ike = optarg;
			continue;

		case CD_ESP:	/* --esp <esp_alg1,esp_alg2,...> */
			msg.wm_esp = optarg;
			continue;

		case CD_REMOTE_PEER_TYPE:	/* --remote-peer-type <cisco> */
			msg.wm_remote_peer_type = optarg;
			continue;

		case CD_NM_CONFIGURED:		/* --nm-configured[=yes|no] */
			msg.wm_nm_configured = (optarg == NULL ? "yes" : optarg);
			continue;

		case CD_TCP: /* --tcp */
			if (streq(optarg, "yes"))
				msg.enable_tcp = IKE_TCP_ONLY;
			else if (streq(optarg, "no"))
				msg.enable_tcp = IKE_TCP_NO;
			else if (streq(optarg, "fallback"))
				msg.enable_tcp = IKE_TCP_FALLBACK;
			else
				diagw("--tcp-options are 'yes', 'no' or 'fallback'");
			continue;
		case CD_TCP_REMOTE_PORT:
			msg.tcp_remoteport = optarg_uintmax(logger);
			continue;

		case CD_LABELED_IPSEC:	/* obsolete --labeledipsec */
			/* ignore */
			continue;

		case CD_SEC_LABEL:	/* --sec-label */
			msg.wm_sec_label = optarg;
			continue;


		/* RSASIG/ECDSA need more than a single policy bit */
		case OPT_AUTHBY_PSK:		/* --psk */
			append_str(&authby, ",", "secret");
			continue;
		case OPT_AUTHBY_AUTH_NEVER:	/* --auth-never */
			append_str(&authby, ",", "never");
			continue;
		case OPT_AUTHBY_AUTH_NULL:	/* --auth-null */
			append_str(&authby, ",", "null");
			continue;
		case OPT_AUTHBY_RSASIG: /* --rsasig */
		case OPT_AUTHBY_RSA_SHA1: /* --rsa-sha1 */
		case OPT_AUTHBY_RSA_SHA2: /* --rsa-sha2 */
		case OPT_AUTHBY_RSA_SHA2_256:	/* --rsa-sha2_256 */
		case OPT_AUTHBY_RSA_SHA2_384:	/* --rsa-sha2_384 */
		case OPT_AUTHBY_RSA_SHA2_512:	/* --rsa-sha2_512 */
		case OPT_AUTHBY_ECDSA: /* --ecdsa and --ecdsa-sha2 */
		case OPT_AUTHBY_ECDSA_SHA2_256:	/* --ecdsa-sha2_256 */
		case OPT_AUTHBY_ECDSA_SHA2_384:	/* --ecdsa-sha2_384 */
		case OPT_AUTHBY_ECDSA_SHA2_512:	/* --ecdsa-sha2_512 */
			/* that's the option with "--" stripped */
			append_str(&authby, ",", optarg_options[optarg_index].name);
			continue;

		case CD_CONNIPV4:	/* --ipv4; mimic --ipv6 */
			msg.wm_hostaddrfamily = "ipv4";
			continue;

		case CD_CONNIPV6:	/* --ipv6; mimic ipv4 */
			msg.wm_hostaddrfamily = "ipv6";
			continue;

		case CD_TUNNELIPV4:	/* --tunnelipv4 */
			if (seen[CD_TUNNELIPV6]) {
				diagw("--tunnelipv4 conflicts with --tunnelipv6");
			}
			if (child_family.used_by != NULL) {
				optarg_fatal(logger, "must precede %s", child_family.used_by);
			}
			child_family.used_by = optarg_options[optarg_index].name;
			child_family.type = &ipv4_info;
			continue;

		case CD_TUNNELIPV6:	/* --tunnelipv6 */
			if (seen[CD_TUNNELIPV4]) {
				diagw("--tunnelipv6 conflicts with --tunnelipv4");
			}
			if (child_family.used_by != NULL) {
				optarg_fatal(logger, "must precede %s", child_family.used_by);
			}
			child_family.used_by = optarg_options[optarg_index].name;
			child_family.type = &ipv6_info;
			continue;

		case END_XAUTHSERVER:	/* --xauthserver[={yes,no}] */
			end->xauthserver = optarg_yn(logger, YN_YES);
			continue;

		case END_XAUTHCLIENT:	/* --xauthclient[={yes,no}] */
			end->xauthclient =  optarg_yn(logger, YN_YES);
			continue;

		case OPT_USERNAME:	/* --username, was --xauthname */
			/*
			 * we can't tell if this is going to be --initiate, or
			 * if this is going to be an conn definition, so do
			 * both actions
			 */
			end->we_xauthusername = optarg;
			/* ??? why does this length include NUL? */
			/* XXX: no clue; but >0 does imply being present */
			usernamelen = jam_str(xauthusername, sizeof(xauthusername), optarg) - xauthusername + 1;
			continue;

		case OPT_XAUTHPASS:	/* --xauthpass */
			/* ??? why does this length include NUL? */
			/* XXX: no clue; but >0 does imply being present */
			xauthpasslen = jam_str(xauthpass, sizeof(xauthpass), optarg) - xauthpass + 1;
			continue;

		case END_CAT:		/* --cat */
			end->cat = optarg_yn(logger, YN_YES);
			continue;

		case END_ADDRESSPOOL:	/* --addresspool */
			end->we_addresspool = optarg;
			continue;

		case END_MODECFGCLIENT:	/* --modeconfigclient */
			end->modecfgclient = optarg_yn(logger, YN_YES);
			continue;
		case END_MODECFGSERVER:	/* --modeconfigserver */
			end->modecfgserver = optarg_yn(logger, YN_YES);
			continue;
		case CD_MODECFGPULL:	/* --modecfgpull */
			msg.modecfgpull = optarg_yn(logger, YN_YES);
			continue;

		case CD_MODECFGDNS:	/* --modecfgdns */
			msg.wm_modecfgdns = optarg;
			continue;
		case CD_MODECFGDOMAINS:	/* --modecfgdomains */
			msg.wm_modecfgdomains = optarg;
			continue;
		case CD_MODECFGBANNER:	/* --modecfgbanner */
			msg.wm_modecfgbanner = optarg;
			continue;

		case CD_CONN_MARK:      /* --conn-mark */
			msg.wm_mark = optarg;
			continue;
		case CD_CONN_MARK_IN:      /* --conn-mark-in */
			msg.wm_mark_in = optarg;
			continue;
		case CD_CONN_MARK_OUT:      /* --conn-mark-out */
			msg.wm_mark_out = optarg;
			continue;

		case CD_VTI_INTERFACE:      /* --vti-interface=IFACE */
			msg.wm_vti_interface = optarg;
			continue;
		case CD_VTI_ROUTING:	/* --vti-routing[=yes|no] */
			msg.vti_routing = optarg_yn(logger, YN_YES);
			continue;
		case CD_VTI_SHARED:	/* --vti-shared[=yes|no] */
			msg.vti_shared = optarg_yn(logger, YN_YES);
			continue;

		case CD_IPSEC_INTERFACE:      /* --ipsec-interface=... */
			msg.wm_ipsec_interface = optarg;
			continue;

		case CD_XAUTHBY:	/* --xauthby */
			msg.xauthby = optarg_sparse(logger, 0, &xauthby_names);
			continue;

		case CD_XAUTHFAIL:	/* --xauthfail */
			msg.xauthfail = optarg_sparse(logger, 0, &xauthfail_names);
			continue;

		case CD_METRIC:	/* --metric */
			msg.metric = optarg_uintmax(logger);
			continue;

		case CD_MTU:	/* --mtu */
			msg.wm_mtu = optarg;
			continue;

		case CD_PRIORITY:	/* --priority */
			msg.wm_priority = optarg;
			continue;

		case CD_TFC:	/* --tfc */
			msg.wm_tfc = optarg;
			continue;

		case CD_SEND_ESP_TFC_PADDING_NOT_SUPPORTED:	/* --send-esp-tfc-padding-not-supported */
			msg.send_esp_tfc_padding_not_supported =
				optarg_yn(logger, YN_YES);
			continue;

		case CD_REJECT_SIMULTANEOUS_IKE_AUTH: /* --reject-simultaneous-ike-auth */
			msg.reject_simultaneous_ike_auth = optarg_yn(logger, YN_YES);
			continue;

		case CD_PFS:	/* --pfs */
			msg.pfs = optarg_yn(logger, YN_YES);
			continue;

		case CD_NFLOG_GROUP:	/* --nflog-group */
			msg.wm_nflog_group = optarg;
			continue;

		case CD_REQID:	/* --reqid */
			msg.wm_reqid = optarg;
			continue;

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
			msg.whack_debugging = lmod_clr(msg.whack_debugging, DBG_mask);
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
			msg.whack_debugging = lmod_clr(msg.whack_debugging, DBG_mask);
			msg.whack_debugging = lmod_set(msg.whack_debugging, DBG_all);
			continue;
		case DBGOPT_DEBUG:	/* --debug */
			optarg_debug_lmod(OPTARG_DEBUG_YES, &msg.whack_debugging);
			continue;
		case DBGOPT_NO_DEBUG:	/* --no-debug */
			optarg_debug_lmod(OPTARG_DEBUG_NO, &msg.whack_debugging);
			continue;

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

		case DBGOPT_MAGIC:	/* --magic <number> */
		{
			/*
			 * Hack for testing:
			 *
			 * When <number> is zero, force .magic to the
			 * build's WHACK_MAGIC number.  Else force
			 * .magic to the given value.
			 */
			unsigned magic = optarg_uintmax(logger);
			msg.basic.magic = (magic == 0 ? whack_magic() : magic);
			continue;
		}
		}

		/*
		 * Since cases in above switch "continue" the loop;
		 * reaching here is BAD.
		 */
		bad_case(c);
	}

	if (optind != argc) {
		/*
		 * If you see this message unexpectedly, perhaps the
		 * case for the previous option ended with "break"
		 * instead of "continue"
		 */
		diagq("unexpected argument", argv[optind]);
	}

	msg.authby = authby;

	/*
	 * For each possible form of the command, figure out if an argument
	 * suggests whether that form was intended, and if so, whether all
	 * required information was supplied.
	 */

	/*
	 * Check acquire (opportunistic initiation) simulation
	 * request.
	 */
	if (msg.whack_command == WHACK_ACQUIRE) {
		if (!seen[OPT_OPPO_HERE] ||
		    !seen[OPT_OPPO_THERE]) {
			diagw("acquire (opportunistic initiation) simulation requires both --oppohere and --oppothere");
		}
	}

	/* check connection description */
	if (opts_seen & CONN_OPT_SEEN) {
		if (!seen[CD_TO]) {
			diagw("connection description option, but no --to");
		}

		/* set by --to! */
		PASSERT(logger, msg.whack_command == WHACK_ADD);

		if (!seen[END_HOST]) {
			/* must be after --to as --to scrubs seen[END_*] */
			diagw("connection missing --host after --to");
		}

	}

	/*
	 * Does --redirect-to have a matching command?  When it
	 * doesn't it must be an active redirect.
	 *
	 * --to sets WHACK_ADD and global-redirect-to sets
	 * --WHACK_GLOBAL_REDIRECT.
	 */
	if (msg.wm_redirect_to != NULL) {
		switch (msg.whack_command) {
		case 0:
			whack_command(&msg, WHACK_ACTIVE_REDIRECT);
			break;
		case WHACK_ADD:
		case WHACK_ACTIVE_REDIRECT:
		case WHACK_GLOBAL_REDIRECT:
			break;
		default:
			diagw("unexpected --redirect-to");
		}
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
	    seen[OPT_SUSPEND] ||
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

	if (!(msg.basic.whack_status ||
	      msg.basic.whack_shutdown ||
	      msg.whack_command != 0 ||
	      msg.whack_key ||
	      !lmod_empty(msg.whack_debugging) ||
	      msg.impairments.len > 0)) {
		diagw("no action specified; try --help for hints");
	}

	if (msg.whack_command == WHACK_SHUTDOWN_LEAVE_STATE) {
		/* --leave-state overrides basic shutdown */
		msg.basic.whack_shutdown = false;
	}

	int exit_status = whack_send_msg(&msg,
					 (ctlsocket == NULL ? DEFAULT_CTL_SOCKET : ctlsocket),
					 xauthusername, xauthpass,
					 usernamelen, xauthpasslen,
					 logger);

	if (ignore_errors)
		return 0;

	return exit_status;
}
