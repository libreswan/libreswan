/* Structure of messages from whack to Pluto proper.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
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
 *
 */

#ifndef _WHACK_H
#define _WHACK_H

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>

/* Since the message remains on one host, native representation is used.
 * Think of this as horizontal microcode: all selected operations are
 * to be done (in the order declared here).
 *
 * MAGIC is used to help detect version mismatches between whack and Pluto.
 * Whenever the interface (i.e. this struct) changes in form or
 * meaning, change this value (probably by changing the last number).
 *
 * If the command only requires basic actions (status or shutdown),
 * it is likely that the relevant part of the message changes less frequently.
 * Whack uses WHACK_BASIC_MAGIC in those cases.
 *
 * NOTE: no value of WHACK_BASIC_MAGIC may equal any value of WHACK_MAGIC.
 * Otherwise certain version mismatches will not be detected.
 */

#define WHACK_BASIC_MAGIC (((((('w' << 8) + 'h') << 8) + 'k') << 8) + 25)
#define WHACK_MAGIC (((((('o' << 8) + 'h') << 8) + 'k') << 8) + 40)

/* struct whack_end is a lot like connection.h's struct end
 * It differs because it is going to be shipped down a socket
 * and because whack is a separate program from pluto.
 */
struct whack_end {
	char *id;       /* id string (if any) -- decoded by pluto */
	char *cert;     /* path string (if any) -- loaded by pluto  */
	char *ca;       /* distinguished name string (if any) -- parsed by pluto */
	char *groups;   /* access control groups (if any) -- parsed by pluto */

	enum keyword_host host_type;
	ip_address host_addr,
		   host_nexthop,
		   host_srcip;
	ip_subnet client;

	bool key_from_DNS_on_demand;
	bool has_client;
	bool has_client_wildcard;
	bool has_port_wildcard;
	char *updown;           /* string */
	u_int16_t host_port;    /* host order  (for IKE communications) */
	u_int16_t port;         /* host order */
	u_int8_t protocol;
	char *virt;
	ip_range pool_range;    /* store start of v4 addresspool */
	bool xauth_server;      /* for XAUTH */
	bool xauth_client;
	char *xauth_name;
	bool modecfg_server;    /* for MODECFG */
	bool modecfg_client;
	unsigned int tundev;
	enum certpolicy sendcert;
	enum ipsec_cert_type certtype;

	char *host_addr_name;   /* DNS name for host, of hosttype==IPHOSTNAME*/
	                        /* pluto will convert to IP address again,
	                         * if this is non-NULL when conn fails.
	                         */
};

enum whack_opt_set {
	WHACK_ADJUSTOPTIONS=0,          /* normal case */
	WHACK_SETDUMPDIR=1,             /* string1 contains new dumpdir */
	WHACK_STARTWHACKRECORD=2,       /* string1 contains file to write options to */
	WHACK_STOPWHACKRECORD=3,        /* turn off recording to file */
};

struct whack_message {
	unsigned int magic;

	/* for WHACK_STATUS: */
	bool whack_status;

	/* for WHACK_SHUTDOWN */
	bool whack_shutdown;

	/* END OF BASIC COMMANDS
	 * If you change anything earlier in this struct, update WHACK_BASIC_MAGIC.
	 */

	/* name is used in connection and initiate */
	size_t name_len; /* string 1 */
	char *name;

	/* for WHACK_OPTIONS: */

	bool whack_options;

	lset_t debugging;

	/* for WHACK_CONNECTION */

	bool whack_connection;
	bool whack_async;

	lset_t policy;
	time_t sa_ike_life_seconds;
	time_t sa_ipsec_life_seconds;
	time_t sa_rekey_margin;
	unsigned long sa_rekey_fuzz;
	unsigned long sa_keying_tries;

	/* For IKEv1 RFC 3706 - Dead Peer Detection */
	time_t dpd_delay;
	time_t dpd_timeout;
	enum dpd_action dpd_action;
	int dpd_count;

	/* Cisco interop:  remote peer type*/
	enum keyword_remotepeertype remotepeertype;

	/* Force the use of NAT-T on a connection */
	bool forceencaps;

	/* Option to allow per-conn setting of sending of NAT-T keepalives - default is enabled  */
	bool nat_keepalive;

	/* Option to allow sending INITIAL-CONTACT payload - default is disabled */
	bool initial_contact;

	/*
	 * Option to just send the Cisco VID - the other end will behave
	 * differently (ModeCFG + RSA?)
	 */
	bool cisco_unity;

	/* send our own libreswan vendorid or not */
	bool send_vendorid;

	bool sha2_truncbug;

	/* Checking if this connection is configured by Network Manager*/
	bool nmconfigured;

	/* XAUTH Authentication can be file (default) PAM or 'alwaysok' */
	enum keyword_xauthby xauthby;

	/* XAUTH failure mode can be hard (default) or soft */
	enum keyword_xauthfail xauthfail;

	/* Force the MTU for this connection */
	int connmtu;

	int sa_priority;
	int sa_reqid;

	bool loopback;
	bool labeled_ipsec;
	char *policy_label;

	/*  note that each end contains string 2/5.id, string 3/6 cert,
	 *  and string 4/7 updown
	 */
	struct whack_end left;
	struct whack_end right;

	/* note: if the client is the gateway, the following must be equal */
	sa_family_t addr_family;        /* between gateways */
	sa_family_t tunnel_addr_family; /* between clients */

	char *ike;                      /* ike algo string (separated by commas) */
	char *pfsgroup;                 /* pfsgroup will be "encapsulated" in esp string for pluto */
	char *esp;                      /* esp algo string (separated by commas) */

	/* for WHACK_KEY: */
	bool whack_key;
	bool whack_addkey;
	char *keyid;    /* string 8 */
	enum pubkey_alg pubkey_alg;
	chunk_t keyval; /* chunk */

	/* for WHACK_MYID: */
	bool whack_myid;
	char *myid; /* string 7 */

	/* for WHACK_ROUTE: */
	bool whack_route;

	/* for WHACK_UNROUTE: */
	bool whack_unroute;

	/* for WHACK_INITIATE: */
	bool whack_initiate;

	/* for WHACK_OPINITIATE */
	bool whack_oppo_initiate;
	ip_address oppo_my_client, oppo_peer_client;

	/* for WHACK_TERMINATE: */
	bool whack_terminate;

	/* for WHACK_DELETE: */
	bool whack_delete;

	/* for WHACK_DELETESTATE: */
	bool whack_deletestate;
	long unsigned int whack_deletestateno;

	/* for WHACK_LISTEN: */
	bool whack_listen, whack_unlisten;

	/* for WHACK_CRASH - note if a remote peer is known to have rebooted */
	bool whack_crash;
	ip_address whack_crash_peer;

	/* for WHACK_LIST */
	bool whack_utc;
	bool whack_check_pub_keys;
	lset_t whack_list;

	/* for WHACK_REREAD */
	u_char whack_reread;

	/* for connalias string */
	char *connalias;

	/* for MODECFG */
	ip_address modecfg_dns1;
	ip_address modecfg_dns2;
	char *modecfg_domain;
	char *modecfg_banner;

	/* what metric to put on ipsec routes */
	int metric;

	char *dnshostname;

	/* for use with general option adjustments */
	enum whack_opt_set opt_set;
	char *string1;
	char *string2;
	char *string3;

	/* space for strings (hope there is enough room):
	 * Note that pointers don't travel on wire.
	 *  1 connection name [name_len]
	 *  2 left's name [left.host.name.len]
	 *  3 left's cert
	 *  4 left's ca
	 *  5 left's groups
	 *  6 left's updown
	 *  7 left's virt
	 *  8 right's name [left.host.name.len]
	 *  9 right's cert
	 * 10 right's ca
	 * 11 right's groups
	 * 12 right's updown
	 * 13 right's virt
	 * 14 keyid
	 * 15 myid
	 * 16 ike
	 * 17 esp
	 * 18 left.xauth_name
	 * 19 right.xauth_name
	 * 20 connalias
	 * 21 left.host_addr_name
	 * 22 right.host_addr_name
	 * 23 genstring1  - used with opt_set
	 * 24 genstring2
	 * 25 genstring3
	 * 26 dnshostname
	 * 27 policy_label if compiled with with LABELED_IPSEC
	 * plus keyval (limit: 8K bits + overhead), a chunk.
	 */
	size_t str_size;
	unsigned char string[4096];
};

/* options of whack --list*** command */

#define LIST_NONE       0x0000  /* don't list anything */
#define LIST_PUBKEYS    0x0001  /* list all public keys */
#define LIST_CERTS      0x0002  /* list all host/user certs */
#define LIST_CACERTS    0x0004  /* list all ca certs */
#define LIST_ACERTS     0x0008  /* list all attribute certs */
#define LIST_AACERTS    0x0010  /* list all aa certs */
/* #define LIST_OCSPCERTS	0x0020	obsoleted, was: list all ocsp certs */
#define LIST_GROUPS     0x0020  /* list all access control groups */
#define LIST_CRLS       0x0040  /* list all crls */
/* #define LIST_OCSP	0x0100	obsoleted, was list all ocsp cache entries */
#define LIST_PSKS       0x0080  /* list all preshared keys (by name) */
#define LIST_EVENTS     0x0100  /* list all queued events */

/* omit events from listing options */
#define LIST_ALL        LRANGES(LIST_PUBKEYS, LIST_PSKS)  /* all list options */

/* options of whack --reread*** command */

#define REREAD_NONE       0x00                                  /* don't reread anything */
#define REREAD_SECRETS    0x01                                  /* reread /etc/ipsec.secrets */
#define REREAD_CACERTS    0x02                                  /* reread certs in /etc/ipsec.d/cacerts */
#define REREAD_AACERTS    0x04                                  /* reread certs in /etc/ipsec.d/aacerts */
/* #define REREAD_OCSPCERTS  0x08	obsoleted, was reread certs in /etc/ipsec.d/ocspcerts */
#define REREAD_ACERTS     0x08                                  /* reread certs in /etc/ipsec.d/acerts */
#define REREAD_CRLS       0x10                                  /* reread crls in /etc/ipsec.d/crls */
#define REREAD_ALL      LRANGES(REREAD_SECRETS, REREAD_CRLS)    /* all reread options */

struct whackpacker {
	struct whack_message *msg;
	unsigned char        *str_roof;
	unsigned char        *str_next;
	int n;
};

extern err_t pack_whack_msg(struct whackpacker *wp);
extern err_t unpack_whack_msg(struct whackpacker *wp);
extern void clear_end(struct whack_end *e);

extern size_t whack_get_secret(char *buf, size_t bufsize);
extern int whack_get_value(char *buf, size_t bufsize);

extern bool lsw_alias_cmp(const char *needle, const char *haystack);
extern void whack_process(int whackfd, const struct whack_message msg);

#endif /* _WHACK_H */
