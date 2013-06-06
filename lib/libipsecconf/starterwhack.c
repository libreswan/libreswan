/* Libreswan whack functions to communicate with pluto (whack.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "ipsecconf/starterwhack.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterlog.h"

#include "socketwrapper.h"

#ifndef _LIBRESWAN_H
#include <libreswan.h>  /** FIXME: ugly include lines **/
#include "constants.h"
#endif

#include "lswalloc.h"
#include "lswlog.h"
#include "whack.h"
#include "id.h"

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

static int send_reply(int sock, char *buf, ssize_t len)
{
	/* send the secret to pluto */
	if (write(sock, buf, len) != len) {
		int e = errno;

		starter_log(LOG_LEVEL_ERR, "whack: write() failed (%d %s)\n",
			    e, strerror(e));
		return RC_WHACK_PROBLEM;
	}
	return 0;
}

int starter_whack_read_reply(int sock,
			     char xauthname[XAUTH_MAX_NAME_LENGTH],
			     char xauthpass[XAUTH_MAX_PASS_LENGTH],
			     int xauthnamelen,
			     int xauthpasslen)
{
	char buf[4097]; /* arbitrary limit on log line length */
	char *be = buf;
	int ret = 0;

	for (;; ) {
		char *ls = buf;
		ssize_t rl = read(sock, be, (buf + sizeof(buf) - 1) - be);

		if (rl < 0) {
			int e = errno;

			fprintf(stderr, "whack: read() failed (%d %s)\n", e, strerror(
					e));
			return RC_WHACK_PROBLEM;
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

			le++;   /* include NL in line */
			if (isatty(STDOUT_FILENO) &&
			    write(STDOUT_FILENO, ls, le - ls) == -1) {
				int e = errno;
				starter_log(LOG_LEVEL_ERR,
					    "whack: write() starterwhack.c:124 failed (%d %s), and ignored.\n",
					    e, strerror(e));
			}
			/* figure out prefix number
			 * and how it should affect our exit status
			 */
			{
				unsigned long s = strtoul(ls, NULL, 10);

				switch (s) {
				case RC_COMMENT:
				case RC_LOG:
					/* ignore */
					break;
				case RC_SUCCESS:
					/* be happy */
					ret = 0;
					break;

				case RC_ENTERSECRET:
					if (xauthpasslen == 0) {
						xauthpasslen =
							whack_get_secret(
								xauthpass,
								XAUTH_MAX_PASS_LENGTH);
					}
					if (xauthpasslen >
					    XAUTH_MAX_PASS_LENGTH) {        /* for input >= 128, xauthpasslen would be 129 */
						xauthpasslen =
							XAUTH_MAX_PASS_LENGTH;
						starter_log(LOG_LEVEL_ERR,
							    "xauth password cannot be >= %d chars",
							    XAUTH_MAX_PASS_LENGTH);
					}
					ret = send_reply(sock, xauthpass,
							 xauthpasslen);
					if (ret != 0)
						return ret;

					break;

				case RC_XAUTHPROMPT:
					if (xauthnamelen == 0) {
						xauthnamelen = whack_get_value(
							xauthname,
							XAUTH_MAX_NAME_LENGTH);
					}
					if (xauthnamelen >
					    XAUTH_MAX_NAME_LENGTH) {        /* for input >= 128, xauthnamelen would be 129 */
						xauthnamelen =
							XAUTH_MAX_NAME_LENGTH;
						starter_log(LOG_LEVEL_ERR,
							    "xauth name cannot be >= %d chars",
							    XAUTH_MAX_NAME_LENGTH);
					}
					ret = send_reply(sock, xauthname,
							 xauthnamelen);
					if (ret != 0)
						return ret;

					break;

				/* case RC_LOG_SERIOUS: */
				default:
					/* pass through */
					ret = s;
					break;
				}
			}
			ls = le;
		}
	}
	return ret;
}

static int send_whack_msg(struct whack_message *msg, char *ctlbase)
{
	struct sockaddr_un ctl_addr =
	{ .sun_family = AF_UNIX };
	int sock;
	ssize_t len;
	struct whackpacker wp;
	err_t ugh;
	int ret;

	/* copy socket location */
	strncpy(ctl_addr.sun_path, ctlbase, sizeof(ctl_addr.sun_path));

	/**
	 * Pack strings
	 */
	wp.msg = msg;
	wp.str_next = (unsigned char *)msg->string;
	wp.str_roof = (unsigned char *)&msg->string[sizeof(msg->string)];

	ugh = pack_whack_msg(&wp);

	if (ugh) {
		starter_log(LOG_LEVEL_ERR,
			    "send_wack_msg(): can't pack strings: %s", ugh);
		return -1;
	}

	len = wp.str_next - (unsigned char *)msg;

	/**
	 * Connect to pluto ctl
	 */
	sock = safe_socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		starter_log(LOG_LEVEL_ERR, "socket() failed: %s",
			    strerror(errno));
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&ctl_addr,
		    offsetof(struct sockaddr_un,
			     sun_path) + strlen(ctl_addr.sun_path)) < 0) {
		starter_log(LOG_LEVEL_ERR, "connect(pluto_ctl) failed: %s",
			    strerror(errno));
		close(sock);
		return -1;
	}

	/**
	 * Send message
	 */
	if (write(sock, msg, len) != len) {
		starter_log(LOG_LEVEL_ERR, "write(pluto_ctl) failed: %s",
			    strerror(errno));
		close(sock);
		return -1;
	}

	/**
	 * read reply
	 */
	{
		char xauthname[XAUTH_MAX_NAME_LENGTH];
		char xauthpass[XAUTH_MAX_PASS_LENGTH];

		ret =
			starter_whack_read_reply(sock, xauthname, xauthpass, 0,
						 0);
		close(sock);
	}

	return ret;
}

static void init_whack_msg(struct whack_message *msg)
{
	memset(msg, 0, sizeof(struct whack_message));
	msg->magic = WHACK_MAGIC;
}

static char *connection_name(struct starter_conn *conn)
{
	/**
	 * If connection name is '%auto', create a new name like conn_xxxxx
	 */
	static char buf[32];

	if (strcmp(conn->name, "%auto") == 0) {
		sprintf(buf, "conn_%ld", conn->id);
		return buf;
	} else {
		return conn->name;
	}
}

static void set_whack_end(struct starter_config *cfg,
			  char *lr,
			  struct whack_end *w,
			  struct starter_end *l)
{
	w->id = l->id;
	w->host_type = l->addrtype;

	switch (l->addrtype) {
	case KH_DEFAULTROUTE:
		w->host_addr = cfg->dr;
		if (addrtypeof(&w->host_addr) == 0)
			w->host_addr = *aftoinfo(l->addr_family)->any;
		break;

	case KH_IPADDR:
	case KH_IFACE:
		w->host_addr = l->addr;
		break;

	case KH_IPHOSTNAME:
		/* note: we always copy the name string below */
		anyaddr(l->addr_family, &w->host_addr);
		break;

	case KH_OPPO:
	case KH_GROUP:
	case KH_OPPOGROUP:
		/* policy should have been set to OPPO */
		anyaddr(l->addr_family, &w->host_addr);
		break;

	case KH_ANY:
		anyaddr(l->addr_family, &w->host_addr);
		break;

	default:
		printf("%s: do something with host case: %d\n", lr,
		       l->addrtype);
		break;
	}
	w->host_addr_name = l->strings[KSCF_IP];

	switch (l->nexttype) {
	case KH_DEFAULTROUTE:
		w->host_nexthop = cfg->dnh;
		break;

	case KH_IPADDR:
		w->host_nexthop = l->nexthop;
		break;

	case KH_NOTSET:  /* acceptable to not set nexthop */
		/* but, get the family set up right
		 * XXX the nexthop type has to get into the whack message!
		 *
		 */
		anyaddr(addrtypeof(&l->addr), &w->host_nexthop);
		break;

	default:
		printf("%s: do something with nexthop case: %d\n", lr,
		       l->nexttype);
		break;
	}

	if (!isanyaddr(&l->sourceip))
		w->host_srcip = l->sourceip;

	w->has_client = l->has_client;
	if (l->has_client)
		w->client = l->subnet;
	else
		w->client.addr.u.v4.sin_family = l->addr_family;
	w->updown = l->strings[KSCF_UPDOWN];
	w->host_port = IKE_UDP_PORT;
	w->has_client_wildcard = l->has_client_wildcard;
	w->has_port_wildcard   = l->has_port_wildcard;

	w->cert = l->cert;
	w->ca   = l->ca;
	if (l->options_set[KNCF_SENDCERT])
		w->sendcert = l->options[KNCF_SENDCERT];
	else
		w->sendcert = cert_alwayssend;

	w->updown = l->updown;
	w->virt   = NULL;
	w->protocol = l->protocol;
	w->port = l->port;
	w->virt = l->virt;
	w->key_from_DNS_on_demand = l->key_from_DNS_on_demand;

#ifdef XAUTH
	if (l->options_set[KNCF_XAUTHSERVER])
		w->xauth_server = l->options[KNCF_XAUTHSERVER];
	if (l->options_set[KNCF_XAUTHCLIENT])
		w->xauth_client = l->options[KNCF_XAUTHCLIENT];
	if (l->strings_set[KSCF_XAUTHUSERNAME])
		w->xauth_name = l->strings[KSCF_XAUTHUSERNAME];

# ifdef MODECFG
	if (l->options_set[KNCF_MODECONFIGSERVER])
		w->modecfg_server = l->options[KNCF_MODECONFIGSERVER];
	if (l->options_set[KNCF_MODECONFIGCLIENT])
		w->modecfg_client = l->options[KNCF_MODECONFIGCLIENT];
	w->pool_range = l->pool_range;
# endif
#endif
}

static int starter_whack_add_pubkey(struct starter_config *cfg,
				    struct starter_conn *conn,
				    struct starter_end *end, const char *lr)
{
	const char *err;
	char keyspace[1024 + 4];
	struct whack_message msg;
	int ret;

	ret = 0;

	init_whack_msg(&msg);

	msg.whack_key = TRUE;
	msg.pubkey_alg = PUBKEY_ALG_RSA;
	if (end->id && end->rsakey1) {
		msg.keyid = end->id;

		switch (end->rsakey1_type) {
		case PUBKEY_DNS:
		case PUBKEY_DNSONDEMAND:
			starter_log(LOG_LEVEL_DEBUG,
				    "conn %s/%s has key from DNS",
				    connection_name(conn), lr);
			break;

		case PUBKEY_CERTIFICATE:
			starter_log(LOG_LEVEL_DEBUG,
				    "conn %s/%s has key from certificate",
				    connection_name(conn), lr);
			break;

		case PUBKEY_NOTSET:
			break;

		case PUBKEY_PREEXCHANGED:
			err = atobytes((char *)end->rsakey1, 0, keyspace,
				       sizeof(keyspace),
				       &msg.keyval.len);
			if (err) {
				starter_log(LOG_LEVEL_ERR,
					    "conn %s/%s: rsakey malformed [%s]",
					    connection_name(conn), lr, err);
				return 1;
			} else {
				msg.keyval.ptr = (unsigned char *)keyspace;
				ret = send_whack_msg(&msg, cfg->ctlbase);
			}
		}
	}

	if (ret < 0)
		return ret;

	init_whack_msg(&msg);

	msg.whack_key = TRUE;
	msg.pubkey_alg = PUBKEY_ALG_RSA;
	if (end->id && end->rsakey2) {
		/* printf("addkey2: %s\n", lr); */

		msg.keyid = end->id;
		switch (end->rsakey2_type) {
		case PUBKEY_NOTSET:
		case PUBKEY_DNS:
		case PUBKEY_DNSONDEMAND:
		case PUBKEY_CERTIFICATE:
			break;

		case PUBKEY_PREEXCHANGED:
			err = atobytes((char *)end->rsakey2, 0, keyspace,
				       sizeof(keyspace),
				       &msg.keyval.len);
			if (err) {
				starter_log(LOG_LEVEL_ERR,
					    "conn %s/%s: rsakey malformed [%s]",
					    connection_name(conn), lr, err);
				return 1;
			} else {
				msg.keyval.ptr = (unsigned char *)keyspace;
				return send_whack_msg(&msg, cfg->ctlbase);
			}
		}
	}
	return 0;
}

static int starter_whack_basic_add_conn(struct starter_config *cfg,
					struct starter_conn *conn)
{
	struct whack_message msg;
	int r;

	init_whack_msg(&msg);

	msg.whack_connection = TRUE;
	msg.whack_delete = TRUE;      /* always do replace for now */
	msg.name = connection_name(conn);

	msg.addr_family = conn->left.addr_family;
	msg.tunnel_addr_family = conn->left.addr_family;

	if (conn->right.addrtype == KH_IPHOSTNAME)
		msg.dnshostname = conn->right.strings[KSCF_IP];

	msg.sa_ike_life_seconds = conn->options[KBF_IKELIFETIME];
	msg.sa_ipsec_life_seconds = conn->options[KBF_SALIFETIME];
	msg.sa_rekey_margin = conn->options[KBF_REKEYMARGIN];
	msg.sa_rekey_fuzz = conn->options[KBF_REKEYFUZZ];
	msg.sa_keying_tries = conn->options[KBF_KEYINGTRIES];

	msg.policy = conn->policy;

	msg.connalias = conn->connalias;

	msg.metric = conn->options[KBF_METRIC];

	if (conn->options_set[KBF_CONNMTU])
		msg.connmtu   = conn->options[KBF_CONNMTU];

	if (conn->options_set[KBF_DPDDELAY] &&
	    conn->options_set[KBF_DPDTIMEOUT]) {
		msg.dpd_delay   = conn->options[KBF_DPDDELAY];
		msg.dpd_timeout = conn->options[KBF_DPDTIMEOUT];
		if (conn->options_set[KBF_DPDACTION])
			msg.dpd_action = conn->options[KBF_DPDACTION];

		if (conn->options_set[KBF_REKEY] && conn->options[KBF_REKEY] ==
		    FALSE) {
			if ( (conn->options[KBF_DPDACTION] ==
			      DPD_ACTION_RESTART_BY_PEER ||
			      conn->options[KBF_DPDACTION] ==
			      DPD_ACTION_RESTART)) {
				starter_log(LOG_LEVEL_ERR,
					    "conn: \"%s\" warning dpdaction cannot be 'restart' or 'restart_by_peer' when rekey=no - defaulting to 'hold'",
					    conn->name);
				msg.dpd_action = DPD_ACTION_HOLD;
			}
		}
	} else {
		if (conn->options_set[KBF_DPDDELAY]  ||
		    conn->options_set[KBF_DPDTIMEOUT] ||
		    conn->options_set[KBF_DPDACTION]) {
			starter_log(LOG_LEVEL_ERR,
				    "conn: \"%s\" warning dpd settings are ignored unless both dpdtimeout= and dpddelay= are set",
				    conn->name);
		}
	}
#ifdef NAT_TRAVERSAL
	if (conn->options_set[KBF_FORCEENCAP])
		msg.forceencaps = conn->options[KBF_FORCEENCAP];
	if (conn->options_set[KBF_NAT_KEEPALIVE])
		msg.nat_keepalive = conn->options[KBF_NAT_KEEPALIVE];
	else
		msg.nat_keepalive = TRUE;
#endif

	if (conn->options_set[KBF_INITIAL_CONTACT])
		msg.initial_contact = conn->options[KBF_INITIAL_CONTACT];

	/*Cisco interop : remote peer type*/
	if (conn->options_set[KBF_REMOTEPEERTYPE])
		msg.remotepeertype = conn->options[KBF_REMOTEPEERTYPE];

	if (conn->options_set[KBF_SHA2_TRUNCBUG])
		msg.sha2_truncbug = conn->options[KBF_SHA2_TRUNCBUG];

#ifdef HAVE_NM
	/*Network Manager support*/
	if (conn->options_set[KBF_NMCONFIGURED])
		msg.nmconfigured = conn->options[KBF_NMCONFIGURED];

#endif

#ifdef HAVE_LABELED_IPSEC
	/*Labeled ipsec support*/
	if (conn->options_set[KBF_LOOPBACK])
		msg.loopback = conn->options[KBF_LOOPBACK];
	starter_log(LOG_LEVEL_DEBUG, "conn: \"%s\" loopback=%d", conn->name,
		    msg.loopback);

	if (conn->options_set[KBF_LABELED_IPSEC])
		msg.labeled_ipsec = conn->options[KBF_LABELED_IPSEC];
	starter_log(LOG_LEVEL_DEBUG, "conn: \"%s\" labeled_ipsec=%d",
		    conn->name, msg.labeled_ipsec);

	msg.policy_label = conn->policy_label;
	starter_log(LOG_LEVEL_DEBUG, "conn: \"%s\" policy_label=%d",
		    conn->name, msg.policy_label);
#endif

#ifdef XAUTH
	if (conn->options_set[KBF_XAUTHBY])
		msg.xauthby = conn->options[KBF_XAUTHBY];
	if (conn->options_set[KBF_XAUTHFAIL])
		msg.xauthfail = conn->options[KBF_XAUTHFAIL];

#endif

	set_whack_end(cfg, "left",  &msg.left, &conn->left);
	set_whack_end(cfg, "right", &msg.right, &conn->right);

	/* for bug #1004 */
	update_ports(&msg);

	msg.esp = conn->esp;
	msg.ike = conn->ike;

	if (conn->modecfg_dns1) {
		if (!tnatoaddr(conn->modecfg_dns1, 0, AF_INET,
			       &(msg.modecfg_dns1)) &&
		    !tnatoaddr(conn->modecfg_dns1, 0, AF_INET6,
			       &(msg.modecfg_dns1)))
			starter_log(LOG_LEVEL_ERR,
				    "Ignoring modecfg_dns1 entry, it is not a valid IPv4 or IPv6 address");


	}
	if (conn->modecfg_dns2) {
		if (!tnatoaddr(conn->modecfg_dns2, 0, AF_INET,
			       &(msg.modecfg_dns2)) &&
		    !tnatoaddr(conn->modecfg_dns2, 0, AF_INET6,
			       &(msg.modecfg_dns2)))
			starter_log(LOG_LEVEL_ERR,
				    "Ignoring modecfg_dns2 entry, it is not a valid IPv4 or IPv6 address");


	}
	msg.tpmeval = NULL;

	r =  send_whack_msg(&msg, cfg->ctlbase);

	if ((r == 0) && (conn->policy & POLICY_RSASIG)) {
		r = starter_whack_add_pubkey(cfg, conn, &conn->left,  "left");
		if (r == 0)
			r = starter_whack_add_pubkey(cfg, conn, &conn->right,
						     "right");
	}

	return r;
}

bool one_subnet_from_string(struct starter_conn *conn,
			    char **psubnets,
			    int af,
			    ip_subnet *sn,
			    char *lr)
{
	char *eln;
	char *subnets = *psubnets;
	err_t e;

	if (subnets == NULL)
		return FALSE;

	/* find first non-space item */
	while (*subnets != '\0' && (isspace(*subnets) || *subnets == ','))
		subnets++;

	/* did we find something? */
	if (*subnets == '\0')
		return FALSE;             /* no */

	eln = subnets;

	/* find end of this item */
	while (*subnets != '\0' && !(isspace(*subnets) || *subnets == ','))
		subnets++;

	e = ttosubnet(eln, subnets - eln, af, sn);
	if (e) {
		starter_log(LOG_LEVEL_ERR,
			    "conn: \"%s\" warning '%s' is not a subnet declaration. (%ssubnets)",
			    conn->name,
			    eln, lr);
	}

	*psubnets = subnets;
	return TRUE;
}

/*
 * permutate_conns - generate all combinations of subnets={}
 *
 * @operation - the function to apply to each generated conn
 * @cfg       - the base configuration
 * @conn      - the conn to permute
 *
 * This function goes through the set of N x M combinations of the subnets
 * defined in conn's "subnets=" declarations and synthesizes conns with
 * the proper left/right subnet setttings, and then calls operation(),
 * (which is usually add/delete/route/etc.)
 *
 */
int starter_permutate_conns(int (*operation)(struct starter_config *cfg,
					     struct starter_conn *conn),
			    struct starter_config *cfg,
			    struct starter_conn *conn)
{
	struct starter_conn sc;
	bool done = FALSE;
	int lc, rc;
	char *leftnets, *rightnets;
	char tmpconnname[256];
	ip_subnet lnet, rnet;

	leftnets = "";
	if (conn->left.strings_set[KSCF_SUBNETS])
		leftnets = conn->left.strings[KSCF_SUBNETS];

	rightnets = "";
	if (conn->right.strings_set[KSCF_SUBNETS])
		rightnets = conn->right.strings[KSCF_SUBNETS];

	/*
	 * the first combination is the current leftsubnet/rightsubnet
	 * value, and then each iteration of rightsubnets, and then
	 * each permutation of leftsubnets X rightsubnets.
	 *
	 * If both subnet= is set and subnets=, then it is as if an extra
	 * element of subnets= has been added, so subnets= for only one
	 * side will do the right thing, as will some combinations of also=
	 *
	 */

	if (conn->left.strings_set[KSCF_SUBNET]) {
		lnet = conn->left.subnet;
		lc = 0;
	} else {
		one_subnet_from_string(conn, &leftnets, conn->left.addr_family,
				       &lnet, "left");
		lc = 1;
	}

	if (conn->right.strings_set[KSCF_SUBNET]) {
		rnet = conn->right.subnet;
		rc = 0;
	} else {
		one_subnet_from_string(conn, &rightnets,
				       conn->right.addr_family, &rnet,
				       "right");
		rc = 1;
	}

	do {
		int success;

		/* copy conn  --- we can borrow all pointers, since this
		 * is a temporary copy */
		sc = *conn;

		/* fix up leftsubnet/rightsubnet properly, make sure
		 * that has_client is set.
		 */
		sc.left.subnet = lnet;
		sc.left.has_client = TRUE;

		sc.right.subnet = rnet;
		sc.right.has_client = TRUE;

		snprintf(tmpconnname, 256, "%s/%ux%u", conn->name, lc, rc);
		sc.name = tmpconnname;

		sc.connalias = conn->name;

		success = (*operation)(cfg, &sc);
		if (success != 0) {
			/* fail at first failure? . I think so */
			return success;
		}

		/* okay, advance right first, and if it is out, then do
		 * left.
		 */
		rc++;
		if (!one_subnet_from_string(conn, &rightnets,
					    conn->right.addr_family, &rnet,
					    "right")) {
			/* reset right, and advance left! */
			rightnets = "";
			if (conn->right.strings_set[KSCF_SUBNETS])
				rightnets = conn->right.strings[KSCF_SUBNETS];

			/* should rightsubnet= be the first item ? */
			if (conn->right.strings_set[KSCF_SUBNET]) {
				rnet = conn->right.subnet;
				rc = 0;
			} else {
				one_subnet_from_string(conn, &rightnets,
						       conn->right.addr_family,
						       &rnet, "right");
				rc = 1;
			}

			/* left */
			lc++;
			if (!one_subnet_from_string(conn, &leftnets,
						    conn->left.addr_family,
						    &lnet, "left"))
				done = 1;
		}

	} while (!done);

	return 0;  /* success. */
}

int starter_whack_add_conn(struct starter_config *cfg,
			   struct starter_conn *conn)
{
	/* basic case, nothing special to synthize! */
	if (!conn->left.strings_set[KSCF_SUBNETS] &&
	    !conn->right.strings_set[KSCF_SUBNETS])
		return starter_whack_basic_add_conn(cfg, conn);

	return starter_permutate_conns(starter_whack_basic_add_conn,
				       cfg, conn);
}

int starter_whack_basic_del_conn(struct starter_config *cfg,
				 struct starter_conn *conn)
{
	struct whack_message msg;

	init_whack_msg(&msg);
	msg.whack_delete = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(&msg, cfg->ctlbase);
}

int starter_whack_del_conn(struct starter_config *cfg,
			   struct starter_conn *conn)
{
	/* basic case, nothing special to synthize! */
	if (!conn->left.strings_set[KSCF_SUBNETS] &&
	    !conn->right.strings_set[KSCF_SUBNETS])
		return starter_whack_basic_del_conn(cfg, conn);

	return starter_permutate_conns(starter_whack_basic_del_conn,
				       cfg, conn);
}

int starter_whack_basic_route_conn(struct starter_config *cfg,
				   struct starter_conn *conn)
{
	struct whack_message msg;

	init_whack_msg(&msg);
	msg.whack_route = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(&msg, cfg->ctlbase);
}

int starter_whack_route_conn(struct starter_config *cfg,
			     struct starter_conn *conn)
{
	/* basic case, nothing special to synthize! */
	if (!conn->left.strings_set[KSCF_SUBNETS] &&
	    !conn->right.strings_set[KSCF_SUBNETS])
		return starter_whack_basic_route_conn(cfg, conn);

	return starter_permutate_conns(starter_whack_basic_route_conn,
				       cfg, conn);
}

int starter_whack_initiate_conn(struct starter_config *cfg,
				struct starter_conn *conn)
{
	struct whack_message msg;

	init_whack_msg(&msg);
	msg.whack_initiate = TRUE;
	msg.whack_async = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(&msg, cfg->ctlbase);
}

int starter_whack_listen(struct starter_config *cfg)
{
	struct whack_message msg;

	init_whack_msg(&msg);
	msg.whack_listen = TRUE;
	return send_whack_msg(&msg, cfg->ctlbase);
}

int starter_whack_shutdown(struct starter_config *cfg)
{
	struct whack_message msg;

	init_whack_msg(&msg);
	msg.whack_shutdown = TRUE;
	return send_whack_msg(&msg, cfg->ctlbase);
}

