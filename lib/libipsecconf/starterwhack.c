/* FreeS/WAN whack functions to communicate with pluto (whack.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
 * RCSID $Id: starterwhack.c,v 1.8 2004/12/01 07:33:14 ken Exp $
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

#ifndef _OPENSWAN_H
#include <openswan.h>  /** FIXME: ugly include lines **/
#include "constants.h"
#endif

#include "oswalloc.h"
#include "oswlog.h"
#include "whack.h"
#include "id.h"

static int
send_reply(int sock, char *buf, ssize_t len)
{
    /* send the secret to pluto */
    if (write(sock, buf, len) != len)
    {
	int e = errno;

	starter_log(LOG_LEVEL_ERR, "whack: write() failed (%d %s)\n",
		    e, strerror(e));
	return RC_WHACK_PROBLEM;
    }
    return 0;
}

int starter_whack_read_reply(int sock,
			     char xauthname[128],
			     char xauthpass[128],
			     int xauthnamelen,
			     int xauthpasslen)
{
	char buf[4097];	/* arbitrary limit on log line length */
	char *be = buf;
	int ret = 0;
	
	for (;;)
	{
		char *ls = buf;
		ssize_t rl = read(sock, be, (buf + sizeof(buf)-1) - be);
		
		if (rl < 0)
		{
			int e = errno;
			
			fprintf(stderr, "whack: read() failed (%d %s)\n", e, strerror(e));
			return RC_WHACK_PROBLEM;
		}
		if (rl == 0)
		{
			if (be != buf)
				fprintf(stderr, "whack: last line from pluto too long or unterminated\n");
			break;
		}
		
		be += rl;
		*be = '\0';
		
		for (;;)
		{
		    char *le = strchr(ls, '\n');

		    if (le == NULL)
		    {
			/* move last, partial line to start of buffer */
			memmove(buf, ls, be-ls);
			be -= ls - buf;
			break;
		    }
		    
		    le++;	/* include NL in line */
		    write(1, ls, le - ls);
		    fsync(1);
		    
		    /* figure out prefix number
		     * and how it should affect our exit status
		     */
		    {
			unsigned long s = strtoul(ls, NULL, 10);

			switch (s)
			{
			case RC_COMMENT:
			case RC_LOG:
			    /* ignore */
			    break;
			case RC_SUCCESS:
			    /* be happy */
			    ret = 0;
			    break;

			case RC_ENTERSECRET:
				if(xauthpasslen==0) {
					xauthpasslen = whack_get_secret(xauthpass
								  , sizeof(xauthpass));
				}
				ret=send_reply(sock, xauthpass, xauthpasslen);
				if(ret!=0) return ret;
				break;

			case RC_XAUTHPROMPT:
				if(xauthnamelen==0) {
					xauthnamelen = whack_get_value(xauthname
								 , sizeof(xauthname));
				}
				ret=send_reply(sock, xauthname, xauthnamelen);
				if(ret!=0) return ret;
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

static int send_whack_msg (struct whack_message *msg, char *ctlbase)
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
	wp.str_next = (char *)msg->string;
	wp.str_roof = (char *)&msg->string[sizeof(msg->string)];

	ugh = pack_whack_msg(&wp);

	if(ugh)
	{
	    starter_log(LOG_LEVEL_ERR, "send_wack_msg(): can't pack strings: %s", ugh);
	    return -1;
	}

	len = wp.str_next - (unsigned char *)msg;

	/**
	 * Connect to pluto ctl
	 */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		starter_log(LOG_LEVEL_ERR, "socket() failed: %s", strerror(errno));
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&ctl_addr,
		offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path))<0) {
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
		char xauthname[128];
		char xauthpass[128];
			
		ret = starter_whack_read_reply(sock, xauthname,xauthpass,0,0);
		close(sock);
	}

	return ret;
}

static void init_whack_msg (struct whack_message *msg)
{
	memset(msg, 0, sizeof(struct whack_message));
	msg->magic = WHACK_MAGIC;
}

static char *connection_name (struct starter_conn *conn)
{
	/**
	 * If connection name is '%auto', create a new name like conn_xxxxx
	 */
	static char buf[32];
	if (strcmp(conn->name, "%auto")==0) {
		sprintf(buf, "conn_%ld", conn->id);
		return buf;
	}
	else {
		return conn->name;
	}
	return conn->name;
}

static void set_whack_end(struct starter_config *cfg
			  , char *lr
			  , struct whack_end *w
			  , struct starter_end *l)
{
	w->id = l->id;
	w->host_type = l->addrtype;

	switch(l->addrtype) {
	case KH_DEFAULTROUTE:
		w->host_addr = cfg->dr;
		if(addrtypeof(&w->host_addr) == 0) {
			w->host_addr = *aftoinfo(AF_INET)->any;
		}
		break;
		
	case KH_IPADDR:
		w->host_addr = l->addr;
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
		printf("%s: do something with host case: %d\n", lr, l->addrtype);
		break;
	}

	switch(l->nexttype) {
	case KH_DEFAULTROUTE:
		w->host_nexthop = cfg->dnh;
		break;
		
	case KH_IPADDR:
		w->host_nexthop = l->nexthop;
		break;
		
	default:
		printf("%s: do something with nexthop case: %d\n", lr, l->nexttype);
		break;

	case KH_NOTSET:  /* acceptable to not set nexthop */
		/* but, get the family set up right
		 * XXX the nexthop type has to get into the whack message!
		 *
		 */
		anyaddr(addrtypeof(&l->addr), &w->host_nexthop);
		break;
	}

	w->has_client = l->has_client;
	if (l->has_client) {
		w->client = l->subnet;
	}
	else {
		w->client.addr.u.v4.sin_family = AF_INET;
	}
	w->updown = l->strings[KSCF_UPDOWN];
	w->host_port = IKE_UDP_PORT;
	w->has_client_wildcard = l->has_client_wildcard;
	w->cert = l->cert;
	w->ca   = l->ca;
	w->updown = l->updown;
	w->virt   = NULL;
	w->protocol = l->protocol;
	w->port = l->port;
	w->virt = l->virt;

	w->key_from_DNS_on_demand = l->key_from_DNS_on_demand;
}

static int starter_whack_add_pubkey (struct starter_config *cfg,
				     struct starter_conn *conn,
				     struct starter_end *end, const char *lr)
{
	const char *err;
	char keyspace[1024 + 4];
	struct whack_message msg;
	int ret;

	init_whack_msg(&msg);

	msg.whack_key = TRUE;
	msg.pubkey_alg = PUBKEY_ALG_RSA;
	if (end->id && end->rsakey1) {
		msg.keyid = end->id;

		switch(end->rsakey1_type) {
		case PUBKEY_DNS:
		case PUBKEY_DNSONDEMAND:
		    starter_log(LOG_LEVEL_DEBUG, "conn %s/%s has key from DNS",
				connection_name(conn), lr);
		    break;

		case PUBKEY_CERTIFICATE:
		    starter_log(LOG_LEVEL_DEBUG, "conn %s/%s has key from certificate",
				connection_name(conn), lr);
		    break;

		case PUBKEY_NOTSET:
		    break;

		case PUBKEY_PREEXCHANGED:
		    err = atobytes(end->rsakey1, 0, keyspace, sizeof(keyspace),
				   &msg.keyval.len);
		    if (err) {
			starter_log(LOG_LEVEL_ERR, "conn %s/%s: rsakey malformed [%s]",
				    connection_name(conn), lr, err);
			return 1;
		    }
		    else {
			msg.keyval.ptr = keyspace;
			ret = send_whack_msg(&msg, cfg->ctlbase);
		    }
		}
	}

	if(ret < 0) return ret;

	init_whack_msg(&msg);

	msg.whack_key = TRUE;
	msg.pubkey_alg = PUBKEY_ALG_RSA;
	if (end->id && end->rsakey2) {
		/* printf("addkey2: %s\n", lr); */

		msg.keyid = end->id;
		switch(end->rsakey2_type) {
		case PUBKEY_NOTSET:
		case PUBKEY_DNS:
		case PUBKEY_DNSONDEMAND:
		case PUBKEY_CERTIFICATE:
		    break;

		case PUBKEY_PREEXCHANGED:
		    err = atobytes(end->rsakey2, 0, keyspace, sizeof(keyspace),
				   &msg.keyval.len);
		    if (err) {
			starter_log(LOG_LEVEL_ERR, "conn %s/%s: rsakey malformed [%s]",
				    connection_name(conn), lr, err);
			return 1;
		    }
		    else {
			msg.keyval.ptr = keyspace;
			return send_whack_msg(&msg, cfg->ctlbase);
		    }
		}
	}
	return 0;
}

int starter_whack_add_conn (struct starter_config *cfg
			    , struct starter_conn *conn)
{
	struct whack_message msg;
	int r;

	init_whack_msg(&msg);

	msg.whack_connection = TRUE;
	msg.whack_delete = TRUE;      /* always do replace for now */
	msg.name = connection_name(conn);

	msg.addr_family = AF_INET;
	msg.tunnel_addr_family = AF_INET;

	msg.sa_ike_life_seconds = conn->options[KBF_IKELIFETIME];
	msg.sa_ipsec_life_seconds = conn->options[KBF_SALIFETIME];
	msg.sa_rekey_margin = conn->options[KBF_REKEYMARGIN];
	msg.sa_rekey_fuzz = conn->options[KBF_REKEYFUZZ];
	msg.sa_keying_tries = conn->options[KBF_KEYINGTRIES];

	msg.policy = conn->policy;

	set_whack_end(cfg, "left",  &msg.left, &conn->left);
	set_whack_end(cfg, "right", &msg.right, &conn->right);

	msg.esp = conn->esp;
	msg.ike = conn->ike;
	msg.tpmeval = NULL;

	r =  send_whack_msg(&msg, cfg->ctlbase);

	if ((r==0) && (conn->policy & POLICY_RSASIG)) {
	    r=starter_whack_add_pubkey (cfg, conn, &conn->left,  "left");
	    if(r==0) {
	      r=starter_whack_add_pubkey (cfg, conn, &conn->right, "right");
	    }
	}

	return r;
}

int starter_whack_del_conn (struct starter_config *cfg
			    , struct starter_conn *conn)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_delete = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(&msg, cfg->ctlbase);
}

int starter_whack_route_conn (struct starter_config *cfg
			      , struct starter_conn *conn)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_route = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(&msg, cfg->ctlbase);
}

int starter_whack_initiate_conn (struct starter_config *cfg
				 ,struct starter_conn *conn)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_initiate = TRUE;
	msg.whack_async = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(&msg, cfg->ctlbase);
}

int starter_whack_listen (struct starter_config *cfg)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_listen = TRUE;
	return send_whack_msg(&msg, cfg->ctlbase);
}

int starter_whack_shutdown (struct starter_config *cfg)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_shutdown = TRUE;
	return send_whack_msg(&msg, cfg->ctlbase);
}

