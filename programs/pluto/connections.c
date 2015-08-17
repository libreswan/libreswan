/*
 * information about connections between hosts and clients
 *
 * Copyright (C) 1998-2002,2010,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2010 Shinichi Furuso <Shinichi.Furuso@jp.sony.com>
 * Copyright (C) 2010,2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2012 Bram <bram-bcrafjna-erqzvar@spam.wizbit.be>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
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

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"
#include "kameipsec.h"

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "secrets.h"

#include "defs.h"
#include "connections.h" /* needs id.h */
#include "pending.h"
#include "foodgroups.h"
#include "packet.h"
#include "demux.h" /* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h" /* needs demux.h and state.h */
#include "server.h"
#include "kernel.h" /* needs connections.h */
#include "log.h"
#include "keys.h"
#include "adns.h" /* needs <resolv.h> */
#include "dnskey.h" /* needs keys.h and adns.h */
#include "whack.h"
#include "alg_info.h"
#include "spdb.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1_xauth.h"
#include "addresspool.h"
#include "nat_traversal.h"
#include "pluto_x509.h"
#include "nss_cert_load.h"

#include "virtual.h"	/* needs connections.h */

#include "hostpair.h"

struct connection *connections = NULL;

struct connection *unoriented_connections = NULL;

/*
 * Find a connection by name.
 *
 * If strict, don't accept a CK_INSTANCE.
 * Move the winner (if any) to the front.
 * If none is found, and strict, a diagnostic is logged to whack.
 */
struct connection *con_by_name(const char *nm, bool strict)
{
	struct connection *p, *prev;

	for (prev = NULL, p = connections;; prev = p, p = p->ac_next) {
		if (p == NULL) {
			if (strict)
				whack_log(RC_UNKNOWN_NAME,
					"no connection named \"%s\"", nm);
			break;
		}
		if (streq(p->name, nm) &&
			(!strict || p->kind != CK_INSTANCE)) {
			if (prev != NULL) {
				/* remove p from list */
				prev->ac_next = p->ac_next;
				/* and stick it on front */
				p->ac_next = connections;
				connections = p;
			}
			break;
		}
	}
	return p;
}

void release_connection(struct connection *c, bool relations)
{
	if (c->kind == CK_INSTANCE) {
		/*
		 * This does everything we need.
		 * Note that we will be called recursively by delete_connection,
		 * but kind will be CK_GOING_AWAY.
		 */
		delete_connection(c, relations);
	} else {
		flush_pending_by_connection(c);
		delete_states_by_connection(c, relations);
		unroute_connection(c);
	}
}

/* update the host pairs with the latest DNS ip address */
void update_host_pairs(struct connection *c)
{
	struct host_pair *p = c->host_pair;
	struct connection *d;
	struct connection *conn_next_tmp;
	struct connection *conn_list = NULL;
	ip_address new_addr;
	char *dnshostname = c->dnshostname;

	/* ??? perhaps we should return early if dnshostname == NULL */

	if (p == NULL)
		return;

	d = p->connections;

	/* ??? looks as if addr_family is not allowed to change.  Bug? */
	/* ??? why are we using d->dnshostname instead of c->hostname? */
	if (d == NULL ||
	    d->dnshostname == NULL ||
	    ttoaddr(d->dnshostname, 0, d->addr_family, &new_addr) != NULL ||
	    sameaddr(&new_addr, &p->him.addr))
		return;

	for (; d != NULL; d = conn_next_tmp) {
		conn_next_tmp = d->hp_next;
		/*
		 * ??? this test used to assume that dnshostname != NULL
		 * if d->dnshostname != NULL.  Is that true?
		 */
		if (d->dnshostname != NULL && dnshostname != NULL &&
		    streq(d->dnshostname, dnshostname)) {
			/*
			 * If there is a dnshostname and it is the same as
			 * the one that has changed, then change
			 * the connection's remote host address and remove
			 * the connection from the host pair.
			 */
			d->spd.that.host_addr = new_addr;
			list_rm(struct connection, hp_next, d,
				d->host_pair->connections);

			d->hp_next = conn_list;
			conn_list = d;
		}
	}

	if (conn_list != NULL) {
		for (d = conn_list; d != NULL; d = conn_next_tmp) {
			/*
			 * connect the connection to the new host_pair
			 */
			conn_next_tmp = d->hp_next;
			connect_to_host_pair(d);
		}
	}

	if (p->connections == NULL) {
		passert(p->pending == NULL); /* ??? must deal with this! */
		list_rm(struct host_pair, next, p, host_pairs);
		pfree(p);
	}
}

/* Delete a connection */
static void delete_end(struct end *e)
{
	free_id_content(&e->id);

	if (e->cert.u.nss_cert != NULL)
		CERT_DestroyCertificate(e->cert.u.nss_cert);

	freeanychunk(e->ca);
	pfreeany(e->cert_nickname);
	pfreeany(e->updown);
	pfreeany(e->host_addr_name);
	pfreeany(e->xauth_password);
	pfreeany(e->xauth_name);
}

static void delete_sr(struct spd_route *sr)
{
	delete_end(&sr->this);
	delete_end(&sr->that);
}

/*
 * delete_connection -- removes a connection by pointer
 *
 * @c - the connection pointer
 * @relations - whether to delete any instances as well.
 *
 */

void delete_connection(struct connection *c, bool relations)
{
	struct spd_route *sr;
	struct connection *old_cur_connection =
		cur_connection == c ? NULL : cur_connection;

	lset_t old_cur_debugging = cur_debugging;
	set_cur_connection(c);

	/*
	 * Must be careful to avoid circularity:
	 * we mark c as going away so it won't get deleted recursively.
	 */
	passert(c->kind != CK_GOING_AWAY);
	if (c->kind == CK_INSTANCE) {
		ipstr_buf b;

		if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			libreswan_log(
				"deleting connection \"%s\" instance with peer %s "
				"{isakmp=#%lu/ipsec=#%lu}",
				c->name,
				ipstr(&c->spd.that.host_addr, &b),
				c->newest_isakmp_sa, c->newest_ipsec_sa);
		}
		c->kind = CK_GOING_AWAY;
		if (c->pool != NULL)
			rel_lease_addr(c);
	} else {
		libreswan_log("deleting connection");
	}
	release_connection(c, relations); /* won't delete c */

	if (c->kind == CK_GROUP)
		delete_group(c);

	if (c->pool != NULL)
		unreference_addresspool(c);

	/* free up any logging resources */
	perpeer_logfree(c);

	/* find and delete c from connections list */
	list_rm(struct connection, ac_next, c, connections);
	cur_connection = old_cur_connection;

	/* find and delete c from the host pair list */
	if (c->host_pair == NULL) {
		list_rm(struct connection, hp_next, c, unoriented_connections);
	} else {
		struct host_pair *hp = c->host_pair;

		list_rm(struct connection, hp_next, c, hp->connections);
		c->host_pair = NULL; /* redundant, but safe */

		/*
		 * if there are no more connections with this host_pair
		 * and we haven't even made an initial contact, let's delete
		 * this guy in case we were created by an attempted DOS attack.
		 */
		if (hp->connections == NULL) {
			/* ??? must deal with this! */
			passert(hp->pending == NULL);
			remove_host_pair(hp);
			pfree(hp);
		}
	}

	if (c->kind != CK_GOING_AWAY)
		pfreeany(c->spd.that.virt);

	set_debugging(old_cur_debugging);
	pfreeany(c->name);
	pfreeany(c->cisco_dns_info);
	pfreeany(c->modecfg_domain);
	pfreeany(c->modecfg_banner);
#ifdef HAVE_LABELED_IPSEC
	pfreeany(c->policy_label);
#endif
	pfreeany(c->dnshostname);

	sr = &c->spd;
	while (sr) {
		delete_sr(sr);
		sr = sr->next;
	}

	free_generalNames(c->requested_ca, TRUE);

	if ((c->policy & POLICY_AUTH_NULL) == LEMPTY)
		gw_delref(&c->gw_info);

	if (c->alg_info_ike != NULL) {
		alg_info_delref(&c->alg_info_ike->ai);
		c->alg_info_ike = NULL;
	}

	if (c->alg_info_esp != NULL) {
		alg_info_delref(&c->alg_info_esp->ai);
		c->alg_info_esp = NULL;
	}

	pfree(c);
}

int foreach_connection_by_alias(const char *alias,
				int (*f)(struct connection *c, void *arg),
				void *arg)
{
	struct connection *p, *pnext;
	int count = 0;

	for (p = connections; p != NULL; p = pnext) {
		pnext = p->ac_next;

		if (lsw_alias_cmp(alias, p->connalias))
			count += (*f)(p, arg);
	}
	return count;
}

static int delete_connection_wrap(struct connection *c, void *arg)
{
	bool *barg = (bool *)arg;

	delete_connection(c, *barg);
	return 1;
}

/* Delete connections with the specified name */
void delete_connections_by_name(const char *name, bool strict)
{
	bool f = FALSE;

	passert(name != NULL);
	struct connection *c = con_by_name(name, strict);

	if (c == NULL) {
		(void)foreach_connection_by_alias(name, delete_connection_wrap,
						  &f);
	} else {
		for (; c != NULL; c = con_by_name(name, FALSE))
			delete_connection(c, FALSE);
	}
}

void delete_every_connection(void)
{
	while (connections != NULL)
		delete_connection(connections, TRUE);
}

/* Adjust orientations of connections to reflect newly added interfaces. */
void check_orientations(void)
{
	/* Try to orient all the unoriented connections. */
	{
		struct connection *c = unoriented_connections;

		unoriented_connections = NULL;

		while (c != NULL) {
			struct connection *nxt = c->hp_next;

			(void)orient(c);
			connect_to_host_pair(c);
			c = nxt;
		}
	}

	/*
	 * Check that no oriented connection has become double-oriented.
	 * In other words, the far side must not match one of our new
	 * interfaces.
	 */
	{
		struct iface_port *i;

		for (i = interfaces; i != NULL; i = i->next) {
			if (i->change == IFN_ADD) {
				struct host_pair *hp;

				for (hp = host_pairs; hp != NULL;
					hp = hp->next) {
					if (sameaddr(&hp->him.addr,
						     &i->ip_addr) &&
					    (kern_interface != NO_KERNEL ||
					     hp->him.host_port == pluto_port))
					{
						/*
						 * bad news: the whole chain of
						 * connections hanging off this
						 * host pair has both sides
						 * matching an interface.
						 * We'll get rid of them, using
						 * orient and
						 * connect_to_host_pair.
						 * But we'll be lazy and not
						 * ditch the host_pair itself
						 * (the cost of leaving it is
						 * slight and cannot be
						 * induced by a foe).
						 */
						struct connection *c =
							hp->connections;

						hp->connections = NULL;
						while (c != NULL) {
							struct connection *nxt =
								c->hp_next;

							c->interface = NULL;
							(void)orient(c);
							connect_to_host_pair(c);
							c = nxt;
						}
					}
				}
			}
		}
	}
}

static err_t default_end(struct end *e, ip_address *dflt_nexthop)
{
	err_t ugh = NULL;
	const struct af_info *afi = aftoinfo(addrtypeof(&e->host_addr));

	if (afi == NULL)
		return "unknown address family in default_end";

	/* Default ID to IP (but only if not NO_IP -- WildCard) */
	if (e->id.kind == ID_NONE && !isanyaddr(&e->host_addr)) {
		e->id.kind = afi->id_addr;
		e->id.ip_addr = e->host_addr;
		e->has_id_wildcards = FALSE;
	}

	/* Default nexthop to other side. */
	if (isanyaddr(&e->host_nexthop))
		e->host_nexthop = *dflt_nexthop;

	/*
	 * Default client to subnet containing only self
	 * XXX This may mean that the client's address family doesn't match
	 * tunnel_addr_family.
	 */
	if (!e->has_client)
		ugh = addrtosubnet(&e->host_addr, &e->client);

	if (e->sendcert == 0)
		e->sendcert = cert_sendifasked;

	return ugh;
}

/*
 * Format the topology of a connection end, leaving out defaults.
 * Largest left end looks like: client === host : port [ host_id ] --- hop
 * Note: if that == NULL, skip nexthop
 * Returns strlen of formated result (length excludes NUL at end).
 */
size_t format_end(char *buf,
		size_t buf_len,
		const struct end *this,
		const struct end *that,
		bool is_left,
		lset_t policy,
		bool filter_rnh)
{
	char client[SUBNETTOT_BUF];
	const char *client_sep = "";
	char protoport[sizeof(":255/65535")];
	const char *host = NULL;
	char host_space[ADDRTOT_BUF + 256]; /* if you change this, see below */
	bool dohost_name = FALSE;
	char host_port[sizeof(":65535")];
	char host_id[IDTOA_BUF + 2];
	char hop[ADDRTOT_BUF];
	char endopts[sizeof("MS+MC+XS+XC+Sxx") + 1] = "";
	const char *hop_sep = "";
	const char *open_brackets  = "";
	const char *close_brackets = "";
	const char *id_obrackets = "";
	const char *id_cbrackets = "";
	const char *id_comma = "";

	if (isanyaddr(&this->host_addr)) {
		if (this->host_type == KH_IPHOSTNAME) {
			host = strcpy(host_space, "%dns");
			dohost_name = TRUE;
		} else {
			switch (policy & (POLICY_GROUP | POLICY_OPPORTUNISTIC)) {
			case POLICY_GROUP:
				host = "%group";
				break;
			case POLICY_OPPORTUNISTIC:
				host = "%opportunistic";
				break;
			case POLICY_GROUP | POLICY_OPPORTUNISTIC:
				host = "%opportunisticgroup";
				break;
			default:
				host = "%any";
				break;
			}
		}
	}

	client[0] = '\0';

	if (is_virtual_end(this) && isanyaddr(&this->host_addr))
		host = "%virtual";

	/* [client===] */
	if (this->has_client) {
		ip_address client_net, client_mask;

		networkof(&this->client, &client_net);
		maskof(&this->client, &client_mask);
		client_sep = "===";

		/* {client_subnet_wildcard} */
		if (this->has_client_wildcard) {
			open_brackets  = "{";
			close_brackets = "}";
		}

		if (isanyaddr(&client_net) && isanyaddr(&client_mask) &&
			(policy & (POLICY_GROUP | POLICY_OPPORTUNISTIC))) {
			client_sep = ""; /* boring case */
		} else if (is_virtual_end(this)) {
			if (is_virtual_vhost(this))
				strcpy(client, "vhost:?");
			else
				strcpy(client, "vnet:?");
		} else if (subnetisnone(&this->client)) {
			strcpy(client, "?");
		} else {
			subnettot(&this->client, 0, client, sizeof(client));
		}
	}

	/* host */
	if (host == NULL) {
		addrtot(&this->host_addr, 0, host_space, sizeof(host_space));
		host = host_space;
		dohost_name = TRUE;
	}

	if (dohost_name) {
		if (this->host_addr_name) {
			size_t icl = strlen(host_space);
			int room = sizeof(host_space) - icl - 1;
			int needed = snprintf(host_space + icl, room, "<%s>",
					this->host_addr_name);

			if (needed > room)
				loglog(RC_BADID,
					"format_end: buffer too small for dohost_name - should not happen");
		}
	}

	host_port[0] = '\0';
	if (this->host_port_specific)
		snprintf(host_port, sizeof(host_port), ":%u",
			 this->host_port);

	/* payload portocol and port */
	protoport[0] = '\0';
	if (this->has_port_wildcard) {
		snprintf(protoport, sizeof(protoport), ":%u/%%any",
			this->protocol);
	} else if (this->port || this->protocol) {
		snprintf(protoport, sizeof(protoport), ":%u/%u",
			this->protocol,
			this->port);
	}

	/* id, if different from host */
	host_id[0] = '\0';
	if (this->id.kind == ID_MYID) {
		id_obrackets = "[";
		id_cbrackets = "]";
		strcpy(host_id, "%myid");
	} else if (!(this->id.kind == ID_NONE ||
			(id_is_ipaddr(&this->id) &&
				sameaddr(&this->id.ip_addr,
					&this->host_addr)))) {
		id_obrackets = "[";
		id_cbrackets = "]";
		idtoa(&this->id, host_id, sizeof(host_id));
	}

	if (this->modecfg_server || this->modecfg_client ||
	    this->xauth_server || this->xauth_client ||
	    this->sendcert != cert_defaultcertpolicy) {
		char *p = endopts;

		if (id_obrackets[0] == '[') {
			id_comma = ",";
		} else {
			id_obrackets = "[";
			id_cbrackets = "]";
		}

		if (this->modecfg_server)
			p = jam_str(endopts, sizeof(endopts), "MS");

		if (this->modecfg_client)
			p = add_str(endopts, sizeof(endopts), p, "+MC");

		if (this->xauth_server)
			p = add_str(endopts, sizeof(endopts), p, "+XS");

		if (this->xauth_client)
			p = add_str(endopts, sizeof(endopts), p, "+XC");

		{
			const char *send_cert = "+UNKNOWN";

			switch (this->sendcert) {
			case cert_neversend:
				send_cert = "+S-C";
				break;
			case cert_sendifasked:
				send_cert = "+S?C";
				break;
			case cert_alwayssend:
				send_cert = "+S=C";
				break;
			}
			add_str(endopts, sizeof(endopts), p, send_cert);
		}
	}

	/* [---hop] */
	hop[0] = '\0';
	hop_sep = "";
	if (that != NULL && !filter_rnh && !sameaddr(&this->host_nexthop, &that->host_addr)) {
		addrtot(&this->host_nexthop, 0, hop, sizeof(hop));
		hop_sep = "---";
	}

	if (is_left) {
		snprintf(buf, buf_len, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
			open_brackets, client, close_brackets,
			client_sep, host, host_port,
			id_obrackets, host_id, id_comma, endopts,
			id_cbrackets,
			protoport, hop_sep, hop);
	} else {
		snprintf(buf, buf_len, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
			hop, hop_sep, host, host_port,
			id_obrackets, host_id, id_comma, endopts,
			id_cbrackets,
			protoport, client_sep,
			open_brackets, client, close_brackets);
	}
	return strlen(buf);
}

/*
 * format topology of a connection.
 * Two symmetric ends separated by ...
 */
#define CONN_BUF_LEN    (2 * (END_BUF - 1) + 4)

static size_t format_connection(char *buf, size_t buf_len,
			const struct connection *c,
			struct spd_route *sr)
{
	size_t w =
		format_end(buf, buf_len, &sr->this, &sr->that, TRUE, LEMPTY, FALSE);

	snprintf(buf + w, buf_len - w, "...");
	w += strlen(buf + w);
	return w + format_end(buf + w, buf_len - w, &sr->that, &sr->this,
			FALSE, c->policy, oriented(*c));
}

/* spd_route's with end's get copied in xauth.c */
void unshare_connection_end_strings(struct end *e)
{
	/* do "left" */
	unshare_id_content(&e->id);

	if (e->cert.u.nss_cert) {
		e->cert.u.nss_cert = CERT_DupCertificate(e->cert.u.nss_cert);
		passert(e->cert.u.nss_cert);
	}

	if (e->ca.ptr != NULL)
		clonetochunk(e->ca, e->ca.ptr, e->ca.len, "ca string");

	e->updown = clone_str(e->updown, "updown");
	e->xauth_name = clone_str(e->xauth_name, "xauth name");
	e->xauth_password = clone_str(e->xauth_password, "xauth password");
	e->host_addr_name = clone_str(e->host_addr_name, "host ip");
	e->cert_nickname = clone_str(e->cert_nickname, "cert_nickname");
}

static void unshare_connection_strings(struct connection *c)
{
	struct spd_route *sr;

	c->name = clone_str(c->name, "connection name");

	c->cisco_dns_info = clone_str(c->cisco_dns_info,
				"connection cisco_dns_info");
	c->modecfg_domain = clone_str(c->modecfg_domain,
				"connection modecfg_domain");
	c->modecfg_banner = clone_str(c->modecfg_banner,
				"connection modecfg_banner");
#ifdef HAVE_LABELED_IPSEC
	c->policy_label = clone_str(c->policy_label,
				    "connection policy_label");
#endif
	c->dnshostname = clone_str(c->dnshostname, "connection dnshostname");

	/* duplicate any alias, adding spaces to the beginning and end */
	c->connalias = clone_str(c->connalias, "connection alias");

	/* do "right" */
	for (sr = &c->spd; sr != NULL; sr = sr->next) {
		unshare_connection_end_strings(&sr->this);
		unshare_connection_end_strings(&sr->that);
	}

	/* increment references to algo's, if any */
	if (c->alg_info_ike != NULL)
		alg_info_addref(&c->alg_info_ike->ai);

	if (c->alg_info_esp != NULL)
		alg_info_addref(&c->alg_info_esp->ai);

	if (c->pool !=  NULL)
		reference_addresspool(c->pool);
}

static bool load_end_nss_certificate(const char *name, struct end *dst)
{
	cert_t cert;

	zero(&dst->cert);	/* redundant */
	dst->cert.ty = CERT_NONE;
	dst->cert.u.nss_cert = NULL;

	if (name == NULL)
		return FALSE;

	if (!load_nss_cert_from_db(name, &cert)) {
		whack_log(RC_FATAL, "cannot load certificate \'%s\'", name);
		/* No cert, default to IP ID */
		dst->id.kind = ID_NONE;
		return FALSE;
	}

	dst->cert_nickname = (char *)name;
	DBG(DBG_CONTROL, DBG_log("loaded certificate \'%s\'", name));

	switch (cert.ty) {
	case CERT_X509_SIGNATURE:
		/* check validity of cert */
		if (CERT_CheckCertValidTimes(cert.u.nss_cert,
					     PR_Now(),FALSE) !=
						secCertTimeValid) {
			loglog(RC_LOG_SERIOUS,"certificate time is expired/invalid");
			CERT_DestroyCertificate(cert.u.nss_cert);
			cert.ty = CERT_NONE;
			return FALSE;
		}

		select_nss_cert_id(cert.u.nss_cert, &dst->id);

		DBG(DBG_CONTROL, DBG_log("certificate is valid"));
		add_rsa_pubkey_from_cert(&dst->id, cert.u.nss_cert);
		dst->cert = cert;

		/* if no CA is defined, use issuer as default */
		if (dst->ca.ptr == NULL)
			dst->ca = secitem_to_chunk(
					    cert.u.nss_cert->derIssuer);
		break;
	default:
		bad_case(cert.ty);
	}

	return TRUE;
}

static bool extract_end(struct end *dst, const struct whack_end *src,
			const char *which)
{
	bool same_ca = FALSE;

	/* decode id, if any */
	if (src->id == NULL) {
		dst->id.kind = ID_NONE;
	} else {
		err_t ugh = atoid(src->id, &dst->id, TRUE, FALSE);

		if (ugh != NULL) {
			loglog(RC_BADID, "bad %s --id: %s (ignored)", which,
				ugh);
			dst->id = empty_id; /* ignore bad one */
		}
	}

	dst->ca = empty_chunk;

	/* decode CA distinguished name, if any */
	if (src->ca != NULL) {
		if (streq(src->ca, "%same")) {
			same_ca = TRUE;
		} else if (!streq(src->ca, "%any")) {
			err_t ugh;

			dst->ca.ptr = temporary_cyclic_buffer();
			ugh = atodn(src->ca, &dst->ca);
			if (ugh != NULL) {
				libreswan_log(
					"bad CA string '%s': %s (ignored)",
					src->ca, ugh);
				dst->ca = empty_chunk;
			}
		}
	}

	/* load local end certificate and extract ID, if any */
	if (!load_end_nss_certificate(src->cert, dst)) {
		DBG_log("certificate not loaded for this end");
	}

	/* ??? what should we do on load_end_certificate failure? */

	/* does id have wildcards? */
	dst->has_id_wildcards = id_count_wildcards(&dst->id) > 0;

	/* the rest is simple copying of corresponding fields */
	dst->host_type = src->host_type;
	dst->host_addr = src->host_addr;
	dst->host_addr_name = src->host_addr_name;
	dst->host_nexthop = src->host_nexthop;
	dst->host_srcip = src->host_srcip;
	dst->client = src->client;

#ifdef HAVE_SIN_LEN
	/* XXX need to fix this for v6 */
	dst->client.addr.u.v4.sin_len  = sizeof(struct sockaddr_in);
	dst->host_addr.u.v4.sin_len = sizeof(struct sockaddr_in);
	dst->host_nexthop.u.v4.sin_len = sizeof(struct sockaddr_in);
	dst->host_srcip.u.v4.sin_len = sizeof(struct sockaddr_in);
#endif

	dst->modecfg_server = src->modecfg_server;
	dst->modecfg_client = src->modecfg_client;
	dst->pool_range = src->pool_range;

	dst->xauth_server = src->xauth_server;
	dst->xauth_client = src->xauth_client;
	dst->xauth_name = src->xauth_name;

	dst->protocol = src->protocol;
	dst->port = src->port;
	dst->has_port_wildcard = src->has_port_wildcard;
	dst->key_from_DNS_on_demand = src->key_from_DNS_on_demand;
	dst->has_client = src->has_client;
	dst->has_client_wildcard = src->has_client_wildcard;
	dst->updown = src->updown;
	dst->host_port = pluto_port;
	if (src->host_port != pluto_port) {
		dst->host_port = src->host_port;
		dst->host_port_specific = TRUE;
	}

	dst->sendcert =  src->sendcert;

	/*
	 * see if we can resolve the DNS name right now
	 * XXX this is WRONG, we should do this asynchronously, as part of
	 * the normal loading process
	 */
	{
		err_t er;
		int port;

		switch (dst->host_type) {
		case KH_IPHOSTNAME:
			er = ttoaddr(dst->host_addr_name, 0, AF_UNSPEC,
				&dst->host_addr);

			/* The above call wipes out the port, put it again */
			port = htons(dst->port);
			setportof(port, &dst->host_addr);

			if (er != NULL) {
				loglog(RC_COMMENT,
					"failed to convert '%s' at load time: "
					"%s", dst->host_addr_name, er);
			}
			break;

		default:
			break;
		}
	}

	return same_ca;
}

void setup_client_ports(struct spd_route *sr)
{
	if (!sr->this.has_port_wildcard)
		setportof(htons(sr->this.port), &sr->this.client.addr);
	if (!sr->that.has_port_wildcard)
		setportof(htons(sr->that.port), &sr->that.client.addr);
}

static bool check_connection_end(const struct whack_end *this,
				const struct whack_end *that,
				const struct whack_message *wm)
{
	if ((this->host_type == KH_IPADDR || this->host_type == KH_IFACE) &&
		(wm->addr_family != addrtypeof(&this->host_addr) ||
			wm->addr_family != addrtypeof(&this->host_nexthop))) {
		/*
		 * This should have been diagnosed by whack, so we need not
		 * be clear.
		 * !!! overloaded use of RC_CLASH
		 */
		loglog(RC_CLASH,
			"address family inconsistency in this connection=%d "
			"host=%d/nexthop=%d",
			wm->addr_family,
			addrtypeof(&this->host_addr),
			addrtypeof(&this->host_nexthop));
		return FALSE;
	}

	/* ??? seems like a nasty test (in-band, low-level) */
	if (this->pool_range.start.u.v4.sin_addr.s_addr != 0) {
		struct ip_pool *pool;
		err_t er = find_addresspool(&this->pool_range, &pool);

		if (er != NULL) {
			loglog(RC_CLASH, "leftaddresspool clash");
			return FALSE;
		}
	}

	if (subnettypeof(&this->client) != subnettypeof(&that->client)) {
		/*
		 * This should have been diagnosed by whack, so we need not
		 * be clear.
		 * !!! overloaded use of RC_CLASH
		 */
		loglog(RC_CLASH,
			"address family inconsistency in this/that connection");
		return FALSE;
	}

	/* MAKE this more sane in the face of unresolved IP addresses */
	if (that->host_type != KH_IPHOSTNAME && isanyaddr(&that->host_addr)) {
		/*
		 * Other side is wildcard: we must check if other conditions
		 * met.
		 */
		if (this->host_type != KH_IPHOSTNAME &&
			isanyaddr(&this->host_addr)) {
			loglog(RC_ORIENT,
				"connection %s must specify host IP address for our side",
				wm->name);
			return FALSE;
		} else if (!NEVER_NEGOTIATE(wm->policy)) {
			/*
			 * Check that all main mode RW IKE policies agree
			 * because we must implement them before the correct
			 * connection is known.
			 *
			 * We cannot enforce this for other non-RW connections
			 * because differentiation is possible when a command
			 * specifies which to initiate.
			 *
			 * Aggressive mode IKE policies do not have to agree
			 * amongst themselves as the ID is known from the
			 * outset.
			 */
			const struct connection *c = NULL;

			c = find_host_pair_connections(__FUNCTION__,
						&this->host_addr,
						this->host_port,
						(const ip_address *)NULL,
						that->host_port);

			for (; c != NULL; c = c->hp_next) {
				if (c->policy & POLICY_AGGRESSIVE)
					continue;
#if 0	/* ??? suppressing this code makes this whole leg pointless */
				if (!NEVER_NEGOTIATE(c->policy) &&
					((c->policy ^ wm->policy) &
						(POLICY_PSK | POLICY_RSASIG))) {
					loglog(RC_CLASH,
						"authentication method "
						"disagrees with \"%s\", "
						"which is also for an "
						"unspecified peer",
						c->name);
					return FALSE;
				}
#endif
			}
		}
	}

#if 0
	/*
	 * Virtual IP is also valid with rightsubnet=vnet:%priv or with
	 * rightprotoport=17/%any
	 */
	if ((this->virt) &&
		(!isanyaddr(&this->host_addr) || this->has_client)) {
		loglog(RC_CLASH,
			"virtual IP must only be used with %%any and without "
			"client");
		return FALSE;
	}
#endif

	return TRUE; /* happy */
}

static struct connection *find_connection_by_reqid(reqid_t reqid)
{
	struct connection *c;

	/* find base reqid */
	if (reqid > IPSEC_MANUAL_REQID_MAX) {
		reqid &= ~3;
	}

	for (c = connections; c != NULL; c = c->ac_next)
		if (c->spd.reqid == reqid)
			break;

	return c;
}

/*
 * generate a base reqid for automatic keying
 *
 * We are actually allocating a group of four contiguous
 * numbers: one is used for each SA in an SA bundle.
 *
 * - must not be in range 0 to IPSEC_MANUAL_REQID_MAX
 * - is a multiple of 4 (not actually a requirement?)
 * - does not duplicate any currently in use
 */
static reqid_t gen_reqid(void)
{
	static reqid_t	last_reqid = IPSEC_MANUAL_REQID_MAX + 1;
	reqid_t r = last_reqid;

	passert(r % 4 == 0);
	for (;;) {
		r += 4;	/* may wrap */
		/* don't use range 0 to IPSEC_MANUAL_REQID_MAX */
		if (r <= IPSEC_MANUAL_REQID_MAX)
			r = IPSEC_MANUAL_REQID_MAX + 1;

		if (r == last_reqid) {
			/* gone around the clock without success */
			exit_log("unable to allocate reqid");
		}
		if (!find_connection_by_reqid(r)) {
			last_reqid = r;
			return r;
		}
	}
}

static bool have_wm_certs(const struct whack_message *wm)
{
	if (wm->left.cert != NULL) {
		if (!cert_exists_in_nss(wm->left.cert)) {
			loglog(RC_COMMENT, "leftcert with the "
					   "nickname \"%s\" does "
					   "not exist in NSS db",
					   wm->left.cert);
			return FALSE;
		}
	}

	if (wm->right.cert != NULL) {
		if (!cert_exists_in_nss(wm->right.cert)) {
			loglog(RC_COMMENT, "rightcert with the "
					   "nickname \"%s\" does "
					   "not exist in NSS db",
					   wm->right.cert);
			return FALSE;
		}
	}

	return TRUE;
}

void add_connection(const struct whack_message *wm)
{
	struct alg_info_ike *alg_info_ike;

	alg_info_ike = NULL;

	if (con_by_name(wm->name, FALSE) != NULL) {
		loglog(RC_DUPNAME, "attempt to redefine connection \"%s\"",
			wm->name);
		return;
	}

	/* pre-check for leftcert/rightcert availablility */
	if (!have_wm_certs(wm))
		return;

	if ((wm->policy & POLICY_COMPRESS) && !can_do_IPcomp) {
		loglog(RC_FATAL,
			"Failed to add connection \"%s\" with compress because kernel is not configured to do IPCOMP",
			wm->name);
		return;
	}

	switch (wm->policy & (POLICY_AUTHENTICATE  | POLICY_ENCRYPT)) {
	case LEMPTY:
		if (!NEVER_NEGOTIATE(wm->policy)) {
			loglog(RC_LOG_SERIOUS,
				"Connection without AH or ESP cannot negotiate");
			return;
		}
		break;
	case POLICY_AUTHENTICATE | POLICY_ENCRYPT:
		loglog(RC_LOG_SERIOUS,
			"Must specify either AH or ESP.");
		return;
	}

	if (!NEVER_NEGOTIATE(wm->policy) && wm->ike != NULL) {
		char err_buf[256];	/* ??? big enough? */

		alg_info_ike = alg_info_ike_create_from_str(wm->ike,
			err_buf, sizeof(err_buf));

		if (alg_info_ike == NULL) {
			loglog(RC_LOG_SERIOUS, "ike string error: %s",
				err_buf);
			return;
		}
		if (alg_info_ike->ai.alg_info_cnt == 0) {
			loglog(RC_LOG_SERIOUS,
				"got 0 transforms for ike=\"%s\"", wm->ike);
			return;
		}
	}

	if ((wm->ike == NULL || alg_info_ike != NULL) &&
		check_connection_end(&wm->right, &wm->left, wm) &&
		check_connection_end(&wm->left, &wm->right, wm))
	{

		/*
		 * Connection values are set using strings in the whack
		 * message, unshare_connection_strings() is responsible
		 * for cloning the strings before the whack message is
		 * destroyed.
		 */

		char err_buf[256] = "";	/* ??? big enough? */
		bool same_rightca, same_leftca;
		struct connection *c = alloc_thing(struct connection,
						"struct connection");

		c->name = wm->name;
		c->connalias = wm->connalias;
		c->dnshostname = wm->dnshostname;
		c->policy = wm->policy;

		DBG(DBG_CONTROL,
			DBG_log("Added new connection %s with policy %s",
				c->name,
				prettypolicy(c->policy)));

		if (!NEVER_NEGOTIATE(wm->policy))
		{

		c->alg_info_esp = NULL;
		if (wm->esp != NULL) {
			DBG(DBG_CONTROL,
				DBG_log("from whack: got --esp=%s",
					wm->esp ? wm->esp : "NULL"));

			if (c->policy & POLICY_ENCRYPT)
				c->alg_info_esp = alg_info_esp_create_from_str(
					wm->esp ? wm->esp : "", err_buf, sizeof(err_buf));

			if (c->policy & POLICY_AUTHENTICATE)
				c->alg_info_esp = alg_info_ah_create_from_str(
					wm->esp ? wm->esp : "",  err_buf, sizeof(err_buf));

			DBG(DBG_CONTROL, {
				char buf[256] = "<NULL>"; /* XXX: fix magic value */

				if (c->alg_info_esp != NULL)
					alg_info_snprint(buf, sizeof(buf),
							(struct alg_info *)c->
							alg_info_esp);
				DBG_log("phase2alg string values: %s", buf);
			});
			if (c->alg_info_esp != NULL) {
				if (c->alg_info_esp->ai.alg_info_cnt == 0) {
					loglog(RC_LOG_SERIOUS,
						"got 0 transforms for "
						"esp=\"%s\"",
						wm->esp);
					pfree(c);
					return;
				}
			} else {
				loglog(RC_LOG_SERIOUS,
					"phase2alg string error: %s",
					err_buf);
				pfree(c);
				return;
			}
		}

		c->alg_info_ike = NULL;
		if (wm->ike) {
			c->alg_info_ike = alg_info_ike;

			DBG(DBG_CRYPT | DBG_CONTROL, {
				char buf[256]; /* XXX: fix magic value */
				alg_info_snprint(buf, sizeof(buf),
						(struct alg_info *)c->
						alg_info_ike);
				DBG_log("ike (phase1) algorithm values: %s",
					buf);
			});
			if (c->alg_info_ike != NULL) {
				if (c->alg_info_ike->ai.alg_info_cnt == 0) {
					loglog(RC_LOG_SERIOUS,
						"got 0 transforms for "
						"ike=\"%s\"",
						wm->ike);
					pfree(c);
					return;
				}
			} else {
				loglog(RC_LOG_SERIOUS,
					"ike string error: %s",
					err_buf);
				pfree(c);
				return;
			}
		}

		c->sa_ike_life_seconds = wm->sa_ike_life_seconds;
		c->sa_ipsec_life_seconds = wm->sa_ipsec_life_seconds;
		c->sa_rekey_margin = wm->sa_rekey_margin;
		c->sa_rekey_fuzz = wm->sa_rekey_fuzz;
		c->sa_keying_tries = wm->sa_keying_tries;
		c->r_timeout = wm->r_timeout;
		c->r_interval = wm->r_interval;

		if (!deltaless(c->sa_rekey_margin, c->sa_ipsec_life_seconds)) {
			deltatime_t new_rkm = deltatimescale(1, 2, c->sa_ipsec_life_seconds);

			libreswan_log("conn: %s, rekeymargin (%lds) >= "
				"salifetime (%lds); "
				"reducing rekeymargin to %ld seconds",
				c->name,
				(long) deltasecs(c->sa_rekey_margin),
				(long) deltasecs(c->sa_ipsec_life_seconds),
				(long) deltasecs(new_rkm));

			c->sa_rekey_margin = new_rkm;
		}

		/* RFC 3706 DPD */
		c->dpd_delay = wm->dpd_delay;
		c->dpd_timeout = wm->dpd_timeout;
		c->dpd_action = wm->dpd_action;

		/* Cisco interop: remote peer type */
		c->remotepeertype = wm->remotepeertype;

		c->sha2_truncbug = wm->sha2_truncbug;

		/* Network Manager support */
#ifdef HAVE_NM
		c->nmconfigured = wm->nmconfigured;
#endif

#ifdef HAVE_LABELED_IPSEC
		c->labeled_ipsec = wm->labeled_ipsec;
		c->policy_label = wm->policy_label;
#endif
		c->metric = wm->metric;
		c->connmtu = wm->connmtu;
		c->forceencaps = wm->forceencaps;
		c->nat_keepalive = wm->nat_keepalive;
		c->ikev1_natt = wm->ikev1_natt;
		c->initial_contact = wm->initial_contact;
		c->cisco_unity = wm->cisco_unity;
		c->send_vendorid = wm->send_vendorid;
		c->send_ca = wm->send_ca;
		c->xauthby = wm->xauthby;
		c->xauthfail = wm->xauthfail;

		c->modecfg_dns1 = wm->modecfg_dns1;
		c->modecfg_dns2 = wm->modecfg_dns2;
		c->modecfg_domain = wm->modecfg_domain;
		c->modecfg_banner = wm->modecfg_banner;

		} /* !NEVER_NEGOTIATE() */

		c->nflog_group = wm->nflog_group;
		c->sa_priority = wm->sa_priority;
		c->addr_family = wm->addr_family;
		c->tunnel_addr_family = wm->tunnel_addr_family;

		/*
		 * Set this up so that we can log which end is which after
		 * orient
		 */
		c->spd.this.left = TRUE;
		c->spd.that.left = FALSE;

		same_leftca = extract_end(&c->spd.this, &wm->left, "left");
		same_rightca = extract_end(&c->spd.that, &wm->right, "right");

		if (same_rightca) {
			c->spd.that.ca = c->spd.this.ca;
		} else if (same_leftca) {
			c->spd.this.ca = c->spd.that.ca;
		}

		/*
		 * How to add addresspool only for responder?
		 * It is not necessary on the initiator
		 */

		if (wm->left.pool_range.start.u.v4.sin_addr.s_addr) {
			/* there is address pool range add to the global list */
			c->pool = install_addresspool(&wm->left.pool_range);
		}
		if (wm->right.pool_range.start.u.v4.sin_addr.s_addr) {
			/* there is address pool range add to the global list */
			c->pool = install_addresspool(&wm->right.pool_range);
		}

		if (c->spd.this.xauth_server || c->spd.that.xauth_server)
			c->policy |= POLICY_XAUTH;


		default_end(&c->spd.this, &c->spd.that.host_addr);
		default_end(&c->spd.that, &c->spd.this.host_addr);

		/*
		 * force any wildcard host IP address, any wildcard subnet
		 * or any wildcard ID to that end
		 */
		if (isanyaddr(&c->spd.this.host_addr) ||
		    c->spd.this.has_client_wildcard ||
		    c->spd.this.has_port_wildcard ||
		    c->spd.this.has_id_wildcards) {
			struct end t = c->spd.this;

			c->spd.this = c->spd.that;
			c->spd.that = t;
		}

		c->spd.next = NULL;

		if (wm->sa_reqid == 0) {
			c->spd.reqid = gen_reqid();
		} else {
			c->spd.reqid = wm->sa_reqid;
		}

		/* set internal fields */
		c->instance_serial = 0;
		c->ac_next = connections;
		connections = c;
		c->interface = NULL;
		c->spd.routing = RT_UNROUTED;
		c->newest_isakmp_sa = SOS_NOBODY;
		c->newest_ipsec_sa = SOS_NOBODY;
		c->spd.eroute_owner = SOS_NOBODY;
		c->cisco_dns_info = NULL; /* XXX: scratchpad - should be phased out */
#ifdef XAUTH_HAVE_PAM
		c->pamh = NULL;
#endif

		/* force all oppo connections to have a client */
		if (c->policy & POLICY_OPPORTUNISTIC) {
			c->spd.that.has_client = TRUE;
			c->spd.that.client.maskbits = 0; /* shouldn't this be 32 for v4? */
		}

		if (c->policy & POLICY_GROUP) {
			c->kind = CK_GROUP;
			add_group(c);
		} else if ((isanyaddr(&c->spd.that.host_addr) &&
				!NEVER_NEGOTIATE(c->policy)) ||
			c->spd.that.has_client_wildcard ||
			c->spd.that.has_port_wildcard ||
			((c->policy & POLICY_SHUNT_MASK) == POLICY_SHUNT_TRAP &&
				c->spd.that.has_id_wildcards )) {
			DBG(DBG_CONTROL,
				DBG_log("based upon policy, the connection is a template."));

			/*
			 * Opportunistic or Road Warrior or wildcard client
			 * subnet
			 * or wildcard ID
			 */
			c->kind = CK_TEMPLATE;
		} else if ((wm->left.virt != NULL) ||
			(wm->right.virt != NULL)) {
			/*
			 * If we have a subnet=vnet: needing instantiation
			 * so we can accept multiple subnets from
			 * the remote peer.
			 */
			c->kind = CK_TEMPLATE;
		} else if (c->policy & POLICY_IKEV2_ALLOW_NARROWING) {
			DBG(DBG_CONTROL,
				DBG_log("based upon policy narrowing=yes, "
					"the connection is a template."));
			c->kind = CK_TEMPLATE;
		} else {
			c->kind = CK_PERMANENT;
		}

		set_policy_prio(c); /* must be after kind is set */

		c->extra_debugging = wm->debugging;

		c->gw_info = NULL;

		passert(!(wm->left.virt && wm->right.virt));
		if (wm->left.virt || wm->right.virt) {
			/*
			 * This now happens with wildcards on
			 * non-instantiations, such as rightsubnet=vnet:%priv
			 * or rightprotoport=17/%any
			 * passert(isanyaddr(&c->spd.that.host_addr));
			 */
			c->spd.that.virt = create_virtual(c,
							wm->left.virt ?
							wm->left.virt :
							wm->right.virt);
			if (c->spd.that.virt)
				c->spd.that.has_client = TRUE;
		}

		/* ensure we allocate copies of all strings */
		unshare_connection_strings(c);

		(void)orient(c);
		connect_to_host_pair(c);

		/* log all about this connection */
		libreswan_log("added connection description \"%s\"", c->name);
		DBG(DBG_CONTROL, {
				char topo[CONN_BUF_LEN];

				(void) format_connection(topo, sizeof(topo), c,
							&c->spd);

				DBG_log("%s", topo);
			});

#if 0
		/*
		 * Make sure that address families can be correctly inferred
		 * from printed ends.
		 */
		passert(c->addr_family == addrtypeof(&c->spd.this.host_addr));
		passert(c->addr_family ==
			addrtypeof(&c->spd.this.host_nexthop));
		passert((c->spd.this.has_client ?
			  c->tunnel_addr_family : c-> addr_family) ==
			subnettypeof(&c->spd.this.client));

		passert(c->addr_family == addrtypeof(&c->spd.that.host_addr));
		passert(c->addr_family ==
			addrtypeof(&c->spd.that.host_nexthop));
		passert((c->spd.that.has_client ?
			  c->tunnel_addr_family : c->addr_family) ==
			subnettypeof(&c->spd.that.client));
#endif

		DBG(DBG_CONTROL,
			DBG_log("ike_life: %lds; ipsec_life: %lds; "
				"rekey_margin: %lds; "
				"rekey_fuzz: %lu%%; "
				"keyingtries: %lu; policy: %s",
				(long) deltasecs(c->sa_ike_life_seconds),
				(long) deltasecs(c->sa_ipsec_life_seconds),
				(long) deltasecs(c->sa_rekey_margin),
				c->sa_rekey_fuzz,
				c->sa_keying_tries,
				prettypolicy(c->policy)));
	} else {
		loglog(RC_FATAL, "attempt to load incomplete connection");
	}
}

/*
 * Derive a template connection from a group connection and target.
 * Similar to instantiate(). Happens at whack --listen.
 * Returns name of new connection. May be NULL.
 * Caller is responsible for pfreeing.
 */
char *add_group_instance(struct connection *group, const ip_subnet *target)
{
	char namebuf[100],
		targetbuf[SUBNETTOT_BUF];
	struct connection *t;
	char *name = NULL;

	passert(group->kind == CK_GROUP);
	passert(oriented(*group));

	/* manufacture a unique name for this template */
	subnettot(target, 0, targetbuf, sizeof(targetbuf));
	snprintf(namebuf, sizeof(namebuf), "%s#%s", group->name, targetbuf);

	if (con_by_name(namebuf, FALSE) != NULL) {
		loglog(RC_DUPNAME,
			"group name + target yields duplicate name \"%s\"",
			namebuf);
	} else {
		t = clone_thing(*group, "group instance");
		t->name = namebuf;
		unshare_connection_strings(t);
		name = clone_str(t->name, "group instance name");
		t->spd.that.client = *target;
		t->policy &= ~(POLICY_GROUP | POLICY_GROUTED);
		t->policy |= POLICY_GROUPINSTANCE; /* mark as group instance for later */
		t->kind = isanyaddr(&t->spd.that.host_addr) &&
			!NEVER_NEGOTIATE(t->policy) ?
			CK_TEMPLATE : CK_INSTANCE;

		/* reset log file info */
		t->log_file_name = NULL;
		t->log_file = NULL;
		t->log_file_err = FALSE;

		if (group->spd.reqid) {
			t->spd.reqid = group->spd.reqid;
		} else {
			t->spd.reqid = gen_reqid();
		}

		if (t->spd.that.virt) {
			DBG_log("virtual_ip not supported in group instance");
			t->spd.that.virt = NULL;
		}

		/* add to connections list */
		t->ac_next = connections;
		connections = t;

		/* same host_pair as parent: stick after parent on list */
		group->hp_next = t;

		/* route if group is routed */
		if (group->policy & POLICY_GROUTED) {
			if (!trap_connection(t))
				whack_log(RC_ROUTE, "could not route");
		}
	}
	return name;
}

/* An old target has disappeared for a group: delete instance. */
void remove_group_instance(const struct connection *group,
			const char *name)
{
	passert(group->kind == CK_GROUP);
	passert(oriented(*group));

	delete_connections_by_name(name, FALSE);
}

/*
 * Common part of instantiating a Road Warrior or Opportunistic connection.
 * his_id can be used to carry over an ID discovered in Phase 1.
 * It must not disagree with the one in c, but if that is unspecified,
 * the new connection will use his_id.
 * If his_id is NULL, and c.that.id is uninstantiated (ID_NONE), the
 * new connection will continue to have an uninstantiated that.id.
 * Note: instantiation does not affect port numbers.
 *
 * Note that instantiate can only deal with a single SPD/eroute.
 */
struct connection *instantiate(struct connection *c, const ip_address *him,
			const struct id *his_id)
{
	struct connection *d;

	passert(c->kind == CK_TEMPLATE);
	passert(c->spd.next == NULL);

	c->instance_serial++;
	d = clone_thing(*c, "instantiated connection");
	if (his_id != NULL) {
		int wildcards;

		passert(d->spd.that.id.kind == ID_FROMCERT || match_id(his_id, &d->spd.that.id, &wildcards));
		d->spd.that.id = *his_id;
		d->spd.that.has_id_wildcards = FALSE;
	}
	unshare_connection_strings(d);

	if (c->pool !=  NULL)
		reference_addresspool(c->pool);

	d->kind = CK_INSTANCE;

	passert(oriented(*d));
	if (him != NULL)
		d->spd.that.host_addr = *him;
	setportof(htons(c->spd.that.port), &d->spd.that.host_addr);
	default_end(&d->spd.that, &d->spd.this.host_addr);

	/*
	 * We cannot guess what our next_hop should be, but if it was
	 * explicitly specified as 0.0.0.0, we set it to be him.
	 * (whack will not allow nexthop to be elided in RW case.)
	 */
	default_end(&d->spd.this, &d->spd.that.host_addr);
	d->spd.next = NULL;

	if (c->spd.reqid) {
		d->spd.reqid = c->spd.reqid;
	} else {
		d->spd.reqid = gen_reqid();
	}

	/* set internal fields */
	d->ac_next = connections;
	connections = d;
	d->spd.routing = RT_UNROUTED;
	d->newest_isakmp_sa = SOS_NOBODY;
	d->newest_ipsec_sa = SOS_NOBODY;
	d->spd.eroute_owner = SOS_NOBODY;

	/* reset log file info */
	d->log_file_name = NULL;
	d->log_file = NULL;
	d->log_file_err = FALSE;

	connect_to_host_pair(d);

	return d;
}

struct connection *rw_instantiate(struct connection *c,
				const ip_address *him,
				const ip_subnet *his_net,
				const struct id *his_id)
{
	struct connection *d = instantiate(c, him, his_id);

	if (his_net != NULL && is_virtual_connection(c)) {
		d->spd.that.client = *his_net;
		if (subnetishost(his_net) && addrinsubnet(him, his_net))
			d->spd.that.has_client = FALSE;
	}

	if (d->policy & POLICY_OPPORTUNISTIC) {
		/*
		 * This must be before we know the client addresses.
		 * Fill in one that is impossible. This prevents anyone else
		 * from trying to use this connection to get to a particular
		 * client
		 */
		d->spd.that.client = *aftoinfo(subnettypeof(
						&d->spd.that.client))->none;
	}
	DBG(DBG_CONTROL, {
		ipstr_buf b;
		char inst[CONN_INST_BUF];
		DBG_log("rw_instantiate() instantiated \"%s\"%s for %s",
			d->name, fmt_conn_instance(d, inst),
			ipstr(him, &b));
	});
	return d;
}

#if 0
/*
 * IKEv2 instantiation
 * We needed to instantiate because we are updating our traffic selectors
 * and subnets
 * taken frmo oppo_instantiate
 */
struct connection *ikev2_ts_instantiate(struct connection *c,
					const ip_address *our_client,
					const u_int16_t our_port,
					const ip_address *peer_client,
					const u_int16_t peer_port,
					const u_int8_t protocol)
{
	struct connection *d = instantiate(c, him, his_id);

	DBG(DBG_CONTROL,
		DBG_log("ikev2_ts instantiate d=%s from c=%s with c->routing "
			"%s, d->routing %s",
			d->name, c->name,
			enum_name(&routing_story, c->spd.routing),
			enum_name(&routing_story, d->spd.routing)));
	DBG(DBG_CONTROL, {
			char instbuf[512];
			DBG_log("new ikev2_ts instance: %s",
				(format_connection(instbuf, sizeof(instbuf), d,
						&d->spd), instbuf));
		});

	passert(d->spd.next == NULL);

	/* fill in our client side */
	if (d->spd.this.has_client) {
		/*
		 * There was a client in the abstract connection
		 * so we demand that the required client is within that subnet.
		 */
		passert(addrinsubnet(our_client, &d->spd.this.client));
		happy(addrtosubnet(our_client, &d->spd.this.client));
	} else {
		/*
		 * There was no client in the abstract connection
		 * so we demand that the required client be the host.
		 */
		passert(sameaddr(our_client, &d->spd.this.host_addr));
	}

	/*
	 * Fill in peer's client side.
	 * If the client is the peer, excise the client from the connection.
	 */
	passert(addrinsubnet(peer_client, &d->spd.that.client));
	happy(addrtosubnet(peer_client, &d->spd.that.client));

	if (sameaddr(peer_client, &d->spd.that.host_addr))
		d->spd.that.has_client = FALSE;

	passert(d->gw_info == NULL);
	gw_addref(gw);
	d->gw_info = gw;

#if 0
	/*
	 * Remember if the template is routed:
	 * if so, this instance applies for initiation
	 * even if it is created for responding.
	 */
	if (routed(c->spd.routing))
		d->instance_initiation_ok = TRUE;
#endif

	DBG(DBG_CONTROL, {
			char topo[CONN_BUF_LEN];

			(void) format_connection(topo, sizeof(topo), d,
						&d->spd);
			DBG_log("instantiated \"%s\": %s", d->name, topo);
		});
	return d;
}
#endif

struct connection *oppo_instantiate(struct connection *c,
				const ip_address *him,
				const struct id *his_id,
				struct gw_info *gw,
				const ip_address *our_client,
				const ip_address *peer_client)
{
	struct connection *d = instantiate(c, him, his_id);

	DBG(DBG_CONTROL,
		DBG_log("oppo instantiate d=\"%s\" from c=\"%s\" with c->routing "
			"%s, d->routing %s",
			d->name, c->name,
			enum_name(&routing_story, c->spd.routing),
			enum_name(&routing_story, d->spd.routing)));
	DBG(DBG_CONTROL, {
			char instbuf[512];
			DBG_log("new oppo instance: %s",
				(format_connection(instbuf, sizeof(instbuf), d,
						&d->spd), instbuf));
		});

	passert(d->spd.next == NULL);

	/* fill in our client side */
	if (d->spd.this.has_client) {
		/*
		 * There was a client in the abstract connection
		 * so we demand that the required client is within that subnet.
		 */
		passert(addrinsubnet(our_client, &d->spd.this.client));
		happy(addrtosubnet(our_client, &d->spd.this.client));
		/* opportunistic connections do not use port selectors */
		setportof(0, &d->spd.this.client.addr);
	} else {
		/*
		 * There was no client in the abstract connection
		 * so we demand that the required client be the host.
		 */
		passert(sameaddr(our_client, &d->spd.this.host_addr));
	}

	/*
	 * Fill in peer's client side.
	 * If the client is the peer, excise the client from the connection.
	 */
	passert(d->policy & POLICY_OPPORTUNISTIC);
	passert(addrinsubnet(peer_client, &d->spd.that.client));
	happy(addrtosubnet(peer_client, &d->spd.that.client));

	/* opportunistic connections do not use port selectors */
	setportof(0, &d->spd.that.client.addr);

	if (sameaddr(peer_client, &d->spd.that.host_addr))
		d->spd.that.has_client = FALSE;

	if (!(d->policy & POLICY_AUTH_NULL)) {
		passert(d->gw_info == NULL);
		gw_addref(gw);
		d->gw_info = gw;
	}

	/*
	 * Adjust routing if something is eclipsing c.
	 * It must be a %hold for us (hard to passert this).
	 * If there was another instance eclipsing, we'd be using it.
	 */
	if (c->spd.routing == RT_ROUTED_ECLIPSED)
		d->spd.routing = RT_ROUTED_PROSPECTIVE;

	/*
	 * Remember if the template is routed:
	 * if so, this instance applies for initiation
	 * even if it is created for responding.
	 */
	if (routed(c->spd.routing))
		d->instance_initiation_ok = TRUE;

	DBG(DBG_CONTROL, {
			char topo[CONN_BUF_LEN];
			char inst[CONN_INST_BUF];

			(void) format_connection(topo, sizeof(topo), d,
						&d->spd);
			DBG_log("oppo_instantiate() instantiated \"%s\"%s: %s",
				fmt_conn_instance(d, inst), d->name,
				topo);
		});
	return d;
}

/* priority formatting */
void fmt_policy_prio(policy_prio_t pp, char buf[POLICY_PRIO_BUF])
{
	if (pp == BOTTOM_PRIO)
		snprintf(buf, POLICY_PRIO_BUF, "0");
	else
		snprintf(buf, POLICY_PRIO_BUF, "%lu,%lu",
			pp >> 16, (pp & ~(~(policy_prio_t)0 << 16)) >> 8);
}

/*
 * Format any information needed to identify an instance of a connection.
 * Fills any needed information into buf which MUST be big enough.
 * Road Warrior: peer's IP address
 * Opportunistic: [" " myclient "==="] " ..." peer ["===" hisclient] '\0'
 */
static size_t fmt_client(const ip_subnet *client, const ip_address *gw,
			const char *prefix, char buf[ADDRTOT_BUF])
{
	if (subnetisaddr(client, gw)) {
		buf[0] = '\0'; /* compact denotation for "self" */
	} else {
		char *ap;

		strcpy(buf, prefix);
		ap = buf + strlen(prefix);
		if (subnetisnone(client))
			strcpy(ap, "?"); /* unknown */
		else
			subnettot(client, 0, ap, SUBNETTOT_BUF);
	}
	return strlen(buf);
}

char *fmt_conn_instance(const struct connection *c, char buf[CONN_INST_BUF])
{
	char *p = buf;

	*p = '\0';

	if (c->kind == CK_INSTANCE) {
		if (c->instance_serial != 0) {
			snprintf(p, CONN_INST_BUF, "[%lu]",
				c->instance_serial);
			p += strlen(p);
		}

		if (c->policy & POLICY_OPPORTUNISTIC) {
			size_t w = fmt_client(&c->spd.this.client,
					&c->spd.this.host_addr, " ", p);

			p += w;

			strcpy(p, w == 0 ? " ..." : "=== ...");
			p += strlen(p);

			p += addrtot(&c->spd.that.host_addr, 0, p, ADDRTOT_BUF) - 1;

			(void) fmt_client(&c->spd.that.client,
					&c->spd.that.host_addr, "===", p);
		} else {
			*p++ = ' ';
			addrtot(&c->spd.that.host_addr, 0, p, ADDRTOT_BUF);
		}
	}

	return buf;
}

/*
 * Find an existing connection for a trapped outbound packet.
 * This is attempted before we bother with gateway discovery.
 *   + this connection is routed or instance_of_routed_template
 *     (i.e. approved for on-demand)
 *   + this subnet contains our_client (or we are our_client)
 *   + that subnet contains peer_client (or peer is peer_client)
 *   + don't care about Phase 1 IDs (we don't know)
 * Note: result may still need to be instantiated.
 * The winner has the highest policy priority.
 *
 * If there are several with that priority, we give preference to
 * the first one that is an instance.
 *
 * See also build_outgoing_opportunistic_connection.
 */
struct connection *find_connection_for_clients(struct spd_route **srp,
					const ip_address *our_client,
					const ip_address *peer_client,
					int transport_proto)
{
	struct connection *c, *best = NULL;
	policy_prio_t best_prio = BOTTOM_PRIO;
	struct spd_route *sr;
	struct spd_route *best_sr;
	int our_port = ntohs(portof(our_client));
	int peer_port = ntohs(portof(peer_client));

	best_sr = NULL;

	passert(!isanyaddr(our_client) && !isanyaddr(peer_client));

	DBG(DBG_CONTROL, {
		ipstr_buf a;
		ipstr_buf b;

		DBG_log("find_connection: looking for policy for "
			"connection: %s:%d/%d -> %s:%d/%d",
			ipstr(our_client, &a),
			transport_proto, our_port,
			ipstr(peer_client, &b),
			transport_proto, peer_port);
	});

	for (c = connections; c != NULL; c = c->ac_next) {
		if (c->kind == CK_GROUP)
			continue;

		for (sr = &c->spd; best != c && sr; sr = sr->next) {
			if ((routed(sr->routing) ||
					c->instance_initiation_ok) &&
				addrinsubnet(our_client, &sr->this.client) &&
				addrinsubnet(peer_client, &sr->that.client) &&
				(!sr->this.protocol ||
				    transport_proto == sr->this.protocol) &&
				(!sr->this.port || our_port == sr->this.port) &&
				(!sr->that.port ||
					peer_port == sr->that.port)) {

				policy_prio_t prio =
					8 * (c->prio +
					     (c->kind == CK_INSTANCE)) +
					2 * (sr->this.port == our_port) +
					2 * (sr->that.port == peer_port) +
					(sr->this.protocol == transport_proto);

				DBG(DBG_CONTROLMORE, {
						char cib[CONN_INST_BUF];
						char c_ocb[SUBNETTOT_BUF];
						char c_pcb[SUBNETTOT_BUF];

						subnettot(&c->spd.this.client,
							0, c_ocb,
							sizeof(c_ocb));
						subnettot(&c->spd.that.client,
							0, c_pcb,
							sizeof(c_pcb));
						DBG_log("find_connection: conn \"%s\"%s has compatible peers: %s -> %s [pri: %ld]",
							c->name,
							fmt_conn_instance(c,
									cib),
							c_ocb, c_pcb, prio);
					});

				if (best == NULL) {
					best = c;
					best_sr = sr;
					best_prio = prio;
				}

				DBG(DBG_CONTROLMORE, {
					char cib[CONN_INST_BUF];
					char cib2[CONN_INST_BUF];
					DBG_log("find_connection: comparing best \"%s\"%s [pri:%ld]{%p} (child %s) to \"%s\"%s [pri:%ld]{%p} (child %s)",
						best->name,
						fmt_conn_instance(best, cib),
						best_prio,
						best,
						best->policy_next ?
							best->policy_next->name :
							"none",
						c->name,
						fmt_conn_instance(c, cib2),
						prio, c,
						c->policy_next ?
							c->policy_next->name :
							"none");
				});

				if (prio > best_prio) {
					best = c;
					best_sr = sr;
					best_prio = prio;
				}
			}
		}
	}

	if (best != NULL && NEVER_NEGOTIATE(best->policy))
		best = NULL;

	if (srp != NULL && best != NULL)
		*srp = best_sr;

	DBG(DBG_CONTROL, {
		if (best != NULL) {
			char cib[CONN_INST_BUF];
			DBG_log("find_connection: concluding with \"%s\"%s [pri:%ld]{%p} kind=%s",
				best->name,
				fmt_conn_instance(best, cib),
				best_prio,
				best,
				enum_name(&connection_kind_names, best->kind));
		} else {
			DBG_log("find_connection: concluding with empty");
		}
	});

	return best;
}

/*
 * Find and instantiate a connection for an outgoing Opportunistic connection.
 * We've already discovered its gateway.
 * We look for a the connection such that:
 *   + this is one of our interfaces
 *   + this subnet contains our_client (or we are our_client)
 *     (we will specialize the client). We prefer the smallest such subnet.
 *   + that subnet contains peer_clent (we will specialize the client).
 *     We prefer the smallest such subnet.
 *   + is opportunistic
 *   + that peer is NO_IP
 *   + don't care about Phase 1 IDs (probably should be default)
 * We could look for a connection that already had the desired peer
 * (rather than NO_IP) specified, but it doesn't seem worth the
 * bother.
 *
 * We look for the routed policy applying to the narrowest subnets.
 * We only succeed if we find such a policy AND it is satisfactory.
 *
 * The body of the inner loop is a lot like that in
 * find_connection_for_clients. In this case, we know the gateways
 * that we need to instantiate an opportunistic connection.
 */
struct connection *build_outgoing_opportunistic_connection(struct gw_info *gw,
						const ip_address *our_client,
						const ip_address *peer_client)
{
	struct iface_port *p;
	struct connection *best = NULL;
	struct spd_route *sr, *bestsr;

	passert(!isanyaddr(our_client) && !isanyaddr(peer_client));

	/* We don't know his ID yet, so gw id must be an ipaddr */
	// valid for AUTH_NULL
	// passert(gw->key != NULL);
	// passert(id_is_ipaddr(&gw->gw_id));

	/* for each of our addresses... */
	for (p = interfaces; p != NULL; p = p->next) {
		/*
		 * Go through those connections with our address and NO_IP as
		 * hosts.
		 * We cannot know what port the peer would use, so we assume
		 * that it is pluto_port (makes debugging easier).
		 */
		struct connection *c = find_host_pair_connections(__FUNCTION__,
								&p->ip_addr,
								pluto_port,
								(ip_address
									*)NULL,
								pluto_port);

		for (; c != NULL; c = c->hp_next) {
			DBG(DBG_OPPO,
				DBG_log("checking %s", c->name));
			if (c->kind == CK_GROUP)
				continue;

			for (sr = &c->spd; best != c && sr; sr = sr->next) {
				if (routed(sr->routing) &&
					addrinsubnet(our_client,
						&sr->this.client) &&
					addrinsubnet(peer_client,
						&sr->that.client)) {
					if (best == NULL) {
						best = c;
						break;
					}

					DBG(DBG_OPPO,
						DBG_log("comparing best %s "
							"to %s",
							best->name, c->name));

					for (bestsr = &best->spd; best != c && bestsr; bestsr = bestsr->next) {
						if (!subnetinsubnet(&bestsr->this.client,
							&sr->this.client) || (samesubnet(&bestsr->this.client,
							&sr->this.client) && !subnetinsubnet(
								&bestsr->that.client,
								&sr->that.client))) {
							best = c;
						}
					}
				}
			}
		}
	}

	if (best == NULL ||
		NEVER_NEGOTIATE(best->policy) ||
		(best->policy & POLICY_OPPORTUNISTIC) == LEMPTY ||
		best->kind != CK_TEMPLATE)
		return NULL;
	else
		return oppo_instantiate(best, &gw->gw_id.ip_addr, NULL, gw,
					our_client, peer_client);
}

/*
 * Find the connection to connection c's peer's client with the
 * largest value of .routing.  All other things being equal,
 * preference is given to c.  If none is routed, return NULL.
 *
 * If erop is non-null, set *erop to a connection sharing both
 * our client subnet and peer's client subnet with the largest value
 * of .routing.  If none is erouted, set *erop to NULL.
 *
 * The return value is used to find other connections sharing a route.
 * *erop is used to find other connections sharing an eroute.
 */
struct connection *route_owner(struct connection *c,
			struct spd_route *cur_spd,
			struct spd_route **srp,
			struct connection **erop,
			struct spd_route **esrp)
{
	struct connection *d,
		*best_ro = c,
		*best_ero = c;
	struct spd_route *srd, *src;
	struct spd_route *best_sr, *best_esr;
	enum routing_t best_routing, best_erouting;

	if (!oriented(*c)) {
		libreswan_log("route_owner: connection no longer oriented - system interface change?");
		return NULL;
	}
	best_sr = NULL;
	best_esr = NULL;
	best_routing = cur_spd->routing;
	best_erouting = best_routing;

	for (d = connections; d != NULL; d = d->ac_next) {

#ifdef KLIPS_MAST
		/* in mast mode we must also delete the iptables rule */
		if (kern_interface == USE_MASTKLIPS)
			if (compatible_overlapping_connections(c, d))
				continue;
#endif

		for (srd = &d->spd; srd; srd = srd->next) {
			if (srd->routing == RT_UNROUTED)
				continue;

			for (src = &c->spd; src; src = src->next) {
				if (src == srd)
					continue;

				if (!samesubnet(&src->that.client,
							&srd->that.client))
					continue;
				if (src->that.protocol != srd->that.protocol)
					continue;
				if (src->that.port != srd->that.port)
					continue;

				/*
				 * with old eroutes/routing, we could not do
				 * this. This allows a host with two IP's to
				 * talk to 1 oter host with both IP's using
				 * two different tunnels.
				 */
				if (!sameaddr(&src->this.host_addr,
						&srd->this.host_addr))
					continue;

				passert(oriented(*d));
				if (srd->routing > best_routing) {
					best_ro = d;
					best_sr = srd;
					best_routing = srd->routing;
				}

				if (!samesubnet(&src->this.client,
							&srd->this.client))
					continue;
				if (src->this.protocol != srd->this.protocol)
					continue;
				if (src->this.port != srd->this.port)
					continue;
				if (srd->routing > best_erouting) {
					best_ero = d;
					best_esr = srd;
					best_erouting = srd->routing;
				}
			}
		}
	}

	DBG(DBG_CONTROL, {
		char cib[CONN_INST_BUF];
		err_t m = builddiag("route owner of \"%s\"%s %s:",
				c->name,
				fmt_conn_instance(c, cib),
				enum_name(&routing_story,
					cur_spd->routing));

		if (!routed(best_routing)) {
			m = builddiag("%s NULL", m);
		} else if (best_ro == c) {
			m = builddiag("%s self", m);
		} else {
			m = builddiag("%s \"%s\"%s %s", m,
				best_ro->name,
				fmt_conn_instance(best_ro, cib),
				enum_name(&routing_story, best_routing));
		}

		if (erop != NULL) {
			m = builddiag("%s; eroute owner:", m);
			if (!erouted(best_ero->spd.routing)) {
				m = builddiag("%s NULL", m);
			} else if (best_ero == c) {
				m = builddiag("%s self", m);
			} else {
				m = builddiag("%s \"%s\"%s %s", m,
					best_ero->name,
					fmt_conn_instance(best_ero, cib),
					enum_name(&routing_story,
						best_ero->spd.routing));
			}
		}

		DBG_log("%s", m);
	});

	if (erop != NULL)
		*erop = erouted(best_erouting) ? best_ero : NULL;

	if (srp != NULL ) {
		*srp = best_sr;
		if (esrp != NULL )
			*esrp = best_esr;
	}

	return routed(best_routing) ? best_ro : NULL;
}

/*
 * find_host_connection: find the first satisfactory connection
 *	with this pair of hosts.
 *
 * find_next_host_connection: find the next satisfactory connection
 *	Starts where find_host_connection left off.
 *	NOTE: it will return its argument; if you want to
 *	advance, use c->hp_next.
 *
 * We start with the list that find_host_pair_connections would yield
 * but we narrow the selection.
 *
 * We only yield a connection that can negotiate.
 *
 * The caller can specify policy requirements as
 * req_policy and policy_exact_mask.
 *
 * All policy bits found in req_policy must be in the
 * policy of the connection.
 *
 * For all bits in policy_exact mask, the req_policy
 * and connection's policy must be equal.  Likely candidates:
 * - XAUTH (POLICY_XAUTH)
 * - kind of IKEV1 (POLICY_AGGRESSIVE | POLICY_IKEV1_ALLOW)
 * These should only be used if the caller actually knows
 * the exact value and has included it in req_policy.
 */
struct connection *find_host_connection(
	const ip_address *me, u_int16_t my_port,
	const ip_address *him, u_int16_t his_port,
	lset_t req_policy, lset_t policy_exact_mask)
{
	DBG(DBG_CONTROLMORE, {
		ipstr_buf a;
		ipstr_buf b;
		DBG_log("find_host_connection me=%s:%d him=%s:%d policy=%s",
			ipstr(me, &a), my_port,
			him != NULL ? ipstr(him, &b) : "%any",
			his_port,
			bitnamesof(sa_policy_bit_names, req_policy));
	});

	return find_next_host_connection(
		find_host_pair_connections(__FUNCTION__,
			me, my_port, him, his_port),
		req_policy, policy_exact_mask);
}
stf_status ikev2_find_host_connection( struct connection **cp,
		const ip_address *me, u_int16_t my_port, const ip_address *him,
		u_int16_t his_port, lset_t policy)
{
	struct connection *c = find_host_connection(me, my_port, him, his_port, policy,LEMPTY);

	if (c == NULL) {
		/* See if a wildcarded connection can be found.
		 * We cannot pick the right connection, so we're making a guess.
		 * All Road Warrior connections are fair game:
		 * we pick the first we come across (if any).
		 * If we don't find any, we pick the first opportunistic
		 * with the smallest subnet that includes the peer.
		 * There is, of course, no necessary relationship between
		 * an Initiator's address and that of its client,
		 * but Food Groups kind of assumes one.
		 */
		{
			struct connection *d = find_host_connection(me,
					pluto_port, (ip_address*)NULL, his_port,
					policy, LEMPTY);

			while (d != NULL) {
				if (d->kind == CK_GROUP) {
					/* ignore */
				} else {
					if (d->kind == CK_TEMPLATE &&
							!(d->policy & POLICY_OPPORTUNISTIC)) {
						/* must be Road Warrior: we have a winner */
						c = d;
						break;
					}

					/* Opportunistic or Shunt: pick tightest match */
					if (addrinsubnet(him, &d->spd.that.client) &&
							(c == NULL ||
							 !subnetinsubnet(&c->spd.that.client,
								 &d->spd.that.client))) {
						c = d;
					}
				}
				d = find_next_host_connection(d->hp_next,
						policy, LEMPTY);
			}
		}
		if (c == NULL) {
			ipstr_buf b;

			loglog(RC_LOG_SERIOUS, "initial parent SA message received on %s:%u but no connection has been authorized with policy %s",
					ipstr(me, &b),
					ntohs(portof(me)),
					bitnamesof(sa_policy_bit_names, policy));
			*cp = NULL;
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
		if (c->kind != CK_TEMPLATE) {
			ipstr_buf b;

			loglog(RC_LOG_SERIOUS, "initial parent SA message received on %s:%u"
					" but \"%s\" kind=%s forbids connection",
					ipstr(me, &b), pluto_port, c->name,
					enum_name(&connection_kind_names, c->kind));
			*cp = NULL;
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
		if (c->policy & POLICY_OPPORTUNISTIC) {
			/* opporstunistic */
			c = oppo_instantiate(c, him, &c->spd.that.id, NULL, &c->spd.this.host_addr, him);
		} else {
			/* regular roadwarrior */
			c = rw_instantiate(c, him, NULL, NULL);
		}
	} else {
		/* We found a non-wildcard connection.
		 * Double check whether it needs instantiation anyway (eg. vnet=)
		 */
		/* vnet=/vhost= should have set CK_TEMPLATE on connection loading */
		if ((c->kind == CK_TEMPLATE) && c->spd.that.virt) {
			DBG(DBG_CONTROL,
					DBG_log("local endpoint has virt (vnet/vhost) set without wildcards - needs instantiation"));
			c = rw_instantiate(c, him, NULL, NULL);
		} else if ((c->kind == CK_TEMPLATE) &&
				(c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
			DBG(DBG_CONTROL,
					DBG_log("local endpoint has narrowing=yes - needs instantiation"));
			c = rw_instantiate(c, him, NULL, NULL);
		}
	}
	*cp = c;
	return STF_OK;
}

struct connection *find_next_host_connection(
	struct connection *c,
	lset_t req_policy, lset_t policy_exact_mask)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("find_next_host_connection policy=%s",
			bitnamesof(sa_policy_bit_names, req_policy)));

	for (; c != NULL; c = c->hp_next) {
		DBG(DBG_CONTROLMORE,
			DBG_log("found policy = %s (%s)",
				bitnamesof(sa_policy_bit_names,
					c->policy),
				c->name));

		if (NEVER_NEGOTIATE(c->policy)) {
			/* are we a block or clear connection? */
		        lset_t shunt = (c->policy & POLICY_SHUNT_MASK) >> POLICY_SHUNT_SHIFT;
			if (shunt) {
				/*
				 * We need to match block/clear so we can send back
				 * NO_PROPOSAL_CHOSEN, otherwise not match so we
				 * can hit packetdefault to do real IKE.
				 * clear and block do not have POLICY_OPPORTUNISTIC,
				 * but clear-or-private and private-or-clear do, but
				 * they don't do IKE themselves but allow packetdefault
				 * to be hit and do the work.
				 * if not policy_oppo -> we hit clear/block so this is right c
				 */
				if ((c->policy & POLICY_OPPORTUNISTIC))
					continue;
				/* shunt match - stop the search for another conn if we are groupinstance*/
				if (c->policy & POLICY_GROUPINSTANCE)
					break;
			}
			continue;
		}

		/*
		 * Success may require exact match of:
		 * (1) XAUTH (POLICY_XAUTH)
		 * (2) kind of IKEV1 (POLICY_AGGRESSIVE | POLICY_IKEV1_ALLOW)
		 * So if any bits are on in the exclusive OR, we fail.
		 * Each of our callers knows what is known so specifies
		 * the policy_exact_mask.
		 */
		if ((req_policy ^ c->policy) & policy_exact_mask)
			continue;

		/*
		 * Success if all specified policy bits are in candidate's policy.
		 * It works even when the exact-match bits are included.
		 */
		if ((req_policy & ~c->policy) == LEMPTY)
			break;
	}

	DBG(DBG_CONTROLMORE,
		DBG_log("find_next_host_connection returns %s",
			c ? c->name : "empty"));

	return c;
}

/*
 * Extracts the peer's ca from the chained list of public keys.
 */
static chunk_t get_peer_ca(const struct id *peer_id)
{
	struct pubkey_list *p;

	for (p = pluto_pubkeys; p != NULL; p = p->next) {
		struct pubkey *key = p->key;

		if (key->alg == PUBKEY_ALG_RSA && same_id(peer_id, &key->id))
			return key->issuer;
	}
	return empty_chunk;
}

/*
 * Given an up-until-now satisfactory connection, find the best connection
 * now that we just got the Phase 1 Id Payload from the peer.
 *
 * Comments in the code describe the (tricky!) matching criteria.
 * Although this routine could handle the initiator case,
 * it isn't currently called in this case.
 * If it were, it could "upgrade" an Opportunistic Connection
 * to a Road Warrior Connection if a suitable Peer ID were found.
 *
 * In RFC 2409 "The Internet Key Exchange (IKE)",
 * in 5.1 "IKE Phase 1 Authenticated With Signatures", describing Main
 * Mode:
 *
 *         Initiator                          Responder
 *        -----------                        -----------
 *         HDR, SA                     -->
 *                                     <--    HDR, SA
 *         HDR, KE, Ni                 -->
 *                                     <--    HDR, KE, Nr
 *         HDR*, IDii, [ CERT, ] SIG_I -->
 *                                     <--    HDR*, IDir, [ CERT, ] SIG_R
 *
 * In 5.4 "Phase 1 Authenticated With a Pre-Shared Key":
 *
 *               HDR, SA             -->
 *                                   <--    HDR, SA
 *               HDR, KE, Ni         -->
 *                                   <--    HDR, KE, Nr
 *               HDR*, IDii, HASH_I  -->
 *                                   <--    HDR*, IDir, HASH_R
 *
 * refine_host_connection could be called in two case:
 *
 * - the Responder receives the IDii payload:
 *   + [PSK] after using PSK to decode this message
 *   + before sending its IDir payload
 *   + before using its ID in HASH_R computation
 *   + [DSig] before using its private key to sign SIG_R
 *   + before using the Initiator's ID in HASH_I calculation
 *   + [DSig] before using the Initiator's public key to check SIG_I
 *
 * - the Initiator receives the IDir payload:
 *   + [PSK] after using PSK to encode previous message and decode this message
 *   + after sending its IDii payload
 *   + after using its ID in HASH_I computation
 *   + [DSig] after using its private key to sign SIG_I
 *   + before using the Responder's ID to compute HASH_R
 *   + [DSig] before using Responder's public key to check SIG_R
 *
 * refine_host_connection can choose a different connection, as long as
 * nothing already used is changed.
 *
 * In the Initiator case, the particular connection might have been
 * specified by whatever provoked Pluto to initiate.  For example:
 *	whack --initiate connection-name
 * The advantages of switching connections when we're the Initiator seem
 * less important than the disadvantages, so after FreeS/WAN 1.9, we
 * don't do this.
 */
struct connection *refine_host_connection(const struct state *st,
					const struct id *peer_id,
					bool initiator,
					lset_t auth_policy,
					bool *fromcert)
{
	struct connection *c = st->st_connection;
	struct connection *best_found = NULL;
	const struct RSA_private_key *my_RSA_pri = NULL;
	bool wcpip; /* wildcard Peer IP? */
	int wildcards = 0,
		best_wildcards = 0;
	int our_pathlen = 0,
		best_our_pathlen = 0,
		peer_pathlen = 0,
		best_peer_pathlen = 0;
	const chunk_t *psk = NULL;

	*fromcert = FALSE;

	DBG(DBG_CONTROLMORE,
		DBG_log("refine_host_connection: starting with %s",
			c->name));

	if (auth_policy & POLICY_AUTH_NULL) {
		DBG(DBG_CONTROLMORE,
			DBG_log("refine_host_connection: cannot refine AUTH_NULL policy which is tied to ephemeral SKEYSEED"));
		return c;
	}

	chunk_t peer_ca = get_peer_ca(peer_id);

	if (same_id(&c->spd.that.id, peer_id) &&
		peer_ca.ptr != NULL &&
		trusted_ca_nss(peer_ca, c->spd.that.ca, &peer_pathlen) &&
		peer_pathlen == 0 &&
		match_requested_ca(c->requested_ca, c->spd.this.ca,
				&our_pathlen) &&
		our_pathlen == 0) {

		DBG(DBG_CONTROLMORE,
			DBG_log("refine_host_connection: happy with starting point: %s",
				c->name));

		/* peer ID matches current connection -- look no further */
		return c;
	}

	if (auth_policy & POLICY_PSK) {
		if (initiator) {
			psk = get_preshared_secret(c);
			/*
			 * It should be virtually impossible to fail to find
			 * PSK: we just used it to decode the current message!
			 */
			if (psk == NULL)
				return NULL; /* cannot determine PSK! */
		}
	} else if (auth_policy & POLICY_RSASIG) {
		if (initiator) {
			/*
			 * At this point, we've committed to our RSA private
			 * key: we used it in our previous message.
			 */
			my_RSA_pri = get_RSA_private_key(c);
			if (my_RSA_pri == NULL)
				 /* cannot determine my RSA private key! */
				return NULL;
		}
	} else {
		/* don't die bad_case(auth); */
		DBG(DBG_CONTROL,
			DBG_log("refine_host_connection: unexpected auth policy: only handling PSK or RSA"));
		return NULL;
	}

	/*
	 * The current connection won't do: search for one that will.
	 * First search for one with the same pair of hosts.
	 * If that fails, search for a suitable Road Warrior or Opportunistic
	 * connection (i.e. wildcard peer IP).
	 * We need to match:
	 * - peer_id (slightly complicated by instantiation)
	 * - if PSK auth, the key must not change (we used it to decode message)
	 * - policy-as-used must be acceptable to new connection
	 * - if initiator, also:
	 *   + our ID must not change (we sent it in previous message)
	 *   + our RSA key must not change (we used in in previous message)
	 */
	passert(c != NULL);

	struct connection *d = c->host_pair->connections;

	for (wcpip = FALSE;; wcpip = TRUE) {
		for (; d != NULL; d = d->hp_next) {
			bool d_fromcert = FALSE;
			bool match1 = match_id(peer_id, &d->spd.that.id,
					&wildcards);
			bool match2 = trusted_ca_nss(peer_ca, d->spd.that.ca,
						&peer_pathlen);
			bool match3 = match_requested_ca(c->requested_ca,
							d->spd.this.ca,
							&our_pathlen);

			DBG(DBG_CONTROLMORE, {
				char b1[CONN_INST_BUF];
				char b2[CONN_INST_BUF];

				DBG_log("refine_host_connection: checking %s%s "
					"against %s%s, best=%s with "
					"match=%d(id=%d/ca=%d/reqca=%d)",
					c->name,
					fmt_conn_instance(c, b1),
					d->name,
					fmt_conn_instance(d, b2),
					best_found ?
						best_found->name : "(none)",
					match1 && match2 && match3,
					match1, match2, match3);});

			/* ignore group connections */
			if (d->policy & POLICY_GROUP)
				continue;

			/* match2 and match3 are required */
			if (!match2 || !match3)
				continue;
			/*
			 * Check if peer_id matches, exactly or after
			 * instantiation.
			 * Check for the match but also check to see if it's
			 * the %fromcert + peer id match result. - matt
			 */
			if (!match1) {
				d_fromcert = id_kind(&d->spd.that.id) ==
					ID_FROMCERT;
				if (!d_fromcert)
					continue;
			}

			/* if initiator, our ID must match exactly */
			if (initiator &&
				!same_id(&c->spd.this.id, &d->spd.this.id))
				continue;

			/*
			 * Authentication used must fit policy of this
			 * connection.
			 */
			if ((d->policy & auth_policy & ~POLICY_AGGRESSIVE) == LEMPTY) {
				/* Our auth isn't OK for this connection. */
				continue;
			}

			if ((d->policy & (st->st_ikev2 ? POLICY_IKEV2_ALLOW : POLICY_IKEV1_ALLOW)) == LEMPTY) {
				/* IKE version has to match */
				continue;
			}

			if ((d->policy ^ auth_policy) & POLICY_AGGRESSIVE) {
				/*
				 * Disallow phase1 main/aggressive mode
				 * mismatch.
				 */
				continue;
			}

			if (d->spd.this.xauth_server !=
			    c->spd.this.xauth_server) {
				/* Disallow IKEv2 CP or IKEv1 XAUTH mismatch */
				continue;
			}

			if (d->spd.this.xauth_client !=
			    c->spd.this.xauth_client) {
				/* Disallow IKEv2 CP or IKEv1 XAUTH mismatch */
				continue;
			}

			DBG(DBG_CONTROLMORE, {
				char b1[CONN_INST_BUF];
				char b2[CONN_INST_BUF];

				DBG_log("refine_host_connection: checked %s%s "
					"against %s%s, now for see if best",
					c->name,
					fmt_conn_instance(c, b1),
					d->name,
					fmt_conn_instance(d, b2)); } );

			if (auth_policy & POLICY_PSK) {
				/* secret must match the one we already used */
				const chunk_t *dpsk = get_preshared_secret(d);

				/*
				 * We can change PSK mid-way in IKEv2 or agressive mode.
				 * If we initiated, the key we used and the key
				 * we would have used with d must match.
				 */
				if (!st->st_ikev2 && !(auth_policy & POLICY_AGGRESSIVE)) {
					if (dpsk == NULL)
						continue; /* no secret */

					if (initiator && psk != dpsk &&
					    !(psk->len == dpsk->len &&
					      memeq(psk->ptr, dpsk->ptr, psk->len))) {
							continue; /* different secret */
					}
				}
			}

			if (auth_policy & POLICY_RSASIG) {
				/*
				 * We must at least be able to find our
				 * private key.
				 * If we initiated, it must match the one we
				 * used in the SIG_I payload that we sent
				 * previously.
				 */
				const struct RSA_private_key *pri = get_RSA_private_key(d);

				if (pri == NULL)
					continue;	/* no key */

				if (initiator &&
				    !same_RSA_public_key(&my_RSA_pri->pub, &pri->pub)) {
					continue;	/* different key */
				}
			}

			/*
			 * Paul: We need to check all the other relevant
			 * policy bits, like compression, pfs, etc
			 */

			/*
			 * d has passed all the tests.
			 * We'll go with it if the Peer ID was an exact match.
			 */
			if (match1 && wildcards == 0 &&
				peer_pathlen == 0 && our_pathlen == 0) {
				*fromcert = d_fromcert;
				return d;
			}

			/*
			 * If it was a non-exact (wildcard) match, we'll
			 * remember it as best_found in case an exact match
			 * doesn't come along.
			 * ??? the logic involving *_pathlen looks wrong.
			 * ??? which matters more peer_pathlen or our_pathlen minimization?
			 */
			if (best_found == NULL || wildcards < best_wildcards ||
				((wildcards == best_wildcards &&
				  peer_pathlen < best_peer_pathlen) ||
				 (peer_pathlen == best_peer_pathlen &&
				  our_pathlen < best_our_pathlen))) {
				DBG(DBG_CONTROLMORE,
					DBG_log("refine_host_connection: picking "
						"new best %s (wild=%d, peer_"
						"pathlen=%d/our=%d)",
						d->name,
						wildcards, peer_pathlen,
						our_pathlen));
				*fromcert = d_fromcert;
				best_found = d;
				best_wildcards = wildcards;
				best_peer_pathlen = peer_pathlen;
				best_our_pathlen = our_pathlen;
			}
		}
		if (wcpip) {
			/* been around twice already */
			return best_found;
		}

		/*
		 * Starting second time around.
		 * We're willing to settle for a connection that needs Peer IP
		 * instantiated: Road Warrior or Opportunistic.
		 * Look on list of connections for host pair with wildcard
		 * Peer IP.
		 */
		d = find_host_pair_connections(__FUNCTION__,
					&c->spd.this.host_addr,
					c->spd.this.host_port,
					(ip_address *)NULL,
					c->spd.that.host_port);
	}
}

/*
 * With virtual addressing, we must not allow someone to use an already
 * used (by another id) addr/net.
 */
static bool is_virtual_net_used(struct connection *c,
				const ip_subnet *peer_net,
				const struct id *peer_id)
{
	struct connection *d;
	char cbuf[CONN_INST_BUF];

	for (d = connections; d != NULL; d = d->ac_next) {
		switch (d->kind) {
		case CK_PERMANENT:
		case CK_TEMPLATE:
		case CK_INSTANCE:
			if ((subnetinsubnet(peer_net, &d->spd.that.client) ||
					subnetinsubnet(&d->spd.that.client,
						peer_net)) &&
				!same_id(&d->spd.that.id, peer_id)) {
				char buf[IDTOA_BUF];
				char client[SUBNETTOT_BUF];
				const char *cname;
				const char *doesnot = " does not";
				const char *esses = "";

				subnettot(peer_net, 0, client, sizeof(client));
				idtoa(&d->spd.that.id, buf, sizeof(buf));

				libreswan_log(
					"Virtual IP %s overlaps with connection %s\"%s\" (kind=%s) '%s'",
					client, d->name,
					fmt_conn_instance(d, cbuf),
					enum_name(&connection_kind_names,
						d->kind),
					buf);

				if (!kernel_overlap_supported()) {
					libreswan_log(
						"Kernel method '%s' does not support overlapping IP ranges",
						kernel_if_name());
					return TRUE;

				} else if (LIN(POLICY_OVERLAPIP, c->policy) &&
					LIN(POLICY_OVERLAPIP, d->policy)) {
					libreswan_log(
						"overlap is okay by mutual consent");

					/*
					 * Look for another overlap to report
					 * on.
					 */
					break;

				} else if (LIN(POLICY_OVERLAPIP, c->policy) &&
					!LIN(POLICY_OVERLAPIP, d->policy)) {
					/* redundant */
					cname = d->name;
					fmt_conn_instance(d, cbuf);
				} else if (!LIN(POLICY_OVERLAPIP, c->policy) &&
					LIN(POLICY_OVERLAPIP, d->policy)) {
					cname = c->name;
					fmt_conn_instance(c, cbuf);
				} else {
					cbuf[0] = '\0';
					doesnot = "";
					esses = "s";
					cname = "neither";
				}

				libreswan_log(
					"overlap is forbidden (%s%s%s agree%s "
					"to overlap)",
					cname,
					cbuf,
					doesnot,
					esses);

				idtoa(peer_id, buf, sizeof(buf));
				libreswan_log("Your ID is '%s'", buf);

				return TRUE; /* already used by another one */
			}
			break;
		case CK_GOING_AWAY:
		default:
			break;
		}
	}
	return FALSE; /* you can safely use it */
}

/*
 * find_client_connection: given a connection suitable for ISAKMP
 * (i.e. the hosts match), find a one suitable for IPSEC
 * (i.e. with matching clients).
 *
 * If we don't find an exact match (not even our current connection),
 * we try for one that still needs instantiation.  Try Road Warrior
 * abstract connections and the Opportunistic abstract connections.
 * This requires inverse instantiation: abstraction.
 *
 * After failing to find an exact match, we abstract the peer
 * to be NO_IP (the wildcard value).  This enables matches with
 * Road Warrior and Opportunistic abstract connections.
 *
 * After failing that search, we also abstract the Phase 1 peer ID
 * if possible.  If the peer's ID was the peer's IP address, we make
 * it NO_ID; instantiation will make it the peer's IP address again.
 *
 * If searching for a Road Warrior abstract connection fails,
 * and conditions are suitable, we search for the best Opportunistic
 * abstract connection.
 *
 * Note: in the end, both Phase 1 IDs must be preserved, after any
 * instantiation.  They are the IDs that have been authenticated.
 */

#define PATH_WEIGHT 1
#define WILD_WEIGHT (MAX_CA_PATH_LEN + 1)
#define PRIO_WEIGHT ((MAX_WILDCARDS + 1) * WILD_WEIGHT)

/* fc_try: a helper function for find_client_connection */
static struct connection *fc_try(const struct connection *c,
				struct host_pair *hp,
				const struct id *peer_id UNUSED,
				const ip_subnet *our_net,
				const ip_subnet *peer_net,
				const u_int8_t our_protocol,
				const u_int16_t our_port,
				const u_int8_t peer_protocol,
				const u_int16_t peer_port)
{
	struct connection *d;
	struct connection *best = NULL;
	policy_prio_t best_prio = BOTTOM_PRIO;
	int wildcards, pathlen;
	const bool peer_net_is_host = subnetisaddr(peer_net,
						&c->spd.that.host_addr);
	err_t virtualwhy = NULL;
	char s1[SUBNETTOT_BUF], d1[SUBNETTOT_BUF];

	subnettot(our_net, 0, s1, sizeof(s1));
	subnettot(peer_net, 0, d1, sizeof(d1));

	for (d = hp->connections; d != NULL; d = d->hp_next) {
		struct spd_route *sr;

		if (d->policy & POLICY_GROUP)
			continue;

		if (!(same_id(&c->spd.this.id, &d->spd.this.id) &&
				match_id(&c->spd.that.id, &d->spd.that.id,
					&wildcards) &&
				trusted_ca_nss(c->spd.that.ca, d->spd.that.ca,
					&pathlen)))
			continue;

		/* compare protocol and ports */
		if (d->spd.this.protocol != our_protocol ||
			(d->spd.this.port && d->spd.this.port != our_port) ||
			d->spd.that.protocol != peer_protocol ||
			(d->spd.that.port != peer_port &&
				!d->spd.that.has_port_wildcard))
			continue;

		/*
		 * non-Opportunistic case:
		 * our_client must match.
		 *
		 * So must peer_client, but the testing is complicated
		 * by the fact that the peer might be a wildcard
		 * and if so, the default value of that.client
		 * won't match the default peer_net. The appropriate test:
		 *
		 * If d has a peer client, it must match peer_net.
		 * If d has no peer client, peer_net must just have peer itself.
		 */

		for (sr = &d->spd; best != d && sr != NULL; sr = sr->next) {
			policy_prio_t prio;

			DBG(DBG_CONTROLMORE, {
				char s3[SUBNETTOT_BUF];
				char d3[SUBNETTOT_BUF];
				subnettot(&sr->this.client, 0, s3,
					sizeof(s3));
				subnettot(&sr->that.client, 0, d3,
					sizeof(d3));
				DBG_log("  fc_try trying "
					"%s:%s:%d/%d -> %s:%d/%d%s vs "
					"%s:%s:%d/%d -> %s:%d/%d%s",
					c->name, s1, c->spd.this.protocol,
					c->spd.this.port, d1,
					c->spd.that.protocol, c->spd.that.port,
					is_virtual_connection(c) ?
					"(virt)" : "", d->name, s3,
					sr->this.protocol, sr->this.port,
					d3, sr->that.protocol, sr->that.port,
					is_virtual_sr(sr) ? "(virt)" : "");
			});

			if (!samesubnet(&sr->this.client, our_net)) {
				DBG(DBG_CONTROLMORE,
					char s3[SUBNETTOT_BUF];
					subnettot(&sr->this.client, 0, s3,
						sizeof(s3));
					DBG_log("   our client(%s) not in our_net (%s)",
						s3, s1));

				continue;
			}

			if (sr->that.has_client) {
				if (sr->that.has_client_wildcard) {
					if (!subnetinsubnet(peer_net,
							    &sr->that.client))
						continue;
				} else {
					if (!samesubnet(&sr->that.client,
							 peer_net) &&
					    !is_virtual_sr(sr)) {
						DBG(DBG_CONTROLMORE, {
							char d3[SUBNETTOT_BUF];
							subnettot(&sr->that.client, 0, d3,
								sizeof(d3));
							DBG_log("   their client(%s) not in same peer_net (%s)",
								d3, d1);
						});
						continue;
					}

					virtualwhy = check_virtual_net_allowed(
							d,
							peer_net,
							&sr->that.host_addr);

					if (is_virtual_sr(sr) &&
					    (virtualwhy != NULL ||
					     is_virtual_net_used(
						d,
						peer_net,
						peer_id != NULL ?
						    peer_id : &sr->that.id)))
					{
						DBG(DBG_CONTROLMORE,
							DBG_log("   virtual net not allowed"));
						continue;
					}
				}
			} else {
				if (!peer_net_is_host)
					continue;
			}

			/*
			 * We've run the gauntlet -- success:
			 * We've got an exact match of subnets.
			 * The connection is feasible, but we continue looking
			 * for the best.
			 * The highest priority wins, implementing eroute-like
			 * rule.
			 * - a routed connection is preferrred
			 * - given that, the smallest number of ID wildcards
			 *   are preferred
			 * - given that, the shortest CA pathlength is preferred
			 */
			prio = PRIO_WEIGHT * routed(sr->routing) +
				WILD_WEIGHT * (MAX_WILDCARDS - wildcards) +
				PATH_WEIGHT * (MAX_CA_PATH_LEN - pathlen) +
				1;
			if (prio > best_prio) {
				best = d;
				best_prio = prio;
			}
		}
	}

	if (best != NULL && NEVER_NEGOTIATE(best->policy))
		best = NULL;

	DBG(DBG_CONTROLMORE,
		DBG_log("  fc_try concluding with %s [%ld]",
			(best ? best->name : "none"), best_prio));

	if (best == NULL) {
		if (virtualwhy != NULL) {
			libreswan_log(
				"peer proposal was reject in a virtual connection policy: %s",
				virtualwhy);
		}
	}

	return best;
}

static struct connection *fc_try_oppo(const struct connection *c,
				struct host_pair *hp,
				const ip_subnet *our_net,
				const ip_subnet *peer_net,
				const u_int8_t our_protocol,
				const u_int16_t our_port,
				const u_int8_t peer_protocol,
				const u_int16_t peer_port)
{
	struct connection *d;
	struct connection *best = NULL;
	policy_prio_t best_prio = BOTTOM_PRIO;
	int wildcards, pathlen;

	for (d = hp->connections; d != NULL; d = d->hp_next) {
		struct spd_route *sr;
		policy_prio_t prio;

		if (d->policy & POLICY_GROUP)
			continue;

		if (!(same_id(&c->spd.this.id, &d->spd.this.id) &&
				match_id(&c->spd.that.id, &d->spd.that.id,
					&wildcards) &&
				trusted_ca_nss(c->spd.that.ca, d->spd.that.ca,
					&pathlen)))
			continue;

		/* compare protocol and ports */
		if (d->spd.this.protocol != our_protocol ||
			(d->spd.this.port && d->spd.this.port != our_port) ||
			d->spd.that.protocol != peer_protocol ||
			(d->spd.that.port != peer_port &&
				!d->spd.that.has_port_wildcard))
			continue;

		/*
		 * Opportunistic case:
		 * our_net must be inside d->spd.this.client
		 * and peer_net must be inside d->spd.that.client
		 * Note: this host_pair chain also has shunt
		 * eroute conns (clear, drop), but they won't
		 * be marked as opportunistic.
		 */
		for (sr = &d->spd; sr != NULL; sr = sr->next) {
			DBG(DBG_CONTROLMORE, {
				char s1[SUBNETTOT_BUF];
				char d1[SUBNETTOT_BUF];
				char s3[SUBNETTOT_BUF];
				char d3[SUBNETTOT_BUF];

				subnettot(our_net, 0, s1, sizeof(s1));
				subnettot(peer_net, 0, d1, sizeof(d1));
				subnettot(&sr->this.client, 0, s3,
					sizeof(s3));
				subnettot(&sr->that.client, 0, d3,
					sizeof(d3));
				DBG_log("  fc_try_oppo trying %s:%s -> "
					"%s vs %s:%s -> %s",
					c->name, s1, d1, d->name, s3, d3);
			});

			if (!subnetinsubnet(our_net, &sr->this.client) ||
				!subnetinsubnet(peer_net, &sr->that.client))
				continue;

			/*
			 * The connection is feasible, but we continue looking
			 * for the best.
			 * The highest priority wins, implementing eroute-like
			 * rule.
			 * - our smallest client subnet is preferred (longest
			 *   mask)
			 * - given that, his smallest client subnet is preferred
			 * - given that, a routed connection is preferrred
			 * - given that, the smallest number of ID wildcards
			 *   are preferred
			 * - given that, the shortest CA pathlength is preferred
			 */
			prio = PRIO_WEIGHT * (d->prio + routed(sr->routing)) +
				WILD_WEIGHT * (MAX_WILDCARDS - wildcards) +
				PATH_WEIGHT * (MAX_CA_PATH_LEN - pathlen);
			if (prio > best_prio) {
				best = d;
				best_prio = prio;
			}
		}
	}

	/* if the best wasn't opportunistic, we fail: it must be a shunt */
	if (best != NULL &&
		(NEVER_NEGOTIATE(best->policy) ||
			(best->policy & POLICY_OPPORTUNISTIC) == LEMPTY))
		best = NULL;

	DBG(DBG_CONTROLMORE,
		DBG_log("  fc_try_oppo concluding with %s [%ld]",
			(best ? best->name : "none"), best_prio));
	return best;

}

struct connection *find_client_connection(struct connection *const c,
					const ip_subnet *our_net,
					const ip_subnet *peer_net,
					const u_int8_t our_protocol,
					const u_int16_t our_port,
					const u_int8_t peer_protocol,
					const u_int16_t peer_port)
{
	struct connection *d;
	struct spd_route *sr;

	DBG(DBG_CONTROLMORE, {
		char s1[SUBNETTOT_BUF];
		char d1[SUBNETTOT_BUF];

		subnettot(our_net, 0, s1, sizeof(s1));
		subnettot(peer_net, 0, d1, sizeof(d1));

		DBG_log("find_client_connection starting with %s",
			c->name);
		DBG_log("  looking for %s:%d/%d -> %s:%d/%d",
			s1, our_protocol, our_port,
			d1, peer_protocol, peer_port);
	});

	/*
	 * Give priority to current connection
	 * but even greater priority to a routed concrete connection.
	 */
	{
		struct connection *unrouted = NULL;
		int srnum = -1;

		for (sr = &c->spd; unrouted == NULL && sr != NULL;
			sr = sr->next) {
			srnum++;

			DBG(DBG_CONTROLMORE, {
				char s2[SUBNETTOT_BUF];
				char d2[SUBNETTOT_BUF];

				subnettot(&sr->this.client, 0, s2, sizeof(s2));
				subnettot(&sr->that.client, 0, d2, sizeof(d2));
				DBG_log("  concrete checking against sr#%d "
					"%s -> %s", srnum, s2, d2);
			});

			if (samesubnet(&sr->this.client, our_net) &&
				samesubnet(&sr->that.client, peer_net) &&
				sr->this.protocol == our_protocol &&
				(!sr->this.port ||
					sr->this.port == our_port) &&
				(sr->that.protocol == peer_protocol) &&
				(!sr->that.port ||
					sr->that.port == peer_port)) {
				passert(oriented(*c));
				if (routed(sr->routing))
					return c;

				unrouted = c;
			}
		}

		/* exact match? */
		/*
		 * clang 3.4 says: warning: Access to field 'host_pair' results in a dereference of a null pointer (loaded from variable 'c')
		 * If so, the caller must have passed NULL for it
		 * and earlier references would be wrong (segfault).
		 */
		d = fc_try(c, c->host_pair, NULL, our_net, peer_net,
			our_protocol, our_port, peer_protocol, peer_port);

		DBG(DBG_CONTROLMORE,
			DBG_log("  fc_try %s gives %s",
				c->name,
				(d ? d->name : "none")));

		if (d == NULL)
			d = unrouted;
	}

	if (d == NULL) {
		/* look for an abstract connection to match */
		struct spd_route *sra;
		struct host_pair *hp = NULL;

		for (sra = &c->spd; hp == NULL &&
				sra != NULL; sra = sra->next) {
			hp = find_host_pair(&sra->this.host_addr,
					sra->this.host_port,
					NULL,
					sra->that.host_port);
			DBG(DBG_CONTROLMORE, {
				char s2[SUBNETTOT_BUF];
				char d2[SUBNETTOT_BUF];

				subnettot(&sra->this.client, 0, s2,
					sizeof(s2));
				subnettot(&sra->that.client, 0, d2,
					sizeof(d2));

				DBG_log("  checking hostpair %s -> %s is %s",
					s2, d2,
					(hp ? "found" : "not found"));
			});
		}

		if (hp != NULL) {
			/* RW match with actual peer_id or abstract peer_id? */
			d = fc_try(c, hp, NULL, our_net, peer_net,
				our_protocol, our_port, peer_protocol,
				peer_port);

			if (d == NULL &&
				subnetishost(our_net) &&
				subnetishost(peer_net)) {
				/*
				 * Opportunistic match?
				 * Always use abstract peer_id.
				 * Note that later instantiation will result
				 * in the same peer_id.
				 */
				d = fc_try_oppo(c, hp, our_net, peer_net,
						our_protocol, our_port,
						peer_protocol, peer_port);
			}
		}
	}

	DBG(DBG_CONTROLMORE,
		DBG_log("  concluding with d = %s",
			(d ? d->name : "none")));
	return d;
}

/* signed result suitable for quicksort */
int connection_compare(const struct connection *ca,
		const struct connection *cb)
{
	int ret;

	ret = strcmp(ca->name, cb->name);
	if (ret != 0)
		return ret;

	/* note: enum connection_kind behaves like int */
	ret = ca->kind - cb->kind;
	if (ret != 0)
		return ret;

	/* same name, and same type */
	switch (ca->kind) {
	case CK_INSTANCE:
		return ca->instance_serial < cb->instance_serial ? -1 :
		ca->instance_serial > cb-> instance_serial ? 1 : 0;

	default:
		return ca->prio < cb->prio ? -1 : ca->prio > cb->prio ? 1 : 0;
	}
}

static int connection_compare_qsort(const void *a, const void *b)
{
	return connection_compare(*(const struct connection *const *)a,
				*(const struct connection *const *)b);
}

static void show_one_sr(struct connection *c,
			struct spd_route *sr,
			char *instance)
{
	char topo[CONN_BUF_LEN];
	ipstr_buf thisipb, thatipb, dns1b, dns2b;

	(void) format_connection(topo, sizeof(topo), c, sr);
	whack_log(RC_COMMENT, "\"%s\"%s: %s; %s; eroute owner: #%lu",
		c->name, instance, topo,
		enum_name(&routing_story, sr->routing),
		sr->eroute_owner);

#define OPT_HOST(h, ipb)  (addrbytesptr(h, NULL) == 0 || isanyaddr(h) ? \
			"unset" : ipstr(h, &ipb))

		/* note: this macro generates a pair of arguments */
#define OPT_PREFIX_STR(pre, s) (s) == NULL ? "" : (pre), (s) == NULL? "" : (s)

	whack_log(RC_COMMENT,
		"\"%s\"%s:     %s; my_ip=%s; their_ip=%s%s%s%s%s%s%s%s%s",
		c->name, instance,
		oriented(*c) ? "oriented" : "unoriented",
		OPT_HOST(&c->spd.this.host_srcip, thisipb),
		OPT_HOST(&c->spd.that.host_srcip, thatipb),
		OPT_PREFIX_STR("; myup=", sr->this.updown),
		OPT_PREFIX_STR("; theirup=", sr->that.updown),
		OPT_PREFIX_STR("; mycert=", sr->this.cert_nickname),
		OPT_PREFIX_STR("; hiscert=", sr->that.cert_nickname));

#undef OPT_HOST
#undef OPT_PREFIX_STR

	/*
	 * Both should not be set, but if they are, we want
	 * to know
	 */
#define COMBO(END, SERVER, CLIENT) \
	((END).SERVER ? \
		((END).CLIENT ? "BOTH??" : "server") : \
		((END).CLIENT ? "client" : "none"))

	whack_log(RC_COMMENT,
		"\"%s\"%s:   xauth info: us:%s, them:%s, %s my_xauthuser=%s; their_xauthuser=%s",
		c->name, instance,
		/*
		 * Both should not be set, but if they are, we want to
		 * know
		 */
		COMBO(sr->this, xauth_server, xauth_client),
		COMBO(sr->that, xauth_server, xauth_client),
		/* should really be an enum name */
		sr->this.xauth_server ?
			c->xauthby == XAUTHBY_FILE ?
				"method:file;" :
			c->xauthby == XAUTHBY_PAM ?
				"method:pam;" :
				"method:alwaysok;" :
			"",
		sr->this.xauth_name != NULL ? sr->this.xauth_name : "[any]",
		sr->that.xauth_name != NULL ? sr->that.xauth_name : "[any]");

	whack_log(RC_COMMENT,
		"\"%s\"%s:   modecfg info: us:%s, them:%s, modecfg "
		"policy:%s, dns1:%s, dns2:%s, domain:%s%s;",
		c->name, instance,
		COMBO(sr->this, modecfg_server, modecfg_client),
		COMBO(sr->that, modecfg_server, modecfg_client),

		(c->policy & POLICY_MODECFG_PULL) ? "pull" : "push",
		isanyaddr(&c->modecfg_dns1) ? "unset" : ipstr(&c->modecfg_dns1, &dns1b),
		isanyaddr(&c->modecfg_dns2) ? "unset" : ipstr(&c->modecfg_dns2, &dns2b),
		(c->modecfg_domain == NULL) ? "unset" : c->modecfg_domain,
		(c->modecfg_banner == NULL) ? ", banner:unset" : "");

#undef COMBO

	if (c->modecfg_banner != NULL) {
		whack_log(RC_COMMENT, "\"%s\"%s: banner:%s;",
		c->name, instance, c->modecfg_banner);
	}

	/*
	 * Always print the labeled ipsec status; and always use the
	 * same log call.  Ensures that test result output is
	 * consistent regardless of support.
	 */
	const char *labeled_ipsec;
	const char *policy_label;
#ifdef HAVE_LABELED_IPSEC
	labeled_ipsec = c->labeled_ipsec ? "yes" : "no";
	policy_label = (c->policy_label == NULL) ? "unset" : c->policy_label;
#else
	labeled_ipsec = "no";
	policy_label = "unset";
#endif
	whack_log(RC_COMMENT, "\"%s\"%s:   labeled_ipsec:%s;",
		  c->name, instance, labeled_ipsec);
	whack_log(RC_COMMENT, "\"%s\"%s:   policy_label:%s;",
		  c->name, instance, policy_label);

}

void show_one_connection(struct connection *c)
{
	const char *ifn;
	char instance[1 + 10 + 1];
	char prio[POLICY_PRIO_BUF];
	char mtustr[8];
	char sapriostr[13];
	char nflogstr[8];

	ifn = oriented(*c) ? c->interface->ip_dev->id_rname : "";

	instance[0] = '\0';
	if (c->kind == CK_INSTANCE && c->instance_serial != 0)
		snprintf(instance, sizeof(instance), "[%lu]",
			c->instance_serial);

	/* Show topology. */
	{
		struct spd_route *sr = &c->spd;

		while (sr != NULL) {
			show_one_sr(c, sr, instance);
			sr = sr->next;
		}
	}

	/* Show CAs */
	if (c->spd.this.ca.ptr != NULL || c->spd.that.ca.ptr != NULL) {
		char this_ca[IDTOA_BUF], that_ca[IDTOA_BUF];

		dntoa_or_null(this_ca, IDTOA_BUF, c->spd.this.ca, "%any");
		dntoa_or_null(that_ca, IDTOA_BUF, c->spd.that.ca, "%any");

		whack_log(RC_COMMENT,
			"\"%s\"%s:   CAs: '%s'...'%s'",
			c->name,
			instance,
			this_ca,
			that_ca);
	}

	whack_log(RC_COMMENT,
		"\"%s\"%s:   ike_life: %lds; ipsec_life: %lds;"
		" rekey_margin: %lds; rekey_fuzz: %lu%%; keyingtries: %lu;",
		c->name,
		instance,
		(long) deltasecs(c->sa_ike_life_seconds),
		(long) deltasecs(c->sa_ipsec_life_seconds),
		(long) deltasecs(c->sa_rekey_margin),
		c->sa_rekey_fuzz,
		c->sa_keying_tries);

	whack_log(RC_COMMENT,
		"\"%s\"%s:   retransmit-interval: %ldms; retransmit-timeout: %lds;",
		c->name,
		instance,
		c->r_interval,
		(long) deltasecs(c->r_timeout));

	whack_log(RC_COMMENT,
		  "\"%s\"%s:   sha2_truncbug:%s; initial_contact:%s; cisco_unity:%s; send_vendorid:%s;",
		  c->name, instance,
		  (c->sha2_truncbug) ? "yes" : "no",
		  (c->initial_contact) ? "yes" : "no",
		  (c->cisco_unity) ? "yes" : "no",
		  (c->send_vendorid) ? "yes" : "no");

	if (c->policy_next) {
		whack_log(RC_COMMENT,
			"\"%s\"%s:   policy_next: %s",
			c->name, instance, c->policy_next->name);
	}

	whack_log(RC_COMMENT, "\"%s\"%s:   policy: %s%s%s%s;",
		  c->name, instance,
		  prettypolicy(c->policy),
		  c->spd.this.key_from_DNS_on_demand |
			c->spd.that.key_from_DNS_on_demand ? "; " : "",
		  c->spd.this.key_from_DNS_on_demand ? "+lKOD" : "",
		  c->spd.that.key_from_DNS_on_demand ? "+rKOD" : "");

	if (c->connmtu != 0)
		snprintf(mtustr, sizeof(mtustr), "%d", c->connmtu);
	else
		strcpy(mtustr, "unset");

	if (c->sa_priority != 0)
		snprintf(sapriostr, sizeof(sapriostr), "%u", c->sa_priority);
	else
		strcpy(sapriostr, "auto");

	if (c->nflog_group != 0)
		snprintf(nflogstr, sizeof(nflogstr), "%d", c->nflog_group);
	else
		strcpy(nflogstr, "unset");

	fmt_policy_prio(c->prio, prio);
	whack_log(RC_COMMENT,
		  "\"%s\"%s:   conn_prio: %s; interface: %s; metric: %lu; mtu: %s; sa_prio:%s; nflog-group: %s;",
		  c->name, instance,
		  prio,
		  ifn,
		  (unsigned long)c->metric,
		  mtustr, sapriostr, nflogstr);

	/* slightly complicated stuff to avoid extra crap */
	/* ??? real-world and DBG control flow mixed */
	if (deltasecs(c->dpd_timeout) > 0 || DBGP(DBG_DPD)) {
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   dpd: %s; delay:%ld; timeout:%ld; nat-t: force_encaps:%s; nat_keepalive:%s; ikev1_natt:%s",
			  c->name, instance,
			  enum_name(&dpd_action_names, c->dpd_action),
			  (long) deltasecs(c->dpd_delay),
			  (long) deltasecs(c->dpd_timeout),
			  (c->forceencaps) ? "yes" : "no",
			  (c->nat_keepalive) ? "yes" : "no",
			  (c->ikev1_natt == natt_both) ? "both" :
			  ((c->ikev1_natt == natt_rfc) ? "rfc" : "drafts"));
	}

	if (c->extra_debugging) {
		whack_log(RC_COMMENT, "\"%s\"%s:   debug: %s",
			c->name,
			instance,
			bitnamesof(debug_bit_names,
				c->extra_debugging));
	}

	whack_log(RC_COMMENT,
		"\"%s\"%s:   newest ISAKMP SA: #%lu; newest IPsec SA: #%lu;",
		c->name,
		instance,
		c->newest_isakmp_sa,
		c->newest_ipsec_sa);

	if (c->connalias) {
		whack_log(RC_COMMENT,
			"\"%s\"%s:   aliases: %s\n",
			c->name,
			instance,
			c->connalias);
	}

	ike_alg_show_connection(c, instance);
	kernel_alg_show_connection(c, instance);
}

void show_connections_status(void)
{
	int count = 0;
	int active = 0;
	struct connection *c;

	whack_log(RC_COMMENT, " "); /* spacer */
	whack_log(RC_COMMENT, "Connection list:"); /* spacer */
	whack_log(RC_COMMENT, " "); /* spacer */

	for (c = connections; c != NULL; c = c->ac_next) {
		count++;
		if (c->spd.routing == RT_ROUTED_TUNNEL)
			active++;
	}

	if (count != 0) {
		/* make an array of connections, sort it, and report it */

		struct connection **array =
			alloc_bytes(sizeof(struct connection *) * count,
				"connection array");
		int i = 0;

		for (c = connections; c != NULL; c = c->ac_next)
			array[i++] = c;

		/* sort it! */
		qsort(array, count, sizeof(struct connection *),
			connection_compare_qsort);

		for (i = 0; i < count; i++)
			show_one_connection(array[i]);

		pfree(array);
		whack_log(RC_COMMENT, " "); /* spacer */
	}

	whack_log(RC_COMMENT, "Total IPsec connections: loaded %d, active %d",
		count, active);
}

/*
 * Delete a connection if it is an instance and it is no longer in use.
 * We must be careful to avoid circularity:
 * we don't touch it if it is CK_GOING_AWAY.
 */
void connection_discard(struct connection *c)
{
	if (c->kind == CK_INSTANCE) {
		if (in_pending_use(c))
			return;

		if (!states_use_connection(c))
			delete_connection(c, FALSE);
	}
}

/*
 * A template connection's eroute can be eclipsed by
 * either a %hold or an eroute for an instance iff
 * the template is a /32 -> /32. This requires some special casing.
 */
long eclipse_count = 0;

struct connection *eclipsed(struct connection *c, struct spd_route **esrp)
{
	struct connection *ue;
	struct spd_route *sr1 = &c->spd;

	ue = NULL;

	/*
	 * This function was changed in freeswan 2.02 and since
	 * then has never worked because it always returned NULL.
	 * It should be caught by the testing/pluto/co-terminal test cases
	 */

	if (sr1 == NULL) {
		DBG(DBG_CONTROLMORE, DBG_log("eclipsed() returning NULL due to sr1 == NULL"));
		return NULL;
	}

	for (ue = connections; ue != NULL; ue = ue->ac_next) {
		struct spd_route *srue = &ue->spd;

		while (srue != NULL && srue->routing == RT_ROUTED_ECLIPSED &&
			!(samesubnet(&sr1->this.client, &srue->this.client) &&
				samesubnet(&sr1->that.client,
					&srue->that.client)))
			srue = srue->next;
		if (srue != NULL && srue->routing == RT_ROUTED_ECLIPSED) {
			*esrp = srue;
			break;
		}
	}
	if (ue == NULL) {
		DBG(DBG_CONTROLMORE, DBG_log("eclipsed() returning NULL due to ue == NULL"));
	} else {
		DBG(DBG_CONTROLMORE, DBG_log("eclipsed() returning non-NULL ue"));
	}
	return ue;
}

void liveness_clear_connection(struct connection *c, char *v)
{
	libreswan_log("%s: Clearing Connection %s[%lu] %s",v, c->name,
			c->instance_serial, enum_name(&connection_kind_names,
				c->kind));
	/*
	 * For CK_INSTANCE, delete_states_by_connection() will clear
	 * Note that delete_states_by_connection changes c->kind but we need
	 * to remember what it was to know if we still need to unroute after delete
	 */
	if (c->kind == CK_INSTANCE) {
		delete_states_by_connection(c, TRUE);
	} else {
		flush_pending_by_connection(c); /* remove any partial negotiations that are failing */
		delete_states_by_connection(c, TRUE);
		DBG(DBG_DPD,
				DBG_log("%s: unrouting connection %s",
					enum_name(&connection_kind_names,
						c->kind), v));
		unroute_connection(c); /* --unroute */
	}
}
