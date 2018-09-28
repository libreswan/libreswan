/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2010,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2009 Stefan Arentz <stefan@arentz.ca>
 * Copyright (C) 2009-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2007-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Panagiotis Tamtamis <tamtamis@gmail.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 *
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
 *
 */

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "secrets.h"

#include "defs.h"
#include "connections.h"        /* needs id.h */
#include "pending.h"
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "server.h"
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "keys.h"
#include "whack.h"
#include "alg_info.h"
#include "spdb.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1_xauth.h"
#include "nat_traversal.h"
#include "ip_address.h"

#include "virtual.h"	/* needs connections.h */

#include "hostpair.h"

/*
 * swap ends and try again.
 * It is a little tricky to see that this loop will stop.
 * Only continue if the far side matches.
 * If both sides match, there is an error-out.
 */
static void swap_ends(struct connection *c)
{
	struct spd_route *sr = &c->spd;
	struct end t = sr->this;

	sr->this = sr->that;
	sr->that = t;

	/*
	 * in case of asymetric auth c->policy contains left.authby
	 * This magic will help responder to find connction during INIT
	 */
	if (sr->this.authby != sr->that.authby)
	{
		c->policy &= ~POLICY_ID_AUTH_MASK;
		switch (sr->this.authby) {
		case AUTH_PSK:
			c->policy |= POLICY_PSK;
			break;
		case AUTH_RSASIG:
			c->policy |= POLICY_RSASIG;
			break;
		case AUTH_ECDSA:
			c->policy |= POLICY_ECDSA;
			break;
		case AUTH_NULL:
			c->policy |= POLICY_AUTH_NULL;
			break;
		case AUTH_NEVER:
			/* nothing to add */
			break;
		default:
			bad_case(sr->this.authby);
		}
	}
}


bool orient(struct connection *c)
{
	if (!oriented(*c)) {
		const struct iface_port *p;
		struct spd_route *sr = &c->spd;
		for (p = interfaces; p != NULL; p = p->next) {
			if (p->ike_float)
				continue;

			for (;;) {
				/* check if this interface matches this end */
				if (sameaddr(&sr->this.host_addr,
					     &p->ip_addr) &&
				    (kern_interface != NO_KERNEL ||
				     sr->this.host_port ==
				     pluto_port)) {
					if (oriented(*c)) {
						if (c->interface->ip_dev == p->ip_dev) {
							char cib[CONN_INST_BUF];
							loglog(RC_LOG_SERIOUS,
								"both sides of \"%s\"%s are our interface %s!",
								c->name, fmt_conn_instance(c, cib),
								p->ip_dev->id_rname);
						} else {
							char cib[CONN_INST_BUF];
							loglog(RC_LOG_SERIOUS, "two interfaces match \"%s\"%s (%s, %s)",
								c->name, fmt_conn_instance(c, cib),
								c->interface->ip_dev->id_rname,
								p->ip_dev->id_rname);
							}
						terminate_connection(c->name);
						c->interface = NULL; /* withdraw orientation */
						return FALSE;
					}
					c->interface = p;
				}

				/* done with this interface if it doesn't match that end */
				if (!(sameaddr(&sr->that.host_addr,
					       &p->ip_addr) &&
				      (kern_interface != NO_KERNEL ||
				       sr->that.host_port ==
				       pluto_port)))
					break;

				swap_ends(c);
			}
		}
	}
	return oriented(*c);
}

struct initiate_stuff {
	fd_t whackfd;
	lmod_t more_debugging;
	lmod_t more_impairing;
	char *remote_host;
};

static int initiate_a_connection(struct connection *c, void *arg)
{
	struct initiate_stuff *is = (struct initiate_stuff *)arg;
	fd_t whackfd = is->whackfd;

	set_cur_connection(c);

	/* turn on any extra debugging asked for */
	lmod_merge(&c->extra_debugging, is->more_debugging);
	lmod_merge(&c->extra_impairing, is->more_impairing);

	/* If whack supplied a remote IP, fill it in if we can */
	if (is->remote_host != NULL && isanyaddr(&c->spd.that.host_addr)) {
		ip_address remote_ip;

		ttoaddr_num(is->remote_host, 0, AF_UNSPEC, &remote_ip);

		if (c->kind != CK_TEMPLATE) {
			loglog(RC_NOPEERIP,
				"Cannot instantiate non-template connection to a supplied remote IP address");
			reset_cur_connection();
			return 0;
		}

		c = instantiate(c, &remote_ip, NULL);
		whack_log(RC_LOG, "Instantiated connection '%s' with remote IP set to %s",
			c->name, is->remote_host);
		/* now proceed as normal */
	}

	if (!oriented(*c)) {
		ipstr_buf a;
		ipstr_buf b;
		loglog(RC_ORIENT,
			"We cannot identify ourselves with either end of this connection.  %s or %s are not usable",
			ipstr(&c->spd.this.host_addr, &a),
			ipstr(&c->spd.that.host_addr, &b));
		reset_cur_connection();
		return 0;
	}

	if (NEVER_NEGOTIATE(c->policy)) {
		loglog(RC_INITSHUNT,
			"cannot initiate an authby=never connection");
		reset_cur_connection();
		return 0;
	}

	if ((is->remote_host == NULL) && (c->kind != CK_PERMANENT) && !(c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
		if (isanyaddr(&c->spd.that.host_addr)) {
			if (c->dnshostname != NULL) {
				loglog(RC_NOPEERIP,
					"cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s)",
					enum_show(&connection_kind_names,
						 c->kind));
				c->policy |= POLICY_UP;
				reset_cur_connection();
				return 1;
			} else {
				loglog(RC_NOPEERIP,
					"cannot initiate connection without knowing peer IP address (kind=%s)",
					enum_show(&connection_kind_names, c->kind));
			}
			reset_cur_connection();
			return 0;
		}

		if (!(c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
			loglog(RC_WILDCARD,
				"cannot initiate connection with narrowing=no and (kind=%s)",
				enum_show(&connection_kind_names, c->kind));
		} else {
			loglog(RC_WILDCARD,
				"cannot initiate connection with ID wildcards (kind=%s)",
				enum_show(&connection_kind_names, c->kind));
		}
		reset_cur_connection();
		return 0;
	}

	if (isanyaddr(&c->spd.that.host_addr) && (c->policy & POLICY_IKEV2_ALLOW_NARROWING) ) {
		if (c->dnshostname != NULL) {
			loglog(RC_NOPEERIP,
				"cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s, narrowing=%s)",
				enum_show(&connection_kind_names, c->kind),
					bool_str((c->policy & POLICY_IKEV2_ALLOW_NARROWING) != LEMPTY));
			c->policy |= POLICY_UP;
			reset_cur_connection();
			return 1;
		} else {
			loglog(RC_NOPEERIP,
				"cannot initiate connection without knowing peer IP address (kind=%s narrowing=%s)",
				enum_show(&connection_kind_names,
					c->kind),
				bool_str((c->policy & POLICY_IKEV2_ALLOW_NARROWING) != LEMPTY));
			reset_cur_connection();
			return 0;
		}
	}

	if (LIN(POLICY_IKEV2_PROPOSE | POLICY_IKEV2_ALLOW_NARROWING, c->policy) &&
		c->kind == CK_TEMPLATE) {
			c = instantiate(c, NULL, NULL);
	}

	/* We will only request an IPsec SA if policy isn't empty
	 * (ignoring Main Mode items).
	 * This is a fudge, but not yet important.
	 * If we are to proceed asynchronously, whackfd will be NULL_FD.
	 */

	if (c->policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE)) {
		struct alg_info_esp *alg = c->alg_info_esp;
		struct db_sa *phase2_sa = kernel_alg_makedb(
			c->policy, alg, TRUE);

		if (alg != NULL && phase2_sa == NULL) {
			whack_log(RC_LOG_SERIOUS,
				  "cannot initiate: no acceptable kernel algorithms loaded");
			reset_cur_connection();
			close_any(&is->whackfd);
			return 0;
		}
		free_sa(&phase2_sa);
	}

	c->policy |= POLICY_UP;
	whackfd = dup_any(whackfd);
	ipsecdoi_initiate(whackfd, c, c->policy, 1, SOS_NOBODY
#ifdef HAVE_LABELED_IPSEC
		  , NULL
#endif
		  );

	reset_cur_connection();
	return 1;
}

void initiate_connection(const char *name, fd_t whackfd,
			 lmod_t more_debugging,
			 lmod_t more_impairing,
			 char *remote_host)
{
	struct connection *c = conn_by_name(name, FALSE, FALSE);
	int count;

	passert(name != NULL);
	struct initiate_stuff is = {
		.whackfd = whackfd,
		.more_debugging = more_debugging,
		.more_impairing = more_impairing,
		.remote_host = remote_host,
	};

	if (c != NULL) {
		if (!initiate_a_connection(c, &is))
			whack_log(RC_FATAL, "failed to initiate %s", c->name);
		close_any(&is.whackfd);
		return;
	}

	loglog(RC_COMMENT, "initiating all conns with alias='%s'", name);
	count = foreach_connection_by_alias(name, initiate_a_connection, &is);

	if (count == 0) {
		whack_log(RC_UNKNOWN_NAME,
			  "no connection named \"%s\"", name);
	}

	close_any(&is.whackfd);
}

static bool same_host(const char *a_dnshostname, const ip_address *a_host_addr,
		const char *b_dnshostname, const ip_address *b_host_addr)
{
	/* should this be dnshostname and host_addr ?? */

	return a_dnshostname == NULL ?
		b_dnshostname == NULL && sameaddr(a_host_addr, b_host_addr) :
		b_dnshostname != NULL && streq(a_dnshostname, b_dnshostname);
}

static bool same_in_some_sense(const struct connection *a,
			const struct connection *b)
{
	return same_host(a->dnshostname, &a->spd.that.host_addr,
			b->dnshostname, &b->spd.that.host_addr);
}

void restart_connections_by_peer(struct connection *const c)
{
	/*
	 * If c is a CK_INSTANCE, it will be removed by terminate_connection.
	 * Any parts of c we need after that must be copied first.
	 */

	struct host_pair *hp = c->host_pair;
	enum connection_kind c_kind  = c->kind;
	struct connection *hp_next = hp->connections->hp_next;

	pexpect(hp != NULL);	/* ??? why would this happen? */
	if (hp == NULL)
		return;

	char *dnshostname = clone_str(c->dnshostname, "dnshostname for restart");

	ip_address host_addr = c->spd.that.host_addr;

	struct connection *d;

	for (d = hp->connections; d != NULL;) {
		struct connection *next = d->hp_next; /* copy before d is deleted, CK_INSTANCE */

		if (same_host(dnshostname, &host_addr,
				d->dnshostname, &d->spd.that.host_addr))
		{
			/* This might delete c if CK_INSTANCE */
			/* ??? is there a chance hp becomes dangling? */
			terminate_connection(d->name);
		}
		d = next;
	}

	if (c_kind != CK_INSTANCE) {
		/* reference to c is OK because not CK_INSTANCE */
		update_host_pairs(c);
		/* host_pair/host_addr changes with dynamic dns */
		hp = c->host_pair;
		host_addr = c->spd.that.host_addr;
	}

	if (c_kind == CK_INSTANCE && hp_next == NULL) {
		/* in simple cases this is  a dangling hp */
		DBG(DBG_CONTROL,
			DBG_log ("no connection to restart after termination"));
	} else {
		for (d = hp->connections; d != NULL; d = d->hp_next) {
			if (same_host(dnshostname, &host_addr,
					d->dnshostname, &d->spd.that.host_addr))
				initiate_connection(d->name, null_fd,
						    empty_lmod, empty_lmod,
						    NULL);
		}
	}
	pfreeany(dnshostname);
}

/* (Possibly) Opportunistic Initiation:
 * Knowing clients (single IP addresses), try to build a tunnel.
 * This may involve discovering a gateway and instantiating an
 * Opportunistic connection.  Called when a packet is caught by
 * a %trap, or when whack --oppohere --oppothere is used.
 * It may turn out that an existing or non-opporunistic connnection
 * can handle the traffic.
 *
 * Most of the code will be restarted if an ADNS request is made
 * to discover the gateway.  The only difference between the first
 * and second entry is whether gateways_from_dns is NULL or not.
 *	initiate_opportunistic: initial entrypoint
 *	continue_oppo: where we pickup when ADNS result arrives
 *	initiate_opportunistic_body: main body shared by above routines
 *	cannot_oppo: a helper function to log a diagnostic
 * This structure repeats a lot of code when the ADNS result arrives.
 * This seems like a waste, but anything learned the first time through
 * may no longer be true!
 *
 * After the first IKE message is sent, the regular state machinery
 * carries negotiation forward.
 */

struct find_oppo_bundle {
	err_t want;
	bool failure_ok;        /* if true, continue_oppo should not die on DNS failure */
	ip_address our_client;  /* not pointer! */
	ip_address peer_client;
	int transport_proto;
	bool held;
	policy_prio_t policy_prio;
	ipsec_spi_t negotiation_shunt; /* in host order! */
	ipsec_spi_t failure_shunt; /* in host order! */
	fd_t whackfd;
};

static void cannot_oppo(struct connection *c,
			struct find_oppo_bundle *b,
			err_t ughmsg)
{
	char pcb[ADDRTOT_BUF];
	char ocb[ADDRTOT_BUF];

	addrtot(&b->peer_client, 0, pcb, sizeof(pcb));
	addrtot(&b->our_client, 0, ocb, sizeof(ocb));

	DBG(DBG_OPPO,
	    libreswan_log("Cannot opportunistically initiate for %s to %s: %s",
			  ocb, pcb, ughmsg));

	whack_log(RC_OPPOFAILURE,
		  "Cannot opportunistically initiate for %s to %s: %s",
		  ocb, pcb, ughmsg);

	if (c != NULL && c->policy_next != NULL) {
		/* there is some policy that comes afterwards */
		struct connection *nc = c->policy_next;

		passert(c->kind == CK_TEMPLATE);
		passert(nc->kind == CK_PERMANENT);

		DBG(DBG_OPPO,
		    DBG_log("OE failed for %s to %s, but %s overrides shunt",
			    ocb, pcb, nc->name));

		/*
		 * okay, here we need add to the "next" policy, which ought
		 * to be an instance.
		 * We will add another entry to the spd_route list for the specific
		 * situation that we have.
		 */

		struct spd_route *shunt_spd = clone_thing(nc->spd, "shunt eroute policy");

		shunt_spd->spd_next = nc->spd.spd_next;
		nc->spd.spd_next = shunt_spd;

		happy(addrtosubnet(&b->peer_client, &shunt_spd->that.client));

		if (sameaddr(&b->peer_client, &shunt_spd->that.host_addr))
			shunt_spd->that.has_client = FALSE;

		/*
		 * override the tunnel destination with the one from the secondaried
		 * policy
		 */
		shunt_spd->that.host_addr = nc->spd.that.host_addr;

		/* now, lookup the state, and poke it up. */

		struct state *st = state_with_serialno(nc->newest_ipsec_sa);

		/* XXX what to do if the IPSEC SA has died? */
		passert(st != NULL);

		/*
		 * link the new connection instance to the state's list of
		 * connections
		 */

		DBG(DBG_OPPO, DBG_log("installing state: %lu for %s to %s",
				      nc->newest_ipsec_sa,
				      ocb, pcb));

		DBG(DBG_OPPO | DBG_CONTROLMORE, {
			char state_buf[LOG_WIDTH];
			char state_buf2[LOG_WIDTH];

			fmt_state(st, mononow(), state_buf, sizeof(state_buf),
				  state_buf2, sizeof(state_buf2));
			DBG_log("cannot_oppo, failure SA1: %s", state_buf);
			DBG_log("cannot_oppo, failure SA2: %s", state_buf2);
		});

		if (!route_and_eroute(c, shunt_spd, st)) {
			whack_log(RC_OPPOFAILURE,
				  "failed to instantiate shunt policy %s for %s to %s",
				  c->name,
				  ocb, pcb);
		}
		return;
	}

	if (b->held) {
		/* this was filled in for us based on packet trigger, not whack --oppo trigger */
		DBG(DBG_CONTROL, DBG_log("cannot_oppo() detected packet triggered shunt from bundle"));

		/*
		 * Replace negotiationshunt (hold or pass) with failureshunt (hold or pass)
		 * If no failure_shunt specified, use SPI_PASS -- THIS MAY CHANGE.
		 */
		pexpect(b->failure_shunt != 0); /* PAUL: I don't think this can/should happen? */
		if (replace_bare_shunt(&b->our_client, &b->peer_client,
					  b->policy_prio,
					  b->negotiation_shunt,
					  b->failure_shunt,
					  b->transport_proto,
					  ughmsg))
		{
			DBG(DBG_CONTROL,
				DBG_log("cannot_oppo() replaced negotiationshunt with bare failureshunt=%s",
					enum_short_name(&spi_names, b->failure_shunt)));
		} else {
			libreswan_log("cannot_oppo() failed to replace negotiationshunt with bare failureshunt");
		}
	}
}

static void initiate_ondemand_body(struct find_oppo_bundle *b
#ifdef HAVE_LABELED_IPSEC
				   , struct xfrm_user_sec_ctx_ike *uctx
#endif
				  )
{
	struct connection *c = NULL;
	struct spd_route *sr;
	char ours[ADDRTOT_BUF];
	char his[ADDRTOT_BUF];
	int ourport, hisport;
	char demandbuf[256];
	bool loggedit = FALSE;

	/* What connection shall we use?
	 * First try for one that explicitly handles the clients.
	 */

	addrtot(&b->our_client, 0, ours, sizeof(ours));
	addrtot(&b->peer_client, 0, his, sizeof(his));
	ourport = ntohs(portof(&b->our_client));
	hisport = ntohs(portof(&b->peer_client));

#ifdef HAVE_LABELED_IPSEC
	DBG(DBG_CONTROLMORE, {
		if (uctx != NULL) {
			DBG_log("received security label string: %.*s",
				uctx->ctx.ctx_len,
				uctx->sec_ctx_value);
		}
	});
#endif

	snprintf(demandbuf, sizeof(demandbuf),
		 "initiate on demand from %s:%d to %s:%d proto=%d because: %s",
		 ours, ourport, his, hisport, b->transport_proto, b->want);


	/* ??? DBG and real-world code mixed */
	if (DBGP(DBG_OPPOINFO)) {
		libreswan_log("%s", demandbuf);
		loggedit = TRUE;
	} else if (fd_p(whack_log_fd)) {
		whack_log(RC_COMMENT, "%s", demandbuf);
		loggedit = TRUE;
	}

	if (isanyaddr(&b->our_client) || isanyaddr(&b->peer_client)) {
		cannot_oppo(NULL, b, "impossible IP address");
	} else if (sameaddr(&b->our_client, &b->peer_client)) {
		/* NETKEY gives us acquires for our own IP */
		/* this does not catch talking to ourselves on another ip */
		cannot_oppo(NULL, b, "acquire for our own IP address");
	} else if ((c = find_connection_for_clients(&sr,
						     &b->our_client,
						     &b->peer_client,
						     b->transport_proto))
		   == NULL) {
		/* No connection explicitly handles the clients and there
		 * are no Opportunistic connections -- whine and give up.
		 * The failure policy cannot be gotten from a connection; we pick %pass.
		 */
		if (!loggedit) {
			libreswan_log("%s", demandbuf);
			loggedit = TRUE;	/* loggedit not subsequently used */
		}

		cannot_oppo(NULL, b, "no routed template covers this pair");
	} else if ((c->policy & POLICY_OPPORTUNISTIC) && !orient(c)) {
		/* happens when dst is ourselves on a different IP */
		cannot_oppo(NULL, b, "connection to self on another IP?");
	}  else if (c->kind == CK_TEMPLATE && (c->policy & POLICY_OPPORTUNISTIC) == 0) {
		if (!loggedit) {
			libreswan_log("%s", demandbuf);
			loggedit = TRUE;	/* loggedit not subsequently used */
		}
		loglog(RC_NOPEERIP,
		       "cannot initiate connection for packet %s:%d -> %s:%d proto=%d - template conn",
		       ours, ourport, his, hisport, b->transport_proto);
	} else if (c->kind != CK_TEMPLATE) {
		/* We've found a connection that can serve.
		 * Do we have to initiate it?
		 * Not if there is currently an IPSEC SA.
		 * But if there is an IPSEC SA, then KLIPS would not
		 * have generated the acquire.  So we assume that there isn't one.
		 * This may be redundant if a non-opportunistic
		 * negotiation is already being attempted.
		 */

		/* If we are to proceed asynchronously, b->whackfd will be NULL_WHACKFD. */

		if (c->kind == CK_INSTANCE) {
			char cib[CONN_INST_BUF];
			/* there is already an instance being negotiated */
#if 0
			libreswan_log(
				"rekeying existing instance \"%s\"%s, due to acquire",
				c->name,
				fmt_conn_instance(c, cib));

			/*
			 * we used to return here, but rekeying is a better choice. If we
			 * got the acquire, it is because something turned stuff into a
			 * %trap, or something got deleted, perhaps due to an expiry.
			 */
#else
			/*
			 * XXX We got an acquire (NETKEY only?) for
			 * something we already have an instance for ??
			 * We cannot process as normal because the
			 * bare_shunts table and assign_holdpass()
			 * would get confused between this new entry
			 * and the existing one. So we return without
			 * doing anything
			 */
			libreswan_log("found existing state, ignoring instance \"%s\"%s, due to duplicate acquire",
				c->name, fmt_conn_instance(c, cib));
			return;
#endif
		}

		/* we have a connection, fill in the negotiation_shunt and failure_shunt */
		b->failure_shunt = shunt_policy_spi(c, FALSE);
		b->negotiation_shunt = (c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_HOLD;

		/*
		 * otherwise, there is some kind of static conn that can handle
		 * this connection, so we initiate it.
		 * Only needed if we this was triggered by a packet, not by whack
		 */
		if (b->held) {
			if (assign_holdpass(c, sr, b->transport_proto, b->negotiation_shunt,
					   &b->our_client, &b->peer_client)) {
				DBG(DBG_CONTROL, DBG_log("initiate_ondemand_body() installed negotiation_shunt,"));
			} else {
				libreswan_log("initiate_ondemand_body() failed to install negotiation_shunt,");
			}
		}

		if (!loggedit) {
			libreswan_log("%s", demandbuf);
			loggedit = TRUE;	/* loggedit not subsequently used */
		}

		ipsecdoi_initiate(b->whackfd, c, c->policy, 1,
				  SOS_NOBODY
#ifdef HAVE_LABELED_IPSEC
				  , uctx
#endif
				  );
		b->whackfd = null_fd; /* protect from close */
	} else {
		/* We are handling an opportunistic situation.
		 * This involves several DNS lookup steps that require suspension.
		 * NOTE: will be re-implemented
		 *
		 * old comment:
		 * The first chunk of code handles the result of the previous
		 * DNS query (if any).  It also selects the kind of the next step.
		 * The second chunk initiates the next DNS query (if any).
		 */
		char mycredentialstr[IDTOA_BUF];

		DBG(DBG_CONTROL, {
			    char cib[CONN_INST_BUF];
			    DBG_log("creating new instance from \"%s\"%s",
				    c->name,
				    fmt_conn_instance(c, cib));
		    });

		idtoa(&sr->this.id, mycredentialstr, sizeof(mycredentialstr));

		passert(c->policy & POLICY_OPPORTUNISTIC); /* can't initiate Road Warrior connections */

		/* we have a connection, fill in the negotiation_shunt and failure_shunt */
		b->failure_shunt = shunt_policy_spi(c, FALSE);
		b->negotiation_shunt = (c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_HOLD;



			/*
			 * KLIPS always has shunts without protoports.
			 * XFRM always has shunts with protoports, even when no *protoport= settings in conn
			 */
			if (b->negotiation_shunt != SPI_HOLD ||
				(b->transport_proto != 0 ||
				ourport != 0 ||
				hisport != 0))
			{
				const char *const delmsg = "delete bare kernel shunt - was replaced with  negotiationshunt";
				const char *const addwidemsg = "oe-negotiating";
				ip_subnet this_client, that_client;
				int shunt_proto = b->transport_proto;

				happy(addrtosubnet(&b->our_client, &this_client));
				happy(addrtosubnet(&b->peer_client, &that_client));
				/* OLD: negotiationshunt must be wider than bare shunt, esp on NETKEY */
				/* if the connection we found has protoports, match those for the shunt */


				setportof(0, &this_client.addr); /* always catch all ephemeral to dest */
				setportof(0, &that_client.addr); /* default unless connection says otherwise */
				if (b->transport_proto != 0) {
					if (c->spd.that.protocol == 0) {
						DBG(DBG_OPPO, DBG_log("shunt widened for protoports since conn does not limit protocols"));
						shunt_proto = 0;
						ourport = 0;
						hisport =0;
					} else {
						if (hisport != 0) {
							if (c->spd.that.port != 0) {
								if (c->spd.that.port != hisport) {
									loglog(RC_LOG_SERIOUS, "Dragons! connection port %d mismatches shunt dest port %d",
										c->spd.that.port, hisport);
								} else {
									hsetportof(hisport, that_client.addr);
									DBG(DBG_OPPO, DBG_log("bare shunt destination port set to %d", hisport));
								}
							} else {
								DBG(DBG_OPPO, DBG_log("not really expecting a shunt for dport 0 ?"));
							}
						} else {
							DBG(DBG_OPPO, DBG_log("KLIPS might not support these shunts with protoport"));
						}
					}

				} else {
					DBG(DBG_OPPO, DBG_log("shunt not widened for oppo because no protoport received from the kernel for the shunt"));
				}

				DBG(DBG_OPPO,
					DBG_log("going to initiate opportunistic, first installing %s negotiationshunt",
						enum_short_name(&spi_names, b->negotiation_shunt)));

				// PAUL: should this use shunt_eroute() instead of API violation into raw_eroute()
				/* if we have protoport= set, narrow to it. zero out ephemeral port */
				if (shunt_proto != 0) {
					if (c->spd.this.port != 0)
						setportof(portof(&b->our_client), &this_client.addr);
					if (c->spd.that.port != 0)
						setportof(portof(&b->peer_client), &that_client.addr);
				}

				if (!raw_eroute(&b->our_client, &this_client,
					&b->peer_client, &that_client,
					htonl(SPI_HOLD), /* kernel induced */
					htonl(b->negotiation_shunt),
					SA_INT, shunt_proto,
					ET_INT, null_proto_info,
					deltatime(SHUNT_PATIENCE),
					calculate_sa_prio(c),
					NULL,
					ERO_ADD, addwidemsg
#ifdef HAVE_LABELED_IPSEC
					, NULL
#endif
					))
				{
					libreswan_log("adding bare wide passthrough negotiationshunt failed");
				} else {
					DBG(DBG_OPPO, DBG_log("added bare (possibly wided) passthrough negotiationshunt succeeded (violating API)"));
					add_bare_shunt(&this_client, &that_client, shunt_proto, SPI_HOLD, addwidemsg);
				}
				/* now delete the (obsoleted) narrow bare kernel shunt - we have a (possibly broadened) negotiationshunt replacement installed */
				if (!delete_bare_shunt(&b->our_client, &b->peer_client,
					b->transport_proto, SPI_HOLD /* kernel dictated */, delmsg))
				{
					libreswan_log("Failed to: %s", delmsg);
				} else {
					DBG(DBG_OPPO, DBG_log("success taking down narrow bare shunt"));
				}
			}


			c = build_outgoing_opportunistic_connection(
				&b->our_client,
				&b->peer_client,
				b->transport_proto);

			if (c == NULL) {
				/* We cannot seem to instantiate a suitable connection:
				 * complain clearly.
				 */
				ipstr_buf b1, b2;

				/* ??? CLANG 3.5 thinks ac might be NULL (look up) */
				loglog(RC_OPPOFAILURE,
				       "no suitable connection for opportunism between %s and %s",
				       ipstr(&b->our_client, &b1),
				       ipstr(&b->peer_client, &b2));

				/*
				 * Replace negotiation_shunt with failure_shunt
				 * The type of replacement *ought* to be
				 * specified by policy, but we did not find a connection, so
				 * default to HOLD
				 */
				if (b->held) {
					if (replace_bare_shunt(
						&b->our_client,
						&b->peer_client,
						b->policy_prio,
						b->negotiation_shunt, /* if not from conn, where did this come from? */
						b->failure_shunt, /* if not from conn, where did this come from? */
						b->transport_proto,
						"no suitable connection")) {
							DBG(DBG_OPPO, DBG_log("replaced negotiationshunt with failurehunt=hold because no connection was found"));
					} else {
						libreswan_log("failed to replace negotiationshunt with failurehunt=hold");
					}
				}
				/* ??? c == NULL -- what can we do? */
			} else {
				/* If we are to proceed asynchronously, b->whackfd will be NULL_WHACKFD. */
				passert(c->kind == CK_INSTANCE);
				passert(HAS_IPSEC_POLICY(c->policy));
				passert(LHAS(LELEM(RT_UNROUTED) |
					     LELEM(RT_ROUTED_PROSPECTIVE),
					     c->spd.routing));
				if (b->held) {
					/* if we have protoport= set, narrow to it. zero out ephemeral port */
					if (b->transport_proto != 0) {
						if (c->spd.this.port != 0) {
							setportof(htons(c->spd.this.port), &b->our_client);
						}
						if (c->spd.that.port != 0) {
							setportof(htons(c->spd.that.port), &b->peer_client);
						}
					}
					/* packet triggered - not whack triggered */
					DBG(DBG_OPPO, DBG_log("assigning negotiation_shunt to connection"));
					/* if we have protoport= set, narrow to it. zero out ephemeral port */
					/* warning: we know ports in this_client/that_client are 0 so far */
					if (c->spd.this.protocol != 0) {
						if (c->spd.this.port != 0)
							setportof(portof(&b->our_client), &c->spd.this.client.addr);
						if (c->spd.that.port != 0)
							setportof(portof(&b->peer_client), &c->spd.that.client.addr);
					}
					if (assign_holdpass(c, &c->spd,
						   b->transport_proto,
						   b->negotiation_shunt,
						   &b->our_client,
						   &b->peer_client)) {
						DBG(DBG_CONTROL, DBG_log("assign_holdpass succeeded"));
					} else {
						libreswan_log("assign_holdpass failed!");
					}
				}
				DBG(DBG_OPPO | DBG_CONTROL,
				    DBG_log("initiate on demand from %s:%d to %s:%d proto=%d because: %s",
					    ours, ourport, his, hisport,
					    b->transport_proto,
					    b->want));

				ipsecdoi_initiate(b->whackfd, c, c->policy, 1,
						  SOS_NOBODY
#ifdef HAVE_LABELED_IPSEC
						  , NULL /* shall we pass uctx for opportunistic connections? */
#endif
						  );
				b->whackfd = null_fd; /* protect from close */
			}
		}

		/* the second chunk: initiate the next DNS query (if any) */
		DBG(DBG_OPPO | DBG_CONTROL, {
			if (c != NULL) {
				ipstr_buf b1;
				ipstr_buf b2;
				DBG_log("initiate on demand using %s from %s to %s",
					(c->policy & POLICY_AUTH_NULL) ? "AUTH_NULL" : "RSASIG",
					ipstr(&b->our_client, &b1),
					ipstr(&b->peer_client, &b2));
			}
		});

	close_any(&b->whackfd);
}

void initiate_ondemand(const ip_address *our_client,
		      const ip_address *peer_client,
		      int transport_proto,
		      bool held,
		      fd_t whackfd,
#ifdef HAVE_LABELED_IPSEC
		      struct xfrm_user_sec_ctx_ike *uctx,
#endif
		      err_t why)
{
	struct find_oppo_bundle b;

	b.want = why;   /* fudge */
	b.failure_ok = FALSE;
	b.our_client = *our_client;
	b.peer_client = *peer_client;
	b.transport_proto = transport_proto;
	b.held = held;
	b.policy_prio = BOTTOM_PRIO;
	b.negotiation_shunt = SPI_HOLD; /* until we found connection policy */
	b.failure_shunt = SPI_HOLD; /* until we found connection policy */
	b.whackfd = whackfd;

	initiate_ondemand_body(&b
#ifdef HAVE_LABELED_IPSEC
				, uctx
#endif
	);
}

/* Find a connection that owns the shunt eroute between subnets.
 * There ought to be only one.
 * This might get to be a bottleneck -- try hashing if it does.
 */
struct connection *shunt_owner(const ip_subnet *ours, const ip_subnet *his)
{
	struct connection *c;

	for (c = connections; c != NULL; c = c->ac_next) {
		const struct spd_route *sr;

		for (sr = &c->spd; sr; sr = sr->spd_next) {
			if (shunt_erouted(sr->routing) &&
			    samesubnet(ours, &sr->this.client) &&
			    samesubnet(his, &sr->that.client))
				return c;
		}
	}
	return NULL;
}


/* time before retrying DDNS host lookup for phase 1 */
#define PENDING_DDNS_INTERVAL secs_per_minute

/*
 * call me periodically to check to see if any DDNS tunnel can come up
 */

static void connection_check_ddns1(struct connection *c)
{
	struct connection *d;
	ip_address new_addr;
	const char *e;

	if (NEVER_NEGOTIATE(c->policy))
		return;

	if (c->dnshostname == NULL)
		return;

	if (!isanyaddr(&c->spd.that.host_addr)) {
		DBG(DBG_DNS, {
			char cib[CONN_INST_BUF];
			DBG_log("pending ddns: connection \"%s\"%s has address",
				c->name, fmt_conn_instance(c, cib));
		});
		return;
	}

	if (c->spd.that.has_client_wildcard || c->spd.that.has_port_wildcard ||
	    ((c->policy & POLICY_SHUNT_MASK) == POLICY_SHUNT_TRAP &&
	     c->spd.that.has_id_wildcards)) {
		DBG(DBG_DNS, {
			char cib[CONN_INST_BUF];
			DBG_log("pending ddns: connection \"%s\"%s with wildcard not started",
				c->name, fmt_conn_instance(c, cib));
		});
		return;
	}

	e = ttoaddr(c->dnshostname, 0, AF_UNSPEC, &new_addr);
	if (e != NULL) {
		DBG(DBG_DNS, {
			char cib[CONN_INST_BUF];
			DBG_log("pending ddns: connection \"%s\"%s lookup of \"%s\" failed: %s",
				c->name, fmt_conn_instance(c, cib),
				c->dnshostname, e);
		});
		return;
	}

	if (isanyaddr(&new_addr)) {
		DBG(DBG_DNS, {
			char cib[CONN_INST_BUF];
			DBG_log("pending ddns: connection \"%s\"%s still no address for \"%s\"",
				c->name, fmt_conn_instance(c, cib),
				c->dnshostname);
		});
		return;
	}

	/* I think this is ok now we check everything above ? */
	c->kind = CK_PERMANENT;
	c->spd.that.host_addr = new_addr;

	/* a small bit of code from default_end to fixup the end point */
	/* default nexthop to other side */
	if (isanyaddr(&c->spd.this.host_nexthop))
		c->spd.this.host_nexthop = c->spd.that.host_addr;

	/* default client to subnet containing only self
	 * XXX This may mean that the client's address family doesn't match
	 * tunnel_addr_family.
	 */
	if (!c->spd.that.has_client)
		addrtosubnet(&c->spd.that.host_addr, &c->spd.that.client);

	/*
	 * reduce the work we do by updating all connections waiting for this
	 * lookup
	 */
	update_host_pairs(c);
	initiate_connection(c->name, null_fd, empty_lmod, empty_lmod, NULL);

	/* no host pairs, no more to do */
	pexpect(c->host_pair != NULL);	/* ??? surely */
	if (c->host_pair == NULL)
		return;

	for (d = c->host_pair->connections; d != NULL; d = d->hp_next) {
		if (c != d && same_in_some_sense(c, d))
			initiate_connection(d->name, null_fd,
					    empty_lmod, empty_lmod, NULL);
	}
}

void connection_check_ddns(void)
{
	struct connection *c, *cnext;
	realtime_t tv1 = realnow();

	/* reschedule */
	event_schedule_s(EVENT_PENDING_DDNS, PENDING_DDNS_INTERVAL, NULL);

	for (c = connections; c != NULL; c = cnext) {
		cnext = c->ac_next;
		connection_check_ddns1(c);
	}
	for (c = unoriented_connections; c != NULL; c = cnext) {
		cnext = c->ac_next;
		connection_check_ddns1(c);
	}
	check_orientations();

	LSWDBGP(DBG_DNS, buf) {
		realtime_t tv2 = realnow();
		lswlogf(buf, "elapsed time in %s for hostname lookup ", __func__);
		lswlog_deltatime(buf, realtimediff(tv2, tv1));
	};
}

/* time between scans of pending phase2 */
#define PENDING_PHASE2_INTERVAL (2 * secs_per_minute)

/*
 * call me periodically to check to see if pending phase2s ever got
 * unstuck, and if not, perform DPD action.
 */
void connection_check_phase2(void)
{
	struct connection *c, *cnext;

	/* reschedule */
	event_schedule_s(EVENT_PENDING_PHASE2, PENDING_PHASE2_INTERVAL, NULL);

	for (c = connections; c != NULL; c = cnext) {
		cnext = c->ac_next;

		if (NEVER_NEGOTIATE(c->policy)) {
			DBG(DBG_CONTROL, {
				char cib[CONN_INST_BUF];
				DBG_log("pending review: connection \"%s\"%s has no negotiated policy, skipped",
					c->name, fmt_conn_instance(c, cib));
			});
			continue;
		}

		if (!(c->policy & POLICY_UP)) {
			char cib[CONN_INST_BUF];
			DBG(DBG_CONTROL, {
				DBG_log("pending review: connection \"%s\"%s was not up, skipped",
					c->name, fmt_conn_instance(c, cib));
			});
			continue;
		}

		DBG(DBG_CONTROL, {
			char cib[CONN_INST_BUF];
			DBG_log("pending review: connection \"%s\"%s checked",
				c->name, fmt_conn_instance(c, cib));
		});

		if (pending_check_timeout(c)) {
			struct state *p1st;
			ipstr_buf b;
			char cib[CONN_INST_BUF];

			libreswan_log(
				"pending IPsec SA negotiation with %s \"%s\"%s took too long -- replacing phase 1",
				ipstr(&c->spd.that.host_addr, &b),
				c->name, fmt_conn_instance(c, cib));

			p1st = find_phase1_state(c,
						 ISAKMP_SA_ESTABLISHED_STATES |
						 IKEV2_ISAKMP_INITIATOR_STATES |
						 PHASE1_INITIATOR_STATES);

			if (p1st != NULL) {
				/* arrange to rekey the phase 1, if there was one. */
				if (c->dnshostname != NULL) {
					restart_connections_by_peer(c);
				} else {
					event_force(EVENT_SA_REPLACE, p1st);
				}
			} else {
				/* start a new connection. Something wanted it up */
				struct initiate_stuff is;

				is.whackfd = null_fd;
				is.more_debugging = empty_lmod;
				is.more_impairing = empty_lmod;
				is.remote_host = NULL;

				initiate_a_connection(c, &is);
			}
		}
	}
}

void init_connections(void)
{
	event_schedule_s(EVENT_PENDING_DDNS, PENDING_DDNS_INTERVAL, NULL);
	event_schedule_s(EVENT_PENDING_PHASE2, PENDING_PHASE2_INTERVAL, NULL);
}
