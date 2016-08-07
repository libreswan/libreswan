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
 * Copyright (C) 2012-2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 *
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
#include "kameipsec.h"

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
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "whack.h"
#include "alg_info.h"
#include "spdb.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1_xauth.h"
#include "nat_traversal.h"

#include "virtual.h"	/* needs connections.h */

#include "hostpair.h"

bool orient(struct connection *c)
{
	if (!oriented(*c)) {
		struct spd_route *sr;

		for (sr = &c->spd; sr; sr = sr->spd_next) {
			/* There can be more then 1 spd policy associated - required
			 * for cisco split networking when remote_peer_type=cisco
			 */
			if (c->remotepeertype == CISCO && sr != &c->spd )
				continue;

			/* Note: this loop does not stop when it finds a match:
			 * it continues checking to catch any ambiguity.
			 */
			const struct iface_port *p;

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

					/* swap ends and try again.
					 * It is a little tricky to see that this loop will stop.
					 * Only continue if the far side matches.
					 * If both sides match, there is an error-out.
					 */
					{
						struct end t = sr->this;

						sr->this = sr->that;
						sr->that = t;
					}
				}
			}
		}
	}
	return oriented(*c);
}

struct initiate_stuff {
	int whackfd;
	lset_t moredebug;
	enum crypto_importance importance;
};

static int initiate_a_connection(struct connection *c,
				 void *arg)
{
	struct initiate_stuff *is = (struct initiate_stuff *)arg;
	int whackfd = is->whackfd;
	lset_t moredebug = is->moredebug;
	enum crypto_importance importance = is->importance;
	int success = 0;

	set_cur_connection(c);

	/* turn on any extra debugging asked for */
	c->extra_debugging |= moredebug;

	if (!oriented(*c)) {
		ipstr_buf a;
		ipstr_buf b;
		loglog(RC_ORIENT,
		       "We cannot identify ourselves with either end of this connection.  %s or %s are not usable",
		       ipstr(&c->spd.this.host_addr, &a),
		       ipstr(&c->spd.that.host_addr, &b));
	} else if (NEVER_NEGOTIATE(c->policy)) {
		loglog(RC_INITSHUNT,
		       "cannot initiate an authby=never connection");
	} else if ((c->kind != CK_PERMANENT) &&
		    !(c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
		if (isanyaddr(&c->spd.that.host_addr)) {
			if (c->dnshostname != NULL) {
				loglog(RC_NOPEERIP,
				       "cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s)",
				       enum_show(&connection_kind_names,
						 c->kind));
				success = 1;
				c->policy |= POLICY_UP;
			} else {
				loglog(RC_NOPEERIP,
				       "cannot initiate connection without knowing peer IP address (kind=%s)",
				       enum_show(&connection_kind_names, c->kind));
			}
		} else if (!(c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
			loglog(RC_WILDCARD,
			       "cannot initiate connection with narrowing=no and (kind=%s)",
			       enum_show(&connection_kind_names, c->kind));
		} else {
			loglog(RC_WILDCARD,
			       "cannot initiate connection with ID wildcards (kind=%s)",
			       enum_show(&connection_kind_names, c->kind));
		}
	} else {
		if (isanyaddr(&c->spd.that.host_addr) &&
		    (c->policy & POLICY_IKEV2_ALLOW_NARROWING) ) {
			if (c->dnshostname != NULL) {
				loglog(RC_NOPEERIP,
				       "cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s, narrowing=%s)",
				       enum_show(&connection_kind_names,
						 c->kind),
				       (c->policy &
					POLICY_IKEV2_ALLOW_NARROWING) ? "yes" : "no");
				success = 1;
				c->policy |= POLICY_UP;
			} else {
				loglog(RC_NOPEERIP,
					"cannot initiate connection without knowing peer IP address (kind=%s narrowing=%s)",
					enum_show(&connection_kind_names,
						c->kind),
			       (c->policy &
				POLICY_IKEV2_ALLOW_NARROWING) ? "yes" : "no");
			}
		} else {
			if (LIN(POLICY_IKEV2_PROPOSE | POLICY_IKEV2_ALLOW_NARROWING, c->policy) &&
				c->kind == CK_TEMPLATE) {
					c = instantiate(c, NULL, NULL);
			}

			/* We will only request an IPsec SA if policy isn't empty
			 * (ignoring Main Mode items).
			 * This is a fudge, but not yet important.
			 * If we are to proceed asynchronously, whackfd will be NULL_FD.
			 */
			c->policy |= POLICY_UP;

			if (c->policy &
			    (POLICY_ENCRYPT | POLICY_AUTHENTICATE)) {
				struct alg_info_esp *alg = c->alg_info_esp;
				struct db_sa *phase2_sa = kernel_alg_makedb(
					c->policy, alg, TRUE);

				if (alg != NULL && phase2_sa == NULL) {
					whack_log(RC_LOG_SERIOUS,
						  "cannot initiate: no acceptable kernel algorithms loaded");
					reset_cur_connection();
					close_any(is->whackfd);
					return 0;
				}
				free_sa(&phase2_sa);
			}

			{
				whackfd = dup(whackfd);
				ipsecdoi_initiate(whackfd, c, c->policy, 1,
						  SOS_NOBODY, importance
#ifdef HAVE_LABELED_IPSEC
						  , NULL
#endif
						  );
				success = 1;
			}
		}
	}
	reset_cur_connection();

	return success;
}

void initiate_connection(const char *name, int whackfd,
			 lset_t moredebug,
			 enum crypto_importance importance)
{
	struct initiate_stuff is;
	struct connection *c = con_by_name(name, FALSE);
	int count;

	passert(name != NULL);
	is.whackfd   = whackfd;
	is.moredebug = moredebug;
	is.importance = importance;

	if (c != NULL) {
		initiate_a_connection(c, &is);
		close_any(is.whackfd);
		return;
	}

	loglog(RC_COMMENT, "initiating all conns with alias='%s'", name);
	count = foreach_connection_by_alias(name, initiate_a_connection, &is);

	if (count == 0) {
		whack_log(RC_UNKNOWN_NAME,
			  "no connection named \"%s\"", name);
	}

	close_any(is.whackfd);
}

static bool same_host(const char *a_dnshostname, const ip_address *a_host_addr,
		const char *b_dnshostname, const ip_address *b_host_addr)
{
	/* should this be dnshostname and host_addr ?? */

	return (a_dnshostname != NULL && b_dnshostname != NULL &&
			streq(a_dnshostname, b_dnshostname)) ||
		(a_dnshostname == NULL && b_dnshostname == NULL &&
		 sameaddr(a_host_addr, b_host_addr));
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

	for (d = hp->connections; d != NULL; d = d->hp_next) {
		if (same_host(dnshostname, &host_addr,
				d->dnshostname, &d->spd.that.host_addr))
			initiate_connection(d->name, NULL_FD, LEMPTY,
					pcim_demand_crypto);
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

enum find_oppo_step {
	fos_start,
	fos_myid_ip_txt,
	fos_myid_hostname_txt,
	fos_myid_ip_key,
	fos_myid_hostname_key,
	fos_our_client,
	fos_our_txt,
	fos_his_client,
	fos_done,
};

static const char *const oppo_step_name[] = {
	"fos_start",
	"fos_myid_ip_txt",
	"fos_myid_hostname_txt",
	"fos_myid_ip_key",
	"fos_myid_hostname_key",
	"fos_our_client",
	"fos_our_txt",
	"fos_his_client",
	"fos_done"
};

struct find_oppo_bundle {
	enum find_oppo_step step;
	err_t want;
	bool failure_ok;        /* if true, continue_oppo should not die on DNS failure */
	ip_address our_client;  /* not pointer! */
	ip_address peer_client;
	int transport_proto;
	bool held;
	policy_prio_t policy_prio;
	ipsec_spi_t negotiation_shunt; /* in host order! */
	ipsec_spi_t failure_shunt; /* in host order! */
	int whackfd;
};

struct find_oppo_continuation {
	struct adns_continuation ac;    /* common prefix */
	struct find_oppo_bundle b;
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
					(b->failure_shunt == SPI_PASS) ? "pass" :
					(b->failure_shunt == SPI_HOLD) ? "hold" :
					"very-unexpected"));
		} else {
			libreswan_log("cannot_oppo() failed to replace negotiationshunt with bare failureshunt");
		}
	}
}

static void initiate_ondemand_body(struct find_oppo_bundle *b,
				  struct adns_continuation *ac, err_t ac_ugh
#ifdef HAVE_LABELED_IPSEC
				  , struct xfrm_user_sec_ctx_ike *uctx
#endif
				  ); /* forward */

void initiate_ondemand(const ip_address *our_client,
		      const ip_address *peer_client,
		      int transport_proto,
		      bool held,
		      int whackfd
#ifdef HAVE_LABELED_IPSEC
		      , struct xfrm_user_sec_ctx_ike *uctx
#endif
		      , err_t why)
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
	b.step = fos_start;
	initiate_ondemand_body(&b, NULL, NULL
#ifdef HAVE_LABELED_IPSEC
				      , uctx
#endif
				      );
}

static err_t check_txt_recs(enum myid_state try_state,
			    const struct connection *c,
			    struct adns_continuation *ac)
{
	/* Check if IPSECKEY lookup yielded good results.
	 * Looking up based on our ID.  Used if
	 * client is ourself, or if IPSECKEY had no public key.
	 * Note: if c is different this time, there is
	 * a chance that we did the wrong query.
	 * If so, treat as a kind of failure.
	 */
	enum myid_state old_myid_state = myid_state;
	const struct RSA_private_key *our_RSA_pri;
	err_t ugh = NULL;

	myid_state = try_state;

	if (old_myid_state != myid_state &&
	    old_myid_state == MYID_SPECIFIED) {
		ugh = "%myid was specified while we were guessing";
	} else if ((our_RSA_pri = get_RSA_private_key(c)) == NULL) {
		ugh = "we don't know our own RSA key";
	} else if (!same_id(&ac->id, &c->spd.this.id)) {
		ugh = "our ID changed underfoot";
	} else {
		/* Similar to code in RSA_check_signature
		 * for checking the other side.
		 */
		struct gw_info *gwp;

		ugh = "no IPSECKEY RR found for us";
		for (gwp = ac->gateways_from_dns; gwp != NULL;
		     gwp = gwp->next) {
			ugh = "all our IPSECKEY RRs have the wrong public key";
			if (gwp->key->alg == PUBKEY_ALG_RSA &&
			    same_RSA_public_key(&our_RSA_pri->pub,
						&gwp->key->u.rsa)) {
				ugh = NULL; /* good! */
				break;
			}
		}
	}
	if (ugh != NULL)
		myid_state = old_myid_state;
	return ugh;
}

/* note: gateways_from_dns must be NULL iff this is the first call */
static void initiate_ondemand_body(struct find_oppo_bundle *b,
				  struct adns_continuation *ac,
				  err_t ac_ugh
#ifdef HAVE_LABELED_IPSEC
				  , struct xfrm_user_sec_ctx_ike *uctx
#endif
				  )
{
	struct connection *c;
	struct spd_route *sr;
	char ours[ADDRTOT_BUF];
	char his[ADDRTOT_BUF];
	int ourport;
	int hisport;
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
		 "initiate on demand from %s:%d to %s:%d proto=%d state: %s because: %s",
		 ours, ourport, his, hisport, b->transport_proto,
		 oppo_step_name[b->step], b->want);


	/* ??? DBG and real-world code mixed */
	if (DBGP(DBG_OPPOINFO)) {
		libreswan_log("%s", demandbuf);
		loggedit = TRUE;
	} else if (whack_log_fd != NULL_FD) {
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

		/* If we are to proceed asynchronously, b->whackfd will be NULL_FD. */

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
				  SOS_NOBODY, pcim_local_crypto
#ifdef HAVE_LABELED_IPSEC
				  , uctx
#endif
				  );
		b->whackfd = NULL_FD; /* protect from close */
	} else {
		/* We are handling an opportunistic situation.
		 * This involves several DNS lookup steps that require suspension.
		 * Note: many facts might change while we're suspended.
		 * Here be dragons.
		 *
		 * The first chunk of code handles the result of the previous
		 * DNS query (if any).  It also selects the kind of the next step.
		 * The second chunk initiates the next DNS query (if any).
		 */
		enum find_oppo_step next_step;
		err_t ugh = ac_ugh;
		char mycredentialstr[IDTOA_BUF];
		struct gw_info nullgw;

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


		/* handle any DNS answer; select next step */

		switch (b->step) {
		case fos_start:

			if (b->negotiation_shunt != SPI_HOLD ||
				(b->transport_proto != 0 ||
				portof(&b->our_client) != 0 ||
				portof(&b->peer_client) != 0))
			{
				const char *const delmsg = "delete bare kernel shunt - was replaced with  negotiationshunt";
				const char *const addwidemsg = "oe-negotiating";
				ip_subnet this_client, that_client;

				happy(addrtosubnet(&b->our_client, &this_client));
				happy(addrtosubnet(&b->peer_client, &that_client));
				/* negotiationshunt must be wider than bare shunt, esp on NETKEY */
				setportof(0, &this_client.addr);
				setportof(0, &that_client.addr);

				DBG(DBG_OPPO,
					DBG_log("going to initiate opportunistic, first installing '%s' negotiationshunt",
						(b->negotiation_shunt == SPI_PASS) ? "pass" :
						(b->negotiation_shunt == SPI_HOLD) ? "hold" :
						"unknown?"));

				// PAUL: should this use shunt_eroute() instead of API violation into raw_eroute()
				if (!raw_eroute(&b->our_client, &this_client,
					&b->peer_client, &that_client,
					htonl(SPI_HOLD), /* kernel induced */
					htonl(b->negotiation_shunt),
					SA_INT, 0, /* transport_proto */
					ET_INT, null_proto_info,
					deltatime(SHUNT_PATIENCE),
					DEFAULT_IPSEC_SA_PRIORITY,
					NULL,
					ERO_ADD, addwidemsg
	#ifdef HAVE_LABELED_IPSEC
					, NULL
	#endif
					))
				{
					libreswan_log("adding bare wide passthrough negotiationshunt failed");
				} else {
					DBG(DBG_OPPO, DBG_log("added bare wide passthrough negotiationshunt succeeded (violating API)"));
					add_bare_shunt(&this_client, &that_client, 0 /* broadened transport_proto */, SPI_HOLD, addwidemsg);
				}
				/* now delete the (obsoleted) narrow bare kernel shunt - we have a broadened negotiationshunt replacement installed */
				if (!delete_bare_shunt(&b->our_client, &b->peer_client,
					b->transport_proto, SPI_HOLD /* kernel dictated */, delmsg))
				{
					libreswan_log("Failed to: %s", delmsg);
				} else {
					DBG(DBG_OPPO, DBG_log("success taking down narrow bare shunt"));
				}
			}

			if ((c->policy & POLICY_RSASIG) == LEMPTY) {
				ipstr_buf b1;

				/* no dns queries to find the gateway. create one here */
				if (c->policy & POLICY_AUTH_NULL) {

					DBG(DBG_OPPO, DBG_log("use POLICY_AUTH_NULL to initiate to  %s",
								ipstr(&b->peer_client, &b1)));
					nullgw.client_id.kind = ID_NULL;
					nullgw.gw_id.kind = ID_NULL;
					nullgw.gw_id.ip_addr = b->peer_client;
				}

				b->step = fos_his_client;
				goto CASE_fos_his_client;
			} else {
				/* just starting out: select first query step */
				next_step = fos_myid_ip_txt;
			}
			break;

		case fos_myid_ip_txt: /* IPSECKEY for our default IP address as %myid */
			ugh = check_txt_recs(MYID_IP, c, ac);
			if (ugh != NULL) {
				/* cannot use our IP as OE identitiy for initiation */
				DBG(DBG_OPPO,
				    DBG_log("cannot use our IP (%s:IPSECKEY) as identity: %s",
					    myid_str[MYID_IP],
					    ugh));
				if (!logged_myid_ip_txt_warning) {
					loglog(RC_LOG_SERIOUS,
					       "cannot use our IP (%s:IPSECKEY) as identity: %s",
					       myid_str[MYID_IP],
					       ugh);
					logged_myid_ip_txt_warning = TRUE;
				}

				next_step = fos_myid_hostname_txt;
				ugh = NULL; /* failure can be recovered from */
			} else {
				/* we can use our IP as OE identity for initiation */
				if (!logged_myid_ip_txt_warning) {
					loglog(RC_LOG_SERIOUS,
					       "using our IP (%s:IPSECKEY) as identity!",
					       myid_str[MYID_IP]);
					logged_myid_ip_txt_warning = TRUE;
				}

				next_step = fos_our_client;
			}
			break;

		case fos_myid_hostname_txt: /* IPSECKEY for our hostname as %myid */
			ugh = check_txt_recs(MYID_HOSTNAME, c, ac);
			if (ugh != NULL) {
				/* cannot use our hostname as OE identitiy for initiation */
				DBG(DBG_OPPO,
				    DBG_log("cannot use our hostname (%s:IPSECKEY) as identity: %s",
					    myid_str[MYID_HOSTNAME],
					    ugh));
				if (!logged_myid_fqdn_txt_warning) {
					loglog(RC_LOG_SERIOUS,
					       "cannot use our hostname (%s:IPSECKEY) as identity: %s",
					       myid_str[MYID_HOSTNAME],
					       ugh);
					logged_myid_fqdn_txt_warning = TRUE;
				}
				next_step = fos_done;
			} else {
				/* we can use our hostname as OE identity for initiation */
				if (!logged_myid_fqdn_txt_warning) {
					loglog(RC_LOG_SERIOUS,
					       "using our hostname (%s:IPSECKEY) as identity!",
					       myid_str[MYID_HOSTNAME]);
					logged_myid_fqdn_txt_warning = TRUE;
				}
				next_step = fos_our_client;
			}
			break;

		case fos_our_client: /* IPSECKEY for our client */
		{
			/* Our client is not us: we must check the IPSECKEY records.
			 * Note: if c is different this time, there is
			 * a chance that we did the wrong query.
			 * If so, treat as a kind of failure.
			 */
			const struct RSA_private_key *our_RSA_pri =
				get_RSA_private_key(c);

			next_step = fos_his_client; /* normal situation */

			passert(sr != NULL);

			if (our_RSA_pri == NULL) {
				ugh = "we don't know our own RSA key";
			} else if (sameaddr(&sr->this.host_addr,
					    &b->our_client)) {
				/* this wasn't true when we started -- bail */
				ugh = "our IP address changed underfoot";
			} else if (!same_id(&ac->sgw_id, &sr->this.id)) {
				/* this wasn't true when we started -- bail */
				ugh = "our ID changed underfoot";
			} else {
				/* Similar to code in quick_inI1_outR1_tail
				 * for checking the other side.
				 */
				struct gw_info *gwp;

				ugh = "no IPSECKEY RR for our client delegates us";
				for (gwp = ac->gateways_from_dns; gwp != NULL;
				     gwp = gwp->next) {
					passert(same_id(&gwp->gw_id,
							&sr->this.id));

					ugh = "IPSECKEY RR for our client has wrong key";
					/* If there is a key from the IPSECKEY record,
					 * we count it as a win if we match the key.
					 * If there was no key, we have a tentative win:
					 * we need to check our KEY record to be sure.
					 */
					if (!gwp->gw_key_present) {
						/* Success, but the IPSECKEY had no key
						 * so we must check our our own KEY records.
						 */
						next_step = fos_our_txt;
						ugh = NULL; /* good! */
						break;
					}
					if (same_RSA_public_key(&our_RSA_pri->
								pub,
								&gwp->key->u.
								rsa)) {
						ugh = NULL; /* good! */
						break;
					}
				}
			}
		}
		break;

		case fos_our_txt: /* IPSECKEY for us */
		{
			/* Check if IPSECKEY lookup yielded good results.
			 * Looking up based on our ID.  Used if
			 * client is ourself, or if IPSECKEY had no public key.
			 * Note: if c is different this time, there is
			 * a chance that we did the wrong query.
			 * If so, treat as a kind of failure.
			 */
			const struct RSA_private_key *our_RSA_pri =
				get_RSA_private_key(c);

			next_step = fos_his_client; /* unless we decide to look for KEY RR */

			if (our_RSA_pri == NULL) {
				ugh = "we don't know our own RSA key";
			} else if (!same_id(&ac->id, &c->spd.this.id)) {
				ugh = "our ID changed underfoot";
			} else {
				/* Similar to code in RSA_check_signature
				 * for checking the other side.
				 */
				struct gw_info *gwp;

				ugh = "no IPSECKEY RR for us";
				for (gwp = ac->gateways_from_dns; gwp != NULL;
				     gwp = gwp->next) {
					passert(same_id(&gwp->gw_id,
							&sr->this.id));

					ugh = "IPSECKEY RR for us has wrong key";
					if (gwp->gw_key_present &&
					    same_RSA_public_key(&our_RSA_pri->
								pub,
								&gwp->key->u.
								rsa)) {
						DBG(DBG_OPPO,
						    DBG_log("initiate on demand found IPSECKEY with right public key at: %s",
							    mycredentialstr));
						ugh = NULL;
						break;
					}
				}
			}
		}
		break;

		CASE_fos_his_client:
		case fos_his_client: /* IPSECKEY for his client */
		{
			/* We've finished last DNS queries: IPSECKEY for his client.
			 * Using the information, try to instantiate a connection
			 * and start negotiating.
			 * We now know the peer.  The choosing of "c" ignored this,
			 * so we will disregard its current value.
			 * !!! We need to randomize the entry in gw that we choose.
			 */
			next_step = fos_done; /* no more queries */

			c = build_outgoing_opportunistic_connection(
				(ac == NULL) ? &nullgw : ac->gateways_from_dns,
				&b->our_client,
				&b->peer_client);

			if (c == NULL) {
				/* We cannot seem to instantiate a suitable connection:
				 * complain clearly.
				 */
				ipstr_buf b1, b2, b3;

				/* ??? CLANG 3.5 thinks ac might be NULL (look up) */
				passert(id_is_ipaddr(&ac->gateways_from_dns->
						     gw_id));
				loglog(RC_OPPOFAILURE,
				       "no suitable connection for opportunism between %s and %s with %s as peer",
				       ipstr(&b->our_client, &b1),
				       ipstr(&b->peer_client, &b2),
				       ipstr(&ac->gateways_from_dns->gw_id.ip_addr, &b3));

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
				/* If we are to proceed asynchronously, b->whackfd will be NULL_FD. */
				passert(c->kind == CK_INSTANCE);
				// passert(c->gw_info != NULL);
				passert(HAS_IPSEC_POLICY(c->policy));
				passert(LHAS(LELEM(RT_UNROUTED) |
					     LELEM(RT_ROUTED_PROSPECTIVE),
					     c->spd.routing));
				if (b->held) {
					/* packet triggered - not whack triggered */
					DBG(DBG_OPPO, DBG_log("assigning negotiation_shunt to connection"));
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
				    DBG_log("initiate on demand from %s:%d to %s:%d proto=%d state: %s because: %s",
					    ours, ourport, his, hisport,
					    b->transport_proto,
					    oppo_step_name[b->step], b->want));

				ipsecdoi_initiate(b->whackfd, c, c->policy, 1,
						  SOS_NOBODY, pcim_local_crypto
#ifdef HAVE_LABELED_IPSEC
						  , NULL /* shall we pass uctx for opportunistic connections? */
#endif
						  );
				b->whackfd = NULL_FD; /* protect from close */
			}
		}
		break;

		default:
			next_step = fos_done; /* Not used, but pleases compiler */
			bad_case(b->step);
		}

		/* the second chunk: initiate the next DNS query (if any) */
		DBG(DBG_OPPO | DBG_CONTROL, {
			if (c != NULL) {
				ipstr_buf b1;
				ipstr_buf b2;
				DBG_log("initiate on demand using %s from %s to %s new state: %s%s%s",
					(c->policy & POLICY_AUTH_NULL) ? "AUTH_NULL" : "RSASIG",
					ipstr(&b->our_client, &b1),
					ipstr(&b->peer_client, &b2),
					oppo_step_name[b->step],
					ugh ? " - error:" : "",
					ugh ? ugh : "");
			}
		});

		if (c == NULL) {
			/*
			 * build_outgoing_opportunistic_connection failed.
			 * This case has been handled already.
			 */
		} else if (ugh != NULL) {
			/* I dont think this can happen without DNS, and then these value are already set */
			b->policy_prio = c->prio;
			b->negotiation_shunt = (c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_HOLD;
			b->failure_shunt = shunt_policy_spi(c, FALSE);
			cannot_oppo(c, b, ugh);
		} else if (next_step != fos_done) {
			/* set up the next query */
			struct find_oppo_continuation *cr = alloc_thing(
				struct find_oppo_continuation,
				"opportunistic continuation");
			b->policy_prio = c->prio;
			b->negotiation_shunt = (c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_HOLD;
			b->failure_shunt = shunt_policy_spi(c, FALSE);
			cr->b = *b; /* copy; start hand off of whackfd */
			cr->b.failure_ok = FALSE;
			cr->b.step = next_step;

			for (sr = &c->spd
			     ; sr != NULL &&
			      !sameaddr(&sr->this.host_addr, &b->our_client)
			     ; sr = sr->spd_next)
				;

			if (sr == NULL)
				sr = &c->spd;

			/* If a %hold shunt has replaced the eroute for this template,
			 * record this fact.
			 */
			if (b->held &&
			    sr->routing == RT_ROUTED_PROSPECTIVE &&
			    eclipsable(sr)) {
				sr->routing = RT_ROUTED_ECLIPSED;
				eclipse_count++;
			}

			/* Switch to issue next query.
			 * A case may turn out to be unnecessary.  If so, it falls
			 * through to the next case.
			 * Figuring out what %myid can stand for must be done before
			 * our client credentials are looked up: we must know what
			 * the client credentials may use to identify us.
			 * On the other hand, our own credentials should be looked
			 * up after our clients in case our credentials are not
			 * needed at all.
			 * XXX this is a wasted effort if we don't have credentials
			 * BUT they are not needed.
			 */
			switch (next_step) {
			case fos_myid_ip_txt:
				cr->b.step = fos_myid_hostname_txt;
			/* FALL THROUGH */
			case fos_myid_hostname_txt:
				cr->b.step = fos_our_client;
			/* FALL THROUGH */
			case fos_our_client: /* IPSECKEY for our client */
				cr->b.step = fos_our_txt;
			/* FALL THROUGH */
			case fos_our_txt: /* IPSECKEY for us */
				break;
			case fos_his_client: /* IPSECKEY for his client */
				break;
			default:
				bad_case(next_step);
			}

			if (ugh == NULL)
				b->whackfd = NULL_FD; /* complete hand-off */
			else
				cannot_oppo(c, b, ugh);
		}
	}
	close_any(b->whackfd);
}

/*
 * an ISAKMP SA has been established.
 * Note the serial number, and release any connections with
 * the same peer ID but different peer IP address.
 */
bool uniqueIDs = FALSE; /* --uniqueids? */

/*
 * Called by main_inI3_outR3_tail() which is called for initiator and responder
 * alike! So this function should not be in initiate.c. It is also not called
 * in IKEv2 code. All it does is set latest serial in connection and check xauth,
 * so it is ikev1 specific. It is also not called in IKEv1 Aggressive Mode!
 */
void ISAKMP_SA_established(struct connection *c, so_serial_t serial)
{
	c->newest_isakmp_sa = serial;

	if (uniqueIDs && !c->spd.this.xauth_server &&
		(c->policy & POLICY_AUTH_NULL) == LEMPTY) {
		/*
		 * for all connections: if the same Phase 1 IDs are used
		 * for different IP addresses, unorient that connection.
		 * We also check ports, since different Phase 1 ID's can
		 * exist for the same IP when NAT is involved.
		 */
		struct connection *d;

		for (d = connections; d != NULL; ) {
			/* might move underneath us */
			struct connection *next = d->ac_next;

			/*
			 * We try to find duplicate instances of same
			 * connection to clean up old ones when uniqueids=yes
			 *
			 * We are testing for all of:
			 * 1: an appropriate kind to consider
			 * 2: same ids, left and right
			 * 3: same address family
			 * 4: same connection name
			 * 5: but different IP address or port
			 * 6: differing dnsnames (sort of)
			 *
			 * DHR (2014-10-29):
			 * Is the sense of the last clause inverted?
			 * The logic kind of suggests that in fact the
			 * same dnsnames should be the same, not different.
			 *
			 * Let's make 6 clearer:
			 *   if BOTH have dnsnames, they must be unequal.
			 *
			 * I suspect that it should be:
			 *   if BOTH have dnsnames, they must be equal.
			 *
			 * In other words the streq result should be negated.
			 */
			if ((d->kind == CK_PERMANENT ||
				d->kind == CK_INSTANCE ||
				d->kind == CK_GOING_AWAY) &&
				(c->name == d->name) &&
				same_id(&c->spd.this.id, &d->spd.this.id) &&
				same_id(&c->spd.that.id, &d->spd.that.id) &&
				addrtypeof(&c->spd.that.host_addr) ==
				addrtypeof(&d->spd.that.host_addr) &&
				(!sameaddr(&c->spd.that.host_addr,
					&d->spd.that.host_addr) ||
				c->spd.that.host_port !=
					d->spd.that.host_port) &&
				!(c->dnshostname != NULL &&
					d->dnshostname != NULL &&
					streq(c->dnshostname,
						d->dnshostname))) {
				release_connection(d, FALSE);
			}
			d = next;
		}
	}
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
	initiate_connection(c->name, NULL_FD, LEMPTY, pcim_demand_crypto);

	/* no host pairs, no more to do */
	pexpect(c->host_pair != NULL);	/* ??? surely */
	if (c->host_pair == NULL)
		return;

	for (d = c->host_pair->connections; d != NULL; d = d->hp_next) {
		if (c != d && same_in_some_sense(c, d))
			initiate_connection(d->name, NULL_FD, LEMPTY,
					    pcim_demand_crypto);
	}
}

void connection_check_ddns(void)
{
	struct connection *c, *cnext;
	struct timeval tv1;

	gettimeofday(&tv1, NULL);

	/* reschedule */
	event_schedule(EVENT_PENDING_DDNS, PENDING_DDNS_INTERVAL, NULL);

	for (c = connections; c != NULL; c = cnext) {
		cnext = c->ac_next;
		connection_check_ddns1(c);
	}
	for (c = unoriented_connections; c != NULL; c = cnext) {
		cnext = c->ac_next;
		connection_check_ddns1(c);
	}
	check_orientations();

	DBG(DBG_DNS, {
		struct timeval tv2;
		unsigned long borrow;

		gettimeofday(&tv2, NULL);
		borrow = tv2.tv_usec < tv1.tv_usec ? 1 : 0;
		DBG_log("elapsed time in %s for hostname lookup %lu.%06lu",
			__func__,
			(unsigned long)(tv2.tv_sec - borrow - tv2.tv_sec),
			(unsigned long)(tv2.tv_usec + borrow * 1000000 - tv2.tv_usec));
	});
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
	event_schedule(EVENT_PENDING_PHASE2, PENDING_PHASE2_INTERVAL, NULL);

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
				"pending Quick Mode with %s \"%s\"%s took too long -- replacing phase 1",
				ipstr(&c->spd.that.host_addr, &b),
				c->name, fmt_conn_instance(c, cib));

			p1st = find_phase1_state(c,
						 ISAKMP_SA_ESTABLISHED_STATES |
						 PHASE1_INITIATOR_STATES);

			if (p1st != NULL) {
				/* arrange to rekey the phase 1, if there was one. */
				if (c->dnshostname != NULL) {
					restart_connections_by_peer(c);
				} else {
					delete_event(p1st);
					event_schedule(EVENT_SA_REPLACE, 0, p1st);
				}
			} else {
				/* start a new connection. Something wanted it up */
				struct initiate_stuff is;

				is.whackfd = NULL_FD;
				is.moredebug = 0;
				is.importance = pcim_local_crypto;

				initiate_a_connection(c, &is);
			}
		}
	}
}

void init_connections(void)
{
	event_schedule(EVENT_PENDING_DDNS, PENDING_DDNS_INTERVAL, NULL);
	event_schedule(EVENT_PENDING_PHASE2, PENDING_PHASE2_INTERVAL, NULL);
}
