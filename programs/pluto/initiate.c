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
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
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
#include "adns.h"       /* needs <resolv.h> */
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
	struct spd_route *sr;

	if (!oriented(*c)) {
		struct iface_port *p;

		for (sr = &c->spd; sr; sr = sr->next) {
			/* There can be more then 1 spd policy associated - required
			 * for cisco split networking when remote_peer_type=cisco
			 */
			if (c->remotepeertype == CISCO && sr != &c->spd )
				continue;

			/* Note: this loop does not stop when it finds a match:
			 * it continues checking to catch any ambiguity.
			 */
			for (p = interfaces; p != NULL; p = p->next) {
				if (p->ike_float)
					continue;

#ifdef HAVE_LABELED_IPSEC
				if (c->loopback &&
				    sameaddr(&sr->this.host_addr,
					     &p->ip_addr)) {
					DBG(DBG_CONTROLMORE,
					    DBG_log("loopback connections \"%s\" with interface %s!",
						    c->name,
						    p->ip_dev->id_rname));
					c->interface = p;
					break;
				}
#endif

				for (;; ) {
					/* check if this interface matches this end */
					if (sameaddr(&sr->this.host_addr,
						     &p->ip_addr) &&
					    (kern_interface != NO_KERNEL ||
					     sr->this.host_port ==
					     pluto_port)) {
						if (oriented(*c)) {
							if (c->interface->
							    ip_dev ==
							    p->ip_dev) {
								loglog(RC_LOG_SERIOUS,
									"both sides of \"%s\" are our interface %s!",
									c->name,
									p->ip_dev->id_rname);
							} else {
								loglog(RC_LOG_SERIOUS, "two interfaces match \"%s\" (%s, %s)",
									c->name, c->interface->ip_dev->id_rname,
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
		loglog(RC_ORIENT,
		       "We cannot identify ourselves with either end of this connection.");
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
			} else
			loglog(RC_NOPEERIP,
			       "cannot initiate connection without knowing peer IP address (kind=%s)",
			       enum_show(&connection_kind_names, c->kind));
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
			} else
			loglog(RC_NOPEERIP,
			       "cannot initiate connection without knowing peer IP address (kind=%s narrowing=%s)",
			       enum_show(&connection_kind_names,
					 c->kind),
			       (c->policy &
				POLICY_IKEV2_ALLOW_NARROWING) ? "yes" : "no");

		} else {
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
				free_sa(phase2_sa);
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
		if (!oriented(*c)) {
			whack_log(RC_LOG_SERIOUS,
			  "cannot initiate unoriented connection \"%s\" - IP address not on system?", name);
			close_any(is.whackfd);
			return;
		} 
		if ((c->policy &  POLICY_IKEV2_PROPOSE) &&
		    (c->policy & POLICY_IKEV2_ALLOW_NARROWING))
			c = instantiate(c, NULL, NULL);
		initiate_a_connection(c, &is);
		close_any(is.whackfd);
		return;
	}

	loglog(RC_COMMENT, "initiating all conns with alias='%s'\n", name);
	count = foreach_connection_by_alias(name, initiate_a_connection, &is);

	if (count == 0) {
		whack_log(RC_UNKNOWN_NAME,
			  "no connection named \"%s\"", name);
	}

	close_any(is.whackfd);
}

void restart_connections_by_peer(struct connection *c)
{
	struct connection *d;

	if (c->host_pair == NULL)
		return;

	d = c->host_pair->connections;
	for (; d != NULL; d = d->hp_next) {
		if ((c->dnshostname && d->dnshostname &&
		     streq(c->dnshostname, d->dnshostname)) ||
		    (c->dnshostname == NULL && d->dnshostname == NULL &&
		     sameaddr(&d->spd.that.host_addr,
				 &c->spd.that.host_addr)))
			terminate_connection(d->name);
	}

	update_host_pairs(c);

	if (c->host_pair == NULL)
		return;

	d = c->host_pair->connections;
	for (; d != NULL; d = d->hp_next) {
		if ((c->dnshostname && d->dnshostname &&
		     streq(c->dnshostname, d->dnshostname)) ||
		    (c->dnshostname == NULL && d->dnshostname == NULL &&
		     sameaddr(&d->spd.that.host_addr,
				 &c->spd.that.host_addr)))
			initiate_connection(d->name, NULL_FD, 0,
					    pcim_demand_crypto);
	}
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
	fos_done
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
	ipsec_spi_t failure_shunt; /* in host order!  0 for delete. */
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
	    libreswan_log("Can not opportunistically initiate for %s to %s: %s",
			  ocb, pcb, ughmsg));

	whack_log(RC_OPPOFAILURE,
		  "Can not opportunistically initiate for %s to %s: %s",
		  ocb, pcb, ughmsg);

	if (c != NULL && c->policy_next != NULL) {
		/* there is some policy that comes afterwards */
		struct spd_route *shunt_spd;
		struct connection *nc = c->policy_next;
		struct state *st;

		passert(c->kind == CK_TEMPLATE);
		passert(nc->kind == CK_PERMANENT);

		DBG(DBG_OPPO,
		    DBG_log("OE failed for %s to %s, but %s overrides shunt",
			    ocb, pcb, nc->name));

		/*
		 * okay, here we need add to the "next" policy, which is ought
		 * to be an instance.
		 * We will add another entry to the spd_route list for the specific
		 * situation that we have.
		 */

		shunt_spd = clone_thing(nc->spd, "shunt eroute policy");

		shunt_spd->next = nc->spd.next;
		nc->spd.next = shunt_spd;

		happy(addrtosubnet(&b->peer_client, &shunt_spd->that.client));

		if (sameaddr(&b->peer_client, &shunt_spd->that.host_addr))
			shunt_spd->that.has_client = FALSE;

		/*
		 * override the tunnel destination with the one from the secondaried
		 * policy
		 */
		shunt_spd->that.host_addr = nc->spd.that.host_addr;

		/* now, lookup the state, and poke it up.
		 */

		st = state_with_serialno(nc->newest_ipsec_sa);

		/* XXX what to do if the IPSEC SA has died? */
		passert(st != NULL);

		/* link the new connection instance to the state's list of
		 * connections
		 */

		DBG(DBG_OPPO, DBG_log("installing state: %ld for %s to %s",
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
		int failure_shunt = b->failure_shunt;

		/* Replace HOLD with b->failure_shunt.
		 * If no failure_shunt specified, use SPI_PASS -- THIS MAY CHANGE.
		 */
		if (failure_shunt == 0) {
			DBG(DBG_OPPO,
			    DBG_log("no explicit failure shunt for %s to %s; removing spurious hold shunt",
				    ocb, pcb));
		}
		(void) replace_bare_shunt(&b->our_client, &b->peer_client,
					  b->policy_prio,
					  failure_shunt,
					  failure_shunt != 0,
					  b->transport_proto,
					  ughmsg);
	}
}

static bool initiate_ondemand_body(struct find_oppo_bundle *b,
				  struct adns_continuation *ac, err_t ac_ugh
#ifdef HAVE_LABELED_IPSEC
				  , struct xfrm_user_sec_ctx_ike *uctx
#endif
				  ); /* forward */

bool initiate_ondemand(const ip_address *our_client,
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
	b.failure_shunt = 0;
	b.whackfd = whackfd;
	b.step = fos_start;
	return initiate_ondemand_body(&b, NULL, NULL
#ifdef HAVE_LABELED_IPSEC
				      , uctx
#endif
				      );
}

static void continue_oppo(struct adns_continuation *acr, err_t ugh)
{
	struct find_oppo_continuation *cr = (void *)acr; /* inherit, damn you! */
	struct connection *c;
	bool was_held = cr->b.held;
	int whackfd = cr->b.whackfd;

	/* note: cr->id has no resources; cr->sgw_id is id_none:
	 * neither need freeing.
	 */
	whack_log_fd = whackfd;

	/* Discover and record whether %hold has gone away.
	 * This could have happened while we were awaiting DNS.
	 * We must check BEFORE any call to cannot_oppo.
	 */
	if (was_held) {
		cr->b.held = has_bare_hold(&cr->b.our_client,
					   &cr->b.peer_client,
					   cr->b.transport_proto);
	}

	/* if we're going to ignore the error, at least note it in debugging log */
	if (cr->b.failure_ok && ugh != NULL) {
		DBG(DBG_CONTROL | DBG_DNS, {
			ipstr_buf a;
			ipstr_buf b;
			DBG_log("continuing from failed DNS lookup for %s, %s to %s: %s",
				cr->b.want,
				ipstr(&cr->b.our_client, &a),
				ipstr(&cr->b.peer_client, &b),
				ugh);
		});
	}

	if (!cr->b.failure_ok && ugh != NULL) {
		c = find_connection_for_clients(NULL, &cr->b.our_client,
						&cr->b.peer_client,
						cr->b.transport_proto);
		cannot_oppo(c, &cr->b,
			    builddiag("%s: %s", cr->b.want, ugh));
	} else if (was_held && !cr->b.held) {
		/* was_held indicates we were started due to a %trap firing
		 * (as opposed to a "whack --oppohere --oppothere").
		 * Since the %hold has gone, we can assume that somebody else
		 * has beaten us to the punch.  We can go home.  But lets log it.
		 */
		ipstr_buf a, b;

		loglog(RC_COMMENT,
		       "%%hold otherwise handled during DNS lookup for Opportunistic Initiation for %s to %s",
		       ipstr(&cr->b.our_client, &a),
		       ipstr(&cr->b.peer_client, &b));
	} else {
		(void)initiate_ondemand_body(&cr->b, &cr->ac, ugh
#ifdef HAVE_LABELED_IPSEC
					     , NULL
#endif
					     );
		whackfd = NULL_FD; /* was handed off */
	}

	whack_log_fd = NULL_FD;
	close_any(whackfd);
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
/* return true if we did something */
static bool initiate_ondemand_body(struct find_oppo_bundle *b,
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
	bool work = FALSE;

	/* on klips/mast assume we will do something */
	work = kern_interface == USE_KLIPS ||
	       kern_interface == USE_MASTKLIPS ||
	       kern_interface == USE_NETKEY;

	/* What connection shall we use?
	 * First try for one that explicitly handles the clients.
	 */

	addrtot(&b->our_client, 0, ours, sizeof(ours));
	addrtot(&b->peer_client, 0, his, sizeof(his));
	ourport = ntohs(portof(&b->our_client));
	hisport = ntohs(portof(&b->peer_client));

#ifdef HAVE_LABELED_IPSEC
	char sec_ctx_value[MAX_SECCTX_LEN];

	zero(&sec_ctx_value);
	if (uctx != NULL)
		memcpy(sec_ctx_value, uctx->sec_ctx_value, uctx->ctx_len);
	DBG(DBG_CONTROLMORE,
	    DBG_log("received security label string: %s", sec_ctx_value));
#endif

	snprintf(demandbuf, 256,
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
		work = FALSE;
	} else if (!(c = find_connection_for_clients(&sr,
						     &b->our_client,
						     &b->peer_client,
						     b->transport_proto))) {
		/* No connection explicitly handles the clients and there
		 * are no Opportunistic connections -- whine and give up.
		 * The failure policy cannot be gotten from a connection; we pick %pass.
		 */
		if (!loggedit) {
			libreswan_log("%s", demandbuf);
			loggedit = TRUE;
		}
		cannot_oppo(NULL, b, "no routed template covers this pair");
		work = FALSE;
	} else if (c->kind == CK_TEMPLATE && (c->policy & POLICY_OPPORTUNISTIC) == 0) {
		if (!loggedit) {
			libreswan_log("%s", demandbuf);
			loggedit = TRUE;
		}
		loglog(RC_NOPEERIP,
		       "cannot initiate connection for packet %s:%d -> %s:%d proto=%d - template conn",
		       ours, ourport, his, hisport, b->transport_proto);
		work = FALSE;
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
			/* there is already an instance being negotiated, do nothing */
			libreswan_log(
				"rekeying existing instance \"%s\"%s, due to acquire",
				c->name,
				(fmt_conn_instance(c, cib), cib));

			/*
			 * we used to return here, but rekeying is a better choice. If we
			 * got the acquire, it is because something turned stuff into a
			 * %trap, or something got deleted, perhaps due to an expiry.
			 */
		}

		/* otherwise, there is some kind of static conn that can handle
		 * this connection, so we initiate it
		 */
		if (b->held) {
			/* what should we do on failure? */
			(void) assign_hold(c, sr, b->transport_proto,
					   &b->our_client, &b->peer_client);
		}

		if (!loggedit) {
			libreswan_log("%s", demandbuf);
			loggedit = TRUE;
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

		DBG(DBG_CONTROL, {
			    char cib[CONN_INST_BUF];
			    DBG_log("creating new instance from \"%s\"%s",
				    c->name,
				    (fmt_conn_instance(c, cib), cib));
		    });

		idtoa(&sr->this.id, mycredentialstr, sizeof(mycredentialstr));

		passert(c->policy & POLICY_OPPORTUNISTIC); /* can't initiate Road Warrior connections */

		/* handle any DNS answer; select next step */

		switch (b->step) {
		case fos_start:
			/* just starting out: select first query step */
			next_step = fos_myid_ip_txt;
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
						DBG(DBG_CONTROL,
						    DBG_log("initiate on demand found IPSECKEY with right public key at: %s",
							    mycredentialstr));
						ugh = NULL;
						break;
					}
				}
			}
		}
		break;

		case fos_his_client: /* IPSECKEY for his client */
		{
			/* We've finished last DNS queries: IPSECKEY for his client.
			 * Using the information, try to instantiate a connection
			 * and start negotiating.
			 * We now know the peer.  The chosing of "c" ignored this,
			 * so we will disregard its current value.
			 * !!! We need to randomize the entry in gw that we choose.
			 */
			next_step = fos_done; /* no more queries */

			c = build_outgoing_opportunistic_connection(
				ac->gateways_from_dns,
				&b->our_client,
				&b->peer_client);

			if (c == NULL) {
				/* We cannot seem to instantiate a suitable connection:
				 * complain clearly.
				 */
				ipstr_buf b1, b2, b3;

				passert(id_is_ipaddr(&ac->gateways_from_dns->
						     gw_id));
				loglog(RC_OPPOFAILURE,
				       "no suitable connection for opportunism"
				       " between %s and %s with %s as peer",
				       ipstr(&b->our_client, &b1),
				       ipstr(&b->peer_client, &b2),
				       ipstr(&ac->gateways_from_dns->gw_id.ip_addr, &b3));

				if (b->held) {
					/* Replace HOLD with PASS.
					 * The type of replacement *ought* to be
					 * specified by policy.
					 */
					(void) replace_bare_shunt(
						&b->our_client,
						&b->peer_client,
						BOTTOM_PRIO,
						SPI_PASS, /* fail into PASS */
						TRUE,
						b->transport_proto,
						"no suitable connection");
				}
			} else {
				/* If we are to proceed asynchronously, b->whackfd will be NULL_FD. */
				passert(c->kind == CK_INSTANCE);
				passert(c->gw_info != NULL);
				passert(HAS_IPSEC_POLICY(c->policy));
				passert(LHAS(LELEM(RT_UNROUTED) |
					     LELEM(RT_ROUTED_PROSPECTIVE),
					     c->spd.routing));
				if (b->held) {
					/* what should we do on failure? */
					(void) assign_hold(c, &c->spd,
							   b->transport_proto,
							   &b->our_client,
							   &b->peer_client);
				}
				DBG(DBG_OPPO | DBG_CONTROL,
				    DBG_log("initiate on demand from %s:%d to %s:%d proto=%d state: %s because: %s",
					    ours, ourport, his, hisport,
					    b->transport_proto,
					    oppo_step_name[b->step], b->want));

				ipsecdoi_initiate(b->whackfd, c, c->policy, 1,
						  SOS_NOBODY, pcim_local_crypto
#ifdef HAVE_LABELED_IPSEC
						  , NULL /*shall we pass uctx for opportunistic connections?*/
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
		DBG(DBG_CONTROL, {
			ipstr_buf b1;
			ipstr_buf b2;
			DBG_log("initiate on demand from %s to %s new state: %s with ugh: %s",
				ipstr(&b->our_client, &b1),
				ipstr(&b->peer_client, &b2),
				oppo_step_name[b->step],
				ugh ? ugh : "ok");
		});

		if (ugh != NULL) {
			b->policy_prio = c->prio;
			b->failure_shunt = shunt_policy_spi(c, FALSE);
			cannot_oppo(c, b, ugh);
		} else if (next_step == fos_done) {
			/* nothing to do */
		} else {
			/* set up the next query */
			struct find_oppo_continuation *cr = alloc_thing(
				struct find_oppo_continuation,
				"opportunistic continuation");
			struct id id;

			b->policy_prio = c->prio;
			b->failure_shunt = shunt_policy_spi(c, FALSE);
			cr->b = *b; /* copy; start hand off of whackfd */
			cr->b.failure_ok = FALSE;
			cr->b.step = next_step;

			for (sr = &c->spd
			     ; sr != NULL &&
			      !sameaddr(&sr->this.host_addr, &b->our_client)
			     ; sr = sr->next)
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
				if (c->spd.this.id.kind == ID_MYID &&
				    myid_state != MYID_SPECIFIED) {
					cr->b.failure_ok = TRUE;
					cr->b.want = b->want =
						"IPSECKEY record for IP address as %myid";
					ugh = start_adns_query(&myids[MYID_IP],
							       &myids[MYID_IP],
							       ns_t_txt,
							       continue_oppo,
							       &cr->ac);
					break;
				}
				cr->b.step = fos_myid_hostname_txt;
			/* FALL THROUGH */
			case fos_myid_hostname_txt:
				if (c->spd.this.id.kind == ID_MYID &&
				    myid_state != MYID_SPECIFIED) {
					cr->b.failure_ok = FALSE;
					cr->b.want = b->want =
						"IPSECKEY record for hostname as %myid";
					ugh = start_adns_query(&myids[
								 MYID_HOSTNAME],
							       &myids[MYID_HOSTNAME],
							       ns_t_txt,
							       continue_oppo,
							       &cr->ac);
					break;
				}

				cr->b.step = fos_our_client;
			/* FALL THROUGH */
			case fos_our_client: /* IPSECKEY for our client */
				if (!sameaddr(&c->spd.this.host_addr,
					      &b->our_client)) {
					/* Check that at least one IPSECKEY(reverse(b->our_client)) is workable.
					 * Note: {unshare|free}_id_content not needed for id: ephemeral.
					 */
					cr->b.want = b->want =
						"our client's IPSECKEY record";
					iptoid(&b->our_client, &id);
					ugh = start_adns_query(&id,
							       &c->spd.this.id, /* we are the security gateway */
							       ns_t_txt,
							       continue_oppo,
							       &cr->ac);
					break;
				}
				cr->b.step = fos_our_txt;
			/* FALL THROUGH */
			case fos_our_txt: /* IPSECKEY for us */
				cr->b.failure_ok = b->failure_ok = TRUE;
				cr->b.want = b->want = "our IPSECKEY record";
				ugh = start_adns_query(&sr->this.id,
						       &sr->this.id, /* we are the security gateway XXX - maybe ignore? mcr */
						       ns_t_txt,
						       continue_oppo,
						       &cr->ac);
				break;

			case fos_his_client: /* IPSECKEY for his client */
				/* note: {unshare|free}_id_content not needed for id: ephemeral */
				cr->b.want = b->want =
						     "target's IPSECKEY record";
				cr->b.failure_ok = b->failure_ok = FALSE;
				iptoid(&b->peer_client, &id);
				ugh = start_adns_query(&id,
						       (const struct id *) NULL, /* security gateway unconstrained */
						       ns_t_txt,
						       continue_oppo,
						       &cr->ac);
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
	return work;
}

/* an ISAKMP SA has been established.
 * Note the serial number, and release any connections with
 * the same peer ID but different peer IP address.
 */
bool uniqueIDs = FALSE; /* --uniqueids? */

void ISAKMP_SA_established(struct connection *c, so_serial_t serial)
{
	c->newest_isakmp_sa = serial;

	if (uniqueIDs && !c->spd.this.xauth_server) {
		/*
		 * for all connections: if the same Phase 1 IDs are used
		 * for different IP addresses, unorient that connection.
		 * We also check ports, since different Phase 1 ID's can
		 * exist for the same IP when NAT is involved
		 */
		struct connection *d;

		for (d = connections; d != NULL; ) {
			/* might move underneath us */
			struct connection *next = d->ac_next;

			if ((d->kind == CK_PERMANENT ||
			     d->kind == CK_INSTANCE ||
			     d->kind == CK_GOING_AWAY) &&
			    same_id(&c->spd.this.id, &d->spd.this.id) &&
			    same_id(&c->spd.that.id, &d->spd.that.id) &&
			    addrtypeof(&c->spd.that.host_addr) ==
				addrtypeof(&d->spd.that.host_addr) &&
			    (!sameaddr(&c->spd.that.host_addr,
				  &d->spd.that.host_addr) ||
			      c->spd.that.host_port !=
				  d->spd.that.host_port) &&
			    !(c->dnshostname && d->dnshostname &&
			      streq(c->dnshostname, d->dnshostname))) {
				/*
				 * Paul and AA  tried to delete phase2
				 * didn't really work.
				 * delete_p2states_by_connection(d);
				 */
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
	struct spd_route *sr;

	for (c = connections; c != NULL; c = c->ac_next) {
		for (sr = &c->spd; sr; sr = sr->next) {
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
	/* const struct af_info afi; */
	const char *e;

	if (NEVER_NEGOTIATE(c->policy))
		return;

	if (c->dnshostname == NULL)
		return;

	if (!isanyaddr(&c->spd.that.host_addr)) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("pending ddns: connection \"%s\" has address",
			    c->name));
		return;
	}

	if (c->spd.that.has_client_wildcard || c->spd.that.has_port_wildcard ||
	    ((c->policy & POLICY_SHUNT_MASK) == 0 &&
	     c->spd.that.has_id_wildcards)) {
		DBG(DBG_CONTROL,
		    DBG_log("pending ddns: connection \"%s\" with wildcard not started",
			    c->name));
		return;
	}

	e = ttoaddr(c->dnshostname, 0, AF_UNSPEC, &new_addr);
	if (e != NULL) {
		DBG(DBG_CONTROL,
		    DBG_log("pending ddns: connection \"%s\" lookup of \"%s\" failed: %s",
			    c->name, c->dnshostname, e));
		return;
	}

	if (isanyaddr(&new_addr)) {
		DBG(DBG_CONTROL,
		    DBG_log("pending ddns: connection \"%s\" still no address for \"%s\"",
			    c->name, c->dnshostname));
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
	initiate_connection(c->name, NULL_FD, 0, pcim_demand_crypto);

	/* no host pairs,  no more to do */
	if (c->host_pair == NULL)
		return;

	d = c->host_pair->connections;
	for (; d != NULL; d = d->hp_next) {
		/* just in case we see ourselves */
		if (c == d)
			continue;
		if ((c->dnshostname && d->dnshostname &&
		     streq(c->dnshostname, d->dnshostname)) ||
		    (c->dnshostname == NULL && d->dnshostname == NULL &&
		     sameaddr(&d->spd.that.host_addr, &c->spd.that.host_addr)))
			initiate_connection(d->name, NULL_FD, 0,
					    pcim_demand_crypto);
	}
}

void connection_check_ddns(void)
{
	struct connection *c, *cnext;

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
			DBG(DBG_CONTROL,
			    DBG_log("pending review: connection \"%s\" has no negotiated policy, skipped",
				    c->name));
			continue;
		}

		if (!(c->policy & POLICY_UP)) {
			DBG(DBG_CONTROL,
			    DBG_log("pending review: connection \"%s\" was not up, skipped",
				    c->name));
			continue;
		}

		DBG(DBG_CONTROL,
		    DBG_log("pending review: connection \"%s\" checked",
			    c->name));

		if (pending_check_timeout(c)) {
			struct state *p1st;
			ipstr_buf b;

			libreswan_log(
				"pending Quick Mode with %s \"%s\" took too long -- replacing phase 1",
				ipstr(&c->spd.that.host_addr, &b),
				c->name);

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
