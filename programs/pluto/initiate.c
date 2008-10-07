/* information about connections between hosts and clients
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "openswan/pfkeyv2.h"
#include "kameipsec.h"

#include "sysdep.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswtime.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "secrets.h"

#include "defs.h"
#include "ac.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "pending.h"
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "server.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "keys.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "whack.h"
#include "alg_info.h"
#include "spdb.h"
#include "ike_alg.h"
#include "plutocerts.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "xauth.h"
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#include "virtual.h"

#include "hostpair.h"

bool
orient(struct connection *c)
{
    struct spd_route *sr;

    if (!oriented(*c))
    {
	struct iface_port *p;

	for (sr = &c->spd; sr; sr = sr->next)
	{
	    /* Note: this loop does not stop when it finds a match:
	     * it continues checking to catch any ambiguity.
	     */
	    for (p = interfaces; p != NULL; p = p->next)
	    {
#ifdef NAT_TRAVERSAL
		if (p->ike_float) continue;
#endif
		for (;;)
		{
		    /* check if this interface matches this end */
		    if (sameaddr(&sr->this.host_addr, &p->ip_addr)
			&& (kern_interface != NO_KERNEL
			    || sr->this.host_port == pluto_port))
		    {
			if (oriented(*c))
			{
			    if (c->interface->ip_dev == p->ip_dev)
				loglog(RC_LOG_SERIOUS
				       , "both sides of \"%s\" are our interface %s!"
				       , c->name, p->ip_dev->id_rname);
			    else
				loglog(RC_LOG_SERIOUS, "two interfaces match \"%s\" (%s, %s)"
				       , c->name, c->interface->ip_dev->id_rname, p->ip_dev->id_rname);
			    c->interface = NULL;	/* withdraw orientation */
			    return FALSE;
			}
			c->interface = p;
		    }

		    /* done with this interface if it doesn't match that end */
		    if (!(sameaddr(&sr->that.host_addr, &p->ip_addr)
			  && (kern_interface!=NO_KERNEL
			      || sr->that.host_port == pluto_port)))
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
    int    whackfd;
    lset_t moredebug;
    enum crypto_importance importance;
};

static int
initiate_a_connection(struct connection *c
		      , void *arg)
{
    struct initiate_stuff *is = (struct initiate_stuff *)arg;
    int whackfd = is->whackfd;
    lset_t moredebug = is->moredebug;
    enum crypto_importance importance = is->importance;
    int success = 0;

    set_cur_connection(c);

    /* turn on any extra debugging asked for */
    c->extra_debugging |= moredebug;
    
    if (!oriented(*c))
    {
	loglog(RC_ORIENT, "We cannot identify ourselves with either end of this connection.");
    }
    else if (NEVER_NEGOTIATE(c->policy))
    {
	loglog(RC_INITSHUNT
	       , "cannot initiate an authby=never connection");
    }
    else if (c->kind != CK_PERMANENT)
    {
	if (isanyaddr(&c->spd.that.host_addr))
	    loglog(RC_NOPEERIP, "cannot initiate connection without knowing peer IP address (kind=%s)"
		   , enum_show(&connection_kind_names, c->kind));
	else
	    loglog(RC_WILDCARD, "cannot initiate connection with ID wildcards (kind=%s)"
		   , enum_show(&connection_kind_names, c->kind));
    }
    else
    {
	/* We will only request an IPsec SA if policy isn't empty
	 * (ignoring Main Mode items).
	 * This is a fudge, but not yet important.
	 * If we are to proceed asynchronously, whackfd will be NULL_FD.
	 */
	c->policy |= POLICY_UP;
	
	if(c->policy & (POLICY_ENCRYPT|POLICY_AUTHENTICATE)) {
	    struct alg_info_esp *alg = c->alg_info_esp;
	    struct db_sa *phase2_sa = kernel_alg_makedb(c->policy, alg, TRUE);
	    
	    if(alg != NULL && phase2_sa == NULL) {
		whack_log(RC_NOALGO, "can not initiate: no acceptable kernel algorithms loaded");
		reset_cur_connection();
		close_any(is->whackfd);
		return 0;
	    }
	    free_sa(phase2_sa);
	}
	
#ifdef SMARTCARD
	/* do we have to prompt for a PIN code? */
	if (c->spd.this.sc != NULL && !c->spd.this.sc->valid && whackfd != NULL_FD)
	    scx_get_pin(c->spd.this.sc, whackfd);
	
	if (c->spd.this.sc != NULL && !c->spd.this.sc->valid)
	{
	    loglog(RC_NOVALIDPIN, "cannot initiate connection without valid PIN");
	}
	else
#endif
	{
	    whackfd = dup(whackfd);
	    ipsecdoi_initiate(whackfd, c, c->policy, 1
			      , SOS_NOBODY, importance);
	    success = 1;
	}
    }
    reset_cur_connection();
    
    return success;
}

void
initiate_connection(const char *name, int whackfd
		    , lset_t moredebug
		    , enum crypto_importance importance)
{
    struct initiate_stuff is;
    struct connection *c = con_by_name(name, FALSE);
    int count;

    is.whackfd   = whackfd;
    is.moredebug = moredebug;
    is.importance= importance;

    if (c != NULL)
    {
	initiate_a_connection(c, &is);
	close_any(is.whackfd);
	return;
    }

    loglog(RC_COMMENT, "initiating all conns with alias='%s'\n", name);
    count = foreach_connection_by_alias(name, initiate_a_connection, &is);

    if(count == 0) {
	whack_log(RC_UNKNOWN_NAME
		  , "no connection named \"%s\"", name);
    }

    close_any(is.whackfd);
}

void
restart_connections_by_peer(struct connection *c)
{
    struct connection *d;

    d = c->host_pair->connections;
    for (; d != NULL; d = d->hp_next) {
	   if (
#ifdef DYNAMICDNS
		(c->dnshostname && d->dnshostname && (strcmp(c->dnshostname, d->dnshostname) == 0))
		 || (c->dnshostname == NULL && d->dnshostname == NULL && 
#endif
		sameaddr(&d->spd.that.host_addr, &c->spd.that.host_addr)
#ifdef DYNAMICDNS
		)
#endif 
		)
	       terminate_connection(d->name);
    }

#ifdef DYNAMICDNS
    update_host_pairs(c);
#endif /* DYNAMICDNS */

    if (c->host_pair == NULL)
    	   return;
    d = c->host_pair->connections;
    for (; d != NULL; d = d->hp_next) {
    	   if (
#ifdef DYNAMICDNS
		(c->dnshostname && d->dnshostname && (strcmp(c->dnshostname, d->dnshostname) == 0))
		|| (c->dnshostname == NULL && d->dnshostname == NULL && 
#endif /* DYNAMICDNS */
		sameaddr(&d->spd.that.host_addr, &c->spd.that.host_addr)
#ifdef DYNAMICDNS
		)
#endif /* DYNAMICDNS */
               )
	       initiate_connection(d->name, NULL_FD, 0, pcim_demand_crypto);
    }
}

/* (Possibly) Opportunistic Initiation:
 * Knowing clients (single IP addresses), try to build an tunnel.
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
#ifdef USE_KEYRR
    fos_our_key,
#endif /* USE_KEYRR */
    fos_his_client,
    fos_done
};

#ifdef DEBUG
static const char *const oppo_step_name[] = {
    "fos_start",
    "fos_myid_ip_txt",
    "fos_myid_hostname_txt",
    "fos_myid_ip_key",
    "fos_myid_hostname_key",
    "fos_our_client",
    "fos_our_txt",
#ifdef USE_KEYRR
    "fos_our_key",
#endif /* USE_KEYRR */
    "fos_his_client",
    "fos_done"
};
#endif /* DEBUG */

struct find_oppo_bundle {
    enum find_oppo_step step;
    err_t want;
    bool failure_ok;		/* if true, continue_oppo should not die on DNS failure */
    ip_address our_client;	/* not pointer! */
    ip_address peer_client;
    int transport_proto;
    bool held;
    policy_prio_t policy_prio;
    ipsec_spi_t failure_shunt;	/* in host order!  0 for delete. */
    int whackfd;
};

struct find_oppo_continuation {
    struct adns_continuation ac;	/* common prefix */
    struct find_oppo_bundle b;
};

static void
cannot_oppo(struct connection *c
	    , struct find_oppo_bundle *b
	    , err_t ughmsg)
{
    char pcb[ADDRTOT_BUF];
    char ocb[ADDRTOT_BUF];

    addrtot(&b->peer_client, 0, pcb, sizeof(pcb));
    addrtot(&b->our_client, 0, ocb, sizeof(ocb));

    DBG(DBG_OPPO,
	openswan_log("Can not opportunistically initiate for %s to %s: %s"
		     , ocb, pcb, ughmsg));

    whack_log(RC_OPPOFAILURE
	, "Can not opportunistically initiate for %s to %s: %s"
	, ocb, pcb, ughmsg);

    if (c != NULL && c->policy_next != NULL)
    {
	/* there is some policy that comes afterwards */
	struct spd_route *shunt_spd;
	struct connection *nc = c->policy_next;
	struct state *st;

	passert(c->kind == CK_TEMPLATE);
	passert(c->policy_next->kind == CK_PERMANENT);

	DBG(DBG_OPPO, DBG_log("OE failed for %s to %s, but %s overrides shunt"
			      , ocb, pcb, c->policy_next->name));

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

	DBG(DBG_OPPO, DBG_log("installing state: %ld for %s to %s"
			      , nc->newest_ipsec_sa
			      , ocb, pcb));

#ifdef DEBUG
	if (DBGP(DBG_OPPO | DBG_CONTROLMORE))
	{
	    char state_buf[LOG_WIDTH];
	    char state_buf2[LOG_WIDTH];
	    time_t n = now();

	    fmt_state(st, n, state_buf, sizeof(state_buf)
		      , state_buf2, sizeof(state_buf2));
	    DBG_log("cannot_oppo, failure SA1: %s", state_buf);
	    DBG_log("cannot_oppo, failure SA2: %s", state_buf2);
	}
#endif /* DEBUG */

	if (!route_and_eroute(c, shunt_spd, st))
	{
	    whack_log(RC_OPPOFAILURE
		      , "failed to instantiate shunt policy %s for %s to %s"
		      , c->name
		      , ocb, pcb);
	}
	return;
    }

#ifdef KLIPS
    if (b->held)
    {
	int failure_shunt = b->failure_shunt;

	/* Replace HOLD with b->failure_shunt.
	 * If no b->failure_shunt specified, use SPI_PASS -- THIS MAY CHANGE.
	 */
	if (b->failure_shunt == 0)
	{
	    DBG(DBG_OPPO, DBG_log("no explicit failure shunt for %s to %s; installing %%pass"
				  , ocb, pcb));
	    failure_shunt = SPI_PASS;
	}

	(void) replace_bare_shunt(&b->our_client, &b->peer_client
	    , b->policy_prio
	    , failure_shunt
	    , failure_shunt == SPI_PASS
	    , b->transport_proto
	    , ughmsg);
    }
#endif
}

static void initiate_ondemand_body(struct find_oppo_bundle *b
    , struct adns_continuation *ac, err_t ac_ugh);	/* forward */

void
initiate_ondemand(const ip_address *our_client
, const ip_address *peer_client
, int transport_proto
, bool held
, int whackfd
, err_t why)
{
    struct find_oppo_bundle b;

    b.want = why;	/* fudge */
    b.failure_ok = FALSE;
    b.our_client = *our_client;
    b.peer_client = *peer_client;
    b.transport_proto = transport_proto;
    b.held = held;
    b.policy_prio = BOTTOM_PRIO;
    b.failure_shunt = 0;
    b.whackfd = whackfd;
    b.step = fos_start;
    initiate_ondemand_body(&b, NULL, NULL);
}

static void
continue_oppo(struct adns_continuation *acr, err_t ugh)
{
    struct find_oppo_continuation *cr = (void *)acr;	/* inherit, damn you! */
    struct connection *c;
    bool was_held = cr->b.held;
    int whackfd = cr->b.whackfd;

    /* note: cr->id has no resources; cr->sgw_id is id_none:
     * neither need freeing.
     */
    whack_log_fd = whackfd;

#ifdef KLIPS
    /* Discover and record whether %hold has gone away.
     * This could have happened while we were awaiting DNS.
     * We must check BEFORE any call to cannot_oppo.
     */
    if (was_held)
	cr->b.held = has_bare_hold(&cr->b.our_client, &cr->b.peer_client
	    , cr->b.transport_proto);
#endif

#ifdef DEBUG
    /* if we're going to ignore the error, at least note it in debugging log */
    if (cr->b.failure_ok && ugh != NULL)
    {
	DBG(DBG_CONTROL | DBG_DNS,
	    {
		char ocb[ADDRTOT_BUF];
		char pcb[ADDRTOT_BUF];

		addrtot(&cr->b.our_client, 0, ocb, sizeof(ocb));
		addrtot(&cr->b.peer_client, 0, pcb, sizeof(pcb));
		DBG_log("continuing from failed DNS lookup for %s, %s to %s: %s"
		    , cr->b.want, ocb, pcb, ugh);
	    });
    }
#endif

    if (!cr->b.failure_ok && ugh != NULL)
    {
	c = find_connection_for_clients(NULL, &cr->b.our_client, &cr->b.peer_client
	    , cr->b.transport_proto);
	cannot_oppo(c, &cr->b
		    , builddiag("%s: %s", cr->b.want, ugh));
    }
    else if (was_held && !cr->b.held)
    {
	/* was_held indicates we were started due to a %trap firing
	 * (as opposed to a "whack --oppohere --oppothere").
	 * Since the %hold has gone, we can assume that somebody else
	 * has beaten us to the punch.  We can go home.  But lets log it.
	 */
	char ocb[ADDRTOT_BUF];
	char pcb[ADDRTOT_BUF];

	addrtot(&cr->b.our_client, 0, ocb, sizeof(ocb));
	addrtot(&cr->b.peer_client, 0, pcb, sizeof(pcb));

	loglog(RC_COMMENT
	    , "%%hold otherwise handled during DNS lookup for Opportunistic Initiation for %s to %s"
	    , ocb, pcb);
    }
    else
    {
	initiate_ondemand_body(&cr->b, &cr->ac, ugh);
	whackfd = NULL_FD;	/* was handed off */
    }

    whack_log_fd = NULL_FD;
    close_any(whackfd);
}

#ifdef USE_KEYRR
static err_t
check_key_recs(enum myid_state try_state
, const struct connection *c
, struct adns_continuation *ac)
{
    /* Check if KEY lookup yielded good results.
     * Looking up based on our ID.  Used if
     * client is ourself, or if TXT had no public key.
     * Note: if c is different this time, there is
     * a chance that we did the wrong query.
     * If so, treat as a kind of failure.
     */
    enum myid_state old_myid_state = myid_state;
    const struct RSA_private_key *our_RSA_pri;
    err_t ugh = NULL;

    myid_state = try_state;

    if (old_myid_state != myid_state
    && old_myid_state == MYID_SPECIFIED)
    {
	ugh = "%myid was specified while we were guessing";
    }
    else if ((our_RSA_pri = get_RSA_private_key(c)) == NULL)
    {
	ugh = "we don't know our own RSA key";
    }
    else if (!same_id(&ac->id, &c->spd.this.id))
    {
	ugh = "our ID changed underfoot";
    }
    else
    {
	/* Similar to code in RSA_check_signature
	 * for checking the other side.
	 */
	struct pubkey_list *kr;

	ugh = "no KEY RR found for us";
	for (kr = ac->keys_from_dns; kr != NULL; kr = kr->next)
	{
	    ugh = "all our KEY RRs have the wrong public key";
	    if (kr->key->alg == PUBKEY_ALG_RSA
	    && same_RSA_public_key(&our_RSA_pri->pub, &kr->key->u.rsa))
	    {
		ugh = NULL;	/* good! */
		break;
	    }
	}
    }
    if (ugh != NULL)
	myid_state = old_myid_state;
    return ugh;
}
#endif /* USE_KEYRR */

static err_t
check_txt_recs(enum myid_state try_state
, const struct connection *c
, struct adns_continuation *ac)
{
    /* Check if TXT lookup yielded good results.
     * Looking up based on our ID.  Used if
     * client is ourself, or if TXT had no public key.
     * Note: if c is different this time, there is
     * a chance that we did the wrong query.
     * If so, treat as a kind of failure.
     */
    enum myid_state old_myid_state = myid_state;
    const struct RSA_private_key *our_RSA_pri;
    err_t ugh = NULL;

    myid_state = try_state;

    if (old_myid_state != myid_state
    && old_myid_state == MYID_SPECIFIED)
    {
	ugh = "%myid was specified while we were guessing";
    }
    else if ((our_RSA_pri = get_RSA_private_key(c)) == NULL)
    {
	ugh = "we don't know our own RSA key";
    }
    else if (!same_id(&ac->id, &c->spd.this.id))
    {
	ugh = "our ID changed underfoot";
    }
    else
    {
	/* Similar to code in RSA_check_signature
	 * for checking the other side.
	 */
	struct gw_info *gwp;

	ugh = "no TXT RR found for us";
	for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
	{
	    ugh = "all our TXT RRs have the wrong public key";
	    if (gwp->key->alg == PUBKEY_ALG_RSA
	    && same_RSA_public_key(&our_RSA_pri->pub, &gwp->key->u.rsa))
	    {
		ugh = NULL;	/* good! */
		break;
	    }
	}
    }
    if (ugh != NULL)
	myid_state = old_myid_state;
    return ugh;
}


/* note: gateways_from_dns must be NULL iff this is the first call */
static void
initiate_ondemand_body(struct find_oppo_bundle *b
, struct adns_continuation *ac
, err_t ac_ugh)
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

    snprintf(demandbuf, 256, "initiate on demand from %s:%d to %s:%d proto=%d state: %s because: %s"
	     , ours, ourport, his, hisport, b->transport_proto
	     , oppo_step_name[b->step], b->want);
    
    if(DBGP(DBG_OPPOINFO)) {
	openswan_log("%s", demandbuf);
	loggedit = TRUE;
    } else if(whack_log_fd != NULL_FD) {
	whack_log(RC_COMMENT, "%s", demandbuf);
	loggedit = TRUE;
    }

    if (isanyaddr(&b->our_client) || isanyaddr(&b->peer_client))
    {
	cannot_oppo(NULL, b, "impossible IP address");
    }
    else if ((c = find_connection_for_clients(&sr
					      , &b->our_client
					      , &b->peer_client
					      , b->transport_proto)) == NULL)
    {
	/* No connection explicitly handles the clients and there
	 * are no Opportunistic connections -- whine and give up.
	 * The failure policy cannot be gotten from a connection; we pick %pass.
	 */
	if(!loggedit) { openswan_log("%s", demandbuf); loggedit=TRUE; }
	cannot_oppo(NULL, b, "no routed template covers this pair");
    }
    else if (c->kind == CK_TEMPLATE && (c->policy & POLICY_OPPO)==0)
    {
	if(!loggedit) { openswan_log("%s", demandbuf); loggedit=TRUE; }
	loglog(RC_NOPEERIP, "cannot initiate connection for packet %s:%d -> %s:%d proto=%d - template conn"
	       , ours, ourport, his, hisport, b->transport_proto);
    }
    else if (c->kind != CK_TEMPLATE)
    {
	/* We've found a connection that can serve.
	 * Do we have to initiate it?
	 * Not if there is currently an IPSEC SA.
	 * But if there is an IPSEC SA, then KLIPS would not
	 * have generated the acquire.  So we assume that there isn't one.
	 * This may be redundant if a non-opportunistic
	 * negotiation is already being attempted.
	 */

	/* If we are to proceed asynchronously, b->whackfd will be NULL_FD. */

	if(c->kind == CK_INSTANCE)
	{
	    char cib[CONN_INST_BUF];
	    /* there is already an instance being negotiated, do nothing */
	    openswan_log("rekeing existing instance \"%s\"%s, due to acquire"
			 , c->name
			 , (fmt_conn_instance(c, cib), cib));

	    /*
	     * we used to return here, but rekeying is a better choice. If we
	     * got the acquire, it is because something turned stuff into a
	     * %trap, or something got deleted, perhaps due to an expiry.
	     */
	}

	/* otherwise, there is some kind of static conn that can handle
	 * this connection, so we initiate it */

#ifdef KLIPS
	if (b->held)
	{
	    /* what should we do on failure? */
	    (void) assign_hold(c, sr, b->transport_proto, &b->our_client, &b->peer_client);
	}
#endif

	if(!loggedit) { openswan_log("%s", demandbuf); loggedit=TRUE; }
	ipsecdoi_initiate(b->whackfd, c, c->policy, 1
			  , SOS_NOBODY, pcim_local_crypto);
	b->whackfd = NULL_FD;	/* protect from close */
    }
    else
    {
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
	char cib[CONN_INST_BUF];

	DBG(DBG_CONTROL, DBG_log("creating new instance from \"%s\"%s"
				 , c->name
				 , (fmt_conn_instance(c, cib), cib)));

	idtoa(&sr->this.id, mycredentialstr, sizeof(mycredentialstr));

	passert(c->policy & POLICY_OPPO);   /* can't initiate Road Warrior connections */

	/* handle any DNS answer; select next step */

	switch (b->step)
	{
	case fos_start:
	    /* just starting out: select first query step */
	    next_step = fos_myid_ip_txt;
	    break;

	case fos_myid_ip_txt:	/* TXT for our default IP address as %myid */
	    ugh = check_txt_recs(MYID_IP, c, ac);
	    if (ugh != NULL)
	    {
		/* cannot use our IP as OE identitiy for initiation */
		DBG(DBG_OPPO, DBG_log("can not use our IP (%s:TXT) as identity: %s"
				      , myid_str[MYID_IP]
				      , ugh));
		if (!logged_myid_ip_txt_warning)
		{
		    loglog(RC_LOG_SERIOUS
			   , "can not use our IP (%s:TXT) as identity: %s"
			   , myid_str[MYID_IP]
			   , ugh);
		    logged_myid_ip_txt_warning = TRUE;
		}

		next_step = fos_myid_hostname_txt;
		ugh = NULL;	/* failure can be recovered from */
	    }
	    else
	    {
		/* we can use our IP as OE identity for initiation */
		if (!logged_myid_ip_txt_warning)
		{
		    loglog(RC_LOG_SERIOUS
			   , "using our IP (%s:TXT) as identity!"
			   , myid_str[MYID_IP]);
		    logged_myid_ip_txt_warning = TRUE;
		}

		next_step = fos_our_client;
	    }
	    break;

	case fos_myid_hostname_txt:	/* TXT for our hostname as %myid */
	    ugh = check_txt_recs(MYID_HOSTNAME, c, ac);
	    if (ugh != NULL)
	    {
		/* cannot use our hostname as OE identitiy for initiation */
		DBG(DBG_OPPO, DBG_log("can not use our hostname (%s:TXT) as identity: %s"
				      , myid_str[MYID_HOSTNAME]
				      , ugh));
		if (!logged_myid_fqdn_txt_warning)
		{
		    loglog(RC_LOG_SERIOUS
			   , "can not use our hostname (%s:TXT) as identity: %s"
			   , myid_str[MYID_HOSTNAME]
			   , ugh);
		    logged_myid_fqdn_txt_warning = TRUE;
		}
#ifdef USE_KEYRR
		next_step = fos_myid_ip_key;
		ugh = NULL;	/* failure can be recovered from */
#endif
	    }
	    else
	    {
		/* we can use our hostname as OE identity for initiation */
		if (!logged_myid_fqdn_txt_warning)
		{
		    loglog(RC_LOG_SERIOUS
			   , "using our hostname (%s:TXT) as identity!"
			   , myid_str[MYID_HOSTNAME]);
		    logged_myid_fqdn_txt_warning = TRUE;
		}
		next_step = fos_our_client;
	    }
	    break;

#ifdef USE_KEYRR
	case fos_myid_ip_key:	/* KEY for our default IP address as %myid */
	    ugh = check_key_recs(MYID_IP, c, ac);
	    if (ugh != NULL)
	    {
		/* cannot use our IP as OE identitiy for initiation */
		DBG(DBG_OPPO, DBG_log("can not use our IP (%s:KEY) as identity: %s"
				      , myid_str[MYID_IP]
				      , ugh));
		if (!logged_myid_ip_key_warning)
		{
		    loglog(RC_LOG_SERIOUS
			   , "can not use our IP (%s:KEY) as identity: %s"
			   , myid_str[MYID_IP]
			   , ugh);
		    logged_myid_ip_key_warning = TRUE;
		}

		next_step = fos_myid_hostname_key;
		ugh = NULL;	/* failure can be recovered from */
	    }
	    else
	    {
		/* we can use our IP as OE identity for initiation */
		if (!logged_myid_ip_key_warning)
		{
		    loglog(RC_LOG_SERIOUS
			   , "using our IP (%s:KEY) as identity!"
			   , myid_str[MYID_IP]);
		    logged_myid_ip_key_warning = TRUE;
		}
		next_step = fos_our_client;
	    }
	    break;

	case fos_myid_hostname_key:	/* KEY for our hostname as %myid */
	    ugh = check_key_recs(MYID_HOSTNAME, c, ac);
	    if (ugh != NULL)
	    {
		/* cannot use our IP as OE identitiy for initiation */
		DBG(DBG_OPPO, DBG_log("can not use our hostname (%s:KEY) as identity: %s"
				      , myid_str[MYID_HOSTNAME]
				      , ugh));
		if (!logged_myid_fqdn_key_warning)
		{
		    loglog(RC_LOG_SERIOUS
			   , "can not use our hostname (%s:KEY) as identity: %s"
			   , myid_str[MYID_HOSTNAME]
			   , ugh);
		    logged_myid_fqdn_key_warning = TRUE;
		}

		next_step = fos_myid_hostname_key;
		ugh = NULL;	/* failure can be recovered from */
	    }
	    else
	    {
		/* we can use our IP as OE identity for initiation */
		if (!logged_myid_fqdn_key_warning)
		{
		    loglog(RC_LOG_SERIOUS
			   , "using our hostname (%s:KEY) as identity!"
			   , myid_str[MYID_HOSTNAME]);
		    logged_myid_fqdn_key_warning = TRUE;
		}
		next_step = fos_our_client;
	    }
	    break;
#endif

	case fos_our_client:	/* TXT for our client */
	    {
		/* Our client is not us: we must check the TXT records.
		 * Note: if c is different this time, there is
		 * a chance that we did the wrong query.
		 * If so, treat as a kind of failure.
		 */
		const struct RSA_private_key *our_RSA_pri = get_RSA_private_key(c);

		next_step = fos_his_client;	/* normal situation */

		passert(sr != NULL);

		if (our_RSA_pri == NULL)
		{
		    ugh = "we don't know our own RSA key";
		}
		else if (sameaddr(&sr->this.host_addr, &b->our_client))
		{
		    /* this wasn't true when we started -- bail */
		    ugh = "our IP address changed underfoot";
		}
		else if (!same_id(&ac->sgw_id, &sr->this.id))
		{
		    /* this wasn't true when we started -- bail */
		    ugh = "our ID changed underfoot";
		}
		else
		{
		    /* Similar to code in quick_inI1_outR1_tail
		     * for checking the other side.
		     */
		    struct gw_info *gwp;

		    ugh = "no TXT RR for our client delegates us";
		    for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
		    {
			passert(same_id(&gwp->gw_id, &sr->this.id));

			ugh = "TXT RR for our client has wrong key";
			/* If there is a key from the TXT record,
			 * we count it as a win if we match the key.
			 * If there was no key, we have a tentative win:
			 * we need to check our KEY record to be sure.
			 */
			if (!gwp->gw_key_present)
			{
			    /* Success, but the TXT had no key
			     * so we must check our our own KEY records.
			     */
			    next_step = fos_our_txt;
			    ugh = NULL;	/* good! */
			    break;
			}
			if (same_RSA_public_key(&our_RSA_pri->pub, &gwp->key->u.rsa))
			{
			    ugh = NULL;	/* good! */
			    break;
			}
		    }
		}
	    }
	    break;

	case fos_our_txt:	/* TXT for us */
	    {
		/* Check if TXT lookup yielded good results.
		 * Looking up based on our ID.  Used if
		 * client is ourself, or if TXT had no public key.
		 * Note: if c is different this time, there is
		 * a chance that we did the wrong query.
		 * If so, treat as a kind of failure.
		 */
		const struct RSA_private_key *our_RSA_pri = get_RSA_private_key(c);

		next_step = fos_his_client;	/* unless we decide to look for KEY RR */

		if (our_RSA_pri == NULL)
		{
		    ugh = "we don't know our own RSA key";
		}
		else if (!same_id(&ac->id, &c->spd.this.id))
		{
		    ugh = "our ID changed underfoot";
		}
		else
		{
		    /* Similar to code in RSA_check_signature
		     * for checking the other side.
		     */
		    struct gw_info *gwp;

		    ugh = "no TXT RR for us";
		    for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
		    {
			passert(same_id(&gwp->gw_id, &sr->this.id));

			ugh = "TXT RR for us has wrong key";
			if (gwp->gw_key_present
			&& same_RSA_public_key(&our_RSA_pri->pub, &gwp->key->u.rsa))
			{
			    DBG(DBG_CONTROL,
				DBG_log("initiate on demand found TXT with right public key at: %s"
					, mycredentialstr));
			    ugh = NULL;
			    break;
			}
		    }
#ifdef USE_KEYRR
		    if (ugh != NULL)
		    {
			/* if no TXT with right key, try KEY */
			DBG(DBG_CONTROL,
			    DBG_log("will try for KEY RR since initiate on demand found %s: %s"
				    , ugh, mycredentialstr));
			next_step = fos_our_key;
			ugh = NULL;
		    }
#endif
		}
	    }
	    break;

#ifdef USE_KEYRR
	case fos_our_key:	/* KEY for us */
	    {
		/* Check if KEY lookup yielded good results.
		 * Looking up based on our ID.  Used if
		 * client is ourself, or if TXT had no public key.
		 * Note: if c is different this time, there is
		 * a chance that we did the wrong query.
		 * If so, treat as a kind of failure.
		 */
		const struct RSA_private_key *our_RSA_pri = get_RSA_private_key(c);

		next_step = fos_his_client;	/* always */

		if (our_RSA_pri == NULL)
		{
		    ugh = "we don't know our own RSA key";
		}
		else if (!same_id(&ac->id, &c->spd.this.id))
		{
		    ugh = "our ID changed underfoot";
		}
		else
		{
		    /* Similar to code in RSA_check_signature
		     * for checking the other side.
		     */
		    struct pubkey_list *kr;

		    ugh = "no KEY RR found for us (and no good TXT RR)";
		    for (kr = ac->keys_from_dns; kr != NULL; kr = kr->next)
		    {
			ugh = "all our KEY RRs have the wrong public key (and no good TXT RR)";
			if (kr->key->alg == PUBKEY_ALG_RSA
			&& same_RSA_public_key(&our_RSA_pri->pub, &kr->key->u.rsa))
			{
			    /* do this only once a day */
			    if (!logged_txt_warning)
			    {
				loglog(RC_LOG_SERIOUS
				       , "found KEY RR but not TXT RR for %s."
				       , mycredentialstr);
				logged_txt_warning = TRUE;
			    }
			    ugh = NULL;	/* good! */
			    break;
			}
		    }
		}
	    }
	    break;
#endif /* USE_KEYRR */

	case fos_his_client:	/* TXT for his client */
	    {
		/* We've finished last DNS queries: TXT for his client.
		 * Using the information, try to instantiate a connection
		 * and start negotiating.
		 * We now know the peer.  The chosing of "c" ignored this,
		 * so we will disregard its current value.
		 * !!! We need to randomize the entry in gw that we choose.
		 */
		next_step = fos_done;	/* no more queries */

		c = build_outgoing_opportunistic_connection(ac->gateways_from_dns
							    , &b->our_client
							    , &b->peer_client);

		if (c == NULL)
		{
		    /* We cannot seem to instantiate a suitable connection:
		     * complain clearly.
		     */
		    char ocb[ADDRTOT_BUF]
			, pcb[ADDRTOT_BUF]
			, pb[ADDRTOT_BUF];

		    addrtot(&b->our_client, 0, ocb, sizeof(ocb));
		    addrtot(&b->peer_client, 0, pcb, sizeof(pcb));
		    passert(id_is_ipaddr(&ac->gateways_from_dns->gw_id));
		    addrtot(&ac->gateways_from_dns->gw_id.ip_addr, 0, pb, sizeof(pb));
		    loglog(RC_OPPOFAILURE
			, "no suitable connection for opportunism"
			  " between %s and %s with %s as peer"
			, ocb, pcb, pb);

#ifdef KLIPS
		    if (b->held)
		    {
			/* Replace HOLD with PASS.
			 * The type of replacement *ought* to be
			 * specified by policy.
			 */
			(void) replace_bare_shunt(&b->our_client, &b->peer_client
			    , BOTTOM_PRIO
			    , SPI_PASS	/* fail into PASS */
			    , TRUE, b->transport_proto
			    , "no suitable connection");
		    }
#endif
		}
		else
		{
		    /* If we are to proceed asynchronously, b->whackfd will be NULL_FD. */
		    passert(c->kind == CK_INSTANCE);
		    passert(c->gw_info != NULL);
		    passert(HAS_IPSEC_POLICY(c->policy));
		    passert(LHAS(LELEM(RT_UNROUTED) | LELEM(RT_ROUTED_PROSPECTIVE), c->spd.routing));
#ifdef KLIPS
		    if (b->held)
		    {
			/* what should we do on failure? */
			(void) assign_hold(c, &c->spd
					   , b->transport_proto
					   , &b->our_client, &b->peer_client);
		    }
#endif
		    c->gw_info->key->last_tried_time = now();
		    DBG(DBG_OPPO|DBG_CONTROL,
			DBG_log("initiate on demand from %s:%d to %s:%d proto=%d state: %s because: %s"
				, ours, ourport, his, hisport, b->transport_proto
				, oppo_step_name[b->step], b->want));

		    ipsecdoi_initiate(b->whackfd, c, c->policy, 1
				      , SOS_NOBODY, pcim_local_crypto);
		    b->whackfd = NULL_FD;	/* protect from close */
		}
	    }
	    break;

	default:
	    bad_case(b->step);
	}

	/* the second chunk: initiate the next DNS query (if any) */
	DBG(DBG_CONTROL,
	{
	    char ours2[ADDRTOT_BUF];
	    char his2[ADDRTOT_BUF];

	    addrtot(&b->our_client, 0, ours2, sizeof(ours));
	    addrtot(&b->peer_client, 0, his2, sizeof(his));
	    DBG_log("initiate on demand from %s to %s new state: %s with ugh: %s"
		    , ours2, his2, oppo_step_name[b->step], ugh ? ugh : "ok");
	});

	if (ugh != NULL)
	{
	    b->policy_prio = c->prio;
	    b->failure_shunt = shunt_policy_spi(c, FALSE);
	    cannot_oppo(c, b, ugh);
	}
	else if (next_step == fos_done)
	{
	    /* nothing to do */
	}
	else
	{
	    /* set up the next query */
	    struct find_oppo_continuation *cr = alloc_thing(struct find_oppo_continuation
		, "opportunistic continuation");
	    struct id id;

	    b->policy_prio = c->prio;
	    b->failure_shunt = shunt_policy_spi(c, FALSE);
	    cr->b = *b;	/* copy; start hand off of whackfd */
	    cr->b.failure_ok = FALSE;
	    cr->b.step = next_step;

	    for (sr = &c->spd
	    ; sr!=NULL && !sameaddr(&sr->this.host_addr, &b->our_client)
	    ; sr = sr->next)
		;

	    if (sr == NULL)
		sr = &c->spd;

	    /* If a %hold shunt has replaced the eroute for this template,
	     * record this fact.
	     */
	    if (b->held
	    && sr->routing == RT_ROUTED_PROSPECTIVE && eclipsable(sr))
	    {
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
	    switch (next_step)
	    {
	    case fos_myid_ip_txt:
		if (c->spd.this.id.kind == ID_MYID
		&& myid_state != MYID_SPECIFIED)
		{
		    cr->b.failure_ok = TRUE;
		    cr->b.want = b->want = "TXT record for IP address as %myid";
		    ugh = start_adns_query(&myids[MYID_IP]
			, &myids[MYID_IP]
			, ns_t_txt
			, continue_oppo
			, &cr->ac);
		    break;
		}
		cr->b.step = fos_myid_hostname_txt;
		/* fall through */

	    case fos_myid_hostname_txt:
		if (c->spd.this.id.kind == ID_MYID
		&& myid_state != MYID_SPECIFIED)
		{
#ifdef USE_KEYRR
		    cr->b.failure_ok = TRUE;
#else
		    cr->b.failure_ok = FALSE;
#endif
		    cr->b.want = b->want = "TXT record for hostname as %myid";
		    ugh = start_adns_query(&myids[MYID_HOSTNAME]
			, &myids[MYID_HOSTNAME]
			, ns_t_txt
			, continue_oppo
			, &cr->ac);
		    break;
		}

#ifdef USE_KEYRR
		cr->b.step = fos_myid_ip_key;
		/* fall through */

	    case fos_myid_ip_key:
		if (c->spd.this.id.kind == ID_MYID
		&& myid_state != MYID_SPECIFIED)
		{
		    cr->b.failure_ok = TRUE;
		    cr->b.want = b->want = "KEY record for IP address as %myid (no good TXT)";
		    ugh = start_adns_query(&myids[MYID_IP]
			, (const struct id *) NULL	/* security gateway meaningless */
			, ns_t_key
			, continue_oppo
			, &cr->ac);
		    break;
		}
		cr->b.step = fos_myid_hostname_key;
		/* fall through */

	    case fos_myid_hostname_key:
		if (c->spd.this.id.kind == ID_MYID
		&& myid_state != MYID_SPECIFIED)
		{
		    cr->b.failure_ok = FALSE;		/* last attempt! */
		    cr->b.want = b->want = "KEY record for hostname as %myid (no good TXT)";
		    ugh = start_adns_query(&myids[MYID_HOSTNAME]
			, (const struct id *) NULL	/* security gateway meaningless */
			, ns_t_key
			, continue_oppo
			, &cr->ac);
		    break;
		}
#endif
		cr->b.step = fos_our_client;
		/* fall through */

	    case fos_our_client:	/* TXT for our client */
		if (!sameaddr(&c->spd.this.host_addr, &b->our_client))
		{
		    /* Check that at least one TXT(reverse(b->our_client)) is workable.
		     * Note: {unshare|free}_id_content not needed for id: ephemeral.
		     */
		    cr->b.want = b->want = "our client's TXT record";
		    iptoid(&b->our_client, &id);
		    ugh = start_adns_query(&id
			, &c->spd.this.id	/* we are the security gateway */
			, ns_t_txt
			, continue_oppo
			, &cr->ac);
		    break;
		}
		cr->b.step = fos_our_txt;
		/* fall through */

	    case fos_our_txt:	/* TXT for us */
		cr->b.failure_ok = b->failure_ok = TRUE;
		cr->b.want = b->want = "our TXT record";
		ugh = start_adns_query(&sr->this.id
		    , &sr->this.id	/* we are the security gateway XXX - maybe ignore? mcr */
		    , ns_t_txt
		    , continue_oppo
		    , &cr->ac);
		break;

#ifdef USE_KEYRR
	    case fos_our_key:	/* KEY for us */
		cr->b.want = b->want = "our KEY record";
		cr->b.failure_ok = b->failure_ok = FALSE;
		ugh = start_adns_query(&sr->this.id
		    , (const struct id *) NULL	/* security gateway meaningless */
		    , ns_t_key
		    , continue_oppo
		    , &cr->ac);
		break;
#endif /* USE_KEYRR */

	    case fos_his_client:	/* TXT for his client */
		/* note: {unshare|free}_id_content not needed for id: ephemeral */
		cr->b.want = b->want = "target's TXT record";
		cr->b.failure_ok = b->failure_ok = FALSE;
		iptoid(&b->peer_client, &id);
		ugh = start_adns_query(&id
		    , (const struct id *) NULL	/* security gateway unconstrained */
		    , ns_t_txt
		    , continue_oppo
		    , &cr->ac);
		break;

	    default:
		bad_case(next_step);
	    }

	    if (ugh == NULL)
		b->whackfd = NULL_FD;	/* complete hand-off */
	    else
		cannot_oppo(c, b, ugh);
	}
    }
    close_any(b->whackfd);
}

static int
terminate_a_connection(struct connection *c, void *arg UNUSED)
{
    set_cur_connection(c);
    openswan_log("terminating SAs using this connection");
    c->policy &= ~POLICY_UP;
    flush_pending_by_connection(c);
    delete_states_by_connection(c, FALSE);
    reset_cur_connection();

    return 1;
}
    

void
terminate_connection(const char *nm)
{
    /* Loop because more than one may match (master and instances)
     * But at least one is required (enforced by con_by_name).
     */
    struct connection *c, *n;
    int count;

    c = con_by_name(nm, TRUE);

    if(c) {
	for (; c != NULL; c = n)
	{
	    n = c->ac_next;	/* grab this before c might disappear */
	    if (streq(c->name, nm)
		&& c->kind >= CK_PERMANENT
		&& !NEVER_NEGOTIATE(c->policy))
	    {
		terminate_a_connection(c, NULL);
	    }
	}
	return;
    } 

    loglog(RC_COMMENT, "terminating all conns with alias='%s'\n", nm);
    count = foreach_connection_by_alias(nm, terminate_a_connection, NULL);

    if(count == 0) {
	whack_log(RC_UNKNOWN_NAME
		  , "no connection named \"%s\"", nm);
    }
}

/* check nexthop safety
 * Our nexthop must not be within a routed client subnet, and vice versa.
 * Note: we don't think this is true.  We think that KLIPS will
 * not process a packet output by an eroute.
 */
#ifdef NEVER
//bool
//check_nexthop(const struct connection *c)
//{
//    struct connection *d;
//
//    if (addrinsubnet(&c->spd.this.host_nexthop, &c->spd.that.client))
//    {
//	loglog(RC_LOG_SERIOUS, "cannot perform routing for connection \"%s\""
//	    " because nexthop is within peer's client network",
//	    c->name);
//	return FALSE;
//    }
//
//    for (d = connections; d != NULL; d = d->next)
//    {
//	if (d->routing != RT_UNROUTED)
//	{
//	    if (addrinsubnet(&c->spd.this.host_nexthop, &d->spd.that.client))
//	    {
//		loglog(RC_LOG_SERIOUS, "cannot do routing for connection \"%s\"
//		    " because nexthop is contained in"
//		    " existing routing for connection \"%s\"",
//		    c->name, d->name);
//		return FALSE;
//	    }
//	    if (addrinsubnet(&d->spd.this.host_nexthop, &c->spd.that.client))
//	    {
//		loglog(RC_LOG_SERIOUS, "cannot do routing for connection \"%s\"
//		    " because it contains nexthop of"
//		    " existing routing for connection \"%s\"",
//		    c->name, d->name);
//		return FALSE;
//	    }
//	}
//    }
//    return TRUE;
//}
#endif /* NEVER */

/* an ISAKMP SA has been established.
 * Note the serial number, and release any connections with
 * the same peer ID but different peer IP address.
 */
bool uniqueIDs = FALSE;	/* --uniqueids? */

void
ISAKMP_SA_established(struct connection *c, so_serial_t serial)
{
    c->newest_isakmp_sa = serial;

    if (uniqueIDs
#ifdef XAUTH
	 && (!c->spd.this.xauth_server)
#endif
	)
{
	/* 
	 * for all connections: if the same Phase 1 IDs are used
	 * for different IP addresses, unorient that connection.
	 * We also check ports, since different Phase 1 ID's can
	 * exist for the same IP when NAT is involved
	 */
	struct connection *d;

	for (d = connections; d != NULL; )
	{
	    struct connection *next = d->ac_next;	/* might move underneath us */

	    if (d->kind >= CK_PERMANENT
	    && same_id(&c->spd.this.id, &d->spd.this.id)
	    && same_id(&c->spd.that.id, &d->spd.that.id)
	    && (!sameaddr(&c->spd.that.host_addr, &d->spd.that.host_addr)
		|| (c->spd.that.host_port != d->spd.that.host_port))
#ifdef DYNAMICDNS
	    && !(c->dnshostname && d->dnshostname && (strcmp(c->dnshostname, d->dnshostname) == 0))
#endif /* DYNAMICDNS */            
	       )

	    {
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
struct connection *
shunt_owner(const ip_subnet *ours, const ip_subnet *his)
{
    struct connection *c;
    struct spd_route *sr;

    for (c = connections; c != NULL; c = c->ac_next)
    {
	for (sr = &c->spd; sr; sr = sr->next)
	{
	    if (shunt_erouted(sr->routing)
	    && samesubnet(ours, &sr->this.client)
	    && samesubnet(his, &sr->that.client))
		return c;
	}
    }
    return NULL;
}

#define PENDING_PHASE2_INTERVAL (60*2) /*time between scans of pending phase2*/

/*
 * call me periodically to check to see if pending phase2s ever got
 * unstuck, and if not, perform DPD action.
 */
void connection_check_phase2(void)
{
    struct connection *c, *cnext;
    
    /* reschedule */
    event_schedule(EVENT_PENDING_PHASE2, PENDING_PHASE2_INTERVAL, NULL);

    for (c = connections; c!=NULL; c = cnext) {
	cnext = c->ac_next;

	if(NEVER_NEGOTIATE(c->policy)) {
	    DBG(DBG_CONTROL,
		DBG_log("pending review: connection \"%s\" has no negotiated policy, skipped", c->name));
	    continue;
	}

	if(!(c->policy & POLICY_UP)) {
	    DBG(DBG_CONTROL,
		DBG_log("pending review: connection \"%s\" was not up, skipped", c->name));
	    continue;
	}

	DBG(DBG_CONTROL,
	    DBG_log("pending review: connection \"%s\" checked", c->name));
	
	if(pending_check_timeout(c)) {
	    struct state *p1st;
	    enum connection_kind kind;
	    openswan_log("pending Quick Mode with %s \"%s\" took too long -- replacing phase 1" 
			 , ip_str(&c->spd.that.host_addr)
			 , c->name);

	    kind = c->kind;

	    p1st = find_phase1_state(c, ISAKMP_SA_ESTABLISHED_STATES|PHASE1_INITIATOR_STATES);

	    if(p1st) {
		/* arrange to rekey the phase 1, if there was one. */
#ifdef DYNAMICDNS
	    if (c->dnshostname != NULL)
		restart_connections_by_peer(c);
	    else 
	    {
#endif /* DYNAMICDNS */
		delete_event(p1st);
		event_schedule(EVENT_SA_REPLACE, 0, p1st);
#ifdef DYNAMICDNS
           }
#endif /* DYNAMICDNS */

	    } else {
		/* start a new connection. Something wanted it up */
		struct initiate_stuff is;

		is.whackfd   = NULL_FD;
		is.moredebug = 0;
		is.importance= pcim_local_crypto;
		
		initiate_a_connection(c, &is);
	    }
	}
    }
}

void init_connections(void)
{
    event_schedule(EVENT_PENDING_PHASE2, PENDING_PHASE2_INTERVAL, NULL);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
