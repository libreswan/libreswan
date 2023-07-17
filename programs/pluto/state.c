/* routines for state objects, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001, 2013-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009, 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012 Bram <bram-bcrafjna-erqzvar@spam.wizbit.be>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2015-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2015-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Richard Guy Briggs <rgb@tricolour.ca>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2021 Paul Wouters <paul.wouters@aiven.io>
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

#include "constants.h"
#include "defs.h"
#ifdef USE_PAM_AUTH
#include "pam_auth.h"		/* for pam_auth_cancel() */
#endif
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "state_db.h"
#include "ikev1_msgid.h"
#include "log.h"
#include "rnd.h"
#include "demux.h"	/* needs packet.h */
#include "pending.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "crypt_symkey.h"
#include "ikev2.h"
#include "secrets.h"    	/* for pubkey_delref() */
#include "enum_names.h"
#include "crypt_dh.h"
#include "host_pair.h"
#include "kernel.h"
#include "kernel_xfrm_interface.h"
#include "iface.h"
#include "ikev1_send.h"		/* for free_v1_messages() */
#include "ikev2_send.h"		/* for free_v2_messages() */
#include "pluto_stats.h"
#include "ip_info.h"
#include "revival.h"
#include "ikev1.h"		/* for send_v1_delete() */
#include "ikev2_delete.h"	/* for record_v2_delete() */
#include "orient.h"
#include "ikev2_proposals.h"		/* for free_ikev2_proposal() */
#include "ikev2_eap.h"			/* for free_eap_state() */
#include "lswfips.h"			/* for libreswan_fipsmode() */
#include "show.h"
#include "ikev1_replace.h"
#include "ikev2_replace.h"
#include "routing.h"

bool uniqueIDs = false;

/*
 * default global NFLOG group - 0 means no logging
 * Note: variable is only used to display in ipsec status
 * actual work is done outside pluto, by ipsec --checknflog
 */
uint16_t pluto_nflog_group = 0;

#ifdef XFRM_LIFETIME_DEFAULT
/*
 * Note: variable is only used to display in ipsec status
 * actual work is done outside pluto, by ipsec _stackmanager
 */
uint16_t pluto_xfrmlifetime = 30;
#endif

/*
 * Handle for each and every state.
 *
 * XXX: The array finite_states[] is something of a hack until it is
 * figured out if the array or separate objects for each state is
 * better.
 */

static struct finite_state state_undefined = {
	.kind = STATE_UNDEFINED,
	.name = "STATE_UNDEFINED",
	.short_name = "UNDEFINED",
	.story = "not defined - either very new or dead (internal)",
	.category = CAT_IGNORE,
};

#ifdef USE_IKEv1
static struct finite_state state_ikev1_roof = {
	.kind = STATE_IKEv1_ROOF,
	.name = "STATE_IKEv1_ROOF",
	.short_name = "IKEv1_ROOF",
	.story = "invalid state - IKEv1 roof",
	.category = CAT_IGNORE,
};
#endif

static struct finite_state state_ikev2_roof = {
	.kind = STATE_IKEv2_ROOF,
	.name = "STATE_IKEv2_ROOF",
	.short_name = "IKEv2_ROOF",
	.story = "invalid state - IKEv2 roof",
	.category = CAT_IGNORE,
};

const struct finite_state *finite_states[STATE_IKE_ROOF] = {
	[STATE_UNDEFINED] = &state_undefined,
#ifdef USE_IKEv1
	[STATE_IKEv1_ROOF] = &state_ikev1_roof,
#endif
	[STATE_IKEv2_ROOF] = &state_ikev2_roof,
};

void lswlog_finite_state(struct jambuf *buf, const struct finite_state *fs)
{
	if (fs == NULL) {
		jam_string(buf, "NULL-FINITE_STATE");
	} else {
		jam(buf, "%s:", fs->short_name);
		jam(buf, " category: ");
		jam_enum_short(buf, &state_category_names, fs->category);
		switch (fs->ike_version) {
		case IKEv1:
			/* no enum_name available? */
			jam(buf, "; v1.flags: "PRI_LSET, fs->v1.flags);
			break;
		case IKEv2:
			jam(buf, "; v2.secured: %s", bool_str(fs->v2.secured));
			break;
		}
	}
}

/* state categories */

static const char *const cat_name[] = {
	[CAT_UNKNOWN] = "unknown",
	[CAT_HALF_OPEN_IKE_SA] = "half-open IKE SA",
	[CAT_OPEN_IKE_SA] = "open IKE SA",
	[CAT_ESTABLISHED_IKE_SA] = "established IKE SA",
	[CAT_ESTABLISHED_CHILD_SA] = "established CHILD SA",
	[CAT_INFORMATIONAL] = "informational",
	[CAT_IGNORE] = "ignore",
};

enum_names state_category_names = {
	0, elemsof(cat_name) - 1,
	ARRAY_REF(cat_name),
	"",
	NULL
};

/*
 * Track the categories and for ESTABLISHED, also track if the SA was
 * AUTHENTICATED or ANONYMOUS.  Among other things used for DDoS
 * tracking.
 *
 * Hack: CAT_T is unsigned (like values it gets compared against), and
 * assumed to be implemented using 2's complement.  However, the value
 * is printed as a "signed" value - so that should underflow occur it
 * is displayed as -ve (rather than a huge positive).
 */

typedef unsigned long cat_t;
#define PRI_CAT "%ld"

static cat_t cat_count[elemsof(cat_name)] = { 0 };

/* see .st_ikev2_anon, enum would be better */
#define CAT_AUTHENTICATED false
#define CAT_ANONYMOUS true
static cat_t cat_count_ike_sa[2];
static cat_t cat_count_child_sa[2];
static cat_t state_count[STATE_IKE_ROOF];

static cat_t total_ike_sa(void)
{
	return (cat_count[CAT_HALF_OPEN_IKE_SA] +
		cat_count[CAT_OPEN_IKE_SA] +
		cat_count[CAT_ESTABLISHED_IKE_SA]);
}

static cat_t total_sa(void)
{
	return total_ike_sa() + cat_count[CAT_ESTABLISHED_CHILD_SA];
}

/*
 * Count everything except STATE_UNDEFINED (CAT_IGNORE) et.al. All
 * states start and end in those states.
 */
static void update_state_stat(struct state *st,
			      const struct finite_state *state,
			      int delta)
{
	if (state->category != CAT_IGNORE) {
		state_count[state->kind] += delta;
		cat_count[state->category] += delta;
		/*
		 * When deleting, st->st_connection can be NULL, so we
		 * cannot look at the policy to determine
		 * anonymity. We therefore use a scratchpad at
		 * st->st_ikev2_anon (a bool) which is copied from
		 * parent to child states
		 */
		switch (state->category) {
		case CAT_ESTABLISHED_IKE_SA:
			cat_count_ike_sa[st->st_ikev2_anon] += delta;
			break;
		case CAT_ESTABLISHED_CHILD_SA:
			cat_count_child_sa[st->st_ikev2_anon] += delta;
			break;
		default: /* ignore */
			break;
		}
	}
}

static void update_state_stats(struct state *st,
			       const struct finite_state *old_state,
			       const struct finite_state *new_state)
{
	/* catch / log unexpected cases */
	pexpect(old_state->category != CAT_UNKNOWN);
	pexpect(new_state->category != CAT_UNKNOWN);

	update_state_stat(st, old_state, -1);
	update_state_stat(st, new_state, +1);

	/*
	 * ??? this seems expensive: on each state change we do this
	 * whole rigamarole.
	 *
	 * XXX: It's an assertion check only executed when debugging.
	 */
	if (DBGP(DBG_BASE)) {
		DBG_log("%s state #%lu: %s(%s) => %s(%s)",
			IS_IKE_SA(st) ? "parent" : "child", st->st_serialno,
			old_state->short_name,
			enum_name(&state_category_names, old_state->category),
			new_state->short_name,
			enum_name(&state_category_names, new_state->category));

		cat_t category_states = 0;
		for (unsigned cat = 0; cat < elemsof(cat_count); cat++) {
			category_states += cat_count[cat];
		}

		cat_t count_states = 0;
		for (unsigned s = 0; s < elemsof(state_count); s++) {
			count_states += state_count[s];
		}

		if (category_states != count_states) {
			/* not really ST's fault? */
			llog_pexpect(st->st_logger, HERE,
				     "category states: "PRI_CAT" != count states: "PRI_CAT,
				     category_states, count_states);
		}

		if (cat_count[CAT_ESTABLISHED_IKE_SA] !=
		    (cat_count_ike_sa[CAT_AUTHENTICATED] + cat_count_ike_sa[CAT_ANONYMOUS])) {
			/* not really ST's fault? */
			llog_pexpect(st->st_logger, HERE,
				     "established IKE SA: "PRI_CAT" != authenticated: "PRI_CAT" + anoynmous: "PRI_CAT,
				     cat_count[CAT_ESTABLISHED_IKE_SA],
				     cat_count_ike_sa[CAT_AUTHENTICATED],
				     cat_count_ike_sa[CAT_ANONYMOUS]);
		}

		if (cat_count[CAT_ESTABLISHED_CHILD_SA] !=
		    (cat_count_child_sa[CAT_AUTHENTICATED] + cat_count_child_sa[CAT_ANONYMOUS])) {
			/* not really ST's fault? */
			llog_pexpect(st->st_logger, HERE,
				     "established CHILD SA: "PRI_CAT" != authenticated: "PRI_CAT" + anoynmous: "PRI_CAT,
				     cat_count[CAT_ESTABLISHED_CHILD_SA],
				     cat_count_child_sa[CAT_AUTHENTICATED],
				     cat_count_child_sa[CAT_ANONYMOUS]);
		}
	}
}

/*
 * This file has the functions that handle the
 * state hash table and the Message ID list.
 */

static void change_state(struct state *st, enum state_kind new_state_kind)
{
	const struct finite_state *old_state = st->st_state;
	const struct finite_state *new_state = finite_states[new_state_kind];
	passert(new_state != NULL);
	if (new_state != old_state) {
		update_state_stats(st, old_state, new_state);
		binlog_state(st, new_state_kind /* XXX */);
		st->st_state = new_state;
	}
}

void change_v1_state(struct state *st, enum state_kind new_state_kind)
{
	change_state(st, new_state_kind);
}

void change_v2_state(struct state *st)
{
	if (pexpect(st->st_v2_transition != NULL)) {
		st->st_v2_last_transition = st->st_v2_transition;
		change_state(st, st->st_v2_transition->next_state);
#if 0
		/*
		 * Breaks IKE_AUTH where IKE SA changes state twice:
		 * mid transition when authentication is established;
		 * and at the end by success_v2_state_transition()).
		 */
		 st->st_v2_transition = NULL;
#endif
	}
}

static size_t jam_readable_humber(struct jambuf *buf, uint64_t num, bool kilos)
{
	uint64_t to_print = num;
	const char *suffix;

	if (!kilos && num < 1024) {
		suffix = "B";
	} else {
		if (!kilos)
			to_print /= 1024;

		if (to_print < 1024) {
			suffix = "KB";
		} else {
			to_print /= 1024;
			suffix = "MB";
		}
	}

	return jam(buf, "%" PRIu64 "%s", to_print, suffix + kilos);
}

/*
 * Get the IKE SA managing the security association.
 */

struct ike_sa *ike_sa(struct state *st, where_t where)
{
	if (st != NULL && IS_CHILD_SA(st)) {
		struct state *pst = state_by_serialno(st->st_clonedfrom);
		if (pst == NULL) {
			llog_pexpect(st->st_logger, where,
				     "child state missing parent state "PRI_SO,
				     pri_so(st->st_clonedfrom));
			/* about to crash with an NPE? */
			return NULL;
		}
		return (struct ike_sa*) pst;
	}
	return (struct ike_sa*) st;
}

struct ike_sa *pexpect_ike_sa_where(struct state *st, where_t where)
{
	if (st == NULL) {
		return NULL;
	}
	if (!IS_IKE_SA(st)) {
		llog_pexpect(st->st_logger, where,
			     "state #%lu is not an IKE SA", st->st_serialno);
		return NULL; /* kaboom */
	}
	return (struct ike_sa*) st;
}

struct child_sa *pexpect_child_sa_where(struct state *st, where_t where)
{
	if (st == NULL) {
		return NULL;
	}
	if (!IS_CHILD_SA(st)) {
		/* In IKEv2 a re-keying IKE SA starts life as a child */
		llog_pexpect(st->st_logger, where,
			     "state #%lu is not a CHILD", st->st_serialno);
		return NULL; /* kaboom */
	}
	return (struct child_sa*) st;
}

/*
 * Get a state object.
 *
 * Caller must schedule an event for this object so that it doesn't
 * leak.  Caller must add_state_to_db().
 */

static struct state *new_state(struct connection *c,
			       const ike_spi_t ike_initiator_spi,
			       const ike_spi_t ike_responder_spi,
			       enum sa_type sa_type,
			       enum sa_role sa_role,
			       struct fd *whackfd,
			       where_t where)
{
	union sas {
		struct child_sa child;
		struct ike_sa ike;
		struct state st;
	};
	union sas *sap = alloc_thing(union sas, "struct state");
	passert(&sap->st == &sap->child.sa);
	passert(&sap->st == &sap->ike.sa);
	struct state *st = &sap->st;

	/* Create the logger ASAP; needs real ST */
	st->st_logger = alloc_logger(st, &logger_state_vec,
				     c->logger->debugging, whackfd,
				     where);

	/* Determine the serialno.  */
	static so_serial_t state_serialno;
	state_serialno++;
	passert(state_serialno > 0); /* can't overflow */
	st->st_serialno = state_serialno;

	/* needed by jam_state_connection_serialno() */
	st->st_connection = c;
	state_db_init_state(st); /* hash called below */

	st->st_state = &state_undefined;
	st->st_inception = realnow();
	st->st_sa_role = sa_role;
	st->st_sa_type_when_established = sa_type;
	st->st_ike_spis.initiator = ike_initiator_spi;
	st->st_ike_spis.responder = ike_responder_spi;
	st->st_ah.protocol = &ip_protocol_ah;
	st->st_esp.protocol = &ip_protocol_esp;
	st->st_ipcomp.protocol = &ip_protocol_ipcomp;
	st->hidden_variables.st_nat_oa = ipv4_info.address.unspec;
	st->hidden_variables.st_natd = ipv4_info.address.unspec;

	dbg("creating state object #%lu at %p", st->st_serialno, (void *) st);

	state_db_add(st);
	pstat_sa_started(st, sa_type);

	return st;
}

struct ike_sa *new_v1_istate(struct connection *c, struct fd *whackfd)
{
	struct state *st = new_state(c, ike_initiator_spi(), zero_ike_spi,
				     IKE_SA, SA_INITIATOR, whackfd, HERE);
	struct ike_sa *ike = pexpect_ike_sa(st);
	return ike;
}

struct ike_sa *new_v1_rstate(struct connection *c, struct msg_digest *md)
{
	struct state *st = new_state(c, md->hdr.isa_ike_spis.initiator,
				     ike_responder_spi(&md->sender, md->md_logger),
				     IKE_SA, SA_RESPONDER, null_fd, HERE);
	struct ike_sa *ike = pexpect_ike_sa(st);
	update_ike_endpoints(ike, md);
	return ike;
}

struct ike_sa *new_v2_ike_sa(struct connection *c,
			     const struct v2_state_transition *transition,
			     enum sa_role sa_role,
			     const ike_spi_t ike_initiator_spi,
			     const ike_spi_t ike_responder_spi,
			     lset_t policy,
			     struct fd *whack_sock)
{
	struct state *st = new_state(c, ike_initiator_spi, ike_responder_spi,
				     IKE_SA, sa_role, whack_sock, HERE);
	struct ike_sa *ike = pexpect_ike_sa(st);
	change_state(&ike->sa, transition->state);
	set_v2_transition(&ike->sa, transition, HERE);
	v2_msgid_init_ike(ike);
	initialize_new_state(&ike->sa, policy);
	event_schedule(EVENT_SA_DISCARD, EXCHANGE_TIMEOUT_DELAY, &ike->sa);
	return ike;
}

/*
 * Initialize the state table.
 */
void init_states(void)
{
	/* did IKEv1/IKEv2 do their job? */
	for (unsigned kind = 0; kind < elemsof(finite_states); kind++) {
		const struct finite_state *s = finite_states[kind];
		passert(s != NULL);
		passert(s->name != NULL);
		passert(s->short_name != NULL);
		passert(s->story != NULL);
		passert(s->kind == kind);
		passert(s->category != CAT_UNKNOWN);
	}
}

static void send_delete(struct ike_sa *ike)
{
	switch (ike->sa.st_ike_version) {
#ifdef USE_IKEv1
	case IKEv1:
		/*
		 * Tell the other side of any IPSEC
		 * SAs that are going down
		 */
		send_v1_delete(&ike->sa);
		return;
#endif
	case IKEv2:
		/*
		 *
		 * ??? in IKEv2, we should not immediately delete: we
		 * should use an Informational Exchange to coordinate
		 * deletion.
		 *
		 * XXX: It's worse ....
		 *
		 * should_send_delete() can return
		 * true when ST is a Child SA.  But
		 * the below sends out a delete for
		 * the IKE SA.
		 */
		record_n_send_v2_delete(ike, HERE);
		return;
	}
	bad_case(ike->sa.st_ike_version);
}

void delete_state_by_id_name(struct state *st, const char *name)
{
	struct connection *c = st->st_connection;

	if (!IS_PARENT_SA(st)) {
		return;
	}
	struct ike_sa *ike = pexpect_ike_sa(st); /* per above */

	id_buf thatidb;
	const char *thatidbuf = str_id(&c->remote->host.id, &thatidb);
	if (streq(thatidbuf, name)) {
		if (IS_PARENT_SA_ESTABLISHED(&ike->sa)) {
			send_delete(ike);
		}
		ike->sa.st_on_delete.skip_send_delete = true;
		delete_ike_family(&ike);
	}
}

void delete_v1_state_by_username(struct state *st, const char *name)
{
	/* only support deleting ikev1 with XAUTH username */
	if (!IS_ISAKMP_SA(st)) {
		return;
	}
	struct ike_sa *ike = pexpect_ike_sa(st); /* per above */

	if (!streq(ike->sa.st_xauth_username, name)) {
		return;
	}

	if (IS_PARENT_SA_ESTABLISHED(&ike->sa)) {
		send_v1_delete(&ike->sa);
	}
	ike->sa.st_on_delete.skip_send_delete = true;
	delete_ike_family(&ike);
	/* note: no md->v1_st to clear */
}

/*
 * Re-insert the state in the database after updating the RCOOKIE, and
 * possibly the ICOOKIE.
 *
 * ICOOKIE is only updated if icookie != NULL
 */
void rehash_state(struct state *st, const ike_spi_t *ike_responder_spi)
{
	/* update the responder's SPI */
	st->st_ike_spis.responder = *ike_responder_spi;
	/* now, update the state */
	rehash_state_cookies_in_db(st);
	/* just logs change */
	binlog_refresh_state(st);
}

void v2_expire_unused_ike_sa(struct ike_sa *ike)
{
	passert(ike != NULL);
	passert(ike->sa.st_ike_version == IKEv2);

	if (!IS_IKE_SA_ESTABLISHED(&ike->sa)) {
		dbg("can't expire unused IKE SA #%lu; not established - strange",
		    ike->sa.st_serialno);
		return; /* only deal with established parent SA */
	}

	/* Any children? */
	struct state *st = state_by_ike_spis(IKEv2,
					     &ike->sa.st_serialno,
					     NULL /* ignore v1 msgid */,
					     NULL /* ignore role */,
					     &ike->sa.st_ike_spis,
					     NULL, NULL /* no predicate */,
					     __func__);
	if (st != NULL) {
		dbg("can't expire unused IKE SA #%lu; it has the child #%lu",
		    ike->sa.st_serialno, st->st_serialno);
		return;
	}

	connection_buf cib;
	struct connection *c = ike->sa.st_connection;
	llog_sa(RC_INFORMATIONAL, ike, "expire unused IKE SA #%lu "PRI_CONNECTION,
		  ike->sa.st_serialno,
		  pri_connection(c, &cib));
	event_force(EVENT_SA_EXPIRE, &ike->sa);
}


/*
 * XXX: This is broken on IKEv2.  It schedules a replace event for
 * each child except that fires _after_ the IKE SA has been deleted.
 * Should it schedule pending events?
 */

static bool flush_incomplete_child(struct state *cst, void *pst)
{
	struct child_sa *child = pexpect_child_sa(cst);

	if (!IS_IPSEC_SA_ESTABLISHED(&child->sa)) {

		struct ike_sa *ike = pexpect_ike_sa(pst);
		struct connection *c = child->sa.st_connection;

		/*
		 * If it wasn't so rudely interrupted, what would the
		 * CHILD SA have eventually replaced?
		 */
		so_serial_t replacing_sa;
		switch (child->sa.st_sa_type_when_established) {
		case IKE_SA: replacing_sa = c->newest_ike_sa; break;
		case IPSEC_SA: replacing_sa = c->newest_ipsec_sa; break;
		default: bad_case(child->sa.st_sa_type_when_established);
		}

		if (child->sa.st_serialno > replacing_sa &&
		    (c->policy & POLICY_UP) &&
		    c->config->rekey) {

			/*
			 * Nothing else has managed to replace
			 * REPLACING_SA and the connection needs to
			 * say up.
			 */
			llog_sa(RC_LOG_SERIOUS, child,
				"reschedule pending %s - the %s #%lu is going away",
				c->config->ike_info->child_sa_name,
				c->config->ike_info->ike_sa_name,
				ike->sa.st_serialno);
			child->sa.st_policy = c->policy; /* for pick_initiator */
			event_force(c->config->ike_info->replace_event, &child->sa);

		} else {

			/*
			 * Either something else replaced
			 * REPLACING_SA, or the connection shouldn't
			 * stay up.
			 */
			llog_sa(RC_LOG_SERIOUS, child,
				"expire pending %s - the %s #%lu is going away",
				c->config->ike_info->child_sa_name,
				c->config->ike_info->ike_sa_name,
				ike->sa.st_serialno);
			event_force(EVENT_SA_EXPIRE, &child->sa);

		}
		/*
		 * Shut down further logging for the child, above are
		 * the last whack will hear from them.
		 */
		release_whack(child->sa.st_logger, HERE);
	}
	/*
	 * XXX: why was this non-conditional?  probably doesn't matter
	 * as it is idenpotent?
	 */
	delete_cryptographic_continuation(&child->sa);
	return false; /* keep going */
}

static void flush_incomplete_children(struct ike_sa *ike)
{
	state_by_ike_spis(ike->sa.st_ike_version, /* match: IKE VERSION */
			  &ike->sa.st_serialno /* match: parent is IKE SA */,
			  NULL /* ignore MSGID */,
			  NULL /* ignore role */,
			  &ike->sa.st_ike_spis /* match: IKE SPIs */,
			  flush_incomplete_child, ike/*arg*/,
			  __func__);
}

static bool should_send_delete(const struct state *st)
{
	if (st->st_on_delete.skip_send_delete) {
		ldbg(st->st_logger,
		     "%s: "PRI_SO"? NO, because .st_on_delete.skip_send_delete",
		     __func__, pri_so(st->st_serialno));
		return false;
	}

#if 0
	/*
	 * Not yet!
	 *
	 * linux-audit-01-ok-ikev2, for instance, barfs because "ipsec
	 * whack --delete" is expecting delete_state() to send the
	 * delete message.
	 */
	pexpect(st->st_ike_version == IKEv1);
#endif
	switch (st->st_ike_version) {
#ifdef USE_IKEv1
	case IKEv1:
		if (!IS_V1_ISAKMP_SA_ESTABLISHED(st) &&
		    !IS_IPSEC_SA_ESTABLISHED(st)) {
			ldbg(st->st_logger,
			     "%s: "PRI_SO"? no, IKEv1 SA in state %s is not established",
			     __func__, pri_so(st->st_serialno), st->st_state->short_name);
			return false;
		}
		if (find_phase1_state(st->st_connection, V1_ISAKMP_SA_ESTABLISHED_STATES) == NULL) {
			/*
			 * PW: But this is valid for IKEv1, where it
			 * would need to start a new IKE SA to send
			 * the delete notification ???
			 */
			ldbg(st->st_logger,
			     "%s: "PRI_SO"? no, IKEv1 SA in state %s has no ISAKMP (Phase 1) SA",
			     __func__, st->st_serialno, st->st_state->name);
			return false;
		}
		ldbg(st->st_logger, "%s: "PRI_SO"? yes, IKEv1 and no reason not to",
		     __func__, pri_so(st->st_serialno));
		return true;
#endif
	case IKEv2:
		if (IS_CHILD_SA(st)) {
			/*
			 * Without an IKE SA sending the notify isn't
			 * possible.
			 *
			 * ??? in v2, there must be a parent
			 *
			 * XXX:
			 *
			 * Except when delete_state(ike), instead of
			 * delete_ike_family(ike), is called ...
			 *
			 * There's also the idea of having Child SAs
			 * linger while the IKE SA is trying to
			 * re-establish.  Or should that code only use
			 * information in the connection?
			 *
			 * Anyway, play it safe.
			 */
			ldbg(st->st_logger,
			     "%s: "PRI_SO"? no, IKEv2 Child SAs never send delete",
			     __func__, pri_so(st->st_serialno));
			return false;
		}
		if (!IS_IKE_SA_ESTABLISHED(st)) {
			ldbg(st->st_logger,
			     "%s: "PRI_SO"? no, IKEv2 IKE SA in state %s is not established",
			     __func__, pri_so(st->st_serialno), st->st_state->short_name);
			return false;
		}
		/*
		 * Established Child SA implies it's IKE SA is
		 * established.
		 *
		 * Don't require .st_viable_parent; a rekeyed IKE SA,
		 * which is established but not viable, needs to send
		 * a delete.
		 */
		dbg("%s: "PRI_SO"? yes, IKEv2 IKE SA is established",
		    __func__, pri_so(st->st_serialno));
		return true;
	}
	bad_case(st->st_ike_version);
}

void delete_child_sa(struct child_sa **child)
{
	struct state *st = &(*child)->sa;
	*child = NULL;
	st->st_on_delete.skip_revival = true;
	st->st_on_delete.skip_send_delete = true;
	st->st_on_delete.skip_connection = true;
	st->st_on_delete.skip_kernel_policy = true;
	delete_state(st);
}

void delete_ike_sa(struct ike_sa **ike)
{
	struct state *st = &(*ike)->sa;
	*ike = NULL;
	st->st_on_delete.skip_revival = true;
	st->st_on_delete.skip_send_delete = true;
	st->st_on_delete.skip_connection = true;
	delete_state(st);
}

static void update_and_log_traffic(struct child_sa *child, const char *name,
				   struct ipsec_proto_info *proto,
				   struct pstats_bytes *pstats)
{
	/* pull in the traffic counters into state before they're lost */
	if (!get_ipsec_traffic(child, proto, DIRECTION_OUTBOUND)) {
		llog_sa(RC_LOG, child, "failed to pull traffic counters from outbound IPsec SA");
	}
	if (!get_ipsec_traffic(child, proto, DIRECTION_INBOUND)) {
		llog_sa(RC_LOG, child, "failed to pull traffic counters from inbound IPsec SA");
	}

	LLOG_JAMBUF(RC_INFORMATIONAL, child->sa.st_logger, buf) {
		jam(buf, "%s traffic information:", name);
		/* in */
		jam_string(buf, " in=");
		jam_humber(buf, proto->inbound.bytes);
		jam_string(buf, "B");
		/* out */
		jam_string(buf, " out=");
		jam_humber(buf, proto->outbound.bytes);
		jam_string(buf, "B");
		if (child->sa.st_xauth_username[0] != '\0') {
			jam_string(buf, " XAUTHuser=");
			jam_string(buf, child->sa.st_xauth_username);
		}
	}

	pstats->in += proto->inbound.bytes;
	pstats->out += proto->outbound.bytes;
}

void llog_state_delete_n_send(lset_t rc_flags, struct state *st, bool sending_delete)
{
	LLOG_JAMBUF(rc_flags, st->st_logger, buf) {
		/* deleting {IKE,Child,IPsec,ISAKMP} SA */
		jam_string(buf, "deleting ");
		jam_string(buf, sa_name(st->st_connection->config->ike_version,
					st->st_sa_type_when_established));
		/* (STATE-NAME) XXX: drop this? */
		jam_string(buf, " (");
		jam_string(buf, st->st_state->short_name);
		jam_string(buf, ")");
		/* aged NNNs */
		jam_string(buf, " aged ");
		jam_deltatime(buf, realtimediff(realnow(), st->st_inception));
		jam_string(buf, "s");
		/*
		 * Should this be optional?  For instance IKEv2 child
		 * SAs never send delete but logging that they are
		 * gone can be useful
		 */
		if (sending_delete) {
			jam_string(buf, " and sending notification");
		} else {
			jam_string(buf, " and NOT sending notification");
		}
	}
}

/* delete a state object */
void delete_state(struct state *st)
{
	/*
	 * WHen an IKEv2 IKE SA, there can be no children.
	 */
	if (st->st_connection->config->ike_version == IKEv2 &&
	    IS_IKE_SA(st) &&
	    DBGP(DBG_BASE)) {
		struct state_filter sf = {
			.ike = ike_sa(st, HERE),
			.where = HERE,
		};
		while (next_state_old2new(&sf)) {
			state_buf sb;
#if 0
			llog_passert(st->st_logger, HERE,
				     "unexpected child state "PRI_STATE,
				     pri_state(sf.st, &sb));
#else
			llog(DEBUG_STREAM|ADD_PREFIX, st->st_logger,
			     "unexpected child state "PRI_STATE,
			     pri_state(sf.st, &sb));
#endif
		}
	}

	/*
	 * Where to log?
	 *
	 * IKEv2 children never send send a delete notification so
	 * logging "and NOT sending delete" is redundant.  However,
	 * sometimes IKEv2 children should log that they have been
	 * deleted.  Let the caller decide.
	 */
	lset_t rc_flags;
	if (st->st_ike_version == IKEv2 && IS_CHILD_SA(st)) {
		rc_flags = DBGP(DBG_BASE) ? DEBUG_STREAM : LEMPTY;
	} else if (st->st_on_delete.skip_log_message) {
		rc_flags = DBGP(DBG_BASE) ? DEBUG_STREAM : LEMPTY;
	} else {
		rc_flags = RC_LOG;
	}
	if (rc_flags != LEMPTY) {
		/*
		 * Use should_send_delete() to try and second guess if
		 * a send is needed (the actual decision is made
		 * later).
		 */
		llog_state_delete_n_send(rc_flags, st,
					 should_send_delete(st));
	}
	/* delete logged, don't log again */
	st->st_on_delete.skip_log_message = true;

	pstat_sa_deleted(st);

	/*
	 * Even though code tries to always track CPU time, only log
	 * it when debugging - values range from very approximate to
	 * (in the case of IKEv1) simply wrong.
	 */
	if (DBGP(DBG_CPU_USAGE) || DBGP(DBG_BASE)) {
		DBG_log("#%lu main thread "PRI_CPU_USAGE" helper thread "PRI_CPU_USAGE" in total",
			st->st_serialno,
			pri_cpu_usage(st->st_timing.main_usage),
			pri_cpu_usage(st->st_timing.helper_usage));
	}

	/*
	 * Audit-log failures.  Just assume any state failing to
	 * establish needs reporting.
	 */
	switch (st->st_ike_version) {
	case IKEv1:
#ifdef USE_IKEv1
		if (IS_V1_ISAKMP_SA(st) && !IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
			linux_audit_conn(st, LAK_PARENT_FAIL);
		}
#endif
		break;
	case IKEv2:
		if (IS_IKE_SA(st) && st->st_state->kind < STATE_V2_ESTABLISHED_IKE_SA) {
			linux_audit_conn(st, LAK_PARENT_FAIL);
		}
		if (IS_CHILD_SA(st) && st->st_state->kind < STATE_V2_ESTABLISHED_CHILD_SA) {
			linux_audit_conn(st, LAK_CHILD_FAIL);
		}
		break;
	}

	/*
	 * only log parent state deletes, we log children in
	 * ipsec_delete_sa()
	 */
	if (IS_IKE_SA_ESTABLISHED(st) ||
	    IS_V1_ISAKMP_SA_ESTABLISHED(st) ||
	    st->st_state->kind == STATE_V2_IKE_SA_DELETE)
		linux_audit_conn(st, LAK_PARENT_DESTROY);

	if (IS_IPSEC_SA_ESTABLISHED(st) ||
	    IS_CHILD_SA_ESTABLISHED(st)) {
		/*
		 * Note that a state/SA can have more then one of
		 * ESP/AH/IPCOMP
		 */
		struct child_sa *child = pexpect_child_sa(st);
		if (st->st_esp.present) {
			update_and_log_traffic(child, "ESP", &st->st_esp,
					       &pstats_esp_bytes);
			pstats_ipsec_bytes.in += st->st_esp.inbound.bytes;
			pstats_ipsec_bytes.out += st->st_esp.outbound.bytes;
		}

		if (st->st_ah.present) {
			update_and_log_traffic(child, "AH", &st->st_ah,
					       &pstats_ah_bytes);
			pstats_ipsec_bytes.in += st->st_ah.inbound.bytes;
			pstats_ipsec_bytes.out += st->st_ah.outbound.bytes;
		}

		if (st->st_ipcomp.present) {
			update_and_log_traffic(child, "IPCOMP", &st->st_ipcomp,
					       &pstats_ipcomp_bytes);
			/* XXX: not ipcomp */
		}
	}

#ifdef USE_PAM_AUTH
	if (st->st_pam_auth != NULL) {
		pam_auth_abort(st, "deleting state");
	}
#endif

	/* intermediate */
	free_chunk_content(&st->st_v2_ike_intermediate.initiator);
	free_chunk_content(&st->st_v2_ike_intermediate.responder);

	/* if there is a suspended state transition, disconnect us */
	struct msg_digest *md = unsuspend_any_md(st);
	if (md != NULL) {
		dbg("disconnecting state #%lu from md", st->st_serialno);
		md_delref(&md);
	}

	if (should_send_delete(st)) {
		switch (st->st_ike_version) {
#ifdef USE_IKEv1
		case IKEv1:
			/*
			 * Tell the other side of any IPsec
			 * SAs that are going down
			 */
			send_v1_delete(st);
			break;
#endif
		case IKEv2:
			/*
			 * ??? in IKEv2, we should not immediately delete: we
			 * should use an Informational Exchange to coordinate
			 * deletion.
			 */
			record_n_send_v2_delete(pexpect_ike_sa(st), HERE);
			break;
		}
	}

	/* delete any pending timer event */
	delete_state_event(&st->st_event, HERE);
	delete_state_event(&st->st_retransmit_event, HERE);
	delete_state_event(&st->st_v1_send_xauth_event, HERE);
	delete_state_event(&st->st_v1_dpd_event, HERE);
	delete_state_event(&st->st_v2_liveness_event, HERE);
	delete_state_event(&st->st_v2_addr_change_event, HERE);
	delete_state_event(&st->st_v2_refresh_event, HERE);
	delete_state_event(&st->st_v2_lifetime_event, HERE);
	clear_retransmits(st);

	/*
	 * Ditch anything pending on ISAKMP SA being established.
	 * Note: this must be done before the unhash_state to prevent
	 * flush_pending_by_state inadvertently and prematurely
	 * deleting our connection.
	 */
	if (IS_IKE_SA(st)) {
		flush_pending_by_state(pexpect_ike_sa(st));
	}

	/* flush unestablished child states */
	if (IS_IKE_SA(st)) {
		flush_incomplete_children(pexpect_ike_sa(st));
	}

	/*
	 * if there is anything in the cryptographic queue, then remove this
	 * state from it.
	 */
	delete_cryptographic_continuation(st);

	/*
	 * Tell kernel to uninstall any larval or established IPsecSA,
	 * optionally replacing the kernel policy with a prospective
	 * or failing policy.
	 *
	 * Note that ST could be either for a Child SA or an IKE SA.
	 * For instance, when a state for an on-demand connection
	 * fails during IKE_SA_INIT, it is the IKE SA that is downing
	 * the connection.
	 */

	if (IS_CHILD_SA(st)) {
		if (st->st_on_delete.skip_kernel_policy) {
			ldbg(st->st_logger, "skiping delete kernel policy (only deleting kernel state)");
		} else {
			/* this function just returns when the call is
			 * invalid */
			teardown_ipsec_kernel_policies(CONNECTION_DELETE_CHILD, pexpect_child_sa(st));
		}
		/* this function just returns when the call is
		 * invalid */
		teardown_ipsec_kernel_states(pexpect_child_sa(st));
	}

	if (st->st_connection->newest_ipsec_sa == st->st_serialno)
		st->st_connection->newest_ipsec_sa = SOS_NOBODY;

	if (st->st_connection->newest_ike_sa == st->st_serialno)
		st->st_connection->newest_ike_sa = SOS_NOBODY;

	/*
	 * If policy dictates, try to keep the state's connection
	 * alive.  DONT_REKEY overrides UP.
	 */
	if (st->st_on_delete.skip_revival) {
		ldbg(st->st_logger, "skipping revival (handled earlier)");
	} else if (should_revive(st)) {
		/*
		 * XXX: no clue as to why the state is being deleted
		 * so make something up; caller should have scheduled
		 * revival earlier.
		 */
		schedule_revival(st, "received a Delete/Notify");
	}

	/*
	 * fake a state change here while we are still associated with a
	 * connection.  Without this the state logging (when enabled) cannot
	 * work out what happened.
	 */
	binlog_fake_state(st, STATE_UNDEFINED);

	iface_endpoint_delref(&st->st_interface);

	/*
	 * Release stored IKE fragments. This is a union in st so only
	 * call one!  XXX: should be a union???
	 */
	switch (st->st_ike_version) {
	case IKEv1:
#ifdef USE_IKEv1
		free_v1_message_queues(st);
#endif
		break;
	case IKEv2:
		free_v2_message_queues(st);
		break;
	default:
		bad_case(st->st_ike_version);
	}

	/*
	 * This, effectively,  deletes any ISAKMP SA that this state
	 * represents - lookups for this state no longer work.
	 */
	state_db_del(st);

	/*
	 * Break the STATE->CONNECTION link.  If CONNECTION is an
	 * instance, then it too will be deleted.
	 *
	 * - checks ST's POLICY_UP
	 *
	 *   is the established IKE SA being revived and, hence, the
	 *   connection should not be deleted
	 *
	 * - checks for a another state still using the connection
	 *
	 *   since this state was removed from the CONNECTION -> STATE
	 *   hash table this succeeding means that there must be a
	 *   second state using the connection
	 */
	if (st->st_on_delete.skip_connection) {
		connection_buf cb;
		ldbg(st->st_logger, "skipping connection_delete_unused_instance "PRI_CONNECTION,
		     pri_connection(st->st_connection, &cb));
		st->st_connection = NULL;
	} else {
		connection_delete_unused_instance(&st->st_connection, st,
						  st->st_logger->global_whackfd);
	}

	pexpect(st->st_connection == NULL);

	v2_msgid_free(st);

	change_state(st, STATE_UNDEFINED);

	release_whack(st->st_logger, HERE);

	/* from here on we are just freeing RAM */

#ifdef USE_IKEv1
	ikev1_clear_msgid_list(st);
#endif
	pubkey_delref(&st->st_peer_pubkey);
	md_delref(&st->st_eap_sa_md);
	free_eap_state(&st->st_eap);

	free_ikev2_proposals(&st->st_v2_create_child_sa_proposals);
	free_ikev2_proposal(&st->st_v2_accepted_proposal);

	/* helper may have its own ref */
	dh_local_secret_delref(&st->st_dh_local_secret, HERE);

	/* without st_connection, st isn't complete */
	/* from here on logging is for the wrong state */

	release_certs(&st->st_remote_certs.verified);
	free_public_keys(&st->st_remote_certs.pubkey_db);

	free_generalNames(st->st_v1_requested_ca, true);

	free_chunk_content(&st->st_firstpacket_me);
	free_chunk_content(&st->st_firstpacket_peer);
#ifdef USE_IKEv1
	free_chunk_content(&st->st_v1_tpacket);
	free_chunk_content(&st->st_v1_rpacket);
#endif
	free_chunk_content(&st->st_p1isa);
	free_chunk_content(&st->st_gi);
	free_chunk_content(&st->st_gr);
	free_chunk_content(&st->st_ni);
	free_chunk_content(&st->st_nr);
	free_chunk_content(&st->st_dcookie);
	free_chunk_content(&st->st_v2_id_payload.data);

#    define free_any_nss_symkey(p)  release_symkey(__func__, #p, &(p))
	free_any_nss_symkey(st->st_dh_shared_secret);
	free_any_nss_symkey(st->st_skeyid_nss);
	free_any_nss_symkey(st->st_skey_d_nss);	/* aka st_skeyid_d_nss */
	free_any_nss_symkey(st->st_skey_ai_nss); /* aka st_skeyid_a_nss */
	free_any_nss_symkey(st->st_skey_ar_nss);
	free_any_nss_symkey(st->st_skey_ei_nss); /* aka st_skeyid_e_nss */
	free_any_nss_symkey(st->st_skey_er_nss);
	free_any_nss_symkey(st->st_skey_pi_nss);
	free_any_nss_symkey(st->st_skey_pr_nss);
	free_any_nss_symkey(st->st_enc_key_nss);

	free_any_nss_symkey(st->st_sk_d_no_ppk);
	free_any_nss_symkey(st->st_sk_pi_no_ppk);
	free_any_nss_symkey(st->st_sk_pr_no_ppk);

#   undef free_any_nss_symkey

	free_chunk_content(&st->st_skey_initiator_salt);
	free_chunk_content(&st->st_skey_responder_salt);
	free_chunk_content(&st->st_skey_chunk_SK_pi);
	free_chunk_content(&st->st_skey_chunk_SK_pr);

#define wipe_any_chunk(C)				\
	{						\
		if (C.ptr != NULL) {			\
			memset(C.ptr, 0, C.len);	\
			free_chunk_content(&(C));	\
		}					\
	}
	wipe_any_chunk(st->st_ah.inbound.keymat);
	wipe_any_chunk(st->st_ah.outbound.keymat);
	wipe_any_chunk(st->st_esp.inbound.keymat);
	wipe_any_chunk(st->st_esp.outbound.keymat);
#undef wipe_any_chunk

#   define wipe_any(p, l) { \
		if ((p) != NULL) { \
			memset((p), 0x00, (l)); \
			pfree(p); \
			(p) = NULL; \
		} \
	}
	wipe_any(st->st_xauth_password.ptr, st->st_xauth_password.len);
#   undef wipe_any

	/* st_xauth_username is an array on the state itself, not clone_str()'ed */
	pfreeany(st->st_seen_cfg_dns);
	pfreeany(st->st_seen_cfg_domains);
	pfreeany(st->st_seen_cfg_banner);

	free_chunk_content(&st->st_v1_seen_sec_label);
	free_chunk_content(&st->st_v1_acquired_sec_label);

	free_chunk_content(&st->st_no_ppk_auth);
	free_chunk_content(&st->st_active_redirect_gw);

	free_logger(&st->st_logger, HERE);
	messup(st);
	pfree(st);
}

/*
 * Delete all states that have somehow not ben deleted yet
 * but using interfaces that are going down
 */

void delete_states_dead_interfaces(struct logger *logger)
{
	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *this = sf.st;
		if (this->st_interface &&
		    this->st_interface->ip_dev->ifd_change == IFD_DELETE) {
			char *id_vname = NULL;
			struct connection *c = this->st_connection;
			if (c->xfrmi != NULL && c->xfrmi->name != NULL)
				id_vname = c->xfrmi->name;
			else
				id_vname = this->st_interface->ip_dev->id_rname;
			llog(RC_LOG, logger,
				    "deleting lasting state #%lu on interface (%s) which is shutting down",
				    this->st_serialno, id_vname);
			/* XXX: better? */
			fd_delref(&this->st_logger->global_whackfd);
			this->st_logger->global_whackfd = fd_addref(logger->global_whackfd);
			delete_state(this);
			/* note: no md->v1_st to clear */
		}
	}
}

/*
 * Delete all states that were created for a given connection.
 *
 * In addition to the currently established Child/IKE SAs, this will
 * also clean up larval and dying State.
 */

static void delete_v1_states_by_connection_bottom_up(struct connection *c)
{
	/*
	 * IKEv1 needs children to be deleted before the parent;
	 * otherwise the child has no way to send its delete message.
	 */

 	/*
	 * We take two passes so that we delete any ISAKMP SAs last.
	 * This allows Delete Notifications to be sent.
	 *
	 * XXX: need to go through all states using the connection as,
	 * in addition to .newest_ike_sa there could be larval or
	 * dying states hanging around.
	 */
	for (int pass = 1; pass <= 2; pass++) {
		struct state_filter sf = {
			.connection_serialno = c->serialno,
			.where = HERE,
		};
		while (next_state_new2old(&sf)) {
			struct state *this = sf.st;
			/* on first pass, ignore established ISAKMP SA's */
			if (pass == 1 &&
			    IS_V1_ISAKMP_SA_ESTABLISHED(this)) {
				continue;
			}
			dbg("pass %d: delete "PRI_SO" which has connection",
			    pass, this->st_serialno);
			pexpect(this->st_connection == c);
			state_attach(this, c->logger);
			delete_state(this);
		}
	}
}

static void delete_v2_states_by_connection_top_down(struct connection *c)
{
	/*
	 * Capture anything useful in the connection.
	 *
	 * When *CP is an instance, deleting the last state refering
	 * to *CP will also delete *CP leaving *CP dangling.
	 *
	 * Somewhat conversely, if the code below finds a state
	 * sharing the connection then the connection can't have yet
	 * been deleted.
	 */

	struct ike_sa *ike = ike_sa_by_serialno(c->newest_ike_sa);
	if (ike != NULL) {
		pexpect(ike->sa.st_connection == c);
		state_attach(&ike->sa, ike->sa.st_connection->logger);
		delete_state(&ike->sa);
		ike = NULL;
	}

	/*
	 * Now zap any children.
	 */

	struct state_filter sf = {
		.connection_serialno = c->serialno,
		.where = HERE,
	};
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;
		pexpect(st->st_connection == c);
		state_attach(st, st->st_connection->logger);
		delete_state(st);
	}
}

void delete_states_by_connection(struct connection *c)
{
	connection_buf cb;
	dbg("deleting all states for connection "PRI_CONNECTION,
	    pri_connection(c, &cb));

	/*
	 * Must be careful to avoid circularity, something like:
	 *
	 *   delete_states_by_connection() ->
	 *   delete_v1_states_by_connection() ->
	 *   delete_connection().
	 *
	 * We mark c as going away so it won't get deleted
	 * recursively.
	 */
	PASSERT(c->logger, !c->going_away);

	co_serial_t connection_serialno = c->serialno;

	c->going_away = true;
	switch (c->config->ike_version) {
	case IKEv1:
		delete_v1_states_by_connection_bottom_up(c);
		break;
	case IKEv2:
		delete_v2_states_by_connection_top_down(c);
		break;
	}
	c->going_away = false;

	/* Was (c), an instance, deleted? */
	passert(connection_by_serialno(connection_serialno) != NULL);
	if (is_instance(c)) {
		return;
	}

	if (c->child.routing == RT_ROUTED_TUNNEL) {
		llog_pexpect(c->logger, HERE, "routing should not be ROUTED_TUNNEL (what should it be?)");
	}

	/*
	 * These passerts are not true currently due to
	 * mobike.  Requires some re-implementation. Use
	 * pexpect for now.
	 */
	if (c->child.newest_routing_sa != SOS_NOBODY) {
		llog_pexpect(c->logger, HERE, "kernel_policy_owner for is "PRI_SO", should be 0",
			     pri_so(c->child.newest_routing_sa));
	} else {
		ldbg(c->logger, "kernel_policy_owner is 0");
	}
}

/*
 * Walk through the state table, and delete each state whose phase 1 (IKE)
 * peer is among those given.
 * This function is only called for ipsec whack --crash peer
 */
void delete_states_by_peer(struct show *s, const ip_address *peer)
{
	address_buf peer_buf;
	const char *peerstr = ipstr(peer, &peer_buf);

	whack_log(RC_COMMENT, s, "restarting peer %s", peerstr);

	/* first restart the phase1s */
	for (int ph1 = 0; ph1 < 2; ph1++) {
		struct state_filter sf = { .where = HERE, };
		while (next_state_new2old(&sf)) {
			struct state *st = sf.st;
			const struct connection *c = st->st_connection;
			endpoint_buf b;
			dbg("comparing %s to %s",
			    str_endpoint(&st->st_remote_endpoint, &b),
			    peerstr);

			if (peer != NULL /* ever false? */ &&
			    endpoint_address_eq_address(st->st_remote_endpoint, *peer)) {
				if (ph1 == 0 && IS_IKE_SA(st)) {
					whack_log(RC_COMMENT, s,
						  "peer %s for connection %s crashed; replacing",
						  peerstr,
						  c->name);
					switch (st->st_ike_version) {
#ifdef USE_IKEv1
					case IKEv1:
						ikev1_replace(st);
						break;
#endif
					case IKEv2:
						ikev2_replace(st);
						break;
					}
				} else {
					event_force(c->config->ike_info->replace_event, st);
				}
			}
		}
	}
}

/*
 * IKEv1: Duplicate a Phase 1 state object, to create a Phase 2 object.
 *
 * IKEv2: Duplicate an IKE SA state object, to create either a CHILD
 * SA or IKE SA (rekeying parent) object.
 *
 * Caller must schedule an event for this object so that it doesn't leak.
 * Caller must insert_state().
 */
static struct state *duplicate_state(struct connection *c,
				     struct state *st,
				     enum sa_type sa_type,
				     enum sa_role sa_role,
				     struct fd *whackfd)
{
	struct state *nst;

	if (sa_type == IPSEC_SA) {
		/* record use of the Phase 1 / Parent state */
		st->st_outbound_count++;
		st->st_outbound_time = mononow();
	}

	nst = new_state(c,
			st->st_ike_spis.initiator,
			st->st_ike_spis.responder,
			sa_type, sa_role, whackfd, HERE);

	connection_buf cib;
	dbg("duplicating state object #%lu "PRI_CONNECTION" as #%lu for %s",
	    st->st_serialno, pri_connection(st->st_connection, &cib),
	    nst->st_serialno, sa_type == IPSEC_SA ? "IPSEC SA" : "IKE SA");

	if (sa_type == IPSEC_SA) {
		nst->st_oakley = st->st_oakley;
	}

	nst->quirks = st->quirks;
	nst->hidden_variables = st->hidden_variables;
	nst->st_remote_endpoint = st->st_remote_endpoint;
	endpoint_buf eb;
	dbg("#%lu setting local endpoint to %s from #%ld.st_localport "PRI_WHERE,
	    nst->st_serialno,
	    str_endpoint(&st->st_interface->local_endpoint, &eb),
	    st->st_serialno,pri_where(HERE));
	pexpect(nst->st_interface == NULL);
	nst->st_interface = iface_endpoint_addref(st->st_interface);
	nst->st_clonedfrom = st->st_serialno;
	passert(nst->st_ike_version == st->st_ike_version);
	nst->st_ikev2_anon = st->st_ikev2_anon;
	nst->st_seen_fragmentation_supported = st->st_seen_fragmentation_supported;
	nst->st_v1_seen_fragments = st->st_v1_seen_fragments;
	nst->st_seen_ppk = st->st_seen_ppk;
	nst->st_seen_redirect_sup = st->st_seen_redirect_sup;
	nst->st_sent_redirect = st->st_sent_redirect;
	nst->st_event = NULL;

	/* these were set while we didn't have client state yet */
	/* we should really split the NOTIFY loop in two cleaner ones */
	nst->st_ipcomp.attrs = st->st_ipcomp.attrs;
	nst->st_ipcomp.present = st->st_ipcomp.present;
	nst->st_ipcomp.inbound.spi = st->st_ipcomp.inbound.spi;

	if (sa_type == IPSEC_SA) {
#   define clone_nss_symkey_field(field) nst->field = reference_symkey(__func__, #field, st->field)
		clone_nss_symkey_field(st_skeyid_nss);
		clone_nss_symkey_field(st_skey_d_nss); /* aka st_skeyid_d_nss */
		clone_nss_symkey_field(st_skey_ai_nss); /* aka st_skeyid_a_nss */
		clone_nss_symkey_field(st_skey_ar_nss);
		clone_nss_symkey_field(st_skey_ei_nss); /* aka st_skeyid_e_nss */
		clone_nss_symkey_field(st_skey_er_nss);
		clone_nss_symkey_field(st_skey_pi_nss);
		clone_nss_symkey_field(st_skey_pr_nss);
		clone_nss_symkey_field(st_enc_key_nss);
#   undef clone_nss_symkey_field

		/* v2 duplication of state */
#   define state_clone_chunk(CHUNK) nst->CHUNK = clone_hunk(st->CHUNK, #CHUNK " in duplicate state")
		state_clone_chunk(st_ni);
		state_clone_chunk(st_nr);
#   undef state_clone_chunk
	}

	/*
	 * These are done because we need them in child st when
	 * do_command() uses them to fill in our format string.
	 * Maybe similarly to above for chunks, do this for all
	 * strings on the state?
	 */
	jam_str(nst->st_xauth_username, sizeof(nst->st_xauth_username), st->st_xauth_username);

	nst->st_seen_cfg_dns = clone_str(st->st_seen_cfg_dns, "child st_seen_cfg_dns");
	nst->st_seen_cfg_domains = clone_str(st->st_seen_cfg_domains, "child st_seen_cfg_domains");
	nst->st_seen_cfg_banner = clone_str(st->st_seen_cfg_banner, "child st_seen_cfg_banner");

	/* XXX: scary */
	nst->st_v1_acquired_sec_label = st->st_v1_acquired_sec_label;
	nst->st_v1_seen_sec_label = st->st_v1_seen_sec_label;

	return nst;
}

struct state *ikev1_duplicate_state(struct connection *c,
				    struct state *st,
				    enum sa_role sa_role,
				    struct fd *whackfd)
{
	return duplicate_state(c, st, IPSEC_SA, sa_role, whackfd);
}

struct child_sa *new_v2_child_sa(struct connection *c,
				 struct ike_sa *ike,
				 enum sa_type sa_type,
				 enum sa_role sa_role,
				 enum state_kind kind, /* const struct v2_state_transition *transition */
				 struct fd *whackfd)
{
	/* XXX: transitions should be parameter */
	const struct finite_state *fs = finite_states[kind];
	passert(fs->nr_transitions == 1);
	const struct v2_state_transition *transition = &fs->v2.transitions[0];
	struct state *cst = duplicate_state(c, &ike->sa, sa_type, sa_role, whackfd);
	struct child_sa *child = pexpect_child_sa(cst);
	change_state(&child->sa, transition->state);
	set_v2_transition(&child->sa, transition, HERE);
	binlog_refresh_state(&child->sa);
	return child;
}

#ifdef USE_IKEv1
struct state *find_state_ikev1(const ike_spis_t *ike_spis, msgid_t msgid)
{
	return state_by_ike_spis(IKEv1,
				 NULL /*ignore-clonedfrom*/,
				 &msgid/*check v1 msgid*/,
				 NULL /*ignore-role*/,
				 ike_spis, NULL, NULL, __func__);
}

struct state *find_state_ikev1_init(const ike_spi_t *ike_initiator_spi,
				    msgid_t msgid)
{
	return state_by_ike_initiator_spi(IKEv1,
					  NULL /*ignore-clonedfrom*/,
					  &msgid /*check v1 msgid*/,
					  NULL /*ignore-role*/,
					  ike_initiator_spi, __func__);
}
#endif

/*
 * Find the IKEv2 IKE SA with the specified SPIs.
 */
struct ike_sa *find_v2_ike_sa(const ike_spis_t *ike_spis,
			      enum sa_role local_ike_role)
{
	const so_serial_t sos_nobody = SOS_NOBODY;
	struct state *st = state_by_ike_spis(IKEv2,
					     &sos_nobody/*clonedfrom: IKE SA*/,
					     NULL /*ignore v1 msgid*/,
					     &local_ike_role,
					     ike_spis, NULL, NULL, __func__);
	return pexpect_ike_sa(st);
}

/*
 * Find an IKEv2 IKE SA with a matching SPIi.
 *
 * This is used doring the IKE_SA_INIT exchange where SPIr is either
 * zero (message request) or not-yet-known (message response).
 */
struct ike_sa *find_v2_ike_sa_by_initiator_spi(const ike_spi_t *ike_initiator_spi,
					       enum sa_role local_ike_role)
{
	const so_serial_t sos_nobody = SOS_NOBODY;
	struct state *st = state_by_ike_initiator_spi(IKEv2,
						      &sos_nobody/*clonedfrom: IKE_SA*/,
						      NULL/*ignore v1 msgid*/,
						      &local_ike_role,
						      ike_initiator_spi, __func__);
	return pexpect_ike_sa(st);
}

/*
 * Find an IKEv2 CHILD SA using the protocol and the (from our POV)
 * 'outbound' SPI.
 *
 * The remote end, when identifying a CHILD SA in a Delete or REKEY_SA
 * notification, sends its end's inbound SPI, which from our
 * point-of-view is the outbound SPI aka 'attrs.spi'.
 *
 * From 1.3.3.  Rekeying Child SAs with the CREATE_CHILD_SA Exchange:
 * The SA being rekeyed is identified by the SPI field in the
 * [REKEY_SA] Notify payload; this is the SPI the exchange initiator
 * would expect in inbound ESP or AH packets.
 *
 * From 3.11.  Delete Payload: [the delete payload will] contain the
 * IPsec protocol ID of that protocol (2 for AH, 3 for ESP), and the
 * SPI is the SPI the sending endpoint would expect in inbound ESP or
 * AH packets.
 */

struct v2_spi_filter {
	uint8_t protoid;
	ipsec_spi_t outbound_spi;
	ipsec_spi_t inbound_spi;
	ip_address *dst;
};

static bool v2_spi_predicate(struct state *st, void *context)
{
	struct v2_spi_filter *filter = context;
	bool ret = false;

	struct ipsec_proto_info *pr;
	switch (filter->protoid) {
	case PROTO_IPSEC_AH:
		pr = &st->st_ah;
		break;
	case PROTO_IPSEC_ESP:
		pr = &st->st_esp;
		break;
	default:
		bad_case(filter->protoid);
	}

	if (pr->present) {
		if (pr->outbound.spi == filter->outbound_spi) {
			dbg("v2 CHILD SA #%lu found using their inbound (our outbound) SPI, in %s",
			    st->st_serialno, st->st_state->name);
			ret = true;
			if (filter->dst != NULL) {
				ret = false;
				if (sameaddr(&st->st_connection->remote->host.addr,
					     filter->dst))
					ret = true;
			}
		} else if (filter->inbound_spi > 0 &&
				filter->inbound_spi == pr->inbound.spi) {
			dbg("v2 CHILD SA #%lu found using their our SPI, in %s",
			    st->st_serialno, st->st_state->name);
			ret = true;
			if (filter->dst != NULL) {
				ret = false;
				if (sameaddr(&st->st_connection->local->host.addr,
				    filter->dst))
					ret = true;
			}
		}
#if 0
		/* see function description above */
		if (pr->inbound.spi == filter->outbound_spi) {
			dbg("v2 CHILD SA #%lu found using our inbound (their outbound) !?! SPI, in %s",
			    st->st_serialno,
			    st->st_state->name);
			return true;
		}
#endif
	}
	return ret;
}

struct child_sa *find_v2_child_sa_by_spi(ipsec_spi_t spi, int8_t protoid,
					 ip_address *dst)
{
	struct v2_spi_filter filter = {
		.protoid = protoid,
		.outbound_spi = spi,
		/* fill the same spi, the kernel expire has no direction */
		.inbound_spi = spi,
		.dst = dst,
	};
	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;
		if (v2_spi_predicate(st, &filter))
			break;
	};
	return pexpect_child_sa(sf.st);
}

struct child_sa *find_v2_child_sa_by_outbound_spi(struct ike_sa *ike,
						  uint8_t protoid,
						  ipsec_spi_t outbound_spi)
{
	struct v2_spi_filter filter = {
		.protoid = protoid,
		.outbound_spi = outbound_spi,
	};
	struct state *st = state_by_ike_spis(IKEv2,
					     &ike->sa.st_serialno,
					     NULL /* ignore v1 msgid */,
					     NULL /* ignore-role */,
					     &ike->sa.st_ike_spis,
					     v2_spi_predicate, &filter, __func__);
	return pexpect_child_sa(st);
}

#ifdef USE_IKEv1
struct v1_msgid_filter {
	msgid_t msgid;
};

static bool v1_msgid_predicate(struct state *st, void *context)
{
	struct v1_msgid_filter *filter = context;
	dbg("peer and cookies match on #%lu; msgid=%08" PRIx32 " st_msgid=%08" PRIx32 " st_v1_msgid.phase15=%08" PRIx32,
	    st->st_serialno, filter->msgid,
	    st->st_v1_msgid.id, st->st_v1_msgid.phase15);
	if ((st->st_v1_msgid.phase15 != v1_MAINMODE_MSGID &&
	     filter->msgid == st->st_v1_msgid.phase15) ||
	    filter->msgid == st->st_v1_msgid.id) {
		dbg("p15 state object #%lu found, in %s",
		    st->st_serialno, st->st_state->name);
		return true;
	}
	return false;
}

struct state *find_v1_info_state(const ike_spis_t *ike_spis, msgid_t msgid)
{
	struct v1_msgid_filter filter = {
		.msgid = msgid,
	};
	return state_by_ike_spis(IKEv1,
				 NULL /* ignore-clonedfrom */,
				 NULL /* ignore v1 msgid; see predicate */,
				 NULL /* ignore-role */,
				 ike_spis, v1_msgid_predicate,
				 &filter, __func__);
}
#endif

/*
 * find_phase2_state_to_delete: find an AH or ESP SA to delete
 *
 * We are supposed to be given the other side's SPI.
 * Certain CISCO implementations send our side's SPI instead.
 * We'll accept this, but mark it as bogus.
 */
struct state *find_phase2_state_to_delete(const struct state *p1st,
					  uint8_t protoid,
					  ipsec_spi_t spi,
					  bool *bogus)
{
	const struct connection *p1c = p1st->st_connection;
	struct state *bogusst = NULL;

	*bogus = false;
	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;
		const struct connection *c = st->st_connection;
		if (IS_IPSEC_SA_ESTABLISHED(st) &&
		    p1c->host_pair == c->host_pair &&
		    same_peer_ids(p1c, c, NULL))
		{
			struct ipsec_proto_info *pr =
				protoid == PROTO_IPSEC_AH ?
					&st->st_ah : &st->st_esp;

			if (pr->present) {
				if (pr->outbound.spi == spi) {
					*bogus = false;
					return st;
				}

				if (pr->inbound.spi == spi) {
					*bogus = true;
					bogusst = st;
					/* don't return! */
				}
			}
		}
	}
	return bogusst;
}

/*
 * to initiate a new IPsec SA or to rekey IPsec
 * the IKE SA must be around for while. If IKE rekeying itself no new IPsec SA.
 */
bool ikev2_viable_parent(const struct ike_sa *ike)
{
	/* this check is defined only for an IKEv2 parent */
	if (ike->sa.st_ike_version != IKEv2)
		return true;

	const monotime_t now = mononow();
	const struct state_event *ev = ike->sa.st_v2_lifetime_event;
	deltatime_t lifetime = monotimediff(ev->ev_time, now);

	if (deltatime_cmp(lifetime, >, PARENT_MIN_LIFE_DELAY) &&
	    /* in case st_margin == 0, insist minimum life */
	    deltatime_cmp(lifetime, >, ike->sa.st_replace_margin)) {
		return true;
	}

	deltatime_buf lb, rb;
	llog_sa(RC_LOG_SERIOUS, ike,
		  "no new CREATE_CHILD_SA exchange using #%lu. Parent lifetime %s < st_margin %s",
		  ike->sa.st_serialno,
		  str_deltatime(lifetime, &lb),
		  str_deltatime(ike->sa.st_replace_margin, &rb));

	return false;
}

/*
 * Find newest Phase 1 negotiation state object for suitable for connection c
 */
struct state *find_phase1_state(const struct connection *c, lset_t ok_states)
{
	struct state *best = NULL;

	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;
		if (LHAS(ok_states, st->st_state->kind) &&
		    c->config->ike_version == st->st_ike_version &&
		    c->host_pair == st->st_connection->host_pair &&
		    same_peer_ids(c, st->st_connection, NULL) &&
		    endpoint_address_eq_address(st->st_remote_endpoint, c->remote->host.addr) &&
		    IS_IKE_SA(st) &&
		    (best == NULL || best->st_serialno < st->st_serialno))
		{
			best = st;
		}
	}

	return best;
}

void state_eroute_usage(const ip_selector *ours, const ip_selector *peers,
			unsigned long count, monotime_t nw)
{
	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;
		struct connection *c = st->st_connection;

		/* XXX spd-enum */
		if (IS_IPSEC_SA_ESTABLISHED(st) &&
		    c->child.newest_routing_sa == st->st_serialno &&
		    c->child.routing == RT_ROUTED_TUNNEL &&
		    selector_range_eq_selector_range(c->spd->local->client, *ours) &&
		    selector_range_eq_selector_range(c->spd->remote->client, *peers)) {
			if (st->st_outbound_count != count) {
				st->st_outbound_count = count;
				st->st_outbound_time = nw;
			}
			return;
		}
	}
	if (DBGP(DBG_BASE)) {
		selector_buf ourst;
		selector_buf hist;
		DBG_log("unknown tunnel eroute %s -> %s found in scan",
			str_selector_subnet_port(ours, &ourst),
			str_selector_subnet_port(peers, &hist));
	}
}

void jam_humber_uintmax(struct jambuf *buf,
			const char *prefix, uintmax_t val, const char *suffix)
{
	jam_string(buf, prefix);
	if (/*double-negative*/ !(pexpect(val <= IPSEC_SA_MAX_OPERATIONS))) {
		jam(buf, "%ju", val);
	} else if (val == IPSEC_SA_MAX_OPERATIONS) {
		jam_string(buf, IPSEC_SA_MAX_OPERATIONS_STRING);
	} else {
		jam_humber(buf, val);
	}
	jam_string(buf, suffix);
}

/*
 * Note: st cannot be const because we call get_sa_bundle_info on it
 */

static void show_state(struct show *s, struct state *st, const monotime_t now)
{
	/* what the heck is interesting about a state? */
	SHOW_JAMBUF(RC_COMMENT, s, buf) {

		const struct connection *c = st->st_connection;

		jam(buf, "#%lu: ", st->st_serialno);
		jam_connection(buf, c);
		jam(buf, ":%u", endpoint_hport(st->st_remote_endpoint));
		if (st->st_interface->io->protocol == &ip_protocol_tcp) {
			jam(buf, "(tcp)");
		}
		jam(buf, " %s (%s);", st->st_state->name, st->st_state->story);

		/*
		 * Hunt and peck for events (needs fixing).
		 *
		 * XXX: use two loops as a hack to avoid short term
		 * output churn.  This entire function needs an
		 * update, start listing all events then.
		 */
		const struct state_event *events[] = {
			st->st_event,
			st->st_retransmit_event,
			st->st_v1_send_xauth_event,
			st->st_v2_liveness_event,
			st->st_v2_addr_change_event,
			st->st_v2_refresh_event,
			st->st_v2_lifetime_event,
		};
		/* remove NULLs */
		unsigned nr_events = 0;
		FOR_EACH_ELEMENT(event, events) {
			if (*event != NULL) {
				events[nr_events] = *event;
				nr_events++;
			}
		}
		/* sort */
		state_event_sort(events, nr_events);
		/* and log */
		for (const struct state_event **event = events; event < events+nr_events; event++) {
			jam_string(buf, " ");
			jam_enum_short(buf, &event_type_names, (*event)->ev_type);
			intmax_t delta = deltasecs(monotimediff((*event)->ev_time, now));
			jam(buf, " in %jds;", delta);
		}

		if (c->newest_ike_sa == st->st_serialno ||
		    c->newest_ipsec_sa == st->st_serialno) {
			jam(buf, " newest;");
		}

		/* XXX spd-enum */ /* XXX: huh? */
		if (c->child.newest_routing_sa == st->st_serialno) {
			jam(buf, " eroute owner;");
		}

		if (IS_IPSEC_SA_ESTABLISHED(st)) {
			jam(buf, " %s "PRI_SO";",
			    c->config->ike_info->ike_sa_name,
			    pri_so(st->st_clonedfrom));
		} else if (st->hidden_variables.st_peer_supports_dpd) {
			/* ??? why is printing -1 better than 0? */
			/* XXX: because config uses -1 for disabled? */
			jam(buf, " lastdpd=%jds(seq in:%u out:%u);",
			    (!is_monotime_epoch(st->st_last_dpd) ?
			     deltasecs(monotimediff(now, st->st_last_dpd)) :
			     (intmax_t)-1),
			    st->st_dpd_seqno,
			    st->st_dpd_expectseqno);
		} else if (dpd_active_locally(st->st_connection) && (st->st_ike_version == IKEv2)) {
			/* stats are on parent sa */
			if (IS_CHILD_SA(st)) {
				struct state *pst = state_by_serialno(st->st_clonedfrom);
				if (pst != NULL) {
					jam(buf, " lastlive=%jds;",
					    deltasecs(monotimediff(now, pst->st_v2_msgid_windows.last_recv)));
				}
			}
		} else if (st->st_ike_version == IKEv1) {
			jam(buf, " nodpd;");
		}

		if (st->st_offloaded_task != NULL &&
		    !st->st_offloaded_task_in_background) {
			jam(buf, " crypto_calculating;");
		} else if (st->st_suspended_md != NULL) {
			jam(buf, " crypto/dns-lookup;");
		} else {
			jam(buf, " idle;");
		}
	}
}

static void show_established_child_details(struct show *s, struct child_sa *child,
					   const monotime_t now)
{
	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		const struct connection *c = child->sa.st_connection;

		jam_so(buf, child->sa.st_serialno);
		jam_string(buf, ": ");
		jam_connection(buf, c);

		/*
		 * XXX - mcr last used is really an attribute of
		 * the connection
		 */
		if (c->child.newest_routing_sa == child->sa.st_serialno &&
		    child->sa.st_outbound_count != 0) {
			jam(buf, " used %jds ago;",
			    deltasecs(monotimediff(now , child->sa.st_outbound_time)));
		}

#define add_said(ADDRESS, PROTOCOL, SPI)				\
		{							\
			ip_said s = said_from_address_protocol_spi(ADDRESS, \
								   PROTOCOL, \
								   SPI); \
			jam(buf, " ");					\
			jam_said(buf, &s);				\
		}

		/* SAIDs */

		if (child->sa.st_ah.present) {
			add_said(c->remote->host.addr,
				 &ip_protocol_ah,
				 child->sa.st_ah.outbound.spi);
			add_said(c->local->host.addr,
				 &ip_protocol_ah,
				 child->sa.st_ah.inbound.spi);
		}
		if (child->sa.st_esp.present) {
			add_said(c->remote->host.addr,
				 &ip_protocol_esp,
				 child->sa.st_esp.outbound.spi);
			add_said(c->local->host.addr,
				 &ip_protocol_esp,
				 child->sa.st_esp.inbound.spi);
		}
		if (child->sa.st_ipcomp.present) {
			add_said(c->remote->host.addr,
				 &ip_protocol_ipcomp,
				 child->sa.st_ipcomp.outbound.spi);
			add_said(c->local->host.addr,
				 &ip_protocol_ipcomp,
				 child->sa.st_ipcomp.inbound.spi);
		}
#if defined(KERNEL_XFRM)
		if (child->sa.st_ah.attrs.mode == ENCAPSULATION_MODE_TUNNEL ||
		    child->sa.st_esp.attrs.mode == ENCAPSULATION_MODE_TUNNEL ||
		    child->sa.st_ipcomp.attrs.mode == ENCAPSULATION_MODE_TUNNEL) {
			add_said(c->remote->host.addr,
				 &ip_protocol_ipip,
				 (ipsec_spi_t)0);
			add_said(c->local->host.addr,
				 &ip_protocol_ipip,
				 (ipsec_spi_t)0);
		}
#endif
#       undef add_said

		jam(buf, " Traffic:");

		/*
		 * this code is counter-intuitive because counts only
		 * appear in the first SA in a bundle.  So we ascribe
		 * flow in the first SA to all of the SAs in a bundle.
		 *
		 * This leads to incorrect IPCOMP counts since the
		 * number of bytes changes with compression.
		 */

		struct ipsec_proto_info *first_proto_info =
			(child->sa.st_ah.present ? &child->sa.st_ah :
			 child->sa.st_esp.present ? &child->sa.st_esp :
			 child->sa.st_ipcomp.present ? &child->sa.st_ipcomp :
			 NULL);

		bool in_info = get_ipsec_traffic(child, first_proto_info, DIRECTION_INBOUND);
		bool out_info = get_ipsec_traffic(child, first_proto_info, DIRECTION_OUTBOUND);

		if (child->sa.st_ah.present) {
			if (in_info) {
				jam(buf, " AHin=");
				jam_readable_humber(buf, first_proto_info->inbound.bytes, false);
			}
			if (out_info) {
				jam(buf, " AHout=");
				jam_readable_humber(buf, first_proto_info->outbound.bytes, false);
			}
			jam_humber_uintmax(buf, " AHmax=", c->config->sa_ipsec_max_bytes, "B");
		}
		if (child->sa.st_esp.present) {
			if (in_info) {
				jam(buf, " ESPin=");
				jam_readable_humber(buf, first_proto_info->inbound.bytes, false);
			}
			if (out_info) {
				jam(buf, " ESPout=");
				jam_readable_humber(buf, first_proto_info->outbound.bytes, false);
			}
			jam_humber_uintmax(buf, " ESPmax=", c->config->sa_ipsec_max_bytes, "B");
		}
		if (child->sa.st_ipcomp.present) {
			if (in_info) {
				jam(buf, " IPCOMPin=");
				jam_readable_humber(buf, first_proto_info->inbound.bytes, false);
			}
			if (out_info) {
				jam(buf, " IPCOMPout=");
				jam_readable_humber(buf, first_proto_info->outbound.bytes, false);
			}
			jam_humber_uintmax(buf, " IPCOMPmax=", c->config->sa_ipsec_max_bytes, "B");
		}

		jam(buf, " "); /* TBD: trailing blank */
		if (child->sa.st_xauth_username[0] != '\0') {
			jam(buf, "username=%s", child->sa.st_xauth_username);
		}
	}
}

/*
 * sorting logic is:
 *
 *  name
 *  type
 *  instance#
 *  isakmp_sa (XXX probably wrong)
 *  state serial no#
 */

static int state_compare(const struct state *sl,
			 const struct state *sr)
{
	struct connection *cl = sl->st_connection;
	struct connection *cr = sr->st_connection;

	/* DBG_log("comparing %s to %s", ca->name, cb->name); */

	int order = connection_compare(cl, cr);
	if (order != 0) {
		return order;
	}

	const so_serial_t sol = sl->st_serialno;
	const so_serial_t sor = sr->st_serialno;

	/* sol - sor */
	return (sol < sor ? -1 :
		sol > sor ? 1 :
		0);
}

static int state_cmp(const void *l, const void *r)
{
	const struct state *sl = *(const struct state *const *)l;
	const struct state *sr = *(const struct state *const *)r;
	return state_compare(sl, sr);
}

/*
 * NULL terminated array of state pointers.
 *
 * Returns NULL (rather than an array containing one NULL) when there
 * are no states.
 *
 * Caller is responsible for freeing the structure.
 */

static struct state **sort_states(where_t where)
{
	/* COUNT the number of states. */
	int count = 0;
	{
		struct state_filter sf = { .where = where, };
		while (next_state_new2old(&sf)) {
			count++;
		}
	}

	if (count == 0) {
		return NULL;
	}

	/*
	 * Create an array of COUNT+1 (NULL terminal) state pointers.
	 */
	struct state **array = alloc_things(struct state *, count + 1, "sorted state");
	{
		int p = 0;

		struct state_filter sf = { .where = where, };
		while (next_state_new2old(&sf)) {
			struct state *st = sf.st;
			passert(st != NULL);
			array[p++] = st;
		}
		passert(p == count);
		array[p] = NULL;
	}

	/* sort it! */
	qsort(array, count, sizeof(struct state *), state_cmp);

	return array;
}

void show_brief_status(struct show *s)
{
	show_separator(s);
	show_comment(s, "State Information: DDoS cookies %s, %s new IKE connections",
		     require_ddos_cookies() ? "REQUIRED" : "not required",
		     drop_new_exchanges() ? "NOT ACCEPTING" : "Accepting");

	show_comment(s, "IKE SAs: total("PRI_CAT"), half-open("PRI_CAT"), open("PRI_CAT"), authenticated("PRI_CAT"), anonymous("PRI_CAT")",
		  total_ike_sa(),
		  cat_count[CAT_HALF_OPEN_IKE_SA],
		  cat_count[CAT_OPEN_IKE_SA],
		  cat_count_ike_sa[CAT_AUTHENTICATED],
		  cat_count_ike_sa[CAT_ANONYMOUS]);
	show_comment(s, "IPsec SAs: total("PRI_CAT"), authenticated("PRI_CAT"), anonymous("PRI_CAT")",
		  cat_count[CAT_ESTABLISHED_CHILD_SA],
		  cat_count_child_sa[CAT_AUTHENTICATED],
		  cat_count_child_sa[CAT_ANONYMOUS]);
}

void show_states(struct show *s, const monotime_t now)
{
	show_separator(s);
	struct state **array = sort_states(HERE);

	if (array != NULL) {
		/* now print sorted results */
		int i;
		for (i = 0; array[i] != NULL; i++) {
			struct state *st = array[i];
			show_state(s, st, now);
			if (IS_IPSEC_SA_ESTABLISHED(st)) {
				/* print out SPIs if SAs are established */
				show_established_child_details(s, pexpect_child_sa(st), now);
			}  else if (IS_IKE_SA(st)) {
				/* show any associated pending Phase 2s */
				show_pending_child_details(s, st->st_connection,
							   pexpect_ike_sa(st));
			}

		}
		pfree(array);
	}
}

/*
 * Given that we've used up a range of unused CPI's,
 * search for a new range of currently unused ones.
 * Note: this is very expensive when not trivial!
 * If we can't find one easily, choose 0 (a bad SPI,
 * no matter what order) indicating failure.
 */
void find_my_cpi_gap(cpi_t *latest_cpi, cpi_t *first_busy_cpi)
{
	int tries = 0;
	cpi_t base = *latest_cpi;
	cpi_t closest;

startover:
	closest = ~0;   /* not close at all */
	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;
		if (st->st_ipcomp.present) {
			cpi_t c = ntohl(st->st_ipcomp.inbound.spi) - base;

			if (c < closest) {
				if (c == 0) {
					/*
					 * oops: next spot is
					 * occupied; start over
					 */
					if (++tries == 20) {
						/* FAILURE */
						*latest_cpi = 0;
						*first_busy_cpi = 0;
						return;
					}
					base++;
					if (base > IPCOMP_LAST_NEGOTIATED)
						base = IPCOMP_FIRST_NEGOTIATED;

					/* really a tail call */
					goto startover;
				}
				closest = c;
			}
		}
	}
	*latest_cpi = base;	/* base is first in next free range */
	*first_busy_cpi = closest + base;	/* and this is the roof */
}

/*
 * Muck with high-order 16 bits of this SPI in order to make
 * the corresponding SAID unique.
 * Its low-order 16 bits hold a well-known IPCOMP CPI.
 * Oh, and remember that SPIs are stored in network order.
 * Kludge!!!  So I name it with the non-English word "uniquify".
 * If we can't find one easily, return 0 (a bad SPI,
 * no matter what order) indicating failure.
 *
 * v1-only.
 * cpi is in network order.
 */
ipsec_spi_t uniquify_peer_cpi(ipsec_spi_t cpi, const struct state *st, int tries)
{
	/* cpi is in network order so first two bytes are the high order ones */
	get_rnd_bytes((uint8_t *)&cpi, 2);

	/*
	 * Make sure that the result is unique.
	 * Hard work.  If there is no unique value, we'll loop forever!
	 */
	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *s = sf.st;
		if (s->st_ipcomp.present &&
		    sameaddr(&s->st_connection->remote->host.addr,
			     &st->st_connection->remote->host.addr) &&
		    cpi == s->st_ipcomp.outbound.spi)
		{
			if (++tries == 20)
				return 0; /* FAILURE */
			return uniquify_peer_cpi(cpi, st, tries);
		}
	}
	return cpi;
}

void merge_quirks(struct state *st, const struct msg_digest *md)
{
	struct isakmp_quirks *dq = &st->quirks;
	const struct isakmp_quirks *sq = &md->quirks;

	dq->xauth_ack_msgid   |= sq->xauth_ack_msgid;
	dq->modecfg_pull_mode |= sq->modecfg_pull_mode;
	/* ??? st->quirks.qnat_traversal is never used */
	if (dq->qnat_traversal_vid < sq->qnat_traversal_vid)
		dq->qnat_traversal_vid = sq->qnat_traversal_vid;
	dq->xauth_vid |= sq->xauth_vid;
}

/*
 * see https://tools.ietf.org/html/rfc7296#section-2.23
 *
 * [...] SHOULD store this as the new address and port combination
 * for the SA (that is, they SHOULD dynamically update the address).
 * A host behind a NAT SHOULD NOT do this type of dynamic address
 * update if a validated packet has different port and/or address
 * values because it opens a possible DoS attack (such as allowing
 * an attacker to break the connection with a single packet).
 *
 * The probe bool is used to signify we are answering a MOBIKE
 * probe request (basically a informational without UPDATE_ADDRESS
 */
void update_ike_endpoints(struct ike_sa *ike,
			  const struct msg_digest *md)
{
	/* caller must ensure we are not behind NAT */
	ike->sa.st_remote_endpoint = md->sender;
	endpoint_buf eb1, eb2;
	dbg("#%lu updating local interface from %s to %s using md->iface "PRI_WHERE,
	    ike->sa.st_serialno,
	    ike->sa.st_interface != NULL ? str_endpoint(&ike->sa.st_interface->local_endpoint, &eb1) : "<none>",
	    str_endpoint(&md->iface->local_endpoint, &eb2),
	    pri_where(HERE));
	iface_endpoint_delref(&ike->sa.st_interface);
	ike->sa.st_interface = iface_endpoint_addref(md->iface);
}

/*
 * We have successfully decrypted this packet, so we can update
 * the remote IP / port
 */
bool update_mobike_endpoints(struct ike_sa *ike, const struct msg_digest *md)
{
	struct connection *c = ike->sa.st_connection;
	const struct ip_info *afi = endpoint_type(&md->iface->local_endpoint);

	/*
	 * AA_201705 is this the right way to find Child SA(s)?
	 * would it work if there are multiple Child SAs on this parent??
	 * would it work if the Child SA connection is different from IKE SA?
	 * for now just do this one connection, later on loop over all Child SAs
	 */
	struct child_sa *child = child_sa_by_serialno(c->newest_ipsec_sa);
	if (child == NULL) {
		/*
		 * XXX: Technically, loosing the first child (it gets
		 * torn down but others remain) is perfectly
		 * reasonable.  However, per above comments, handling
		 * multiple Child SAs is still a TODO item.
		 */
		llog_pexpect(ike->sa.st_logger, HERE,
			     "IKE SA lost first Child SA "PRI_SO, pri_so(c->newest_ipsec_sa));
		return false;
	}

	/* check for all conditions before updating IPsec SA's */
	if (afi != address_type(&c->remote->host.addr)) {
		llog_sa(RC_LOG, ike,
			  "MOBIKE: AF change switching between v4 and v6 not supported");
		return false;
	}

	passert(child->sa.st_connection == ike->sa.st_connection);

	ip_endpoint old_endpoint;
	ip_endpoint new_endpoint;

	enum message_role md_role = v2_msg_role(md);
	switch (md_role) {
	case MESSAGE_RESPONSE:
		/* MOBIKE inititor processing response */
		old_endpoint = ike->sa.st_interface->local_endpoint;

		child->sa.st_mobike_local_endpoint = ike->sa.st_mobike_local_endpoint;
		child->sa.st_mobike_host_nexthop = ike->sa.st_mobike_host_nexthop;

		new_endpoint = ike->sa.st_mobike_local_endpoint;
		break;
	case MESSAGE_REQUEST:
		/* MOBIKE responder processing request */
		old_endpoint = ike->sa.st_remote_endpoint;

		child->sa.st_mobike_remote_endpoint = md->sender;
		ike->sa.st_mobike_remote_endpoint = md->sender;

		new_endpoint =md->sender;
		break;
	default:
		bad_case(md_role);
	}

	char buf[256];
	endpoint_buf old;
	endpoint_buf new;
	snprintf(buf, sizeof(buf), "MOBIKE update %s address %s -> %s",
		 md_role == MESSAGE_RESPONSE ? "local" : "remote",
		 str_endpoint_sensitive(&old_endpoint, &old),
		 str_endpoint_sensitive(&new_endpoint, &new));

	dbg("#%lu pst=#%lu %s", child->sa.st_serialno,
	    ike->sa.st_serialno, buf);

	if (endpoint_eq_endpoint(old_endpoint, new_endpoint)) {
		if (md_role == MESSAGE_REQUEST) {
			/* on responder NAT could hide end-to-end change */
			endpoint_buf b;
			llog_sa(RC_LOG, ike,
				  "MOBIKE success no change to kernel SA same IP address and port %s",
				  str_endpoint_sensitive(&old_endpoint, &b));

			return true;
		}
	}

	if (!kernel_ops_migrate_ipsec_sa(child)) {
		llog_sa(RC_LOG, ike, "%s FAILED", buf);
		return false;
	}

	llog_sa(RC_LOG, ike, " success %s", buf);

	switch (md_role) {
	case MESSAGE_RESPONSE:
		/* MOBIKE initiator processing response */
		c->local->host.addr = endpoint_address(child->sa.st_mobike_local_endpoint);
		dbg("%s() %s.host_port: %u->%u", __func__, c->local->config->leftright,
		    c->spd->local->host->port, endpoint_hport(child->sa.st_mobike_local_endpoint));
		c->spd->local->host->port = endpoint_hport(child->sa.st_mobike_local_endpoint);
		c->spd->local->host->nexthop = child->sa.st_mobike_host_nexthop;
		break;
	case MESSAGE_REQUEST:
		/* MOBIKE responder processing request */
		c->remote->host.addr = endpoint_address(md->sender);
		dbg("%s() %s.host_port: %u->%u", __func__, c->remote->config->leftright,
		    c->spd->remote->host->port, endpoint_hport(md->sender));
		c->spd->remote->host->port = endpoint_hport(md->sender);

		/* for the consistency, correct output in ipsec status */
		child->sa.st_remote_endpoint = ike->sa.st_remote_endpoint = md->sender;
		break;
	default:
		bad_case(md_role);
	}
	iface_endpoint_delref(&ike->sa.st_interface);
	iface_endpoint_delref(&child->sa.st_interface);
	ike->sa.st_interface = iface_endpoint_addref(md->iface);
	child->sa.st_interface = iface_endpoint_addref(md->iface);

	delete_oriented_hp(c); /* hp list may have changed */
	if (!orient(&c, ike->sa.st_logger)) {
		llog_pexpect(ike->sa.st_logger, HERE,
			     "%s after mobike failed", "orient");
	}
	/* assumption: orientation has not changed */
	connect_to_host_pair(c); /* re-create hp listing */

	if (md_role == MESSAGE_RESPONSE) {
		/* MOBIKE initiator processing response */
		connection_resume(child, HERE);
		ike->sa.st_deleted_local_addr = unset_address;
		child->sa.st_deleted_local_addr = unset_address;
		if (dpd_active_locally(child->sa.st_connection) &&
		    child->sa.st_v2_liveness_event == NULL) {
			dbg("dpd re-enabled after mobike, scheduling ikev2 liveness checks");
			deltatime_t delay = deltatime_max(child->sa.st_connection->config->dpd.delay, deltatime(MIN_LIVENESS));
			event_schedule(EVENT_v2_LIVENESS, delay, &child->sa);
		}
	}

	return true;
}

/*
 * Find all CHILD SAs belonging to FROM and migrate them to TO.
 */

struct v2_migrate_filter {
	struct ike_sa *from;
	struct child_sa *to;
};

static bool v2_migrate_predicate(struct state *st, void *context)
{
	struct v2_migrate_filter *filter = context;
	passert(st->st_serialno != filter->to->sa.st_serialno);
	/*
	 * Migrate the CHILD SA.
	 *
	 * Just the IKE_SPIrehash the SPIs without moving entry.
	 *
	 * XXX: this should also wipe message counters but first need
	 * evidence.
	 */
	dbg("#%lu migrated from IKE SA #%lu to IKE SA #%lu",
	    st->st_serialno, filter->from->sa.st_serialno,
	    filter->to->sa.st_serialno);
	st->st_clonedfrom = filter->to->sa.st_serialno;
	st->st_ike_spis = filter->to->sa.st_ike_spis;
	/*
	 * Delete the old IKE_SPI hash entries (both for I and I+R
	 * and), and then inserts new ones using ST's current IKE SPI
	 * values.  The serialno tables are not touched.
	 */
	rehash_state_cookies_in_db(st);
	return false; /* keep going */
}

void v2_migrate_children(struct ike_sa *from, struct child_sa *to)
{
	/*
	 * TO is in the process of being emancipated.  Its
	 * .st_clonedfrom has been zapped and the new IKE_SPIs
	 * installed (a true child would have FROM's IKE SPIs).
	 *
	 * While FROM and TO should have different IKE_SPIs there's
	 * nothing to force them both being different - relying on
	 * luck.
	 */
	passert(to->sa.st_clonedfrom == SOS_NOBODY);
	/* passert(SPIs should be different) */

	/*
	 * Use ..._NEW2OLD() to iterate over the slot.  Since this
	 * macro maintains a "cursor" that is one ahead of ST it is
	 * safe for rehash_state_cookies_in_db(st) to delete the old
	 * hash entries.  Similarly, since the table is walked
	 * NEW2OLD, insert will happen at the front of the table
	 * which, the cursor is past (this odds of this are very low).
	 */
	struct v2_migrate_filter filter = {
		.from = from,
		.to = to,
	};
	state_by_ike_spis(IKEv2,
			  &from->sa.st_serialno,
			  NULL /*ignore v1 msgid */,
			  NULL /*ignore-sa-role */,
			  &from->sa.st_ike_spis,
			  v2_migrate_predicate, &filter, __func__);
}

static bool delete_ike_family_child(struct state *st, void *unused_context UNUSED)
{
	struct ike_sa *ike = ike_sa(st, HERE);
	passert(&ike->sa != st); /* only children */
	passert(ike != NULL);

	/*
	 * Transfer the IKE SA's whack-fd to the child so that the
	 * child can also log its demise; better abstraction?
	 */
	if (fd_p(ike->sa.st_logger->global_whackfd)) {
		fd_delref(&st->st_logger->global_whackfd);
		st->st_logger->global_whackfd = fd_addref(ike->sa.st_logger->global_whackfd);
	}
	switch (st->st_ike_version) {

	case IKEv1:
	{
		struct connection *const c = st->st_connection;
		bool should_notify = should_send_delete(st);
		bool will_notify = should_notify && !impair.send_no_delete;
		const char *impair_notify = should_notify == will_notify ? "" : "IMPAIR: ";
		if (ike->sa.st_connection == st->st_connection) {
			deltatime_buf dtb;
			llog_sa(RC_LOG, ike,
				"%sdeleting other state #%lu (%s) aged %ss and %ssending notification",
				impair_notify, st->st_serialno, st->st_state->name,
				str_deltatime(realtimediff(realnow(), st->st_inception), &dtb),
				will_notify ? "" : "NOT ");
		} else {
			deltatime_buf dtb;
			connection_buf cib;
			llog_sa(RC_LOG, ike,
				"%sdeleting other state #%lu connection (%s) "PRI_CONNECTION" aged %ss and %ssending notification",
				impair_notify, st->st_serialno, st->st_state->name,
				pri_connection(c, &cib),
				str_deltatime(realtimediff(realnow(), st->st_inception), &dtb),
				will_notify ? "" : "NOT ");
		}
		break;
	}

	case IKEv2:
		st->st_on_delete.skip_send_delete = true;
		break;
	}

	st->st_on_delete.skip_log_message = true;
	delete_state(st);
	return false; /* keep going */
}

void delete_ike_family(struct ike_sa **ikep)
{
	struct ike_sa *ike = (*ikep);
	(*ikep) = NULL;
	ike->sa.st_viable_parent = false;

	/*
	 * We are a parent: delete our children and
	 * then prepare to delete ourself.
	 * Our children will be on the same hash chain
	 * because we share IKE SPIs.
	 */
	dbg("delete_ike_family() called");
	state_by_ike_spis(ike->sa.st_ike_version,
			  &ike->sa.st_serialno,
			  NULL /*ignore v1 msgid */,
			  NULL /*ignore-sa-role */,
			  &ike->sa.st_ike_spis,
			  delete_ike_family_child, NULL,
			  __func__);
	/* delete self */
	delete_state(&ike->sa);
}

/*
 * if the state is too busy to process a packet, say so
 *
 * Two things indicate this - st_suspended_md is non-NULL or there's
 * an offloaded task.
 */

void suspend_any_md_where(struct state *st, struct msg_digest *md, where_t where)
{
	if (md != NULL) {
		dbg("suspend: saving MD@%p in state "PRI_SO" "PRI_WHERE,
		    md, (st)->st_serialno, pri_where(where));
		passert(st->st_suspended_md == NULL);
		st->st_suspended_md = md_addref_where(md, where);
		passert(state_is_busy(st));
	} else {
		dbg("suspend: no MD to save in state "PRI_SO" "PRI_WHERE,
		    st->st_serialno, pri_where(where));
	}
}

struct msg_digest *unsuspend_any_md_where(struct state *st, where_t where)
{
	/* don't assume it is non-NULL */
	struct msg_digest *md = st->st_suspended_md;
	if (md != NULL) {
		dbg("suspend: restoring MD@%p from state "PRI_SO" "PRI_WHERE,
		    md, st->st_serialno, pri_where(where));
		st->st_suspended_md = NULL;
	} else {
		dbg("suspend: no MD saved in state "PRI_SO" "PRI_WHERE,
		    st->st_serialno, pri_where(where));
	}
	return md;
}

bool state_is_busy(const struct state *st)
{
	passert(st != NULL);
	/*
	 * Ignore a packet if the state has a suspended state
	 * transition.  Probably a duplicated packet but the original
	 * packet is not yet recorded in st->st_v1_rpacket, so duplicate
	 * checking won't catch.
	 *
	 * ??? Should the packet be recorded earlier to improve
	 * diagnosis?
	 *
	 * See comments in state.h.
	 *
	 * ST_SUSPENDED.MD acts as a poor proxy for indicating a busy
	 * state.  For instance, the initial initiator (both IKEv1 and
	 * IKEv2) doesn't have a suspended MD.  To get around this a
	 * 'fake_md' MD is created.
	 *
	 * XXX: what about xauth? It sets ST_SUSPENDED.MD.
	 */
	if (st->st_suspended_md != NULL) {
		dbg("#%lu is busy; has suspended MD %p",
		    st->st_serialno, st->st_suspended_md);
		return true;
	}
	/*
	 * If IKEv1 is doing something in the background then the
	 * state isn't busy.
	 */
	if (st->st_offloaded_task_in_background) {
		pexpect(st->st_offloaded_task != NULL);
		dbg("#%lu is idle; has background offloaded task",
		    st->st_serialno);
		return false;
	}
	/*
	 * If this state is busy calculating.
	 */
	if (st->st_offloaded_task != NULL) {
		dbg("#%lu is busy; has an offloaded task",
		    st->st_serialno);
		return true;
	}
	dbg("#%lu is idle", st->st_serialno);
	return false;
}

bool verbose_state_busy(const struct state *st)
{
	if (st == NULL) {
		dbg("#null state always idle");
		return false;
	}
	if (!state_is_busy(st)) {
		dbg("#%lu idle", st->st_serialno);
		return false;
	}
	if (st->st_suspended_md != NULL) {
		/* not whack */
		/* XXX: why not whack? */
		/* XXX: can this and below be merged; is there always an offloaded task? */
		log_state(LOG_STREAM/*not-whack*/, st,
			  "discarding packet received during asynchronous work (DNS or crypto) in %s",
			  st->st_state->name);
	} else if (st->st_offloaded_task != NULL) {
		log_state(RC_LOG, st, "message received while calculating. Ignored.");
	}
	return true;
}

bool require_ddos_cookies(void)
{
	return pluto_ddos_mode == DDOS_FORCE_BUSY ||
		(pluto_ddos_mode == DDOS_AUTO &&
		 cat_count[CAT_HALF_OPEN_IKE_SA] >= pluto_ddos_threshold);
}

bool drop_new_exchanges(void)
{
	return cat_count[CAT_HALF_OPEN_IKE_SA] >= pluto_max_halfopen;
}

void show_globalstate_status(struct show *s)
{
	unsigned shunts = shunt_count();

	show_raw(s, "config.setup.ike.ddos_threshold=%u", pluto_ddos_threshold);
	show_raw(s, "config.setup.ike.max_halfopen=%u", pluto_max_halfopen);

	/* technically shunts are not a struct state's - but makes it easier to group */
	show_raw(s, "current.states.all="PRI_CAT, shunts + total_sa());
	show_raw(s, "current.states.ipsec="PRI_CAT, cat_count[CAT_ESTABLISHED_CHILD_SA]);
	show_raw(s, "current.states.ike="PRI_CAT, total_ike_sa());
	show_raw(s, "current.states.shunts=%u", shunts);
	show_raw(s, "current.states.iketype.anonymous="PRI_CAT, cat_count_ike_sa[CAT_ANONYMOUS]);
	show_raw(s, "current.states.iketype.authenticated="PRI_CAT, cat_count_ike_sa[CAT_AUTHENTICATED]);
	show_raw(s, "current.states.iketype.halfopen="PRI_CAT, cat_count[CAT_HALF_OPEN_IKE_SA]);
	show_raw(s, "current.states.iketype.open="PRI_CAT, cat_count[CAT_OPEN_IKE_SA]);
#ifdef USE_IKEv1
	for (enum state_kind sk = STATE_IKEv1_FLOOR; sk < STATE_IKEv1_ROOF; sk++) {
		const struct finite_state *fs = finite_states[sk];
		show_raw(s, "current.states.enumerate.%s="PRI_CAT,
			 fs->name, state_count[sk]);
	}
#endif
	for (enum state_kind sk = STATE_IKEv2_FLOOR; sk < STATE_IKEv2_ROOF; sk++) {
		const struct finite_state *fs = finite_states[sk];
		show_raw(s, "current.states.enumerate.%s="PRI_CAT,
			 fs->name, state_count[sk]);
	}
}

static void append_word(char **sentence, const char *word)
{
	size_t sl = strlen(*sentence);
	size_t wl = strlen(word);
	char *ns = alloc_bytes(sl + 1 + wl + 1, "sentence");

	memcpy(ns, *sentence, sl);
	ns[sl] = ' ';
	memcpy(&ns[sl + 1], word, wl+1);	/* includes NUL */
	pfree(*sentence);
	*sentence = ns;
}

/*
 * Moved from ikev1_xauth.c since IKEv2 code now also uses it
 * Converted to store ephemeral data in the state, not connection
 */
void append_st_cfg_dns(struct state *st, const char *dnsip)
{
	if (st->st_seen_cfg_dns == NULL) {
		st->st_seen_cfg_dns = clone_str(dnsip, "fresh append_st_cfg_dns");
	} else {
		append_word(&st->st_seen_cfg_dns, dnsip);
	}
}

void append_st_cfg_domain(struct state *st, char *domain)
{
	/* note: we are responsible to ensure domain is freed */
	if (st->st_seen_cfg_domains == NULL) {
		st->st_seen_cfg_domains = domain;
	} else {
		append_word(&st->st_seen_cfg_domains, domain);
		pfree(domain);
	}
}

void suppress_delete_notify(const struct ike_sa *ike,
			    const char *what, so_serial_t so)
{
	struct state *st = state_by_serialno(so);
	if (st == NULL) {
		llog_sa(RC_LOG, ike,
			  "did not find old %s state #%lu to mark for suppressing delete",
			  what, so);
		return;
	}

	st->st_on_delete.skip_send_delete = true;
	dbg("marked %s state #%lu to suppress sending delete notify",
	    what, st->st_serialno);
}

static void list_state_event(struct show *s, struct state *st,
			     struct state_event *pe, const monotime_t now)
{
	if (pe != NULL) {
		pexpect(st == pe->ev_state);
		SHOW_JAMBUF(RC_COMMENT, s, buf) {
			jam(buf, "event ");
			jam_enum_short(buf, &event_type_names, pe->ev_type);
			jam(buf, "schd: %jd (in %jds)",
			    monosecs(pe->ev_time),
			    deltasecs(monotimediff(pe->ev_time, now)));
			if (st->st_connection != NULL) {
				connection_buf cib;
				jam(buf, " "PRI_CONNECTION, pri_connection(st->st_connection, &cib));
			}
			jam(buf, "  #%lu", st->st_serialno);
		}
	}
}

void list_state_events(struct show *s, const monotime_t now)
{
	struct state_filter sf = {
		.where = HERE,
	};
	while (next_state_old2new(&sf)) {
		struct state *st = sf.st;
		list_state_event(s, st, st->st_event, now);
		list_state_event(s, st, st->st_v1_send_xauth_event, now);
		list_state_event(s, st, st->st_v1_dpd_event, now);
		/* order makes no sense */
		list_state_event(s, st, st->st_v2_lifetime_event, now);
		list_state_event(s, st, st->st_v2_liveness_event, now);
		list_state_event(s, st, st->st_v2_addr_change_event, now);
		/*list_state_event(s, st, st->st_v2_refresh_event, now);*/
	}
}

#ifdef USE_IKEv1
void set_v1_transition(struct state *st, const struct state_v1_microcode *transition,
		       where_t where)
{
	LDBGP_JAMBUF(DBG_BASE, st->st_logger, buf) {
		jam(buf, "#%lu.st_v1_transition ", st->st_serialno);
		jam_v1_transition(buf, st->st_v1_transition);
		jam(buf, " to ");
		jam_v1_transition(buf, transition);
		jam_string(buf, " ");
		jam_where(buf, where);
	}
	st->st_v1_transition = transition;
}
#endif

void set_v2_transition(struct state *st, const struct v2_state_transition *transition,
		       where_t where)
{
	LDBGP_JAMBUF(DBG_BASE, st->st_logger, buf) {
		jam(buf, "#%lu.st_v2_transition ", st->st_serialno);
		jam_v2_transition(buf, st->st_v2_transition);
		jam(buf, " -> ");
		jam_v2_transition(buf, transition);
		jam_string(buf, " ");
		jam_where(buf, where);
	}
	st->st_v2_transition = transition;
}

static void jam_st(struct jambuf *buf, struct state *st)
{
	if (st == NULL) {
		jam(buf, "NULL");
	} else {
		jam(buf, "%s #%lu %s",
		    IS_CHILD_SA(st) ? "CHILD" : "IKE",
		    st->st_serialno, st->st_state->short_name);
	}
}

void switch_md_st(struct msg_digest *md, struct state *st, where_t where)
{
	LDBGP_JAMBUF(DBG_BASE, st->st_logger, buf) {
		jam(buf, "switching IKEv%d MD.ST from ", st->st_ike_version);
		jam_st(buf, md->v1_st);
		jam(buf, " to ");
		jam_st(buf, st);
		jam_string(buf, " ");
		jam_where(buf, where);
	}
	md->v1_st = st;
}

/*
 * Every time a state's connection is changed, the following need to happen:
 *
 * - update the connection->state hash table
 *
 * - discard the old connection when not in use
 */

void connswitch_state_and_log(struct state *st, struct connection *new)
{
	struct connection *old = st->st_connection;
	passert(old != NULL);
	passert(new != NULL);

	passert(old != new);
	passert(old != NULL);

	connection_buf nb;
	log_state(RC_LOG, st, "switched to "PRI_CONNECTION,
		  pri_connection(new, &nb));
	st->st_connection = new;
	state_db_rehash_connection_serialno(st);
	connection_delete_unused_instance(&old, st,
					  st->st_logger->global_whackfd);
}

/*
 * This logs to the main log the authentication and encryption keys
 * for an IKE/ISAKMP SA.  This is done in a format that is compatible
 * with tcpdump 4.0's -E option.
 *
 * The log message will require that a cut command is used to remove
 * the initial text.
 *
 * DANGER: this intentionally leaks cryptographic secrets.
 */
void DBG_tcpdump_ike_sa_keys(const struct state *st)
{
	passert(DBGP(DBG_PRIVATE));
	passert(!libreswan_fipsmode());

	if (st->st_oakley.ta_integ == NULL ||
	    st->st_oakley.ta_encrypt == NULL)
		return;

	/* format initiator SPI */
	char tispi[3 + 2*IKE_SA_SPI_SIZE];
	datatot(st->st_ike_spis.initiator.bytes, sizeof(st->st_ike_spis.initiator.bytes),
		'x', tispi, sizeof(tispi));

	/* format responder SPI */
	char trspi[3 + 2*IKE_SA_SPI_SIZE];
	datatot(st->st_ike_spis.responder.bytes, sizeof(st->st_ike_spis.responder.bytes),
		'x', trspi, sizeof(trspi));

	const char *authalgo = st->st_oakley.ta_integ->integ_tcpdump_name;
	const char *encalgo = st->st_oakley.ta_encrypt->encrypt_tcpdump_name;

	/*
	 * Text of encryption key length (suffix for encalgo).
	 * No more than 3 digits, but compiler fears it might be 5.
	 */
	char tekl[6] = "";
	if (st->st_oakley.enckeylen != 0)
		snprintf(tekl, sizeof(tekl), "%u",
			 st->st_oakley.enckeylen);

	/* v2 IKE authentication key for initiator (256 bit bound) */
	chunk_t ai = chunk_from_symkey("ai", st->st_skey_ai_nss,
				       st->st_logger);
	char tai[3 + 2 * BYTES_FOR_BITS(256)] = "";
	datatot(ai.ptr, ai.len, 'x', tai, sizeof(tai));
	free_chunk_content(&ai);

	/* v2 IKE encryption key for initiator (256 bit bound) */
	chunk_t ei = chunk_from_symkey("ei", st->st_skey_ei_nss,
				       st->st_logger);
	char tei[3 + 2 * BYTES_FOR_BITS(256)] = "";
	datatot(ei.ptr, ei.len, 'x', tei, sizeof(tei));
	free_chunk_content(&ei);

	DBG_log("ikev%d I %s %s %s:%s %s%s:%s",
		st->st_ike_version,
		tispi, trspi,
		authalgo, tai,
		encalgo, tekl, tei);

	/* v2 IKE authentication key for responder (256 bit bound) */
	chunk_t ar = chunk_from_symkey("ar", st->st_skey_ar_nss,
				       st->st_logger);
	char tar[3 + 2 * BYTES_FOR_BITS(256)] = "";
	datatot(ar.ptr, ar.len, 'x', tar, sizeof(tar));
	free_chunk_content(&ar);

	/* v2 IKE encryption key for responder (256 bit bound) */
	chunk_t er = chunk_from_symkey("er", st->st_skey_er_nss,
				       st->st_logger);
	char ter[3 + 2 * BYTES_FOR_BITS(256)] = "";
	datatot(er.ptr, er.len, 'x', ter, sizeof(ter));
	free_chunk_content(&er);

	DBG_log("ikev%d R %s %s %s:%s %s%s:%s",
		st->st_ike_version,
		tispi, trspi,
		authalgo, tar,
		encalgo, tekl, ter);
}

void set_sa_expire_next_event(enum event_type next_event, struct state *st)
{
	switch (st->st_ike_version) {
	case IKEv2:
		event_delete(EVENT_v2_LIVENESS, st);
		if (next_event == EVENT_NULL)
			next_event = EVENT_v2_REKEY;

		break;
	case IKEv1:
		event_delete(EVENT_v1_DPD, st);
		if (next_event == EVENT_NULL)
			next_event = EVENT_v1_REPLACE;
		break;
	default:
		bad_case(st->st_ike_version);
	}

	event_force(next_event, st);
}
