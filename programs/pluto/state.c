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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "xauth.h"		/* for xauth_cancel() */
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "state_db.h"
#include "ikev1_msgid.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "packet.h"	/* so we can calculate sizeof(struct isakmp_hdr) */
#include "keys.h"	/* for free_public_key */
#include "rnd.h"
#include "timer.h"
#include "whack.h"
#include "demux.h"	/* needs packet.h */
#include "pending.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "crypto.h"
#include "crypt_symkey.h"
#include "spdb.h"
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "ikev2_redirect.h"
#include "secrets.h"    /* unreference_key() */
#include "enum_names.h"
#include "crypt_dh.h"
#include "hostpair.h"

#include "kernel.h"

#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>

#include "ikev2_msgid.h"
#include "pluto_stats.h"
#include "ikev2_ipseckey.h"
#include "ip_address.h"

bool uniqueIDs = FALSE;

/*
 * Global variables: had to go somewhere, might as well be this file.
 */

uint16_t pluto_port = IKE_UDP_PORT;	/* Pluto's port */
uint16_t pluto_nat_port = NAT_IKE_UDP_PORT;	/* Pluto's NAT-T port */

/*
 * default global NFLOG group - 0 means no logging
 * Note: variable is only used to display in ipsec status
 * actual work is done outside pluto, by ipsec --checknflog
 */
uint16_t pluto_nflog_group = 0;

/*
 * Note: variable is only used to display in ipsec status
 * actual work is done outside pluto, by ipsec _stackmanager
 */
uint16_t pluto_xfrmlifetime = 300;

/*
 * Handle for each and every state.
 *
 * XXX: The array finite_states[] is something of a hack until it is
 * figured out if the array or separate objects for each state is
 * better.
 */
struct finite_state state_undefined = {
	.kind = STATE_UNDEFINED,
	.name = "STATE_UNDEFINED",
	.short_name = "UNDEFINED",
	.story = "not defined - either very new or dead (internal)",
	.category = CAT_IGNORE,
};

const struct finite_state *finite_states[STATE_IKE_ROOF] = {
	[STATE_UNDEFINED] = &state_undefined,
};

/*
 * Revival mechanism: keep track of connections
 * that should be kept up, even though all their
 * states have been deleted.
 *
 * We record the connection names.
 * Each name is recorded only once.
 *
 * XXX: This functionality totally overlaps both "initiate" and
 * "pending" and should be merged (howerver, this simple code might
 * prove to be a better starting point).
 */

struct revival {
	char *name;
	struct revival *next;
};

static struct revival *revivals = NULL;

/*
 * XXX: Return connection C's revival object's link, if found.  If the
 * connection C can't be found, then the address of the revival list's
 * tail is returned.  Perhaps, exiting the loop and returning NULL
 * would be more obvious.
 */
static struct revival **find_revival(const struct connection *c)
{
	for (struct revival **rp = &revivals; ; rp = &(*rp)->next) {
		if (*rp == NULL || streq((*rp)->name, c->name)) {
			return rp;
		}
	}
}

/*
 * XXX: In addition to freeing RP (and killing the pointer), this
 * "free" function has the side effect of unlinks RP from the revival
 * list.  Perhaps free*() isn't the best name.
 */
static void free_revival(struct revival **rp)
{
	struct revival *r = *rp;
	*rp = r->next;
	pfree(r->name);
	pfree(r);
}

void flush_revival(const struct connection *c)
{
	struct revival **rp = find_revival(c);

	if (*rp == NULL) {
		dbg("flush revival: connection '%s' wasn't on the list",
		    c->name);
	} else {
		dbg("flush revival: connection '%s' revival flushed",
		    c->name);
		free_revival(rp);
	}
}

static void add_revival(struct connection *c)
{
	if (*find_revival(c) == NULL) {
		struct revival *r = alloc_thing(struct revival,
						"revival struct");

		r->name = clone_str(c->name, "revival conn name");
		r->next = revivals;
		revivals = r;
		int delay = c->temp_vars.revive_delay;
		dbg("add revival: connection '%s' added to the list and scheduled for %d seconds",
		    c->name, delay);
		c->temp_vars.revive_delay = min(delay + REVIVE_CONN_DELAY,
						REVIVE_CONN_DELAY_MAX);
		/*
		 * XXX: Schedule the next revival using this
		 * connection's revival delay and not the most urgent
		 * connection's revival delay.  Trying to fix this
		 * here just is annoying and probably of marginal
		 * benefit: it is something better handled with a
		 * proper connection event so that the event loop deal
		 * with all the math (this code would then be
		 * deleted); and would encroach even further on
		 * "initiate" and "pending" functionality.
		 */
		schedule_oneshot_timer(EVENT_REVIVE_CONNS, deltatime(delay));
	}
}

void revive_conns(void)
{
	/*
	 * XXX: Revive all listed connections regardless of their
	 * DELAY.  See note above in add_revival().
	 */
	while (revivals != NULL) {
		libreswan_log("Initiating connection %s which received a Delete/Notify but must remain up per local policy",
			revivals->name);
		initiate_connection(revivals->name, null_fd, empty_lmod, empty_lmod, NULL);
		free_revival(&revivals);
	}
}

/* end of revival mechanism */

void lswlog_finite_state(struct lswlog *buf, const struct finite_state *fs)
{
	if (fs == NULL) {
		lswlogs(buf, "NULL-FINITE_STATE");
	} else {
		lswlogf(buf, "%s:", fs->short_name);
		lswlogf(buf, " category: ");
		lswlog_enum_short(buf, &state_category_names, fs->category);
		/* no enum_name available? */
		lswlogf(buf, " flags: "PRI_LSET, fs->flags);
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
 * is printed as a "signed" value - so that should underflow occure it
 * is diplayed as -ve (rather than a huge positive).
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
		 * anonimity. We therefore use a scratchpad at
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
			PEXPECT_LOG("category states: "PRI_CAT" != count states: "PRI_CAT,
				    category_states, count_states);
		}

		if (cat_count[CAT_ESTABLISHED_IKE_SA] !=
		    (cat_count_ike_sa[CAT_AUTHENTICATED] + cat_count_ike_sa[CAT_ANONYMOUS])) {
			PEXPECT_LOG("established IKE SA: "PRI_CAT" != authenticated: "PRI_CAT" + anoynmous: "PRI_CAT,
				    cat_count[CAT_ESTABLISHED_IKE_SA],
				    cat_count_ike_sa[CAT_AUTHENTICATED],
				    cat_count_ike_sa[CAT_ANONYMOUS]);
		}

		if (cat_count[CAT_ESTABLISHED_CHILD_SA] !=
		    (cat_count_child_sa[CAT_AUTHENTICATED] + cat_count_child_sa[CAT_ANONYMOUS])) {
			PEXPECT_LOG("established CHILD SA: "PRI_CAT" != authenticated: "PRI_CAT" + anoynmous: "PRI_CAT,
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

void change_state(struct state *st, enum state_kind new_state_kind)
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

/*
 * readable_humber: make large numbers clearer by expressing them as KB or MB,
 * as appropriate.
 * The prefix is literally copied into the output.
 * Tricky representation: if the prefix starts with !, the number
 * is taken as kilobytes.  Thus the caller can avoid scaling, with its
 * risk of overflow.  The ! is not printed.
 */
static char *readable_humber(uint64_t num,
			     char *buf,
			     const char *buf_roof,
			     const char *prefix)
{
	size_t buf_len = buf_roof - buf;
	uint64_t to_print = num;
	const char *suffix;
	int ret;
	bool kilos = prefix[0] == '!';

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

	ret = snprintf(buf, buf_len, "%s%" PRIu64 "%s", prefix, to_print,
		       suffix + kilos);
	if (ret < 0 || (size_t) ret >= buf_len)
		return buf;

	return buf + ret;
}

/*
 * Get the IKE SA managing the security association.
 */

struct ike_sa *ike_sa(struct state *st)
{
	if (st != NULL && IS_CHILD_SA(st)) {
		struct state *pst = state_by_serialno(st->st_clonedfrom);
		if (pst == NULL) {
			PEXPECT_LOG("child state #%lu missing parent state #%lu",
				    st->st_serialno, st->st_clonedfrom);
			/* about to crash with an NPE */
		}
		return (struct ike_sa*) pst;
	}
	return (struct ike_sa*) st;
}

struct ike_sa *pexpect_ike_sa(struct state *st)
{
	if (st == NULL) {
		return NULL;
	}
	if (!IS_IKE_SA(st)) {
		PEXPECT_LOG("state #%lu is not an IKE SA", st->st_serialno);
		return NULL; /* kaboom */
	}
	return (struct ike_sa*) st;
}

struct child_sa *pexpect_child_sa(struct state *st)
{
	if (st == NULL) {
		return NULL;
	}
	if (!IS_CHILD_SA(st)) {
		/* In IKEv2 a re-keying IKE SA starts life as a child */
		PEXPECT_LOG("state #%lu is not a CHILD", st->st_serialno);
		return NULL; /* kaboom */
	}
	return (struct child_sa*) st;
}

union sas { struct child_sa child; struct ike_sa ike; struct state st; };

/*
 * Get a state object.
 * Caller must schedule an event for this object so that it doesn't leak.
 * Caller must insert_state().
 */

static so_serial_t next_so = SOS_FIRST;

so_serial_t next_so_serialno(void)
{
	return next_so;
}

static struct state *new_state(enum ike_version ike_version,
			       const struct finite_state *fs,
			       const ike_spi_t ike_initiator_spi,
			       const ike_spi_t ike_responder_spi,
			       enum sa_type sa_type)
{
	union sas *sas = alloc_thing(union sas, "struct state in new_state()");
	passert(&sas->st == &sas->child.sa);
	passert(&sas->st == &sas->ike.sa);
	struct state *st = &sas->st;
	*st = (struct state) {
		.st_whack_sock = null_fd,	/* note: not 0 */
		.st_state = fs,
		.st_serialno = next_so++,
		.st_inception = realnow(),
		.st_ike_version = ike_version,
		.st_establishing_sa = sa_type,
		.st_ike_spis = {
			.initiator = ike_initiator_spi,
			.responder = ike_responder_spi,
		},
	};
	passert(next_so > SOS_FIRST);   /* overflow can't happen! */
	statetime_start(st);

	anyaddr(AF_INET, &st->hidden_variables.st_nat_oa);
	anyaddr(AF_INET, &st->hidden_variables.st_natd);

	dbg("creating state object #%lu at %p", st->st_serialno, (void *) st);
	add_state_to_db(st);
	pstat_sa_started(st, sa_type);

	return st;
}

struct state *new_v1_istate(void)
{
	struct state *st = new_state(IKEv1, &state_undefined, ike_initiator_spi(),
				     zero_ike_spi, IKE_SA);
	return st;
}

struct state *new_v1_rstate(struct msg_digest *md)
{
	struct state *st = new_state(IKEv1, &state_undefined,
				     md->hdr.isa_ike_spis.initiator,
				     ike_responder_spi(&md->sender),
				     IKE_SA);
	update_ike_endpoints(st, md);
	return st;
}

struct ike_sa *new_v2_state(enum state_kind kind, enum sa_role sa_role,
			    const ike_spi_t ike_initiator_spi,
			    const ike_spi_t ike_responder_spi)
{
	struct state *st = new_state(IKEv2, &state_undefined,
				     ike_initiator_spi, ike_responder_spi,
				     IKE_SA);
	st->st_sa_role = sa_role;
	st->st_msgid_lastack = v2_INVALID_MSGID;
	st->st_msgid_lastrecv = v2_INVALID_MSGID;
	st->st_msgid_nextuse = 0;
	dbg("Message ID: init #%lu: msgid="PRI_MSGID" lastack="PRI_MSGID" nextuse="PRI_MSGID" lastrecv="PRI_MSGID" lastreplied="PRI_MSGID,
	    st->st_serialno, st->st_msgid,
	    st->st_msgid_lastack, st->st_msgid_nextuse,
	    st->st_msgid_lastrecv, st->st_msgid_lastreplied);
	const struct finite_state *fs = finite_states[kind];
	change_state(st, fs->kind);
	struct ike_sa *ike = pexpect_ike_sa(st);
	v2_msgid_init_ike(ike);
	/*
	 * New states are never standing still - they are always in
	 * transition to the next state.
	 */
	pexpect(fs->v2_transitions != NULL);
	pexpect(fs->nr_transitions == 1);
	/* st->st_v2_transition = fs->state_transitions[0] */
	return ike;
}

/*
 * Initialize the state table.
 */
void init_states(void)
{
	init_oneshot_timer(EVENT_REVIVE_CONNS, revive_conns);
}

void delete_state_by_id_name(struct state *st, void *name)
{
	char thatidbuf[IDTOA_BUF];
	struct connection *c = st->st_connection;

	if (!IS_IKE_SA(st))
		return;

	idtoa(&c->spd.that.id, thatidbuf, sizeof(thatidbuf));
	if (streq(thatidbuf, name)) {
		delete_my_family(st, FALSE);
		/* note: no md->st to clear */
	}
}

void v1_delete_state_by_username(struct state *st, void *name)
{
	/* only support deleting ikev1 with XAUTH username */
	if (st->st_ike_version == IKEv2)
		return;

	if (IS_IKE_SA(st) && streq(st->st_xauth_username, name)) {
		delete_my_family(st, FALSE);
		/* note: no md->st to clear */
	}
}

/*
 * Find the state object with this serial number.  This allows state
 * object references that don't turn into dangerous dangling pointers:
 * reference a state by its serial number.  Returns NULL if there is
 * no such state.
 */
struct state *state_with_serialno(so_serial_t sn)
{
	return state_by_serialno(sn);
}

/*
 * Re-insert the state in the dabase after updating the RCOOKIE, and
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

/*
 * Free the Whack socket file descriptor.
 * This has the side effect of telling Whack that we're done.
 */
void release_whack(struct state *st)
{
	close_any(&st->st_whack_sock);
}

static void release_v2fragments(struct state *st)
{
	passert(st->st_ike_version == IKEv2);

	if (st->st_v2_rfrags != NULL) {
		for (unsigned i = 0; i < elemsof(st->st_v2_rfrags->frags); i++) {
			struct v2_ike_rfrag *frag = &st->st_v2_rfrags->frags[i];
			freeanychunk(frag->cipher);
		}
		pfree(st->st_v2_rfrags);
		st->st_v2_rfrags = NULL;
	}

	for (struct v2_ike_tfrag *frag = st->st_v2_tfrags; frag != NULL; ) {
		struct v2_ike_tfrag *this = frag;
		frag = this->next;
		freeanychunk(this->cipher);
		pfree(this);
	}
	st->st_v2_tfrags = NULL;
}

static void release_v1fragments(struct state *st)
{
	passert(st->st_ike_version == IKEv1);

	struct ike_frag *frag = st->st_v1_rfrags;
	while (frag != NULL) {
		struct ike_frag *this = frag;

		frag = this->next;
		release_md(this->md);
		pfree(this);
	}

	st->st_v1_rfrags = NULL;
}

/*
 * Release stored IKE fragments. This is a union in st so only call one!
 */
void release_fragments(struct state *st)
{
	switch (st->st_ike_version) {
	case IKEv1:
		release_v1fragments(st);
		break;
	case IKEv2:
		release_v2fragments(st);
		break;
	default:
		bad_case(st->st_ike_version);
	}
}

void v2_expire_unused_ike_sa(struct ike_sa *ike)
{
	passert(ike != NULL);
	passert(ike->sa.st_ike_version == IKEv2);

	if (!IS_PARENT_SA_ESTABLISHED(&ike->sa)) {
		dbg("can't expire unused IKE SA #%lu; not established - strange",
		    ike->sa.st_serialno);
		return; /* only deal with established parent SA */
	}

	/* Any children? */
	struct state *st = state_by_ike_spis(IKEv2, ike->sa.st_serialno,
					     NULL/* ignore v1 msgid */,
					     &ike->sa.st_ike_spis,
					     NULL, NULL /* no predicate */,
					     __func__);
	if (st != NULL) {
		dbg("can't expire unused IKE SA #%lu; it has the child #%lu",
		    ike->sa.st_serialno, st->st_serialno);
		return;
	}

	{
		char cib[CONN_INST_BUF];
		struct connection *c = ike->sa.st_connection;
		loglog(RC_INFORMATIONAL, "expire unused IKE SA #%lu \"%s\"%s",
		       ike->sa.st_serialno, c->name,
		       fmt_conn_instance(c, cib));
		event_force(EVENT_SA_EXPIRE, &ike->sa);
	}
}


static bool flush_incomplete_child(struct state *st, void *pst UNUSED)
{
	if (!IS_IPSEC_SA_ESTABLISHED(st)) {

		char cib[CONN_INST_BUF];
		struct connection *c = st->st_connection;

		so_serial_t newest_sa;
		switch (st->st_establishing_sa) {
		case IKE_SA: newest_sa = c->newest_isakmp_sa; break;
		case IPSEC_SA: newest_sa = c->newest_ipsec_sa; break;
		default: bad_case(st->st_establishing_sa);
		}

		if (st->st_serialno > newest_sa &&
		    (c->policy & POLICY_UP) &&
		    (c->policy & POLICY_DONT_REKEY) == LEMPTY) {
			loglog(RC_LOG_SERIOUS, "reschedule pending child #%lu %s of "
			       "connection \"%s\"%s - the parent is going away",
			       st->st_serialno, st->st_state->name,
			       c->name, fmt_conn_instance(c, cib));

			st->st_policy = c->policy; /* for pick_initiator */
			event_force(EVENT_SA_REPLACE, st);
		} else {
			loglog(RC_LOG_SERIOUS, "expire pending child #%lu %s of "
			       "connection \"%s\"%s - the parent is going away",
			       st->st_serialno, st->st_state->name,
			       c->name, fmt_conn_instance(c, cib));

			event_force(EVENT_SA_EXPIRE, st);
		}
	}
	/*
	 * XXX: why was this non-conditional?  probably doesn't matter
	 * as it is idenpotent?
	 */
	delete_cryptographic_continuation(st);
	return false; /* keep going */
}

static void flush_incomplete_children(struct state *pst)
{
	if (IS_CHILD_SA(pst))
		return;

	state_by_ike_spis(pst->st_ike_version,
			  pst->st_serialno,
			  NULL /* ignore MSGID */,
			  &pst->st_ike_spis,
			  flush_incomplete_child, NULL/*arg*/, __func__);
}

static bool send_delete_check(const struct state *st)
{
	if (st->st_suppress_del_notify)
		return FALSE;

	if (IS_IPSEC_SA_ESTABLISHED(st) ||
			IS_ISAKMP_SA_ESTABLISHED(st->st_state))
	{
		if ((st->st_ike_version == IKEv2) &&
				IS_CHILD_SA(st) &&
				state_with_serialno(st->st_clonedfrom) == NULL) {
			/* ??? in v2, there must be a parent */
			DBG(DBG_CONTROL, DBG_log("deleting state but IKE SA does not exist for this child SA so Informational Exchange cannot be sent"));

			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

static void delete_state_log(struct state *st, struct state *cur_state)
{
	struct connection *const c = st->st_connection;
	bool del_notify = !IMPAIR(SEND_NO_DELETE) && send_delete_check(st);

	if (cur_state != NULL && cur_state == st) {
		/*
		* Don't log state and connection if it is the same as
		* the message prefix.
		*/
		libreswan_log("deleting state (%s) aged "PRI_DELTATIME"s and %ssending notification",
			st->st_state->name,
			pri_deltatime(realtimediff(realnow(), st->st_inception)),
			del_notify ? "" : "NOT ");
	} else if (cur_state != NULL && cur_state->st_connection == st->st_connection) {
		libreswan_log("deleting other state #%lu (%s) aged "PRI_DELTATIME"s and %ssending notification",
			st->st_serialno,
			st->st_state->name,
			pri_deltatime(realtimediff(realnow(), st->st_inception)),
			del_notify ? "" : "NOT ");
	} else {
		char cib[CONN_INST_BUF];
		libreswan_log("deleting other state #%lu connection (%s) \"%s\"%s aged "PRI_DELTATIME"s and %ssending notification",
			st->st_serialno,
			st->st_state->name,
			c->name,
			fmt_conn_instance(c, cib),
			pri_deltatime(realtimediff(realnow(), st->st_inception)),
			del_notify ? "" : "NOT ");
	}

	dbg("%s state #%lu: %s(%s) => delete",
	    IS_IKE_SA(st) ? "parent" : "child", st->st_serialno,
	    st->st_state->short_name,
	    enum_name(&state_category_names, st->st_state->category));
}

/* delete a state object */
void delete_state(struct state *st)
{
	struct connection *const c = st->st_connection;
	pstat_sa_deleted(st);

	/*
	 * Even though code tries to always track CPU time, only log
	 * it when debugging - values range from very approximate to
	 * (in the case of IKEv1) simply wrong.
	 */
	if (DBGP(DBG_CPU_USAGE|DBG_BASE) &&
	    st->st_ike_version == IKEv2 &&
	    st->st_timing.approx_seconds > 0) {
		DBG_log("#%lu "PRI_CPU_USAGE" in total",
			st->st_serialno,
			pri_cpu_usage(st->st_timing.approx_seconds));
	}

	so_serial_t old_serialno = push_cur_state(st);
	delete_state_log(st, state_by_serialno(old_serialno));

#ifdef USE_LINUX_AUDIT
	/*
	 * only log parent state deletes, we log children in
	 * ipsec_delete_sa()
	 */
	if (IS_IKE_SA_ESTABLISHED(st) || st->st_state->kind == STATE_IKESA_DEL)
		linux_audit_conn(st, LAK_PARENT_DESTROY);
#endif

	/* If we are failed OE initiator, make shunt bare */
	if (IS_IKE_SA(st) && (c->policy & POLICY_OPPORTUNISTIC) &&
	    (st->st_state->kind == STATE_PARENT_I1 ||
	     st->st_state->kind == STATE_PARENT_I2)) {
		ipsec_spi_t failure_shunt = shunt_policy_spi(c, FALSE /* failure_shunt */);
		ipsec_spi_t nego_shunt = shunt_policy_spi(c, TRUE /* negotiation shunt */);

		DBG(DBG_OPPO, DBG_log(
			"OE: delete_state orphaning hold with failureshunt %s (negotiation shunt would have been %s)",
			enum_short_name(&spi_names, failure_shunt),
			enum_short_name(&spi_names, nego_shunt)));

		if (!orphan_holdpass(c, &c->spd, c->spd.this.protocol, failure_shunt)) {
			loglog(RC_LOG_SERIOUS, "orphan_holdpass() failure ignored");
		}
	}

	if (IS_IPSEC_SA_ESTABLISHED(st)) {
		/* pull in the traffic counters into state before they're lost */
		if (!get_sa_info(st, FALSE, NULL)) {
			libreswan_log("failed to pull traffic counters from outbound IPsec SA");
		}
		if (!get_sa_info(st, TRUE, NULL)) {
			libreswan_log("failed to pull traffic counters from inbound IPsec SA");
		}

		/*
		 * Note that a state/SA can have more then one of
		 * ESP/AH/IPCOMP
		 */
		if (st->st_esp.present) {
			char statebuf[1024];
			char *sbcp = readable_humber(st->st_esp.our_bytes,
					       statebuf,
					       statebuf + sizeof(statebuf),
					       "ESP traffic information: in=");

			(void)readable_humber(st->st_esp.peer_bytes,
					       sbcp,
					       statebuf + sizeof(statebuf),
					       " out=");
			loglog(RC_INFORMATIONAL, "%s%s%s",
				statebuf,
				(st->st_xauth_username[0] != '\0') ? " XAUTHuser=" : "",
				st->st_xauth_username);
			pstats_ipsec_in_bytes += st->st_esp.our_bytes;
			pstats_ipsec_out_bytes += st->st_esp.peer_bytes;
		}

		if (st->st_ah.present) {
			char statebuf[1024];
			char *sbcp = readable_humber(st->st_ah.peer_bytes,
					       statebuf,
					       statebuf + sizeof(statebuf),
					       "AH traffic information: in=");

			(void)readable_humber(st->st_ah.our_bytes,
					       sbcp,
					       statebuf + sizeof(statebuf),
					       " out=");
			loglog(RC_INFORMATIONAL, "%s%s%s",
				statebuf,
				(st->st_xauth_username[0] != '\0') ? " XAUTHuser=" : "",
				st->st_xauth_username);
			pstats_ipsec_in_bytes += st->st_ah.peer_bytes;
			pstats_ipsec_out_bytes += st->st_ah.our_bytes;
		}

		if (st->st_ipcomp.present) {
			char statebuf[1024];
			char *sbcp = readable_humber(st->st_ipcomp.peer_bytes,
					       statebuf,
					       statebuf + sizeof(statebuf),
					       " IPCOMP traffic information: in=");

			(void)readable_humber(st->st_ipcomp.our_bytes,
					       sbcp,
					       statebuf + sizeof(statebuf),
					       " out=");
			loglog(RC_INFORMATIONAL, "%s%s%s",
				statebuf,
				(st->st_xauth_username[0] != '\0') ? " XAUTHuser=" : "",
				st->st_xauth_username);
			pstats_ipsec_in_bytes += st->st_ipcomp.peer_bytes;
			pstats_ipsec_out_bytes += st->st_ipcomp.our_bytes;
		}
	}

#ifdef XAUTH_HAVE_PAM
	if (st->st_xauth != NULL) {
		xauth_pam_abort(st);
	}
#endif

	delete_dpd_event(st);
	delete_liveness_event(st);
	delete_state_event(st, &st->st_rel_whack_event);
	delete_state_event(st, &st->st_send_xauth_event);
	delete_state_event(st, &st->st_addr_change_event);

	/* if there is a suspended state transition, disconnect us */
	struct msg_digest *md = unsuspend_md(st);
	if (md != NULL) {
		DBG(DBG_CONTROL,
		    DBG_log("disconnecting state #%lu from md",
			    st->st_serialno));
		release_any_md(&md);
	}

	if (send_delete_check(st)) {
		/*
		 * tell the other side of any IPSEC SAs that are going down
		 *
		 * ??? in IKEv2, we should not immediately delete:
		 * we should use an Informational Exchange to
		 * co-ordinate deletion.
		 * ikev2_delete_out doesn't really accomplish this.
		 */
		send_delete(st);
	} else if (IS_CHILD_SA(st)) {
		change_state(st, STATE_CHILDSA_DEL);
	}

	delete_event(st); /* delete any pending timer event */

	/*
	 * Ditch anything pending on ISAKMP SA being established.
	 * Note: this must be done before the unhash_state to prevent
	 * flush_pending_by_state inadvertently and prematurely
	 * deleting our connection.
	 */
	flush_pending_by_state(st);

	/* flush unestablished child states */
	flush_incomplete_children(st);

	/*
	 * if there is anything in the cryptographic queue, then remove this
	 * state from it.
	 */
	delete_cryptographic_continuation(st);

	/*
	 * effectively, this deletes any ISAKMP SA that this state represents
	 */
	del_state_from_db(st);

	/*
	 * tell kernel to delete any IPSEC SA
	 */
	if (IS_IPSEC_SA_ESTABLISHED(st) ||
		IS_CHILD_SA_ESTABLISHED(st) ||
		st->st_state->kind == STATE_CHILDSA_DEL) {
			delete_ipsec_sa(st);
	}

	if (c->newest_ipsec_sa == st->st_serialno)
		c->newest_ipsec_sa = SOS_NOBODY;

	if (c->newest_isakmp_sa == st->st_serialno)
		c->newest_isakmp_sa = SOS_NOBODY;

	/*
	 * If policy dictates, try to keep the connection alive.
	 * DONT_REKEY overrides UP.
	 *
	 * XXX: need more info from someone knowing what the problem
	 * is.
	 * ??? What problem is this refering to?
	 */
	if ((c->policy & (POLICY_UP | POLICY_DONT_REKEY)) == POLICY_UP &&
	    IS_IKE_SA(st)) {
		/* XXX: break it down so it can be logged */
		so_serial_t newer_sa = get_newer_sa_from_connection(st);
		if (state_by_serialno(newer_sa) != NULL) {
			/*
			 * Presumably this is an old state that has
			 * either been rekeyed or replaced.
			 *
			 * XXX: Should not even be here through!  The
			 * old IKE SA should be going through delete
			 * state transition that, at the end, cleanly
			 * deletes it with none of this guff.
			 */
			dbg("IKE delete_state() for #%lu and connection '%s' that is supposed to remain up;  not a problem - have newer #%lu",
			    st->st_serialno, c->name, newer_sa);
		} else if (impair_revival) {
			libreswan_log("IMPAIR: skipping revival of connection '%s' that is supposed to remain up",
				      c->name);
		} else {
			/* 'cur' is ST; so #SO is in log prefix */
			log_to_log("deleting IKE SA for connection '%s' but connection is supposed to remain up; schedule EVENT_REVIVE_CONNS",
				   c->name);
			add_revival(c);
		}
	}

	/*
	 * fake a state change here while we are still associated with a
	 * connection.  Without this the state logging (when enabled) cannot
	 * work out what happened.
	 */
	binlog_fake_state(st, STATE_UNDEFINED);

	/* we might be about to free it */
	st->st_connection = NULL;	/* c will be discarded */
	connection_discard(c);

	change_state(st, STATE_UNDEFINED);

	release_whack(st);

	/* from here on we are just freeing RAM */

	ikev1_clear_msgid_list(st);
	unreference_key(&st->st_peer_pubkey);
	release_fragments(st);

	/*
	 * Free the accepted proposal first, it points into the
	 * proposals.
	 */
	free_ikev2_proposal(&st->st_accepted_ike_proposal);
	free_ikev2_proposal(&st->st_accepted_esp_or_ah_proposal);

	/*
	 * If this state 'owns' the DH secret, release it.  If not
	 * then it is presumably owned by a crypto-helper and that can
	 * clean it up.
	 */
	if (st->st_dh_secret != NULL) {
		free_dh_secret(&st->st_dh_secret);
	}

	/* without st_connection, st isn't complete */
	/* from here on logging is for the wrong state */
	pop_cur_state(old_serialno);

	release_certs(&st->st_remote_certs.verified);
	free_public_keys(&st->st_remote_certs.pubkey_db);

	free_generalNames(st->st_requested_ca, TRUE);

	freeanychunk(st->st_firstpacket_me);
	freeanychunk(st->st_firstpacket_him);
	freeanychunk(st->st_tpacket);
	freeanychunk(st->st_rpacket);
	freeanychunk(st->st_p1isa);
	freeanychunk(st->st_gi);
	freeanychunk(st->st_gr);
	freeanychunk(st->st_ni);
	freeanychunk(st->st_nr);
	freeanychunk(st->st_dcookie);

#    define free_any_nss_symkey(p)  release_symkey(__func__, #p, &(p))
	free_any_nss_symkey(st->st_shared_nss);
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

	freeanychunk(st->st_skey_initiator_salt);
	freeanychunk(st->st_skey_responder_salt);
	freeanychunk(st->st_skey_chunk_SK_pi);
	freeanychunk(st->st_skey_chunk_SK_pr);

#   define wipe_any(p, l) { \
		if ((p) != NULL) { \
			memset((p), 0x00, (l)); \
			pfree(p); \
			(p) = NULL; \
		} \
	}
	wipe_any(st->st_ah.our_keymat, st->st_ah.keymat_len);
	wipe_any(st->st_ah.peer_keymat, st->st_ah.keymat_len);
	wipe_any(st->st_esp.our_keymat, st->st_esp.keymat_len);
	wipe_any(st->st_esp.peer_keymat, st->st_esp.keymat_len);

	wipe_any(st->st_xauth_password.ptr, st->st_xauth_password.len);
#   undef wipe_any

	/* st_xauth_username is an array on the state itself, not clone_str()'ed */
	pfreeany(st->st_seen_cfg_dns);
	pfreeany(st->st_seen_cfg_domains);
	pfreeany(st->st_seen_cfg_banner);

	pfreeany(st->st_active_redirect_gw);
	freeanychunk(st->st_no_ppk_auth);

#ifdef HAVE_LABELED_IPSEC
	pfreeany(st->sec_ctx);
#endif
	messup(st);
	pfree(st);
}

/*
 * Is a connection in use by some state?
 */
bool states_use_connection(const struct connection *c)
{
	/* are there any states still using it? */
	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *st = NULL;
	FOR_EACH_STATE_NEW2OLD(st) {
		if (st->st_connection == c)
			return TRUE;
	};

	return FALSE;
}

bool shared_phase1_connection(const struct connection *c)
{
	so_serial_t serial_us = c->newest_isakmp_sa;

	if (serial_us == SOS_NOBODY)
		return FALSE;

	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *st = NULL;
	FOR_EACH_STATE_NEW2OLD(st) {
		if (st->st_connection != c && st->st_clonedfrom == serial_us)
			return TRUE;
	}

	return FALSE;
}

bool v2_child_connection_probably_shared(struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;

	if (in_pending_use(c)) {
		dbg("#%lu connection is also pending; but what about pending for this state???",
		    child->sa.st_serialno);
		return true;
	}

	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct ike_sa *ike = ike_sa(&child->sa);
	struct state *st = NULL;
	FOR_EACH_STATE_NEW2OLD(st) {
		if (st->st_connection != c) {
			continue;
		}
		if (st == &child->sa) {
			dbg("ignoring ourselves #%lu sharing connection %s",
			    st->st_serialno, c->name);
			continue;
		}
		if (st == &ike->sa) {
			dbg("ignoring IKE SA #%lu sharing connection %s with #%lu",
			    st->st_serialno, c->name, child->sa.st_serialno);
			continue;
		}
		dbg("#%lu and #%lu share connection %s",
		    child->sa.st_serialno, st->st_serialno,
		    c->name);
		return true;
	}

	return false;
}

/*
 * delete all states that were created for a given connection,
 * additionally delete any states for which func(st, c)
 * returns true.
 */
static void foreach_state_by_connection_func_delete(struct connection *c,
					      bool (*comparefunc)(
						      struct state *st,
						      struct connection *c))
{
	/* this kludge avoids an n^2 algorithm */

	/* We take two passes so that we delete any ISAKMP SAs last.
	 * This allows Delete Notifications to be sent.
	 * ?? We could probably double the performance by caching any
	 * ISAKMP SA states found in the first pass, avoiding a second.
	 */
	for (int pass = 0; pass != 2; pass++) {
		DBG(DBG_CONTROL, DBG_log("pass %d", pass));
		dbg("FOR_EACH_STATE_... in %s", __func__);
		struct state *this = NULL;
		FOR_EACH_STATE_NEW2OLD(this) {
			DBG(DBG_CONTROL,
			    DBG_log("state #%lu",
				this->st_serialno));

			/* on first pass, ignore established ISAKMP SA's */
			if (pass == 0 &&
			    IS_ISAKMP_SA_ESTABLISHED(this->st_state))
				continue;

			/* call comparison function */
			if ((*comparefunc)(this, c)) {
				/*
				 * XXX: this simingly redundant
				 * push/pop has the side effect
				 * suppressing the message 'deleting
				 * other state'.
				 */
				so_serial_t old_serialno = push_cur_state(this);
				delete_state(this);
				pop_cur_state(old_serialno);
			}
		}
	}
}

/*
 * Delete all states that have somehow not ben deleted yet
 * but using interfaces that are going down
 */

void delete_states_dead_interfaces(void)
{
	struct state *this = NULL;
	dbg("FOR_EACH_STATE_... in %s", __func__);
	FOR_EACH_STATE_NEW2OLD(this) {
		if (this->st_interface &&
		    this->st_interface->change == IFN_DELETE) {
			libreswan_log(
				"deleting lasting state #%lu on interface (%s) which is shutting down",
				this->st_serialno,
				this->st_interface->ip_dev->id_vname);
			delete_state(this);
			/* note: no md->st to clear */
		}
	}
}

/*
 * delete all states that were created for a given connection.
 * if relations == TRUE, then also delete states that share
 * the same phase 1 SA.
 */

static bool same_phase1_sa(struct state *this,
			   struct connection *c)
{
	return this->st_connection == c;
}

static bool same_phase1_sa_relations(struct state *this,
				     struct connection *c)
{
	so_serial_t parent_sa = c->newest_isakmp_sa;

	return this->st_connection == c ||
	       (parent_sa != SOS_NOBODY &&
		this->st_clonedfrom == parent_sa);
}

void delete_states_by_connection(struct connection *c, bool relations)
{
	enum connection_kind ck = c->kind;

	DBG(DBG_CONTROL, DBG_log("Deleting states for connection - %s",
		relations ? "including all other IPsec SA's of this IKE SA" :
			"not including other IPsec SA's"
		));

	/*
	 * save this connection's isakmp SA,
	 * since it will get set to later SOS_NOBODY
	 */
	if (ck == CK_INSTANCE)
		c->kind = CK_GOING_AWAY;

	foreach_state_by_connection_func_delete(c,
		relations ? same_phase1_sa_relations : same_phase1_sa);

	const struct spd_route *sr;

	for (sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		passert(sr->eroute_owner == SOS_NOBODY);
		passert(sr->routing != RT_ROUTED_TUNNEL);
	}

	if (ck == CK_INSTANCE) {
		c->kind = ck;
		delete_connection(c, relations);
	}
}

/*
 * Walk through the state table, and delete each state whose phase 1 (IKE)
 * peer is among those given.
 * This function is only called for ipsec whack --crash peer
 */
void delete_states_by_peer(const ip_address *peer)
{
	ip_address_buf peer_buf;
	const char *peerstr = ipstr(peer, &peer_buf);

	whack_log(RC_COMMENT, "restarting peer %s\n", peerstr);

	/* first restart the phase1s */
	for (int ph1 = 0; ph1 < 2; ph1++) {
		struct state *this;
		dbg("FOR_EACH_STATE_... in %s", __func__);
		FOR_EACH_STATE_NEW2OLD(this) {
			const struct connection *c = this->st_connection;
			DBG(DBG_CONTROL, {
				ipstr_buf b;
				DBG_log("comparing %s to %s",
					ipstr(&this->st_remoteaddr, &b),
					peerstr);
			});

			if (sameaddr(&this->st_remoteaddr, peer)) {
				if (ph1 == 0 && IS_IKE_SA(this)) {
					whack_log(RC_COMMENT,
						  "peer %s for connection %s crashed; replacing",
						  peerstr,
						  c->name);
					ipsecdoi_replace(this, 1);
				} else {
					event_force(EVENT_SA_REPLACE, this);
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
static struct state *duplicate_state(struct state *st,
				     enum sa_type sa_type,
				     const struct finite_state *fs)
{
	struct state *nst;
	char cib[CONN_INST_BUF];

	if (sa_type == IPSEC_SA) {
		/* record use of the Phase 1 / Parent state */
		st->st_outbound_count++;
		st->st_outbound_time = mononow();
	}

	nst = new_state(st->st_ike_version, fs,
			st->st_ike_spis.initiator,
			st->st_ike_spis.responder,
			sa_type);

	DBG(DBG_CONTROL,
		DBG_log("duplicating state object #%lu \"%s\"%s as #%lu for %s",
			 st->st_serialno,
			 st->st_connection->name,
			 fmt_conn_instance(st->st_connection, cib),
			 nst->st_serialno,
			 sa_type == IPSEC_SA ? "IPSEC SA" : "IKE SA"));

	nst->st_connection = st->st_connection;

	if (sa_type == IPSEC_SA) {
		nst->st_oakley = st->st_oakley;
	}

	nst->quirks = st->quirks;
	nst->hidden_variables = st->hidden_variables;
	nst->st_remoteaddr = st->st_remoteaddr;
	nst->st_remoteport = st->st_remoteport;
	nst->st_localaddr = st->st_localaddr;
	nst->st_localport = st->st_localport;
	nst->st_interface = st->st_interface;
	nst->st_clonedfrom = st->st_serialno;
	passert(nst->st_ike_version == st->st_ike_version);
	nst->st_ikev2_anon = st->st_ikev2_anon;
	nst->st_original_role = st->st_original_role;
	nst->st_seen_fragvid = st->st_seen_fragvid;
	nst->st_seen_fragments = st->st_seen_fragments;
	nst->st_seen_ppk = st->st_seen_ppk;
	nst->st_seen_redirect_sup = st->st_seen_redirect_sup;
	nst->st_seen_use_ipcomp = st->st_seen_use_ipcomp;
	nst->st_sent_redirect = st->st_sent_redirect;
	nst->st_event = NULL;

	/* these were set while we didn't have client state yet */
	/* we should really split the NOTIFY loop in two cleaner ones */
	nst->st_ipcomp.attrs = st->st_ipcomp.attrs;
	nst->st_ipcomp.present = st->st_ipcomp.present;
	nst->st_ipcomp.our_spi = st->st_ipcomp.our_spi;

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

		clone_nss_symkey_field(st_sk_d_no_ppk);
		clone_nss_symkey_field(st_sk_pi_no_ppk);
		clone_nss_symkey_field(st_sk_pr_no_ppk);
#   undef clone_nss_symkey_field

		/* v2 duplication of state */
#   define state_clone_chunk(CHUNK) \
		nst->CHUNK = clone_chunk(st->CHUNK, #CHUNK " in duplicate state")

		state_clone_chunk(st_ni);
		state_clone_chunk(st_nr);
		state_clone_chunk(st_skey_initiator_salt);
		state_clone_chunk(st_skey_responder_salt);

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

	return nst;
}

struct state *ikev1_duplicate_state(struct state *st)
{
	return duplicate_state(st, IPSEC_SA, &state_undefined);
}

struct child_sa *ikev2_duplicate_state(struct ike_sa *ike,
				       enum sa_type sa_type,
				       enum sa_role role)
{
	struct state *cst = duplicate_state(&ike->sa, sa_type, &state_undefined);
	cst->st_sa_role = role;
	struct child_sa *child = pexpect_child_sa(cst);
	v2_msgid_init_child(ike, child);
	return child;
}

void for_each_state(void (*f)(struct state *, void *data), void *data)
{
	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *st = NULL;
	FOR_EACH_STATE_NEW2OLD(st) {
		/*
		 * Since OLD_STATE might be deleted by f();
		 * save/restore using serialno.
		 */
		so_serial_t old_serialno = push_cur_state(st);
		(*f)(st, data);
		pop_cur_state(old_serialno);
	}
}

/*
 * Find a state object for an IKEv1 state
 */

struct state *find_state_ikev1(const ike_spis_t *ike_spis, msgid_t msgid)
{
	return state_by_ike_spis(IKEv1, SOS_IGNORE/*clonedfrom*/,
				 &msgid/*check v1 msgid*/,
				 ike_spis, NULL, NULL, __func__);
}

struct state *find_state_ikev1_init(const ike_spi_t *ike_initiator_spi,
				    msgid_t msgid)
{
	return state_by_ike_initiator_spi(IKEv1, SOS_IGNORE,
					  &msgid/*check v1 msgid*/,
					  ike_initiator_spi, __func__);
}

/*
 * Find the IKEv2 IKE SA with the specified SPIs.
 */
struct ike_sa *find_v2_ike_sa(const ike_spis_t *ike_spis)
{
	struct state *st = state_by_ike_spis(IKEv2, SOS_NOBODY/*clonedfrom*/,
					     NULL/*ignore v1 msgid*/,
					     ike_spis, NULL, NULL, __func__);
	return pexpect_ike_sa(st);
}

/*
 * Find an IKEv2 IKE SA with a matching SPIi.
 *
 * This is used doring the IKE_SA_INIT exchange where SPIr is either
 * zero (message request) or not-yet-known (message response).
 */
struct ike_sa *find_v2_ike_sa_by_initiator_spi(const ike_spi_t *ike_initiator_spi)
{
	struct state *st = state_by_ike_initiator_spi(IKEv2, SOS_NOBODY/*IKE_SA*/,
						      NULL/*ignore v2 msgid*/,
						      ike_initiator_spi, __func__);
	return pexpect_ike_sa(st);
}

/*
 * Find the SA (IKE or CHILD), within IKE's family, that initiated a
 * request using MSGID.
 *
 * Could use a linked list, but for now exploit hash table property
 * that children share hash with parent.
 */

struct request_filter {
	msgid_t msgid;
};

static bool v2_sa_by_initiator_mip_p(struct state *st, void *context)
{
	const struct request_filter *filter = context;
	return st->st_v2_msgid_wip.initiator == filter->msgid;
}

struct state *find_v2_sa_by_initiator_mip(struct ike_sa *ike, const msgid_t msgid)
{
	struct request_filter filter = {
		.msgid = msgid,
	};
	struct state *st = state_by_ike_spis(IKEv2, SOS_IGNORE/*see predicate*/,
					     NULL/*ignore v1 msgid*/, &ike->sa.st_ike_spis,
					     v2_sa_by_initiator_mip_p, &filter, __func__);
	pexpect(st == NULL ||
		st->st_clonedfrom == SOS_NOBODY ||
		st->st_clonedfrom == ike->sa.st_serialno);
	return st;
}

static bool v2_sa_by_responder_mip_p(struct state *st, void *context)
{
	const struct request_filter *filter = context;
	return st->st_v2_msgid_wip.responder == filter->msgid;
}

struct state *find_v2_sa_by_responder_mip(struct ike_sa *ike, const msgid_t msgid)
{
	struct request_filter filter = {
		.msgid = msgid,
	};
	struct state *st = state_by_ike_spis(IKEv2, SOS_IGNORE/*see predicate*/,
					     NULL/*ignore v1 msgid*/, &ike->sa.st_ike_spis,
					     v2_sa_by_responder_mip_p, &filter, __func__);
	pexpect(st == NULL ||
		st->st_clonedfrom == SOS_NOBODY ||
		st->st_clonedfrom == ike->sa.st_serialno);
	return st;
}

/*
 * Find an IKEv2 CHILD SA using the protocol and the (from our POV)
 * 'outbound' SPI.
 *
 * The remote end, when identifing a CHILD SA in a Delete or REKEY_SA
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
};

static bool v2_spi_predicate(struct state *st, void *context)
{
	struct v2_spi_filter *filter = context;

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
		if (pr->attrs.spi == filter->outbound_spi) {
			dbg("v2 CHILD SA #%lu found using their inbound (our outbound) SPI, in %s",
			    st->st_serialno,
			    st->st_state->name);
			return true;
		}
#if 0
		/* see function description above */
		if (pr->our_spi == filter->outbound_spi) {
			dbg("v2 CHILD SA #%lu found using our inbound (their outbound) !?! SPI, in %s",
			    st->st_serialno,
			    st->st_state->name);
			return true;
		}
#endif
	}
	return false;
}

struct child_sa *find_v2_child_sa_by_outbound_spi(struct ike_sa *ike,
						  uint8_t protoid,
						  ipsec_spi_t outbound_spi)
{
	struct v2_spi_filter filter = {
		.protoid = protoid,
		.outbound_spi = outbound_spi,
	};
	struct state *st = state_by_ike_spis(IKEv2, SOS_SOMEBODY/*child*/,
					     NULL/* ignore v1 msgid*/,
					     &ike->sa.st_ike_spis,
					     v2_spi_predicate, &filter, __func__);
	return pexpect_child_sa(st);
}

/*
 * Find a state object(s) with specific conn name/remote ip
 * and send IKEv2 informational.
 * Used for active redirect mechanism (RFC 5685)
 */
void find_states_and_redirect(const char *conn_name,
			      ip_address remote_ip,
			      char *redirect_gw)
{
	struct state *redirect_state = NULL;
	ipstr_buf b;

	if (conn_name == NULL) {
		dbg("FOR_EACH_STATE_... in %s", __func__);
		struct state *st = NULL;
		FOR_EACH_STATE_NEW2OLD(st) {
			if (sameaddr(&st->st_remoteaddr, &remote_ip) &&
			    IS_CHILD_SA(st))
			{
				redirect_state = st;
				/* we must clone it, because of pointer magic when free'ing it */
				st->st_active_redirect_gw = clone_str(redirect_gw, "redirect_gw address state clone");
				DBG_log("successfully found a state (#%lu) with remote ip address: %s",
					st->st_serialno, sensitive_ipstr(&remote_ip, &b));
				send_active_redirect_in_informational(st);
			}
		}

		if (redirect_state == NULL)
			loglog(RC_LOG_SERIOUS, "no active tunnel with remote ip address %s",
				sensitive_ipstr(&remote_ip, &b));
	} else {
		dbg("FOR_EACH_STATE_... in %s", __func__);
		struct state *st = NULL;
		FOR_EACH_STATE_NEW2OLD(st) {
			if (streq(conn_name, st->st_connection->name) &&
			    IS_CHILD_SA(st))
			{
				redirect_state = st;
				/* we must clone it, because of pointer magic when free'ing it */
				st->st_active_redirect_gw = clone_str(redirect_gw, "redirect_gw address state clone");
				DBG_log("successfully found a state (#%lu) with connection name \"%s\"",
					st->st_serialno, conn_name);
				send_active_redirect_in_informational(st);
			}
		}

		if (redirect_state == NULL)
			loglog(RC_LOG_SERIOUS, "no active tunnel for connection \"%s\"",
				conn_name);
	}
	pfree(redirect_gw);
}

/*
 * Find a state object.
 */
struct v1_msgid_filter {
	msgid_t msgid;
};

static bool v1_msgid_predicate(struct state *st, void *context)
{
	struct v1_msgid_filter *filter = context;
	dbg("peer and cookies match on #%lu; msgid=%08" PRIx32 " st_msgid=%08" PRIx32 " st_msgid_phase15=%08" PRIx32,
	    st->st_serialno, filter->msgid,
	    st->st_msgid, st->st_msgid_phase15);
	if ((st->st_msgid_phase15 != v1_MAINMODE_MSGID &&
	     filter->msgid == st->st_msgid_phase15) ||
	    filter->msgid == st->st_msgid) {
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
	return state_by_ike_spis(IKEv1, SOS_IGNORE,
				 NULL/*ignore v1 msgid; see predicate*/,
				 ike_spis, v1_msgid_predicate,
				 &filter, __func__);
}

/*
 * Find the state that sent a packet with this prefix
 * ??? this could be expensive -- it should be rate-limited to avoid DoS
 */
struct state *find_likely_sender(size_t packet_len, u_char *packet)
{
	if (packet_len >= sizeof(struct isakmp_hdr)) {
		dbg("FOR_EACH_STATE_... in %s", __func__);
		struct state *st = NULL;
		FOR_EACH_STATE_NEW2OLD(st) {
			if (st->st_tpacket.ptr != NULL &&
			    st->st_tpacket.len >= packet_len &&
			    memeq(st->st_tpacket.ptr, packet, packet_len))
			{
				return st;
			}
		}
	}
	return NULL;
}

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
	struct state  *bogusst = NULL;

	*bogus = FALSE;
	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *st;
	FOR_EACH_STATE_NEW2OLD(st) {
		const struct connection *c = st->st_connection;
		if (IS_IPSEC_SA_ESTABLISHED(st) &&
		    p1c->host_pair == c->host_pair &&
		    same_peer_ids(p1c, c, NULL))
		{
			struct ipsec_proto_info *pr =
				protoid == PROTO_IPSEC_AH ?
					&st->st_ah : &st->st_esp;

			if (pr->present) {
				if (pr->attrs.spi == spi) {
					*bogus = FALSE;
					return st;
				}

				if (pr->our_spi == spi) {
					*bogus = TRUE;
					bogusst = st;
					/* don't return! */
				}
			}
		}
	}
	return bogusst;
}

bool find_pending_phase2(const so_serial_t psn,
		const struct connection *c, lset_t ok_states)
{
	struct state *best = NULL;
	int n = 0;

	passert(psn >= SOS_FIRST);

	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *st = NULL;
	FOR_EACH_STATE_NEW2OLD(st) {
		if (LHAS(ok_states, st->st_state->kind) &&
		    IS_CHILD_SA(st) &&
		    st->st_clonedfrom == psn &&
		    streq(st->st_connection->name, c->name)) /* not instances */
		{
			n++;
			if (best == NULL || best->st_serialno < st->st_serialno)
				best = st;
		}
	}

	if (n > 0) {
		DBG(DBG_CONTROL,
			DBG_log("connection %s has %d pending IPsec negotiations ike #%lu last child state #%lu",
				c->name, n, psn, best->st_serialno));
	}

	return best != NULL;
}

/*
 * to initiate a new IPsec SA or to rekey IPsec
 * the IKE SA must be around for while. If IKE rekeying itself no new IPsec SA.
 */
bool ikev2_viable_parent(const struct ike_sa *ike)
{
	/* this check is defined only for an IKEv2 parent */
	if (ike->sa.st_ike_version != IKEv2)
		return TRUE;

	monotime_t now = mononow();
	const struct pluto_event *ev = ike->sa.st_event;
	long lifetime = monobefore(now, ev->ev_time) ?
				deltasecs(monotimediff(ev->ev_time, now)) :
				-1 * deltasecs(monotimediff(now, ev->ev_time));

	if (lifetime > PARENT_MIN_LIFE)
		/* in case st_margin == 0, insist minimum life */
		if (lifetime > deltasecs(ike->sa.st_replace_margin))
			return TRUE;

		loglog(RC_LOG_SERIOUS, "no new CREATE_CHILD_SA exchange using #%lu. Parent lifetime %ld < st_margin %jd",
				ike->sa.st_serialno, lifetime,
				deltasecs(ike->sa.st_replace_margin));

	return FALSE;
}

/*
 * Find newest Phase 1 negotiation state object for suitable for connection c
 */
struct state *find_phase1_state(const struct connection *c, lset_t ok_states)
{
	struct state *best = NULL;
	bool is_ikev2 = (c->policy & POLICY_IKEV1_ALLOW) == LEMPTY;

	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *st;
	FOR_EACH_STATE_NEW2OLD(st) {
		if (LHAS(ok_states, st->st_state->kind) &&
		    (st->st_ike_version == IKEv2) == is_ikev2 &&
		    c->host_pair == st->st_connection->host_pair &&
		    same_peer_ids(c, st->st_connection, NULL) &&
		    sameaddr(&st->st_remoteaddr, &c->spd.that.host_addr) &&
		    IS_IKE_SA(st) &&
		    (best == NULL || best->st_serialno < st->st_serialno))
		{
			best = st;
		}
	}

	return best;
}

void state_eroute_usage(const ip_subnet *ours, const ip_subnet *his,
			unsigned long count, monotime_t nw)
{
	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *st = NULL;
	FOR_EACH_STATE_NEW2OLD(st) {
		struct connection *c = st->st_connection;

		/* XXX spd-enum */
		if (IS_IPSEC_SA_ESTABLISHED(st) &&
		    c->spd.eroute_owner == st->st_serialno &&
		    c->spd.routing == RT_ROUTED_TUNNEL &&
		    samesubnet(&c->spd.this.client, ours) &&
		    samesubnet(&c->spd.that.client, his)) {
			if (st->st_outbound_count != count) {
				st->st_outbound_count = count;
				st->st_outbound_time = nw;
			}
			return;
		}
	}
	DBG(DBG_CONTROL, {
		char ourst[SUBNETTOT_BUF];
		char hist[SUBNETTOT_BUF];

		subnettot(ours, 0, ourst, sizeof(ourst));
		subnettot(his, 0, hist, sizeof(hist));
		DBG_log("unknown tunnel eroute %s -> %s found in scan",
			ourst, hist);
	});
}

/* note: this mutates *st by calling get_sa_info */
void fmt_list_traffic(struct state *st, char *state_buf,
		      const size_t state_buf_len)
{
	const struct connection *c = st->st_connection;
	char inst[CONN_INST_BUF];
	char traffic_buf[512];
	char thatidbuf[IDTOA_BUF] ;

	state_buf[0] = '\0';   /* default to empty */
	traffic_buf[0] = '\0';
	thatidbuf[0] = '\0';

	if (IS_IKE_SA(st))
		return; /* ignore non-IPsec states */

	if (!IS_IPSEC_SA_ESTABLISHED(st))
		return; /* ignore non established states */

	fmt_conn_instance(c, inst);

	{
		char *mode = st->st_esp.present ? "ESP" : st->st_ah.present ? "AH" : st->st_ipcomp.present ? "IPCOMP" : "UNKNOWN";
		char *mbcp = traffic_buf + snprintf(traffic_buf,
				sizeof(traffic_buf) - 1, ", type=%s, add_time=%" PRIu64, mode,  st->st_esp.add_time);

		if (get_sa_info(st, TRUE, NULL)) {
			size_t buf_len =  traffic_buf + sizeof(traffic_buf) - mbcp;
			unsigned inb = st->st_esp.present ? st->st_esp.our_bytes:
				st->st_ah.present ? st->st_ah.our_bytes :
				st->st_ipcomp.present ? st->st_ipcomp.our_bytes : 0;
			mbcp += snprintf(mbcp, buf_len - 1, ", inBytes=%u", inb);
		}

		if (get_sa_info(st, FALSE, NULL)) {
			size_t buf_len =  traffic_buf + sizeof(traffic_buf) - mbcp;
			unsigned outb = st->st_esp.present ? st->st_esp.peer_bytes :
				st->st_ah.present ? st->st_ah.peer_bytes :
				st->st_ipcomp.present ? st->st_ipcomp.peer_bytes : 0;
			snprintf(mbcp, buf_len - 1, ", outBytes=%u", outb);
		}
	}

	char lease_ip[SUBNETTOT_BUF] = "";
	if (c->spd.that.has_lease) {
		/*
		 * "this" gave "that" a lease from "this" address
		 * pool.
		 */
		subnettot(&c->spd.that.client, 0, lease_ip, sizeof(lease_ip));
	} else if (c->spd.this.has_internal_address) {
		/*
		 * "this" received an internal address from "that";
		 * presumably from "that"'s address pool.
		 */
		subnettot(&c->spd.this.client, 0, lease_ip, sizeof(lease_ip));
	}

	if (st->st_xauth_username[0] == '\0') {
		idtoa(&c->spd.that.id, thatidbuf, sizeof(thatidbuf));
	}

	snprintf(state_buf, state_buf_len,
		 "#%lu: \"%s\"%s%s%s%s%s%s%s%s%s",
		 st->st_serialno,
		 c->name, inst,
		 (st->st_xauth_username[0] != '\0') ? ", username=" : "",
		 (st->st_xauth_username[0] != '\0') ? st->st_xauth_username : "",
		 (traffic_buf[0] != '\0') ? traffic_buf : "",
		 thatidbuf[0] != '\0' ? ", id='" : "",
		 thatidbuf[0] != '\0' ? thatidbuf : "",
		 thatidbuf[0] != '\0' ? "'" : "",
		 lease_ip[0] != '\0' ? ", lease=" : "",
		 lease_ip[0] != '\0' ? lease_ip : ""
		);
}

/*
 * odd fact: st cannot be const because we call get_sa_info on it
 */
void fmt_state(struct state *st, const monotime_t now,
	       char *state_buf, const size_t state_buf_len,
	       char *state_buf2, const size_t state_buf2_len)
{
	/* what the heck is interesting about a state? */
	const struct connection *c = st->st_connection;
	char inst[CONN_INST_BUF];
	char dpdbuf[128];
	char traffic_buf[512], *mbcp;
	const char *np1 = c->newest_isakmp_sa == st->st_serialno ?
			  "; newest ISAKMP" : "";
	const char *np2 = c->newest_ipsec_sa == st->st_serialno ?
			  "; newest IPSEC" : "";
	/* XXX spd-enum */
	const char *eo = c->spd.eroute_owner == st->st_serialno ?
			 "; eroute owner" : "";

	fmt_conn_instance(c, inst);

	dpdbuf[0] = '\0';	/* default to empty string */
	if (IS_IPSEC_SA_ESTABLISHED(st)) {
		snprintf(dpdbuf, sizeof(dpdbuf), "; isakmp#%lu",
			 st->st_clonedfrom);
	} else {
		if (st->hidden_variables.st_peer_supports_dpd) {
			/* ??? why is printing -1 better than 0? */
			snprintf(dpdbuf, sizeof(dpdbuf),
				 "; lastdpd=%jds(seq in:%u out:%u)",
				 !is_monotime_epoch(st->st_last_dpd) ?
					deltasecs(monotimediff(mononow(), st->st_last_dpd)) : (intmax_t)-1,
				 st->st_dpd_seqno,
				 st->st_dpd_expectseqno);
		} else if (dpd_active_locally(st) && (st->st_ike_version == IKEv2)) {
			/* stats are on parent sa */
			if (IS_CHILD_SA(st)) {
				struct state *pst = state_with_serialno(st->st_clonedfrom);

				if (pst != NULL) {
					snprintf(dpdbuf, sizeof(dpdbuf),
						"; lastlive=%jds",
						 !is_monotime_epoch(pst->st_last_liveness) ?
						 deltasecs(monotimediff(mononow(), pst->st_last_liveness)) :
						0);
				}
			}
		} else {
			if (st->st_ike_version == IKEv1)
				snprintf(dpdbuf, sizeof(dpdbuf), "; nodpd");
		}
	}

	intmax_t delta;
	if (st->st_event != NULL) {
		delta = deltasecs(monotimediff(st->st_event->ev_time, now));
	} else {
		delta = -1;	/* ??? sort of odd signifier */
	}

	snprintf(state_buf, state_buf_len,
		 "#%lu: \"%s\"%s:%u %s (%s); %s in %jds%s%s%s%s; %s;",
		 st->st_serialno,
		 c->name, inst,
		 st->st_remoteport,
		 st->st_state->name,
		 st->st_state->story,
		 st->st_event == NULL ? "none" :
			enum_name(&timer_event_names, st->st_event->ev_type),
		 delta,
		 np1, np2, eo, dpdbuf,
		 (st->st_offloaded_task != NULL && !st->st_v1_offloaded_task_in_background)
		 ? "crypto_calculating" :
			st->st_suspended_md != NULL ?  "crypto/dns-lookup" :
			"idle");

	/* print out SPIs if SAs are established */
	if (state_buf2_len != 0)
		state_buf2[0] = '\0';   /* default to empty */
	if (IS_IPSEC_SA_ESTABLISHED(st)) {
		char lastused[40];      /* should be plenty long enough */
		char buf[SATOT_BUF * 6 + 1];
		char *p = buf;

#	define add_said(adst, aspi, aproto) { \
		ip_said s; \
		\
		initsaid(adst, aspi, aproto, &s); \
		if (p < &buf[sizeof(buf) - 1]) \
		{ \
			*p++ = ' '; \
			p += satot(&s, 0, p, &buf[sizeof(buf)] - p) - 1; \
		} \
}

		/*
		 * XXX - mcr last used is really an attribute of
		 * the connection
		 */
		lastused[0] = '\0';
		if (c->spd.eroute_owner == st->st_serialno &&
		    st->st_outbound_count != 0) {
			snprintf(lastused, sizeof(lastused),
				 " used %jds ago;",
				 deltasecs(monotimediff(mononow(),
							st->st_outbound_time)));
		}

		mbcp = traffic_buf +
		       snprintf(traffic_buf, sizeof(traffic_buf) - 1,
				"Traffic:");

		*p = '\0';
		if (st->st_ah.present) {
			add_said(&c->spd.that.host_addr, st->st_ah.attrs.spi,
				 SA_AH);
			if (get_sa_info(st, FALSE, NULL)) {
				mbcp = readable_humber(st->st_ah.peer_bytes,
						       mbcp,
						       traffic_buf +
							  sizeof(traffic_buf),
						       " AHout=");
			}
			add_said(&c->spd.this.host_addr, st->st_ah.our_spi,
				 SA_AH);
			if (get_sa_info(st, TRUE, NULL)) {
				mbcp = readable_humber(st->st_ah.our_bytes,
						       mbcp,
						       traffic_buf +
							 sizeof(traffic_buf),
						       " AHin=");
			}
			mbcp = readable_humber(
					(u_long)st->st_ah.attrs.life_kilobytes,
					mbcp,
					traffic_buf +
					  sizeof(traffic_buf),
					"! AHmax=");
		}
		if (st->st_esp.present) {
			add_said(&c->spd.that.host_addr, st->st_esp.attrs.spi,
				 SA_ESP);
			if (get_sa_info(st, TRUE, NULL)) {
				mbcp = readable_humber(st->st_esp.our_bytes,
						       mbcp,
						       traffic_buf +
							 sizeof(traffic_buf),
						       " ESPin=");
			}
			add_said(&c->spd.this.host_addr, st->st_esp.our_spi,
				 SA_ESP);
			if (get_sa_info(st, FALSE, NULL)) {
				mbcp = readable_humber(st->st_esp.peer_bytes,
						       mbcp,
						       traffic_buf +
							 sizeof(traffic_buf),
						       " ESPout=");
			}

			mbcp = readable_humber(
					(u_long)st->st_esp.attrs.life_kilobytes,
					mbcp,
					traffic_buf +
					  sizeof(traffic_buf),
					"! ESPmax=");
		}
		if (st->st_ipcomp.present) {
			add_said(&c->spd.that.host_addr,
				 st->st_ipcomp.attrs.spi, SA_COMP);
			if (get_sa_info(st, FALSE, NULL)) {
				mbcp = readable_humber(
						st->st_ipcomp.peer_bytes,
						mbcp,
						traffic_buf +
						  sizeof(traffic_buf),
						" IPCOMPout=");
			}
			add_said(&c->spd.this.host_addr, st->st_ipcomp.our_spi,
				 SA_COMP);
			if (get_sa_info(st, TRUE, NULL)) {
				mbcp = readable_humber(
						st->st_ipcomp.our_bytes,
						mbcp,
						traffic_buf +
						  sizeof(traffic_buf),
						" IPCOMPin=");
			}

			/* mbcp not subsequently used */
			mbcp = readable_humber(
					(u_long)st->st_ipcomp.attrs.life_kilobytes,
					mbcp,
					traffic_buf + sizeof(traffic_buf),
					"! IPCOMPmax=");
		}

#if defined(NETKEY_SUPPORT) || defined(KLIPS)
		if (st->st_ah.attrs.encapsulation ==
			ENCAPSULATION_MODE_TUNNEL ||
			st->st_esp.attrs.encapsulation ==
			ENCAPSULATION_MODE_TUNNEL ||
			st->st_ipcomp.attrs.encapsulation ==
			ENCAPSULATION_MODE_TUNNEL) {
			add_said(&c->spd.that.host_addr, st->st_tunnel_out_spi,
				SA_IPIP);
			add_said(&c->spd.this.host_addr, st->st_tunnel_in_spi,
				SA_IPIP);
		}
#endif

		snprintf(state_buf2, state_buf2_len,
			"#%lu: \"%s\"%s%s%s ref=%" PRIu32 " refhim=%" PRIu32 " %s %s%s",
			st->st_serialno,
			c->name, inst,
			lastused,
			buf,
			st->st_ref,
			st->st_refhim,
			traffic_buf,
			(st->st_xauth_username[0] != '\0') ? "username=" : "",
			(st->st_xauth_username[0] != '\0') ? st->st_xauth_username : "");

#       undef add_said
	}
}

/*
 * sorting logic is:
 *  name
 *  state serial no#
 */

static int state_compare_serial(const void *a, const void *b)
{
	const struct state *sap = *(const struct state *const *)a;
	const struct state *sbp = *(const struct state *const *)b;
	const so_serial_t a_sn = sap->st_serialno;
	const so_serial_t b_sn = sbp->st_serialno;
	struct connection *ca = sap->st_connection;
	struct connection *cb = sbp->st_connection;
	int ret;

	ret = strcmp(ca->name, cb->name);
	if (ret != 0)
		return ret;

	return a_sn < b_sn ? -1 : a_sn > b_sn ? 1 : 0;
}

/*
 * sorting logic is:
 *
 *  name
 *  type
 *  instance#
 *  isakmp_sa (XXX probably wrong)
 *  state_compare_serial above
 */
static int state_compare_connection(const void *a, const void *b)
{
	const struct state *sap = *(const struct state *const *)a;
	struct connection *ca = sap->st_connection;
	const struct state *sbp = *(const struct state *const *)b;
	struct connection *cb = sbp->st_connection;

	/* DBG_log("comparing %s to %s", ca->name, cb->name); */

	int order = connection_compare(ca, cb);
	if (order != 0) {
		return order;
	}

	return state_compare_serial(a, b);
}

/*
 * NULL terminated array of state pointers.
 */
static struct state **sort_states(int (*sort_fn)(const void *, const void *))
{
	/* COUNT the number of states. */
	int count = 0;
	{
		dbg("FOR_EACH_STATE_... in %s", __func__);
		struct state *st;
		FOR_EACH_STATE_NEW2OLD(st) {
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

		dbg("FOR_EACH_STATE_... in %s", __func__);
		struct state *st;
		FOR_EACH_STATE_NEW2OLD(st) {
			passert(st != NULL);
			array[p++] = st;
		}
		passert(p == count);
		array[p] = NULL;
	}

	/* sort it!  */
	qsort(array, count, sizeof(struct state *), sort_fn);

	return array;
}

static int log_trafic_state(struct connection *c, void *arg UNUSED)
{
	char state_buf[LOG_WIDTH];
	struct state *st = state_by_serialno(c->newest_ipsec_sa);

	if (st == NULL)
		return 0;

	fmt_list_traffic(st, state_buf, sizeof(state_buf));
	if (state_buf[0] != '\0')
		whack_log(RC_INFORMATIONAL_TRAFFIC, "%s", state_buf);

	return 1;
}

void show_traffic_status(const char *name)
{
	if (name == NULL) {
		struct state **array = sort_states(state_compare_serial);

		/* now print sorted results */
		if (array != NULL) {
			int i;
			for (i = 0; array[i] != NULL; i++) {
				char state_buf[LOG_WIDTH];
				fmt_list_traffic(array[i], state_buf, sizeof(state_buf));
				if (state_buf[0] != '\0')
					whack_log(RC_INFORMATIONAL_TRAFFIC, "%s", state_buf);
			}
			pfree(array);
		}
	} else {
		struct connection *c = conn_by_name(name, TRUE, TRUE);

		if (c != NULL) {
			(void) log_trafic_state(c, NULL);
		} else {
			int count = foreach_connection_by_alias(name, log_trafic_state, NULL);

			if (count == 0)
				loglog(RC_UNKNOWN_NAME,
					"no such connection or aliased connection named \"%s\"", name);
		}
	}
}

void show_states_status(bool brief)
{
	whack_log(RC_COMMENT, " ");             /* spacer */
	whack_log(RC_COMMENT, "State Information: DDoS cookies %s, %s new IKE connections",
		  require_ddos_cookies() ? "REQUIRED" : "not required",
		  drop_new_exchanges() ? "NOT ACCEPTING" : "Accepting");

	whack_log(RC_COMMENT, "IKE SAs: total("PRI_CAT"), half-open("PRI_CAT"), open("PRI_CAT"), authenticated("PRI_CAT"), anonymous("PRI_CAT")",
		  total_ike_sa(),
		  cat_count[CAT_HALF_OPEN_IKE_SA],
		  cat_count[CAT_OPEN_IKE_SA],
		  cat_count_ike_sa[CAT_AUTHENTICATED],
		  cat_count_ike_sa[CAT_ANONYMOUS]);
	whack_log(RC_COMMENT, "IPsec SAs: total("PRI_CAT"), authenticated("PRI_CAT"), anonymous("PRI_CAT")",
		  cat_count[CAT_ESTABLISHED_CHILD_SA],
		  cat_count_child_sa[CAT_AUTHENTICATED],
		  cat_count_child_sa[CAT_ANONYMOUS]);
	whack_log(RC_COMMENT, " ");             /* spacer */

	if (brief)
		return;

	struct state **array = sort_states(state_compare_connection);

	if (array != NULL) {
		monotime_t n = mononow();
		/* now print sorted results */
		int i;
		for (i = 0; array[i] != NULL; i++) {
			struct state *st = array[i];

			char state_buf[LOG_WIDTH];
			char state_buf2[LOG_WIDTH];
			fmt_state(st, n, state_buf, sizeof(state_buf),
				  state_buf2, sizeof(state_buf2));
			whack_log(RC_COMMENT, "%s", state_buf);
			if (state_buf2[0] != '\0')
				whack_log(RC_COMMENT, "%s", state_buf2);

			/* show any associated pending Phase 2s */
			if (IS_IKE_SA(st))
				show_pending_phase2(st->st_connection, st);
		}

		whack_log(RC_COMMENT, " "); /* spacer */
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
	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *st;
	FOR_EACH_STATE_NEW2OLD(st) {
		if (st->st_ipcomp.present) {
			cpi_t c = ntohl(st->st_ipcomp.our_spi) - base;

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
ipsec_spi_t uniquify_his_cpi(ipsec_spi_t cpi, const struct state *st, int tries)
{
	/* cpi is in network order so first two bytes are the high order ones */
	get_rnd_bytes((u_char *)&cpi, 2);

	/*
	 * Make sure that the result is unique.
	 * Hard work.  If there is no unique value, we'll loop forever!
	 */
	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *s;
	FOR_EACH_STATE_NEW2OLD(s) {
		if (s->st_ipcomp.present &&
		    sameaddr(&s->st_connection->spd.that.host_addr,
			     &st->st_connection->spd.that.host_addr) &&
		    cpi == s->st_ipcomp.attrs.spi)
		{
			if (++tries == 20)
				return 0; /* FAILURE */
			return uniquify_his_cpi(cpi, st, tries);
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
void update_ike_endpoints(struct state *st,
			  const struct msg_digest *md)
{
	/* caller must ensure we are not behind NAT */
	st->st_remoteaddr = md->sender;
	st->st_remoteport = hportof(&md->sender);
	st->st_localaddr = md->iface->ip_addr;
	st->st_localport = md->iface->port;
	st->st_interface = md->iface;
}

/*
 * We have successfully decrypted this packet, so we can update
 * the remote IP / port
 */
bool update_mobike_endpoints(struct state *pst,
				const struct msg_digest *md)
{
	struct connection *c = pst->st_connection;
	int af = addrtypeof(&md->iface->ip_addr);
	ipstr_buf b;
	ip_address *old_addr, *new_addr;
	uint16_t old_port, new_port;
	bool ret = FALSE;

	/*
	 * AA_201705 is this the right way to find Child SA(s)?
	 * would it work if there are multiple Child SAs on this parent??
	 * would it work if the Child SA connection is different from IKE SA?
	 * for now just do this one connection, later on loop over all Child SAs
	 */
	struct state *cst = state_with_serialno(c->newest_ipsec_sa);
	const bool msg_r = is_msg_response(md); /* MOBIKE inititor */


	/* check for all conditions before updating IPsec SA's */
	if (af != addrtypeof(&c->spd.that.host_addr)) {
		libreswan_log("MOBIKE: AF change switching between v4 and v6 not supported");
		return ret;
	}

	passert(cst->st_connection == pst->st_connection);

	if (msg_r) {
		/* MOBIKE initiator */
		old_addr = &pst->st_localaddr;
		old_port = pst->st_localport;

		cst->st_mobike_localaddr = pst->st_mobike_localaddr;
		cst->st_mobike_localport = pst->st_mobike_localport;
		cst->st_mobike_host_nexthop = pst->st_mobike_host_nexthop;

		new_addr = &pst->st_mobike_localaddr;
		new_port = pst->st_mobike_localport;
	} else {
		/* MOBIKE responder */
		old_addr = &pst->st_remoteaddr;
		old_port = pst->st_remoteport;

		cst->st_mobike_remoteaddr = md->sender;
		cst->st_mobike_remoteport = hportof(&md->sender);
		pst->st_mobike_remoteaddr = md->sender;
		pst->st_mobike_remoteport = hportof(&md->sender);

		new_addr = &pst->st_mobike_remoteaddr;
		new_port = pst->st_mobike_remoteport;
	}

	char buf[256];
	ipstr_buf old;
	ipstr_buf new;
	snprintf(buf, sizeof(buf), "MOBIKE update %s address %s:%u -> %s:%u",
			msg_r ? "local" : "remote",
			sensitive_ipstr(old_addr, &old),
			old_port,
			sensitive_ipstr(new_addr, &new), new_port);

	DBG(DBG_CONTROLMORE, DBG_log("#%lu pst=#%lu %s", cst->st_serialno,
					pst->st_serialno, buf));

	if (sameaddr(old_addr, new_addr) && new_port == old_port) {
		if (!msg_r) {
			/* on responder NAT could hide end-to-end change */
			libreswan_log("MOBIKE success no change to kernel SA same IP address ad port  %s:%u",
						sensitive_ipstr(old_addr, &b), old_port);

			return TRUE;
		}
	}

	if (!migrate_ipsec_sa(cst)) {
		libreswan_log("%s FAILED", buf);
		return ret;
	}

	libreswan_log(" success %s", buf);

	if (msg_r) {
		/* MOBIKE initiator */
		c->spd.this.host_addr = cst->st_mobike_localaddr;
		c->spd.this.host_port = cst->st_mobike_localport;
		c->spd.this.host_nexthop  = cst->st_mobike_host_nexthop;

		pst->st_localaddr = cst->st_localaddr = md->iface->ip_addr;
		pst->st_localport = cst->st_localport = md->iface->port;
		pst->st_interface = cst->st_interface = md->iface;
	} else {
		/* MOBIKE responder */
		c->spd.that.host_addr = md->sender;
		c->spd.that.host_port = hportof(&md->sender);

		/* for the consistency, correct output in ipsec status */
		cst->st_remoteaddr = pst->st_remoteaddr = md->sender;
		cst->st_remoteport = pst->st_remoteport = hportof(&md->sender);
		cst->st_localaddr = pst->st_localaddr = md->iface->ip_addr;
		cst->st_localport = pst->st_localport = md->iface->port;
		cst->st_interface = pst->st_interface = md->iface;
	}

	/* reset liveness */
	pst->st_pend_liveness = FALSE;
	pst->st_last_liveness = monotime_epoch;

	delete_oriented_hp(c); /* hp list may have changed */
	if (!orient(c)) {
		PEXPECT_LOG("%s after mobike failed", "orient");
	}
	connect_to_host_pair(c); /* re-create hp listing */

	if (msg_r) {
		/* MOBIKE initiator */
		migration_up(cst->st_connection, cst);
		if (dpd_active_locally(cst) && cst->st_liveness_event == NULL) {
			DBG(DBG_DPD, DBG_log("dpd re-enabled after mobike, scheduling ikev2 liveness checks"));
			deltatime_t delay = deltatime_max(cst->st_connection->dpd_delay, deltatime(MIN_LIVENESS));
			event_schedule(EVENT_v2_LIVENESS, delay, cst);
		}
	}

	return TRUE;
}

void set_state_ike_endpoints(struct state *st,
			     struct connection *c)
{
	/* reset our choice of interface */
	c->interface = NULL;
	orient(c);
	st->st_interface = c->interface;
	passert(st->st_interface != NULL);

	st->st_localaddr  = c->spd.this.host_addr;
	st->st_localport  = c->spd.this.host_port;
	st->st_remoteaddr = c->spd.that.host_addr;
	st->st_remoteport = c->spd.that.host_port;

}

/* seems to be a good spot for now */
bool dpd_active_locally(const struct state *st)
{
	return deltasecs(st->st_connection->dpd_delay) != 0 &&
		deltasecs(st->st_connection->dpd_timeout) != 0;
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
	 * TO is in the process of being emancipated.  It's
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
	state_by_ike_spis(IKEv2, from->sa.st_serialno,
			  NULL/*ignore v1 msgid*/,
			  &from->sa.st_ike_spis,
			  v2_migrate_predicate, &filter, __func__);
}

struct delete_filter {
	bool v2_responder_state;
};

static bool delete_predicate(struct state *st, void *context)
{
	struct delete_filter *filter = context;
	if (filter->v2_responder_state) {
		/*
		 * XXX: Suspect forcing the state to ..._DEL is a
		 * secret code for do-not send a delete notification?
		 */
		change_state(st, STATE_CHILDSA_DEL);
	}
	delete_state(st);
	return false; /* keep going */
}

void delete_my_family(struct state *pst, bool v2_responder_state)
{
	/*
	 * We are a parent: delete our children and
	 * then prepare to delete ourself.
	 * Our children will be on the same hash chain
	 * because we share IKE SPIs.
	 */
	passert(!IS_CHILD_SA(pst));	/* we had better be a parent */
	struct delete_filter delete_filter = {
		.v2_responder_state = v2_responder_state,
	};
	state_by_ike_spis(pst->st_ike_version, pst->st_serialno,
			  NULL/*ignore v1 msgid*/, &pst->st_ike_spis,
			  delete_predicate, &delete_filter,
			  __func__);
	/* delete self */
	if (v2_responder_state) {
		/*
		 * XXX: Suspect forcing the state to ..._DEL is a
		 * secret code for do-not send a delete notification?
		 */
		change_state(pst, STATE_IKESA_DEL);
	}
	delete_state(pst);
	/* note: no md->st to clear */
}

/*
 * if the state is too busy to process a packet, say so
 *
 * Two things indicate this - st_suspended_md is non-NULL or there's
 * an offloaded task.
 */

struct msg_digest *unsuspend_md(struct state *st)
{
	/* don't assume it is non-NULL */
	struct msg_digest *md = st->st_suspended_md;
	st->st_suspended_md = NULL;
	st->st_suspended_md_func = NULL;
	st->st_suspended_md_line = 0;
	return md;
}

bool state_is_busy(const struct state *st)
{
	passert(st != NULL);
	/*
	 * Ignore a packet if the state has a suspended state
	 * transition.  Probably a duplicated packet but the original
	 * packet is not yet recorded in st->st_rpacket, so duplicate
	 * checking won't catch.
	 *
	 * ??? Should the packet be recorded earlier to improve
	 * diagnosis?
	 *
	 * See comments in state.h.
	 *
	 * ST_SUSPENDED_MD acts as a poor proxy for indicating a busy
	 * state.  For instance, the initial initiator (both IKEv1 and
	 * IKEv2) doesn't have a suspended MD.  To get around this a
	 * 'fake_md' MD is created.
	 *
	 * XXX: what about xauth? It sets ST_SUSPENDED_MD.
	 */
	if (st->st_suspended_md != NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("#%lu is busy; has a suspended MD", st->st_serialno));
		return true;
	}
	/*
	 * If IKEv1 is doing something in the background then the
	 * state isn't busy.
	 */
	if (st->st_v1_offloaded_task_in_background) {
		pexpect(st->st_offloaded_task != NULL);
		DBG(DBG_CONTROLMORE,
		    DBG_log("#%lu is idle; has background offloaded task", st->st_serialno));
		return false;
	}
	/*
	 * If this state is busy calculating.
	 */
	if (st->st_offloaded_task != NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("#%lu is busy; has an offloaded task",
			    st->st_serialno));
		return true;
	}
	DBG(DBG_CONTROLMORE, DBG_log("#%lu is idle", st->st_serialno));
	return false;
}

bool verbose_state_busy(const struct state *st)
{
	if (st == NULL) {
		DBG(DBG_CONTROLMORE, DBG_log("#null state always idle"));
		return false;
	}
	if (!state_is_busy(st)) {
		DBG(DBG_CONTROLMORE, DBG_log("#%lu idle", st->st_serialno));
		return false;
	}
	if (st->st_suspended_md != NULL) {
		/* not whack */
		log_to_log("discarding packet received during asynchronous work (DNS or crypto) in %s",
			   st->st_state->name);
	} else if (st->st_offloaded_task != NULL) {
		libreswan_log("message received while calculating. Ignored.");
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

void show_globalstate_status(void)
{
	unsigned shunts = show_shunt_count();

	whack_log_comment("config.setup.ike.ddos_threshold=%u", pluto_ddos_threshold);
	whack_log_comment("config.setup.ike.max_halfopen=%u", pluto_max_halfopen);

	/* technically shunts are not a struct state's - but makes it easier to group */
	whack_log_comment("current.states.all="PRI_CAT, shunts + total_sa());
	whack_log_comment("current.states.ipsec="PRI_CAT, cat_count[CAT_ESTABLISHED_CHILD_SA]);
	whack_log_comment("current.states.ike="PRI_CAT, total_ike_sa());
	whack_log_comment("current.states.shunts=%u", shunts);
	whack_log_comment("current.states.iketype.anonymous="PRI_CAT,
			  cat_count_ike_sa[CAT_ANONYMOUS]);
	whack_log_comment("current.states.iketype.authenticated="PRI_CAT,
			  cat_count_ike_sa[CAT_AUTHENTICATED]);
	whack_log_comment("current.states.iketype.halfopen="PRI_CAT,
			  cat_count[CAT_HALF_OPEN_IKE_SA]);
	whack_log_comment("current.states.iketype.open="PRI_CAT,
			  cat_count[CAT_OPEN_IKE_SA]);
	for (enum state_kind s = STATE_IKEv1_FLOOR; s < STATE_IKEv1_ROOF; s++) {
		whack_log_comment("current.states.enumerate.%s="PRI_CAT,
			enum_name(&state_names, s), state_count[s]);
	}
	for (enum state_kind s = STATE_IKEv2_FLOOR; s < STATE_IKEv2_ROOF; s++) {
		whack_log_comment("current.states.enumerate.%s="PRI_CAT,
			enum_name(&state_names, s), state_count[s]);
	}
}

static void log_newest_sa_change(const char *f, so_serial_t old_ipsec_sa,
			  struct state *const st)
{
	DBG(DBG_CONTROLMORE,
			DBG_log("%s: instance %s[%lu], setting %s newest_ipsec_sa to #%lu (was #%lu) (spd.eroute=#%lu) cloned from #%lu",
				f, st->st_connection->name,
				st->st_connection->instance_serial,
				enum_name(&ike_version_names, st->st_ike_version),
				st->st_connection->newest_ipsec_sa, old_ipsec_sa,
				st->st_connection->spd.eroute_owner,
				st->st_clonedfrom));
}

void set_newest_ipsec_sa(const char *m, struct state *const st)
{
	so_serial_t old_ipsec_sa = st->st_connection->newest_ipsec_sa;

	st->st_connection->newest_ipsec_sa = st->st_serialno;
	log_newest_sa_change(m, old_ipsec_sa, st);

}

void record_newaddr(ip_address *ip, char *a_type)
{
	ipstr_buf ip_str;
	DBG(DBG_KERNEL, DBG_log("XFRM RTM_NEWADDR %s %s",
				ipstr(ip, &ip_str), a_type));
	dbg("FOR_EACH_STATE_... via for_each_state( in %s", __func__);
	for_each_state(ikev2_record_newaddr, ip);
}

void record_deladdr(ip_address *ip, char *a_type)
{
	ipstr_buf ip_str;
	DBG(DBG_KERNEL, DBG_log("XFRM RTM_DELADDR %s %s",
				ipstr(ip, &ip_str), a_type));
	dbg("FOR_EACH_STATE_... via for_each_state in %s", __func__);
	for_each_state(ikev2_record_deladdr, ip);
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

/*
 * an ISAKMP SA has been established.
 * Note the serial number, and release any connections with
 * the same peer ID but different peer IP address.
 *
 * Called by IKEv1 and IKEv2 when the IKE SA is established.
 * It checks if the freshly established connection needs is
 * replacing an established version of itself.
 *
 * The use of uniqueIDs is mostly historic and might be removed
 * in a future version. It is ignored for PSK based connections,
 * which only act based on being a "server using PSK".
 *
 * IKEv1 code does not send or process INITIAL_CONTACT
 * IKEv2 codes does so we take it into account.
 */
void ISAKMP_SA_established(const struct state *pst)
{
	struct connection *c = pst->st_connection;

	/* NULL authentication can never replaced - it is all anonymous */
	if (LIN(POLICY_AUTH_NULL, c->policy) ||
	    c->spd.that.authby == AUTH_NULL ||
	    c->spd.this.authby == AUTH_NULL) {
		DBG(DBG_CONTROL, DBG_log("NULL Authentication - all clients appear identical"));
	} else if (c->spd.this.xauth_server && LIN(POLICY_PSK, c->policy)) {
		/*
		 * If we are a server and use PSK, all clients use the same group ID
		 * Note that "xauth_server" also refers to IKEv2 CP
		 */
		DBG(DBG_CONTROL, DBG_log("We are a server using PSK and clients are using a group ID"));
	} else if (!uniqueIDs) {
		DBG(DBG_CONTROL, DBG_log("uniqueIDs disabled, not contemplating releasing older self"));
	} else {
		/*
		 * for all existing connections: if the same Phase 1 IDs are used,
		 * unorient the (old) connection (if different from current connection)
		 * Only do this for connections with the same name (can be shared ike sa)
		 */
		for (struct connection *d = connections; d != NULL; ) {
			/* might move underneath us */
			struct connection *next = d->ac_next;

			if (c != d && c->kind == d->kind && streq(c->name, d->name) &&
			    same_id(&c->spd.this.id, &d->spd.this.id) &&
			    same_id(&c->spd.that.id, &d->spd.that.id))
			{
				DBG(DBG_CONTROL, DBG_log("Unorienting old connection with same IDs"));
				suppress_delete(d); /* don't send a delete */
				release_connection(d, FALSE); /* this deletes the states */
			}
			d = next;
		}

		/*
		 * This only affects IKEv2, since we don't store any
		 * received INITIAL_CONTACT for IKEv1.
		 * We don't do this on IKEv1, because it seems to
		 * confuse various third parties (Windows, Cisco VPN 300,
		 * and juniper
		 * likely because this would be called before the IPsec SA
		 * of QuickMode is installed, so the remote endpoints view
		 * this IKE SA still as the active one?
		 */
		if (pst->st_seen_initialc) {
			if (c->newest_isakmp_sa != SOS_NOBODY &&
			    c->newest_isakmp_sa != pst->st_serialno) {
				struct state *old_p1 = state_by_serialno(c->newest_isakmp_sa);

				DBG(DBG_CONTROL, DBG_log("deleting replaced IKE state for %s",
					old_p1->st_connection->name));
				old_p1->st_suppress_del_notify = TRUE;
				event_force(EVENT_SA_EXPIRE, old_p1);
			}

			if (c->newest_ipsec_sa != SOS_NOBODY) {
				struct state *old_p2 = state_by_serialno(c->newest_ipsec_sa);
				struct connection *d = old_p2 == NULL ? NULL : old_p2->st_connection;

				if (c == d && same_id(&c->spd.that.id, &d->spd.that.id)) {
					DBG(DBG_CONTROL, DBG_log("Initial Contact received, deleting old state #%lu from connection '%s'",
						c->newest_ipsec_sa, c->name));
					old_p2->st_suppress_del_notify = TRUE;
					event_force(EVENT_SA_EXPIRE, old_p2);
				}
			}
		}
	}

	c->newest_isakmp_sa = pst->st_serialno;
}

static void whack_log_state_event(struct state *st, struct pluto_event *pe,
				  monotime_t now)
{
	if (pe != NULL) {
		pexpect(st == pe->ev_state);
		LSWLOG_WHACK(RC_LOG, buf) {
			lswlogf(buf, "event %s is ", pe->ev_name);
			if (pe->ev_type == EVENT_NULL) {
				lswlogf(buf, "not timer based");
			} else {
				lswlogf(buf, "schd: %jd (in %jds)",
					monosecs(pe->ev_time),
					deltasecs(monotimediff(pe->ev_time, now)));
			}
			if (st->st_connection != NULL) {
				/* fmt_connection(buf, st->st_connection); */
				char cib[CONN_INST_BUF];
				lswlogf(buf, " \"%s\"%s",
					st->st_connection->name,
					fmt_conn_instance(st->st_connection, cib));
			}
			lswlogf(buf, "  #%lu", st->st_serialno);
		}
	}
}

void list_state_events(monotime_t now)
{
	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *st = NULL;
	FOR_EACH_STATE_OLD2NEW(st) {
		whack_log_state_event(st, st->st_event, now);
		whack_log_state_event(st, st->st_liveness_event, now);
		whack_log_state_event(st, st->st_rel_whack_event, now);
		whack_log_state_event(st, st->st_send_xauth_event, now);
		whack_log_state_event(st, st->st_addr_change_event, now);
		whack_log_state_event(st, st->st_dpd_event, now);
	}
}
