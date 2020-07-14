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
#include <event2/bufferevent.h>		/* TCP: for bufferevent_free()? */

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
#include "initiate.h"
#include "kernel.h"
#include "kernel_xfrm_interface.h"
#include "iface.h"
#include "ikev1_send.h"		/* for free_v1_messages() */
#include "ikev2_send.h"		/* for free_v2_messages() */

#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>

#include "ikev2_msgid.h"
#include "pluto_stats.h"
#include "ikev2_ipseckey.h"
#include "ip_address.h"
#include "ip_info.h"
#include "ip_selector.h"

bool uniqueIDs = FALSE;

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

static struct finite_state state_undefined = {
	.kind = STATE_UNDEFINED,
	.name = "STATE_UNDEFINED",
	.short_name = "UNDEFINED",
	.story = "not defined - either very new or dead (internal)",
	.category = CAT_IGNORE,
};

static struct finite_state state_ikev1_roof = {
	.kind = STATE_IKEv1_ROOF,
	.name = "STATE_IKEv1_ROOF",
	.short_name = "IKEv1_ROOF",
	.story = "invalid state - IKEv1 roof",
	.category = CAT_IGNORE,
};

static struct finite_state state_ikev2_roof = {
	.kind = STATE_IKEv2_ROOF,
	.name = "STATE_IKEv2_ROOF",
	.short_name = "IKEv2_ROOF",
	.story = "invalid state - IKEv2 roof",
	.category = CAT_IGNORE,
};

const struct finite_state *finite_states[STATE_IKE_ROOF] = {
	[STATE_UNDEFINED] = &state_undefined,
	[STATE_IKEv1_ROOF] &state_ikev1_roof,
	[STATE_IKEv2_ROOF] &state_ikev2_roof,
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
 * "pending" and should be merged (however, this simple code might
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

void revive_conns(struct fd *unused_whackfd UNUSED)
{
	/*
	 * XXX: Revive all listed connections regardless of their
	 * DELAY.  See note above in add_revival().
	 *
	 * XXX: since this is called from the event loop, the global
	 * whack_log_fd is invalid so specifying RC isn't exactly
	 * useful.
	 */
	while (revivals != NULL) {
		struct connection *c = conn_by_name(revivals->name,
						    true/*strict: don't accept CK_INSTANCE*/);
		/*
		 * Above call. with quiet=false, would try to log
		 * using whack_log(); but that's useless as the global
		 * whack_log_fd is only valid while in the whack
		 * handler.
		 */
		if (c == NULL) {
			loglog(RC_UNKNOWN_NAME, "failed to initiate connection \"%s\" which received a Delete/Notify but must remain up per local policy; connection no longer exists", revivals->name);
		} else {
			log_connection(RC_LOG, null_fd, c,
				       "initiating connection which received a Delete/Notify but must remain up per local policy");
			if (!initiate_connection(c, NULL, null_fd, true/*background*/)) {
				log_connection(RC_FATAL, null_fd, c,
					       "failed to initiate connection");
			}
		}
		/*
		 * Danger! The free_revival() call removes head,
		 * replacing it with the next in the list.
		 */
		free_revival(&revivals);
	}
}

/* end of revival mechanism */

void lswlog_finite_state(struct lswlog *buf, const struct finite_state *fs)
{
	if (fs == NULL) {
		lswlogs(buf, "NULL-FINITE_STATE");
	} else {
		jam(buf, "%s:", fs->short_name);
		jam(buf, " category: ");
		jam_enum_short(buf, &state_category_names, fs->category);
		/* no enum_name available? */
		jam(buf, "; flags: "PRI_LSET, fs->flags);
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

struct ike_sa *ike_sa(struct state *st, where_t where)
{
	if (st != NULL && IS_CHILD_SA(st)) {
		struct state *pst = state_by_serialno(st->st_clonedfrom);
		if (pst == NULL) {
			log_pexpect(where, "child state #%lu missing parent state #%lu",
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

static struct state *new_state(enum ike_version ike_version,
			       const ike_spi_t ike_initiator_spi,
			       const ike_spi_t ike_responder_spi,
			       enum sa_type sa_type, struct fd *whackfd)
{
	static so_serial_t next_so = SOS_FIRST;
	union sas *sas = alloc_thing(union sas, "struct state in new_state()");
	passert(&sas->st == &sas->child.sa);
	passert(&sas->st == &sas->ike.sa);
	struct state *st = &sas->st;
	*st = (struct state) {
		.st_state = &state_undefined,
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

	st->st_logger = alloc_logger(st, &logger_state_vec, HERE);
	st->st_logger->object_whackfd = dup_any(whackfd);

	st->hidden_variables.st_nat_oa = address_any(&ipv4_info);
	st->hidden_variables.st_natd = address_any(&ipv4_info);

	dbg("creating state object #%lu at %p", st->st_serialno, (void *) st);
	add_state_to_db(st);
	pstat_sa_started(st, sa_type);

	return st;
}

struct ike_sa *new_v1_istate(struct fd *whackfd)
{
	struct state *st = new_state(IKEv1, ike_initiator_spi(),
				     zero_ike_spi, IKE_SA, whackfd);
	struct ike_sa *ike = pexpect_ike_sa(st);
	return ike;
}

struct ike_sa *new_v1_rstate(struct msg_digest *md)
{
	struct state *st = new_state(IKEv1, md->hdr.isa_ike_spis.initiator,
				     ike_responder_spi(&md->sender),
				     IKE_SA, null_fd);
	struct ike_sa *ike = pexpect_ike_sa(st);
	update_ike_endpoints(ike, md);
	return ike;
}

struct ike_sa *new_v2_ike_state(const struct state_v2_microcode *transition,
				enum sa_role sa_role,
				const ike_spi_t ike_initiator_spi,
				const ike_spi_t ike_responder_spi,
				struct connection *c, lset_t policy,
				int try, struct fd *whack_sock)
{
	struct state *st = new_state(IKEv2, ike_initiator_spi, ike_responder_spi,
				     IKE_SA, whack_sock);
	struct ike_sa *ike = pexpect_ike_sa(st);
	ike->sa.st_sa_role = sa_role;
	const struct finite_state *fs = finite_states[transition->state];
	change_state(&ike->sa, fs->kind);
	set_v2_transition(&ike->sa, transition, HERE);
	v2_msgid_init_ike(ike);
	initialize_new_state(&ike->sa, c, policy, try);
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
	init_oneshot_timer(EVENT_REVIVE_CONNS, revive_conns);
}

void delete_state_by_id_name(struct state *st, void *name)
{
	struct connection *c = st->st_connection;

	if (!IS_IKE_SA(st))
		return;

	id_buf thatidb;
	const char *thatidbuf = str_id(&c->spd.that.id, &thatidb);
	if (streq(thatidbuf, name)) {
		delete_ike_family(pexpect_ike_sa(st), PROBABLY_SEND_DELETE);
		/* note: no md->st to clear */
	}
}

void v1_delete_state_by_username(struct state *st, void *name)
{
	/* only support deleting ikev1 with XAUTH username */
	if (st->st_ike_version == IKEv2)
		return;

	if (IS_IKE_SA(st) && streq(st->st_xauth_username, name)) {
		delete_ike_family(pexpect_ike_sa(st), PROBABLY_SEND_DELETE);
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

/*
 * Free the Whack socket file descriptor.
 * This has the side effect of telling Whack that we're done.
 */
void release_any_whack(struct state *st, where_t where, const char *why)
{
	dbg("releasing #%lu's "PRI_FD" because %s",
	    st->st_serialno, pri_fd(st->st_whack_sock), why);
	close_any_fd(&st->st_logger->object_whackfd, where);
	close_any_fd(&st->st_logger->global_whackfd, where);
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
	struct state *st = state_by_ike_spis(IKEv2,
					     &ike->sa.st_serialno,
					     NULL/* ignore v1 msgid */,
					     NULL/* ignore role */,
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


/*
 * XXX: This is broken on IKEv2.  It schedules a replace event for
 * each child except that fires _after_ the IKE SA has been deleted.
 * Should it schedule pending events?
 */

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
		/*
		 * Shut down further logging for the child, above are
		 * the last whack will hear from them.
		 */
		release_any_whack(st, HERE, "IKE going away");
	}
	/*
	 * XXX: why was this non-conditional?  probably doesn't matter
	 * as it is idenpotent?
	 */
	delete_cryptographic_continuation(st);
	return false; /* keep going */
}

static void flush_incomplete_children(struct ike_sa *ike)
{
	state_by_ike_spis(ike->sa.st_ike_version,
			  &ike->sa.st_serialno,
			  NULL /* ignore MSGID */,
			  NULL /* ignore role */,
			  &ike->sa.st_ike_spis,
			  flush_incomplete_child, NULL/*arg*/, __func__);
}

static bool should_send_delete(const struct state *st)
{
	if (st->st_dont_send_delete) {
		dbg("%s: no, just because", __func__);
		return false;
	}

	if (!IS_IPSEC_SA_ESTABLISHED(st) &&
	    !IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
		dbg("%s: no, not established", __func__);
		return false;
	}

	if ((st->st_ike_version == IKEv2) &&
	    IS_CHILD_SA(st) &&
	    state_with_serialno(st->st_clonedfrom) == NULL) {
		/*
		 * ??? in v2, there must be a parent
		 *
		 * XXX: except when delete_state(ike), instead of
		 * delete_ike_family(ike), is called ...
		 *
		 * Without an IKE SA sending the notify isn't
		 * possible.
		 */
		dbg("%s: no, lost parent; suspect IKE SA was deleted without deleting children", __func__);
		return false;
	}

	dbg("%s: yes", __func__);
	return true;
}

static void delete_state_log(struct state *st, struct state *cur_state)
{
	struct connection *const c = st->st_connection;
	bool del_notify = !impair.send_no_delete && should_send_delete(st);

	if (cur_state != NULL && cur_state == st) {
		/*
		* Don't log state and connection if it is the same as
		* the message prefix.
		*/
		deltatime_buf dtb;
		libreswan_log("deleting state (%s) aged %ss and %ssending notification",
			      st->st_state->name,
			      str_deltatime(realtimediff(realnow(), st->st_inception), &dtb),
			      del_notify ? "" : "NOT ");
	} else if (cur_state != NULL && cur_state->st_connection == st->st_connection) {
		deltatime_buf dtb;
		libreswan_log("deleting other state #%lu (%s) aged %ss and %ssending notification",
			      st->st_serialno, st->st_state->name,
			      str_deltatime(realtimediff(realnow(), st->st_inception), &dtb),
			      del_notify ? "" : "NOT ");
	} else {
		deltatime_buf dtb;
		connection_buf cib;
		libreswan_log("deleting other state #%lu connection (%s) "PRI_CONNECTION" aged %ss and %ssending notification",
			      st->st_serialno, st->st_state->name,
			      pri_connection(c, &cib),
			      str_deltatime(realtimediff(realnow(), st->st_inception), &dtb),
			      del_notify ? "" : "NOT ");
	}

	dbg("%s state #%lu: %s(%s) => delete",
	    IS_IKE_SA(st) ? "parent" : "child", st->st_serialno,
	    st->st_state->short_name,
	    enum_name(&state_category_names, st->st_state->category));
}

static v2_msgid_pending_cb ikev2_send_delete_continue;

static stf_status ikev2_send_delete_continue(struct ike_sa *ike UNUSED,
		struct state *st,
		struct msg_digest *md UNUSED)
{
	if (should_send_delete(st)) {
		send_delete(st);
		st->st_dont_send_delete = true;
		dbg("%s Marked IPSEC state #%lu to suppress sending delete notify", __func__, st->st_serialno);
	}

	delete_state(st);
	return STF_OK;
}

void schedule_next_child_delete(struct state *st, struct ike_sa *ike)
{
	if (st->st_ike_version == IKEv2 &&
	    should_send_delete(st)) {
		/* pre delete check for slot to send delete message */
		struct v2_msgid_window *initiator = &ike->sa.st_v2_msgid_windows.initiator;
		intmax_t unack = (initiator->sent - initiator->recv);
		if (unack >= ike->sa.st_connection->ike_window) {
			dbg_v2_msgid(ike, st, "next initiator (send delete) blocked by outstanding response (unack %jd). add delete to Q", unack);
			v2_msgid_queue_initiator(ike, st, ISAKMP_v2_INFORMATIONAL,
						 NULL, ikev2_send_delete_continue);
			return;
		}
	}
	delete_state(st);
	st = NULL;
	v2_expire_unused_ike_sa(ike);
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
	if (DBGP(DBG_CPU_USAGE) || DBGP(DBG_BASE)) {
		DBG_log("#%lu main thread "PRI_CPU_USAGE" helper thread "PRI_CPU_USAGE" in total",
			st->st_serialno,
			pri_cpu_usage(st->st_timing.main_usage),
			pri_cpu_usage(st->st_timing.helper_usage));
	}

	so_serial_t old_serialno = push_cur_state(st);
	delete_state_log(st, state_by_serialno(old_serialno));

	/*
	 * IKEv2 IKE failures are logged in the state transition conpletion.
	 * IKEv1 IKE failures do not go through a transition, so we catch
	 * these in delete_state()
	 */
	if (IS_IKE_SA(st) && st->st_ike_version == IKEv1 &&
		!IS_IKE_SA_ESTABLISHED(st)) {
		linux_audit_conn(st, LAK_PARENT_FAIL);
	}

	/*
	 * only log parent state deletes, we log children in
	 * ipsec_delete_sa()
	 */
	if (IS_IKE_SA_ESTABLISHED(st) || st->st_state->kind == STATE_IKESA_DEL)
		linux_audit_conn(st, LAK_PARENT_DESTROY);

	/* If we are failed OE initiator, make shunt bare */
	if (IS_IKE_SA(st) && (c->policy & POLICY_OPPORTUNISTIC) &&
	    (st->st_state->kind == STATE_PARENT_I1 ||
	     st->st_state->kind == STATE_PARENT_I2)) {
		ipsec_spi_t failure_shunt = shunt_policy_spi(c, FALSE /* failure_shunt */);
		ipsec_spi_t nego_shunt = shunt_policy_spi(c, TRUE /* negotiation shunt */);

		dbg("OE: delete_state orphaning hold with failureshunt %s (negotiation shunt would have been %s)",
		    enum_short_name(&spi_names, failure_shunt),
		    enum_short_name(&spi_names, nego_shunt));

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
				st->st_xauth_username[0] != '\0' ? " XAUTHuser=" : "",
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
				st->st_xauth_username[0] != '\0' ? " XAUTHuser=" : "",
				st->st_xauth_username);
			pstats_ipsec_in_bytes += st->st_ah.peer_bytes;
			pstats_ipsec_out_bytes += st->st_ah.our_bytes;
		}

		if (st->st_ipcomp.present) {
			char statebuf[1024];
			char *sbcp = readable_humber(st->st_ipcomp.peer_bytes,
					       statebuf,
					       statebuf + sizeof(statebuf),
					       "IPCOMP traffic information: in=");

			(void)readable_humber(st->st_ipcomp.our_bytes,
					       sbcp,
					       statebuf + sizeof(statebuf),
					       " out=");
			loglog(RC_INFORMATIONAL, "%s%s%s",
				statebuf,
				st->st_xauth_username[0] != '\0' ? " XAUTHuser=" : "",
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

	event_delete(EVENT_DPD, st);
	event_delete(EVENT_v2_LIVENESS, st);
	event_delete(EVENT_v2_RELEASE_WHACK, st);
	event_delete(EVENT_v1_SEND_XAUTH, st);
	event_delete(EVENT_v2_ADDR_CHANGE, st);

	/* if there is a suspended state transition, disconnect us */
	struct msg_digest *md = unsuspend_md(st);
	if (md != NULL) {
		dbg("disconnecting state #%lu from md", st->st_serialno);
		release_any_md(&md);
	}

	if (should_send_delete(st)) {
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
	 * ??? What problem is this referring to?
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
			 * XXX: Should not even be here though!  The
			 * old IKE SA should be going through delete
			 * state transition that, at the end, cleanly
			 * deletes it with none of this guff.
			 */
			dbg("IKE delete_state() for #%lu and connection '%s' that is supposed to remain up;  not a problem - have newer #%lu",
			    st->st_serialno, c->name, newer_sa);
		} else if (impair.revival) {
			log_state(RC_LOG, st,
				  "IMPAIR: skipping revival of connection that is supposed to remain up");
		} else {
			log_state(RC_LOG, st,
				  "deleting IKE SA but connection is supposed to remain up; schedule EVENT_REVIVE_CONNS");
			add_revival(c);
		}
	}

	/*
	 * fake a state change here while we are still associated with a
	 * connection.  Without this the state logging (when enabled) cannot
	 * work out what happened.
	 */
	binlog_fake_state(st, STATE_UNDEFINED);

	/* XXX: hack to avoid reference counting iface_port. */
	if (st->st_interface != NULL && IS_IKE_SA(st) &&
	    st->st_serialno >= st->st_connection->newest_isakmp_sa) {
		/*
		 * XXX: don't try to delete the iface port of an old
		 * TCP IKE SA.  It's replacement will have taken
		 * ownership.  However, do delete a TCP IKE SA when it
		 * looks like it is getting ready for a replace.
		 */
		if (st->st_interface->protocol == &ip_protocol_tcp) {
			dbg("TCP: freeing interface; release instead?");
			struct iface_port **p = (void*)&st->st_interface; /* hack const */
			/*
			 * XXX: The state and the event loop are
			 * sharing EVP.  This deletes both.
			 */
			free_any_iface_port(p);
		}
	}
	st->st_interface = NULL;

	/*
	 * Unlink the connection which may in turn delete the
	 * connection instance.  Needs to be done before the state is
	 * removed from the state DB as it can otherwise leak the
	 * connection (or explode because it was removed from the
	 * list).
	 */
	update_state_connection(st, NULL);

	/*
	 * Effectively, this deletes any ISAKMP SA that this state
	 * represents
	 */
	del_state_from_db(st);

	v2_msgid_free(st);

	change_state(st, STATE_UNDEFINED);

	release_any_whack(st, HERE, "deleting state");

	/* from here on we are just freeing RAM */

	ikev1_clear_msgid_list(st);
	unreference_key(&st->st_peer_pubkey);

	/*
	 * Release stored IKE fragments. This is a union in st so only
	 * call one!  XXX: should be a union???
	 */
	switch (st->st_ike_version) {
	case IKEv1:
		free_v1_message_queues(st);
		break;
	case IKEv2:
		free_v2_message_queues(st);
		break;
	default:
		bad_case(st->st_ike_version);
	}

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

	free_chunk_content(&st->st_firstpacket_me);
	free_chunk_content(&st->st_firstpacket_peer);
	free_chunk_content(&st->st_v1_tpacket);
	free_chunk_content(&st->st_v1_rpacket);
	free_chunk_content(&st->st_p1isa);
	free_chunk_content(&st->st_gi);
	free_chunk_content(&st->st_gr);
	free_chunk_content(&st->st_ni);
	free_chunk_content(&st->st_nr);
	free_chunk_content(&st->st_dcookie);
	free_chunk_content(&st->st_v2_id_payload.data);

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

	free_chunk_content(&st->st_skey_initiator_salt);
	free_chunk_content(&st->st_skey_responder_salt);
	free_chunk_content(&st->st_skey_chunk_SK_pi);
	free_chunk_content(&st->st_skey_chunk_SK_pr);

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

	free_chunk_content(&st->st_no_ppk_auth);

	pfreeany(st->sec_ctx);
	free_logger(&st->st_logger);
	messup(st);
	pfree(st);
}

/*
 * Is a connection in use by some state?
 */

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
	struct ike_sa *ike = ike_sa(&child->sa, HERE);
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
							    struct connection *c),
						    struct fd *whackfd)
{
	/* this kludge avoids an n^2 algorithm */

	/* We take two passes so that we delete any ISAKMP SAs last.
	 * This allows Delete Notifications to be sent.
	 * ?? We could probably double the performance by caching any
	 * ISAKMP SA states found in the first pass, avoiding a second.
	 */
	for (int pass = 0; pass != 2; pass++) {
		dbg("pass %d", pass);
		dbg("FOR_EACH_STATE_... in %s", __func__);
		struct state *this = NULL;
		FOR_EACH_STATE_NEW2OLD(this) {
			dbg("state #%lu", this->st_serialno);

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
				/* XXX: better way? */
				close_any(&this->st_logger->global_whackfd);
				this->st_logger->global_whackfd = dup_any(whackfd);
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

void delete_states_dead_interfaces(struct fd *whackfd)
{
	struct state *this = NULL;
	dbg("FOR_EACH_STATE_... in %s", __func__);
	FOR_EACH_STATE_NEW2OLD(this) {
		if (this->st_interface &&
		    this->st_interface->ip_dev->ifd_change == IFD_DELETE) {
			char *id_vname = NULL;
			struct connection *c = this->st_connection;
			if (c->xfrmi != NULL && c->xfrmi->name != NULL)
				id_vname = c->xfrmi->name;
			else
				id_vname = this->st_interface->ip_dev->id_rname;
			log_global(RC_LOG, whackfd,
				   "deleting lasting state #%lu on interface (%s) which is shutting down",
				   this->st_serialno, id_vname);
			/* XXX: better? */
			close_any(&this->st_logger->global_whackfd);
			this->st_logger->global_whackfd = dup_any(whackfd);
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

void delete_states_by_connection(struct connection *c, bool relations, struct fd *whackfd)
{
	enum connection_kind ck = c->kind;

	dbg("deleting states for connection - %s",
	    relations ? "including all other IPsec SA's of this IKE SA" :
	    "not including other IPsec SA's");

	/*
	 * save this connection's isakmp SA,
	 * since it will get set to later SOS_NOBODY
	 */
	if (ck == CK_INSTANCE)
		c->kind = CK_GOING_AWAY;

	foreach_state_by_connection_func_delete(c,
						relations ? same_phase1_sa_relations : same_phase1_sa,
						whackfd);

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
void delete_states_by_peer(const struct fd *whackfd, const ip_address *peer)
{
	address_buf peer_buf;
	const char *peerstr = ipstr(peer, &peer_buf);

	whack_log(RC_COMMENT, whackfd, "restarting peer %s", peerstr);

	/* first restart the phase1s */
	for (int ph1 = 0; ph1 < 2; ph1++) {
		struct state *this;
		dbg("FOR_EACH_STATE_... in %s", __func__);
		FOR_EACH_STATE_NEW2OLD(this) {
			const struct connection *c = this->st_connection;
			endpoint_buf b;
			dbg("comparing %s to %s",
			    str_endpoint(&this->st_remote_endpoint, &b),
			    peerstr);

			if (sameaddr(&this->st_remote_endpoint, peer)) {
				if (ph1 == 0 && IS_IKE_SA(this)) {
					whack_log(RC_COMMENT, whackfd,
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
				     struct fd *whackfd)
{
	struct state *nst;

	if (sa_type == IPSEC_SA) {
		/* record use of the Phase 1 / Parent state */
		st->st_outbound_count++;
		st->st_outbound_time = mononow();
	}

	nst = new_state(st->st_ike_version,
			st->st_ike_spis.initiator,
			st->st_ike_spis.responder,
			sa_type, whackfd);

	connection_buf cib;
	dbg("duplicating state object #%lu "PRI_CONNECTION" as #%lu for %s",
	    st->st_serialno, pri_connection(st->st_connection, &cib),
	    nst->st_serialno, sa_type == IPSEC_SA ? "IPSEC SA" : "IKE SA");

	update_state_connection(nst, st->st_connection);

	if (sa_type == IPSEC_SA) {
		nst->st_oakley = st->st_oakley;
	}

	nst->quirks = st->quirks;
	nst->hidden_variables = st->hidden_variables;
	nst->st_remote_endpoint = st->st_remote_endpoint;
	pexpect_st_local_endpoint(st);
	endpoint_buf eb;
	dbg("#%lu setting local endpoint to %s from #%ld.st_localport "PRI_WHERE,
	    nst->st_serialno,
	    str_endpoint(&st->st_interface->local_endpoint, &eb),
	    st->st_serialno,pri_where(HERE));
	nst->st_interface = st->st_interface;
	pexpect_st_local_endpoint(nst);
	nst->st_clonedfrom = st->st_serialno;
	passert(nst->st_ike_version == st->st_ike_version);
	nst->st_ikev2_anon = st->st_ikev2_anon;
	nst->st_seen_fragmentation_supported = st->st_seen_fragmentation_supported;
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
		nst->CHUNK = clone_hunk(st->CHUNK, #CHUNK " in duplicate state")

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

struct state *ikev1_duplicate_state(struct state *st,
				    struct fd *whackfd)
{
	return duplicate_state(st, IPSEC_SA, whackfd);
}

struct child_sa *new_v2_child_state(struct ike_sa *ike,
				    enum sa_type sa_type,
				    enum sa_role role,
				    enum state_kind kind,
				    struct fd *whackfd)
{
	struct state *cst = duplicate_state(&ike->sa, sa_type, whackfd);
	cst->st_sa_role = role;
	struct child_sa *child = pexpect_child_sa(cst);
	v2_msgid_init_child(ike, child);
	change_state(&child->sa, kind);
	const struct state_v2_microcode *transition = child->sa.st_state->v2_transitions;
	set_v2_transition(&child->sa, transition, HERE);
	return child;
}

void for_each_state(void (*f)(struct state *, void *data), void *data,
		    const char *func)
{
	dbg("FOR_EACH_STATE_... in %s (%s)", func, __func__);
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
	return state_by_ike_spis(IKEv1,
				 NULL/*ignore-clonedfrom*/,
				 &msgid/*check v1 msgid*/,
				 NULL/*ignore-role*/,
				 ike_spis, NULL, NULL, __func__);
}

struct state *find_state_ikev1_init(const ike_spi_t *ike_initiator_spi,
				    msgid_t msgid)
{
	return state_by_ike_initiator_spi(IKEv1,
					  NULL/*ignore-clonedfrom*/,
					  &msgid/*check v1 msgid*/,
					  NULL/*ignore-role*/,
					  ike_initiator_spi, __func__);
}

/*
 * Find the IKEv2 IKE SA with the specified SPIs.
 */
struct ike_sa *find_v2_ike_sa(const ike_spis_t *ike_spis,
			      enum sa_role local_ike_role)
{
	const so_serial_t sos_nobody = SOS_NOBODY;
	struct state *st = state_by_ike_spis(IKEv2,
					     &sos_nobody/*clonedfrom: IKE SA*/,
					     NULL/*ignore v1 msgid*/,
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
	struct state *st = state_by_ike_spis(IKEv2,
					     &ike->sa.st_serialno,
					     NULL/* ignore v1 msgid*/,
					     NULL/*ignore-role*/,
					     &ike->sa.st_ike_spis,
					     v2_spi_predicate, &filter, __func__);
	return pexpect_child_sa(st);
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
				 NULL/*ignore-clonedfrom*/,
				 NULL/*ignore v1 msgid; see predicate*/,
				 NULL/*ignore-role*/,
				 ike_spis, v1_msgid_predicate,
				 &filter, __func__);
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
		dbg("connection %s has %d pending IPsec negotiations ike #%lu last child state #%lu",
		    c->name, n, psn, best->st_serialno);
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
	deltatime_t lifetime = monotimediff(ev->ev_time, now);

	if (deltatime_cmp(lifetime, >, PARENT_MIN_LIFE_DELAY) &&
	    /* in case st_margin == 0, insist minimum life */
	    deltatime_cmp(lifetime, >, ike->sa.st_replace_margin)) {
		return true;
	}

	deltatime_buf lb, rb;
	log_state(RC_LOG_SERIOUS, &ike->sa,
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
	bool is_ikev2 = (c->policy & POLICY_IKEV1_ALLOW) == LEMPTY;

	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *st;
	FOR_EACH_STATE_NEW2OLD(st) {
		if (LHAS(ok_states, st->st_state->kind) &&
		    (st->st_ike_version == IKEv2) == is_ikev2 &&
		    c->host_pair == st->st_connection->host_pair &&
		    same_peer_ids(c, st->st_connection, NULL) &&
		    sameaddr(&st->st_remote_endpoint, &c->spd.that.host_addr) &&
		    IS_IKE_SA(st) &&
		    (best == NULL || best->st_serialno < st->st_serialno))
		{
			best = st;
		}
	}

	return best;
}

void state_eroute_usage(const ip_subnet *ours, const ip_subnet *peers,
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
		    samesubnet(&c->spd.that.client, peers)) {
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
			str_selector(ours, &ourst),
			str_selector(peers, &hist));
	}
}

/* note: this mutates *st by calling get_sa_info */
static void jam_state_traffic(jambuf_t *buf, struct state *st)
{
	jam(buf, "#%lu: ", st->st_serialno);
	const struct connection *c = st->st_connection;
	jam_connection(buf, c);

	if (st->st_xauth_username[0] != '\0') {
		jam(buf, ", username=%s", st->st_xauth_username);
	}

	/* traffic */
	jam(buf, ", type=%s, add_time=%"PRIu64,
	    (st->st_esp.present ? "ESP" : st->st_ah.present ? "AH" : st->st_ipcomp.present ? "IPCOMP" : "UNKNOWN"),
	    st->st_esp.add_time);

	if (get_sa_info(st, TRUE, NULL)) {
		unsigned inb = (st->st_esp.present ? st->st_esp.our_bytes:
				st->st_ah.present ? st->st_ah.our_bytes :
				st->st_ipcomp.present ? st->st_ipcomp.our_bytes : 0);
		jam(buf, ", inBytes=%u", inb);
	}

	if (get_sa_info(st, FALSE, NULL)) {
		unsigned outb = (st->st_esp.present ? st->st_esp.peer_bytes :
				 st->st_ah.present ? st->st_ah.peer_bytes :
				 st->st_ipcomp.present ? st->st_ipcomp.peer_bytes : 0);
		jam(buf, ", outBytes=%u", outb);
	}

	if (st->st_xauth_username[0] == '\0') {
		jam(buf, ", id='");
		jam_id(buf, &c->spd.that.id, jam_sanitized_bytes);
		jam(buf, "'");
	}

	if (c->spd.that.has_lease) {
		/*
		 * "this" gave "that" a lease from "this" address
		 * pool.
		 */
		jam(buf, ", lease=");
		jam_subnet(buf, &c->spd.that.client);
	} else if (c->spd.this.has_internal_address) {
		/*
		 * "this" received an internal address from "that";
		 * presumably from "that"'s address pool.
		 */
		jam(buf, ", lease=");
		jam_subnet(buf, &c->spd.this.client);
	}
}

static void show_state_traffic(struct show *s,
			       enum rc_type rc, struct state *st)
{
	if (IS_IKE_SA(st))
		return; /* ignore non-IPsec states */

	if (!IS_IPSEC_SA_ESTABLISHED(st))
		return; /* ignore non established states */

	/* whack-log-global - no prefix */
	WHACK_LOG(rc, show_fd(s), buf) {
		/* note: this mutates *st by calling get_sa_info */
		jam_state_traffic(buf, st);
	}
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

	/*
	 * Hunt and peck for an event?  Should it show the first?
	 */
	struct pluto_event *liveness_events[] = {
		st->st_event,
		st->st_retransmit_event,
	};
	struct pluto_event *liveness = NULL;
	for (unsigned e = 0; e < elemsof(liveness_events); e++) {
		liveness = liveness_events[e];
		if (liveness != NULL) {
			break;
		}
	}
	intmax_t delta = (liveness == NULL ? -1 : /* ??? sort of odd signifier */
			  deltasecs(monotimediff(liveness->ev_time, now)));

	snprintf(state_buf, state_buf_len,
		 "#%lu: \"%s\"%s:%u %s (%s); %s in %jds%s%s%s%s; %s;",
		 st->st_serialno,
		 c->name, inst,
		 endpoint_hport(&st->st_remote_endpoint),
		 st->st_state->name,
		 st->st_state->story,
		 (liveness == NULL ? "none" :
		  enum_name(&timer_event_names, liveness->ev_type)),
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
		char saids_buf[(1 + SATOT_BUF) * 6];
		jambuf_t buf = ARRAY_AS_JAMBUF(saids_buf);

#	define add_said(ADST, ASPI, APROTO)				\
		{							\
			ip_said s = said3(ADST, ASPI, APROTO);		\
			jam(&buf, " ");					\
			jam_said(&buf, &s);				\
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

		if (st->st_ah.present) {
			add_said(&c->spd.that.host_addr, st->st_ah.attrs.spi,
				 &ip_protocol_ah);
			if (get_sa_info(st, FALSE, NULL)) {
				mbcp = readable_humber(st->st_ah.peer_bytes,
						       mbcp,
						       traffic_buf +
							  sizeof(traffic_buf),
						       " AHout=");
			}
			add_said(&c->spd.this.host_addr, st->st_ah.our_spi,
				 &ip_protocol_ah);
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
				 &ip_protocol_esp);
			if (get_sa_info(st, TRUE, NULL)) {
				mbcp = readable_humber(st->st_esp.our_bytes,
						       mbcp,
						       traffic_buf +
							 sizeof(traffic_buf),
						       " ESPin=");
			}
			add_said(&c->spd.this.host_addr, st->st_esp.our_spi,
				 &ip_protocol_esp);
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
				 st->st_ipcomp.attrs.spi, &ip_protocol_comp);
			if (get_sa_info(st, FALSE, NULL)) {
				mbcp = readable_humber(
						st->st_ipcomp.peer_bytes,
						mbcp,
						traffic_buf +
						  sizeof(traffic_buf),
						" IPCOMPout=");
			}
			add_said(&c->spd.this.host_addr, st->st_ipcomp.our_spi,
				 &ip_protocol_comp);
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

#if defined(XFRM_SUPPORT)
		if (st->st_ah.attrs.mode ==
			ENCAPSULATION_MODE_TUNNEL ||
			st->st_esp.attrs.mode ==
			ENCAPSULATION_MODE_TUNNEL ||
			st->st_ipcomp.attrs.mode ==
			ENCAPSULATION_MODE_TUNNEL) {
			add_said(&c->spd.that.host_addr, st->st_tunnel_out_spi,
				 &ip_protocol_ipip);
			add_said(&c->spd.this.host_addr, st->st_tunnel_in_spi,
				 &ip_protocol_ipip);
		}
#endif

		snprintf(state_buf2, state_buf2_len,
			"#%lu: \"%s\"%s%s%s %s %s%s",
			st->st_serialno,
			c->name, inst,
			lastused,
			saids_buf,
			traffic_buf,
			st->st_xauth_username[0] != '\0' ? "username=" : "",
			st->st_xauth_username);

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
 *
 * Returns NULL (rather than an array containing one NULL) when there
 * are no states.
 *
 * Caller is responsible for freeing the structure.
 */
static struct state **sort_states(int (*sort_fn)(const void *, const void *),
				  const char *func)
{
	/* COUNT the number of states. */
	int count = 0;
	{
		dbg("FOR_EACH_STATE_... in %s (%s)", func, __func__);
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

static int show_newest_state_traffic(struct connection *c,
				     struct fd *unused_whackfd UNUSED,
				     void *arg)
{
	struct show *s = arg;
	struct state *st = state_by_serialno(c->newest_ipsec_sa);

	if (st == NULL)
		return 0;

	show_state_traffic(s, RC_INFORMATIONAL_TRAFFIC, st);
	return 1;
}

void show_traffic_status(struct show *s, const char *name)
{
	if (name == NULL) {
		struct state **array = sort_states(state_compare_serial,
						   __func__);

		/* now print sorted results */
		if (array != NULL) {
			int i;
			for (i = 0; array[i] != NULL; i++) {
				show_state_traffic(s,
						   RC_INFORMATIONAL_TRAFFIC,
						   array[i]);
			}
			pfree(array);
		}
	} else {
		struct connection *c = conn_by_name(name, true/*strict*/);

		if (c != NULL) {
			/* cast away const sillyness */
			show_newest_state_traffic(c, NULL, s);
		} else {
			/* cast away const sillyness */
			int count = foreach_connection_by_alias(name, NULL,
								show_newest_state_traffic,
								s);
			if (count == 0) {
				whack_log(RC_UNKNOWN_NAME, show_fd(s),
					  "no such connection or aliased connection named \"%s\"", name);
			}
		}
	}
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

void show_states(struct show *s)
{
	show_separator(s);
	struct state **array = sort_states(state_compare_connection,
					   __func__);

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
			show_comment(s, "%s", state_buf);
			if (state_buf2[0] != '\0')
				show_comment(s, "%s", state_buf2);

			/* show any associated pending Phase 2s */
			if (IS_IKE_SA(st))
				show_pending_phase2(s, st->st_connection,
						    pexpect_ike_sa(st));
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
ipsec_spi_t uniquify_peer_cpi(ipsec_spi_t cpi, const struct state *st, int tries)
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
	ike->sa.st_interface = md->iface;
	pexpect_st_local_endpoint(&ike->sa);
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

	/* check for all conditions before updating IPsec SA's */
	if (afi != address_type(&c->spd.that.host_addr)) {
		libreswan_log("MOBIKE: AF change switching between v4 and v6 not supported");
		return false;
	}

	passert(child->sa.st_connection == ike->sa.st_connection);

	ip_endpoint old_endpoint;
	ip_endpoint new_endpoint;

	enum message_role md_role = v2_msg_role(md);
	switch (md_role) {
	case MESSAGE_RESPONSE:
		/* MOBIKE inititor processing response */
		pexpect_st_local_endpoint(&ike->sa);
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
		 str_sensitive_endpoint(&old_endpoint, &old),
		 str_sensitive_endpoint(&new_endpoint, &new));

	dbg("#%lu pst=#%lu %s", child->sa.st_serialno,
	    ike->sa.st_serialno, buf);

	if (endpoint_eq(old_endpoint, new_endpoint)) {
		if (md_role == MESSAGE_REQUEST) {
			/* on responder NAT could hide end-to-end change */
			endpoint_buf b;
			libreswan_log("MOBIKE success no change to kernel SA same IP address ad port  %s",
				      str_sensitive_endpoint(&old_endpoint, &b));

			return true;
		}
	}

	if (!migrate_ipsec_sa(&child->sa)) {
		libreswan_log("%s FAILED", buf);
		return false;
	}

	libreswan_log(" success %s", buf);

	switch (md_role) {
	case MESSAGE_RESPONSE:
		/* MOBIKE initiator processing response */
		c->spd.this.host_addr = endpoint_address(&child->sa.st_mobike_local_endpoint);
		c->spd.this.host_port = endpoint_hport(&child->sa.st_mobike_local_endpoint);
		c->spd.this.host_nexthop  = child->sa.st_mobike_host_nexthop;

		ike->sa.st_interface = child->sa.st_interface = md->iface;
		break;
	case MESSAGE_REQUEST:
		/* MOBIKE responder processing request */
		c->spd.that.host_addr = md->sender;
		c->spd.that.host_port = endpoint_hport(&md->sender);

		/* for the consistency, correct output in ipsec status */
		child->sa.st_remote_endpoint = ike->sa.st_remote_endpoint = md->sender;
		child->sa.st_interface = ike->sa.st_interface = md->iface;
		break;
	default:
		bad_case(md_role);
	}
	pexpect_st_local_endpoint(&ike->sa);
	pexpect_st_local_endpoint(&child->sa);

	/* reset liveness */
	ike->sa.st_pend_liveness = FALSE;
	ike->sa.st_last_liveness = monotime_epoch;

	delete_oriented_hp(c); /* hp list may have changed */
	if (!orient(c)) {
		PEXPECT_LOG("%s after mobike failed", "orient");
	}
	/* assumption: orientation has not changed */
	connect_to_host_pair(c); /* re-create hp listing */

	if (md_role == MESSAGE_RESPONSE) {
		/* MOBIKE initiator processing response */
		migration_up(child->sa.st_connection, &child->sa);
		ike->sa.st_deleted_local_addr = address_any(&ipv4_info);
		child->sa.st_deleted_local_addr = address_any(&ipv4_info);
		if (dpd_active_locally(&child->sa) && child->sa.st_liveness_event == NULL) {
			dbg("dpd re-enabled after mobike, scheduling ikev2 liveness checks");
			deltatime_t delay = deltatime_max(child->sa.st_connection->dpd_delay, deltatime(MIN_LIVENESS));
			event_schedule(EVENT_v2_LIVENESS, delay, &child->sa);
		}
	}

	return true;
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
	state_by_ike_spis(IKEv2,
			  &from->sa.st_serialno,
			  NULL/*ignore v1 msgid*/,
			  NULL/*ignore-sa-role*/,
			  &from->sa.st_ike_spis,
			  v2_migrate_predicate, &filter, __func__);
}

static bool delete_ike_family_child(struct state *st, void *unused_context UNUSED)
{
	struct ike_sa *ike = ike_sa(st, HERE);
	/* pass down whack fd; better abstraction? */
	if (ike != NULL && fd_p(ike->sa.st_logger->global_whackfd)) {
		close_any(&st->st_logger->global_whackfd);
		st->st_logger->global_whackfd = dup_any(ike->sa.st_logger->global_whackfd);
	}
	switch (st->st_ike_version) {
	case IKEv1:
		break;
	case IKEv2:
		st->st_dont_send_delete = true;
		break;
	}
	delete_state(st);
	return false; /* keep going */
}

void delete_ike_family(struct ike_sa *ike, enum send_delete send_delete)
{
	/*
	 * We are a parent: delete our children and
	 * then prepare to delete ourself.
	 * Our children will be on the same hash chain
	 * because we share IKE SPIs.
	 */
	state_by_ike_spis(ike->sa.st_ike_version,
			  &ike->sa.st_serialno,
			  NULL/*ignore v1 msgid*/,
			  NULL/*ignore-sa-role*/,
			  &ike->sa.st_ike_spis,
			  delete_ike_family_child, NULL,
			  __func__);
	/* delete self */
	switch (send_delete) {
	case DONT_SEND_DELETE:
		ike->sa.st_dont_send_delete = true;
		break;
	case PROBABLY_SEND_DELETE:
		/* let delete_state()'s vodo make the decision */
		break;
	}
	delete_state(&ike->sa);
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
	dbg("unsuspending #%lu MD %p", st->st_serialno, md);
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
	 * ST_SUSPENDED_MD acts as a poor proxy for indicating a busy
	 * state.  For instance, the initial initiator (both IKEv1 and
	 * IKEv2) doesn't have a suspended MD.  To get around this a
	 * 'fake_md' MD is created.
	 *
	 * XXX: what about xauth? It sets ST_SUSPENDED_MD.
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
	if (st->st_v1_offloaded_task_in_background) {
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
	struct fd *whackfd = show_fd(s);
	unsigned shunts = shunt_count();

	whack_print(whackfd, "config.setup.ike.ddos_threshold=%u", pluto_ddos_threshold);
	whack_print(whackfd, "config.setup.ike.max_halfopen=%u", pluto_max_halfopen);

	/* technically shunts are not a struct state's - but makes it easier to group */
	whack_print(whackfd, "current.states.all="PRI_CAT, shunts + total_sa());
	whack_print(whackfd, "current.states.ipsec="PRI_CAT, cat_count[CAT_ESTABLISHED_CHILD_SA]);
	whack_print(whackfd, "current.states.ike="PRI_CAT, total_ike_sa());
	whack_print(whackfd, "current.states.shunts=%u", shunts);
	whack_print(whackfd, "current.states.iketype.anonymous="PRI_CAT,
			  cat_count_ike_sa[CAT_ANONYMOUS]);
	whack_print(whackfd, "current.states.iketype.authenticated="PRI_CAT,
			  cat_count_ike_sa[CAT_AUTHENTICATED]);
	whack_print(whackfd, "current.states.iketype.halfopen="PRI_CAT,
			  cat_count[CAT_HALF_OPEN_IKE_SA]);
	whack_print(whackfd, "current.states.iketype.open="PRI_CAT,
			  cat_count[CAT_OPEN_IKE_SA]);
	for (enum state_kind s = STATE_IKEv1_FLOOR; s < STATE_IKEv1_ROOF; s++) {
		const struct finite_state *ss = finite_states[s];
		whack_print(whackfd, "current.states.enumerate.%s="PRI_CAT,
			    ss->name, state_count[s]);
	}
	for (enum state_kind s = STATE_IKEv2_FLOOR; s < STATE_IKEv2_ROOF; s++) {
		const struct finite_state *ss = finite_states[s];
		whack_print(whackfd, "current.states.enumerate.%s="PRI_CAT,
			    ss->name, state_count[s]);
	}
}

static void log_newest_sa_change(const char *f, so_serial_t old_ipsec_sa,
			  struct state *const st)
{
	dbg("%s: instance %s[%lu], setting %s newest_ipsec_sa to #%lu (was #%lu) (spd.eroute=#%lu) cloned from #%lu",
	    f, st->st_connection->name,
	    st->st_connection->instance_serial,
	    enum_name(&ike_version_names, st->st_ike_version),
	    st->st_connection->newest_ipsec_sa, old_ipsec_sa,
	    st->st_connection->spd.eroute_owner,
	    st->st_clonedfrom);
}

void set_newest_ipsec_sa(const char *m, struct state *const st)
{
	so_serial_t old_ipsec_sa = st->st_connection->newest_ipsec_sa;

	st->st_connection->newest_ipsec_sa = st->st_serialno;
	log_newest_sa_change(m, old_ipsec_sa, st);
}

void record_newaddr(ip_address *ip, char *a_type)
{
	address_buf ip_str;
	dbg("XFRM RTM_NEWADDR %s %s", str_address(ip, &ip_str), a_type);
	for_each_state(ikev2_record_newaddr, ip, __func__);
}

void record_deladdr(ip_address *ip, char *a_type)
{
	address_buf ip_str;
	dbg("XFRM RTM_DELADDR %s %s", str_address(ip, &ip_str), a_type);
	for_each_state(ikev2_record_deladdr, ip, __func__);
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

static void suppress_delete_notify(const struct ike_sa *ike,
				   const char *what, so_serial_t so)
{
	struct state *st = state_by_serialno(so);
	if (st == NULL) {
		log_state(RC_LOG, &ike->sa,
			  "did not find old %s state #%lu to mark for suppressing delete",
			  what, so);
		return;
	}

	st->st_dont_send_delete = true;
	dbg("marked %s state #%lu to suppress sending delete notify",
	    what, st->st_serialno);
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

void IKE_SA_established(const struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;
	bool authnull = (LIN(POLICY_AUTH_NULL, c->policy) || c->spd.that.authby == AUTHBY_NULL);

	if (c->spd.this.xauth_server && LIN(POLICY_PSK, c->policy)) {
		/*
		 * If we are a server and use PSK, all clients use the same group ID
		 * Note that "xauth_server" also refers to IKEv2 CP
		 */
		dbg("We are a server using PSK and clients are using a group ID");
	} else if (!uniqueIDs) {
		dbg("uniqueIDs disabled, not contemplating releasing older self");
	} else {
		/*
		 * for all existing connections: if the same Phase 1 IDs are used,
		 * unorient the (old) connection (if different from current connection)
		 * Only do this for connections with the same name (can be shared ike sa)
		 */
		dbg("FOR_EACH_CONNECTION_... in %s", __func__);
		for (struct connection *d = connections; d != NULL; ) {
			/* might move underneath us */
			struct connection *next = d->ac_next;

			/* if old IKE SA is same as new IKE sa and non-auth isn't overwrting auth */
			if (c != d && c->kind == d->kind && streq(c->name, d->name) &&
			    same_id(&c->spd.this.id, &d->spd.this.id) &&
			    same_id(&c->spd.that.id, &d->spd.that.id))
			{
				bool old_is_nullauth = (LIN(POLICY_AUTH_NULL, d->policy) || d->spd.that.authby == AUTHBY_NULL);
				bool same_remote_ip = sameaddr(&c->spd.that.host_addr, &d->spd.that.host_addr);

				if (same_remote_ip && (!old_is_nullauth && authnull)) {
					log_state(RC_LOG, &ike->sa, "cannot replace old authenticated connection with authnull connection");
				} else if (!same_remote_ip && old_is_nullauth && authnull) {
					log_state(RC_LOG, &ike->sa, "NULL auth ID for different IP's cannot replace each other");
				} else {
					dbg("unorienting old connection with same IDs");
					/*
					 * When replacing an old
					 * existing connection,
					 * suppress sending delete
					 * notify
					 */
					suppress_delete_notify(ike, "ISAKMP", d->newest_isakmp_sa);
					suppress_delete_notify(ike, "IKE", d->newest_ipsec_sa);
					/*
					 * XXX: assume this call
					 * doesn't want to log to
					 * whack(?).  While PST still
					 * has an attached whack, the
					 * global whack that this call
					 * would have used detached
					 * long ago.
					 */
					release_connection(d, false, null_fd); /* this deletes the states */
				}
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
		if (ike->sa.st_seen_initialc) {
			if (c->newest_isakmp_sa != SOS_NOBODY &&
			    c->newest_isakmp_sa != ike->sa.st_serialno) {
				struct state *old_p1 = state_by_serialno(c->newest_isakmp_sa);

				dbg("deleting replaced IKE state for %s",
				    old_p1->st_connection->name);
				old_p1->st_dont_send_delete = true;
				event_force(EVENT_SA_EXPIRE, old_p1);
			}

			if (c->newest_ipsec_sa != SOS_NOBODY) {
				struct state *old_p2 = state_by_serialno(c->newest_ipsec_sa);
				struct connection *d = old_p2 == NULL ? NULL : old_p2->st_connection;

				if (c == d && same_id(&c->spd.that.id, &d->spd.that.id)) {
					dbg("Initial Contact received, deleting old state #%lu from connection '%s'",
					    c->newest_ipsec_sa, c->name);
					old_p2->st_dont_send_delete = true;
					event_force(EVENT_SA_EXPIRE, old_p2);
				}
			}
		}
	}

	c->newest_isakmp_sa = ike->sa.st_serialno;
}

static void whack_log_state_event(const struct fd *whackfd, struct state *st,
				  struct pluto_event *pe, monotime_t now)
{
	if (pe != NULL) {
		pexpect(st == pe->ev_state);
		WHACK_LOG(RC_LOG, whackfd, buf) {
			jam(buf, "event %s is ", pe->ev_name);
			if (pe->ev_type == EVENT_NULL) {
				jam(buf, "not timer based");
			} else {
				jam(buf, "schd: %jd (in %jds)",
				    monosecs(pe->ev_time),
				    deltasecs(monotimediff(pe->ev_time, now)));
			}
			if (st->st_connection != NULL) {
				/* fmt_connection(buf, st->st_connection); */
				char cib[CONN_INST_BUF];
				jam(buf, " \"%s\"%s",
				    st->st_connection->name,
				    fmt_conn_instance(st->st_connection, cib));
			}
			jam(buf, "  #%lu", st->st_serialno);
		}
	}
}

void list_state_events(const struct fd *whackfd, monotime_t now)
{
	dbg("FOR_EACH_STATE_... in %s", __func__);
	struct state *st = NULL;
	FOR_EACH_STATE_OLD2NEW(st) {
		whack_log_state_event(whackfd, st, st->st_event, now);
		whack_log_state_event(whackfd, st, st->st_liveness_event, now);
		whack_log_state_event(whackfd, st, st->st_rel_whack_event, now);
		whack_log_state_event(whackfd, st, st->st_send_xauth_event, now);
		whack_log_state_event(whackfd, st, st->st_addr_change_event, now);
		whack_log_state_event(whackfd, st, st->st_dpd_event, now);
	}
}

void set_v1_transition(struct state *st, const struct state_v1_microcode *transition,
		       where_t where)
{
	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "#%lu.st_v1_transition ", st->st_serialno);
		jam_v1_transition(buf, st->st_v1_transition);
		jam(buf, " to ");
		jam_v1_transition(buf, transition);
		jam(buf, " "PRI_WHERE, pri_where(where));
	}
	st->st_v1_transition = transition;
}

void set_v2_transition(struct state *st, const struct state_v2_microcode *transition,
		       where_t where)
{
	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "#%lu.st_v2_transition ", st->st_serialno);
		jam_v2_transition(buf, st->st_v2_transition);
		jam(buf, " -> ");
		jam_v2_transition(buf, transition);
		jam(buf, " "PRI_WHERE, pri_where(where));
	}
	st->st_v2_transition = transition;
}

static void jam_st(jambuf_t *buf, struct state *st)
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
	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "switching IKEv%d MD.ST from ", st->st_ike_version);
		jam_st(buf, md->st);
		jam(buf, " to ");
		jam_st(buf, st);
		jam(buf, " "PRI_WHERE, pri_where(where));
	}
	md->st = st;
}
