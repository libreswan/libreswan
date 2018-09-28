/*
 * routines for state objects
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001, 2013-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009, 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012 Bram <bram-bcrafjna-erqzvar@spam.wizbit.be>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2015-2017 Andrew Cagney
 * Copyright (C) 2015-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2015-2018 Paul Wouters <pwouters@redhat.com>
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

#include "cookie.h"
#include "crypto.h"
#include "crypt_symkey.h"
#include "spdb.h"
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "secrets.h"    /* unreference_key() */
#include "enum_names.h"
#include "crypt_dh.h"
#include "hostpair.h"

#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>

#include "pluto_stats.h"
#include "ikev2_ipseckey.h"
#include "ip_address.h"

bool uniqueIDs = FALSE;

static void update_state_stats(struct state *st, enum state_kind old_state,
			       enum state_kind new_state);

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
	.fs_state = STATE_UNDEFINED,
	.fs_name = "STATE_UNDEFINED",
	.fs_short_name = "UNDEFINED",
	.fs_story = "not defined - either very new or dead (internal)",
};

const struct finite_state *finite_states[STATE_IKE_ROOF] = {
	[STATE_UNDEFINED] = &state_undefined,
};

void lswlog_finite_state(struct lswlog *buf, const struct finite_state *fs)
{
	if (fs == NULL) {
		lswlogs(buf, "NULL-FINITE_STATE");
	} else {
		lswlogf(buf, "%s (timeout: ", fs->fs_short_name);
		lswlog_enum_short(buf, &timer_event_names, fs->fs_timeout_event);
		/* no enum_name available? */
		lswlogf(buf, " flags: %" PRIxLSET ")", fs->fs_flags);
	}
}

/*
 * This file has the functions that handle the
 * state hash table and the Message ID list.
 */

/* for DDoS tracking, used in change_state */
static unsigned state_count[STATE_IKE_ROOF];

void change_state(struct state *st, enum state_kind new_state)
{
	enum state_kind old_state = st->st_state;

	if (new_state != old_state) {
		update_state_stats(st, old_state, new_state);
		log_state(st, new_state);
		st->st_finite_state = finite_states[new_state];
		passert(st->st_finite_state != NULL);
	}
}

/* non-intersecting state categories */
enum categories {
	CAT_IGNORE,
	CAT_HALF_OPEN_IKE,
	CAT_OPEN_IKE,
	CAT_ANONYMOUS_IKE,
	CAT_AUTHENTICATED_IKE,
	CAT_ANONYMOUS_IPSEC,
	CAT_AUTHENTICATED_IPSEC,
	CAT_INFORMATIONAL,
	CAT_UNKNOWN,
	CAT_roof
};

static const char *const cat_name[CAT_roof] = {
	[CAT_IGNORE] = "ignore",
	[CAT_HALF_OPEN_IKE] = "half-open-ike",
	[CAT_OPEN_IKE] = "open-ike",
	[CAT_ANONYMOUS_IKE] = "established-anonymous-ike",
	[CAT_AUTHENTICATED_IKE] = "established-authenticated-ike",
	[CAT_ANONYMOUS_IPSEC] = "anonymous-ipsec",
	[CAT_AUTHENTICATED_IPSEC] = "authenticated-ipsec",
	[CAT_INFORMATIONAL] = "informational",
	[CAT_UNKNOWN] = "unknown",
};

static enum_names cat_names = {
	CAT_IGNORE, CAT_UNKNOWN,
	cat_name, CAT_roof,
	"",
	NULL
};

static unsigned cat_count[CAT_roof] = { 0 };

/* space for unknown as well */
static unsigned total_established_ike(void)
{
	return cat_count[CAT_ANONYMOUS_IKE] + cat_count[CAT_AUTHENTICATED_IKE];
}

static unsigned total_ike(void)
{
	return cat_count[CAT_HALF_OPEN_IKE] +
		cat_count[CAT_OPEN_IKE] +
		total_established_ike();
}

static unsigned total_ipsec(void)
{
	return cat_count[CAT_AUTHENTICATED_IPSEC] +
		cat_count[CAT_ANONYMOUS_IPSEC];
}

static unsigned total(void)
{
	return total_ike() + total_ipsec() + cat_count[CAT_UNKNOWN];
}

/*
 * When deleting, st->st_connection can be NULL, so we cannot look
 * at the policy to determine anonimity. We therefor use a scratchpad
 * at st->st_ikev2_anon which is copied from parent to child states
 */
static enum categories categorize_state(struct state *st,
					       enum state_kind state)
{
	bool is_parent = IS_PARENT_SA(st);
	enum categories established_ike = st->st_ikev2_anon ?
		CAT_ANONYMOUS_IKE : CAT_AUTHENTICATED_IKE;
	enum categories established_ipsec = st->st_ikev2_anon ?
		CAT_ANONYMOUS_IPSEC : CAT_AUTHENTICATED_IPSEC;

	/*
	 * Use a switch with no default so that missing and extra
	 * states get a -Wswitch diagnostic
	 */
	switch (state) {
	case STATE_UNDEFINED:
	case STATE_IKEv2_BASE:
		/*
		 * When a state object is created by new_state()
		 * it starts out in STATE_UNDEFINED.
		 * ??? this representation does not robustly detect errors.
		 */
		return CAT_IGNORE;

	case STATE_PARENT_I0:
		/*
		 * IKEv2 IKE SA initiator, while the the SA_INIT
		 * packet is being constructed, are in state.  Only
		 * once the packet has been sent out does it
		 * transition to STATE_PARENT_I1 and start being
		 * counted as half-open.
		 */
		return CAT_IGNORE;

	case STATE_PARENT_I1:
	case STATE_PARENT_R1:
	case STATE_AGGR_R0:
	case STATE_AGGR_I1:
	case STATE_MAIN_R0:
	case STATE_MAIN_I1:
		/*
		 * Count I1 as half-open too because with ondemand,
		 * a plaintext packet (that is spoofed) will
		 * trigger an outgoing IKE SA.
		 */
		return CAT_HALF_OPEN_IKE;

	case STATE_PARENT_I2:
	case STATE_MAIN_R1:
	case STATE_MAIN_R2:
	case STATE_MAIN_I2:
	case STATE_MAIN_I3:
	case STATE_AGGR_R1:
		/*
		 * All IKEv1 MAIN modes except the first
		 * (half-open) and last ones are not
		 * authenticated.
		 */
		return CAT_OPEN_IKE;

	case STATE_MAIN_I4:
	case STATE_MAIN_R3:
	case STATE_AGGR_I2:
	case STATE_AGGR_R2:
	case STATE_XAUTH_I0:
	case STATE_XAUTH_I1:
	case STATE_XAUTH_R0:
	case STATE_XAUTH_R1:
	case STATE_V2_CREATE_I0: /* isn't this an ipsec state */
	case STATE_V2_CREATE_I: /* isn't this an ipsec state */
	case STATE_V2_REKEY_IKE_I0:
	case STATE_V2_REKEY_IKE_I:
	case STATE_V2_REKEY_CHILD_I0: /* isn't this an ipsec state */
	case STATE_V2_REKEY_CHILD_I: /* isn't this an ipsec state */
	case STATE_V2_CREATE_R:
	case STATE_V2_REKEY_IKE_R:
	case STATE_V2_REKEY_CHILD_R:
		/*
		 * IKEv1 established states.
		 *
		 * XAUTH, seems to a second level of authentication
		 * performed after the connection is established and
		 * authenticated.
		 */
		return established_ike;

	case STATE_PARENT_I3:
	case STATE_PARENT_R2:
		/*
		 * IKEv2 established states.
		 */
		if (is_parent) {
			return established_ike;
		} else {
			return established_ipsec;
		}

	case STATE_V2_IPSEC_I:
	case STATE_V2_IPSEC_R:
		return established_ipsec;

	case STATE_IKESA_DEL:
		return established_ike;

	case STATE_QUICK_I1: /* this is not established yet? */
	case STATE_QUICK_I2:
	case STATE_QUICK_R0: /* shouldn't we cat_ignore this? */
	case STATE_QUICK_R1:
	case STATE_QUICK_R2:
		/*
		 * IKEv1: QUICK is for child connections children.
		 * Probably won't occur as a parent?
		 */
		pexpect(!is_parent);
		return established_ipsec;

	case STATE_MODE_CFG_I1:
	case STATE_MODE_CFG_R1:
	case STATE_MODE_CFG_R2:
		/*
		 * IKEv1: Post established negotiation.
		 */
		return established_ike;

	case STATE_INFO:
	case STATE_INFO_PROTECTED:
	case STATE_MODE_CFG_R0:
	case STATE_CHILDSA_DEL:
		pexpect(!is_parent);
		return CAT_INFORMATIONAL;

	default:
		loglog(RC_LOG_SERIOUS, "Unexpected state in categorize_state");
		return CAT_UNKNOWN;
	}
}

static void update_state_stats(struct state *st, enum state_kind old_state,
			enum state_kind new_state)
{
	/*
	 * "??? this seems expensive: on each state change we do this
	 * whole rigamarole."
	 *
	 * XXX: Part of the problem is with categorize_state().  It
	 * doesn't implement a simple mapping from state to category.
	 * If there was, struct finite_state' could be used to do the
	 * mapping.
	 */
	enum categories old_category = categorize_state(st, old_state);
	enum categories new_category = categorize_state(st, new_state);

	/*
	 * Count everything except STATE_UNDEFINED et.al. All states
	 * start and end in those states.
	 */
	if (old_category != CAT_IGNORE) {
		pexpect(state_count[old_state] != 0);
		pexpect(cat_count[old_category] != 0);
		state_count[old_state]--;
		cat_count[old_category]--;
	}
	if (new_category != CAT_IGNORE) {
		state_count[new_state]++;
		cat_count[new_category]++;
	}

	/*
	 * ??? this seems expensive: on each state change we do this
	 * whole rigamarole.
	 */
	DBG(DBG_CONTROLMORE, {
		DBG_log("%s state #%lu: %s(%s) => %s(%s)",
			IS_PARENT_SA(st) ? "parent" : "child", st->st_serialno,
			enum_name(&state_names, old_state), enum_name(&cat_names, old_category),
			enum_name(&state_names, new_state), enum_name(&cat_names, new_category));

		unsigned category_states = 0;

		for (enum categories cat = CAT_IGNORE; cat != CAT_roof; cat++) {
			DBG_log("%s states: %u",
				enum_name(&cat_names, cat),
				cat_count[cat]);
			category_states += cat_count[cat];
		}

		unsigned count_states = 0;

		for (enum state_kind s = STATE_IKEv1_FLOOR; s < STATE_IKEv1_ROOF; s++) {
			count_states += state_count[s];
		}

		for (enum state_kind s = STATE_IKEv2_FLOOR; s < STATE_IKEv2_ROOF; s++) {
			count_states += state_count[s];
		}

		DBG_log("category states: %u count states: %u",
			category_states, count_states);
		pexpect(category_states == count_states);
	});

	/* catch / log unexpected cases */
	pexpect(old_category != CAT_UNKNOWN);
	pexpect(new_category != CAT_UNKNOWN);

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
 * Some macros to ease iterating over the above table
 */

#define FOR_EACH_COOKIED_STATE(ST, CODE)				\
	do {								\
		struct state *ST = NULL;				\
		FOR_EACH_STATE_NEW2OLD(ST) {				\
			CODE;						\
		}							\
	} while (false)

/*
 * Iterate through all the states in a slot in new-to-old order.
 */
#define FOR_EACH_STATE_ENTRY(ST, SLOT, CODE)			\
	do {							\
		/* ST##entry is private to this macro */	\
		struct list_head *(ST##slot) = (SLOT);		\
		ST = NULL;					\
		FOR_EACH_LIST_ENTRY_NEW2OLD(ST##slot, ST) {	\
			CODE;					\
		}						\
	} while (false)

/*
 * Iterate over all entries with matching cookies.
 */

#define FOR_EACH_STATE_WITH_COOKIES(ST, ICOOKIE, RCOOKIE, CODE)		\
	FOR_EACH_STATE_ENTRY(ST, cookies_slot((ICOOKIE), (RCOOKIE)), {	\
		if (memeq((ICOOKIE), ST->st_icookie, COOKIE_SIZE) &&	\
		    memeq((RCOOKIE), ST->st_rcookie, COOKIE_SIZE)) {	\
			CODE;						\
		}							\
	})								\

#define FOR_EACH_STATE_WITH_ICOOKIE(ST, ICOOKIE, CODE)			\
	FOR_EACH_STATE_ENTRY(ST, icookie_slot((ICOOKIE)), {		\
		if (memeq((ICOOKIE), ST->st_icookie, COOKIE_SIZE)) {	\
			CODE;						\
		}							\
	})								\


/*
 * Get the IKE SA managing the security association.
 */

static struct ike_sa *get_ike_sa(struct state *st, bool verbose)
{
	if (st != NULL && IS_CHILD_SA(st)) {
		struct state *pst = state_by_serialno(st->st_clonedfrom);
		if (pst == NULL) {
			PEXPECT_LOG("child state #%lu missing parent state #%lu",
				    st->st_serialno, st->st_clonedfrom);
			/* about to crash with an NPE */
		} else if (verbose) {
			PEXPECT_LOG("child state #%lu is not an IKE SA; parent is #%lu",
				    st->st_serialno, st->st_clonedfrom);
		}
		return (struct ike_sa*) pst;
	}
	return (struct ike_sa*) st;
}

struct ike_sa *ike_sa(struct state *st)
{
	return get_ike_sa(st, false);
}

struct ike_sa *pexpect_ike_sa(struct state *st)
{
	return get_ike_sa(st, true);
}

struct child_sa *pexpect_child_sa(struct state *st)
{
	if (pexpect(st != NULL))
		pexpect(IS_CHILD_SA(st));

	return (struct child_sa*) st;
}

union sas { struct child_sa child; struct ike_sa ike; struct state st; };

/*
 * Get a state object.
 * Caller must schedule an event for this object so that it doesn't leak.
 * Caller must insert_state().
 */
struct state *new_state(void)
{
	static so_serial_t next_so = SOS_FIRST;

	union sas *sas = alloc_thing(union sas, "struct state in new_state()");
	passert(&sas->st == &sas->child.sa);
	passert(&sas->st == &sas->ike.sa);
	struct state *st = &sas->st;
	*st = (struct state) {
		.st_whack_sock = null_fd,	/* note: not 0 */
		.st_finite_state = &state_undefined,
		.st_serialno = next_so++,
	};
	passert(next_so > SOS_FIRST);   /* overflow can't happen! */

	anyaddr(AF_INET, &st->hidden_variables.st_nat_oa);
	anyaddr(AF_INET, &st->hidden_variables.st_natd);

	DBG(DBG_CONTROL, DBG_log("creating state object #%lu at %p",
				 st->st_serialno, (void *) st));
	DBG(DBG_CONTROLMORE, {
		enum categories cg = categorize_state(st, st->st_state);
		DBG_log("%s state #%lu: new => %s(%s)",
			IS_PARENT_SA(st) ? "parent" : "child", st->st_serialno,
			st->st_state_name, enum_name(&cat_names, cg));
	});

	return st;
}

struct state *new_rstate(struct msg_digest *md)
{
	struct state *st = new_state();
	update_ike_endpoints(st, md);

	return st;
}
/*
 * Initialize the state table
 *
 * Redundant.
 */
void init_states(void)
{
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
	if (st->st_ikev2)
		return;

	if (IS_IKE_SA(st) && streq(st->st_xauth_username, name)) {
		delete_my_family(st, FALSE);
		/* note: no md->st to clear */
	}
}

static bool ikev2_child_eq_pst_msgid(const struct state *st,
		so_serial_t psn, msgid_t st_msgid)
{
	if (st->st_clonedfrom == psn &&
			st->st_msgid == st_msgid &&
			IS_CHILD_IPSECSA_RESPONSE(st)) {
		return TRUE;
	}
	return FALSE;
}

static bool ikev2_child_resp_eq_pst_msgid(const struct state *st,
		so_serial_t psn, msgid_t st_msgid)
{
	if (st->st_clonedfrom == psn &&
			st->st_msgid == st_msgid &&
			IS_CHILD_SA_RESPONDER(st)) {
		return TRUE;
	}
	return FALSE;
}

/*
 * Find the state object that match the following:
 *	st_msgid (IKEv2 Child responder state)
 *	parent duplicated from
 *	expected state
 */

struct state *resp_state_with_msgid(so_serial_t psn, msgid_t st_msgid)
{
	passert(psn >= SOS_FIRST);

	FOR_EACH_COOKIED_STATE(st, {
		if (ikev2_child_resp_eq_pst_msgid(st, psn, st_msgid))
			return st;
	});
	DBG(DBG_CONTROL,
		DBG_log("no waiting child state matching pst #%lu msg id %u",
			psn, ntohs(st_msgid)));
	return NULL;
}

/*
 * Find the state object that match the following:
 *	st_msgid (IKE/IPsec initiator state)
 *	parent duplicated from
 *	expected state
 */
struct state *state_with_parent_msgid(so_serial_t psn, msgid_t st_msgid)
{
	passert(psn >= SOS_FIRST);

	FOR_EACH_COOKIED_STATE(st, {
		if (ikev2_child_eq_pst_msgid(st, psn, st_msgid))
			return st;
	});
	DBG(DBG_CONTROL,
		DBG_log("no waiting child state matching pst #%lu msg id %u",
			psn, ntohs(st_msgid)));
	return NULL;
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
 * Insert a state object in the hash table. The object is inserted
 * at the beginning of list.
 * Needs cookies, connection, and msgid.
 */
void insert_state(struct state *st)
{
	DBG(DBG_CONTROL,
	    DBG_log("inserting state object #%lu",
		    st->st_serialno))

	add_state_to_db(st);
	refresh_state(st);
}

/*
 * Re-insert the state in the dabase after updating the RCOOKIE, and
 * possibly the ICOOKIE.
 *
 * ICOOKIE is only updated if icookie != NULL
 */
void rehash_state(struct state *st, const u_char *icookie,
		const u_char *rcookie)
{
	DBG(DBG_CONTROL,
	    DBG_log("rehashing state object #%lu",
		    st->st_serialno));
	/* update the cookie */
	memcpy(st->st_rcookie, rcookie, COOKIE_SIZE);
	if (icookie != NULL)
		memcpy(st->st_icookie, icookie, COOKIE_SIZE);
	/* now, update the state */
	rehash_state_cookies_in_db(st);
	/* just logs change */
	refresh_state(st);
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
	passert(st->st_ikev2);

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
	struct ike_frag *frag = st->st_v1_rfrags;

	passert(!st->st_ikev2);
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
	if (!st->st_ikev2)
		release_v1fragments(st);
	else
		release_v2fragments(st);
}

void ikev2_expire_unused_parent(struct state *pst)
{
	struct state *st;

	if (pst == NULL || !IS_PARENT_SA_ESTABLISHED(pst))
		return; /* only deal with established parent SA */

	FOR_EACH_STATE_WITH_COOKIES(st, pst->st_icookie, pst->st_rcookie, {
		if (st->st_clonedfrom == pst->st_serialno)
			return;
	});

	{
		char cib[CONN_INST_BUF];
		struct connection *c = pst->st_connection;

		loglog(RC_INFORMATIONAL, "expire unused parent SA #%lu \"%s\"%s",
				pst->st_serialno, c->name,
				fmt_conn_instance(c, cib));
		event_force(EVENT_SA_EXPIRE, pst);
	}
}

static void flush_pending_child(struct state *pst, struct state *st)
{
	if (!IS_IKE_SA(pst))
		return; /* we had better be a parent */

	if (st->st_clonedfrom == pst->st_serialno) {
		char cib[CONN_INST_BUF];
		struct connection *c = st->st_connection;

		if (IS_IPSEC_SA_ESTABLISHED(st))
			return;

		so_serial_t newest_sa = c->newest_ipsec_sa;
		if (IS_IKE_REKEY_INITIATOR(st))
			newest_sa = c->newest_isakmp_sa;

		if (st->st_serialno > newest_sa &&
				(c->policy & POLICY_UP) &&
				(c->policy & POLICY_DONT_REKEY) == LEMPTY)
		{
			loglog(RC_LOG_SERIOUS, "reschedule pending child #%lu %s of "
					"connection \"%s\"%s - the parent is going away",
					st->st_serialno, st->st_state_name,
					c->name, fmt_conn_instance(c, cib));

			c->failed_ikev2 = FALSE; /* give it a fresh start */
			st->st_policy = c->policy; /* for pick_initiator */
			event_force(EVENT_SA_REPLACE, st);
		} else {
			loglog(RC_LOG_SERIOUS, "expire pending child #%lu %s of "
					"connection \"%s\"%s - the parent is going away",
					st->st_serialno, st->st_state_name,
					c->name, fmt_conn_instance(c, cib));

			event_force(EVENT_SA_EXPIRE, st);
		}
	}
}

static void flush_pending_children(struct state *pst)
{
	if (IS_CHILD_SA(pst))
		return;

	FOR_EACH_COOKIED_STATE(st, {
			if (st->st_clonedfrom == pst->st_serialno) {
				flush_pending_child(pst, st);
				delete_cryptographic_continuation(st);
			}
		});
}

static bool send_delete_check(const struct state *st)
{
	if (st->st_suppress_del_notify)
		return FALSE;

	if (IS_IPSEC_SA_ESTABLISHED(st) ||
			IS_ISAKMP_SA_ESTABLISHED(st->st_state))
	{
		if (st->st_ikev2 &&
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

	if ((c->policy & POLICY_OPPORTUNISTIC) && !IS_IKE_SA_ESTABLISHED(st)) {
		/* reduced logging of OE failures */
		DBG(DBG_LIFECYCLE, {
			char cib[CONN_INST_BUF];

			DBG_log("deleting state #%lu (%s) \"%s\"%s and %ssending notification",
				st->st_serialno,
				st->st_state_name,
				c->name,
				fmt_conn_instance(c, cib),
				del_notify ? "" : "NOT ");
	});
	} else if (cur_state != NULL && cur_state == st) {
		/*
		* Don't log state and connection if it is the same as
		* the message prefix.
		*/
		libreswan_log("deleting state (%s) and %ssending notification",
			st->st_state_name,
			del_notify ? "" : "NOT ");
	} else if (cur_state != NULL && cur_state->st_connection == st->st_connection) {
		libreswan_log("deleting other state #%lu (%s) and %ssending notification",
			st->st_serialno,
			st->st_state_name,
			del_notify ? "" : "NOT ");
	} else {
		char cib[CONN_INST_BUF];
		libreswan_log("deleting other state #%lu connection (%s) \"%s\"%s and %ssending notification",
			st->st_serialno,
			st->st_state_name,
			c->name,
			fmt_conn_instance(c, cib),
			del_notify ? "" : "NOT ");
	}

	DBG(DBG_CONTROLMORE, {
		enum categories cg = categorize_state(st, st->st_state);
		DBG_log("%s state #%lu: %s(%s) => delete",
			IS_PARENT_SA(st) ? "parent" : "child", st->st_serialno,
			st->st_state_name, enum_name(&cat_names, cg));
	});
}

/* delete a state object */
void delete_state(struct state *st)
{
	struct connection *const c = st->st_connection;

	/*
	 * statistics for IKE SA failures. We cannot do the same for IPsec SA
	 * because those failures could happen before we cloned a state
	 */
	if (st->st_clonedfrom == SOS_NOBODY) {
		if (!IS_IKE_SA_ESTABLISHED(st)) {
			if (st->st_ikev2)
				pstats_ikev2_fail++;
			else
				pstats_ikev1_fail++;
		}
	}

	so_serial_t old_serialno = push_cur_state(st);
	delete_state_log(st, state_by_serialno(old_serialno));

#ifdef USE_LINUX_AUDIT
	/*
	 * only log parent state deletes, we log children in
	 * ipsec_delete_sa()
	 */
	if (IS_IKE_SA_ESTABLISHED(st) || st->st_state == STATE_IKESA_DEL)
		linux_audit_conn(st, LAK_PARENT_DESTROY);
#endif

	/* If we are failed OE initiator, make shunt bare */
	if (IS_IKE_SA(st) && (c->policy & POLICY_OPPORTUNISTIC) &&
	    (st->st_state == STATE_PARENT_I1 || st->st_state == STATE_PARENT_I2)) {
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

	/* If DPD is enabled on this state object, clear any pending events */
	if (st->st_dpd_event != NULL)
		delete_dpd_event(st);

	/* clear any ikev2 liveness events */
	if (st->st_ikev2)
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
	flush_pending_children(st);

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
		st->st_state == STATE_CHILDSA_DEL) {
			delete_ipsec_sa(st);
	}

	if (c->newest_ipsec_sa == st->st_serialno)
		c->newest_ipsec_sa = SOS_NOBODY;

	if (c->newest_isakmp_sa == st->st_serialno)
		c->newest_isakmp_sa = SOS_NOBODY;

	/*
	 * fake a state change here while we are still associated with a
	 * connection.  Without this the state logging (when enabled) cannot
	 * work out what happened.
	 */
	fake_state(st, STATE_UNDEFINED);

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
	FOR_EACH_COOKIED_STATE(st, {
		if (st->st_connection == c)
			return TRUE;
	});

	return FALSE;
}

bool shared_phase1_connection(const struct connection *c)
{
	so_serial_t serial_us = c->newest_isakmp_sa;

	if (serial_us == SOS_NOBODY)
		return FALSE;

	FOR_EACH_COOKIED_STATE(st, {
		if (st->st_connection != c && st->st_clonedfrom == serial_us)
			return TRUE;
	});

	return FALSE;
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
		FOR_EACH_COOKIED_STATE(this, {
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
		});
	}
}

/*
 * Delete all states that have somehow not ben deleted yet
 * but using interfaces that are going down
 */

void delete_states_dead_interfaces(void)
{
	FOR_EACH_COOKIED_STATE(this, {
		if (this->st_interface &&
		    this->st_interface->change == IFN_DELETE) {
			libreswan_log(
				"deleting lasting state #%lu on interface (%s) which is shutting down",
				this->st_serialno,
				this->st_interface->ip_dev->id_vname);
			delete_state(this);
			/* note: no md->st to clear */
		}
	});
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
 * delete_p2states_by_connection - deletes only the phase 2 of conn
 *
 * @c - the connection whose states need to be removed.
 *
 * This is like delete_states_by_connection with relations=TRUE,
 * but it only deletes phase 2 states.
 */
static bool same_phase1_no_phase2(struct state *this,
				  struct connection *c)
{
	if (IS_ISAKMP_SA_ESTABLISHED(this->st_state))
		return FALSE;
	if (c->kind == CK_INSTANCE)
		return same_phase1_sa_relations(this, c);
	return FALSE;
}

void delete_p2states_by_connection(struct connection *c)
{
	enum connection_kind ck = c->kind;

	/*
	 * save this connection's isakmp SA,
	 * since it will get set to later SOS_NOBODY
	 */
	if (ck == CK_INSTANCE)
		c->kind = CK_GOING_AWAY;

	foreach_state_by_connection_func_delete(c, same_phase1_no_phase2);

	if (ck == CK_INSTANCE) {
		c->kind = ck;
		delete_connection(c, TRUE);
	}
}

/*
 * Walk through the state table, and delete each state whose phase 1 (IKE)
 * peer is among those given.
 * This function is only called for ipsec whack --crash peer
 */
void delete_states_by_peer(const ip_address *peer)
{
	char peerstr[ADDRTOT_BUF];

	addrtot(peer, 0, peerstr, sizeof(peerstr));

	whack_log(RC_COMMENT, "restarting peer %s\n", peerstr);

	/* first restart the phase1s */
	for (int ph1 = 0; ph1 < 2; ph1++) {
		/* For each hash chain... */
		FOR_EACH_COOKIED_STATE(this, {
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
		});
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
static struct state *duplicate_state(struct state *st, sa_t sa_type)
{
	struct state *nst;
	char cib[CONN_INST_BUF];

	if (sa_type == IPSEC_SA) {
		/* record use of the Phase 1 / Parent state */
		st->st_outbound_count++;
		st->st_outbound_time = mononow();
	}

	nst = new_state();

	DBG(DBG_CONTROL,
		DBG_log("duplicating state object #%lu \"%s\"%s as #%lu for %s",
			 st->st_serialno,
			 st->st_connection->name,
			 fmt_conn_instance(st->st_connection, cib),
			 nst->st_serialno,
			 sa_type == IPSEC_SA ? "IPSEC SA" : "IKE SA"));

	nst->st_connection = st->st_connection;
	if (sa_type == IPSEC_SA) {
		memcpy(nst->st_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(nst->st_rcookie, st->st_rcookie, COOKIE_SIZE);
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
	nst->st_ikev2 = st->st_ikev2;
	nst->st_ikev2_anon = st->st_ikev2_anon;
	nst->st_original_role = st->st_original_role;
	nst->st_seen_fragvid = st->st_seen_fragvid;
	nst->st_seen_fragments = st->st_seen_fragments;
	nst->st_seen_ppk = st->st_seen_ppk;
	nst->st_event = NULL;


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
	return duplicate_state(st, IPSEC_SA);
}

struct state *ikev2_duplicate_state(struct ike_sa *ike,
				    sa_t sa_type, enum sa_role role)
{
	struct state *cst = duplicate_state(&ike->sa, sa_type);
	cst->st_sa_role = role;
	return cst;
}

void for_each_state(void (*f)(struct state *, void *data), void *data)
{
	FOR_EACH_COOKIED_STATE(st, {
		/*
		 * Since OLD_STATE might be deleted by f();
		 * save/restore using serialno.
		 */
		so_serial_t old_serialno = push_cur_state(st);
		(*f)(st, data);
		pop_cur_state(old_serialno);
	});
}

/*
 * Find a state object for an IKEv1 state
 */

struct state *find_state_ikev1(const uint8_t *icookie,
			       const uint8_t *rcookie,
			       msgid_t /*network order*/ msgid)
{
	struct state *st = NULL;
	FOR_EACH_STATE_WITH_COOKIES(st, icookie, rcookie, {
		if (!st->st_ikev2) {
			DBG(DBG_CONTROL,
			    DBG_log("v1 peer and cookies match on #%lu, provided msgid %08" PRIx32 " == %08" PRIx32,
				    st->st_serialno,
				    ntohl(msgid),
				    ntohl(st->st_msgid)));
			if (msgid == st->st_msgid)
				break;
		}
	});

	DBG(DBG_CONTROL, {
		    if (st == NULL) {
			    DBG_log("v1 state object not found");
		    } else {
			    DBG_log("v1 state object #%lu found, in %s",
				    st->st_serialno,
				    st->st_state_name);
		    }
	    });

	return st;
}

struct state *find_state_ikev1_init(const uint8_t *icookie,
				    msgid_t /*network order*/ msgid)
{
	struct state *st = NULL;
	FOR_EACH_STATE_WITH_ICOOKIE(st, icookie, {
		if (!st->st_ikev2) {
			DBG(DBG_CONTROL,
			    DBG_log("v1 peer and icookie match on #%lu, provided msgid %08" PRIx32 " == %08" PRIx32,
				    st->st_serialno,
				    ntohl(msgid),
				    ntohl(st->st_msgid)));
			if (msgid == st->st_msgid)
				break;
		}
	});

	DBG(DBG_CONTROL, {
		    if (st == NULL) {
			    DBG_log("v1 state object not found");
		    } else {
			    DBG_log("v1 state object #%lu found, in %s",
				    st->st_serialno,
				    st->st_state_name);
		    }
	    });

	return st;
}

/*
 * Find a state object for an IKEv2 state.
 * Note: only finds parent states.
 */
struct state *find_state_ikev2_parent(const u_char *icookie,
				      const u_char *rcookie)
{
	struct state *st;
	FOR_EACH_STATE_WITH_COOKIES(st, icookie, rcookie, {
		if (st->st_ikev2 &&
		    !IS_CHILD_SA(st)) {
			DBG(DBG_CONTROL,
			    DBG_log("parent v2 peer and cookies match on #%lu",
				    st->st_serialno));
			break;
		}
	});

	DBG(DBG_CONTROL, {
		if (st == NULL) {
			DBG_log("parent v2 state object not found");
		} else {
			DBG_log("v2 state object #%lu found, in %s",
				st->st_serialno,
				st->st_state_name);
		}
	});

	return st;
}

/*
 * Find a state object for an IKEv2 state, looking by icookie only and
 * matching "struct state" objects in the correct state and IS_CHILD.
 *
 * Note: only finds parent states (this is ok as only interested in
 * state objects in the initial state).
 */
struct state *ikev2_find_state_in_init(const u_char *icookie,
				       enum state_kind expected_state)
{
	struct state *st;
	FOR_EACH_STATE_WITH_ICOOKIE(st, icookie, {
			if (st->st_ikev2 &&
			    st->st_state == expected_state &&
			    !IS_CHILD_SA(st)) {
				DBG(DBG_CONTROL,
				    DBG_log("parent_init v2 peer and cookies match on #%lu",
					    st->st_serialno);
				    DBG_log("v2 state object #%lu found, in %s",
					    st->st_serialno,
					    st->st_state_name));
				return st;
			}
		});

	DBG(DBG_CONTROL, DBG_log("parent_init v2 state object not found"));
	return NULL;
}

/*
 * Find a state object for an IKEv2 state, a response that includes a msgid.
 */

static bool ikev2_ix_state_match(const struct state *st,
		const enum isakmp_xchg_types ix)
{
	bool ret = FALSE;

	switch (ix) {
	case ISAKMP_v2_SA_INIT:
	case ISAKMP_v2_AUTH:
	case ISAKMP_v2_INFORMATIONAL:
		ret = TRUE; /* good enough, strict check could be double work */
		break;

	case ISAKMP_v2_CREATE_CHILD_SA:
		if (IS_CHILD_IPSECSA_RESPONSE(st))
			ret = TRUE;
		break;

	default:
		DBG(DBG_CONTROLMORE, DBG_log("unsolicited response? did we send %s request? ",
					enum_name(&ikev2_exchange_names, ix)));
		break;
	}

	return ret;
}

struct state *find_state_ikev2_child(const enum isakmp_xchg_types ix,
				     const u_char *icookie,
				     const u_char *rcookie,
				     const msgid_t msgid)
{
	struct state *st;
	FOR_EACH_STATE_WITH_COOKIES(st, icookie, rcookie, {
		if (st->st_ikev2 &&
		    st->st_msgid == msgid &&
		    ikev2_ix_state_match(st, ix)) {
			DBG(DBG_CONTROL,
			    DBG_log("v2 peer, cookies and msgid match on #%lu",
				    st->st_serialno));
			break;
		}
	});

	DBG(DBG_CONTROL, {
		if (st == NULL) {
			DBG_log("v2 state object not found");
		} else {
			DBG_log("v2 state object #%lu found, in %s",
				st->st_serialno,
				st->st_state_name);
		}
	});

	return st;
}

/*
 * Find a state object for an IKEv2 child state to delete.
 * In IKEv2, child states can only be distingusihed based on protocols and SPIs
 */
struct state *find_state_ikev2_child_to_delete(const u_char *icookie,
					       const u_char *rcookie,
					       uint8_t protoid,
					       ipsec_spi_t spi)
{
	struct state *st;
	FOR_EACH_STATE_WITH_COOKIES(st, icookie, rcookie, {
		if (st->st_ikev2 && IS_CHILD_SA(st)) {
			struct ipsec_proto_info *pr;

			switch (protoid) {
			case PROTO_IPSEC_AH:
				pr = &st->st_ah;
				break;
			case PROTO_IPSEC_ESP:
				pr = &st->st_esp;
				break;
			default:
				bad_case(protoid);
			}

			if (pr->present) {
				if (pr->attrs.spi == spi)
					break;
				if (pr->our_spi == spi)
					break;
			}

		}
	});

	DBG(DBG_CONTROL, {
		    if (st == NULL) {
			    DBG_log("v2 child state object not found");
		    } else {
			    DBG_log("v2 child state object #%lu found, in %s",
				    st->st_serialno,
				    st->st_state_name);
		    }
	    });

	return st;
}

/*
 * Find a state object.
 */
struct state *ikev1_find_info_state(const u_char *icookie,
			      const u_char *rcookie,
			      const ip_address *peer UNUSED,
			      msgid_t /* network order */ msgid)
{
	struct state *st;
	FOR_EACH_STATE_WITH_COOKIES(st, icookie, rcookie, {
		DBG(DBG_CONTROL,
		    DBG_log("peer and cookies match on #%lu; msgid=%08" PRIx32 " st_msgid=%08" PRIx32 " st_msgid_phase15=%08" PRIx32,
			    st->st_serialno,
			    ntohl(msgid),
			    ntohl(st->st_msgid),
			    ntohl(st->st_msgid_phase15)));
		if ((st->st_msgid_phase15 != v1_MAINMODE_MSGID &&
		     msgid == st->st_msgid_phase15) ||
		    msgid == st->st_msgid)
			break;
	});

	DBG(DBG_CONTROL, {
		if (st == NULL) {
			DBG_log("p15 state object not found");
		} else {
			DBG_log("p15 state object #%lu found, in %s",
				st->st_serialno,
				st->st_state_name);
		}
	});

	return st;
}

/*
 * Find the state that sent a packet with this prefix
 * ??? this could be expensive -- it should be rate-limited to avoid DoS
 */
struct state *find_likely_sender(size_t packet_len, u_char *packet)
{
	if (packet_len >= sizeof(struct isakmp_hdr)) {
		FOR_EACH_COOKIED_STATE(st, {
			if (st->st_tpacket.ptr != NULL &&
			    st->st_tpacket.len >= packet_len &&
			    memeq(st->st_tpacket.ptr, packet, packet_len))
			{
				return st;
			}
		});
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
	FOR_EACH_COOKIED_STATE(st, {
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
	});
	return bogusst;
}

bool find_pending_phase2(const so_serial_t psn,
		const struct connection *c, lset_t ok_states)
{
	struct state *best = NULL;
	int n = 0;

	passert(psn >= SOS_FIRST);

	FOR_EACH_COOKIED_STATE(st, {
		if (LHAS(ok_states, st->st_state) &&
		    IS_CHILD_SA(st) &&
		    st->st_clonedfrom == psn &&
		    streq(st->st_connection->name, c->name)) /* not instances */
		{
			n++;
			if (best == NULL || best->st_serialno < st->st_serialno)
				best = st;
		}
	});

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
	if (!ike->sa.st_ikev2)
		return TRUE;

	monotime_t now = mononow();
	const struct pluto_event *ev = ike->sa.st_event;
	long lifetime = monobefore(now, ev->ev_time) ?
				deltasecs(monotimediff(ev->ev_time, now)) :
				-1 * deltasecs(monotimediff(now, ev->ev_time));

	if (lifetime > PARENT_MIN_LIFE)
		/* in case st_margin == 0, insist minimum life */
		if (lifetime > deltasecs(ike->sa.st_margin))
			return TRUE;

		loglog(RC_LOG_SERIOUS, "no new CREATE_CHILD_SA exchange using #%lu. Parent lifetime %ld < st_margin %jd",
				ike->sa.st_serialno, lifetime,
				deltasecs(ike->sa.st_margin));

	return FALSE;
}

/*
 * Find newest Phase 1 negotiation state object for suitable for connection c
 */
struct state *find_phase1_state(const struct connection *c, lset_t ok_states)
{
	struct state *best = NULL;
	bool is_ikev2 = (c->policy & POLICY_IKEV1_ALLOW) == LEMPTY;

	FOR_EACH_COOKIED_STATE(st, {
		if (LHAS(ok_states, st->st_state) &&
		    st->st_ikev2 == is_ikev2 &&
		    c->host_pair == st->st_connection->host_pair &&
		    same_peer_ids(c, st->st_connection, NULL) &&
		    IS_PARENT_SA(st) &&
		    (best == NULL || best->st_serialno < st->st_serialno))
		{
			best = st;
		}
	});

	return best;
}

void state_eroute_usage(const ip_subnet *ours, const ip_subnet *his,
			unsigned long count, monotime_t nw)
{
	FOR_EACH_COOKIED_STATE(st, {
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
	});
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
		} else if (dpd_active_locally(st) && st->st_ikev2) {
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
			if (!st->st_ikev2)
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
		 st->st_state_name,
		 st->st_state_story,
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
#ifdef KLIPS
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

	FOR_EACH_COOKIED_STATE(st, {
		count++;
	});

	if (count == 0) {
		return NULL;
	}

	/*
	 * Create an array of COUNT+1 (NULL terminal) state pointers.
	 */
	struct state **array = alloc_things(struct state *, count + 1, "sorted state");
	{
		int p = 0;

		FOR_EACH_COOKIED_STATE(st, {
			passert(st != NULL);
			array[p++] = st;
		});
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

void show_states_status(void)
{
	whack_log(RC_COMMENT, " ");             /* spacer */
	whack_log(RC_COMMENT, "State Information: DDoS cookies %s, %s new IKE connections",
		  require_ddos_cookies() ? "REQUIRED" : "not required",
		  drop_new_exchanges() ? "NOT ACCEPTING" : "Accepting");

	whack_log(RC_COMMENT, "IKE SAs: total(%u), half-open(%u), open(%u), authenticated(%u), anonymous(%u)",
		  total_ike(),
		  cat_count[CAT_HALF_OPEN_IKE],
		  cat_count[CAT_OPEN_IKE],
		  cat_count[CAT_AUTHENTICATED_IKE],
		  cat_count[CAT_ANONYMOUS_IKE]);
	whack_log(RC_COMMENT, "IPsec SAs: total(%u), authenticated(%u), anonymous(%u)",
		  total_ipsec(),
		  cat_count[CAT_AUTHENTICATED_IPSEC], cat_count[CAT_ANONYMOUS_IPSEC]);
	whack_log(RC_COMMENT, " ");             /* spacer */

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
	FOR_EACH_COOKIED_STATE(st, {
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
	});
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
 */
ipsec_spi_t uniquify_his_cpi(ipsec_spi_t cpi, const struct state *st)
{
	int tries = 0;

startover:

	/* network order makes first two bytes our target */
	get_rnd_bytes((u_char *)&cpi, 2);

	/*
	 * Make sure that the result is unique.
	 * Hard work.  If there is no unique value, we'll loop forever!
	 */
	FOR_EACH_COOKIED_STATE(s, {
		if (s->st_ipcomp.present &&
		    sameaddr(&s->st_connection->spd.that.host_addr,
			     &st->st_connection->spd.that.host_addr) &&
		    cpi == s->st_ipcomp.attrs.spi)
		{
			if (++tries == 20)
				return 0; /* FAILURE */

			goto startover;
		}
	});
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

	if (!sameaddr(&st->st_remoteaddr, &md->sender) ||
		st->st_remoteport != hportof(&md->sender)) {
		char oldip[ADDRTOT_BUF];
		char newip[ADDRTOT_BUF];

		addrtot(&st->st_remoteaddr, 0, oldip, sizeof(oldip));
		addrtot(&md->sender, 0, newip, sizeof(newip));
	} // why is below not part of this statement????

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

static void  set_st_clonedfrom(struct state *st, so_serial_t nsn)
{
	/* add debug line  too */
	DBG(DBG_CONTROLMORE, DBG_log("#%lu inherit #%lu from parent #%lu",
		nsn, st->st_serialno, st->st_clonedfrom));
	st->st_clonedfrom = nsn;
}

/* Kick the IPsec SA, when the parent is already replaced, to replace now */
void ikev2_repl_est_ipsec(struct state *st, void *data)
{
	so_serial_t predecessor = *(so_serial_t *)data;

	if (st->st_clonedfrom != predecessor)
		return;

	if (predecessor != st->st_connection->newest_isakmp_sa) {
		DBG(DBG_CONTROLMORE,
			DBG_log("#%lu, replacing #%lu. #%lu is not the newest IKE SA of %s",
				predecessor, st->st_serialno,
				predecessor, st->st_connection->name));
	}

	enum event_type ev_type = st->st_event->ev_type;

	passert(st->st_event != NULL);
	event_force(ev_type, st);
}

void ikev2_inherit_ipsec_sa(so_serial_t osn, so_serial_t nsn,
		const u_char *icookie, const u_char *rcookie)
{
	/* new sn, IKE parent, Inherit IPSEC SA from previous IKE with osn. */

	passert(nsn >= SOS_FIRST);

	FOR_EACH_COOKIED_STATE(st, {
		if (st->st_clonedfrom == osn) {
			set_st_clonedfrom(st, nsn);
			rehash_state(st, icookie, rcookie);
		}
	});
}

void delete_my_family(struct state *pst, bool v2_responder_state)
{
	/*
	 * We are a parent: delete our children and
	 * then prepare to delete ourself.
	 * Our children will be on the same hash chain
	 * because we share IKE SPIs.
	 */
	struct state *st;

	passert(!IS_CHILD_SA(pst));	/* we had better be a parent */
	FOR_EACH_STATE_WITH_COOKIES(st, pst->st_icookie, pst->st_rcookie, {
		if (st->st_clonedfrom == pst->st_serialno) {
			if (v2_responder_state)
				change_state(st, STATE_CHILDSA_DEL);
			delete_state(st);
		}
		/* note: no md->st to clear */
	});

	/* delete self */
	if (v2_responder_state)
		change_state(pst, STATE_IKESA_DEL);
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
		LSWLOG_LOG(buf) {
			lswlog_log_prefix(buf);
			lswlogf(buf, "discarding packet received during asynchronous work (DNS or crypto) in %s",
				st->st_state_name);
		}
	} else if (st->st_offloaded_task != NULL) {
		libreswan_log("message received while calculating. Ignored.");
	}
	return true;
}

bool require_ddos_cookies(void)
{
	return pluto_ddos_mode == DDOS_FORCE_BUSY ||
		(pluto_ddos_mode == DDOS_AUTO &&
		 cat_count[CAT_HALF_OPEN_IKE] >= pluto_ddos_threshold);
}

bool drop_new_exchanges(void)
{
	return cat_count[CAT_HALF_OPEN_IKE] >= pluto_max_halfopen;
}

void show_globalstate_status(void)
{
	unsigned shunts = show_shunt_count();

	whack_log_comment("config.setup.ike.ddos_threshold=%u", pluto_ddos_threshold);
	whack_log_comment("config.setup.ike.max_halfopen=%u", pluto_max_halfopen);

	/* technically shunts are not a struct state's - but makes it easier to group */
	whack_log_comment("current.states.all=%u", shunts + total());
	whack_log_comment("current.states.ipsec=%u", total_ipsec());
	whack_log_comment("current.states.ike=%u", total_ike());
	whack_log_comment("current.states.shunts=%u", shunts);
	whack_log_comment("current.states.iketype.anonymous=%u",
		  cat_count[CAT_ANONYMOUS_IKE]);
	whack_log_comment("current.states.iketype.authenticated=%u",
		  cat_count[CAT_AUTHENTICATED_IKE]);
	whack_log_comment("current.states.iketype.halfopen=%u",
		  cat_count[CAT_HALF_OPEN_IKE]);
	whack_log_comment("current.states.iketype.open=%u",
		  cat_count[CAT_OPEN_IKE]);
	for (enum state_kind s = STATE_IKEv1_FLOOR; s < STATE_IKEv1_ROOF; s++) {
		whack_log_comment("current.states.enumerate.%s=%u",
			enum_name(&state_names, s), state_count[s]);
	}
	for (enum state_kind s = STATE_IKEv2_FLOOR; s < STATE_IKEv2_ROOF; s++) {
		whack_log_comment("current.states.enumerate.%s=%u",
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
				st->st_ikev2 ? "IKEv2" : "IKEv1",
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
	for_each_state(ikev2_record_newaddr, ip);
}

void record_deladdr(ip_address *ip, char *a_type)
{
	ipstr_buf ip_str;
	DBG(DBG_KERNEL, DBG_log("XFRM RTM_DELADDR %s %s",
				ipstr(ip, &ip_str), a_type));
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
