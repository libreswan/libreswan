/*
 * routines for state objects
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001, 2013-2015 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012 Bram <bram-bcrafjna-erqzvar@spam.wizbit.be>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
 * Copyright (C) 2015 Antony Antony <antony@phenome.org>
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
#ifdef XAUTH_HAVE_PAM
#include <security/pam_appl.h>
#include "ikev1_xauth.h"	/* just for state_deletion_xauth_cleanup() */
#endif
#include "connections.h"	/* needs id.h */
#include "state.h"
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

#include "sha1.h"
#include "md5.h"
#include "cookie.h"
#include "crypto.h"	/* requires sha1.h and md5.h */
#include "crypt_symkey.h"
#include "spdb.h"
#include "ikev2.h"
#include "secrets.h"    /* unreference_key() */

#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>

static void update_state_stats(struct state *st, enum state_kind old_state,
			       enum state_kind new_state);

/*
 * Global variables: had to go somewhere, might as well be this file.
 */

u_int16_t pluto_port = IKE_UDP_PORT;	/* Pluto's port */
u_int16_t pluto_nat_port = NAT_IKE_UDP_PORT;	/* Pluto's NAT-T port */

/*
 * default global NFLOG group - 0 means no logging
 * Note: variable is only used to display in ipsec status
 * actual work is done outside pluto, by ipsec --checknflog
 */
u_int16_t pluto_nflog_group = 0;

/*
 * Note: variable is only used to display in ipsec status
 * actual work is done outside pluto, by ipsec _stackmanager
 */
u_int16_t pluto_xfrmlifetime = 300;

/*
 * This file has the functions that handle the
 * state hash table and the Message ID list.
 */

/* for DDoS tracking, used in change_state */
static unsigned int state_count[MAX_STATES];

void change_state(struct state *st, enum state_kind new_state)
{
	enum state_kind old_state = st->st_state;

	/*
	 * This always logs the state transition (even when nothing
	 * happens), and the state category.
	 */
	update_state_stats(st, old_state, new_state);

	if (new_state == old_state)
		return;

	log_state(st, new_state);
	st->st_state = new_state;
}

/* non-intersecting state categories */
struct state_category {
	const char *description;
	unsigned int count;
};

struct {
	struct state_category ignore;
	struct state_category half_open_ike;
	struct state_category open_ike;
	struct state_category anonymous_ike;
	struct state_category authenticated_ike;
	struct state_category anonymous_ipsec;
	struct state_category authenticated_ipsec;
	struct state_category informational;
	struct state_category unknown;
} category = {
	.ignore = { .description = "ignore" },
	.half_open_ike = { .description = "half-open-ike" },
	.open_ike = { .description = "open-ike" },
	.anonymous_ike = { .description = "established-anonymous-ike" },
	.authenticated_ike = { .description = "established-authenticated-ike" },
	.anonymous_ipsec = { .description = "anonymous-ipsec", },
	.authenticated_ipsec = { .description = "authenticated-ipsec", },
	.informational = { .description = "informational", },
	.unknown = { .description = "unknown", },
};

/* space for unknown as well */
static unsigned int total_established_ike(void)
{
	return category.anonymous_ike.count +
		category.authenticated_ike.count;
}

static unsigned int total_ike(void)
{
	return category.half_open_ike.count +
		category.open_ike.count +
		total_established_ike();
}

static unsigned int total_ipsec(void)
{
	return category.authenticated_ipsec.count +
		category.anonymous_ipsec.count;
}

static unsigned int total(void)
{
	return total_ike() + total_ipsec() + category.unknown.count;
}

static struct state_category *categorize_state(struct state *st,
					       enum state_kind state)
{
	bool is_parent = IS_PARENT_SA(st);
	bool opportunistic = (st->st_connection != NULL &&
			      st->st_connection->policy & POLICY_OPPORTUNISTIC);
	struct state_category *established_ike = (opportunistic
						  ? &category.anonymous_ike
						  : &category.authenticated_ike);
	struct state_category *established_ipsec = (opportunistic
						    ? &category.anonymous_ipsec
						    : &category.authenticated_ipsec);

	/*
	 * Use a switch with no default so that missing and extra
	 * states get a -Wswitch diagnostic
	 */
	switch (state) {

		/*
		 * IKEv2 initiators, while the INIT packet is being
		 * constructed, are in STATE_IKEv2_BASE.  Only when
		 * the packet is sent out do they transition into
		 * STATE_PARENT_I1 and start being counted as
		 * half-open.
		 */
	case STATE_IKEv2_BASE:
	case STATE_IKEv2_ROOF:
	case STATE_UNDEFINED:
	case STATE_IKE_ROOF:
		return &category.ignore;

		/*
		 * Count I1 as half-open too because with OE,
		 * a plaintext packet (that is spoofed) will
		 * trigger an outgoing IKE SA
		 *
		 * we could do better and check
		 * POLICY_OPPORTUNISTIC on I1's
		 */
	case STATE_PARENT_I1:
	case STATE_PARENT_R1:
	case STATE_AGGR_R0:
	case STATE_AGGR_I1:
	case STATE_MAIN_R0:
	case STATE_MAIN_I1:
		return &category.half_open_ike;

		/*
		 * All IKEv1 MAIN modes except the first
		 * (half-open) and last ones are not
		 * authenticated.
		 */
	case STATE_PARENT_I2:
	case STATE_MAIN_R1:
	case STATE_MAIN_R2:
	case STATE_MAIN_I2:
	case STATE_MAIN_I3:
	case STATE_AGGR_R1:
		return &category.open_ike;

		/*
		 * IKEv1 established states.
		 *
		 * XAUTH, seems to a second level of authentication
		 * performed after the connection is established and
		 * authenticated.
		 */
	case STATE_MAIN_I4:
	case STATE_MAIN_R3:
	case STATE_AGGR_I2:
	case STATE_AGGR_R2:
	case STATE_XAUTH_I0:
	case STATE_XAUTH_I1:
	case STATE_XAUTH_R0:
	case STATE_XAUTH_R1:
		return established_ike;

		/*
		 * IKEv2 established states.
		 */
	case STATE_PARENT_I3:
	case STATE_PARENT_R2:
		if (is_parent) {
			return established_ike;
		} else {
			return established_ipsec;
		}

	case STATE_IKESA_DEL:
		return established_ike;

		/*
		 * Some internal state, will it ever occure?
		 */
	case OPPO_ACQUIRE:
	case OPPO_GW_DISCOVERED:
		return &category.unknown;

		/*
		 * IKEv1: QUICK is for child connections children.
		 * Probably won't occure as a parent?
		 */
	case STATE_QUICK_I1:
	case STATE_QUICK_I2:
	case STATE_QUICK_R0:
	case STATE_QUICK_R1:
	case STATE_QUICK_R2:
		pexpect(!is_parent)
		return established_ipsec;

		/*
		 * IKEv1: Post established negotiation.
		 */
	case STATE_MODE_CFG_I1:
	case STATE_MODE_CFG_R1:
	case STATE_MODE_CFG_R2:
		return established_ike;

	case STATE_INFO:
	case STATE_INFO_PROTECTED:
	case STATE_MODE_CFG_R0:
	case STATE_CHILDSA_DEL:
		pexpect(!is_parent);
		return &category.informational;
	}

	return &category.unknown;
}

static void update_state_stats(struct state *st, enum state_kind old_state,
			enum state_kind new_state)
{
	struct state_category *old_category = categorize_state(st, old_state);
	struct state_category *new_category = categorize_state(st, new_state);

	/*
	 * Count everything except STATE_UNDEFINED et.al. All states
	 * start and end in those states.
	 */
	if (old_category != &category.ignore) {
		state_count[old_state]--;
		old_category->count--;
	}
	if (new_category != &category.ignore) {
		state_count[new_state]++;
		new_category->count++;
	}

	DBG(DBG_CONTROLMORE,
	    DBG_log("%s state #%lu: %s(%s) > %s(%s)",
		    IS_PARENT_SA(st) ? "parent" : "child", st->st_serialno,
		    enum_show(&state_names, old_state), old_category->description,
		    enum_show(&state_names, new_state), new_category->description);
	    struct state_category *state_category;
	    int category_states = 0;
	    for (state_category = (struct state_category *)&category;
		 state_category < (struct state_category *)(&category+1);
		 state_category++) {
		    DBG_log("%s states: %d", state_category->description,
			    state_category->count);
		    category_states += state_category->count;
	    }
	    int count_states = 0;
	    int s;
	    for (s = STATE_MAIN_R0; s < MAX_STATES; s++) {
		    count_states += state_count[s];
	    }
	    DBG_log("category states: %d count states: %d",
		    category_states, count_states);
	    pexpect(category_states == count_states));

	/* catch / log unexpected cases */
	pexpect(old_category != &category.unknown);
	pexpect(new_category != &category.unknown);

}

/*
 * Humanize_number: make large numbers clearer by expressing them as KB or MB,
 * as appropriate.
 * The prefix is literally copied into the output.
 * Tricky representation: if the prefix starts with !, the number
 * is taken as kilobytes.  Thus the caller does not scaling, with the attendant
 * risk of overflow.  The ! is not printed.
 */
static char *humanize_number(unsigned long num,
			     char *buf,
			     const char *buf_roof,
			     const char *prefix)
{
	size_t buf_len = buf_roof - buf;
	unsigned long to_print = num;
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

	ret = snprintf(buf, buf_len, "%s%lu%s", prefix, to_print,
		       suffix + kilos);
	if (ret < 0 || (size_t) ret >= buf_len)
		return buf;

	return buf + ret;
}


/*
 * Hash table indexed by just the ICOOKIE.
 *
 * This is set up to work with any cookie hash table, so, eventually
 * the code can be re-used on the old hash table.
 *
 * Access using hash_entry_common and unhash_entry above.
 */
static struct state_hash_table icookie_hash_table = {
	.name = "icookie hash table",
};

static void hash_icookie(struct state *st)
{
	insert_by_state_cookies(&icookie_hash_table, &st->st_icookie_hash_entry,
				st->st_icookie, zero_cookie);
}

static struct state_entry *icookie_chain(const u_char *icookie)
{
	return *hash_by_state_cookies(&icookie_hash_table, icookie, zero_cookie);
}

/*
 * State Table Functions
 *
 * The statetable is organized as a hash table.
 * The hash is purely based on the icookie and rcookie.
 * Each has chain is a doubly linked list.
 *
 * The phase 1 initiator does does not at first know the
 * responder's cookie, so the state will have to be rehashed
 * when that becomes known.
 *
 * In IKEv2, cookies are renamed IKE SA SPIs.
 *
 * In IKEv2, all children have the same cookies as their parent.
 * This means that you can look along that single chain for
 * your relatives.
 */

static struct state_hash_table statetable = {
	.name = "state hash table",
};

/*
 * Some macros to ease iterating over the above table
 */
#define FOR_EACH_ENTRY(ST, I, CODE) \
	FOR_EACH_STATE_ENTRY(ST, statetable.entries[I], CODE)

#define FOR_EACH_HASH_ENTRY(ST, ICOOKIE, RCOOKIE, CODE) \
	FOR_EACH_HASH_BY_STATE_COOKIES_ENTRY(ST, statetable, ICOOKIE, RCOOKIE, CODE)

/*
 * Get a state object.
 * Caller must schedule an event for this object so that it doesn't leak.
 * Caller must insert_state().
 */
struct state *new_state(void)
{
	/* initialized all to zero & NULL */
	static const struct state blank_state;

	static so_serial_t next_so = SOS_FIRST;
	struct state *st;

	st = clone_const_thing(blank_state, "struct state in new_state()");
	st->st_serialno = next_so++;
	passert(next_so > SOS_FIRST);   /* overflow can't happen! */
	st->st_whack_sock = NULL_FD;

	/* back-link the hash entry.  */
	st->st_hash_entry.state = st;
	st->st_icookie_hash_entry.state = st;

	anyaddr(AF_INET, &st->hidden_variables.st_nat_oa);
	anyaddr(AF_INET, &st->hidden_variables.st_natd);

	DBG(DBG_CONTROL, DBG_log("creating state object #%lu at %p",
				 st->st_serialno, (void *) st));
	DBG(DBG_CONTROLMORE,
	    struct state_category *category = categorize_state(st, st->st_state);
	    DBG_log("%s state #%lu: new > %s(%s)",
		    IS_PARENT_SA(st) ? "parent" : "child", st->st_serialno,
		    enum_show(&state_names, st->st_state), category->description));

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
	/* only support deleting ikev1 with username */
	if (st->st_ikev2)
		return;

	if (IS_IKE_SA(st) && streq(st->st_username, name)) {
		delete_my_family(st, FALSE);
		/* note: no md->st to clear */
	}
}

/*
 * Find the state object with this serial number.
 * This allows state object references that don't turn into dangerous
 * dangling pointers: reference a state by its serial number.
 * Returns NULL if there is no such state.
 * If this turns out to be a significant CPU hog, it could be
 * improved to use a hash table rather than sequential seartch.
 */
struct state *state_with_serialno(so_serial_t sn)
{
	if (sn >= SOS_FIRST) {
		int i;

		for (i = 0; i < STATE_TABLE_SIZE; i++) {
			struct state *st;
			FOR_EACH_ENTRY(st, i, {
				if (st->st_serialno == sn)
					return st;
			});
		}
	}
	return NULL;
}

/*
 * Insert a state object in the hash table. The object is inserted
 * at the begining of list.
 * Needs cookies, connection, and msgid.
 */
void insert_state(struct state *st)
{
	DBG(DBG_CONTROL,
	    DBG_log("inserting state object #%lu",
		    st->st_serialno))
	insert_by_state_cookies(&statetable, &st->st_hash_entry,
				st->st_icookie, st->st_rcookie);
	/*
	 * Also insert it into the icookie table.  Should be more
	 * selective about when this is done.
	 */
	hash_icookie(st);

	/*
	 * Ensure that somebody is in charge of killing this state:
	 * if no event is scheduled for it, schedule one to discard the state.
	 * If nothing goes wrong, this event will be replaced by
	 * a more appropriate one.
	 */
	if (st->st_event == NULL)
		event_schedule(EVENT_SO_DISCARD, 0, st);

	refresh_state(st);
}

/*
 * unlink a state object from the hash table, update its RCOOKIE and
 * then, and hash it into the right place.
 *
 * This doesn't update ICOOKIE_HASH_TABLE since the ICOOKIE didn't
 * change.
 */
void rehash_state(struct state *st, const u_char *rcookie)
{
	DBG(DBG_CONTROL,
	    DBG_log("rehashing state object #%lu",
		    st->st_serialno));

	/* unlink from forward chain */
	remove_state_entry(&st->st_hash_entry);
	/* update the cookie */
	memcpy(st->st_rcookie, rcookie, COOKIE_SIZE);
	/* now, re-insert */
	insert_by_state_cookies(&statetable, &st->st_hash_entry,
				st->st_icookie, st->st_rcookie);
	refresh_state(st); /* just logs change */
	/*
	 * insert_state has this, and this code once called
	 * insert_state.  Is it still needed?
	 */
	if (st->st_event == NULL)
		event_schedule(EVENT_SO_DISCARD, 0, st);
}

/*
 * unlink a state object from the hash table, but don't free it
 */
static void unhash_state(struct state *st)
{
	DBG(DBG_CONTROL,
	    DBG_log("unhashing state object #%lu",
		    st->st_serialno));
	remove_state_entry(&st->st_hash_entry);
	remove_state_entry(&st->st_icookie_hash_entry);
}

/*
 * Free the Whack socket file descriptor.
 * This has the side effect of telling Whack that we're done.
 */
void release_whack(struct state *st)
{
	close_any(st->st_whack_sock);
}

static void release_v2fragments(struct state *st)
{
	struct ikev2_frag *frag = st->st_tfrags;

	passert(st->st_ikev2);
	while (frag != NULL) {
		struct ikev2_frag *this = frag;

		frag = this->next;
		freeanychunk(this->cipher);
		pfree(this);
	}

	st->st_tfrags = NULL;
}

static void release_v1fragments(struct state *st)
{
	struct ike_frag *frag = st->ike_frags;

	passert(!st->st_ikev2);
	while (frag != NULL) {
		struct ike_frag *this = frag;

		frag = this->next;
		release_md(this->md);
		pfree(this);
	}

	st->ike_frags = NULL;
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

/* delete a state object */
void delete_state(struct state *st)
{
	struct connection *const c = st->st_connection;
	struct state *old_cur_state = cur_state == st ? NULL : cur_state;

	if ((c->policy & POLICY_OPPORTUNISTIC) && !IS_IKE_SA_ESTABLISHED(st)) {
		/* reduced logging of OE failures */
		DBG(DBG_LIFECYCLE, {
			char cib[CONN_INST_BUF];
			DBG_log("deleting state #%lu (%s) \"%s\"%s",
				st->st_serialno,
				enum_show(&state_names, st->st_state),
				c->name,
				fmt_conn_instance(c, cib));
		});
	} else if (cur_state == st) {
		/*
		 * Don't log state and connection if it is the same as
		 * the message prefix.
		 */
		libreswan_log("deleting state (%s)",
			enum_show(&state_names, st->st_state));
	} else {
		char cib[CONN_INST_BUF];
		libreswan_log("deleting other state #%lu (%s) \"%s\"%s",
			st->st_serialno,
			enum_show(&state_names, st->st_state),
			c->name,
			fmt_conn_instance(c, cib));
	}

	DBG(DBG_CONTROLMORE,
	    struct state_category *category = categorize_state(st, st->st_state);
	    DBG_log("%s state #%lu: %s(%s) > delete",
		    IS_PARENT_SA(st) ? "parent" : "child", st->st_serialno,
		    enum_show(&state_names, st->st_state), category->description));

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

		DBG(DBG_OPPO, DBG_log("OE: orphaning hold with failureshunt"));
		DBG(DBG_OPPO, DBG_log("negotiationshunt=%s, failureshunt=%s",
			nego_shunt == SPI_PASS ? "passthrough" : "hold",
			failure_shunt == SPI_PASS ? "passthrough" : "hold"));

		DBG(DBG_OPPO, DBG_log("OE: delete_state needs to bare the shunt"));
		if (!orphan_holdpass(c, &c->spd, 0 /* transport_proto */, failure_shunt)) {
			loglog(RC_LOG_SERIOUS,"orphan_holdpass() failure ignored");
		}
	}

	if (IS_IPSEC_SA_ESTABLISHED(st->st_state)) {
		/*
		 * Note that a state/SA can have more then one of
		 * ESP/AH/IPCOMP
		 */
		if (st->st_esp.present) {
			char statebuf[1024];
			char *sbcp = humanize_number(st->st_esp.peer_bytes,
					       statebuf,
					       statebuf + sizeof(statebuf),
					       "ESP traffic information: in=");

			(void)humanize_number(st->st_esp.our_bytes,
					       sbcp,
					       statebuf + sizeof(statebuf),
					       " out=");
			loglog(RC_INFORMATIONAL, "%s%s%s",
				statebuf,
				(st->st_username[0] != '\0') ? " XAUTHuser=" : "",
				st->st_username);
		}

		if (st->st_ah.present) {
			char statebuf[1024];
			char *sbcp = humanize_number(st->st_ah.peer_bytes,
					       statebuf,
					       statebuf + sizeof(statebuf),
					       "AH traffic information: in=");

			(void)humanize_number(st->st_ah.our_bytes,
					       sbcp,
					       statebuf + sizeof(statebuf),
					       " out=");
			loglog(RC_INFORMATIONAL, "%s%s%s",
				statebuf,
				(st->st_username[0] != '\0') ? " XAUTHuser=" : "",
				st->st_username);
		}

		if (st->st_ipcomp.present) {
			char statebuf[1024];
			char *sbcp = humanize_number(st->st_ipcomp.peer_bytes,
					       statebuf,
					       statebuf + sizeof(statebuf),
					       " IPCOMP traffic information: in=");

			(void)humanize_number(st->st_ipcomp.our_bytes,
					       sbcp,
					       statebuf + sizeof(statebuf),
					       " out=");
			loglog(RC_INFORMATIONAL, "%s%s%s",
				statebuf,
				(st->st_username[0] != '\0') ? " XAUTHuser=" : "",
				st->st_username);
		}
	}

#ifdef XAUTH_HAVE_PAM
	state_deletion_xauth_cleanup(st);
	ikev2_free_auth_pam(st->st_serialno);
#endif

	/* If DPD is enabled on this state object, clear any pending events */
	if (st->st_dpd_event != NULL)
		delete_dpd_event(st);

	/* clear any ikev2 liveness events */
	if (st->st_ikev2)
		delete_liveness_event(st);

	if (st->st_rel_whack_event != NULL) {
		pfreeany(st->st_rel_whack_event);
		st->st_rel_whack_event = NULL;
	}

	if (st->st_send_xauth_event != NULL) {
		event_free(st->st_send_xauth_event->ev);
		pfreeany(st->st_send_xauth_event);
		st->st_send_xauth_event = NULL;
	}

	/* if there is a suspended state transition, disconnect us */
	if (st->st_suspended_md != NULL) {
		passert(st->st_suspended_md->st == st);
		DBG(DBG_CONTROL, DBG_log("disconnecting state #%lu from md",
					 st->st_serialno));
		st->st_suspended_md->st = NULL;
	}

	/* tell the other side of any IPSEC SAs that are going down */
	if (IS_IPSEC_SA_ESTABLISHED(st->st_state) ||
			IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
		if (st->st_ikev2 && IS_CHILD_SA(st) &&
		    state_with_serialno(st->st_clonedfrom) == NULL) {
			/* ??? in v2, there must be a parent */
			DBG(DBG_CONTROL, DBG_log("deleting state but IKE SA does not exist for this child SA so Informational Exchange cannot be sent"));
			change_state(st, STATE_CHILDSA_DEL);
		} else  {
			/*
			 * ??? in IKEv2, we should not immediately delete:
			 * we should use an Informational Exchange to
			 * co-ordinate deletion.
			 * ikev2_delete_out doesn't really accomplish this.
			 */
			send_delete(st);
		}
	}

	delete_event(st); /* delete any pending timer event */

	/*
	 * Ditch anything pending on ISAKMP SA being established.
	 * Note: this must be done before the unhash_state to prevent
	 * flush_pending_by_state inadvertently and prematurely
	 * deleting our connection.
	 */
	flush_pending_by_state(st);

	/*
	 * if there is anything in the cryptographic queue, then remove this
	 * state from it.
	 */
	delete_cryptographic_continuation(st);

	/*
	 * effectively, this deletes any ISAKMP SA that this state represents
	 */
	unhash_state(st);

	/*
	 * tell kernel to delete any IPSEC SA
	 */
	if (IS_IPSEC_SA_ESTABLISHED(st->st_state) ||
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
	/* without st_connection, st isn't complete */
	cur_state = old_cur_state;
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

	clear_dh_from_state(st);

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

#    define free_any_nss_symkey(p)  free_any_symkey(#p, &(p))
	free_any_nss_symkey(st->st_shared_nss);

	/* same as st_skeyid_nss */
	free_any_nss_symkey(st->st_skeyseed_nss);
	free_any_nss_symkey(st->st_skey_d_nss);	/* same as st_skeyid_d_nss */
	/* same as st_skeyid_a_nss */
	free_any_nss_symkey(st->st_skey_ai_nss);
	free_any_nss_symkey(st->st_skey_ar_nss);
	/* same as st_skeyid_e_nss */
	free_any_nss_symkey(st->st_skey_ei_nss);
	free_any_nss_symkey(st->st_skey_er_nss);
	free_any_nss_symkey(st->st_skey_pi_nss);
	free_any_nss_symkey(st->st_skey_pr_nss);
	free_any_nss_symkey(st->st_enc_key_nss);
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
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++) {
		struct state *st;

		FOR_EACH_ENTRY(st, i, {
			if (st->st_connection == c)
				return TRUE;
			});
	}
	return FALSE;
}

bool shared_phase1_connection(const struct connection *c)
{
	int i;

	so_serial_t serial_us = c->newest_isakmp_sa;

	if (serial_us == SOS_NOBODY)
		return FALSE;

	for (i = 0; i < STATE_TABLE_SIZE; i++) {
		struct state *st;

		FOR_EACH_ENTRY(st, i, {
			if (st->st_connection == c)
				continue;
			if (st->st_clonedfrom == serial_us)
				return TRUE;
			});
	}
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
	int pass;

	/* this kludge avoids an n^2 algorithm */

	/* We take two passes so that we delete any ISAKMP SAs last.
	 * This allows Delete Notifications to be sent.
	 * ?? We could probably double the performance by caching any
	 * ISAKMP SA states found in the first pass, avoiding a second.
	 */
	for (pass = 0; pass != 2; pass++) {
		DBG(DBG_CONTROL, DBG_log("pass %d", pass));
		/* For each hash chain... */
		int i;
		for (i = 0; i < STATE_TABLE_SIZE; i++) {
			struct state *this;
			FOR_EACH_ENTRY(this, i, {
					DBG(DBG_CONTROL,
					    DBG_log("index %d state #%lu", i,
						    this->st_serialno));

				/* on pass 1, ignore established ISAKMP SA's */
				if (pass == 0 &&
				    IS_ISAKMP_SA_ESTABLISHED(this->st_state))
					continue;

				/* call comparison function */
				if ((*comparefunc)(this, c)) {
					struct state *old_cur_state =
						cur_state == this ?
						  NULL : cur_state;
					lset_t old_cur_debugging =
						cur_debugging;

					set_cur_state(this);

					delete_state(this);
					/* note: no md->st to clear */

					cur_state = old_cur_state;
					set_debugging(old_cur_debugging);
				}
			});
		}
	}
}

/*
 * Delete all states that have somehow not ben deleted yet
 * but using interfaces that are going down
 */

void delete_states_dead_interfaces(void)
{
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++) {
		struct state *this;

		FOR_EACH_ENTRY(this, i, {
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
	int i, ph1;

	addrtot(peer, 0, peerstr, sizeof(peerstr));

	whack_log(RC_COMMENT, "restarting peer %s\n", peerstr);

	/* first restart the phase1s */
	for (ph1 = 0; ph1 < 2; ph1++) {
		/* For each hash chain... */
		for (i = 0; i < STATE_TABLE_SIZE; i++) {
			struct state *this;
			FOR_EACH_ENTRY(this, i, {
				struct connection *c = this->st_connection;
				DBG(DBG_CONTROL, {
					ipstr_buf b;
					DBG_log("comparing %s to %s",
						ipstr(&this->st_remoteaddr, &b),
						peerstr);
				});

				if (sameaddr(&this->st_remoteaddr, peer)) {
					if (ph1 == 0 &&
					    IS_IKE_SA(this)) {
						whack_log(RC_COMMENT,
							  "peer %s for connection %s crashed, replacing",
							  peerstr,
							  c->name);
						ipsecdoi_replace(this, LEMPTY,
								 LEMPTY, 1);
					} else {
						delete_event(this);
						event_schedule(
							EVENT_SA_REPLACE, 0,
							this);
					}
				}
			});
		}
	}
}

/*
 * IKEv1: Duplicate a Phase 1 state object, to create a Phase 2 object.
 * IKEv2: Duplicate a Parent SA state object, to create a Child SA object
 *
 * Caller must schedule an event for this object so that it doesn't leak.
 * Caller must insert_state().
 */
struct state *duplicate_state(struct state *st)
{
	struct state *nst;

	/* record use of the Phase 1 / Parent state */
	st->st_outbound_count++;
	st->st_outbound_time = mononow();

	nst = new_state();

	DBG(DBG_CONTROL, DBG_log("duplicating state object #%lu as #%lu",
				 st->st_serialno, nst->st_serialno));

	memcpy(nst->st_icookie, st->st_icookie, COOKIE_SIZE);
	memcpy(nst->st_rcookie, st->st_rcookie, COOKIE_SIZE);
	nst->st_connection = st->st_connection;

	nst->quirks = st->quirks;
	nst->hidden_variables = st->hidden_variables;
	nst->st_remoteaddr = st->st_remoteaddr;
	nst->st_remoteport = st->st_remoteport;
	nst->st_localaddr = st->st_localaddr;
	nst->st_localport = st->st_localport;
	nst->st_interface = st->st_interface;
	nst->st_clonedfrom = st->st_serialno;
	nst->st_import = st->st_import;
	nst->st_ikev2 = st->st_ikev2;
	nst->st_original_role = st->st_original_role;
	nst->st_seen_fragvid = st->st_seen_fragvid;
	nst->st_seen_fragments = st->st_seen_fragments;
	nst->st_event = NULL;

#   define clone_nss_symkey_field(field) { \
		nst->field = st->field; \
		if (nst->field != NULL) \
			PK11_ReferenceSymKey(nst->field); \
	}
	/* same as st_skeyid_nss */
	clone_nss_symkey_field(st_skeyseed_nss);
	/* same as st_skeyid_d_nss */
	clone_nss_symkey_field(st_skey_d_nss);
	/* same as st_skeyid_a_nss */
	clone_nss_symkey_field(st_skey_ai_nss);
	clone_nss_symkey_field(st_skey_ar_nss);
	/* same as st_skeyid_e_nss */
	clone_nss_symkey_field(st_skey_ei_nss);
	clone_nss_symkey_field(st_skey_er_nss);
	clone_nss_symkey_field(st_skey_pi_nss);
	clone_nss_symkey_field(st_skey_pr_nss);
	clone_nss_symkey_field(st_enc_key_nss);
#   undef clone_nss_symkey_field
#   define clone_any_chunk(field) { \
		if (st->field.ptr == NULL) { \
			nst->field.ptr = NULL; \
			nst->field.len = 0; \
		} else { \
			clonetochunk(nst->field, st->field.ptr, st->field.len, \
				#field " in duplicate state"); \
		} \
	}
	clone_any_chunk(st_skey_initiator_salt);
	clone_any_chunk(st_skey_responder_salt);
#    undef clone_any_chunk

	/* v2 duplication of state */
#   define clone_chunk(ch, name) \
	clonetochunk(nst->ch, st->ch.ptr, st->ch.len, name)

	clone_chunk(st_ni, "st_ni in duplicate_state");
	clone_chunk(st_nr, "st_nr in duplicate_state");
#   undef clone_chunk

	nst->st_oakley = st->st_oakley;

	jam_str(nst->st_username, sizeof(nst->st_username),
		st->st_username);

	return nst;
}

void for_each_state(void (*f)(struct state *, void *data), void *data)
{
	struct state *ocs = cur_state;
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++) {
		struct state *st;
		FOR_EACH_ENTRY(st, i, {
			set_cur_state(st);
			f(st, data);
		});
	}
	cur_state = ocs;
}

/*
 * Find a state object for an IKEv1 state
 */
struct state *find_state_ikev1(const u_char *icookie,
			       const u_char *rcookie,
			       msgid_t /*network order*/ msgid)
{
	struct state *st;
	FOR_EACH_HASH_ENTRY(st, icookie, rcookie, {
		if (memeq(icookie, st->st_icookie, COOKIE_SIZE) &&
		    memeq(rcookie, st->st_rcookie, COOKIE_SIZE) &&
		    !st->st_ikev2) {
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
				    enum_show(&state_names, st->st_state));
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
	FOR_EACH_HASH_ENTRY(st, icookie, rcookie, {
		if (memeq(icookie, st->st_icookie, COOKIE_SIZE) &&
		    memeq(rcookie, st->st_rcookie, COOKIE_SIZE) &&
		    st->st_ikev2 &&
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
				    enum_show(&state_names, st->st_state));
		    }
	    });

	return st;
}

/*
 * Find a state object for an IKEv2 state, looking by icookie only and
 * only matching "struct state" objects in the correct state.
 *
 * Note: only finds parent states (this is ok as only interested in
 * state objects in the initial state).
 */
struct state *find_state_ikev2_parent_init(const u_char *icookie,
					   enum state_kind expected_state)
{
	struct state *st;
	FOR_EACH_STATE_ENTRY(st, icookie_chain(icookie), {
			if (!st->st_ikev2) {
				continue;
			}
			if (st->st_state != expected_state) {
				continue;
			}
			if (!memeq(icookie, st->st_icookie, COOKIE_SIZE)) {
				continue;
			}
			if (IS_CHILD_SA(st)) {
				continue;
			}
			DBG(DBG_CONTROL,
			    DBG_log("parent_init v2 peer and cookies match on #%lu",
				    st->st_serialno);
			    DBG_log("v2 state object #%lu found, in %s",
				    st->st_serialno,
				    enum_show(&state_names, st->st_state)));
			return st;
		});

	DBG(DBG_CONTROL, DBG_log("parent_init v2 state object not found"));
	return NULL;
}

/*
 * Find a state object for an IKEv2 state, a response that includes a msgid.
 */
struct state *find_state_ikev2_child(const u_char *icookie,
				     const u_char *rcookie,
				     msgid_t msgid)
{
	struct state *st;
	FOR_EACH_HASH_ENTRY(st, icookie, rcookie, {
		if (memeq(icookie, st->st_icookie, COOKIE_SIZE) &&
		    memeq(rcookie, st->st_rcookie, COOKIE_SIZE) &&
		    st->st_ikev2 &&
		    st->st_msgid == msgid) {
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
				    enum_show(&state_names, st->st_state));
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
					       u_int8_t protoid,
					       ipsec_spi_t spi)
{
	struct state *st;
	FOR_EACH_HASH_ENTRY(st, icookie, rcookie, {
		if (memeq(icookie, st->st_icookie, COOKIE_SIZE) &&
		    memeq(rcookie, st->st_rcookie, COOKIE_SIZE) &&
		    st->st_ikev2 && IS_CHILD_SA(st)) {
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
				    enum_show(&state_names, st->st_state));
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
	FOR_EACH_HASH_ENTRY(st, icookie, rcookie, {
		if (memeq(icookie, st->st_icookie, COOKIE_SIZE) &&
		    memeq(rcookie, st->st_rcookie, COOKIE_SIZE)) {
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
		}
	});

	DBG(DBG_CONTROL, {
		    if (st == NULL) {
			    DBG_log("p15 state object not found");
		    } else {
			    DBG_log("p15 state object #%lu found, in %s",
				    st->st_serialno,
				    enum_show(&state_names, st->st_state));
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
		int i;

		for (i = 0; i < STATE_TABLE_SIZE; i++) {
			struct state *st;

			FOR_EACH_ENTRY(st, i, {
				if (st->st_tpacket.ptr != NULL &&
				    st->st_tpacket.len >= packet_len &&
				    memeq(st->st_tpacket.ptr, packet, packet_len))
				{
					return st;
				}
			});
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
					  u_int8_t protoid,
					  ipsec_spi_t spi,
					  bool *bogus)
{
	struct state  *bogusst = NULL;
	int i;

	*bogus = FALSE;
	for (i = 0; i < STATE_TABLE_SIZE; i++) {
		struct state *st;

		FOR_EACH_ENTRY(st, i, {
			if (IS_IPSEC_SA_ESTABLISHED(st->st_state) &&
				p1st->st_connection->host_pair ==
				st->st_connection->host_pair &&
				same_peer_ids(p1st->st_connection,
					st->st_connection, NULL))
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
	}
	return bogusst;
}

/*
 * Find newest Phase 1 negotiation state object for suitable for connection c
 */
struct state *find_phase1_state(const struct connection *c, lset_t ok_states)
{
	struct state *best = NULL;
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++) {
		struct state *st;
		FOR_EACH_ENTRY(st, i, {
			if (LHAS(ok_states, st->st_state) &&
				c->host_pair == st->st_connection->host_pair &&
				same_peer_ids(c, st->st_connection, NULL) &&
				(best == NULL ||
					best->st_serialno < st->st_serialno))
				best = st;
		});
	}

	return best;
}

void state_eroute_usage(const ip_subnet *ours, const ip_subnet *his,
			unsigned long count, monotime_t nw)
{
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++) {
		struct state *st;
		FOR_EACH_ENTRY(st, i, {
			struct connection *c = st->st_connection;

			/* XXX spd-enum */
			if (IS_IPSEC_SA_ESTABLISHED(st->st_state) &&
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
	}
	DBG(DBG_CONTROL,
	    {
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

	if (!IS_IPSEC_SA_ESTABLISHED(st->st_state))
		return; /* ignore non established states */

	fmt_conn_instance(c, inst);

	{
		char *mode = st->st_esp.present ? "ESP" : st->st_ah.present ? "AH" : st->st_ipcomp.present ? "IPCOMP" : "UNKNOWN";
		char *mbcp = traffic_buf + snprintf(traffic_buf,
				sizeof(traffic_buf) - 1, ", type=%s, add_time=%" PRIu64, mode,  st->st_esp.add_time);

		if (get_sa_info(st, TRUE, NULL)) {
			size_t buf_len =  traffic_buf + sizeof(traffic_buf) - mbcp;
			u_int inb = st->st_esp.present ? st->st_esp.our_bytes:
				st->st_ah.present ? st->st_ah.our_bytes :
				st->st_ipcomp.present ? st->st_ipcomp.our_bytes : 0;
			mbcp += snprintf(mbcp, buf_len - 1, ", inBytes=%u", inb);
		}

		if (get_sa_info(st, FALSE, NULL)) {
			size_t buf_len =  traffic_buf + sizeof(traffic_buf) - mbcp;
			u_int outb = st->st_esp.present ? st->st_esp.peer_bytes :
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

	if (st->st_username[0] == '\0') {
		idtoa(&c->spd.that.id, thatidbuf, sizeof(thatidbuf));
	}

	snprintf(state_buf, state_buf_len,
		 "#%lu: \"%s\"%s%s%s%s%s%s%s%s%s",
		 st->st_serialno,
		 c->name, inst,
		 (st->st_username[0] != '\0') ? ", username=" : "",
		 (st->st_username[0] != '\0') ? st->st_username : "",
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
void fmt_state(struct state *st, const monotime_t n,
	       char *state_buf, const size_t state_buf_len,
	       char *state_buf2, const size_t state_buf2_len)
{
	/* what the heck is interesting about a state? */
	const struct connection *c = st->st_connection;
	long delta;
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

	if (st->st_event != NULL) {
		/* tricky: in case time_t/monotime_t is an unsigned type */
		delta = monobefore(n, st->st_event->ev_time) ?
			(long)(st->st_event->ev_time.mono_secs - n.mono_secs) :
			-(long)(n.mono_secs - st->st_event->ev_time.mono_secs);
	} else {
		delta = -1;	/* ??? sort of odd signifier */
	}

	dpdbuf[0] = '\0';	/* default to empty string */
	if (IS_IPSEC_SA_ESTABLISHED(st->st_state)) {
		snprintf(dpdbuf, sizeof(dpdbuf), "; isakmp#%lu",
			 (unsigned long)st->st_clonedfrom);
	} else {
		if (st->hidden_variables.st_peer_supports_dpd) {

			/* ??? why is printing -1 better than 0? */
			snprintf(dpdbuf, sizeof(dpdbuf),
				 "; lastdpd=%lds(seq in:%u out:%u)",
				 st->st_last_dpd.mono_secs != UNDEFINED_TIME ?
					(long)deltasecs(monotimediff(mononow(), st->st_last_dpd)) : (long)-1,
				 st->st_dpd_seqno,
				 st->st_dpd_expectseqno);
		} else if (dpd_active_locally(st) && st->st_ikev2) {
			/* stats are on parent sa */
			if (IS_CHILD_SA(st)) {
				struct state *pst = state_with_serialno(st->st_clonedfrom);

				if (pst != NULL) {
					snprintf(dpdbuf, sizeof(dpdbuf),
						"; lastlive=%lds",
						pst->st_last_liveness.mono_secs != UNDEFINED_TIME ?
						deltasecs(monotimediff(mononow(), pst->st_last_liveness)) :
						0);
				}
			}
		} else {
			if (!st->st_ikev2)
				snprintf(dpdbuf, sizeof(dpdbuf), "; nodpd");
		}
	}

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating == %s;", st->st_serialno, __FUNCTION__, __LINE__, st->st_calculating ? "TRUE" : "FALSE"));

	snprintf(state_buf, state_buf_len,
		 "#%lu: \"%s\"%s:%u %s (%s); %s in %lds%s%s%s%s; %s; %s",
		 st->st_serialno,
		 c->name, inst,
		 st->st_remoteport,
		 enum_name(&state_names, st->st_state),
		 enum_name(&state_stories, st->st_state),
		 st->st_event == NULL ? "none" :
			enum_name(&timer_event_names, st->st_event->ev_type),
		 delta,
		 np1, np2, eo, dpdbuf,
		 st->st_calculating ? "crypto_calculating" :
			st->st_suspended_md != NULL ?  "crypto/dns-lookup" :
			"idle",
		 enum_name(&pluto_cryptoimportance_names, st->st_import));

	/* print out SPIs if SAs are established */
	if (state_buf2_len != 0)
		state_buf2[0] = '\0';   /* default to empty */
	if (IS_IPSEC_SA_ESTABLISHED(st->st_state)) {
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
				 " used %lds ago;",
				 (long) deltasecs(monotimediff(mononow(),
						  st->st_outbound_time)));
		}

		mbcp = traffic_buf +
		       snprintf(traffic_buf, sizeof(traffic_buf) - 1,
				"Traffic:");

		*p = '\0';
		if (st->st_ah.present) {
			add_said(&c->spd.that.host_addr, st->st_ah.attrs.spi,
				 SA_AH);
/* needs proper fix, via kernel_ops? */
#if defined(linux) && defined(NETKEY_SUPPORT)
			if (get_sa_info(st, FALSE, NULL)) {
				mbcp = humanize_number(st->st_ah.peer_bytes,
						       mbcp,
						       traffic_buf +
							  sizeof(traffic_buf),
						       " AHout=");
			}
#endif
			add_said(&c->spd.this.host_addr, st->st_ah.our_spi,
				 SA_AH);
#if defined(linux) && defined(NETKEY_SUPPORT)
			if (get_sa_info(st, TRUE, NULL)) {
				mbcp = humanize_number(st->st_ah.our_bytes,
						       mbcp,
						       traffic_buf +
							 sizeof(traffic_buf),
						       " AHin=");
			}
#endif
			mbcp = humanize_number(
					(u_long)st->st_ah.attrs.life_kilobytes,
					mbcp,
					traffic_buf +
					  sizeof(traffic_buf),
					"! AHmax=");
/* ??? needs proper fix, via kernel_ops? */
		}
		if (st->st_esp.present) {
			add_said(&c->spd.that.host_addr, st->st_esp.attrs.spi,
				 SA_ESP);
/* ??? needs proper fix, via kernel_ops? */
#if defined(linux) && defined(NETKEY_SUPPORT)
			if (get_sa_info(st, TRUE, NULL)) {
				mbcp = humanize_number(st->st_esp.our_bytes,
						       mbcp,
						       traffic_buf +
							 sizeof(traffic_buf),
						       " ESPin=");
			}
#endif
			add_said(&c->spd.this.host_addr, st->st_esp.our_spi,
				 SA_ESP);
#if defined(linux) && defined(NETKEY_SUPPORT)
			if (get_sa_info(st, FALSE, NULL)) {
				mbcp = humanize_number(st->st_esp.peer_bytes,
						       mbcp,
						       traffic_buf +
							 sizeof(traffic_buf),
						       " ESPout=");
			}
#endif

			mbcp = humanize_number(
					(u_long)st->st_esp.attrs.life_kilobytes,
					mbcp,
					traffic_buf +
					  sizeof(traffic_buf),
					"! ESPmax=");
		}
		if (st->st_ipcomp.present) {
			add_said(&c->spd.that.host_addr,
				 st->st_ipcomp.attrs.spi, SA_COMP);
#if defined(linux) && defined(NETKEY_SUPPORT)
			if (get_sa_info(st, FALSE, NULL)) {
				mbcp = humanize_number(
						st->st_ipcomp.peer_bytes,
						mbcp,
						traffic_buf +
						  sizeof(traffic_buf),
						" IPCOMPout=");
			}
#endif
			add_said(&c->spd.this.host_addr, st->st_ipcomp.our_spi,
				 SA_COMP);
#if defined(linux) && defined(NETKEY_SUPPORT)
			if (get_sa_info(st, TRUE, NULL)) {
				mbcp = humanize_number(
						st->st_ipcomp.our_bytes,
						mbcp,
						traffic_buf +
						  sizeof(traffic_buf),
						" IPCOMPin=");
			}
#endif

			/* mbcp not subsequently used */
			mbcp = humanize_number(
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
			"#%lu: \"%s\"%s%s%s ref=%lu refhim=%lu %s %s%s",
			st->st_serialno,
			c->name, inst,
			lastused,
			buf,
			(unsigned long)st->st_ref,
			(unsigned long)st->st_refhim,
			traffic_buf,
			(st->st_username[0] != '\0') ? "username=" : "",
			(st->st_username[0] != '\0') ? st->st_username : "");

#       undef add_said
	}
}

/*
 * sorting logic is:
 *
 *  name
 *  type
 *  instance#
 *  isakmp_sa (XXX probably wrong)
 *
 */
static int state_compare(const void *a, const void *b)
{
	const struct state *sap = *(const struct state *const *)a;
	struct connection *ca = sap->st_connection;
	const struct state *sbp = *(const struct state *const *)b;
	struct connection *cb = sbp->st_connection;

	/* DBG_log("comparing %s to %s", ca->name, cb->name); */

	return connection_compare(ca, cb);
}

/*
 * NULL terminated array of state pointers.
 */
static struct state **sort_states(void)
{
	/* COUNT the number of states. */
	int count = 0;
	{
		int i;
		for (i = 0; i < STATE_TABLE_SIZE; i++) {
			struct state *st UNUSED;
			FOR_EACH_ENTRY(st, i, {
					count++;
				});
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
		int i;
		for (i = 0; i < STATE_TABLE_SIZE; i++) {
			struct state *st;
			FOR_EACH_ENTRY(st, i, {
					passert(st != NULL);
					array[p++] = st;
				});
		}
		passert(p == count);
		array[p] = NULL;
	}

	/* sort it!  */
	qsort(array, count, sizeof(struct state *), state_compare);

	return array;
}

void show_traffic_status(void)
{
	whack_log(RC_COMMENT, " ");             /* spacer */

	struct state **array = sort_states();

	/* now print sorted results */
	if (array != NULL) {
		int i;
		for (i = 0; array[i] != NULL; i++) {
			struct state *st = array[i];

			char state_buf[LOG_WIDTH];
			fmt_list_traffic(st, state_buf, sizeof(state_buf));
			if (state_buf[0] != '\0')
				whack_log(RC_INFORMATIONAL_TRAFFIC,
					  "%s", state_buf);
		}
		whack_log(RC_COMMENT, " "); /* spacer */
		pfree(array);
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
		  category.half_open_ike.count,
		  category.open_ike.count,
		  category.authenticated_ike.count,
		  category.anonymous_ike.count);
	whack_log(RC_COMMENT, "IPsec SAs: total(%u), authenticated(%u), anonymous(%d)",
		  total_ipsec(),
		  category.authenticated_ipsec.count, category.anonymous_ipsec.count);
	whack_log(RC_COMMENT, " ");             /* spacer */

	struct state **array = sort_states();

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
	int i;

startover:
	closest = ~0;   /* not close at all */
	for (i = 0; i < STATE_TABLE_SIZE; i++) {
		struct state *st;
		FOR_EACH_ENTRY(st, i, {
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
							*latest_cpi =
								*first_busy_cpi
									= 0;
							return;
						}
						base++;
						if (base >
							IPCOMP_LAST_NEGOTIATED)
							base = IPCOMP_FIRST_NEGOTIATED;

						/* really a tail call */
						goto startover;
					}
					closest = c;
				}
			}
		});
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
 */
ipsec_spi_t uniquify_his_cpi(ipsec_spi_t cpi, const struct state *st)
{
	int tries = 0;
	int i;

startover:

	/* network order makes first two bytes our target */
	get_rnd_bytes((u_char *)&cpi, 2);

	/*
	 * Make sure that the result is unique.
	 * Hard work.  If there is no unique value, we'll loop forever!
	 */
	for (i = 0; i < STATE_TABLE_SIZE; i++) {
		const struct state *s;
		FOR_EACH_ENTRY(s, i, {
			if (s->st_ipcomp.present &&
			    sameaddr(&s->st_connection->spd.that.host_addr,
				     &st->st_connection->spd.that.host_addr) &&
			    cpi == s->st_ipcomp.attrs.spi) {
				if (++tries == 20)
					return 0; /* FAILURE */

				goto startover;
			}
		});
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
 */
void update_ike_endpoints(struct state *st,
			  const struct msg_digest *md)
{
	/* caller must ensure we are not behind NAT */

	st->st_remoteaddr = md->sender;
	st->st_remoteport = md->sender_port;
	st->st_localaddr = md->iface->ip_addr;
	st->st_localport = md->iface->port;
	st->st_interface = md->iface;
}

void set_state_ike_endpoints(struct state *st,
			     struct connection *c)
{
	/* reset our choice of interface */
	c->interface = NULL;
	orient(c);

	st->st_localaddr  = c->spd.this.host_addr;
	st->st_localport  = c->spd.this.host_port;
	st->st_remoteaddr = c->spd.that.host_addr;
	st->st_remoteport = c->spd.that.host_port;

	st->st_interface = c->interface;
}

/* seems to be a good spot for now */
bool dpd_active_locally(const struct state *st)
{
	return deltasecs(st->st_connection->dpd_delay) != 0 &&
		deltasecs(st->st_connection->dpd_timeout) != 0;
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
	FOR_EACH_HASH_ENTRY(st, pst->st_icookie, pst->st_rcookie, {
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

/* if the state is too busy to process a packet, say so */
bool state_busy(const struct state *st) {
	if (st != NULL) {
		/*
		 * Ignore a packet if the state has a suspended state
		 * transition.
		 * Probably a duplicated packet but the original packet is
		 * not yet recorded in st->st_rpacket, so duplicate checking
		 * won't catch.
		 * ??? Should the packet be recorded earlier to improve
		 * diagnosis?
		 */
		if (st->st_suspended_md != NULL) {
			loglog(RC_LOG,
			       "discarding packet received during asynchronous work (DNS or crypto) in %s",
			       enum_name(&state_names, st->st_state));
			return TRUE;
		}

		/*
		 * if this state is busy calculating in between state
		 * transitions, (there will be no suspended state),
		 * then we silently ignore the packet, as there is
		 * nothing we can do right now.
		 */
		DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st != NULL && st->st_calculating == %s;", st->st_serialno, __FUNCTION__, __LINE__, st != NULL && st->st_calculating ? "TRUE" : "FALSE"));
		if (st->st_calculating) {
			libreswan_log("message received while calculating. Ignored.");
			return TRUE;
		}
	}
	return FALSE;
}

void clear_dh_from_state(struct state *st)
{
	/* when responding with INVALID_DH, we didn't do the work yet */
	if (st->st_sec_in_use) {
		SECKEY_DestroyPublicKey(st->st_pubk_nss);
		SECKEY_DestroyPrivateKey(st->st_sec_nss);
		st->st_sec_in_use = FALSE;
	}
}

bool require_ddos_cookies(void)
{
	return pluto_ddos_mode == DDOS_FORCE_BUSY ||
		(pluto_ddos_mode == DDOS_AUTO &&
		 category.half_open_ike.count >= pluto_ddos_threshold);
}

bool drop_new_exchanges(void)
{
	return category.half_open_ike.count >= pluto_max_halfopen;
}

void show_globalstate_status(void)
{
	enum state_kind s;

	whack_log(RC_COMMENT, "~shunts.total %d", show_shunt_count());

	whack_log(RC_COMMENT, "~states.total %d", total());
	whack_log(RC_COMMENT, "~states.child %d", total_ipsec());
	whack_log(RC_COMMENT, "~states.ike %d", total_ike());
	whack_log(RC_COMMENT, "~states.ike.anonymous %d",
		  category.anonymous_ike.count);
	whack_log(RC_COMMENT, "~states.ike.authenticated %d",
		  category.authenticated_ike.count);
	whack_log(RC_COMMENT, "~states.ike.halfopen %d",
		  category.half_open_ike.count);
	whack_log(RC_COMMENT, "~states.ike.open %d",
		  category.open_ike.count);
	whack_log(RC_COMMENT, "~states.ike.ddos_threshold %d",pluto_ddos_threshold);
	whack_log(RC_COMMENT, "~states.ike.max.all %d",pluto_max_halfopen);
	for (s = STATE_MAIN_R0; s < MAX_STATES; s++)
	{
		whack_log(RC_COMMENT, "~states.enumerate.%s:%d",
			enum_show(&state_names, s), state_count[s]);
	}
}


void log_newest_sa_change(char *f, struct state *const st)
{

	DBG(DBG_CONTROLMORE,
			DBG_log("%s: instance %s[%lu], setting %s newest_ipsec_sa to #%lu (was #%lu) (spd.eroute=#%lu) cloned from #%lu",f,
				st->st_connection->name,
				st->st_connection->instance_serial,
				st->st_ikev2 ? "IKEv2" : "IKEv1",
				st->st_serialno,
				st->st_connection->newest_ipsec_sa,
				st->st_connection->spd.
				eroute_owner, st->st_clonedfrom));
}
