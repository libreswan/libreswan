/*
 * IKE and IPsec Statistics for the pluto daemon
 *
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 Andrew Cagney
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include <stddef.h>
#include <string.h>
#include <errno.h>


#include "sysdep.h"
#include "socketwrapper.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "connections.h"        /* needs id.h */
#include "log.h"
#include "packet.h"
#include "demux.h"  /* needs packet.h */
#include "rcv_whack.h"
#include "whack.h"              /* for RC_LOG_SERIOUS */
#include "ike_alg.h"
#include "pluto_stats.h"
#include "nat_traversal.h"

unsigned long pstats_ipsec_sa;
unsigned long pstats_ikev1_sa;
unsigned long pstats_ikev2_sa;
unsigned long pstats_ikev1_fail;
unsigned long pstats_ikev2_fail;
unsigned long pstats_ikev1_completed;
unsigned long pstats_ikev2_completed;
unsigned long pstats_ikev1_encr[OAKLEY_ENCR_PSTATS_ROOF];
unsigned long pstats_ikev2_encr[IKEv2_ENCR_PSTATS_ROOF];
unsigned long pstats_ikev1_integ[OAKLEY_HASH_PSTATS_ROOF];
unsigned long pstats_ikev2_integ[IKEv2_AUTH_PSTATS_ROOF];
unsigned long pstats_ikev1_groups[OAKLEY_GROUP_PSTATS_ROOF];
unsigned long pstats_ikev2_groups[OAKLEY_GROUP_PSTATS_ROOF];
unsigned long pstats_invalidke_recv_s[OAKLEY_GROUP_PSTATS_ROOF];
unsigned long pstats_invalidke_recv_u[OAKLEY_GROUP_PSTATS_ROOF];
unsigned long pstats_invalidke_sent_s[OAKLEY_GROUP_PSTATS_ROOF];
unsigned long pstats_invalidke_sent_u[OAKLEY_GROUP_PSTATS_ROOF];

unsigned long pstats_ikev1_ipsec_encrypt[ESP_PSTATS_ROOF];
unsigned long pstats_ikev2_ipsec_encrypt[IKEv2_ENCR_PSTATS_ROOF];
unsigned long pstats_ikev1_ipsec_integ[AUTH_ALGORITHM_PSTATS_ROOF];
unsigned long pstats_ikev2_ipsec_integ[IKEv2_AUTH_PSTATS_ROOF];

uint64_t pstats_ipsec_in_bytes;	/* total incoming IPsec traffic */
uint64_t pstats_ipsec_out_bytes;	/* total outgoing IPsec traffic */
unsigned long pstats_ike_in_bytes;	/* total incoming IPsec traffic */
unsigned long pstats_ike_out_bytes;	/* total outgoing IPsec traffic */
unsigned long pstats_ikev1_sent_notifies_e[v1N_ERROR_PSTATS_ROOF]; /* types of NOTIFY ERRORS */
unsigned long pstats_ikev1_recv_notifies_e[v1N_ERROR_PSTATS_ROOF]; /* types of NOTIFY ERRORS */
unsigned long pstats_ike_stf[10];	/* count state transitions */ /* ??? what is 10? */
unsigned long pstats_ipsec_esp;
unsigned long pstats_ipsec_ah;
unsigned long pstats_ipsec_ipcomp;
unsigned long pstats_ipsec_encap_yes;
unsigned long pstats_ipsec_encap_no;
unsigned long pstats_ipsec_esn;
unsigned long pstats_ipsec_tfc;
unsigned long pstats_ike_dpd_recv;
unsigned long pstats_ike_dpd_sent;
unsigned long pstats_ike_dpd_replied;
unsigned long pstats_iketcp_started[2];
unsigned long pstats_iketcp_stopped[2];
unsigned long pstats_iketcp_aborted[2];
unsigned long pstats_xauth_started;
unsigned long pstats_xauth_stopped;
unsigned long pstats_xauth_aborted;

#define PLUTO_STAT(TYPE, NAMES, WHAT, FLOOR, ROOF)			\
	static unsigned long pstats_##TYPE##_count[ROOF-FLOOR +1/*overflow*/]; \
	const struct pluto_stat pstats_##TYPE = {			\
		.names = NAMES,						\
		.what = WHAT,						\
		.floor = FLOOR,						\
		.roof = ROOF,						\
		.count = pstats_##TYPE##_count,				\
	};

PLUTO_STAT(ikev2_sent_notifies_e, &ikev2_notify_names,
	    "ikev2.sent.notifies.error",
	    v2N_ERROR_FLOOR, v2N_ERROR_PSTATS_ROOF);
PLUTO_STAT(ikev2_recv_notifies_e, &ikev2_notify_names,
	   "ikev2.recv.notifies.error",
	   v2N_ERROR_FLOOR, v2N_ERROR_PSTATS_ROOF);

PLUTO_STAT(ikev2_sent_notifies_s, &ikev2_notify_names,
	    "ikev2.sent.notifies.status",
	   v2N_STATUS_FLOOR, v2N_STATUS_PSTATS_ROOF);
PLUTO_STAT(ikev2_recv_notifies_s, &ikev2_notify_names,
	   "ikev2.recv.notifies.status",
	   v2N_STATUS_FLOOR, v2N_STATUS_PSTATS_ROOF);

/*
 * SAs.
 *
 * Re-keying is counted as a second SA.  States are counted:
 *
 *  started->failed
 *  started->established->completed
 */

static unsigned long pstats_sa_started[IKE_VERSION_ROOF][SA_TYPE_ROOF];
static unsigned long pstats_sa_finished[IKE_VERSION_ROOF][SA_TYPE_ROOF][DELETE_REASON_ROOF];
static unsigned long pstats_sa_established[IKE_VERSION_ROOF][SA_TYPE_ROOF];

static const char *pstats_sa_names[IKE_VERSION_ROOF][SA_TYPE_ROOF] = {
	[IKEv1] = {
		[IKE_SA] = "ikev1.isakmp",
		[IPSEC_SA] = "ikev1.ipsec",
	},
	[IKEv2] = {
		[IKE_SA] = "ikev2.ike",
		[IPSEC_SA] = "ikev2.child",
	},
};

static const char *pstats_sa_reasons[DELETE_REASON_ROOF] = {
	[REASON_UNKNOWN] = "other",
	[REASON_COMPLETED] = "completed",
	[REASON_EXCHANGE_TIMEOUT] = "exchange-timeout",
	[REASON_CRYPTO_TIMEOUT] = "crypto-timeout",
	[REASON_TOO_MANY_RETRANSMITS] = "too-many-retransmits",
	[REASON_AUTH_FAILED] = "auth-failed",
	[REASON_CRYPTO_FAILED] = "crypto-failed",
};

void pstat_sa_started(struct state *st, enum sa_type sa_type)
{
	st->st_pstats.sa_type = sa_type;
	st->st_pstats.delete_reason = REASON_UNKNOWN;

	const char *name = pstats_sa_names[st->st_ike_version][st->st_pstats.sa_type];
	dbg("pstats #%lu %s started", st->st_serialno, name);

	pstats_sa_started[st->st_ike_version][st->st_pstats.sa_type]++;
}

void pstat_sa_failed(struct state *st, enum delete_reason r)
{
	const char *name = pstats_sa_names[st->st_ike_version][st->st_pstats.sa_type];
	const char *reason = pstats_sa_reasons[r];
	if (st->st_pstats.delete_reason == REASON_UNKNOWN) {
		dbg("pstats #%lu %s failed %s", st->st_serialno, name, reason);
		st->st_pstats.delete_reason = r;
	} else {
		dbg("pstats #%lu %s re-failed %s", st->st_serialno, name, reason);
	}
}

void pstat_sa_deleted(struct state *st)
{
	const char *name = pstats_sa_names[st->st_ike_version][st->st_pstats.sa_type];
	const char *reason = pstats_sa_reasons[st->st_pstats.delete_reason];
	dbg("pstats #%lu %s deleted %s", st->st_serialno, name, reason);

	pstats_sa_finished[st->st_ike_version][st->st_pstats.sa_type][st->st_pstats.delete_reason]++;

	/*
	 * statistics for IKE SA failures. We cannot do the same for IPsec SA
	 * because those failures could happen before we cloned a state
	 *
	 * XXX: ???
	 *
	 * XXX: the above should make this completely redundant.
	 */
	if (IS_IKE_SA(st)) {
		bool fail = !IS_IKE_SA_ESTABLISHED(st) && st->st_state->kind != STATE_IKESA_DEL;
		if (fail) {
			if (st->st_ike_version == IKEv2)
				pstats_ikev2_fail++;
			else
				pstats_ikev1_fail++;
		} else {
			if (st->st_ike_version == IKEv2)
				pstats_ikev2_completed++;
			else
				pstats_ikev1_completed++;
		}
#ifdef NOT_YET
		/*
		 * Only insist on IKEv2 IKE SAs correctly recording
		 * the delete reason; and only when nothing crazy is
		 * going on.
		 */
		pexpect(st->st_ike_version == IKEv1 || exiting_pluto ||
			(st->st_pstats.delete_reason != REASON_UNKNOWN &&
			 fail != (st->st_pstats.delete_reason == REASON_COMPLETED)));
#endif
	}
}

/*
 * Established SAs.
 */

static void pstat_ike_sa_established(struct state *st)
{
	/* keep IKE SA statistics */
	if (st->st_ike_version == IKEv2) {
		pstats_ikev2_sa++;
		pstats(ikev2_encr, st->st_oakley.ta_encrypt->common.id[IKEv2_ALG_ID]);
		if (st->st_oakley.ta_integ != NULL)
			pstats(ikev2_integ, st->st_oakley.ta_integ->common.id[IKEv2_ALG_ID]);
		pstats(ikev2_groups, st->st_oakley.ta_dh->group);
	} else {
		pstats_ikev1_sa++;
		pstats(ikev1_encr, st->st_oakley.ta_encrypt->common.ikev1_oakley_id);
		pstats(ikev1_integ, st->st_oakley.ta_prf->common.id[IKEv1_OAKLEY_ID]);
		pstats(ikev1_groups, st->st_oakley.ta_dh->group);
	}
}

static void pstats_sa(bool nat, bool tfc, bool esn)
{
	if (nat)
		pstats_ipsec_encap_yes++;
	else
		pstats_ipsec_encap_no++;
	if (esn)
		pstats_ipsec_esn++;
	if (tfc)
		pstats_ipsec_tfc++;
}

#define pstatsv(TYPE, V2, INDEXv1, INDEXv2)				\
	{								\
		if (V2) {						\
			pstats(ikev2_##TYPE, INDEXv2);			\
		} else {						\
			pstats(ikev1_##TYPE, INDEXv1);			\
		}							\
	}

static void pstat_child_sa_established(struct state *st)
{
	struct connection *const c = st->st_connection;

	/* don't count IKEv1 half ipsec sa */
	if (st->st_state->kind == STATE_QUICK_R1) {
		pstats_ipsec_sa++;
	}

	if (st->st_esp.present) {
		bool nat = (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) != 0;
		bool tfc = c->sa_tfcpad != 0 && !st->st_seen_no_tfc;
		bool esn = st->st_esp.attrs.transattrs.esn_enabled;

		pstats_ipsec_esp++;
		pstatsv(ipsec_encrypt, (st->st_ike_version == IKEv2),
			st->st_esp.attrs.transattrs.ta_encrypt->common.id[IKEv1_ESP_ID],
			st->st_esp.attrs.transattrs.ta_encrypt->common.id[IKEv2_ALG_ID]);
		pstatsv(ipsec_integ, (st->st_ike_version == IKEv2),
			st->st_esp.attrs.transattrs.ta_integ->common.id[IKEv1_ESP_ID],
			st->st_esp.attrs.transattrs.ta_integ->common.id[IKEv2_ALG_ID]);
		pstats_sa(nat, tfc, esn);
	}
	if (st->st_ah.present) {
		/* XXX: .st_esp? */
		bool esn = st->st_esp.attrs.transattrs.esn_enabled;
		pstats_ipsec_ah++;
		pstatsv(ipsec_integ, (st->st_ike_version == IKEv2),
			st->st_ah.attrs.transattrs.ta_integ->common.id[IKEv1_ESP_ID],
			st->st_ah.attrs.transattrs.ta_integ->common.id[IKEv2_ALG_ID]);
		pstats_sa(FALSE, FALSE, esn);
	}
	if (st->st_ipcomp.present) {
		pstats_ipsec_ipcomp++;
	}
}

void pstat_sa_established(struct state *st)
{
	const char *name = pstats_sa_names[st->st_ike_version][st->st_pstats.sa_type];
	dbg("pstats #%lu %s established", st->st_serialno, name);
	pstats_sa_established[st->st_ike_version][st->st_pstats.sa_type]++;

	/*
	 * Check for double billing.  Only care that IKEv2 gets this
	 * right (IKEv1 is known to be broken).
	 */
#ifdef NOT_YET
	pexpect(st->st_ike_version == IKEv1 ||
		st->st_pstats.delete_reason == REASON_UNKNOWN);
#endif
	st->st_pstats.delete_reason = REASON_COMPLETED;

	switch (st->st_pstats.sa_type) {
	case IKE_SA: pstat_ike_sa_established(st); break;
	case IPSEC_SA: pstat_child_sa_established(st); break;
	}
}

/*
 * Output.
 */

static void whack_pluto_stat(const struct fd *whackfd, const struct pluto_stat *stat)
{
	unsigned long other = stat->count[stat->roof - stat->floor];
	for (unsigned long e = stat->floor; e < stat->roof; e++) {
		const char *nm = enum_short_name(stat->names, e);
		unsigned long count = stat->count[e - stat->floor];
		/* not logging "UNUSED" */
		if (nm != NULL && strstr(nm, "UNUSED") == NULL) {
			whack_print(whackfd, "total.%s.%s=%lu",
				    stat->what, nm, count);
		} else {
			other += count;
		}
	}
	whack_print(whackfd, "total.%s.other=%lu",
		    stat->what, other);
}

static void clear_pluto_stat(const struct pluto_stat *stat)
{
	memset(stat->count, 0, stat->roof - stat->floor + 1);
}

/*
 * Some arrays start at 1, some start at 0, some start at ...
 */
static void enum_stats(const struct fd *whackfd, enum_names *names, unsigned long start,
		       unsigned long elemsof_count,
		       const char *what, unsigned long count[])
{
	for (unsigned e = start; e < elemsof_count; e++) {
		/*
		 * XXX: the bug is that the enum table contains names
		 * that include UNUSED.  Skip them.
		 */
		const char *name = enum_short_name(names, e);
		if (name != NULL && strstr(name, "UNUSED") == NULL) {
			whack_print(whackfd, "total.%s.%s=%lu",
				    what, name, count[e]);
		}
	}
}
#define ENUM_STATS(NAMES, START, WHAT, COUNT)	\
	enum_stats(whackfd, NAMES, START, elemsof(COUNT), WHAT, COUNT)

#define IKE_ALG_STATS(WHAT, TYPE, ID, COUNT)				\
	for (const struct TYPE##_desc **algp = next_##TYPE##_desc(NULL); \
	     algp != NULL; algp = next_##TYPE##_desc(algp)) {		\
		const struct TYPE##_desc *alg = *algp;			\
		long id = alg->common.id[ID];				\
		if (id >= 0 && id < (ssize_t) elemsof(COUNT)) {		\
			whack_print(whackfd, "total.%s.%s=%lu",		\
				    WHAT, alg->common.fqn,		\
				    COUNT[id]);				\
		}							\
	}

void show_pluto_stats(const struct fd *whackfd)
{
	whack_print(whackfd, "total.ipsec.type.all=%lu", pstats_ipsec_sa);
	whack_print(whackfd, "total.ipsec.type.esp=%lu", pstats_ipsec_esp);
	whack_print(whackfd, "total.ipsec.type.ah=%lu", pstats_ipsec_ah);
	whack_print(whackfd, "total.ipsec.type.ipcomp=%lu", pstats_ipsec_ipcomp);
	whack_print(whackfd, "total.ipsec.type.esn=%lu", pstats_ipsec_esn);
	whack_print(whackfd, "total.ipsec.type.tfc=%lu", pstats_ipsec_tfc);
	whack_print(whackfd, "total.ipsec.type.encap=%lu", pstats_ipsec_encap_yes);
	whack_print(whackfd, "total.ipsec.type.non_encap=%lu", pstats_ipsec_encap_no);
	/*
	 * Total counts only total of traffic by terminated IPsec SA's.
	 * Should we call get_sa_info() for bytes of active IPsec SA's?
	 */
	whack_print(whackfd, "total.ipsec.traffic.in=%" PRIu64, pstats_ipsec_in_bytes);
	whack_print(whackfd, "total.ipsec.traffic.out=%" PRIu64, pstats_ipsec_out_bytes);

	/* old */
	whack_print(whackfd, "total.ike.ikev2.established=%lu", pstats_ikev2_sa);
	whack_print(whackfd, "total.ike.ikev2.failed=%lu", pstats_ikev2_fail);
	whack_print(whackfd, "total.ike.ikev2.completed=%lu", pstats_ikev2_completed);
	whack_print(whackfd, "total.ike.ikev1.established=%lu", pstats_ikev1_sa);
	whack_print(whackfd, "total.ike.ikev1.failed=%lu", pstats_ikev1_fail);
	whack_print(whackfd, "total.ike.ikev1.completed=%lu", pstats_ikev1_completed);

	/* new */
	for (enum ike_version v = IKE_VERSION_FLOOR; v < IKE_VERSION_ROOF; v++) {
		for (enum sa_type t = SA_TYPE_FLOOR; t < SA_TYPE_ROOF; t++) {
			const char *name = pstats_sa_names[v][t];
			pexpect(name != NULL);
			whack_print(whackfd, "total.%s.started=%lu",
				    name, pstats_sa_started[v][t]);
			whack_print(whackfd, "total.%s.established=%lu",
				    name, pstats_sa_established[v][t]);
			unsigned long finished = 0;
			for (enum delete_reason r = DELETE_REASON_FLOOR; r < DELETE_REASON_ROOF; r++) {
				const char *reason = pstats_sa_reasons[r];
				pexpect(reason != NULL);
				unsigned long count = pstats_sa_finished[v][t][r];
				finished += count;
				if (count > 0) {
					whack_print(whackfd, "total.%s.finished.%s=%lu",
						    name, reason, count);
				}
			}
			whack_print(whackfd, "total.%s.finished=%lu",
				    name, finished);
		}
	}

	whack_print(whackfd, "total.ike.dpd.sent=%lu", pstats_ike_dpd_sent);
	whack_print(whackfd, "total.ike.dpd.recv=%lu", pstats_ike_dpd_recv);
	whack_print(whackfd, "total.ike.dpd.replied=%lu", pstats_ike_dpd_replied);
	whack_print(whackfd, "total.ike.traffic.in=%lu", pstats_ike_in_bytes);
	whack_print(whackfd, "total.ike.traffic.out=%lu", pstats_ike_out_bytes);

	whack_print(whackfd, "total.xauth.started=%lu", pstats_xauth_started);
	whack_print(whackfd, "total.xauth.stopped=%lu", pstats_xauth_stopped);
	whack_print(whackfd, "total.xauth.aborted=%lu", pstats_xauth_aborted);

	whack_print(whackfd, "total.iketcp.client.started=%lu", pstats_iketcp_started[false]);
	whack_print(whackfd, "total.iketcp.client.stopped=%lu", pstats_iketcp_stopped[false]);
	whack_print(whackfd, "total.iketcp.client.aborted=%lu", pstats_iketcp_aborted[false]);
	whack_print(whackfd, "total.iketcp.server.started=%lu", pstats_iketcp_started[true]);
	whack_print(whackfd, "total.iketcp.server.stopped=%lu", pstats_iketcp_stopped[true]);
	whack_print(whackfd, "total.iketcp.server.aborted=%lu", pstats_iketcp_aborted[true]);

	ENUM_STATS(&oakley_enc_names, OAKLEY_3DES_CBC, "ikev1.encr", pstats_ikev1_encr);
	ENUM_STATS(&oakley_hash_names, OAKLEY_MD5, "ikev1.integ", pstats_ikev1_integ);
	ENUM_STATS(&oakley_group_names, OAKLEY_GROUP_MODP768, "ikev1.group", pstats_ikev1_groups);
	ENUM_STATS(&ikev2_trans_type_encr_names, IKEv2_ENCR_3DES, "ikev2.encr", pstats_ikev2_encr);
	ENUM_STATS(&ikev2_trans_type_integ_names, IKEv2_AUTH_HMAC_MD5_96, "ikev2.integ", pstats_ikev2_integ);
	ENUM_STATS(&oakley_group_names, OAKLEY_GROUP_MODP768, "ikev2.group", pstats_ikev2_groups);

	/* we log the received invalid groups and the suggested valid groups */
	ENUM_STATS(&oakley_group_names, OAKLEY_GROUP_MODP768, "ikev2.recv.invalidke.using", pstats_invalidke_recv_u);
	ENUM_STATS(&oakley_group_names, OAKLEY_GROUP_MODP768, "ikev2.recv.invalidke.suggesting", pstats_invalidke_recv_s);
	ENUM_STATS(&oakley_group_names, OAKLEY_GROUP_MODP768, "ikev2.sent.invalidke.using", pstats_invalidke_sent_u);
	ENUM_STATS(&oakley_group_names, OAKLEY_GROUP_MODP768, "ikev2.sent.invalidke.suggesting", pstats_invalidke_sent_s);

#if 0
	/* ??? THIS IS BROKEN (hint: array is wrong size (10)) */
	for (unsigned long e = STF_IGNORE; e <= STF_FAIL; e++)
	{
		whack_print(whackfd, "total.pluto.stf.%s=%lu",
			    enum_name(&stfstatus_name, e),
			    pstats_ike_stf[e]);
	}
#endif

	IKE_ALG_STATS("ikev1.ipsec.encr", encrypt, IKEv1_ESP_ID, pstats_ikev1_ipsec_encrypt);
	IKE_ALG_STATS("ikev1.ipsec.integ", integ, IKEv1_ESP_ID, pstats_ikev1_ipsec_integ);
	IKE_ALG_STATS("ikev2.ipsec.encr", encrypt, IKEv2_ALG_ID, pstats_ikev2_ipsec_encrypt);
	IKE_ALG_STATS("ikev2.ipsec.integ", integ, IKEv2_ALG_ID, pstats_ikev2_ipsec_integ);

	ENUM_STATS(&ikev1_notify_names, 1, "ikev1.sent.notifies.error", pstats_ikev1_sent_notifies_e);
	ENUM_STATS(&ikev1_notify_names, 1, "ikev1.recv.notifies.error", pstats_ikev1_recv_notifies_e);

	whack_pluto_stat(whackfd, &pstats_ikev2_sent_notifies_e);
	whack_pluto_stat(whackfd, &pstats_ikev2_recv_notifies_e);
	whack_pluto_stat(whackfd, &pstats_ikev2_sent_notifies_s);
	whack_pluto_stat(whackfd, &pstats_ikev2_recv_notifies_s);
}

void clear_pluto_stats(void)
{
	dbg("clearing pluto stats");

	pstats_ipsec_sa = pstats_ikev1_sa = pstats_ikev2_sa = 0;
	pstats_ikev1_fail = pstats_ikev2_fail = 0;
	pstats_ikev1_completed = pstats_ikev2_completed = 0;

	memset(pstats_sa_started, 0, sizeof pstats_sa_started);
	memset(pstats_sa_finished, 0, sizeof pstats_sa_finished);
	memset(pstats_sa_established, 0, sizeof pstats_sa_established);

	pstats_ipsec_in_bytes = pstats_ipsec_out_bytes = 0;
	pstats_ike_in_bytes = pstats_ike_out_bytes = 0;
	pstats_ipsec_esp = pstats_ipsec_ah = pstats_ipsec_ipcomp = 0;
	pstats_ipsec_encap_yes = pstats_ipsec_encap_no = 0;
	pstats_ipsec_esn = pstats_ipsec_tfc = 0;
	pstats_ike_dpd_recv = pstats_ike_dpd_sent = pstats_ike_dpd_replied = 0;
	pstats_xauth_started = pstats_xauth_stopped = pstats_xauth_aborted = 0;

	memset(pstats_iketcp_started, 0, sizeof(pstats_iketcp_started));
	memset(pstats_iketcp_stopped, 0, sizeof(pstats_iketcp_stopped));
	memset(pstats_iketcp_aborted, 0, sizeof(pstats_iketcp_aborted));

	memset(pstats_ikev1_encr, 0, sizeof pstats_ikev1_encr);
	memset(pstats_ikev2_encr, 0, sizeof pstats_ikev2_encr);
	memset(pstats_ikev1_integ, 0, sizeof pstats_ikev1_integ);
	memset(pstats_ikev2_integ, 0, sizeof pstats_ikev2_integ);
	memset(pstats_ikev1_ipsec_encrypt, 0, sizeof pstats_ikev1_ipsec_encrypt);
	memset(pstats_ikev2_ipsec_encrypt, 0, sizeof pstats_ikev2_ipsec_encrypt);
	memset(pstats_ikev1_ipsec_integ, 0, sizeof pstats_ikev1_ipsec_integ);
	memset(pstats_ikev2_ipsec_integ, 0, sizeof pstats_ikev2_ipsec_integ);
	memset(pstats_ikev1_groups, 0, sizeof pstats_ikev1_groups);
	memset(pstats_ikev2_groups, 0, sizeof pstats_ikev2_groups);
	memset(pstats_invalidke_sent_s, 0, sizeof pstats_invalidke_sent_s);
	memset(pstats_invalidke_recv_s, 0, sizeof pstats_invalidke_recv_s);
	memset(pstats_invalidke_sent_u, 0, sizeof pstats_invalidke_sent_u);
	memset(pstats_invalidke_recv_u, 0, sizeof pstats_invalidke_recv_u);
	memset(pstats_ikev1_sent_notifies_e, 0, sizeof pstats_ikev1_sent_notifies_e);
	clear_pluto_stat(&pstats_ikev2_sent_notifies_e);
	clear_pluto_stat(&pstats_ikev2_recv_notifies_e);
	clear_pluto_stat(&pstats_ikev2_sent_notifies_s);
	clear_pluto_stat(&pstats_ikev2_recv_notifies_s);
	memset(pstats_ikev1_recv_notifies_e, 0, sizeof pstats_ikev1_recv_notifies_e);
}
