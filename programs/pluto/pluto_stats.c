/*
 * IKE and IPsec Statistics for the pluto daemon
 *
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
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

#include <libreswan.h>

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

unsigned long pstats_ipsec_sa;
unsigned long pstats_ikev1_sa;
unsigned long pstats_ikev2_sa;
unsigned long pstats_ikev1_fail;
unsigned long pstats_ikev2_fail;
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

static void whack_pluto_stat(const struct pluto_stat *stat)
{
	unsigned long other = stat->count[stat->roof - stat->floor];
	for (unsigned long e = stat->floor; e < stat->roof; e++)
	{
		const char *nm = enum_short_name(stat->names, e);
		unsigned long count = stat->count[e - stat->floor];
		/* not logging "UNUSED" */
		if (nm != NULL && strstr(nm, "UNUSED") == NULL) {
			whack_log_comment("total.%s.%s=%lu",
					  stat->what, nm, count);
		} else {
			other += count;
		}
	}
	whack_log_comment("total.%s.other=%lu",
			  stat->what, other);
}

static void clear_pluto_stat(const struct pluto_stat *stat)
{
	memset(stat->count, 0, stat->roof - stat->floor + 1);
}

/*
 * Some arrays start at 1, some start at 0, some start at ...
 */
static void enum_stats(enum_names *names, unsigned long start,
		       unsigned long elemsof_count,
		       const char *what, unsigned long count[])
{
	for (unsigned e = start; e < elemsof_count; e++) {
		const char *name = enum_short_name(names, e);
		/*
		 * XXX: the bug is that the enum table contains names
		 * that include UNUSED.  Skip them.
		 */
		if (name != NULL && strstr(name, "UNUSED") == NULL)
			whack_log_comment("total.%s.%s=%lu",
				what, name, count[e]);
	}
}
#define ENUM_STATS(NAMES, START, WHAT, COUNT)	\
	enum_stats(NAMES, START, elemsof(COUNT), WHAT, COUNT)

#define IKE_ALG_STATS(WHAT, TYPE, ID, COUNT)				\
	for (const struct TYPE##_desc **algp = next_##TYPE##_desc(NULL); \
	     algp != NULL; algp = next_##TYPE##_desc(algp)) {		\
		const struct TYPE##_desc *alg = *algp;			\
		long id = alg->common.id[ID];				\
		if (id >= 0 && id < (ssize_t) elemsof(COUNT)) {		\
			whack_log_comment("total.%s.%s=%lu",		\
					  WHAT, alg->common.fqn,	\
					  COUNT[id]);			\
		}							\
	}

void show_pluto_stats()
{
	whack_log_comment("total.ipsec.type.all=%lu", pstats_ipsec_sa);
	whack_log_comment("total.ipsec.type.esp=%lu", pstats_ipsec_esp);
	whack_log_comment("total.ipsec.type.ah=%lu", pstats_ipsec_ah);
	whack_log_comment("total.ipsec.type.ipcomp=%lu", pstats_ipsec_ipcomp);
	whack_log_comment("total.ipsec.type.esn=%lu", pstats_ipsec_esn);
	whack_log_comment("total.ipsec.type.tfc=%lu", pstats_ipsec_tfc);
	whack_log_comment("total.ipsec.type.encap=%lu", pstats_ipsec_encap_yes);
	whack_log_comment("total.ipsec.type.non_encap=%lu", pstats_ipsec_encap_no);
	/*
	 * Total counts only total of traffic by terminated IPsec Sa's.
	 * Should we call get_sa_info() for bytes of active IPsec SA's?
	 */
	whack_log_comment("total.ipsec.traffic.in=%" PRIu64, pstats_ipsec_in_bytes);
	whack_log_comment("total.ipsec.traffic.out=%" PRIu64, pstats_ipsec_out_bytes);

	whack_log_comment("total.ike.ikev2.established=%lu", pstats_ikev2_sa);
	whack_log_comment("total.ike.ikev2.failed=%lu", pstats_ikev2_fail);
	whack_log_comment("total.ike.ikev1.established=%lu", pstats_ikev1_sa);
	whack_log_comment("total.ike.ikev1.failed=%lu", pstats_ikev1_fail);

	whack_log_comment("total.ike.dpd.sent=%lu", pstats_ike_dpd_sent);
	whack_log_comment("total.ike.dpd.recv=%lu", pstats_ike_dpd_recv);
	whack_log_comment("total.ike.dpd.replied=%lu", pstats_ike_dpd_replied);
	whack_log_comment("total.ike.traffic.in=%lu", pstats_ike_in_bytes);
	whack_log_comment("total.ike.traffic.out=%lu", pstats_ike_out_bytes);

	whack_log_comment("total.xauth.started=%lu", pstats_xauth_started);
	whack_log_comment("total.xauth.stopped=%lu", pstats_xauth_stopped);
	whack_log_comment("total.xauth.aborted=%lu", pstats_xauth_aborted);

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
		whack_log_comment("total.pluto.stf.%s=%lu",
			enum_name(&stfstatus_name, e), pstats_ike_stf[e]);
	}
#endif

	IKE_ALG_STATS("ikev1.ipsec.encr", encrypt, IKEv1_ESP_ID, pstats_ikev1_ipsec_encrypt);
	IKE_ALG_STATS("ikev1.ipsec.integ", integ, IKEv1_ESP_ID, pstats_ikev1_ipsec_integ);
	IKE_ALG_STATS("ikev2.ipsec.encr", encrypt, IKEv2_ALG_ID, pstats_ikev2_ipsec_encrypt);
	IKE_ALG_STATS("ikev2.ipsec.integ", integ, IKEv2_ALG_ID, pstats_ikev2_ipsec_integ);

	ENUM_STATS(&ikev1_notify_names, 1, "ikev1.sent.notifies.error", pstats_ikev1_sent_notifies_e);
	ENUM_STATS(&ikev1_notify_names, 1, "ikev1.recv.notifies.error", pstats_ikev1_recv_notifies_e);

	whack_pluto_stat(&pstats_ikev2_sent_notifies_e);
	whack_pluto_stat(&pstats_ikev2_recv_notifies_e);
	whack_pluto_stat(&pstats_ikev2_sent_notifies_s);
	whack_pluto_stat(&pstats_ikev2_recv_notifies_s);
}

void clear_pluto_stats()
{
	DBG(DBG_CONTROL, DBG_log("clearing pluto stats"));

	pstats_ipsec_sa = pstats_ikev1_sa = pstats_ikev2_sa = 0;
	pstats_ikev1_fail = pstats_ikev2_fail = 0;
	pstats_ipsec_in_bytes = pstats_ipsec_out_bytes = 0;
	pstats_ike_in_bytes = pstats_ike_out_bytes = 0;
	pstats_ipsec_esp = pstats_ipsec_ah = pstats_ipsec_ipcomp = 0;
	pstats_ipsec_encap_yes = pstats_ipsec_encap_no = 0;
	pstats_ipsec_esn = pstats_ipsec_tfc = 0;
	pstats_ike_dpd_recv = pstats_ike_dpd_sent = pstats_ike_dpd_replied = 0;
	pstats_xauth_started = pstats_xauth_stopped = pstats_xauth_aborted = 0;

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
