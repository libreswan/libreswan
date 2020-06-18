/*
 * IKE and IPsec Statistics for the pluto daemon
 *
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019-2019 Andrew Cagney <cagney@gnu.org>
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
#ifndef _PLUTO_STATS_H
#define _PLUTO_STATS_H

enum delete_reason;

struct pluto_stat {
	const enum_names *names;
	const char *what;
	unsigned long floor;
	unsigned long roof; /* ceil+1 */
	unsigned long *count;
};

/* All statistics are totals since pluto daemon startup */

extern unsigned long pstats_invalidke_recv_s[OAKLEY_GROUP_PSTATS_ROOF];
extern unsigned long pstats_invalidke_recv_u[OAKLEY_GROUP_PSTATS_ROOF];
extern unsigned long pstats_invalidke_sent_s[OAKLEY_GROUP_PSTATS_ROOF];
extern unsigned long pstats_invalidke_sent_u[OAKLEY_GROUP_PSTATS_ROOF];

extern uint64_t pstats_ipsec_in_bytes;	/* total incoming IPsec traffic */
extern uint64_t pstats_ipsec_out_bytes;	/* total outgoing IPsec traffic */
extern unsigned long pstats_ike_in_bytes;	/* total incoming IPsec traffic */
extern unsigned long pstats_ike_out_bytes;	/* total outgoing IPsec traffic */
extern unsigned long pstats_ikev1_sent_notifies_e[v1N_ERROR_PSTATS_ROOF]; /* types of NOTIFY ERRORS */
extern unsigned long pstats_ikev1_recv_notifies_e[v1N_ERROR_PSTATS_ROOF]; /* types of NOTIFY ERRORS */
extern const struct pluto_stat pstats_ikev2_sent_notifies_e; /* types of NOTIFY ERRORS */
extern const struct pluto_stat pstats_ikev2_recv_notifies_e; /* types of NOTIFY ERRORS */
extern const struct pluto_stat pstats_ikev2_sent_notifies_s; /* types of NOTIFY STATUS */
extern const struct pluto_stat pstats_ikev2_recv_notifies_s; /* types of NOTIFY STATUS */
extern unsigned long pstats_ike_stf[10];	/* count state transitions */
extern unsigned long pstats_ike_dpd_recv;
extern unsigned long pstats_ike_dpd_sent;
extern unsigned long pstats_ike_dpd_replied;

extern unsigned long pstats_iketcp_started[2];
extern unsigned long pstats_iketcp_aborted[2];
extern unsigned long pstats_iketcp_stopped[2];

extern unsigned long pstats_xauth_started;
extern unsigned long pstats_xauth_stopped;
extern unsigned long pstats_xauth_aborted;

extern void show_pluto_stats(const struct fd *whackfd);
extern void clear_pluto_stats(void);

/*
 * This (assuming it works) is less evil then an array index
 * out-of-bound; which isn't saying much.
 *
 * "unsigned" forces negative values to large positive ones,
 * presumably INDEX fits in "unsigned".  Is size_t better?
 */

#define pstats(TYPE,INDEX) {						\
		const unsigned __pstat = (INDEX);			\
		if (__pstat < elemsof(pstats_##TYPE)) {			\
			pstats_##TYPE[__pstat]++;			\
		} else if (DBGP(DBG_BASE)) {			\
			DBG_log("pstats %s %d", #TYPE, __pstat);	\
		}							\
	}

#define pstat(TYPE,INDEX)						\
	{								\
		const unsigned pstat_ = (INDEX);			\
		const struct pluto_stat *ps_ = &pstats_##TYPE;		\
		if (pstat_ < ps_->floor || pstat_ >= ps_->roof) {	\
			ps_->count[ps_->roof - ps_->floor]++;		\
		} else {						\
			ps_->count[pstat_-ps_->floor]++;		\
		}							\
	}

void pstat_sa_started(struct state *st, enum sa_type sa_type);
void pstat_sa_failed(struct state *st, enum delete_reason reason);
void pstat_sa_established(struct state *st);
void pstat_sa_deleted(struct state *st);

#endif /* _PLUTO_STATS_H */
