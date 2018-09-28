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
#ifndef _PLUTO_STATS_H
#define _PLUTO_STATS_H

struct pluto_stat {
	const enum_names *names;
	const char *what;
	unsigned long floor;
	unsigned long roof; /* ceil+1 */
	unsigned long *count;
};

/* All statistics are totals since pluto daemon startup */
extern unsigned long pstats_ipsec_sa;
extern unsigned long pstats_ikev1_sa;
extern unsigned long pstats_ikev2_sa;
extern unsigned long pstats_ikev1_fail;
extern unsigned long pstats_ikev2_fail;
extern unsigned long pstats_ikev1_encr[OAKLEY_ENCR_PSTATS_ROOF];
extern unsigned long pstats_ikev2_encr[IKEv2_ENCR_PSTATS_ROOF];
extern unsigned long pstats_ikev1_integ[OAKLEY_HASH_PSTATS_ROOF];
extern unsigned long pstats_ikev2_integ[IKEv2_AUTH_PSTATS_ROOF];
extern unsigned long pstats_ikev1_groups[OAKLEY_GROUP_PSTATS_ROOF];
extern unsigned long pstats_ikev2_groups[OAKLEY_GROUP_PSTATS_ROOF];
extern unsigned long pstats_invalidke_recv_s[OAKLEY_GROUP_PSTATS_ROOF];
extern unsigned long pstats_invalidke_recv_u[OAKLEY_GROUP_PSTATS_ROOF];
extern unsigned long pstats_invalidke_sent_s[OAKLEY_GROUP_PSTATS_ROOF];
extern unsigned long pstats_invalidke_sent_u[OAKLEY_GROUP_PSTATS_ROOF];

extern unsigned long pstats_ikev1_ipsec_encrypt[ESP_PSTATS_ROOF];
extern unsigned long pstats_ikev2_ipsec_encrypt[IKEv2_ENCR_PSTATS_ROOF];
extern unsigned long pstats_ikev1_ipsec_integ[AUTH_ALGORITHM_PSTATS_ROOF];
extern unsigned long pstats_ikev2_ipsec_integ[IKEv2_AUTH_PSTATS_ROOF];

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
extern unsigned long pstats_ipsec_esp;
extern unsigned long pstats_ipsec_ah;
extern unsigned long pstats_ipsec_ipcomp;
extern unsigned long pstats_ipsec_encap_yes;
extern unsigned long pstats_ipsec_encap_no;
extern unsigned long pstats_ipsec_esn;
extern unsigned long pstats_ipsec_tfc;
extern unsigned long pstats_ike_dpd_recv;
extern unsigned long pstats_ike_dpd_sent;
extern unsigned long pstats_ike_dpd_replied;

extern unsigned long pstats_xauth_started;
extern unsigned long pstats_xauth_stopped;
extern unsigned long pstats_xauth_aborted;

extern void show_pluto_stats();
extern void clear_pluto_stats();

/*
 * This (assuming it works) is less evil then an array index
 * out-of-bound; which isn't saying much.
 *
 * "unsigned" forces negative values to large positive ones,
 * presumably INDEX fits in "unsigned".  Is size_t better?
 */

#define pstatsv(TYPE, V2, INDEXv1, INDEXv2)				\
	{								\
		if (V2) {						\
			pstats(ikev2_##TYPE, INDEXv2);			\
		} else {						\
			pstats(ikev1_##TYPE, INDEXv1);			\
		}							\
	}

#define pstats(TYPE,INDEX) {						\
		const unsigned __pstat = (INDEX);			\
		if (__pstat < elemsof(pstats_##TYPE)) {			\
			pstats_##TYPE[__pstat]++;			\
		} else if (DBGP(DBG_CONTROLMORE)) {			\
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

#endif /* _PLUTO_STATS_H */
