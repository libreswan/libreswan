/*
 * IKE and IPsec Statistics for the pluto daemon
 *
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
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

#include "pluto_stats.h"

unsigned long pstats_ipsec_sa;
unsigned long pstats_ikev1_sa;
unsigned long pstats_ikev2_sa;
unsigned long pstats_ikev1_fail;
unsigned long pstats_ikev2_fail;
unsigned long pstats_ikev1_encr[OAKLEY_CAMELLIA_CCM_C+1];
unsigned long pstats_ikev2_encr[IKEv2_ENCR_ROOF+1];
unsigned long pstats_ikev1_integ[OAKLEY_SHA2_512+1];
unsigned long pstats_ikev2_integ[AUTH_ALGORITHM_ROOF+1];
unsigned long pstats_ikev1_groups[OAKLEY_GROUP_ROOF+1];
unsigned long pstats_ikev2_groups[OAKLEY_GROUP_ROOF+1];
unsigned long pstats_invalidke_recv_s[OAKLEY_GROUP_ROOF+1];
unsigned long pstats_invalidke_recv_u[OAKLEY_GROUP_ROOF+1];
unsigned long pstats_invalidke_sent_s[OAKLEY_GROUP_ROOF+1];
unsigned long pstats_invalidke_sent_u[OAKLEY_GROUP_ROOF+1];
unsigned long pstats_ipsec_encr[IKEv2_ENCR_ROOF+1];	/* pretends everything maps 1 to 1 */
unsigned long pstats_ipsec_integ[AUTH_ALGORITHM_ROOF+1];	/* pretends everything maps 1 to 1 */
unsigned long pstats_ipsec_in_bytes;	/* total incoming IPsec traffic */
unsigned long pstats_ipsec_out_bytes;	/* total outgoing IPsec traffic */
unsigned long pstats_ike_in_bytes;	/* total incoming IPsec traffic */
unsigned long pstats_ike_out_bytes;	/* total outgoing IPsec traffic */
unsigned long pstats_ikev1_sent_notifies_e[v1N_ERROR_ROOF+1]; /* types of NOTIFY ERRORS */
unsigned long pstats_ikev1_recv_notifies_e[v1N_ERROR_ROOF+1]; /* types of NOTIFY ERRORS */
unsigned long pstats_ikev2_sent_notifies_e[v2N_ERROR_ROOF+1]; /* types of NOTIFY ERRORS */
unsigned long pstats_ikev2_recv_notifies_e[v2N_ERROR_ROOF+1]; /* types of NOTIFY ERRORS */
unsigned long pstats_ike_stf[10];	/* count state transitions */
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

void show_pluto_stats()
{
	whack_log(RC_COMMENT, "#total.ipsec.type.all=%lu", pstats_ipsec_sa);
	whack_log(RC_COMMENT, "#total.ipsec.type.esp=%lu", pstats_ipsec_esp);
	whack_log(RC_COMMENT, "#total.ipsec.type.ah=%lu", pstats_ipsec_ah);
	whack_log(RC_COMMENT, "#total.ipsec.type.ipcomp=%lu", pstats_ipsec_ipcomp);
	whack_log(RC_COMMENT, "#total.ipsec.type.esn=%lu", pstats_ipsec_esn);
	whack_log(RC_COMMENT, "#total.ipsec.type.tfc=%lu", pstats_ipsec_tfc);
	whack_log(RC_COMMENT, "#total.ipsec.type.encap=%lu", pstats_ipsec_encap_yes);
	whack_log(RC_COMMENT, "#total.ipsec.type.non_encap=%lu", pstats_ipsec_encap_no);
	/*
	 * Total counts only total of traffic by terminated IPsec Sa's.
	 * Should we call get_sa_info() for bytes of active IPsec SA's?
	 */
	whack_log(RC_COMMENT, "#total.ipsec.traffic.in=%lu", pstats_ipsec_in_bytes);
	whack_log(RC_COMMENT, "#total.ipsec.traffic.out=%lu", pstats_ipsec_out_bytes);

	whack_log(RC_COMMENT, "#total.ike.ikev2.established=%lu", pstats_ikev2_sa);
	whack_log(RC_COMMENT, "#total.ike.ikev2.failed=%lu", pstats_ikev2_fail);
	whack_log(RC_COMMENT, "#total.ike.ikev1.established=%lu", pstats_ikev1_sa);
	whack_log(RC_COMMENT, "#total.ike.ikev1.failed=%lu", pstats_ikev1_fail);

	whack_log(RC_COMMENT, "#total.ike.dpd.sent=%lu", pstats_ike_dpd_sent);
	whack_log(RC_COMMENT, "#total.ike.dpd.recv=%lu", pstats_ike_dpd_recv);
	whack_log(RC_COMMENT, "#total.ike.dpd.replied=%lu", pstats_ike_dpd_replied);
	whack_log(RC_COMMENT, "#total.ike.traffic.in=%lu", pstats_ike_in_bytes);
	whack_log(RC_COMMENT, "#total.ike.traffic.out=%lu", pstats_ike_out_bytes);

	for (unsigned long e = OAKLEY_3DES_CBC; e <= OAKLEY_CAMELLIA_CCM_C; e++)
	{
		/* not logging private use (serpent/twofish) or UNUSED */
		if (strstr(enum_name(&oakley_enc_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ikev1.encr.%s=%lu",
				strip_prefix(enum_name(&oakley_enc_names, e), "OAKLEY_"),
				pstats_ikev1_encr[e]);
	}
	for (unsigned long e = OAKLEY_MD5; e <= OAKLEY_SHA2_512; e++)
	{
		if (strstr(enum_name(&oakley_hash_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ikev1.integ.%s=%lu",
				strip_prefix(enum_name(&oakley_hash_names, e), "OAKLEY_"),
				pstats_ikev1_integ[e]);
	}
	for (unsigned long e = OAKLEY_GROUP_MODP768; e <= OAKLEY_GROUP_ROOF; e++)
	{
		if (strstr(enum_name(&oakley_group_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ikev1.group.%s=%lu",
				strip_prefix(enum_name(&oakley_group_names, e), "OAKLEY_GROUP_"),
			pstats_ikev1_groups[e]);
	}

	for (unsigned long e = IKEv2_ENCR_3DES; e <= IKEv2_ENCR_CHACHA20_POLY1305; e++)
	{
		/* not logging private use (serpent/twofish) or UNUSED */
		if (strstr(enum_name(&ikev2_trans_type_encr_names, e), "UNUSED") == NULL)
		whack_log(RC_COMMENT, "#total.ikev2.encr.%s=%lu",
			enum_name(&ikev2_trans_type_encr_names, e), pstats_ikev2_encr[e]);
	}

	for (unsigned long e = IKEv2_AUTH_HMAC_MD5_96; e <= IKEv2_AUTH_ROOF; e++)
	{
		if (strstr(enum_name(&ikev2_trans_type_integ_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ikev2.integ.%s=%lu",
				strip_prefix(enum_name(&ikev2_trans_type_integ_names, e), "OAKLEY_"),
				pstats_ikev2_integ[e]);
	}

	for (unsigned long e = OAKLEY_GROUP_MODP768; e <= OAKLEY_GROUP_ROOF; e++)
	{
		if (strstr(enum_name(&oakley_group_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ikev2.group.%s=%lu",
				strip_prefix(enum_name(&oakley_group_names, e), "OAKLEY_GROUP_"),
			pstats_ikev2_groups[e]);
	}

	/* we log the received invalid groups and the suggested valid groups */
	for (unsigned long e = OAKLEY_GROUP_MODP768; e <= OAKLEY_GROUP_ROOF; e++)
	{
		if (strstr(enum_name(&oakley_group_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ikev2.recv.invalidke.using.%s=%lu",
				strip_prefix(enum_name(&oakley_group_names, e), "OAKLEY_GROUP_"),
			pstats_invalidke_recv_u[e]);
	}
	for (unsigned long e = OAKLEY_GROUP_MODP768; e <= OAKLEY_GROUP_ROOF; e++)
	{
		if (strstr(enum_name(&oakley_group_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ikev2.recv.invalidke.suggesting.%s=%lu",
				strip_prefix(enum_name(&oakley_group_names, e), "OAKLEY_GROUP_"),
			pstats_invalidke_recv_s[e]);
	}
	for (unsigned long e = OAKLEY_GROUP_MODP768; e <= OAKLEY_GROUP_ROOF; e++)
	{
		if (strstr(enum_name(&oakley_group_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ikev2.sent.invalidke.using.%s=%lu",
				strip_prefix(enum_name(&oakley_group_names, e), "OAKLEY_GROUP_"),
			pstats_invalidke_sent_u[e]);
	}
	for (unsigned long e = OAKLEY_GROUP_MODP768; e <= OAKLEY_GROUP_ROOF; e++)
	{
		if (strstr(enum_name(&oakley_group_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ikev2.sent.invalidke.suggesting.%s=%lu",
				strip_prefix(enum_name(&oakley_group_names, e), "OAKLEY_GROUP_"),
			pstats_invalidke_sent_s[e]);
	}

	for (unsigned long e = STF_IGNORE; e <= STF_FAIL; e++)
	{
		whack_log(RC_COMMENT, "#total.pluto.stf.%s=%lu",
			enum_name(&stfstatus_name, e), pstats_ike_stf[e]);
	}

	/* IPsec ENCR maps to IKEv2 ENCR */
	for (unsigned long e = IKEv2_ENCR_3DES; e <= IKEv2_ENCR_ROOF; e++)
	{
		/* not logging private use (serpent/twofish) or UNUSED */
		if (strstr(enum_name(&ikev2_trans_type_encr_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ipsec.encr.%s=%lu",
				enum_name(&ikev2_trans_type_encr_names, e),
				pstats_ipsec_encr[e]);
	}
	for (unsigned long e = AUTH_ALGORITHM_HMAC_MD5; e <= AUTH_ALGORITHM_ROOF; e++)
	{
		if (strstr(enum_name(&auth_alg_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ipsec.integ.%s=%lu",
				strip_prefix(enum_name(&auth_alg_names, e),
					"AUTH_ALGORITHM_"),
				pstats_ipsec_integ[e]);
	}

	for (unsigned long e = 1; e <= v1N_ERROR_ROOF; e++)
	{
		whack_log(RC_COMMENT, "#total.ikev1.sent.notifies.error.%s=%lu",
			enum_name(&ikev1_notify_names, e),
			pstats_ikev1_sent_notifies_e[e]);
	}
	for (unsigned long e = 1; e <= v1N_ERROR_ROOF; e++)
	{
		whack_log(RC_COMMENT, "#total.ikev1.recv.notifies.error.%s=%lu",
			enum_name(&ikev1_notify_names, e),
			pstats_ikev1_recv_notifies_e[e]);
	}

	for (unsigned long e = 1; e <= v2N_ERROR_ROOF; e++)
	{
		if (strstr(enum_name(&ikev2_notify_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ikev2.sent.notifies.error.%s=%lu",
				strip_prefix(enum_name(&ikev2_notify_names, e), "v2N_"),
			pstats_ikev2_sent_notifies_e[e]);
	}
	for (unsigned long e = 1; e <= v2N_ERROR_ROOF; e++)
	{
		if (strstr(enum_name(&ikev2_notify_names, e), "UNUSED") == NULL)
			whack_log(RC_COMMENT, "#total.ikev2.recv.notifies.error.%s=%lu",
				strip_prefix(enum_name(&ikev2_notify_names, e), "v2N_"),
			pstats_ikev2_recv_notifies_e[e]);
	}
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

	memset(pstats_ikev1_encr, 0, sizeof pstats_ikev1_encr);
	memset(pstats_ikev2_encr, 0, sizeof pstats_ikev2_encr);
	memset(pstats_ikev1_integ, 0, sizeof pstats_ikev1_integ);
	memset(pstats_ikev2_integ, 0, sizeof pstats_ikev2_integ);
	memset(pstats_ipsec_encr, 0, sizeof pstats_ipsec_encr);
	memset(pstats_ipsec_integ, 0, sizeof pstats_ipsec_integ);
	memset(pstats_ikev1_groups, 0, sizeof pstats_ikev1_groups);
	memset(pstats_ikev2_groups, 0, sizeof pstats_ikev2_groups);
	memset(pstats_invalidke_sent_s, 0, sizeof pstats_invalidke_sent_s);
	memset(pstats_invalidke_recv_s, 0, sizeof pstats_invalidke_recv_s);
	memset(pstats_invalidke_sent_u, 0, sizeof pstats_invalidke_sent_u);
	memset(pstats_invalidke_recv_u, 0, sizeof pstats_invalidke_recv_u);
	memset(pstats_ikev1_sent_notifies_e, 0, sizeof pstats_ikev1_sent_notifies_e);
	memset(pstats_ikev2_sent_notifies_e, 0, sizeof pstats_ikev2_sent_notifies_e);
	memset(pstats_ikev2_recv_notifies_e, 0, sizeof pstats_ikev2_recv_notifies_e);
	memset(pstats_ikev1_recv_notifies_e, 0, sizeof pstats_ikev1_recv_notifies_e);
}
