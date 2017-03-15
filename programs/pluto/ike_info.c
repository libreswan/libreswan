/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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
 */

#include <stdio.h>

#include "lswlog.h"
#include "alg_info.h"
#include "ike_alg.h"


static int snprint_ike_info(char *buf, size_t buflen, struct ike_info *ike_info,
			    bool fix_zero)
{
	const struct encrypt_desc *enc_desc = ike_info->ike_encrypt;
	passert(!fix_zero || enc_desc != NULL);
	const struct prf_desc *prf_desc = ike_info->ike_prf;
	passert(!fix_zero || prf_desc != NULL);

	int eklen = ike_info->ike_eklen;
	if (fix_zero && eklen == 0)
		eklen = enc_desc->keydeflen;

	struct esb_buf enc_buf, hash_buf, group_buf;
	return snprintf(buf, buflen,
			"%s(%d)_%03d-%s(%d)-%s(%d)",
			enum_show_shortb(&oakley_enc_names,
					 ike_info->ike_encrypt->common.ikev1_oakley_id,
					 &enc_buf),
			ike_info->ike_encrypt->common.ikev1_oakley_id, eklen,
			enum_show_shortb(&oakley_hash_names,
					 ike_info->ike_prf->common.ikev1_oakley_id,
					 &hash_buf),
			ike_info->ike_prf->common.ikev1_oakley_id,
			enum_show_shortb(&oakley_group_names,
					 ike_info->ike_dh_group->group,
					 &group_buf),
			ike_info->ike_dh_group->group);
}

void alg_info_snprint_ike_info(char *buf, size_t buflen,
			       struct ike_info *ike_info)
{
	snprint_ike_info(buf, buflen, ike_info, FALSE);
}

void alg_info_snprint_ike(char *buf, size_t buflen,
			  struct alg_info_ike *alg_info)
{
	char *ptr = buf;
	const char *sep = "";

	FOR_EACH_IKE_INFO(alg_info, ike_info) {
		if (ike_info->ike_encrypt != NULL &&
		    ike_info->ike_prf != NULL &&
		    ike_info->ike_dh_group != NULL) {
			if (strlen(sep) >= buflen) {
				DBG_log("alg_info_snprint_ike: buffer too short for separator");
				break;
			}
			strcpy(ptr, sep);
			ptr += strlen(sep);
			buflen -= strlen(sep);
			int ret = snprint_ike_info(ptr, buflen, ike_info, TRUE);
			if (ret < 0 || (size_t)ret >= buflen) {
				DBG_log("alg_info_snprint_ike: buffer too short for snprintf");
				break;
			}
			ptr += ret;
			buflen -= ret;
			sep = ", ";
		}
	}
}

/* snprint already parsed transform list (alg_info) */

void alg_info_ike_snprint(char *buf, size_t buflen,
			  const struct alg_info_ike *alg_info_ike)
{
	char *ptr = buf;
	char *be = buf + buflen;

	passert(buflen > 0);

	const char *sep = "";
	FOR_EACH_IKE_INFO(alg_info_ike, ike_info) {
		snprintf(ptr, be - ptr,
			 "%s%s(%d)_%03d-%s(%d)-%s(%d)",
			 sep, enum_short_name(&oakley_enc_names,
					      ike_info->ike_encrypt->common.ikev1_oakley_id),
			 ike_info->ike_encrypt->common.ikev1_oakley_id,
			 (int)ike_info->ike_eklen,
			 enum_short_name(&oakley_hash_names,
					 ike_info->ike_prf->common.ikev1_oakley_id),
			 ike_info->ike_prf->common.ikev1_oakley_id,
			 enum_short_name(&oakley_group_names,
					 ike_info->ike_dh_group->group),
			 ike_info->ike_dh_group->group
			);
		ptr += strlen(ptr);
		sep = ", ";
	}
}
