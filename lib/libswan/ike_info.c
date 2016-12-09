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
