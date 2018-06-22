/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2017 Andrew Cagney
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
#include <stdint.h>
#include <limits.h>

#include "constants.h"  /* some how sucks in u_int8_t for pfkeyv2.h */
#include "libreswan/pfkeyv2.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "alg_info.h"
#include "alg_byname.h"
#include "kernel_alg.h"
#include "lswfips.h"

#include "ike_alg.h"
#include "ike_alg_none.h"
#include "ike_alg_aes.h"
#include "ike_alg_sha1.h"

/*
 * Add ESP alg info _with_ logic (policy):
 */
static bool esp_proposal_ok(const struct proposal_parser *parser,
			    const struct proposal_info *proposal)
{
	if (!proposal_aead_none_ok(parser, proposal)) {
		if (!impair_proposal_errors(parser)) {
			return false;
		}
	}

	impaired_passert(PROPOSAL_PARSER, proposal->encrypt != NULL);
	impaired_passert(PROPOSAL_PARSER, proposal->prf == NULL);
	impaired_passert(PROPOSAL_PARSER, proposal->integ != NULL);
	return true;
}

static const struct ike_alg *default_esp_encrypt[] = {
	&ike_alg_encrypt_aes_cbc.common,
	NULL,
};

static const struct ike_alg *default_esp_integ[] = {
	&ike_alg_integ_sha1.common,
	NULL,
};

const struct proposal_defaults esp_defaults = {
	.encrypt = default_esp_encrypt,
	.integ = default_esp_integ,
};

const struct proposal_protocol esp_proposal_protocol = {
	.name = "ESP",
	.ikev1_alg_id = IKEv1_ESP_ID,
	.protoid = PROTO_IPSEC_ESP,
	.ikev1_defaults = &esp_defaults,
	.ikev2_defaults = &esp_defaults,
	.proposal_ok = esp_proposal_ok,
	.encrypt_alg_byname = encrypt_alg_byname,
	.integ_alg_byname = integ_alg_byname,
	.dh_alg_byname = dh_alg_byname,
};

/*
 * ??? why is this called _ah_ when almost everything refers to esp?
 * XXX: Because it is parsing an "ah" line which requires a different
 * parser configuration - encryption isn't allowed.
 *
 * ??? the only difference between this and alg_info_esp is in two
 * parameters to alg_info_parse_str.  XXX: Things are down to just the
 * last parameter being different - but that is critical as it
 * determines what is allowed.
 *
 * XXX: On the other hand, since "struct ike_info" and "struct
 * esp_info" are effectively the same, they can be merged.  Doing
 * that, would eliminate the AH using ESP confusion.
 */

/* This function is tested in testing/algparse/algparse.c */
struct alg_info_esp *alg_info_esp_create_from_str(const struct proposal_policy *policy,
						  const char *alg_str,
						  char *err_buf, size_t err_buf_len)
{
	shunk_t string = shunk1(alg_str);
	const struct proposal_parser parser = proposal_parser(policy,
							      &esp_proposal_protocol,
							      err_buf, err_buf_len);

	/*
	 * alg_info storage should be sized dynamically
	 * but this may require two passes to know
	 * transform count in advance.
	 */
	struct alg_info_esp *alg_info_esp = alloc_thing(struct alg_info_esp,
							"alg_info_esp");
	if (!alg_info_parse_str(&parser, &alg_info_esp->ai, string)) {
		passert(err_buf[0] != '\0');
		alg_info_free(&alg_info_esp->ai);
		return NULL;
	}

	if (!alg_info_pfs_vs_dh_check(&parser, alg_info_esp)) {
		passert(err_buf[0] != '\0');
		alg_info_free(&alg_info_esp->ai);
		return NULL;
	}

	return alg_info_esp;
}
