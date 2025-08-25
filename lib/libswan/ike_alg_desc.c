/*
 * IKE modular algorithm handling interface, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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
 */

#include <stdlib.h>

#include "constants.h"
#include "lswlog.h"

#include "ike_alg.h"

/*
 * Casts
 */

const struct hash_desc *hash_desc(const struct ike_alg *alg)
{
	passert(alg == NULL || alg->type == IKE_ALG_HASH);
	return (const struct hash_desc *)alg;
}

const struct prf_desc *prf_desc(const struct ike_alg *alg)
{
	passert(alg == NULL || alg->type == IKE_ALG_PRF);
	return (const struct prf_desc *)alg;
}

const struct integ_desc *integ_desc(const struct ike_alg *alg)
{
	passert(alg == NULL || alg->type == IKE_ALG_INTEG);
	return (const struct integ_desc *)alg;
}

const struct encrypt_desc *encrypt_desc(const struct ike_alg *alg)
{
	passert(alg == NULL || alg->type == IKE_ALG_ENCRYPT);
	return (const struct encrypt_desc *)alg;
}

const struct kem_desc *kem_desc(const struct ike_alg *alg)
{
	passert(alg == NULL || alg->type == IKE_ALG_KEM);
	return (const struct kem_desc *)alg;
}

const struct ipcomp_desc *ipcomp_desc(const struct ike_alg *alg)
{
	passert(alg == NULL || alg->type == IKE_ALG_IPCOMP);
	return (const struct ipcomp_desc *)alg;
}
