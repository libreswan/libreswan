/* IKEv2 IKE_INTERMEDIATE exchange, for libreswan
 *
 * Copyright (C) 2021   Andrew Cagney <cagney@gnu.org>
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

#ifndef IKEV2_IKE_INTERMEDIATE_H
#define IKEV2_IKE_INTERMEDIATE_H

struct ike_sa;

const struct kem_desc *next_additional_kem_desc(struct ike_sa *ike);

struct ikev2_ike_intermediate_exchange {
	bool required;
	struct {
		const struct kem_desc *kem;
		enum ikev2_trans_type type;
	} addke;
	bool ppk;
};

struct ikev2_ike_intermediate_exchange current_ikev2_ike_intermediate_exchange(struct ike_sa *ike);

extern const struct v2_exchange v2_IKE_INTERMEDIATE_exchange;

#endif
