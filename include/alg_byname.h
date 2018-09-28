/*
 * Algorithm parser name lookup, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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

#ifndef ALG_BYNAME_H
#define ALG_BYNAME_H

#include <shunk.h>

struct ike_alg;
struct proposal_parser;

/*
 * Filter function to accept/reject an algorithm.
 *
 * NAME should contain the string used to find ALG.  It, rather than
 * ALG->NAME, is used when reporting errors into ERR_BUF so that the
 * messages better align with the input files.
 */

bool alg_byname_ok(const struct proposal_parser *parser,
		   const struct ike_alg *alg, shunk_t print_name);

/*
 * Helper functions to implement most of the lookup.
 */

const struct ike_alg *encrypt_alg_byname(const struct proposal_parser *parser,
					 shunk_t name, size_t key_bit_length,
					 shunk_t print_name);

const struct ike_alg *prf_alg_byname(const struct proposal_parser *parser,
				     shunk_t name, size_t key_bit_length,
				     shunk_t print_name);

const struct ike_alg *integ_alg_byname(const struct proposal_parser *parser,
				       shunk_t name, size_t key_bit_length,
				       shunk_t print_name);

const struct ike_alg *dh_alg_byname(const struct proposal_parser *parser,
				    shunk_t name, size_t key_bit_length,
				    shunk_t print_name);

#endif
