/*
 * Algorithm parser name lookup, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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

struct parser_param;
struct parser_policy;

/*
 * Helper functions to implement most of the lookup.
 */

const struct ike_alg *encrypt_alg_byname(const struct parser_param *param,
					 const struct parser_policy *const policy,
					 char *err_buf, size_t err_buf_len,
					 const char *name, size_t key_bit_length);

const struct ike_alg *prf_alg_byname(const struct parser_param *param,
				     const struct parser_policy *const policy,
				     char *err_buf, size_t err_buf_len,
				     const char *name, size_t key_bit_length);

const struct ike_alg *integ_alg_byname(const struct parser_param *param,
				       const struct parser_policy *const policy,
				       char *err_buf, size_t err_buf_len,
				       const char *name, size_t key_bit_length);

const struct ike_alg *dh_alg_byname(const struct parser_param *param,
				    const struct parser_policy *const policy,
				    char *err_buf, size_t err_buf_len,
				    const char *name, size_t key_bit_length);
