/*
 * IKE modular algorithm handling interface, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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

#ifndef IKE_ALG_IPCOMP_H
#define IKE_ALG_IPCOMP_H

struct ipcomp_desc;

extern const struct ipcomp_desc ike_alg_ipcomp_deflate;
extern const struct ipcomp_desc ike_alg_ipcomp_lzs;
extern const struct ipcomp_desc ike_alg_ipcomp_lzjh;

#endif
