/*
 * Parse IKEv1 CAVP test functions, for libreswan
 *
 * Copyright (C) 2015,2017 Andrew Cagney <cagney@gnu.org>
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

#include <pk11pub.h>
#include "chunk.h"

struct prf_desc;

extern struct cavp cavp_ikev2;

void cavp_acvp_ikev2(const struct prf_desc *prf,
		     chunk_t ni, chunk_t nr,
		     PK11SymKey *g_ir, PK11SymKey *g_ir_new,
		     chunk_t spi_i, chunk_t spi_r,
		     signed long sizeof_ike_sa_dkm,
		     signed long sizeof_child_sa_dkm);
