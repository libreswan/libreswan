/* CAVP algorithm, for libreswan
 *
 * Copyright (C) 2018, Andrew Cagney
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

#include <stdbool.h>

struct acvp {
	const char *g_ir;
	const char *g_ir_new;
	const char *ni;
	const char *nr;
	const char *spi_i;
	const char *spi_r;
	const char *dkm_length;
	const char *prf;
	bool use;
};

void acvp(struct acvp *);
