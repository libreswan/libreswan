/* CAVP algorithm, for libreswan
 *
 * Copyright (C) 2018, Andrew Cagney
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

#include <stdbool.h>

struct cavp;

bool acvp_option(const struct cavp *cavp, const char *arg, const char *param);

#define ACVP_TCID "tcId"
#define ACVP_DKM_OPTION "derivedKeyingMaterialLength"
#define ACVP_PRF_OPTION "hashAlg"

