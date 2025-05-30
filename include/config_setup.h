/* ipsec.conf's config setup for Libreswan
 *
 * Copyright (C) 2025  Andrew Cagney
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

#ifndef CONFIG_SETUP_H
#define CONFIG_SETUP_H

#include <stdint.h>

#include "lset.h"

enum keywords;
struct logger;

struct config_setup *config_setup_singleton(void);
void free_config_setup(void);

void config_setup_string(enum keywords kw, const char *string);
void config_setup_option(enum keywords kw, uintmax_t option);

const char *config_setup_ipsecdir(void);
const char *config_setup_secretsfile(void);
const char *config_setup_nssdir(void);
const char *config_setup_dumpdir(void);

lset_t config_setup_debugging(struct logger *logger);

#endif
