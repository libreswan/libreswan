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
#include "deltatime.h"

enum yn_options;
enum keywords;
struct logger;

struct config_setup *config_setup_singleton(void);
void free_config_setup(void);

void update_setup_string(enum keywords kw, const char *string);
void update_setup_yn(enum keywords kw, enum yn_options yn);
void update_setup_deltatime(enum keywords kw, deltatime_t deltatime);
void update_setup_option(enum keywords kw, uintmax_t option);

const char *config_setup_string(const struct config_setup *setup, enum keywords field);
const char *config_setup_string_or_unset(const struct config_setup *setup, enum keywords field, const char *unset);
bool config_setup_yn(const struct config_setup *setup, enum keywords field);
deltatime_t config_setup_deltatime(const struct config_setup *setup, enum keywords field);
uintmax_t config_setup_option(const struct config_setup *setup, enum keywords field);

const char *config_setup_ipsecdir(void);
const char *config_setup_secretsfile(void);
const char *config_setup_nssdir(void);
const char *config_setup_dumpdir(void);
const char *config_setup_vendorid(void);
lset_t config_setup_debugging(struct logger *logger);

/*
 * When FIELD in SETUP is set, extract the value saving it in TARGET.
 *
 * Return TRUE when value was extracted (caller may then proceed to do
 * further validation).
 *
 * Note: An empty string, such as dnssec-anchors=, is turned into
 * NULL.
 */

bool extract_setup_string(const char **target,
			  const struct config_setup *setup,
			  enum keywords field);

bool extract_setup_yn(bool *target,
		      const struct config_setup *setup,
		      enum keywords field);
bool extract_setup_deltatime(deltatime_t *target,
			     const struct config_setup *setup,
			     enum keywords field);

#endif
