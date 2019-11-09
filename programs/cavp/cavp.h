/* CAVP algorithm, for libreswan
 *
 * Copyright (C) 2015-2016,2018, Andrew Cagney
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

struct cavp_entry;

struct cavp {
	const char *alias;
	const char *description;
	void (*print_config)(void);
	void (*run_test)(void);
	const struct cavp_entry *config;
	const struct cavp_entry *data;
	const char *match[];
};
