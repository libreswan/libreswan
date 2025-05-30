/* lock file, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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
 *
 */

#ifndef LOCKFILE_H
#define LOCKFILE_H

#include <stdbool.h>

struct config_setup;
struct logger;

int create_lock_file(const struct config_setup *oco, bool fork_desired, struct logger *logger);
bool fill_and_close_lock_file(int *lockfd, pid_t pid);
void delete_lock_file(void);

#endif /* _DEFS_H */
