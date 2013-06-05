/* FreeS/WAN Pluto launcher (pluto.h)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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

#ifndef _STARTER_PLUTO_H_
#define _STARTER_PLUTO_H_

#define PLUTO_RESTART_DELAY    5

void starter_pluto_sigchild(pid_t pid);
pid_t starter_pluto_pid(void);
int starter_stop_pluto(void);
int starter_start_pluto(struct starter_config *cfg, int debug);

#endif /* _STARTER_PLUTO_H_ */

