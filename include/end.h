/* information about connections between hosts and clients
 *
 * Copyright (C) 2024 Nupur Agrawal <nupur202000@gmail.com>
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

#ifndef END_H
#define END_H

enum end { LEFT_END, RIGHT_END, };
#define END_ROOF 2

extern const struct enum_names end_names; /* LEFT_END RIGHT_END */
extern const struct enum_names end_stories; /* left right */

#endif
