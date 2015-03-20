/* Libreswan netkey init/cleanup (netkey.h)
 * Copyright (C) 2004 Xelerance Corporation
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

#ifndef _STARTER_NETKEY_H_
#define _STARTER_NETKEY_H_

void starter_netkey_cleanup(void);
void starter_netkey_clear(void);
int starter_netkey_init(void);
int starter_netkey_set_config(struct starter_config *);

#endif /* _STARTER_NETKEY_H_ */

