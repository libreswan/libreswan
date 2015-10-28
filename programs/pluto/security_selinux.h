/* Libreswan Selinux APIs
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
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

#ifndef _SECURITY_SELINUX_H
#define _SECURITY_SELINUX_H

#include <selinux/selinux.h>
#include <selinux/avc.h>
#include <selinux/context.h>

void init_avc(void);
int within_range(security_context_t sl, security_context_t range);

#endif /* _SECURITY_SELINUX_H */
