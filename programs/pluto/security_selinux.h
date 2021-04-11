/* Libreswan Selinux APIs
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2020 Richard Haines <richard_c_haines@btinternet.com>
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

#ifndef _SECURITY_SELINUX_H
#define _SECURITY_SELINUX_H

#include "shunk.h"
#include "chunk.h"

err_t vet_seclabel(shunk_t sl);

#ifdef HAVE_LABELED_IPSEC

#include <stdbool.h>

#include <selinux/selinux.h>

#ifdef HAVE_OLD_SELINUX
#include <selinux/avc.h>
#include <selinux/context.h>
#endif

struct logger;

void init_selinux(struct logger *logger);

bool se_label_match(shunk_t a, chunk_t b, struct logger *logger);

#endif /* HAVE_LABELED_IPSEC */

#endif /* _SECURITY_SELINUX_H */
