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

#ifndef LABELED_IPSEC_H
#define LABELED_IPSEC_H

#include <stdbool.h>

#include "shunk.h"
#include "chunk.h"

struct logger;

/*
 * Security Label Context representations.
 *
 * While security label length usually does not exceed 256,
 * there have been requests (rhbz#1154784) for using larger
 * labels. The maximum label size is PAGE_SIZE (4096 on a
 * x86_64, but 64kb on ppc64). However, this label has to fit
 * inside a netlink message whose maximum size is 32KiB.
 * For now we picked the somewhat arbitrary size of 4096.
 */

#define MAX_SECCTX_LEN 4096	/* including '\0'*/

err_t vet_seclabel(shunk_t sl);

void init_labeled_ipsec(const struct logger *logger);

bool sec_label_within_range(const char *source, shunk_t label, chunk_t range,
			    const struct logger *logger);

#endif
