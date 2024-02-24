/* IP-TFS, for libreswan
 *
 * Copyright (C) 2023 Antony Antony
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

#ifndef IPTFS_H
#define IPTFS_H

#include <stdbool.h>

/* RFC 9347 AGGFRAG mode aka IP-TFS or iptfs */
struct pluto_iptfs {
	uint32_t out_size; 	  /* XFRMA_IPTFS_PKT_SIZE */
	uint32_t out_max_delay;   /* XFRMA_IPTFS_INIT_DELAY */
	uint32_t out_queue;	  /* XFRMA_IPTFS_MAX_QSIZE */
	uint32_t in_rewin; 	  /* XFRMA_IPTFS_REORDER_WINDOW */
	uint32_t in_drop_time;	  /* XFRMA_IPTFS_DROP_TIME */
	enum yn_options out_frag; /* XFRMA_IPTFS_DROP_TIME */
};

#endif
