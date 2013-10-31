/*
 * @(#) Definitions relevant to the IPSEC <> radij tree interfacing
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
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
 *
 */

#ifndef _IPSEC_RADIJ_H

#include <libreswan.h>

extern int ipsec_walk(char *);
extern int ipsec_rj_walker_show(struct radij_node *, void *);
extern int ipsec_rj_walker_delete(struct radij_node *, void *);

extern struct radij_node_head *rnh;
extern spinlock_t eroute_lock;

extern struct eroute * ipsec_findroute(struct sockaddr_encap *);

#define O1(x) (int)(((x) >> 24) & 0xff)
#define O2(x) (int)(((x) >> 16) & 0xff)
#define O3(x) (int)(((x) >> 8) & 0xff)
#define O4(x) (int)(((x)) & 0xff)

extern int debug_radij;
extern void rj_dumptrees(void);

#define DB_RJ_DUMPTREES 0x0001
#define DB_RJ_FINDROUTE 0x0002

#define _IPSEC_RADIJ_H
#endif

