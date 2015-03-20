/*

   Copyright (c) 2003,2004 Jeremy Kerr & Rusty Russell

   This file is part of nfsim.

   nfsim is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   nfsim is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with nfsim; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __HAVE_LOG_H
#define __HAVE_LOG_H
#include <stdbool.h>

enum log_type {
	LOG_ALWAYS      = 0x00,
	LOG_KERNEL      = 0x01,
	LOG_UI          = 0x02,
	LOG_ROUTE       = 0x04,
	LOG_PROTOCOL    = 0x08,
	LOG_PACKET      = 0x10,
	LOG_USERSPACE   = 0x20,
	LOG_HOOK        = 0x40,
};

/* Adds a \n for convenient logging.  Returns true if it was expected. */
bool nfsim_log(enum log_type type, const char *format, ...);
/* Builds up buffer and prints out line at a time. */
void nfsim_log_partial(enum log_type type, char *buf, unsigned bufsize,
		       const char *format, ...);

int log_describe_packets(void);

#if 0
#define printk(...) log(LOG_KERNEL, ## __VA_ARGS__)
#endif

void printk(const char *format, ...);
extern int printk_ratelimit(void);

#undef SKB_SEQUENCE_NUMBERS

#if 0
#ifdef SKB_SEQUENCE_NUMBERS
#define log_packet(sk, f, ...) nfsim_log(LOG_PACKET, "[%03d] " f, (sk)->seq, \
					 ## __VA_ARGS__)
#define log_route(sk, f, ...) nfsim_log(LOG_ROUTE, "[%03d] " f, (sk)->seq, \
					## __VA_ARGS__)
#else
#define log_packet(sk, f, ...) nfsim_log(LOG_PACKET, f, ## __VA_ARGS__)
#define log_route(sk, f, ...) nfsim_log(LOG_ROUTE, f, ## __VA_ARGS__)
#endif
#else
#define log_packet(sk, f, ...)
#define log_route(sk, f, ...)
#define nfsim_log(lv, fmt, ...)
#endif

#define p_log(...) nfsim_log(LOG_PACKET, __VA_ARGS__)
#define u_log(...) nfsim_log(LOG_UI, __VA_ARGS__)

#endif /* __HAVE_LOG_H */
