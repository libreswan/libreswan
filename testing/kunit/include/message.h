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

#ifndef __HAVE_MESSAGE_H
#define __HAVE_MESSAGE_H

#include "core.h"
#include "nfsockopt.h"

void message_init(void);
void message_cleanup(void);

int copy_to_user(void *to, const void *from, unsigned long n);
int copy_from_user(void *to, const void *from, unsigned long n);

/* Returns talloced output of child (if running). */
char *wait_for_output(void);

/* We want to fork: split other program */
void fork_other_program(void);

/* Start a program */
void start_program(const char *name, int argc, char *argv[]);
int end_program(const char *name);

/* Trace system calls? */
extern bool strace;
#endif /* __HAVE_MESSAGE_H */
