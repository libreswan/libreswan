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

#ifndef __HAVE_NFSOCKOPT_H
#define __HAVE_NFSOCKOPT_H

/* TODO: use the proper values insetad */
#define SYS_GETSOCKOPT 1
#define SYS_SETSOCKOPT 2

#define KOP_COPY_TO_USER   1
#define KOP_COPY_FROM_USER 2

#define MAX_MESSAGE_ARGS 4

struct nf_userspace_message {
	enum {
		UM_SYSCALL,
		UM_KERNELOP,
	} type;

	/* operation. in the case of syscalls, this
	   is the SYS_<syscall> number */
	int opcode;

	/* length of any data following this header */
	int len;

	/* syscall/kernelop arguments */
	unsigned long args[MAX_MESSAGE_ARGS];

	/* return val of the syscall/kernelop */
	int retval;
};

#endif /* __HAVE_NFSOCKOPT_H */
