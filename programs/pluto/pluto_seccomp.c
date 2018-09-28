/*
 * seccomp support for Linux kernel using seccomp
 *
 * Copyright (c) 2016 Paul Wouters <pwouters@redhat.com>
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

#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "defs.h"
#include "lswlog.h"

#define LSW_SECCOMP_EXIT_FAIL PLUTO_EXIT_SECCOMP_FAIL
#include "lswseccomp.h"

#include "pluto_seccomp.h"

/* helper rules must be a sub-set of main rules */

static void init_seccomp(uint32_t def_action, bool main)
{
	scmp_filter_ctx ctx = seccomp_init(def_action);
	if (ctx == NULL) {
			libreswan_log("seccomp_init() failed!");
			exit_pluto(PLUTO_EXIT_SECCOMP_FAIL);
	}

	/*
	 * read() and wait4() take the vast majority of syscall time
	 * So we place these at the head of the list for performance
	 * example strace -c -f output if pluto:
	 *
	 * % time     seconds  usecs/call     calls    errors syscall
	 * ------ ----------- ----------- --------- --------- ----------------
	 *   73.70   41.137940        1202     34232       343 read
	 *   20.77   11.595734        3549      3267      1176 wait4
	 *    1.47    0.819570         709      1156           epoll_wait
	 *    0.60    0.332147           1    319902           rt_sigprocmask
	 *    0.55    0.307552           5     61578           mmap
	 *    0.41    0.230820           6     37788      2877 open
	 *    [...]
	 */
	LSW_SECCOMP_ADD(ctx, read);
	if (main) {
		LSW_SECCOMP_ADD(ctx, wait4);
	}

#ifdef USE_EFENCE
	LSW_SECCOMP_ADD(ctx, madvise);
#endif

	/* needed for pluto and updown, not helpers */
	if (main) {
		LSW_SECCOMP_ADD(ctx, accept);
		LSW_SECCOMP_ADD(ctx, access);
		LSW_SECCOMP_ADD(ctx, bind);
		LSW_SECCOMP_ADD(ctx, brk);
		LSW_SECCOMP_ADD(ctx, chdir);
		LSW_SECCOMP_ADD(ctx, clone);
		LSW_SECCOMP_ADD(ctx, close);
		LSW_SECCOMP_ADD(ctx, connect);
		LSW_SECCOMP_ADD(ctx, dup);
		LSW_SECCOMP_ADD(ctx, dup2);
		LSW_SECCOMP_ADD(ctx, epoll_create);
		LSW_SECCOMP_ADD(ctx, epoll_ctl);
		LSW_SECCOMP_ADD(ctx, epoll_wait);
		LSW_SECCOMP_ADD(ctx, epoll_pwait);
		LSW_SECCOMP_ADD(ctx, execve);
		LSW_SECCOMP_ADD(ctx, faccessat);
		LSW_SECCOMP_ADD(ctx, fadvise64);
		LSW_SECCOMP_ADD(ctx, fcntl);
		LSW_SECCOMP_ADD(ctx, getcwd);
		LSW_SECCOMP_ADD(ctx, getdents);
		LSW_SECCOMP_ADD(ctx, getegid);
		LSW_SECCOMP_ADD(ctx, geteuid);
		LSW_SECCOMP_ADD(ctx, getgid);
		LSW_SECCOMP_ADD(ctx, getgroups);
		LSW_SECCOMP_ADD(ctx, getpgrp);
		LSW_SECCOMP_ADD(ctx, getpid);
		LSW_SECCOMP_ADD(ctx, getppid);
		LSW_SECCOMP_ADD(ctx, getrlimit);
		LSW_SECCOMP_ADD(ctx, getsockname);
		LSW_SECCOMP_ADD(ctx, getsockopt);
		LSW_SECCOMP_ADD(ctx, getuid);
		LSW_SECCOMP_ADD(ctx, ioctl);
		LSW_SECCOMP_ADD(ctx, lstat);
		LSW_SECCOMP_ADD(ctx, mkdir);
		LSW_SECCOMP_ADD(ctx, munmap);
		LSW_SECCOMP_ADD(ctx, newfstatat);
		LSW_SECCOMP_ADD(ctx, open);
		LSW_SECCOMP_ADD(ctx, openat);
		LSW_SECCOMP_ADD(ctx, pipe);
		LSW_SECCOMP_ADD(ctx, pipe2);
		LSW_SECCOMP_ADD(ctx, poll);
		LSW_SECCOMP_ADD(ctx, prctl);
		LSW_SECCOMP_ADD(ctx, pread64);
		LSW_SECCOMP_ADD(ctx, prlimit64);
		LSW_SECCOMP_ADD(ctx, readlink);
		LSW_SECCOMP_ADD(ctx, recvfrom);
		LSW_SECCOMP_ADD(ctx, recvmsg);
		LSW_SECCOMP_ADD(ctx, select);
		LSW_SECCOMP_ADD(ctx, sendmsg);
		LSW_SECCOMP_ADD(ctx, set_robust_list);
		LSW_SECCOMP_ADD(ctx, setsockopt);
		LSW_SECCOMP_ADD(ctx, socket);
		LSW_SECCOMP_ADD(ctx, socketcall);
		LSW_SECCOMP_ADD(ctx, socketpair);
		LSW_SECCOMP_ADD(ctx, sysinfo);
		LSW_SECCOMP_ADD(ctx, uname);
		LSW_SECCOMP_ADD(ctx, unlink);
		LSW_SECCOMP_ADD(ctx, unlinkat);
	}

	/* common to pluto and helpers */

	LSW_SECCOMP_ADD(ctx, arch_prctl);
	LSW_SECCOMP_ADD(ctx, exit_group);
	LSW_SECCOMP_ADD(ctx, gettid);
	LSW_SECCOMP_ADD(ctx, gettimeofday);
	LSW_SECCOMP_ADD(ctx, fstat);
	LSW_SECCOMP_ADD(ctx, futex);
	LSW_SECCOMP_ADD(ctx, lseek);
	LSW_SECCOMP_ADD(ctx, mmap);
	LSW_SECCOMP_ADD(ctx, mprotect);
	LSW_SECCOMP_ADD(ctx, nanosleep);
	LSW_SECCOMP_ADD(ctx, rt_sigaction);
	LSW_SECCOMP_ADD(ctx, rt_sigprocmask);
	LSW_SECCOMP_ADD(ctx, rt_sigreturn);
	LSW_SECCOMP_ADD(ctx, sched_setparam);
	LSW_SECCOMP_ADD(ctx, sendto);
	LSW_SECCOMP_ADD(ctx, set_tid_address);
	LSW_SECCOMP_ADD(ctx, sigaltstack);
	LSW_SECCOMP_ADD(ctx, sigreturn);
	LSW_SECCOMP_ADD(ctx, stat);
	LSW_SECCOMP_ADD(ctx, statfs);
	LSW_SECCOMP_ADD(ctx, clock_gettime);
	LSW_SECCOMP_ADD(ctx, waitpid);
	LSW_SECCOMP_ADD(ctx, write);

	int rc = seccomp_load(ctx);
	if (rc < 0) {
		LOG_ERRNO(-rc, "seccomp_load() failed!");
		seccomp_release(ctx);
		exit_pluto(PLUTO_EXIT_SECCOMP_FAIL);
	}

	libreswan_log("seccomp security enabled");
}

void init_seccomp_main(uint32_t def_action)
{
	init_seccomp(def_action, TRUE);
}

void init_seccomp_cryptohelper(uint32_t def_action)
{
	init_seccomp(def_action, FALSE);
}

