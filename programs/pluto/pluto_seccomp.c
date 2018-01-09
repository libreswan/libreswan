/*
 * seccomp support for Linux kernel using seccomp
 *
 * Copyright (c) 2016 Paul Wouters <pwouters@redhat.com>
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

#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "defs.h"
#include "lswlog.h"

#include <errno.h>
#include "pluto_seccomp.h"

/* helper rules must be a sub-set of main rules */

static void init_seccomp(uint32_t def_action, bool main)
{
	scmp_filter_ctx ctx = seccomp_init(def_action);
	int rc = 0;

	if (ctx == NULL) {
			libreswan_log("seccomp_init() failed!");
			exit_pluto(PLUTO_EXIT_SECCOMP_FAIL);
	}

	/*
	 * read() and wait4() take the vast majority of syscall time
	 * So we place these at the head of the list for performance
	 * example strace -c -f output if pluto:
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

	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	if (main)
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(wait4), 0);

	if (main) {
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(accept), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(access), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(bind), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(brk), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(chdir), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(clock_gettime), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(clone), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(close), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(connect), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(dup), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(dup2), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(epoll_create), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(epoll_ctl), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(epoll_wait), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(execve), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(exit_group), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(faccessat), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(fadvise64), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(fcntl), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(getcwd), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(getdents), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(getegid), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(geteuid), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(getgid), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(getgroups), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(getpgrp), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(getpid), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(getppid), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(getrlimit), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(getsockname), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(getuid), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(ioctl), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(mkdir), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(munmap), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(newfstatat), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(open), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(openat), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(pipe), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(pipe2), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(poll), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(readlink), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(recvfrom), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(recvmsg), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(select), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(sendmsg), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(sendto), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(set_robust_list), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(setsockopt), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(socket), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(uname), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(unlink), 0);
		rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				SCMP_SYS(unlinkat), 0);
	}

	/* common to main and helpers */
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(arch_prctl), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(gettid), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(gettimeofday), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(fstat), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(futex), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(lseek), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(mmap), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(mprotect), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(nanosleep), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(rt_sigaction), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(rt_sigprocmask), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(rt_sigreturn), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(sched_setparam), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(set_tid_address), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(stat), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(statfs), 0);
	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
			SCMP_SYS(write), 0);

	if (rc != 0) {
		libreswan_log("seccomp_rule_add() failed!");
        	seccomp_release(ctx);
		exit_pluto(PLUTO_EXIT_SECCOMP_FAIL);
	}

	rc = seccomp_load(ctx);
	if (rc < 0) {
		libreswan_log("seccomp_load() failed!");
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

