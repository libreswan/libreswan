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
#define S_RULE_ADD(x) seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(x), 0)
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
	rc |= S_RULE_ADD(read);
	if (main)
		rc |= S_RULE_ADD(wait4);

	/* needed for pluto and updown, not helpers */
	if (main) {
		rc |= S_RULE_ADD(accept);
		rc |= S_RULE_ADD(access);
		rc |= S_RULE_ADD(bind);
		rc |= S_RULE_ADD(brk);
		rc |= S_RULE_ADD(chdir);
		rc |= S_RULE_ADD(clock_gettime);
		rc |= S_RULE_ADD(clone);
		rc |= S_RULE_ADD(close);
		rc |= S_RULE_ADD(connect);
		rc |= S_RULE_ADD(dup);
		rc |= S_RULE_ADD(dup2);
		rc |= S_RULE_ADD(epoll_create);
		rc |= S_RULE_ADD(epoll_ctl);
		rc |= S_RULE_ADD(epoll_wait);
		rc |= S_RULE_ADD(epoll_pwait);
		rc |= S_RULE_ADD(execve);
		rc |= S_RULE_ADD(faccessat);
		rc |= S_RULE_ADD(fadvise64);
		rc |= S_RULE_ADD(fcntl);
		rc |= S_RULE_ADD(getcwd);
		rc |= S_RULE_ADD(getdents);
		rc |= S_RULE_ADD(getegid);
		rc |= S_RULE_ADD(geteuid);
		rc |= S_RULE_ADD(getgid);
		rc |= S_RULE_ADD(getgroups);
		rc |= S_RULE_ADD(getpgrp);
		rc |= S_RULE_ADD(getpid);
		rc |= S_RULE_ADD(getppid);
		rc |= S_RULE_ADD(getrlimit);
		rc |= S_RULE_ADD(getsockname);
		rc |= S_RULE_ADD(getuid);
		rc |= S_RULE_ADD(ioctl);
		rc |= S_RULE_ADD(mkdir);
		rc |= S_RULE_ADD(munmap);
		rc |= S_RULE_ADD(newfstatat);
		rc |= S_RULE_ADD(open);
		rc |= S_RULE_ADD(openat);
		rc |= S_RULE_ADD(pipe);
		rc |= S_RULE_ADD(pipe2);
		rc |= S_RULE_ADD(poll);
		rc |= S_RULE_ADD(prctl);
		rc |= S_RULE_ADD(pread64);
		rc |= S_RULE_ADD(prlimit64);
		rc |= S_RULE_ADD(readlink);
		rc |= S_RULE_ADD(recvfrom);
		rc |= S_RULE_ADD(recvmsg);
		rc |= S_RULE_ADD(select);
		rc |= S_RULE_ADD(sendmsg);
		rc |= S_RULE_ADD(set_robust_list);
		rc |= S_RULE_ADD(setsockopt);
		rc |= S_RULE_ADD(socket);
		rc |= S_RULE_ADD(socketpair);
		rc |= S_RULE_ADD(sysinfo);
		rc |= S_RULE_ADD(uname);
		rc |= S_RULE_ADD(unlink);
		rc |= S_RULE_ADD(unlinkat);
	}

	/* common to pluto and helpers */

	rc |= S_RULE_ADD(arch_prctl);
	rc |= S_RULE_ADD(gettid);
	rc |= S_RULE_ADD(gettimeofday);
	rc |= S_RULE_ADD(fstat);
	rc |= S_RULE_ADD(futex);
	rc |= S_RULE_ADD(lseek);
	rc |= S_RULE_ADD(mmap);
	rc |= S_RULE_ADD(mprotect);
	rc |= S_RULE_ADD(nanosleep);
	rc |= S_RULE_ADD(rt_sigaction);
	rc |= S_RULE_ADD(rt_sigprocmask);
	rc |= S_RULE_ADD(rt_sigreturn);
	rc |= S_RULE_ADD(sched_setparam);
	rc |= S_RULE_ADD(sendto);
	rc |= S_RULE_ADD(set_tid_address);
	rc |= S_RULE_ADD(stat);
	rc |= S_RULE_ADD(statfs);
	rc |= S_RULE_ADD(write);
	rc |= S_RULE_ADD(exit_group);

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
#undef S_RULE_ADD
}

void init_seccomp_main(uint32_t def_action)
{
	init_seccomp(def_action, TRUE);
}

void init_seccomp_cryptohelper(uint32_t def_action)
{
	init_seccomp(def_action, FALSE);
}

