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

#include "lswseccomp.h"
#include "sparse_names.h"

#include "defs.h"
#include "log.h"
#include "pluto_seccomp.h"
#include "show.h"

#ifdef USE_SECCOMP
enum seccomp_mode pluto_seccomp_mode = SECCOMP_DISABLED;
#endif

/* helper rules must be a sub-set of main rules */

static void init_seccomp(uint32_t def_action, bool main, struct logger *logger)
{
	scmp_filter_ctx ctx = seccomp_init(def_action);
	if (ctx == NULL) {
		/* no error code!?! */
		fatal(PLUTO_EXIT_SECCOMP_FAIL, logger, "seccomp_init() failed!");
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
	LSW_SECCOMP_ADD(read);
	if (main) {
		LSW_SECCOMP_ADD(wait4);
	}

	/* needed for pluto and updown, not helpers */
	if (main) {
		LSW_SECCOMP_ADD(_llseek);
		LSW_SECCOMP_ADD(accept);
		LSW_SECCOMP_ADD(access);
		LSW_SECCOMP_ADD(bind);
		LSW_SECCOMP_ADD(brk);
		LSW_SECCOMP_ADD(chdir);
		LSW_SECCOMP_ADD(clone);
#if SCMP_SYS(clone3)
		LSW_SECCOMP_ADD(clone3);
#endif
		LSW_SECCOMP_ADD(connect);
		LSW_SECCOMP_ADD(copy_file_range);
		LSW_SECCOMP_ADD(dup);
		LSW_SECCOMP_ADD(dup2);
		LSW_SECCOMP_ADD(dup3);
		LSW_SECCOMP_ADD(epoll_create);
		LSW_SECCOMP_ADD(epoll_create1);
		LSW_SECCOMP_ADD(epoll_ctl);
		LSW_SECCOMP_ADD(epoll_pwait);
		LSW_SECCOMP_ADD(epoll_wait);
		LSW_SECCOMP_ADD(execve);
		LSW_SECCOMP_ADD(faccessat);
#if SCMP_SYS(faccessat2)
		LSW_SECCOMP_ADD(faccessat2);
#endif
		LSW_SECCOMP_ADD(fadvise64);
		LSW_SECCOMP_ADD(getcwd);
		LSW_SECCOMP_ADD(getdents);
		LSW_SECCOMP_ADD(getdents64);
		LSW_SECCOMP_ADD(getegid);
		LSW_SECCOMP_ADD(geteuid);
		LSW_SECCOMP_ADD(getgid);
		LSW_SECCOMP_ADD(getgroups);
		LSW_SECCOMP_ADD(get_mempolicy);
		LSW_SECCOMP_ADD(getpgid);
		LSW_SECCOMP_ADD(getpgrp);
		LSW_SECCOMP_ADD(getppid);
		LSW_SECCOMP_ADD(getrandom); /* for unbound */
		LSW_SECCOMP_ADD(getrlimit);
		LSW_SECCOMP_ADD(getsockname);
		LSW_SECCOMP_ADD(getsockopt);
		LSW_SECCOMP_ADD(getuid);
		LSW_SECCOMP_ADD(ioctl);
		LSW_SECCOMP_ADD(lstat);
		LSW_SECCOMP_ADD(listen);
		LSW_SECCOMP_ADD(mkdir);
		LSW_SECCOMP_ADD(munmap);
		LSW_SECCOMP_ADD(open);
		LSW_SECCOMP_ADD(pipe);
		LSW_SECCOMP_ADD(pipe2);
		LSW_SECCOMP_ADD(poll);
		LSW_SECCOMP_ADD(ppoll);
		LSW_SECCOMP_ADD(prctl);
		LSW_SECCOMP_ADD(prlimit64);
		LSW_SECCOMP_ADD(pselect6);
		LSW_SECCOMP_ADD(readlink);
		LSW_SECCOMP_ADD(readlinkat);
		LSW_SECCOMP_ADD(recvfrom);
		LSW_SECCOMP_ADD(recvmsg);
#if SCMP_SYS(rseq)
		LSW_SECCOMP_ADD(rseq);
#endif
		LSW_SECCOMP_ADD(sched_getaffinity);
		LSW_SECCOMP_ADD(select);
		LSW_SECCOMP_ADD(sendmmsg);
		LSW_SECCOMP_ADD(sendmsg);
		LSW_SECCOMP_ADD(set_mempolicy);
		LSW_SECCOMP_ADD(set_robust_list);
		LSW_SECCOMP_ADD(setsockopt);
		LSW_SECCOMP_ADD(socket);
		LSW_SECCOMP_ADD(socketcall);
		LSW_SECCOMP_ADD(socketpair);
		LSW_SECCOMP_ADD(sysinfo);
		LSW_SECCOMP_ADD(uname);
		LSW_SECCOMP_ADD(unlink);
		LSW_SECCOMP_ADD(unlinkat);
	}

	/* common to pluto and helpers */

	LSW_SECCOMP_ADD(arch_prctl);
	LSW_SECCOMP_ADD(clock_gettime);
	LSW_SECCOMP_ADD(close);
	LSW_SECCOMP_ADD(exit);
	LSW_SECCOMP_ADD(exit_group);
	LSW_SECCOMP_ADD(fcntl);
	LSW_SECCOMP_ADD(fstat);
	LSW_SECCOMP_ADD(futex);
	LSW_SECCOMP_ADD(getpid);
	LSW_SECCOMP_ADD(gettid);
	LSW_SECCOMP_ADD(gettimeofday);
	LSW_SECCOMP_ADD(lseek);
	LSW_SECCOMP_ADD(madvise);
	LSW_SECCOMP_ADD(mmap);
	LSW_SECCOMP_ADD(mprotect);
	LSW_SECCOMP_ADD(nanosleep);
	LSW_SECCOMP_ADD(newfstatat);
	LSW_SECCOMP_ADD(openat);
	LSW_SECCOMP_ADD(pread64);
	LSW_SECCOMP_ADD(rt_sigaction);
	LSW_SECCOMP_ADD(rt_sigprocmask);
	LSW_SECCOMP_ADD(rt_sigreturn);
	LSW_SECCOMP_ADD(sched_setparam);
	LSW_SECCOMP_ADD(send);
	LSW_SECCOMP_ADD(sendto);
	LSW_SECCOMP_ADD(set_tid_address);
	LSW_SECCOMP_ADD(sigaltstack);
	LSW_SECCOMP_ADD(sigreturn);
	LSW_SECCOMP_ADD(stat);
	LSW_SECCOMP_ADD(statfs);
	LSW_SECCOMP_ADD(statfs64);
	LSW_SECCOMP_ADD(waitpid);
	LSW_SECCOMP_ADD(write);

	int rc = seccomp_load(ctx);
	if (rc < 0) {
		seccomp_release(ctx);
		fatal_errno(PLUTO_EXIT_SECCOMP_FAIL, logger, -rc,
			    "seccomp_load() failed");
	}
}

void init_seccomp_main(struct logger *logger)
{
	switch (pluto_seccomp_mode) {
	case SECCOMP_ENABLED:
		init_seccomp(SCMP_ACT_KILL, true, logger);
		llog(RC_LOG, logger, "seccomp security enabled in strict mode");
		break;
	case SECCOMP_TOLERANT:
		init_seccomp(SCMP_ACT_TRAP, true, logger);
		llog(RC_LOG, logger, "seccomp security enabled in tolerant mode");
		break;
	case SECCOMP_DISABLED:
		/*
		 * XXX: not "is disabled" it makes it sound that
		 * something active was done when nothing was.
		 */
		llog(RC_LOG, logger, "seccomp security is not enabled");
		break;
	default:
		bad_case(pluto_seccomp_mode);
	}

}

void init_seccomp_cryptohelper(int helpernum, struct logger *logger)
{
	switch (pluto_seccomp_mode) {
	case SECCOMP_ENABLED:
		init_seccomp(SCMP_ACT_KILL, false, logger);
		llog(RC_LOG, logger, "seccomp security enabled in strict mode for crypto helper %d", helpernum);
		break;
	case SECCOMP_TOLERANT:
		init_seccomp(SCMP_ACT_TRAP, false, logger);
		llog(RC_LOG, logger, "seccomp security enabled in tolerant mode for crypto helper %d", helpernum);
		break;
	case SECCOMP_DISABLED:
		/*
		 * XXX: see above; also skip log as not helpful.
		 */
		ldbg(logger, "seccomp security is not enabled for crypto helper %d", helpernum);
		break;
	default:
		bad_case(pluto_seccomp_mode);
	}
}

void whack_seccomp_crashtest(const struct whack_message *wm UNUSED, struct show *s)
{
	struct logger *logger = show_logger(s);
	/*
	 * This is a SECCOMP test, it CAN KILL pluto if successful!
	 *
	 * Basically, we call a syscall that pluto does not use and
	 * that is not on the whitelist. Currently we use getsid()
	 *
	 * With seccomp=enabled, pluto will be killed by the kernel
	 * With seccomp=tolerant or seccomp=disabled, pluto will
	 * report the test results.
	 */
	if (pluto_seccomp_mode == SECCOMP_ENABLED)
		llog(RC_LOG, logger,
		     "pluto is running with seccomp=enabled! pluto is expected to die!");
	llog(RC_LOG, logger, "Performing seccomp security test using getsid() syscall");
	pid_t testpid = getsid(0);

	/* We did not get shot by the kernel seccomp protection */
	if (testpid == -1) {
		llog(RC_LOG, logger,
		     "pluto: seccomp test syscall was blocked");
		switch (pluto_seccomp_mode) {
		case SECCOMP_TOLERANT:
			llog(RC_LOG, logger,
			     "OK: seccomp security was tolerant; the rogue syscall was blocked and pluto was not terminated");
			break;
		case SECCOMP_DISABLED:
			llog(RC_LOG, logger,
			     "OK: seccomp security was not enabled and the rogue syscall was blocked");
			break;
		case SECCOMP_ENABLED:
			llog_error(logger, 0/*no-errno*/,
				   "pluto seccomp was enabled but the rogue syscall did not terminate pluto!");
			break;
		default:
			bad_case(pluto_seccomp_mode);
		}
	} else {
		llog(RC_LOG, logger,
		     "pluto: seccomp test syscall was not blocked");
		switch (pluto_seccomp_mode) {
		case SECCOMP_TOLERANT:
			llog_error(logger, 0/*no-errno*/,
				   "pluto seccomp was tolerant but the rogue syscall was not blocked!");
			break;
		case SECCOMP_DISABLED:
			llog(RC_LOG, logger,
			     "OK: pluto seccomp was disabled and the rogue syscall was not blocked");
			break;
		case SECCOMP_ENABLED:
			llog_error(logger, 0/*no-errno*/,
				   "pluto seccomp was enabled but the rogue syscall was not blocked!");
			break;
		default:
			bad_case(pluto_seccomp_mode);
		}
	}
}

void show_seccomp(struct show *s)
{
	SHOW_JAMBUF(s, buf) {
		jam_string(buf, "seccomp=");
		jam_sparse_short(buf, &seccomp_mode_names, pluto_seccomp_mode);
	}
}

void seccomp_sigsys_handler(struct logger *logger)
{
	llog(RC_LOG, logger, "pluto received SIGSYS - possible SECCOMP violation!");
	if (pluto_seccomp_mode == SECCOMP_ENABLED) {
		fatal(PLUTO_EXIT_SECCOMP_FAIL, logger, "seccomp=enabled mandates daemon restart");
	}
}
