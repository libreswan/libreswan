#ifndef _SOCKET_WRAPPER_H_
#define _SOCKET_WRAPPER_H_

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/*
 * This wrapper ensures that we close all file descriptors on exec.
 */
#ifdef FD_CLOEXEC
static inline int safe_socket(int domain, int type, int protocol)
{
	long arg;
	int saved_errno;
	int fd = socket(domain, type, protocol);

	if (fd < 0)
		return fd;

	arg = fcntl(fd, F_GETFD);
	if (arg < 0)
		goto out_fail;

	arg |= FD_CLOEXEC;

	arg = fcntl(fd, F_SETFD, arg);
	if (arg < 0)
		goto out_fail;

out:
	return fd;

out_fail:
	saved_errno = errno;
	close(fd);
	fd = -1;
	errno = saved_errno;
	goto out;
}
#else
#define safe_socket(d, t, p) socket(d, t, p)
#endif

#endif
