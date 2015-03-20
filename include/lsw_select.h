#ifndef _LSW_SELECT_H_
#define _LSW_SELECT_H_ 1
/*
 * Overlay the system select call to handle many more FD's than
 * an fd_set can hold.
 * David McCullough <david_mccullough@securecomputing.com>
 */

#include <sys/select.h>

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * allow build system to override the limit easily
 */

#ifndef LSW_FD_SETSIZE
#define LSW_FD_SETSIZE  8192
#endif

#define LSW_NFDBITS   (8 * sizeof(long int))
#define LSW_FDELT(d)  ((d) / LSW_NFDBITS)
#define LSW_FDMASK(d) ((long int) (1UL << ((d) % LSW_NFDBITS)))
#define LSW_FD_SETCOUNT ((LSW_FD_SETSIZE + LSW_NFDBITS - 1) / LSW_NFDBITS)

typedef struct {
	long int __osfds_bits[LSW_FD_SETCOUNT];
} lsw_fd_set;

#define LSW_FDS_BITS(set) ((set)->__osfds_bits)

#define LSW_FD_ZERO(set) \
	do { \
		unsigned int __i; \
		lsw_fd_set *__arr = (set); \
		for (__i = 0; __i < LSW_FD_SETCOUNT; __i++) \
			LSW_FDS_BITS(__arr)[__i] = 0; \
	} while (0)

#define LSW_FD_SET(d, s)     (LSW_FDS_BITS(s)[LSW_FDELT(d)] |= LSW_FDMASK(d))
#define LSW_FD_CLR(d, s)     (LSW_FDS_BITS(s)[LSW_FDELT(d)] &= ~LSW_FDMASK(d))
#define LSW_FD_ISSET(d, \
		     s)   ((LSW_FDS_BITS(s)[LSW_FDELT(d)] & LSW_FDMASK(d)) != \
			   0)

#define lsw_select(max, r, f, e, t) \
	select(max, (fd_set *)(void *)(r), (fd_set *)(void *)(f), \
	       (fd_set *)(void *)(e), t)

#endif /* _LSW_SELECT_H_ */
