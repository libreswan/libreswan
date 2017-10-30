
#include <linux/types.h>
#define u8 __u8

#define TimeZoneOffset timezone

#include <limits.h>

/*
 * This normally comes in via bind9/config.h
 * Fixes a warning in lib/libisc/random.c:44
 */
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1

/*
 * Not all environments set this? happened on a arm_tools cross compile
 */
#ifndef linux
# define linux
#endif

/* udpfromto socket option for Linux */
#define HAVE_UDPFROMTO 1
#define HAVE_IP_PKTINFO 1

