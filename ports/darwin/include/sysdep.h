#define TimeZoneOffset timezone
#define u8 unsigned char

#include <limits.h>

#ifndef s6_addr16
# define s6_addr16 __u6_addr.__u6_addr16
#endif

#ifndef s6_addr32
# define s6_addr32 __u6_addr.__u6_addr32
#endif

#define NEED_SIN_LEN

/* Needed for proper handling of udpfromto */
#define __APPLE_USE_RFC_3542
