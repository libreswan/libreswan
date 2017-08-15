
#ifndef TimeZoneOffset
# define TimeZoneOffset timezone
#endif

#ifndef u8
# define u8 unsigned char
#endif

#include <limits.h>

#ifndef s6_addr16
# define s6_addr16 __u6_addr.__u6_addr16
#endif

#ifndef s6_addr32
# define s6_addr32 __u6_addr.__u6_addr32
#endif

#define NEED_SIN_LEN

/* udpfromto socket option for BSD */
#define HAVE_UDPFROMTO 1
#define HAVE_IP_RECVDSTADDR 1
