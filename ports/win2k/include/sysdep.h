
/* we need our private copy */
#include "sysqueue.h"

/* this typedef is missing from cygwin */
typedef unsigned short sa_family_t;

#define IPPROTO_ESP     50
#define IPPROTO_AH      51
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP    4
#endif
#define IPPROTO_COMP    108

#define TimeZoneOffset _timezone

/* Not entirely sure if win32 defines this */
#ifndef HOST_NAME_MAX           /* POSIX 1003.1-2001 says <unistd.h> defines this */
# define HOST_NAME_MAX 255      /* upper bound, according to SUSv2 */
#endif

