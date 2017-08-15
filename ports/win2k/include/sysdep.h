
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
