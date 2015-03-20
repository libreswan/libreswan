#include <endian.h>

#if __BYTE_ORDER == LITTLE_ENDIAN
#include "kernelenv_littleendian.h"
#endif

#if __BYTE_ORDER == BIG_ENDIAN
#include "kernelenv_bigendian.h"
#endif

