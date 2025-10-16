# set make variables for local NSS build
NSS_CFLAGS =
NSS_CFLAGS += -I$(top_srcdir)/external/nss/dist/public/nss
NSS_CFLAGS += -I$(top_srcdir)/external/nss/dist/private/nss
NSS_CFLAGS += -I$(top_srcdir)/external/nss/dist/Debug/include/nspr

NSS_LDFLAGS =
NSS_LDFLAGS += -L$(top_srcdir)/external/nss/dist/Debug/lib
NSS_LDFLAGS += -Wl,-rpath=$(abs_top_srcdir)/external/nss/dist/Debug/lib
NSS_LDFLAGS += -lnss3

CERTUTIL = eval LD_LIBRARY_PATH=$(abs_top_srcdir)/external/nss/dist/Debug/lib $(abs_top_srcdir)/external/nss/dist/Debug/bin/certutil
CRLUTIL =  eval LD_LIBRARY_PATH=$(abs_top_srcdir)/external/nss/dist/Debug/lib $(abs_top_srcdir)/external/nss/dist/Debug/bin/crlutil
MODUTIL =  eval LD_LIBRARY_PATH=$(abs_top_srcdir)/external/nss/dist/Debug/lib $(abs_top_srcdir)/external/nss/dist/Debug/bin/modutil
PK12UTIL = eval LD_LIBRARY_PATH=$(abs_top_srcdir)/external/nss/dist/Debug/lib $(abs_top_srcdir)/external/nss/dist/Debug/bin/pk12util
VFYCHAIN = eval LD_LIBRARY_PATH=$(abs_top_srcdir)/external/nss/dist/Debug/lib $(abs_top_srcdir)/external/nss/dist/Debug/bin/vfychain
