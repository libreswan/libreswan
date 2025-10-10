# set make variables for local NSS build
NSS_CFLAGS =
NSS_CFLAGS += -I$(top_srcdir)/external/nss/dist/public/nss
NSS_CFLAGS += -I$(top_srcdir)/external/nss/dist/private/nss
NSS_CFLAGS += -I$(top_srcdir)/external/nss/dist/Debug/include/nspr

NSS_LDFLAGS =
NSS_LDFLAGS += -L$(top_srcdir)/external/nss/dist/Debug/lib
NSS_LDFLAGS += -Wl,-rpath=$(abs_top_srcdir)/external/nss/dist/Debug/lib
NSS_LDFLAGS += -lnss3
