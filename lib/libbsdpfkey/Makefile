LIB=libbsdpfkey.a

OBJS += ipsec_dump_policy.o
OBJS += ipsec_get_policylen.o
OBJS += ipsec_strerror.o
OBJS += key_debug.o
OBJS += pfkey.o
OBJS += pfkey_dump.o
# OBJS += policy_parse.y \
# policy_token.l

USERLAND_INCLUDES += -I$(top_srcdir)/include/libbsdpfkey
USERLAND_CFLAGS += "-DPATH_IPSEC_H=<netipsec/ipsec.h>"
USERLAND_CFLAGS += -DHAVE_STDINT_H

ifdef top_srcdir
include $(top_srcdir)/mk/library.mk
else
include ../../mk/library.mk
endif
