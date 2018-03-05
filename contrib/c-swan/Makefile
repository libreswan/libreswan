.PHONY: clean

CFLAGS	+= \
	-I/usr/include/nspr4 \
	-I../../include \
	-I../../linux/include

LIBSRC	= \
	../../lib/libswan/initsubnet.c \
	../../lib/libswan/ip_address.c \
	../../lib/libswan/sameaddr.c \
	../../lib/libswan/subnettypeof.c \
	../../lib/libswan/ttoaddr.c \
	../../lib/libswan/ttosubnet.c \
	../../lib/libswan/ttoul.c \
	../../linux/net/ipsec/addrtot.c \
	../../linux/net/ipsec/addrtypeof.c \
	../../linux/net/ipsec/anyaddr.c \
	../../linux/net/ipsec/initaddr.c \
	../../linux/net/ipsec/ultot.c

is_encrypted: is_encrypted.c swan.c $(LIBSRC)

clean:
	rm -f is_encrypted
