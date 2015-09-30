# I really am not happy about using symlinks to make this work.
#
# I think that there should be a better way to do this.
# see module26.sh in packaging/makefiles
#

LIBRESWANSRCDIR?=$(shell cd ../../..;pwd)

include ${LIBRESWANSRCDIR}/Makefile.inc

UMLPLAIN=$(shell . ${LIBRESWANSRCDIR}/umlsetup.sh; echo $${POOLSPACE}/plain$${KERNVER})
KLIPS_TOP=${LIBRESWANSRCDIR}/linux

INPUTS=${LIBRESWANSRCDIR}/testing/klips/inputs/01-sunrise-sunset-udpesp-ping.pcap
INPUTS+=${SRCDIR}../rcv-01/cleartext.pcap
PCAP2SKB=${LIBRESWANSRCDIR}/testing/utils/pcap2skb/pcap2skb

CC=gcc
TESTCASE=rcv02main
PACKFILE=rcv02pack

IPSEC_OBJS=ipsec_rcv.o ipsec_esp.o ipsec_ah.o ipsec_ipcomp.o
IPSEC_OBJS+=ipsec_md5c.o ipsec_sha1.o ipsec_sa.o
IPSEC_OBJS+=ipsec_life.o
IPSEC_OBJS+=cbc_enc.o set_key.o des_enc.o ecb_enc.o ipsec_alg_3des.o
IPSEC_OBJS+=ipsec_snprintf.o ipsec_alg.o
IPSEC_OBJS+=aes.o aes_cbc.o aes_xcbc_mac.o ipsec_alg_aes.o

include ${SRCDIR}../Makefile.kunit
