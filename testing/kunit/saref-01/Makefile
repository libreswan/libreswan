#
# Kunit tests for KLIPS -- SA reference allocation
#

LIBRESWANSRCDIR?=$(shell cd ../../..;pwd)

include ${LIBRESWANSRCDIR}/Makefile.inc

UMLPLAIN=$(shell . ${LIBRESWANSRCDIR}/umlsetup.sh; echo $${POOLSPACE}/plain$${KERNVER})
KLIPS_TOP=${LIBRESWANSRCDIR}/linux

#INPUTS=${LIBRESWANSRCDIR}/testing/klips/inputs/02-sunrise-sunset-esp.pcap
#INPUTS+=${SRCDIR}cleartext.pcap

CC=gcc
TESTCASE=sa01main

IPSEC_OBJS=ipsec_sa.o
IPSEC_OBJS+=ipsec_snprintf.o ipsec_alg.o ipsec_sha1.o ipsec_md5c.o
IPSEC_OBJS+=aes.o aes_cbc.o aes_xcbc_mac.o ipsec_alg_aes.o
IPSEC_OBJS+=cbc_enc.o set_key.o des_enc.o ecb_enc.o ipsec_alg_3des.o

include ${SRCDIR}../Makefile.kunit
