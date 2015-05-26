# Libreswan master makefile
#
# Copyright (C) 1998-2002  Henry Spencer.
# Copyright (C) 2003-2004  Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

PATCHES=linux
# where KLIPS goes in the kernel
# note, some of the patches know the last part of this path
KERNELKLIPS=$(KERNELSRC)/net/ipsec
KERNELCRYPTODES=$(KERNELSRC)/crypto/ciphers/des
KERNELLIBFREESWAN=$(KERNELSRC)/lib/libfreeswan
KERNELLIBZLIB=$(KERNELSRC)/lib/zlib
KERNELINCLUDE=$(KERNELSRC)/include

MAKEUTILS=packaging/utils
ERRCHECK=${MAKEUTILS}/errcheck
KVUTIL=${MAKEUTILS}/kernelversion
KVSHORTUTIL=${MAKEUTILS}/kernelversion-short

SUBDIRS?=lib programs initsystems testing

TAGSFILES=$(wildcard include/*.h lib/lib*/*.c programs/*/*.c linux/include/*.h linux/include/openswan/*.h linux/net/ipsec/*.[ch])

tags:	$(TAGSFILES)
	@LC_ALL=C ctags $(CTAGSFLAGS) ${TAGSFILES}

cscope:
	@ls ${TAGSFILES} > cscope.files
	@cscope -b

TAGS:	$(TAGSFILES)
	@LC_ALL=C etags $(ETAGSFLAGS) ${TAGSFILES}

.PHONY: dummy
dummy:



kvm:
	@echo Please run ./testing/libvirt/install.sh

# DESTDIR is normally set in Makefile.inc
check:
ifneq ($(strip(${REGRESSRESULTS})),)
	mkdir -p ${REGRESSRESULTS}
endif
	@for d in $(SUBDIRS); do (cd $$d && $(MAKE) DESTDIR=${DESTDIR} checkprograms || exit 1); done
	@for d in $(SUBDIRS); \
	do \
		echo ===================================; \
		echo Now making check in $$d; \
		echo ===================================; \
		${MAKE} -C $$d DESTDIR=${DESTDIR} check ;\
	done
ifneq ($(strip(${REGRESSRESULTS})),)
	-perl testing/utils/regress-summarize-results.pl ${REGRESSRESULTS}
endif
	@echo "======== End of make check target. ========"

# USE_ variables determine if features are compiled into Libreswan.
# export them so that "make env" can get at them
export USE_KLIPS USE_NETKEY
export USE_XAUTHPAM
export USE_LDAP
export USE_LIBCURL
export USE_EXTRACRYPTO
export USE_DNSSEC USE_LINUX_AUDIT
export USE_IPSEC_CONNECTION_LIMIT IPSEC_CONNECTION_LIMIT
export USE_FIPSCHECK FIPSPRODUCTCHECK
export USE_NM USE_LABELED_IPSEC
export USE_MAST USE_SAREF_KERNEL
