# Libreswan testing makefile
# Copyright (C) 2002 Michael Richardson <mcr@freeswan.org>
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

LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
SRCDIR?=$(shell pwd)/
export LIBRESWANSRCDIR
include $(LIBRESWANSRCDIR)/Makefile.inc

SUBDIRS=
UTILS=${LIBRESWANSRCDIR}/testing/utils

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

# Don't depend on nss-pw and generated certificates, creating
# certificates and running those tests is not reliable.
check: 	${LIBRESWANSRCDIR}/kvmsetup.sh # ${LIBRESWANSRCDIR}/testing/x509/keys/mainca.key
# skip rebuilding KVMs unless started with: make check UPDATE=1
ifneq ($(UPDATE)$(UPDATEONLY),)
	${LIBRESWANSRCDIR}/testing/utils/runkvm.py --reboot --compile --install --hostname east
	${LIBRESWANSRCDIR}/testing/utils/runkvm.py --reboot --install --hostname west
	${LIBRESWANSRCDIR}/testing/utils/runkvm.py --reboot --install --hostname road
	${LIBRESWANSRCDIR}/testing/utils/runkvm.py --reboot --install --hostname north
endif
ifeq ($(UPDATEONLY),)
	../utils/swantest
	../utils/swantest --resanitize
endif

${LIBRESWANSRCDIR}/testing/x509/keys/mainca.key: ${LIBRESWANSRCDIR}/testing/x509/dist_certs.py
	cd ${LIBRESWANSRCDIR}/testing/x509/ && ./dist_certs.py

install install_file_list checkprograms programs:
	@true

clean:
	grep -v '^#' ${SRCDIR}TESTLIST | while read testtype name status; \
	do\
		rm -rf $$name/OUTPUT; \
	done

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean
