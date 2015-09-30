# FreeS/WAN testing makefile
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

LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
SRCDIR?=${LIBRESWANSRCDIR}/testing/lib/libpluto/
include $(LIBRESWANSRCDIR)/Makefile.inc

SUBDIRS=
UTILS=${LIBRESWANSRCDIR}/testing/utils

TESTS=$(shell awk '{print $$2;}' ${SRCDIR}TESTLIST)

all: ${TESTS}
	echo ${TESTS}

one:
	export LIBRESWANLIB=${LIBRESWANLIB} REGRESSRESULTS=$${REGRESSRESULTS-../results} ; . ${UTILS}/functions.sh; eval `grep ${TEST} TESTLIST`

refineconnection: refineconnection.c lib-refineconnection/testlist.sh OUTPUT.refineconnection.txt FLAGS.refineconnection
	. ${UTILS}/functions.sh; multilibtest `basename $< .c`

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

check:
	@ECHO=: REGRESSRESULTS=$${REGRESSRESULTS-../results} ; . ${UTILS}/functions.sh; . ${SRCDIR}TESTLIST
	@echo */core.*

install install_file_list checkprograms programs:
	@true

clean:
	cat ${SRCDIR}TESTLIST | while read testtype name status; \
	do\
		rm -rf `basename $$name .c`;\
	done

ike-secrets.txt: OUTPUT.parentI2.txt
	grep '../parentI2 ikev2 [IR]' OUTPUT.parentI2.txt | cut -c13- >ike-secrets.txt

cleanall: clean

distclean: clean

east.record: ${LIBRESWANSRCDIR}/programs/pluto/rcv_whack.c
	(cd ${LIBRESWANSRCDIR}/programs/pluto && unset LIBRESWANSRCDIR && pl_inst.sh)
	(cd ${LIBRESWANSRCDIR}/testing/pluto/whackrecord-01 && ../../utils/runme.sh )
	. ${LIBRESWANSRCDIR}/kvmsetup.sh; cp $$POOLSPACE/east/root/var/tmp/east.record .

updatepcaps:
	cp lib-parentI1/parentI1.pcap lib-parentR1
	cp lib-parentR1/parentR1.pcap lib-parentI2
	cp lib-parentI2/parentI2.pcap lib-parentR2
	cp lib-parentR2/parentR2.pcap lib-parentI3

