# Libreswan master makefile
#
# Copyright (C) 1998-2002  Henry Spencer.
# Copyright (C) 2003-2004  Xelerance Corporation
# Copyright (C) 2017, Richard Guy Briggs <rgb@tricolour.ca>
# Copyright (C) 2015-2018  Andrew Cagney
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#

ifndef top_srcdir
include mk/dirs.mk
endif

LIBRESWANSRCDIR?=$(shell pwd)

include ${LIBRESWANSRCDIR}/Makefile.inc

SRCDIR?=$(shell pwd)/

# dummy default rule
def help:
	@echo
	@echo "To build and install on a recent Linux kernel that has NETKEY:"
	@echo
	@echo "   make all && sudo make install"
	@echo
	@echo "For a minimal install (no manpages) type:"
	@echo
	@echo "   make base && sudo make install-base"
	@echo
	@echo "See the files INSTALL and README for more general information,"
	@echo "and details on how to build / install on KLIPS and other systems"
	@echo
	@echo "To build debian packages: make deb"
	@echo "To build fedora/rhel/centos rpms, see packaging/"
	@echo
	@false

.PHONY: def help

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

TAGSFILES=$(wildcard include/*.h lib/lib*/*.[ch] programs/*/*.[ch] linux/include/*.h linux/include/libreswan/*.h linux/net/ipsec/*.[ch])

tags:	$(TAGSFILES)
	@LC_ALL=C ctags $(CTAGSFLAGS) ${TAGSFILES}

cscope:
	@ls ${TAGSFILES} > cscope.files
	@cscope -b

TAGS:	$(TAGSFILES)
	@LC_ALL=C etags $(ETAGSFLAGS) ${TAGSFILES}

.PHONY: dummy
dummy:


# Run regress stuff after the other check targets.
.PHONY: regress
check: regress
regress: local-check recursive-check
ifneq ($(strip(${REGRESSRESULTS})),)
	mkdir -p ${REGRESSRESULTS}
	-perl testing/utils/regress-summarize-results.pl ${REGRESSRESULTS}
endif
	@echo "======== End of make check target. ========"

include ${LIBRESWANSRCDIR}/mk/subdirs.mk

# kernel details
# what variant of our patches should we use, and where is it
KERNELREL=$(shell ${KVSHORTUTIL} ${KERNELSRC}/Makefile)

# directories visited by all recursion

# programs

ABSOBJDIR:=$(shell mkdir -p ${OBJDIR}; cd ${OBJDIR} && pwd)
OBJDIRTOP=${ABSOBJDIR}

# Recursive clean dealt with elsewhere.
.PHONY: local-clean-base
local-clean-base:
	$(foreach file,$(RPMTMPDIR) $(RPMDEST) out.*build out.*install, \
		rm -rf $(file) ; )	# but leave out.kpatch

# Delete absolutely everything.
#
# Since "clean" is a recursive target and requires the existence of
# $(OBJDIR), "distclean" does not depend on it.  If it did, "make
# distclean" would have the quirky behaviour of first creating
# $(OBJDIR) only to then delete it.
.PHONY: distclean
distclean: clean-kvm-keys
	rm -f $(RPMTMPDIR) $(RPMDEST) out.*
	rm -rf testing/pluto/*/OUTPUT*
	rm -rf OBJ.* $(OBJDIR)
	rm -rf BACKUP


# set up for build
buildready:
	rm -f dtrmakefile cvs.datemark
	# obsolete cd doc ; $(MAKE) -s

rpm:
	@echo To build an rpm, use: rpmbuild -ba packaging/XXX/libreswan.spec
	@echo where XXX is your rpm based vendor
	rpmbuild -bs packaging/fedora/libreswan.spec

tarpkg:
	@echo "Generating tar.gz package to install"
	@rm -rf /var/tmp/libreswan-${USER}
	@make DESTDIR=/var/tmp/libreswan-${USER} programs install
	@rm /var/tmp/libreswan-${USER}/etc/ipsec.conf
	@(cd /var/tmp/libreswan-${USER} && tar czf - . ) >libreswan-${IPSECVERSION}.tgz
	@ls -l libreswan-${IPSECVERSION}.tgz
	@rm -rf /var/tmp/libreswan-${USER}


env:
	@env | sed -e "s/'/'\\\\''/g" -e "s/\([^=]*\)=\(.*\)/\1='\2'/"

#
#  A target that does nothing intesting is sometimes interesting...
war:
	@echo "Not Love?"

showversion:
	@echo ${IPSECVERSION} | sed "s/^v//"
showdebversion:
	@echo ${IPSECVERSION} |  sed "s/^v//" | sed -e "s/\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\(.*\)/\1.\2~\3/" | sed "s/~-/~/"
showrpmversion:
	@echo ${IPSECVERSION} |  sed "s/^v//" | sed -e "s/^v//;s/\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\(.*\)/\1.\2_\3/;s/-/_/g;s/__/_/g"
showrpmrelease:
	@echo ${IPSECVERSION} | sed "s/^v//" | sed "s/^[^-]*-\(.*\)/\1/"
showobjdir:
	@echo $(OBJDIR)

# these need to move elsewhere and get fixed not to use root

deb:
	cp -r packaging/debian .
	grep "IPSECBASEVERSION" debian/changelog && \
		sed -i "s/@IPSECBASEVERSION@/`make -s showdebversion`/g" debian/changelog || \
		echo "missing IPSECBASEVERSION in debian/changelog. This is not git repository?"
	debuild -i -us -uc -b
	rm -fr debian
	#debuild -S -sa
	@echo "to build optional KLIPS kernel module, run make deb-klips"

release:
	packaging/utils/makerelease

local-install:
	@if test -z "$(DESTDIR)" -a -x /usr/sbin/selinuxenabled -a $(PUBDIR) != "$(DESTDIR)/usr/sbin" ; then \
	if /usr/sbin/selinuxenabled ; then  \
		echo -e "\n************************** WARNING ***********************************" ; \
		echo "SElinux is present on this system and the prefix path is not /usr." ; \
		echo "This can cause software failures if selinux is running in Enforcing mode"; \
		echo -e "unless selinux policies are updated manually to allow this.\n" ; \
		echo "The following commands fix a common issue of /usr/local/ being mislabeled"; \
		echo "    restorecon /usr/local/sbin -Rv"; \
		echo "    restorecon /usr/local/libexec/ipsec -Rv"; \
		if test -x /usr/sbin/getenforce ; then \
			echo -e "\nSElinux is currently running in `/usr/sbin/getenforce` mode" ; \
		fi ; \
		echo -e "**********************************************************************\n" ; \
	fi \
	fi
	@if test ! -f $(DESTDIR)/etc/pam.d/pluto ; then \
		mkdir -p $(DESTDIR)/etc/pam.d/ ; \
		$(INSTALL) $(INSTCONFFLAGS) pam.d/pluto $(DESTDIR)/etc/pam.d/pluto ; \
	else \
		echo -e "\n************************** WARNING ***********************************" ; \
		echo "We are not installing a new copy of the pam.d/pluto file, as one" ; \
		echo "was already present.  You may wish to update it yourself if desired." ; \
		echo -e "**********************************************************************\n" ; \
	fi

# Test only target (run by swan-install) that generates FIPS .*.hmac
# file for pluto that will be verified by fipscheck.
#
# (should really use fipshmac -d /usr/lib64/fipscheck but then
#  we need to hassle with multilib)
# Without this fipscheck (run in FIPS mode) will fail.

.PHONY: install-fipshmac
install-fipshmac:
	fipshmac $(LIBEXECDIR)/pluto

include ${LIBRESWANSRCDIR}/mk/docker-targets.mk
include ${LIBRESWANSRCDIR}/mk/kvm-targets.mk
include ${LIBRESWANSRCDIR}/mk/web-targets.mk
ifeq ($(USE_KLIPS),true)
include ${LIBRESWANSRCDIR}/mk/kernel.mk
endif
