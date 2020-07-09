# Libreswan top level Makefile
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

MAIN_RPM_VERSION = $(shell make showversion | sed "s/-.*//")
MAIN_RPM_PREVER = $(shell make showversion | sed -e  "s/^.[^-]*-\([^-]*\)-\(.*\)/rc\1_\2/" -e "s/-/_/g")
MAIN_RPM_PREFIX  = libreswan-$(MAIN_RPM_VERSION)$(MAIN_RPM_PREVER)
MAIN_RPM_RHEL_PKG = $(shell rpm -qf /etc/redhat-release)
MAIN_RPM_RHEL_VERSION = $(shell echo $(MAIN_RPM_RHEL_PKG) | sed "s/.*-release-\(.\).*/\1/")
MAIN_RPM_SPECFILE = $(shell if [ -f /etc/fedora-release ]; then echo packaging/fedora/libreswan.spec; elif [ -n "$(MAIN_RPM_RHEL_VERSION)" ]; then echo packaging/rhel/$(MAIN_RPM_RHEL_VERSION)/libreswan.spec; else echo "unknown distro, cannot find spec file to use in packaging directory"; fi)
RHEL_LIKE= $(shell cat /etc/os-release | grep ID_LIKE | sed -e "s/ID_LIKE=//" -e 's/"//g' -e "s/ .*//")
RHEL_MAJOR= $(shell cat /etc/os-release |grep VERSION_ID | sed -e 's/.*"\([0-9]*\)"/\1/' -e 's/VERSION_ID=//')
SRCDIR?=$(shell pwd)/

# dummy default rule
def: all

help:
	@echo
	@echo "To build and install on a recent Linux kernel:"
	@echo
	@echo "   make all && sudo make install"
	@echo
	@echo "For a minimal install (no manpages) type:"
	@echo
	@echo "   make base && sudo make install-base"
	@echo
	@echo "See the files INSTALL and README for more general information,"
	@echo
	@echo "To build debian packages: make deb"
	@echo "To build fedora/rhel/centos rpms: make rpm"
	@echo
	@false

.PHONY: def help

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

# directories visited by all recursion

# programs

ABSOBJDIR:=$(shell mkdir -p ${OBJDIR}; cd ${OBJDIR} && pwd)
OBJDIRTOP=${ABSOBJDIR}

# Recursive clean dealt with elsewhere.
.PHONY: local-clean-base
local-clean-base:
	$(foreach file,$(RPMTMPDIR) $(RPMDEST) out.*build out.*install, \
		rm -rf $(file) ; )

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
	@if [ -d .git ]; then \
		echo "For git trees, please run: make git-rpm" ; \
	fi
	@if [ ! -d .git -a -n "$(RHEL_LIKE)" ]; then \
		rpmbuild -ba packaging/rhel/$(RHEL_MAJOR)/libreswan.spec ; \
	fi
	@if [ ! -d .git -a -f /etc/fedora-release ]; then \
		rpmbuild -ba packaging/fedora/libreswan.spec ; \
	fi

git-rpm:
	@echo building rpm for libreswan testing
	mkdir -p ~/rpmbuild/SPECS/
	sed  -e "s/^Version:.*/Version: $(MAIN_RPM_VERSION)/g" \
	     -e "s/^#global prever.*/%global prever $(MAIN_RPM_PREVER)/" \
	     -e "s/^Release:.*/Release: 0.$(MAIN_RPM_PREVER)/" \
		$(MAIN_RPM_SPECFILE) > ~/rpmbuild/SPECS/libreswan.spec
	mkdir -p ~/rpmbuild/SOURCES
	git archive --format=tar --prefix=libreswan-$(MAIN_RPM_VERSION)$(MAIN_RPM_PREVER)/ \
		-o ~/rpmbuild/SOURCES/libreswan-$(MAIN_RPM_VERSION)$(MAIN_RPM_PREVER).tar HEAD
	if [ -a Makefile.inc.local ] ; then \
		tar --transform "s|^|$(MAIN_RPM_PREFIX)/|" -rf ~/rpmbuild/SOURCES/$(MAIN_RPM_PREFIX).tar Makefile.inc.local ; \
	fi;
	echo 'IPSECBASEVERSION=$(MAIN_RPM_VERSION)$(MAIN_RPM_PREVER)' > ~/rpmbuild/SOURCES/version.mk
	( pushd ~/rpmbuild/SOURCES; tar --transform "s|^|$(MAIN_RPM_PREFIX)/mk/|" -rf ~/rpmbuild/SOURCES/$(MAIN_RPM_PREFIX).tar version.mk; popd)
	rm ~/rpmbuild/SOURCES/version.mk
	gzip -f ~/rpmbuild/SOURCES/$(MAIN_RPM_PREFIX).tar
	rpmbuild -ba ~/rpmbuild/SPECS/libreswan.spec

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

.PHONY: deb-prepare
DEBIPSECBASEVERSION=$(shell make -s showdebversion)
deb-prepare:
	cp -r packaging/debian .
	cat debian/changelog
	grep "IPSECBASEVERSION" debian/changelog && \
		sed -i "s/@IPSECBASEVERSION@/$(DEBIPSECBASEVERSION)/g" debian/changelog || \
		echo "missing IPSECBASEVERSION in debian/changelog. This is not git repository?"
	cat debian/changelog

.PHONY: deb
deb: deb-prepare
	debuild -i -us -uc -b
	rm -fr debian
	#debuild -S -sa

release:
	packaging/utils/makerelease

local-install:
	@if test -z "$(DESTDIR)" -a -x /usr/sbin/selinuxenabled -a $(SBINDIR) != "$(DESTDIR)/usr/sbin" ; then \
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
ifeq ($(USE_XAUTHPAM),true)
	@if test ! -f $(DESTDIR)/etc/pam.d/pluto ; then \
		mkdir -p $(DESTDIR)/etc/pam.d/ ; \
		$(INSTALL) $(INSTCONFFLAGS) pam.d/pluto $(DESTDIR)/etc/pam.d/pluto ; \
	else \
		echo -e "\n************************** WARNING ***********************************" ; \
		echo "We are not installing a new copy of the pam.d/pluto file, as one" ; \
		echo "was already present.  You may wish to update it yourself if desired." ; \
		echo -e "**********************************************************************\n" ; \
	fi
endif

# Test only target (run by swan-install) that generates FIPS .*.hmac
# file for pluto that will be verified by fipscheck.
#
# (should really use fipshmac -d /usr/lib64/fipscheck but then
#  we need to hassle with multilib)
# Without this fipscheck (run in FIPS mode) will fail.

.PHONY: install-fipshmac
install-fipshmac:
ifeq ($(USE_FIPSCHECK),true)
	fipshmac $(LIBEXECDIR)/pluto
else
	@echo "install-fipshmac target requires compiling with USE_FIPSCHECK"
	@exit 1
endif

include ${LIBRESWANSRCDIR}/mk/docker-targets.mk
include ${LIBRESWANSRCDIR}/mk/kvm-targets.mk
include ${LIBRESWANSRCDIR}/mk/web-targets.mk
