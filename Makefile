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

include $(top_srcdir)/mk/config.mk

MAIN_RPMBUILD_SOURCES  = $(shell rpm --eval %{_sourcedir})
MAIN_RPMBUILD_SPEC  = $(shell rpm --eval %{_specdir})
MAIN_RPM_VERSION = $(shell make showversion | sed "s/-.*//")
MAIN_RPM_PREVER = $(shell make showversion | sed -e  "s/^.[^-]*-\([^-]*\)-\(.*\)/rc\1_\2/" -e "s/-/_/g" -e "s/\//_/g")
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

SUBDIRS?=lib programs initsystems testing configs

TAGSFILES = $(wildcard include/*.h include/*/*.h lib/lib*/*.[ch] programs/*/*.[ch] testing/check/*/*.[ch])

tags: $(TAGSFILES)
	LC_ALL=C ctags $(CTAGSFLAGS) ${TAGSFILES}

cscope:
	ls ${TAGSFILES} > cscope.files
	cscope -b

TAGS: $(TAGSFILES)
	LC_ALL=C etags $(ETAGSFLAGS) ${TAGSFILES}

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

include ${LIBRESWANSRCDIR}/mk/targets.mk

# directories visited by all recursion

# programs

ABSOBJDIR:=$(shell mkdir -p ${OBJDIR}; cd ${OBJDIR} && pwd)
OBJDIRTOP=${ABSOBJDIR}

# Recursive clean dealt with elsewhere.
.PHONY: local-clean-base
local-clean-base:
	rm -rf out.*
	rm -rf $(OBJDIR)/html

# Delete absolutely everything.
#
# Since "clean" is a recursive target and requires the existence of
# $(OBJDIR), "distclean" does not depend on it.  If it did, "make
# distclean" would have the quirky behaviour of first creating
# $(OBJDIR) only to then delete it.

.PHONY: distclean
distclean:
	: generated test keys
	: careful output mixed with repo files
	rm -rf testing/x509/*/
	rm -f testing/x509/nss-pw
	rm -f testing/baseconfigs/all/etc/bind/signed/*.signed
	rm -f testing/baseconfigs/all/etc/bind/keys/*.key
	rm -f testing/baseconfigs/all/etc/bind/keys/*.private
	rm -f testing/baseconfigs/all/etc/bind/dsset/dsset-*
	: test results
	rm -rf testing/pluto/*/OUTPUT*
	rm -rf BACKUP
	: build results
	rm -f out.*
	rm -rf OBJ.* $(OBJDIR)
	rm -f tags TAGS cscope
	rm -f cscope.files

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
	mkdir -p $(MAIN_RPMBUILD_SPEC) $(MAIN_RPMBUILD_SOURCES)
	sed  -e "s/^Version:.*/Version: $(MAIN_RPM_VERSION)/g" \
	     -e "s/^.global prever.*/%global prever $(MAIN_RPM_PREVER)/" \
	     -e "s/^Release:.*/Release: 0.$(MAIN_RPM_PREVER)/" \
		$(MAIN_RPM_SPECFILE) > $(MAIN_RPMBUILD_SPEC)/libreswan.spec
	git archive --format=tar --prefix=libreswan-$(MAIN_RPM_VERSION)$(MAIN_RPM_PREVER)/ \
		-o $(MAIN_RPMBUILD_SOURCES)/libreswan-$(MAIN_RPM_VERSION)$(MAIN_RPM_PREVER).tar HEAD
	if [ -a Makefile.inc.local ] ; then \
		tar --transform "s|^|$(MAIN_RPM_PREFIX)/|" -rf $(MAIN_RPMBUILD_SOURCES)/$(MAIN_RPM_PREFIX).tar Makefile.inc.local ; \
	fi;
	echo 'IPSECBASEVERSION=$(MAIN_RPM_VERSION)$(MAIN_RPM_PREVER)' > $(MAIN_RPMBUILD_SOURCES)/version.mk
	( pushd $(MAIN_RPMBUILD_SOURCES); tar --transform "s|^|$(MAIN_RPM_PREFIX)/mk/|" -rf $(MAIN_RPMBUILD_SOURCES)/$(MAIN_RPM_PREFIX).tar version.mk; popd)
	rm $(MAIN_RPMBUILD_SOURCES)/version.mk
	gzip -f $(MAIN_RPMBUILD_SOURCES)/$(MAIN_RPM_PREFIX).tar
	# get IKE test vectors if needed
	spectool --get-files $(MAIN_RPMBUILD_SPEC)/libreswan.spec --directory $(MAIN_RPMBUILD_SOURCES);
	rpmbuild -ba $(MAIN_RPMBUILD_SPEC)/libreswan.spec

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
	@$(MAKE) --silent --directory packaging/debian showdebversion
showrpmversion:
	@echo ${IPSECVERSION} |  sed "s/^v//" | sed -e "s/^v//;s/\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\(.*\)/\1.\2_\3/;s/-/_/g;s/__/_/g"
showrpmrelease:
	@echo ${IPSECVERSION} | sed "s/^v//" | sed "s/^[^-]*-\(.*\)/\1/"
showobjdir:
	@echo $(OBJDIR)

# these need get fixed not to use root
.PHONY: deb
deb:
	if [ -f /etc/devuan_version ]; then \
		$(MAKE) --directory packaging/devuan ; \
	else \
		$(MAKE) --directory packaging/debian ; \
	fi

release:
	packaging/utils/makerelease

local-install:

.PHONY: web web-page
web web-page:
	$(MAKE) -C testing/web web-publish

include ${LIBRESWANSRCDIR}/mk/docker-targets.mk
