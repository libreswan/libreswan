# KVM make targets, for Libreswan
#
# Copyright (C) 2015-2025 Andrew Cagney
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

include ../../mk/dirs.mk
include ../../mk/config.mk
include ../../mk/testing.mk

KVM_RUTDIR ?= $(TESTING_RUTDIR)
KVM_BENCHDIR ?= $(TESTING_BENCHDIR)
KVM_SOURCEDIR ?= $(TESTING_SOURCEDIR)
KVM_TESTINGDIR ?= $(TESTING_RUTDIR)/testing

# An educated guess ...
KVM_POOLDIR ?= $(abspath $(abs_top_srcdir)/../pool)
KVM_LOCALDIR ?= $(KVM_POOLDIR)

# Note: GNU Make doesn't let you combine pattern targets (e.x.,
# kvm-install-%: kvm-reboot-%) with .PHONY.  Consequently, so that
# patterns can be used, any targets with dependencies are not marked
# as .PHONY.  Sigh!

# Note: for pattern targets, the value of % can be found in the make
# variable '$*' (why not $%!?!?!, because that was used for archives).
# It is used to extract the DOMAIN from targets like
# kvm-install-DOMAIN.

empty =
comma = ,
sp = $(empty) $(empty)
# the first blank line is ignored
define crlf


endef

#
# Build KVM_TEST_PREFIXES from $(KVM_PREFIX) and $(KVM_WORKERS).  Goal
# is to make KVM_TEST_PREFIXES non-empty.
#
#   KVM_PREFIX=  KVM_WORKERS=  KVM_TEST_PREFIXES=
#                                 $(KVM_LOCALDIR)/
#                    1            $(KVM_LOCALDIR)/
#                    2            $(KVM_LOCALDIR)/   $(KVM_LOCALDIR)/2
#       a                         $(KVM_LOCALDIR)/a
#       a            1            $(KVM_LOCALDIR)/a
#       a            2            $(KVM_LOCALDIR)/a  $(KVM_LOCALDIR)/a2
#       a.                        $(KVM_LOCALDIR)/a.
#       a.           1            $(KVM_LOCALDIR)/a.
#       a.           2            $(KVM_LOCALDIR)/a. $(KVM_LOCALDIR)/a2
#
# Note:
#    $(join $(KVM_LOCALDIR), $(KVM_PREFIX))
# and not not:
#    $(addprefix $(KVM_LOCALDIR), $(KVM_PREFIX))
# is used as, when $(KVM_PREFIX) is empty, the latter expands to
# nothing.
#
# Note: test with:
#    make -C testing/kvm kvm-config KVM_PREFIX=... KVM_WORKERS=... | grep PREFIXES

KVM_PREFIX ?=
KVM_WORKERS ?= 1
KVM_NUMBERS = $(wordlist 2, $(KVM_WORKERS), 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17)
KVM_TEST_PREFIXES ?= $(sort \
	$(join $(KVM_LOCALDIR)/, $(KVM_PREFIX)) \
	$(foreach n, $(KVM_NUMBERS), $(join $(KVM_LOCALDIR)/, $(join $(patsubst %., %, $(KVM_PREFIX)), $(n)))))

#KVM_PYTHON ?= PYTHONPATH=/home/python/pexpect:/home/python/ptyprocess /home/python/v3.8/bin/python3
KVM_PIDFILE ?= $(KVM_BENCHDIR)/kvmrunner.pid
# Current user's UID; and GID used by QEMU
KVM_UID ?= $(shell id -u)
KVM_GID ?= $(shell stat --format=%g $(KVM_HOST_QEMUDIR))

# Don't include @@SOURCEDIR@@ @@TESTINGDIR@@ and @@DOMAIN@@ as they
# change depending on what is being transformed.  Instead they are
# added as needed.

KVM_TRANSMOGRIFY = \
	sed \
	-e 's;@@GATEWAY@@;$(KVM_GATEWAY_ADDRESS);' \
	-e 's;@@BENCHDIR@@;$(KVM_BENCHDIR);' \
	-e 's;@@LOCALDIR@@;$(KVM_LOCALDIR);' \
	-e 's;@@POOLDIR@@;$(KVM_POOLDIR);' \
	-e 's;@@USER@@;$(KVM_UID);' \
	-e 's;@@GROUP@@;$(KVM_GID);' \
	-e 's;@@PREFIX@@;$(KVM_PREFIX);'

# The alternative is qemu:///session and it doesn't require root.
# However, it has never been used, and the python tools all assume
# qemu://system. Finally, it comes with a warning: QEMU usermode
# session is not the virt-manager default.  It is likely that any
# pre-existing QEMU/KVM guests will not be available.  Networking
# options are very limited.

KVM_CONNECTION ?= qemu:///system

VIRSH = sudo virsh --connect=$(KVM_CONNECTION)


#
# Makeflags passed to the KVM build
#
# For each setting two flags are checked:
#
#   KVM_<OS>_<FLAG>
#   KVM_<FLAG>
#
# for instance:
#
#   KVM_LINUX_ALL_ALGS
#   KVM_ALL_ALGS
#
# In KVM-MAKEFLAG, the macro $(KVM_$($*)_$(strip $(1))) expands to
# $(KVM_<OS>_<FLAG>) and $(KVM_$(strip $(1))) expands to
# $(KVM_<FLAG>).

# On Linux, override linux defaults
KVM_LINUX_SD_RESTART_TYPE ?= no
KVM_LINUX_USE_EFENCE ?= true
KVM_LINUX_USE_LABELED_IPSEC ?= true
KVM_LINUX_USE_SECCOMP ?= true

# On Alpine, do a cutdown build
KVM_ALPINE_USE_DNSSEC ?= false

# On Debian, don't try to build ML_KEM
KVM_DEBIAN_USE_ML_KEM_768 ?= false

# from <FLAG> return KVM_<OS>_<FLAG> or KVM_<FLAG>
kvm-flag = \
	$(firstword \
		$(if $(KVM_$($*)_$(strip $(1))), KVM_$($*)_$(strip $(1))) \
		$(if $(KVM_$(strip $(1))),       KVM_$(strip $(1))))

kvm-flag-name = $(call kvm-flag, $(patsubst KVM_%, %, $(1)))
kvm-flag-value = $($(call kvm-flag, $(patsubst KVM_%, %, $(1))))

# either KVM_${PLATFORM}_FLAG or KVM_FLAG
KVM-MAKEFLAG = \
	$(if $(call kvm-flag-name, $(1)), \
		$(patsubst KVM_%, %, $(1))=$(call kvm-flag-value, $(1)))

KVM_MAKEFLAGS ?= $(strip \
	-j$(call kvm-flag-value, KVM_BUILD_CPUS) \
	$(call KVM-MAKEFLAG, KVM_ALL_ARGS) \
	$(call KVM-MAKEFLAG, KVM_NSSDIR) \
	$(call KVM-MAKEFLAG, KVM_NSS_CFLAGS) \
	$(call KVM-MAKEFLAG, KVM_NSS_LDFLAGS) \
	$(call KVM-MAKEFLAG, KVM_SD_RESTART_TYPE) \
	$(call KVM-MAKEFLAG, KVM_USE_EFENCE) \
	$(call KVM-MAKEFLAG, KVM_USE_LABELED_IPSEC) \
	$(call KVM-MAKEFLAG, KVM_USE_LTO) \
	$(call KVM-MAKEFLAG, KVM_USE_NSS_KDF) \
	$(call KVM-MAKEFLAG, KVM_USE_SECCOMP) \
	$(call KVM-MAKEFLAG, KVM_USE_ML_KEM_512) \
	$(call KVM-MAKEFLAG, KVM_USE_ML_KEM_768) \
	$(call KVM-MAKEFLAG, KVM_USE_ML_KEM_1024) \
	$(call KVM-MAKEFLAG, KVM_CC) \
	)

# Fine-tune the BASE and BUILD machines.
#
# BASE is kept small.
#
# BUILD is more complex:
#
# CPUs: so as to not over allocate host cores, stick with
# $(KVM_WORKERS) (default 1). The heuristic is to set $(KVM_WORKERS)
# to #cores/2 - as it seems that a [booting] machine ties up two
# cores.
#
# Memory: a test typically requires two 512mb VMs. With $(KVM_WORKERS)
# that makes at least $(KVM_WORKERS)*2*512mb of ram being used by
# tests VMs.  Boost build's memory by that amount.

VIRT_INSTALL ?= sudo virt-install
VIRT_CPU ?= --cpu=host-passthrough
VIRT_DISK_SIZE_GB ?= 10
VIRT_RND ?= --rng=type=random,device=/dev/random
VIRT_SECURITY ?= --security=type=static,model=dac,label='$(KVM_UID):$(KVM_GID)',relabel=yes
VIRT_GATEWAY ?= --network=network:$(KVM_GATEWAY_NAME),model=virtio
VIRT_BENCHDIR ?= --filesystem=target=bench,type=mount,accessmode=squash,source=$(KVM_BENCHDIR)
VIRT_POOLDIR ?= --filesystem=target=pool,type=mount,accessmode=squash,source=$(KVM_POOLDIR)
# note: these rely on %==$(OS)
VIRT_SOURCEDIR ?= --filesystem=target=source,type=mount,accessmode=squash,source=$(KVM_SOURCEDIR)
VIRT_TESTINGDIR ?= --filesystem=target=testing,type=mount,accessmode=squash,source=$(KVM_TESTINGDIR)

VIRT_INSTALL_FLAGS = \
	--connect=$(KVM_CONNECTION) \$(crlf)\
	--check=path_in_use=off \$(crlf)\
	--graphics=none \$(crlf)\
	--virt-type=kvm \$(crlf)\
	--noreboot \$(crlf)\
	--console=pty,target_type=serial \$(crlf)\
	$(VIRT_CPU) \$(crlf)\
	$(VIRT_GATEWAY) \$(crlf)\
	$(VIRT_RND) \$(crlf)\
	$(VIRT_SECURITY)

#
# Platforms / OSs
#
# To disable an OS use something like:
#     KVM_OPENBSD=
# NOT ...=false

KVM_ALPINE ?=
KVM_DEBIAN ?=
KVM_FEDORA ?=
KVM_LINUX ?= true
KVM_FREEBSD ?=
KVM_NETBSD ?=
KVM_OPENBSD ?=

# so that $($*) converts % to upper case
alpine = ALPINE
debian = DEBIAN
fedora = FEDORA
freebsd = FREEBSD
linux = LINUX
netbsd = NETBSD
openbsd = OPENBSD

# this is what works
KVM_PLATFORMS += alpine
KVM_PLATFORMS += debian
KVM_PLATFORMS += fedora
KVM_PLATFORMS += freebsd
KVM_PLATFORMS += linux
KVM_PLATFORMS += netbsd
KVM_PLATFORMS += openbsd

# this is what is enabled; OS needs a better name; KVM_OSS is weird
KVM_OS += $(if $(filter true, $(KVM_ALPINE)),  alpine)
KVM_OS += $(if $(filter true, $(KVM_DEBIAN)),  debian)
KVM_OS += $(if $(filter true, $(KVM_FEDORA)),  fedora)
KVM_OS += $(if $(filter true, $(KVM_FREEBSD)), freebsd)
KVM_OS += $(if $(filter true, $(KVM_LINUX)),   linux)
KVM_OS += $(if $(filter true, $(KVM_NETBSD)),  netbsd)
KVM_OS += $(if $(filter true, $(KVM_OPENBSD)), openbsd)

#
# Hosts and Domains
#
# These make variables roughly follow the naming convention:
#
#  KVM_*_HOST_NAME KVM_*_HOST_NAMES
#
#      the root names without any additions
#
#  KVM_*_DOMAIN KVM_*_DOMAINS
#
#      the path/domain-name that is used as the make target
#
#      Note: make rules use $(notdir KVM_*_DOMAIN), $(notdir $@), and
#      $* (matching % in pattern rules) to get the domain name from
#      the target

# expand anything using $1 (such as make variable names and values)
# immediately, but delay everything else by using $$.

# override below
KVM_LINUX_TEST_HOST_NAMES = east west north road nic
KVM_OS_TEST_HOST_NAMES = e w rise set

KVM_BASEDIR ?= $(KVM_POOLDIR)
KVM_UPGRADEDIR ?= $(KVM_POOLDIR)
KVM_BUILDDIR ?= $(KVM_LOCALDIR)
KVM_TESTDIR ?= $(KVM_LOCALDIR)

define domains

KVM_$($(strip $1))_BASE_DOMAIN    = $$(KVM_BASEDIR)/$$(KVM_PREFIX)$(strip $1)-base
KVM_$($(strip $1))_UPGRADE_DOMAIN = $$(KVM_UPGRADEDIR)/$$(KVM_PREFIX)$(strip $1)-upgrade
KVM_$($(strip $1))_BUILD_DOMAIN   = $$(KVM_BUILDDIR)/$$(KVM_PREFIX)$(strip $1)

KVM_BASE_DOMAINS     += $$(KVM_$($(strip $1))_BASE_DOMAIN)
KVM_UPGRADE_DOMAINS  += $$(KVM_$($(strip $1))_UPGRADE_DOMAIN)
KVM_BUILD_DOMAINS    += $$(KVM_$($(strip $1))_BUILD_DOMAIN)

# don't override KVM_LINUX_TEST_HOST_NAMES above
KVM_$($(strip $1))_TEST_HOST_NAMES  ?= $$(addprefix $1, $$(KVM_OS_TEST_HOST_NAMES))
KVM_$($(strip $1))_TEST_DOMAINS      = $$(foreach prefix, $$(KVM_TEST_PREFIXES), $$(addprefix $$(prefix), $$(KVM_$($(strip $1))_TEST_HOST_NAMES)))

KVM_$($(strip $1))_DOMAINS += $$(KVM_$($(strip $1))_BASE_DOMAIN)
KVM_$($(strip $1))_DOMAINS += $$(KVM_$($(strip $1))_BUILD_DOMAIN)
KVM_$($(strip $1))_DOMAINS += $$(KVM_$($(strip $1))_UPGRADE_DOMAIN)
KVM_$($(strip $1))_DOMAINS += $$(KVM_$($(strip $1))_TEST_DOMAINS)

endef

$(foreach platform, $(KVM_PLATFORMS), \
	$(eval $(call domains, $(platform))))

KVM_TEST_HOST_NAMES   = $(foreach platform, $(KVM_PLATFORMS), $(KVM_$($(platform))_TEST_HOST_NAMES))
KVM_TEST_DOMAINS      = $(foreach platform, $(KVM_PLATFORMS), $(KVM_$($(platform))_TEST_DOMAINS))

KVM_DOMAINS += $(KVM_BASE_DOMAINS)
KVM_DOMAINS += $(KVM_UPGRADE_DOMAINS)
KVM_DOMAINS += $(KVM_BUILD_DOMAINS)
KVM_DOMAINS += $(KVM_TEST_DOMAINS)

#
# Domains
#
# Generate local names using prefixes
#

# targets for dumping the above; $(info) value to stdout when
# evaluating the command @: gives make real work.

.PHONY: print-kvm-variable
print-kvm-variable:
	@echo "$(strip $($(VARIABLE)))"

#
# Other utilities and directories
#

QEMU_IMG ?= sudo qemu-img

KVMSH      ?= cd $(abs_top_srcdir) && $(KVM_PYTHON) testing/utils/kvmsh.py
KVMRUNNER  ?= cd $(abs_top_srcdir) && $(KVM_PYTHON) testing/utils/kvmrunner.py
KVMRESULTS ?= cd $(abs_top_srcdir) && $(KVM_PYTHON) testing/utils/kvmresults.py

RPM_VERSION = $(shell $(MAKE) --no-print-directory showrpmversion)
RPM_PREFIX  = libreswan-$(RPM_VERSION)
RPM_BUILD_CLEAN ?= --rmsource --rmspec --clean


#
# Detect a fresh boot of the host machine.  Use this as a dependency
# for actions that should only be run once after each boot.
#
# The first time $(MAKE) is run after a boot, this file is touched,
# any further rules leave the file alone.
#

KVM_FRESH_BOOT_FILE = $(KVM_POOLDIR)/$(KVM_PREFIX)boot.ok
$(KVM_FRESH_BOOT_FILE): $(firstword $(wildcard /var/run/rc.log /var/log/boot.log))
$(KVM_FRESH_BOOT_FILE): | $(KVM_POOLDIR)
	touch $@

KVM_HOST_OK += $(KVM_FRESH_BOOT_FILE)

#
# Check that there is enough entoropy for running the domains.
#
# Only do this once per boot.
#

KVM_HOST_ENTROPY_FILE ?= /proc/sys/kernel/random/entropy_avail
KVM_HOST_ENTROPY_OK = $(KVM_POOLDIR)/$(KVM_PREFIX)entropy.ok
$(KVM_HOST_ENTROPY_OK): $(KVM_FRESH_BOOT_FILE)
$(KVM_HOST_ENTROPY_OK): | $(KVM_POOLDIR)
	@if test ! -r $(KVM_HOST_ENTROPY_FILE); then			\
		echo no entropy to check ;				\
	elif test $$(cat $(KVM_HOST_ENTROPY_FILE)) -gt 100 ; then	\
		echo lots of entropy ;					\
	else								\
		echo ;							\
		echo  According to:					\
		echo ;							\
		echo      $(KVM_HOST_ENTROPY_FILE) ;			\
		echo ;							\
		echo  your computer does not have much entropy ;	\
		echo ;							\
		echo  Check the wiki for hints on how to fix this. ;	\
		echo ;							\
		false ;							\
	fi
	touch $@

KVM_HOST_OK += $(KVM_HOST_ENTROPY_OK)

#
# Check that the QEMUDIR is writeable by us.
#
# (assumes that the machine is rebooted after a qemu update)
#


KVM_HOST_QEMUDIR ?= /var/lib/libvirt/qemu
KVM_HOST_QEMUDIR_OK = $(KVM_POOLDIR)/$(KVM_PREFIX)qemudir.ok
$(KVM_HOST_QEMUDIR_OK): $(KVM_FRESH_BOOT_FILE)
$(KVM_HOST_QEMUDIR_OK): | $(KVM_POOLDIR)
	@if ! test -w $(KVM_HOST_QEMUDIR) ; then			\
		echo ;							\
		echo "  The directory:" ;				\
		echo ;							\
		echo "     $(KVM_HOST_QEMUDIR) (KVM_HOST_QEMUDIR)" ;	\
		echo ;							\
		echo "  is not writeable vis:" ;			\
		echo ;							\
		echo "     $$(ls -ld $(KVM_HOST_QEMUDIR))" ;		\
		echo ;							\
		echo "  This will break virsh which is"	;		\
		echo "  used to manipulate the domains." ;		\
		echo "  Typically this is fixed with:" ;		\
		echo ;							\
		echo "     sudo chgrp qemu $(KVM_HOST_QEMUDIR)" ;	\
		echo "     sudo chmod g+w $(KVM_HOST_QEMUDIR)" ;	\
		echo ;							\
		false ;							\
	fi
	touch $@

KVM_HOST_OK += $(KVM_HOST_QEMUDIR_OK)

#
# ensure that NFS is running and everything is exported
#

KVM_HOST_NFS_OK = $(KVM_POOLDIR)/$(KVM_PREFIX)nfs.ok
$(KVM_HOST_NFS_OK): kvm-exportfs.sh
$(KVM_HOST_NFS_OK): $(KVM_FRESH_BOOT_FILE)
$(KVM_HOST_NFS_OK): | $(KVM_POOLDIR)
	sh kvm-exportfs.sh \
		$(KVM_GATEWAY_ADDRESS)/$(KVM_GATEWAY_PREFIX) \
		$(KVM_BENCHDIR) \
		$(KVM_POOLDIR) \
		$(KVM_SOURCEDIR) \
		$(KVM_RUTDIR)
	touch $@

.PHONY: kvm-install-nfs kvm-uninstall-nfs
kvm-install-nfs: $(KVM_HOST_NFS_OK)
kvm-uninstall-nfs:
	sudo exportfs -ua
	rm -f $(KVM_HOST_NFS_OK)
KVM_HOST_OK += $(KVM_HOST_NFS_OK)

#
# Don't create $(KVM_POOLDIR) - let the user do that as it lives
# outside of the current directory tree.
#
# However, do create $(KVM_LOCALDIR) (but not using -p) if it is
# unique and doesn't exist - convention seems to be to point it at
# /tmp/pool which needs to be re-created every time the host is
# rebooted.
#
# Defining a macro and the printing it using $(info) is easier than
# a bunch of echo's or :s.
#

define kvm-pooldir-info

  The directory:

      "$(KVM_POOLDIR)"

  specified by KVM_POOLDIR and used to store the base domain disk
  and other files, does not exist.

  Either create the directory or adjust its location by setting
  KVM_POOLDIR in the file:

      Makefile.inc.local

endef

$(KVM_POOLDIR) $(KVM_POOLDIR)/:
	$(info $(kvm-pooldir-info))
	false

ifneq ($(KVM_POOLDIR),$(KVM_LOCALDIR))
$(KVM_LOCALDIR)/:
	: not -p
	mkdir $(KVM_LOCALDIR)
endif

#
# Build or update the web pages ready for a new test run
#
# For the results directory, just install the HTML / javascript files
# (kvmrunner.py will fill in all the json files).  For the summary
# directory, do a full update so that all the previous runs are
# included.

.PHONY: kvm-web
kvm-web: kvm-ready
ifdef WEB_ENABLED
	$(MAKE) -C $(top_srcdir)/testing/web --no-print-directory web-test-prep
else
	@echo
	@echo Web-pages disabled.
	@echo
	@echo To enable web pages create the directory:
	@echo
	@echo "   $(TESTING_WEBDIR)"
	@echo
	@echo To convert this result into a web page run:
	@echo
	@echo "   make web"
	@echo
endif

#
# [re]run the testsuite.
#
# If the testsuite is being run a second time (for instance,
# re-started or re-run) what should happen: run all tests regardless;
# just run tests that have never been started; run tests that haven't
# yet passed?  Since each alternative has merit, let the user decide
# by providing both kvm-test and kvm-retest.

KVM_TESTS ?= $(KVM_TESTINGDIR)/pluto

# Given a make command like:
#
#     make kvm-test "KVM_TESTS=$(./testing/utils/kvmresults.py --quick testing/pluto | awk '/output-different/ { print $1 }' )"
#
# then KVM_TESTS ends up containing new lines, strip them out.
STRIPPED_KVM_TESTS = $(strip $(KVM_TESTS))

# Run the testsuite.
#
# - depends on kvm-keys-ok and not kvm-keys or $(KVM_KEYS) so that the
#   check that the keys are up-to-date is run.
#
# - need build domains shutdown as, otherwise, test domains can refuse
#   to boot because the domain they were cloned from is still running.

# Allow any of 'KVM_TEST_STATUS=good|wip', 'KVM_TEST_STATUS=good wip',
# or KVM_TEST_STATUS+=wip.

KVM_TEST_PLATFORM += $(KVM_OS)
KVM_TEST_STATUS += good
KVM_RUN_POST_MORTEM ?=
KVM_LOG_CONSOLE_OUTPUT ?=

STRIPPED_KVM_TEST_PLATFORM = $(subst $(sp),|,$(sort $(KVM_TEST_PLATFORM)))
STRIPPED_KVM_TEST_STATUS = $(subst $(sp),|,$(sort $(KVM_TEST_STATUS)))
STRIPPED_KVM_TEST_NAME = $(subst $(sp),|,$(sort $(KVM_TEST_NAME)))

KVM_TEST_NAME ?=

.PHONY: kvm-ready
kvm-ready: kvm-keys-ok
kvm-ready: $(KVM_HOST_OK)
kvm-ready:
	: shutdown all the build domains, kvmrunner shuts down the test domains
	true $(foreach domain, $(KVM_BUILD_DOMAINS), && $(KVMSH) --shutdown $(notdir $(domain)))

kvm-test kvm-check kvm-retest kvm-recheck: \
kvm-%: kvm-ready kvm-web
	: $@
	: KVM_TESTS="$(STRIPPED_KVM_TESTS)"
	$(KVMRUNNER) \
		$(if $(KVM_PIDFILE), --pid-file "$(KVM_PIDFILE)") \
		$(foreach prefix,$(KVM_TEST_PREFIXES), --prefix '$(notdir $(prefix))') \
		--testing-directory $(KVM_TESTINGDIR) \
		$(if $(WEB_ENABLED), --publish-hash        $(TESTING_HASH)) \
		$(if $(WEB_ENABLED), --publish-resultsdir  $(TESTING_RESULTSDIR)) \
		$(if $(WEB_ENABLED), --publish-status      $(TESTING_WEBDIR)/status.json) \
		$(if $(WEB_ENABLED), --publish-result-html $(abs_top_srcdir)/testing/web/result.html) \
		$(if $(PUBLISH_SOURCE_URL), --publish-source-url $(PUBLISH_SOURCE_URL)) \
		$(if $(STRIPPED_KVM_TEST_STATUS),   --test-status   '$(STRIPPED_KVM_TEST_STATUS)') \
		$(if $(STRIPPED_KVM_TEST_NAME),     --test-name     '$(STRIPPED_KVM_TEST_NAME)') \
		$(if $(STRIPPED_KVM_TEST_PLATFORM), --test-platform '$(STRIPPED_KVM_TEST_PLATFORM)') \
		$(if $(filter kvm-re%, $@), --skip passed) \
		$(if $(KVM_RUN_POST_MORTEM),    --run-post-mortem=$(KVM_RUN_POST_MORTEM)) \
		$(if $(KVM_LOG_CONSOLE_OUTPUT), --log-console-output=$(KVM_LOG_CONSOLE_OUTPUT)) \
		$(KVMRUNNER_FLAGS) \
		$(KVM_TEST_FLAGS) \
		$(STRIPPED_KVM_TESTS)

# clean up; accept pretty much everything
KVM_TEST_CLEAN_TARGETS = kvm-clean-check kvm-check-clean kvm-clean-test kvm-test-clean
.PHONY: $(KVM_TEST_CLEAN_TARGETS)
$(KVM_TEST_CLEAN_TARGETS):
	find $(STRIPPED_KVM_TESTS) -name OUTPUT -type d -prune -print0 | xargs -0 -r rm -r

.PHONY: kvm-results
kvm-results:
	$(KVMRESULTS) $(KVMRESULTS_FLAGS) $(KVM_TEST_FLAGS) $(STRIPPED_KVM_TESTS) $(if $(KVM_BASELINE),--baseline $(KVM_BASELINE))
.PHONY: kvm-diffs
kvm-diffs:
	$(KVMRESULTS) $(KVMRESULTS_FLAGS) $(KVM_TEST_FLAGS) $(STRIPPED_KVM_TESTS) $(if $(KVM_BASELINE),--baseline $(KVM_BASELINE)) --print diffs

#
# Build the KVM keys using the KVM.
#
# XXX:
#
# Can't yet force the domain's creation.  This target may have been
# invoked by testing/pluto/Makefile which relies on old domain
# configurations.
#
# Make certain everything is shutdown.  Can't directly depend on the
# phony target kvm-shutdown as that triggers an unconditional rebuild.
# Instead invoke that rule inline.

# file to mark keys are up-to-date
KVM_KEYS = $(KVM_TESTINGDIR)/x509/up-to-date
KVM_KEYS_EXPIRATION_DAY = 7
KVM_KEYS_EXPIRED = find $(KVM_TESTINGDIR)/x509/*/ -type f -mtime +$(KVM_KEYS_EXPIRATION_DAY) -ls
KVM_KEYS_DOMAIN = $(KVM_LINUX_BUILD_DOMAIN)

.PHONY: kvm-keys
kvm-keys:
	: invoke phony target to shut things down and delete old keys
	$(MAKE) kvm-shutdown-linux
	$(MAKE) kvm-clean-keys
	$(MAKE) $(KVM_KEYS)

$(KVM_KEYS): $(KVM_TESTINGDIR)/x509/selfsigned.sh
$(KVM_KEYS): $(KVM_TESTINGDIR)/x509/generate.sh
$(KVM_KEYS): $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/generate-dnssec.sh
$(KVM_KEYS): | $(KVM_KEYS_DOMAIN)
$(KVM_KEYS): | $(KVM_HOST_OK)
	:
	: generate the keys using $(KVM_KEYS_DOMAIN)
	:
	$(KVMSH) $(notdir $(KVM_KEYS_DOMAIN)) /testing/guestbin/keys.sh
	:
	: extract the tarball containing the keys
	:
	cd $(KVM_TESTINGDIR)/x509 && tar xf kvm-keys.tar && rm kvm-keys.tar
	:
	: Also regenerate the DNSSEC keys
	:
	$(KVMSH) --chdir /testing $(notdir $(KVM_KEYS_DOMAIN)) ./baseconfigs/all/etc/bind/generate-dnssec.sh
	:
	: All done.
	:
	$(KVMSH) --shutdown $(KVM_KEYS_DOMAIN)
	touch $@

.PHONY: kvm-clean-keys kvm-keys-clean
kvm-clean-keys kvm-keys-clean:
	: careful output mixed with repo files
	rm -rf $(KVM_TESTINGDIR)/x509/*/
	rm -f $(KVM_KEYS)
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/signed/*.signed
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/keys/*.key
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/keys/*.private
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/dsset/dsset-*
	rm -f $(KVM_POOLDIR)/$(KVM_PREFIX)kvm-keys.tar

# For moment don't force keys to be re-built.
.PHONY: kvm-keys-ok
kvm-keys-ok:
	@if test ! -r $(KVM_KEYS); then					\
		$(MAKE) $(KVM_KEYS) ;					\
	elif test $$($(KVM_KEYS_EXPIRED) | wc -l) -gt 0 ; then		\
		echo "" ;						\
		echo "  The  KVM keys are too old.  Run:" ;		\
		echo "" ;						\
		echo "      ./kvm keys";				\
		echo "" ;						\
		echo "  to force an update" ;				\
		echo "" ;						\
		exit 1 ;						\
	fi


#
# The Gateway and Test networks
#
# Like domains/hosts, these make variables follow the rough naming
# convention:
#
#  KVM_GATEWAY_NAME / KVM_TEST_NETWORK_NAMES
#
#    the name that virsh likes to use
#
#  KVM_GATEWAY / KVM_TEST_NETWORKS
#
#    the path/name that is used as the make target
#
#    Note: make rules use constructs such as $(notdir $(KVM_GATEWAY)),
#    $(notdir $@), and $* (matching % in pattern rules) to get the
#    name from the target.
#
# Because the gateway is created directly from the below using
# hardwired IP addresses, only one gateway is possible.
#
# To avoid the problem where the host has no "default" KVM network
# (there's a strong rumour that libreswan's main testing machine has
# this problem) define a dedicated swandefault gateway.
#
# This:
#
# [ 00.00] IPv4: martian source 198.19.0.1 from 198.19.0.73, on dev eth0
# [ 00.00] ll header: 00000000: ff ff ff ff ff ff 52 54 00 cd dd 9e 08 06
#
# typically indicates that two machines have ended up with the same
# lease.
#
# For instance, /var/lib/libvirt/dnsmasq/swandefault.status show
# 198.19.0.73 leased to ethernet address 52:54:00:cd:dd:9e which is
# "fedora", but "fedoraw"'s ip addr shows it owning the lease:
#
# 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
#    link/ether 52:54:00:c8:26:8f brd ff:ff:ff:ff:ff:ff
#    inet 198.19.0.73/16 metric 1024 brd 198.19.255.255 scope global dynamic eth0
#

KVM_GATEWAY_NAME ?= swandefault
KVM_GATEWAY_ADDRESS ?= 198.19.0.1
KVM_GATEWAY_PREFIX ?= 16
KVM_GATEWAY_DHCP_START ?= 198.19.1.0
KVM_GATEWAY_DHCP_END ?= 198.19.16.255

KVM_GATEWAY = $(KVM_POOLDIR)/$(KVM_GATEWAY_NAME)

define KVM_GATEWAY_XML
<network ipv6='yes'>
  <name>$(KVM_GATEWAY_NAME)</name>
  <forward mode='nat'/>
  <bridge name='$(KVM_GATEWAY_NAME)' stp='on' delay='0'/>
  <domain name='$(KVM_GATEWAY_NAME)'/>
  <ip address='$(KVM_GATEWAY_ADDRESS)' prefix='$(KVM_GATEWAY_PREFIX)'>
    <dhcp>
      <range start='$(KVM_GATEWAY_DHCP_START)' end='$(KVM_GATEWAY_DHCP_END)'/>
    </dhcp>
  </ip>
</network>
endef

$(KVM_GATEWAY): | $(KVM_POOLDIR)
	./kvm-uninstall-network.sh $(KVM_GATEWAY)
	echo "$(strip $(KVM_GATEWAY_XML))" > $(KVM_GATEWAY).xml
	$(VIRSH) net-define $(KVM_GATEWAY).xml
	$(VIRSH) net-autostart $(KVM_GATEWAY_NAME)
	$(VIRSH) net-start $(KVM_GATEWAY_NAME)
	touch $(KVM_GATEWAY)

#
# Test networks.
#

KVM_TEST_NETWORK_NAMES = 192_0_1 192_0_2 192_0_3 192_1_2 192_1_3 198_18_1
KVM_TEST_NETWORKS = \
	$(foreach test_prefix, $(KVM_TEST_PREFIXES), \
		$(foreach test_network, $(KVM_TEST_NETWORK_NAMES), \
			$(test_prefix)$(test_network)))

$(KVM_TEST_NETWORKS): \
$(KVM_LOCALDIR)/%: $(KVM_FRESH_BOOT_FILE) | $(KVM_LOCALDIR)/
	: @=$@
	: *=$*
	-sudo ip link set $* down
	-sudo ip link del name $*
	sudo ip link add $* type bridge
	sudo ip link set $* up
	touch $@

.PHONY: kvm-gateway
kvm-gateway:
	$(MAKE) kvm-uninstall-gateway
	$(MAKE) kvm-install-gateway
.PHONY: kvm-install-test-networks kvm-install-gateway
kvm-install-gateway: $(KVM_GATEWAY)
kvm-install-test-networks: $(KVM_TEST_NETWORKS)

.PHONY: kvm-uninstall-test-networks
kvm-uninstall-test-networks:
	$(foreach network, $(KVM_TEST_NETWORKS), sudo ip link set $(notdir $(network)) down ; sudo ip link del name $(notdir $(network)) ; rm -f $(network) ; )
.PHONY: kvm-uninstall-gateway
kvm-uninstall-gateway:
	./kvm-uninstall-network.sh $(KVM_GATEWAY)

##
##
## Build the base domains
##
##
## The reverse of BASE is PURGE

KVM_BASE_CPUS = 1
KVM_BASE_MEMORY ?= 2048

.PHONY: kvm-base kvm-purge
kvm-base: $(patsubst %, kvm-base-%, $(KVM_OS))
kvm-purge: $(patsubst %, kvm-purge-%, $(KVM_PLATFORMS))

$(patsubst %, kvm-base-%, $(KVM_PLATFORMS)): \
kvm-base-%: kvm-purge-%
	: $@ build a-new
	$(MAKE) $(KVM_$($*)_BASE_DOMAIN)

$(patsubst %, kvm-purge-%, $(KVM_PLATFORMS)): \
kvm-purge-%: kvm-downgrade-%
	: $@=$*
	./kvm-uninstall-domain.sh $(KVM_$($*)_BASE_DOMAIN)
	: delete generated dependencies missed by above
	rm -f $(KVM_$($*)_BASE_DOMAIN).*
	rm -f $(KVM_$($*)_BASE_DOMAIN)

$(KVM_BASE_DOMAINS): \
$(KVM_BASEDIR)/$(KVM_PREFIX)%-base: \
		| \
		./kvm-install-base.py \
		$(KVM_BASEDIR)/ \
		$(KVM_HOST_OK) \
		$(KVM_GATEWAY)
	: @=$@ *=$*
	: clean up old domains
	./kvm-uninstall-domain.sh $@
	: use script to drive build of new domain
	$(KVM_PYTHON) ./kvm-install-base.py \
		os "$*" \
		domain "$(notdir $@)" \
		gateway $(KVM_GATEWAY_ADDRESS) \
		benchdir $(KVM_BENCHDIR) \
		pooldir $(KVM_POOLDIR) \
		-- \
		$(VIRT_INSTALL) \
			$(VIRT_INSTALL_FLAGS) \
			--vcpus=$(call kvm-flag-value, KVM_BASE_CPUS) \
			--memory=$(call kvm-flag-value, KVM_BASE_MEMORY) \
			--name=$(notdir $@) \
			--osinfo=$(KVM_$($*)_OSINFO) \
			--disk=path=$@.qcow2,size=$(VIRT_DISK_SIZE_GB),bus=virtio,format=qcow2 \
			$(VIRT_POOLDIR) \
			$(KVM_$($*)_VIRT_INSTALL_FLAGS)
	:
	: Check that the shell prompt includes the exit code.
	:
	: KVMSH uses the prompt exit code to determine the status of
	: the last command run vis:
	:
	:     [user@host pwd]# false
	:     [user@host pwd 1]# true
	:     [user@host pwd]#
	:   OR
	:     [user@host pwd 0]#
	:
	$(KVMSH) $(notdir $@) -- true
	! ( $(KVMSH) $(notdir $@) -- false )
	:
	: Check that /pool - KVM_POOLDIR - is mounted.
	:
	: The package install, upgrade, and transmogrify scripts
	: are copied to and then run from that directory.
	:
	$(KVMSH) $(notdir $@) -- test -r /pool/$(notdir $@).qcow2
	:
	: Check that /source and /testing directories are not present.
	:
	: The /source and /testing directories are set up by transmogrify.
	: They can change and may not point into this directory tree.
	: Delaying their creation hopefully makes it harder to accidentally
	: access the wrong files.
	:
	$(KVMSH) $(notdir $@) -- test ! -d /source -a ! -d /testing
	:
	: Everything seems to be working, shut down.
	:
	$(KVMSH) --shutdown $(notdir $@)
	touch $@



KVM_GET ?= \
	get() \
	{ \
		set -ex ; \
		curl --no-styled-output --location --continue-at - --output $@.tmp "$$1" ; \
		echo "$$2 ($@.tmp) = $$3" | $(CKSUM) -c ; \
		mv $@.tmp $@ ; \
	} ; \
	get

#
# Alpine
#

KVM_ALPINE_VERSION ?= v3.22
KVM_ALPINE_RELEASE ?= 3.22.1
KVM_ALPINE_MACHINE ?= x86
KVM_ALPINE_OSINFO  ?= $(strip $(shell osinfo-query -f short-id os | grep ' alpinelinux' | sort -V | tail -1))

KVM_ALPINE_URL ?= https://dl-cdn.alpinelinux.org/alpine/$(KVM_ALPINE_VERSION)/releases/$(KVM_ALPINE_MACHINE)

KVM_ALPINE_ISO ?= $(KVM_POOLDIR)/alpine-standard-$(KVM_ALPINE_RELEASE)-$(KVM_ALPINE_MACHINE).iso
KVM_ALPINE_ISO_HASH = SHA256
KVM_ALPINE_ISO_CKSUM ?= e48150959643658c222786cc34b258422dde218ebb9f34aa7c130e6d3f697e63
KVM_ALPINE_ISO_URL ?= $(KVM_ALPINE_URL)/$(notdir $(KVM_ALPINE_ISO))

$(KVM_ALPINE_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_ALPINE_ISO_URL) $(KVM_ALPINE_ISO_HASH) $(KVM_ALPINE_ISO_CKSUM)

KVM_ALPINE_VIRT_INSTALL_FLAGS = \
	--cdrom=$(KVM_ALPINE_ISO)

$(KVM_ALPINE_BASE_DOMAIN): $(KVM_ALPINE_ISO)


#
# Debian
#
# - debian is trying to track the oldest release
#
#   Unfortunately PRESEED only works in debian12+
#
# - debian installs 32-bit so that 32-bit GLIBC builts are tested
#
#   Unfortunately libbirt doesn't know how to boot 32-bit debian ISOs,
#   the work-around is to specify generic linux as the OSINFO.
#
#   https://gitlab.com/libvirt/libvirt/-/issues/755

KVM_DEBIAN_MAJOR ?= 12
KVM_DEBIAN_RELEASE ?= ${KVM_DEBIAN_MAJOR}.2.0
KVM_DEBIAN_BUILD ?= 1
KVM_DEBIAN_MACHINE ?= i386
KVM_DEBIAN_OSINFO  ?= linux2022

# https://cdimage.debian.org/debian-cd/current/amd64/iso-dvd
KVM_DEBIAN_URL ?= https://cdimage.debian.org/mirror/cdimage/archive/$(KVM_DEBIAN_RELEASE)/$(KVM_DEBIAN_MACHINE)/iso-dvd

KVM_DEBIAN_ISO = $(KVM_POOLDIR)/debian-$(KVM_DEBIAN_RELEASE)-$(KVM_DEBIAN_MACHINE)-DVD-$(KVM_DEBIAN_BUILD).iso
KVM_DEBIAN_ISO_HASH = SHA256
KVM_DEBIAN_ISO_CKSUM = 7733a6017c6aab330f4457ab3a73fcbf0aa0165778d0aa2115adb0fb18a65d0c
KVM_DEBIAN_ISO_URL ?= $(KVM_DEBIAN_URL)/$(notdir $(KVM_DEBIAN_ISO))

$(KVM_DEBIAN_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_DEBIAN_ISO_URL) $(KVM_DEBIAN_ISO_HASH) $(KVM_DEBIAN_ISO_CKSUM)

$(KVM_DEBIAN_BASE_DOMAIN).iso: $(KVM_DEBIAN_ISO)
$(KVM_DEBIAN_BASE_DOMAIN).iso: | debian/base.sh
	cp $(KVM_DEBIAN_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		debian/base.sh \
		> $(KVM_DEBIAN_BASE_DOMAIN).sh
	growisofs -M $@.tmp -l -R \
		-input-charset utf-8 \
		-graft-points \
		/base.sh=$(KVM_DEBIAN_BASE_DOMAIN).sh
	mv $@.tmp $@

$(KVM_DEBIAN_BASE_DOMAIN): $(KVM_DEBIAN_BASE_DOMAIN).iso

KVM_DEBIAN_VIRT_INSTALL_FLAGS = \
	--location=$(KVM_DEBIAN_BASE_DOMAIN).iso \
	--initrd-inject=debian/preseed.cfg \
	--extra-args="console=ttyS0,115200 net.ifnames=0 biosdevname=0"


#
# Fedora
#
# - leading edge (i.e., often newer then linux)
#
# - since kickstart is used this is pretty straight forward
#
#   For instance: Fedora-Server-dvd-x86_64-36-1.5.iso

KVM_FEDORA_RELEASE ?= 42
KVM_FEDORA_BUILD ?= 1.1
KVM_FEDORA_OSINFO ?= $(strip $(shell osinfo-query -f short-id os | grep ' fedora' | sort -V | tail -1))

KVM_FEDORA_URL ?= https://download.fedoraproject.org/pub/fedora/linux/releases/$(KVM_FEDORA_RELEASE)/Server/x86_64/iso

KVM_FEDORA_ISO ?= $(KVM_POOLDIR)/Fedora-Server-dvd-x86_64-$(KVM_FEDORA_RELEASE)-$(KVM_FEDORA_BUILD).iso
KVM_FEDORA_ISO_HASH = SHA256
KVM_FEDORA_ISO_CKSUM ?= 7fee9ac23b932c6a8be36fc1e830e8bba5f83447b0f4c81fe2425620666a7043
KVM_FEDORA_ISO_URL ?= $(KVM_FEDORA_URL)/$(notdir $(KVM_FEDORA_ISO))

KVM_FEDORA_KICKSTART_FILE ?= fedora/base.ks

$(KVM_FEDORA_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_FEDORA_ISO_URL) $(KVM_FEDORA_ISO_HASH) $(KVM_FEDORA_ISO_CKSUM)

KVM_FEDORA_VIRT_INSTALL_FLAGS = \
	--location=$(KVM_FEDORA_ISO) \
	--initrd-inject=$(KVM_FEDORA_BASE_DOMAIN).ks \
	--extra-args="inst.ks=file:/$(notdir $(KVM_FEDORA_BASE_DOMAIN).ks) console=ttyS0,115200 net.ifnames=0 biosdevname=0 inst.notmux"

$(KVM_FEDORA_BASE_DOMAIN): $(KVM_FEDORA_ISO)
$(KVM_FEDORA_BASE_DOMAIN): | $(KVM_FEDORA_KICKSTART_FILE)
$(KVM_FEDORA_BASE_DOMAIN): | $(KVM_FEDORA_BASE_DOMAIN).ks

$(KVM_FEDORA_BASE_DOMAIN).ks: | $(KVM_FEDORA_KICKSTART_FILE)
	$(KVM_TRANSMOGRIFY) \
		-e 's;@@PLATFORM@@;fedora;' \
		$(KVM_FEDORA_KICKSTART_FILE) \
		> $@.tmp
	mv $@.tmp $@

#
# FreeBSD
#
# - leading edge
#
# - modifies the install CD
#
# - uses DISK 1, and not DVD 1, as the former does not contain
#   packages; they will be downloaded later
#
# - use what ever libvirt supports

KVM_FREEBSD_RELEASE ?= 14.3
KVM_FREEBSD_OSINFO ?= $(strip $(shell osinfo-query -f short-id os | grep ' freebsd' | sort -V | tail -1))

KVM_FREEBSD_URL ?= https://download.freebsd.org/ftp/releases/ISO-IMAGES/$(KVM_FREEBSD_RELEASE)

KVM_FREEBSD_ISO ?= $(KVM_POOLDIR)/FreeBSD-$(KVM_FREEBSD_RELEASE)-RELEASE-amd64-disc1.iso
KVM_FREEBSD_ISO_HASH ?= SHA256
KVM_FREEBSD_ISO_CKSUM ?= f564822bc72d420d1e1a6faacb72f6056d828fcf539dfafd52e08503ef5fab68
KVM_FREEBSD_ISO_URL ?= $(KVM_FREEBSD_URL)/$(notdir $(KVM_FREEBSD_ISO))

$(KVM_FREEBSD_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_FREEBSD_ISO_URL) $(KVM_FREEBSD_ISO_HASH) $(KVM_FREEBSD_ISO_CKSUM)

KVM_FREEBSD_VIRT_INSTALL_FLAGS = \
       --cdrom=$(KVM_FREEBSD_BASE_DOMAIN).iso

$(KVM_FREEBSD_BASE_DOMAIN): $(KVM_FREEBSD_BASE_DOMAIN).iso

$(KVM_FREEBSD_BASE_DOMAIN).iso: $(KVM_FREEBSD_ISO)
$(KVM_FREEBSD_BASE_DOMAIN).iso: | freebsd/loader.conf
$(KVM_FREEBSD_BASE_DOMAIN).iso: | freebsd/base.conf
	cp $(KVM_FREEBSD_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		freebsd/base.conf \
		> $(KVM_FREEBSD_BASE_DOMAIN).conf
	growisofs -M $@.tmp -l -R \
		-input-charset utf-8 \
		-graft-points \
		/boot/loader.conf=freebsd/loader.conf \
		/etc/installerconfig=$(KVM_FREEBSD_BASE_DOMAIN).conf
	mv $@.tmp $@


#
# Linux
#
# - actually fedora, but not leading edge
#
# - since kickstart is used this is pretty straight forward
#
#   For instance: Fedora-Server-dvd-x86_64-36-1.5.iso
#

KVM_LINUX_RELEASE ?= 41
KVM_LINUX_BUILD ?= 1.4
KVM_LINUX_OSINFO   ?= $(strip $(shell osinfo-query -f short-id os | grep ' fedora' | sort -V | tail -1))

KVM_LINUX_URL ?= https://download.fedoraproject.org/pub/fedora/linux/releases/$(KVM_LINUX_RELEASE)/Server/x86_64/iso
KVM_LINUX_ISO ?= $(KVM_POOLDIR)/Fedora-Server-dvd-x86_64-$(KVM_LINUX_RELEASE)-$(KVM_LINUX_BUILD).iso
KVM_LINUX_ISO_HASH ?= SHA256
KVM_LINUX_ISO_CKSUM ?= 6037e489103401a6ad4e54a4bcb2df7525693bdc3f2ce4aa895838b65647e551
KVM_LINUX_ISO_URL ?= $(KVM_LINUX_URL)/$(notdir $(KVM_LINUX_ISO))

KVM_LINUX_KICKSTART_FILE ?= linux/base.ks

ifneq ($(KVM_LINUX_ISO),$(KVM_FEDORA_ISO))
$(KVM_LINUX_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_LINUX_ISO_URL) $(KVM_LINUX_ISO_HASH) $(KVM_LINUX_ISO_CKSUM)
endif

KVM_LINUX_VIRT_INSTALL_FLAGS = \
	--location=$(KVM_LINUX_ISO) \
	--initrd-inject=$(KVM_LINUX_BASE_DOMAIN).ks \
	--extra-args="inst.ks=file:/$(notdir $(KVM_LINUX_BASE_DOMAIN).ks) console=ttyS0,115200 net.ifnames=0 biosdevname=0 inst.notmux"

$(KVM_LINUX_BASE_DOMAIN): $(KVM_LINUX_ISO)
$(KVM_LINUX_BASE_DOMAIN): | $(KVM_LINUX_KICKSTART_FILE)
$(KVM_LINUX_BASE_DOMAIN): | $(KVM_LINUX_BASE_DOMAIN).ks

$(KVM_LINUX_BASE_DOMAIN).ks: | $(KVM_LINUX_KICKSTART_FILE)
	$(KVM_TRANSMOGRIFY) \
		-e 's;@@PLATFORM@@;linux;' \
		$(KVM_LINUX_KICKSTART_FILE) \
		> $@.tmp
	mv $@.tmp $@


#
# NetBSD
#
# - track leading edge
#
# - needs a second serial console boot iso
#
# - use what ever version libvirt supports

KVM_NETBSD_MACHINE = amd64
KVM_NETBSD_RELEASE ?= NetBSD-10.1
KVM_NETBSD_URL ?= https://cdn.netbsd.org/pub/NetBSD/$(KVM_NETBSD_RELEASE)
KVM_NETBSD_OSINFO  ?= $(strip $(shell osinfo-query -f short-id os | grep ' netbsd' | sort -V | tail -1))

KVM_NETBSD_INSTALL_ISO ?= $(KVM_POOLDIR)/$(KVM_NETBSD_RELEASE)-$(KVM_NETBSD_MACHINE).iso
KVM_NETBSD_INSTALL_ISO_HASH = SHA512
KVM_NETBSD_INSTALL_ISO_CKSUM ?= 7a5e5071307e1795885ffc6e1b8aac465082c21c8b79f4c9b4103ef44e4f2da45477299d213ae0093f6534dc99dc2bbf78f41e9dd556c72a02516068bf43fe49

KVM_NETBSD_INSTALL_ISO_URL ?= $(KVM_NETBSD_URL)/images/$(notdir $(KVM_NETBSD_INSTALL_ISO))

# give downloaded ISO a unique name
KVM_NETBSD_BOOT_ISO ?= $(KVM_POOLDIR)/$(KVM_NETBSD_RELEASE)-$(KVM_NETBSD_MACHINE)-boot-com.iso
KVM_NETBSD_BOOT_ISO_HASH = SHA512
KVM_NETBSD_BOOT_ISO_CKSUM ?= 63341588599eb1e30c744cebdb30699fac159d777672c8948fb841aba99ca83d9eb40592ed21118884af13481e8dbed26583e0d87f548ee400efbb1d7c17c71f

KVM_NETBSD_BOOT_ISO_URL ?= $(KVM_NETBSD_URL)/$(KVM_NETBSD_MACHINE)/installation/cdrom/boot-com.iso

$(KVM_NETBSD_INSTALL_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_NETBSD_INSTALL_ISO_URL) $(KVM_NETBSD_INSTALL_ISO_HASH) $(KVM_NETBSD_INSTALL_ISO_CKSUM)
$(KVM_NETBSD_BOOT_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_NETBSD_BOOT_ISO_URL) $(KVM_NETBSD_BOOT_ISO_HASH) $(KVM_NETBSD_BOOT_ISO_CKSUM)

KVM_NETBSD_VIRT_INSTALL_FLAGS = \
	--cdrom=$(KVM_NETBSD_BOOT_ISO) \
	--disk=path=$(KVM_NETBSD_BASE_DOMAIN).iso,readonly=on,device=cdrom

$(KVM_NETBSD_BASE_DOMAIN): $(KVM_NETBSD_BOOT_ISO)
$(KVM_NETBSD_BASE_DOMAIN): $(KVM_NETBSD_BASE_DOMAIN).iso

$(KVM_NETBSD_BASE_DOMAIN).iso: $(KVM_NETBSD_INSTALL_ISO)
$(KVM_NETBSD_BASE_DOMAIN).iso: | netbsd/base.sh
	cp $(KVM_NETBSD_INSTALL_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		netbsd/base.sh \
		> $(KVM_NETBSD_BASE_DOMAIN).sh
	: this mangles file/directory names
	growisofs -M $@.tmp -l \
		-input-charset utf-8 \
		-graft-points \
		/base.sh=$(KVM_NETBSD_BASE_DOMAIN).sh
	mv $@.tmp $@


#
# OpenBSD
#
# - track leading edge
#
# - the downloaded ISO needs mangling
#
# - sources are in separate tarballs
#
# - use latest OS libvirt supports
#

# Give the OpenBSD ISO a meaningful name.

KVM_OPENBSD_ISO_RELEASE ?= 7.7
KVM_OPENBSD_OSINFO ?= $(strip $(shell osinfo-query -f short-id os | grep ' openbsd' | sort -V | tail -1))

KVM_OPENBSD_URL ?= https://cdn.openbsd.org/pub/OpenBSD/$(KVM_OPENBSD_ISO_RELEASE)/amd64/

# not openbsd... as gets deleted by rm openbsd.*
KVM_OPENBSD_ISO = $(KVM_POOLDIR)/OpenBSD-$(KVM_OPENBSD_ISO_RELEASE)-install.iso
KVM_OPENBSD_ISO_HASH ?= SHA256
KVM_OPENBSD_ISO_CKSUM ?= da0106e39463f015524dca806f407c37a9bdd17e6dfffe533b06a2dd2edd8a27
# note: need to strip "." from version as upstream ISO file omits it
KVM_OPENBSD_ISO_URL ?= $(KVM_OPENBSD_URL)/install$(subst .,,$(KVM_OPENBSD_ISO_RELEASE)).iso

$(KVM_OPENBSD_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_OPENBSD_ISO_URL) $(KVM_OPENBSD_ISO_HASH) $(KVM_OPENBSD_ISO_CKSUM)

KVM_OPENBSD_VIRT_INSTALL_FLAGS = \
	--disk path=$(KVM_OPENBSD_BASE_DOMAIN).iso,readonly=on,device=cdrom,target.bus=sata \
	--install bootdev=cdrom

$(KVM_OPENBSD_BASE_DOMAIN): $(KVM_OPENBSD_BASE_DOMAIN).iso

$(KVM_OPENBSD_BASE_DOMAIN).iso: $(KVM_OPENBSD_ISO)
$(KVM_OPENBSD_BASE_DOMAIN).iso: | openbsd/base.conf
$(KVM_OPENBSD_BASE_DOMAIN).iso: | openbsd/boot.conf
$(KVM_OPENBSD_BASE_DOMAIN).iso: | openbsd/base.sh
$(KVM_OPENBSD_BASE_DOMAIN).iso: | openbsd/base.disk
	cp $(KVM_OPENBSD_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		openbsd/base.sh \
		> $(KVM_OPENBSD_BASE_DOMAIN).sh
	: boot.conf sets up a serial console
	: base.conf configures the installer
	: base.sh gets run by base.py after boot
	growisofs -M $@.tmp -l -R \
		-input-charset utf-8 \
		-graft-points \
		/base.conf=openbsd/base.conf \
		/etc/boot.conf=openbsd/boot.conf \
		/base.sh=$(KVM_OPENBSD_BASE_DOMAIN).sh \
		/base.disk=openbsd/base.disk
	mv $@.tmp $@

##
## Upgrade the base domain: create a clone, install any missing
## packages and upgrade any packages that are out-of-date.
##
## While the script is running only /pool and /bench (pointing into
## this repo) are accessible (/source and /testing which may point
## elsewhere are not accessible, see above and below).
##
## The reverse of UPGRADE is DOWNGRADE

KVM_UPGRADE_CPUS = 1
KVM_UPGRADE_MEMORY ?= 2048

.PHONY: kvm-upgrade kvm-downgrade
kvm-upgrade: $(patsubst %, kvm-upgrade-%, $(KVM_OS))
kvm-downgrade: $(patsubst %, kvm-downgrade-%, $(KVM_PLATFORMS))

$(patsubst %, kvm-upgrade-%, $(KVM_PLATFORMS)): \
kvm-upgrade-%: kvm-downgrade-%
	: $@ build a-new
	$(MAKE) $(KVM_$($*)_UPGRADE_DOMAIN)

$(patsubst %, kvm-downgrade-%, $(KVM_PLATFORMS)): \
kvm-downgrade-%: kvm-uninstall-%
	: $@=$*
	./kvm-uninstall-domain.sh $(KVM_$($*)_UPGRADE_DOMAIN)
	: delete generated dependencies missed by above
	rm -f $(KVM_$($*)_UPGRADE_DOMAIN).*
	rm -f $(KVM_$($*)_UPGRADE_DOMAIN)

$(KVM_UPGRADE_DOMAINS): \
$(KVM_UPGRADEDIR)/$(KVM_PREFIX)%-upgrade: \
		$(KVM_BASEDIR)/$(KVM_PREFIX)%-base \
		| \
		$(KVM_UPGRADEDIR)/ \
		%/upgrade.sh \
		$(KVM_HOST_OK)
	: @=$@ *=$*
	./kvm-uninstall-domain.sh $@
	$(QEMU_IMG) create -f qcow2 -F qcow2 -b $<.qcow2 $@.qcow2
	$(VIRT_INSTALL) \
		$(VIRT_INSTALL_FLAGS) \
		--vcpus=$(call kvm-flag-value, KVM_UPGRADE_CPUS) \
		--memory=$(call kvm-flag-value, KVM_UPGRADE_MEMORY) \
		--name=$(notdir $@) \
		--osinfo=$(KVM_$($*)_OSINFO) \
		--disk=cache=writeback,path=$@.qcow2 \
		$(VIRT_POOLDIR) \
		$(VIRT_BENCHDIR) \
		--import \
		--noautoconsole
	: Copy/transmogrify upgrade.sh in this directory, KVM_BENCHDIR,
	: to KVM_POOLDIR where it can be run from within the VM.
	: Do not use transmogrify.sh from KVM_TESTINGDIR where tests live,
	: or KVM_SOURCEDIR where pluto sources live.
	$(KVM_TRANSMOGRIFY) \
		-e 's;@@DOMAIN@@;$(notdir $@);' \
		$*/upgrade.sh \
		> $@.sh
	$(KVMSH) $(notdir $@) -- \
		/bin/sh -x /pool/$(notdir $@).sh $(KVM_$($*)_UPGRADE_FLAGS)
	: only shutdown after upgrade succeeds
	$(KVMSH) --shutdown $(notdir $@)
	touch $@

KVM_LINUX_UPGRADE_FLAGS ?= $(KVM_LINUX_INSTALL_PACKAGES) -- $(KVM_LINUX_UPGRADE_PACKAGES)

##
## Create the os domain by transmogrifying the updated domain.
##
## This also makes /source $(KVM_SOURCEDIR) and /testing
## $(KVM_TESTINGDIR) available to the VM.  Setting these during
## transmogrify means changing them only requires a re-transmogrify
## and not a full domain rebuild.
##
## The reverse of TRANSMOGRIFY is UNINSTALL

.PHONY: kvm-transmogrify kvm-uninstall
kvm-transmogrify: $(patsubst %, kvm-transmogrify-%, $(KVM_OS))
kvm-uninstall: $(patsubst %, kvm-uninstall-%, $(KVM_PLATFORMS))

$(patsubst %, kvm-transmogrify-%, $(KVM_PLATFORMS)): \
kvm-transmogrify-%: kvm-uninstall-%
	: $@
	$(MAKE) $(KVM_$($*)_BUILD_DOMAIN)

$(patsubst %, kvm-uninstall-%, $(KVM_PLATFORMS)): \
kvm-uninstall-%:
	: $@=$*
	./kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	./kvm-uninstall-domain.sh $(KVM_$($*)_BUILD_DOMAIN)
	: delete generated dependencies missed by above
	rm -f $(KVM_$($*)_BUILD_DOMAIN).*
	rm -f $(KVM_$($*)_BUILD_DOMAIN)
	: transmogrify.sh is in /pool
	rm -f $(KVM_POOLDIR)/$(KVM_PREFIX)$(*).*

# start at 2gb and go up
KVM_BUILD_CPUS = $(KVM_WORKERS)
KVM_BUILD_MEMORY ?= $(shell expr 1792 + $(KVM_BUILD_CPUS) \* 256 )

$(KVM_BUILD_DOMAINS): \
$(KVM_BUILDDIR)/$(KVM_PREFIX)%: \
		$(KVM_UPGRADEDIR)/$(KVM_PREFIX)%-upgrade \
		| \
		%/transmogrify.sh \
		$(KVM_BUILDDIR)/ \
		$(KVM_HOST_OK)
	: @=$@ *=$*
	./kvm-uninstall-domain.sh $@
	$(QEMU_IMG) create -f qcow2 -F qcow2 -b $<.qcow2 $@.qcow2
	: Include TESTINGDIR
	: - fedora runs chcon TESTINGDIR
	: - BSDs need to setup TESTINGDIR NFS mount point
	$(VIRT_INSTALL) \
		$(VIRT_INSTALL_FLAGS) \
		--vcpus=$(call kvm-flag-value, KVM_BUILD_CPUS) \
		--memory=$(call kvm-flag-value, KVM_BUILD_MEMORY) \
		--name=$(notdir $@) \
		--osinfo=$(KVM_$($*)_OSINFO) \
		--disk=cache=writeback,path=$@.qcow2 \
		$(VIRT_BENCHDIR) \
		$(VIRT_POOLDIR) \
		$(VIRT_SOURCEDIR) \
		$(VIRT_TESTINGDIR) \
		--import \
		--noautoconsole
	: Copy/transmogrify transmogrify.sh in this directory, KVM_BENCHDIR,
	: to KVM_POOLDIR where it can be run from within the VM.
	: Do not use transmogrify.sh from KVM_TESTINGDIR where tests live,
	: or KVM_SOURCEDIR where pluto sources live.
	$(KVM_TRANSMOGRIFY) \
		-e 's;@@DOMAIN@@;$(notdir $@);' \
		-e 's;@@SOURCEDIR@@;$(KVM_SOURCEDIR);' \
		-e 's;@@TESTINGDIR@@;$(KVM_TESTINGDIR);' \
		-e 's;@@PLATFORM@@;$*;' \
		$*/transmogrify.sh \
		> $(KVM_POOLDIR)/$(KVM_PREFIX)$(*).transmogrify.sh
	$(KVMSH) $(notdir $@) -- \
		/bin/sh -x /pool/$(notdir $@).transmogrify.sh $(KVM_$($*)_TRANSMOGRIFY_FLAGS)
	: only shutdown after transmogrify succeeds
	$(KVMSH) --shutdown $(notdir $@)
	touch $@

KVM_FEDORA_TRANSMOGRIFY_FILES += $(wildcard fedora/network/*.network)
KVM_LINUX_TRANSMOGRIFY_FILES += $(wildcard linux/network/*.network)
KVM_FREEBSD_TRANSMOGRIFY_FILES += freebsd/rc.conf
KVM_NETBSD_TRANSMOGRIFY_FILES += netbsd/rc.local
KVM_OPENBSD_TRANSMOGRIFY_FILES += openbsd/rc.local


##
## Build/Install libreswan into the build domain.
##

# Notice how the <<gmake base>> and <<gmake install-base>> rules do
# not shut down the domain.  That is left to the rule creating all the
# test instances.

# First delete all of the build domain's clones.  The build domain
# won't boot when its clones are running.
#
# So that all the INSTALL domains are deleted before the build domain
# is booted, this is done using a series of sub-makes (without this,
# things barf because the build domain things its disk is in use).

# some rules are overwritten below
KVM_INSTALL_PLATFORM += $(filter-out fedora, $(KVM_PLATFORMS))
ifneq ($(KVM_INSTALL_RPM),true)
KVM_INSTALL_PLATFORM += fedora
endif

.PHONY: kvm-build
kvm-build: $(foreach os, $(KVM_OS), kvm-make-install-base-$(os))

$(patsubst %, kvm-make-install-base-%, $(KVM_INSTALL_PLATFORM)): \
kvm-make-install-base-%: $(KVM_BUILDDIR)/$(KVM_PREFIX)%
	: $@ $<
	$(KVMSH) $(KVMSH_FLAGS) \
		--chdir /source \
		$(notdir $<) \
		-- \
		ls \> /dev/null \&\& \
		time gmake install-base $(KVM_MAKEFLAGS) $(KVM_$($*)_MAKEFLAGS) \&\& \
		sync \&\& sync \&\& sync

$(patsubst %, kvm-make-install-all-%, $(KVM_INSTALL_PLATFORM)): \
kvm-make-install-all-%: $(KVM_BUILDDIR)/$(KVM_PREFIX)%
	: $@ $<
	$(KVMSH) $(KVMSH_FLAGS) \
		--chdir /source \
		$(notdir $<) \
		-- \
		ls \> /dev/null \&\& \
		time gmake install $(KVM_MAKEFLAGS) $(KVM_$($*)_MAKEFLAGS) \&\& \
		sync \&\& sync \&\& sync

$(patsubst %, kvm-install-%, $(KVM_PLATFORMS)): \
kvm-install-%:
	: $@
	./kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	$(MAKE) kvm-make-install-base-$*
	$(KVMSH) --shutdown $(KVM_PREFIX)$*
	$(MAKE) $(KVM_$($*)_TEST_DOMAINS)

$(patsubst %, kvm-install-base-%, $(KVM_PLATFORMS)): \
kvm-install-base-%:
	: $@
	./kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	$(MAKE) kvm-make-install-base-$*
	$(KVMSH) --shutdown $(KVM_PREFIX)$*
	$(MAKE) $(KVM_$($*)_TEST_DOMAINS)

$(patsubst %, kvm-install-all-%, $(KVM_PLATFORMS)): \
kvm-install-all-%:
	: $@
	./kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	$(MAKE) kvm-make-install-all-$*
	$(KVMSH) --shutdown $(KVM_PREFIX)$*
	$(MAKE) $(KVM_$($*)_TEST_DOMAINS)

.PHONY: kvm-install
kvm-install: kvm-keys-ok
kvm-install: $(foreach os, $(KVM_OS), kvm-install-$(os))

.PHONY: kvm-install-all
kvm-install-all: kvm-keys-ok
kvm-install-all: $(foreach os, $(KVM_OS), kvm-install-all-$(os))

.PHONY: kvm-install-base
kvm-install-base: kvm-keys-ok
kvm-install-base: $(foreach os, $(KVM_OS), kvm-install-base-$(os))

#
# Create the test domains
#

# Since running a domain will likely modify its .qcow2 disk image
# (changing MTIME), the domain's disk isn't a good indicator that a
# domain needs updating.  Instead use the domain-name to indicate that
# a domain has been created.

# in MiB
KVM_TEST_MEMORY ?= 512

.PRECIOUS: $(KVM_TEST_DOMAINS)

define define-test-domain
  $(addprefix $(1), $(2)): \
		$(KVM_TESTDIR)/$(KVM_PREFIX)$(strip $(3)) \
		| \
		$$(addprefix $(1), $$(KVM_TEST_NETWORK_NAMES)) \
		vm/$(strip $(4)).xml
	: define-test-domain
	:  *=$$*
	:  @=$$@
	:  domain=notdir $$@
	:  test_prefix=$(1)
	:  guest_name=$(2)
	:  platform=$(3)
	:  host_name=$(4)
	:  KVM_OS_TEST_MEMORY=$$(KVM_$($(strip $(3)))_TEST_MEMORY)
	./kvm-uninstall-domain.sh $$@
	: work around virsh leaving a file behind
	rm -f $(KVM_TESTDIR)/$(KVM_PREFIX)$(strip $(3)).qcow2.TRANSIENT-$$(notdir $$@)
	$$(KVM_TRANSMOGRIFY) \
		-e 's;@@DOMAIN@@;$$(notdir $$@);' \
		-e 's;@@SOURCEDIR@@;$$(KVM_SOURCEDIR);' \
		-e 's;@@TESTINGDIR@@;$$(KVM_TESTINGDIR);' \
		-e "s;@@TEST_PREFIX@@;$(notdir $(1));" \
		-e 's;@@GUEST_NAME@@;$(strip $(2));' \
		-e 's;@@PLATFORM@@;$(strip $(3));' \
		-e 's;@@HOST_NAME@@;$(strip $(4));' \
		-e 's;@@MEMORY@@;$$(firstword $$(KVM_$($(strip $(3)))_TEST_MEMORY) $$(KVM_TEST_MEMORY));' \
		vm/$(strip $(4)).xml \
		> '$$@.tmp'
	$$(VIRSH) define $$@.tmp
	mv $$@.tmp $$@
endef

# Generate rules for all combinations, including those not enabled.
# Need to pass platform|host and platform and host as, per below,
# linux domains don't get the linux prefix.

$(foreach prefix, $(KVM_TEST_PREFIXES), \
	$(foreach platform, $(KVM_PLATFORMS), \
		$(foreach host, $(KVM_OS_TEST_HOST_NAMES), \
			$(eval $(call define-test-domain, \
				$(prefix), $(platform)$(host), \
				$(platform), \
				$(host))))))

# generate rules for "linux" hosts
$(foreach prefix, $(KVM_TEST_PREFIXES), \
	$(foreach host, $(KVM_LINUX_TEST_HOST_NAMES), \
		$(eval $(call define-test-domain, \
			$(prefix), $(host), \
			linux, \
			$(host)))))

#
# Get rid of (almost) everything
#
# After running the operation, kvm-install will:
#
# kvm-clean-keys:                                               keys, install
# kvm-clean:                               transmogrify, build, keys, install
# kvm-uninstall:                           transmogrify, build,       install
# kvm-downgrade:                  upgrade, transmogrify, build, keys, install
# kvm-purge:                base, upgrade, transmogrify, build, keys, install
# kvm-demolish:    gateway, base, upgrade, transmogrify, build, keys, install
#
# For kvm-uninstall, instead of trying to uninstall libreswan from the
# build domain, delete both the clones and the build domain and
# $(KVM_KEYS_DOMAIN) the install domains were cloned from.  This way,
# in addition to giving kvm-install a 100% fresh start (no dependence
# on 'make uninstall') the next test run also gets entirely new
# domains.

.PHONY: kvm-shutdown

kvm-shutdown: $(foreach os, $(KVM_OS), kvm-shutdown-$(os))

$(patsubst %, kvm-shutdown-%, $(KVM_PLATFORMS)): \
kvm-shutdown-%:
	: $@=$*
	: $(foreach domain, $(KVM_$($*)_DOMAINS), && $(KVMSH) --shutdown $(notdir $(domain)))

.PHONY: kvm-clean

kvm-clean: kvm-uninstall
kvm-clean: kvm-clean-keys
kvm-clean: kvm-clean-check
	rm -rf OBJ.kvm.*

.PHONY: kvm-uninstall

kvm-uninstall: kvm-uninstall-test-networks

.PHONY: kvm-downgrade

kvm-downgrade: kvm-clean

.PHONY: kvm-purge

kvm-purge: kvm-clean
	rm -f $(KVM_HOST_OK)

.PHONY: kvm-demolish

kvm-demolish: kvm-uninstall-gateway
kvm-demolish: $(foreach os, $(KVM_OS), kvm-demolish-$(os))

$(patsubst %, kvm-demolish-%, $(KVM_PLATFORMS)): \
kvm-demolish-%: kvm-purge-%
	: $@=$*


#
# Create an RPM for the test domains
#

.PHONY: kvm-rpm
kvm-rpm: $(KVM_BUILDDIR)/$(KVM_PREFIX)fedora
	@echo building rpm for libreswan testing
	mkdir -p rpmbuild/SPECS/
	: NOTE: testing/packaging/// and NOT packaging/...
	sed -e "s/@IPSECBASEVERSION@/$(RPM_VERSION)/g" \
		-e "s/^Version:.*/Version: $(RPM_VERSION)/g" \
		-e "s/@@INITSYSTEM@@/$(INITSYSTEM)/g" \
		testing/packaging/fedora/libreswan-testing.spec \
		> rpmbuild/SPECS/libreswan-testing.spec
	mkdir -p rpmbuild/SOURCES
	git archive \
		--format=tar \
		--prefix=$(RPM_PREFIX)/ \
		-o rpmbuild/SOURCES/$(RPM_PREFIX).tar \
		HEAD
	: add Makefile.in.local?
	if [ -a Makefile.inc.local ] ; then \
		tar --transform "s|^|$(RPM_PREFIX)/|" \
			-rf rpmbuild/SOURCES/$(RPM_PREFIX).tar \
			Makefile.inc.local ; \
	fi
	gzip -f rpmbuild/SOURCES/$(RPM_PREFIX).tar
	$(KVMSH) --chdir /source $(notdir $<) -- \
		rpmbuild -D_topdir\\ /source/rpmbuild \
			-ba $(RPM_BUILD_CLEAN) \
			rpmbuild/SPECS/libreswan-testing.spec

ifeq ($(KVM_INSTALL_RPM), true)
.PHONY: kvm-fedora-install
kvm-fedora-install: $(KVM_BUILDDIR)/$(KVM_PREFIX)fedora
	rm -fr rpmbuild/*RPMS
	$(MAKE) kvm-rpm
	$(KVMSH) $(KVMSH_FLAGS) --chdir . $(notdir $<) 'rpm -aq | grep libreswan && rpm -e $$(rpm -aq | grep libreswan) || true'
	$(KVMSH) $(KVMSH_FLAGS) --chdir . $(notdir $<) 'rpm -i /source/rpmbuild/RPMS/x86_64/libreswan*rpm'
	$(KVMSH) $(KVMSH_FLAGS) --chdir . $(notdir $<) 'restorecon /usr/local/sbin /usr/local/libexec/ipsec -Rv'
endif


#
# Some hints
#
# Only what is listed in here is "supported"
#

define kvm-var-value
$(1)=$($(1))
	[$(value $(1))]
endef

define kvm-config

Makefile variables:

$(call kvm-var-value,KVM_POOLDIR)
	directory for storing the shared base VM;
	should be relatively permanent storage
$(call kvm-var-value,KVM_LOCALDIR)
	directory for storing the VMs local to this build tree;
	can be temporary storage (for instance /tmp)

$(call kvm-var-value,KVM_BASEDIR)
$(call kvm-var-value,KVM_UPGRADEDIR)
$(call kvm-var-value,KVM_BUILDDIR)
$(call kvm-var-value,KVM_TESTDIR)

$(call kvm-var-value,KVM_SOURCEDIR)
$(call kvm-var-value,KVM_TESTINGDIR)
$(call kvm-var-value,KVM_WORKERS)

$(call kvm-var-value,KVM_PREFIX)
$(call kvm-var-value,KVM_TEST_PREFIXES)

$(call kvm-var-value,KVM_GROUP)
$(call kvm-var-value,KVM_PIDFILE)
$(call kvm-var-value,KVM_UID)
$(call kvm-var-value,KVM_GID)
$(call kvm-var-value,KVM_CONNECTION)
$(call kvm-var-value,KVM_VIRSH)
	the shared NATting gateway;
	used by the base domain along with any local domains
	when internet access is required

$(call kvm-var-value,KVM_KEYS_DOMAIN)

$(call kvm-var-value,KVM_OS)
$(call kvm-var-value,KVM_PLATFORMS)

$(call kvm-var-value,KVM_MAKEFLAGS)

 $(foreach platform,$(KVM_PLATFORMS),$(call kvm-var-value,KVM_$($(platform))_MAKEFLAGS)$(crlf))

 $(foreach platform,$(KVM_PLATFORMS),$(call kvm-var-value,KVM_$($(platform))_OSINFO)$(crlf))

$(call kvm-var-value,KVM_TEST_HOST_NAMES)
$(call kvm-var-value,KVM_LINUX_TEST_HOST_NAMES)
$(call kvm-var-value,KVM_OS_TEST_HOST_NAMES)

 $(foreach platform,$(KVM_PLATFORMS),$(call kvm-var-value,KVM_$($(platform))_TEST_HOST_NAMES)$(crlf))

$(call kvm-var-value,KVM_TEST_DOMAINS)

 $(foreach platform,$(KVM_PLATFORMS),$(call kvm-var-value,KVM_$($(platform))_TEST_DOMAINS)$(crlf))

$(call kvm-var-value,KVM_BASE_DOMAINS)
$(call kvm-var-value,KVM_UPGRADE_DOMAINS)
$(call kvm-var-value,KVM_BUILD_DOMAINS)
$(call kvm-var-value,KVM_TEST_DOMAINS)

$(call kvm-var-value,KVM_DOMAINS)

 $(foreach platform,$(KVM_PLATFORMS),$(call kvm-var-value,KVM_$($(platform))_DOMAINS)$(crlf))

$(call kvm-var-value,KVM_GATEWAY_ADDRESS)
$(call kvm-var-value,KVM_GATEWAY_NAME)
$(call kvm-var-value,KVM_GATEWAY)

$(call kvm-var-value,KVM_TEST_NETWORK_NAMES)
$(call kvm-var-value,KVM_TEST_NETWORKS)

KVM Domains:

    $(KVM_BASE_DOMAIN)
    | gateway: $(KVM_GATEWAY_NAME)
    | directory: $(KVM_POOLDIR)
    |
    +- $(KVM_KEYS_DOMAIN)
    |  | gateway: $(KVM_GATEWAY_NAME)
    |  | directory: $(KVM_POOLDIR)
    |  |  \
$(foreach prefix,$(KVM_TEST_PREFIXES), \
  \
  $(crlf)$(sp)$(sp)$(sp)$(sp)|$(sp)$(sp)| test group $(prefix) \
  $(crlf)$(sp)$(sp)$(sp)$(sp)|$(sp) +-- \
  $(foreach install,$(KVM_TEST_HOST_NAMES),$(prefix)$(install)) \
  \
  $(crlf)$(sp)$(sp)$(sp)$(sp)|$(sp)$(sp)|$(sp$)$(sp)$(sp) networks: \
  $(foreach network, $(KVM_TEST_SUBNETS),$(prefix)$(network)) \
  \
  $(crlf)$(sp)$(sp)$(sp)$(sp)|$(sp)$(sp)| \
)
endef

define kvm-help

Manually building and modifying the base domain and network:

  Normally kvm-install et.al, below, are sufficient.  However ....

  The first step in setting up the test environment is creating the
  base domain.  The make targets below can be used to step through the
  process of constructing the base domain.  At anytime kvmsh-base can
  be used to log into that domain.

    kvmsh-base

      log into the base domain (if necessary, kickstart it); this will
      not trigger an upgrade or transmogrify

    kvm-downgrade

      revert everything back to the kickstarted base domain; no extra
      packages will have been upgraded and no transmogrification will
      have been performed

      if the base domain doesn't exist it will be created

    kvm-upgrade

      perform an incremental install/upgrade any packages needed by
      libreswan; to force a complete re-install of all packages, first
      kvm-downgrade

      to keep kickstart (which is something of a black box) as simple
      as possible, and to make re-running / debugging the upgrade
      process easier, this step is not embedded in kickstart.

    kvm-transmogrify

      install all the configuration files so that the domain will
      automatically transmogrify from the base domain to a test domain
      during boot

  also:

    kvm-install-gateway
    kvm-uninstall-gateway

      just create the base domain's gateway

      note that uninstalling the gateway also uninstalls the base
      domain (since it depends on the gateway)

Standard targets and operations:

  Delete the installed KVMs and networks so that the next kvm-install
  will create new versions:

    kvm-downgrade:
        - delete test domains
	- delete test build
        - delete test results
        - delete test networks
    kvm-demolish: wipe out a directory
        - delete the base domain
        - delete the gateway

  Manipulating and accessing (logging into) domains:

    kvm-shutdown
        - shutdown all domains

  To build or delete the keys used when testing:

    kvm-keys (kvm-clean-keys)
        - use the local build domain to create the test keys

  To set things up for a test run:

    kvm-install:

      build / install (or update) everything needed for a test run

    kvm-uninstall:

      Uninstall libreswan from the the test domains (cheats by
      deleting the build and test domains).

      Doesn't touch the test results

    kvm-clean:

      cleans the directory of the build, test results, and test
      domains ready for a new run

  To run the testsuite against libreswan installed on the test domains
  (see "make kvm-install" above):

    kvm-check         - run all GOOD tests against the
                        previously installed libreswan
    kvm-check KVM_TESTS+=testing/pluto/basic-pluto-0[0-1]
                      - run test matching the pattern
    kvm-check KVM_TEST_FLAGS='--test-status "good|wip"'
                      - run both good and wip tests
    kvm-recheck       - like kvm-check but skip tests that
                        passed during the previous kvm-check
    kvm-check-clean   - delete the test OUTPUT/ directories

    distclean         - scrubs the source tree (but don't touch the KVMS)

    kvm-status        - prints PS for the currently running tests
    kvm-kill          - kill the currently running tests

  To analyze test results:

    kvm-results       - list the tests and their results
                        compare against KVM_BASELINE when defined
    kvm-diffs         - list the tests and their differences
                        compare against KVM_BASELINE when defined

endef

.PHONY: kvm-help
kvm-help:
	$(info $(kvm-help))
	$(info For more details see "make kvm-config" and "make web-config")

.PHONY: kvm-config
kvm-config:
	$(info $(kvm-config))
