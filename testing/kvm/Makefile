# KVM make targets, for Libreswan
#
# Copyright (C) 2015-2023 Andrew Cagney
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

WEB_REPODIR=$(KVM_RUTDIR)

include ../../mk/web-targets.mk

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
# where things live and what gets created
#
# can be a separate directories; RUT == repo under test; bench ==
# testbench

KVM_RUTDIR ?= $(abs_top_srcdir)
KVM_BENCHDIR ?= $(abs_top_srcdir)
KVM_SOURCEDIR ?= $(KVM_RUTDIR)
KVM_TESTINGDIR ?= $(KVM_RUTDIR)/testing
# An educated guess ...
KVM_POOLDIR ?= $(abspath $(abs_top_srcdir)/../pool)
KVM_LOCALDIR ?= $(KVM_POOLDIR)
KVM_SNAPSHOTDIR ?=

#
# Build KVM_TEST_PREFIXES from $(KVM_PREFIX) and $(KVM_WORKERS).  Goal
# is to make KVM_TEST_PREFIXES non-empty.
#
# Compat values:
#   KVM_PREFIX=                 -> KVM_TEST_PREFIXES=$(KVM_LOCALDIR)/
#   KVM_PREFIX=a b              -> KVM_TEST_PREFIXES=$(KVM_LOCALDIR)/a $(KVM_LOCALDIR)/b
#   KVM_PREFIX=a  KVM_WORKERS=1 -> KVM_TEST_PREFIXES=$(KVM_LOCALDIR)/a
#   KVM_PREFIX=a  KVM_WORKERS=2 -> KVM_TEST_PREFIXES=$(KVM_LOCALDIR)/a  $(KVM_LOCALDIR)/a2
#   KVM_PREFIX=a. KVM_WORKERS=3 -> KVM_TEST_PREFIXES=$(KVM_LOCALDIR)/a. $(KVM_LOCALDIR)/a2 $(KVM_LOCALDIR)/a3

KVM_PREFIX ?=
KVM_WORKERS ?= 1
KVM_NUMBERS = $(wordlist 2, $(KVM_WORKERS), 1 2 3 4 5 6 7 8 9)
KVM_TEST_PREFIXES ?= \
	$(if $(wordlist 2, 2, $(KVM_PREFIX)), \
		$(addprefix $(KVM_LOCALDIR)/, $(KVM_PREFIX)), \
	$(if $(wordlist 1, 1, $(KVM_PREFIX)), \
		$(addprefix $(KVM_LOCALDIR)/, $(KVM_PREFIX) $(foreach n, $(KVM_NUMBERS), $(patsubst %., %, $(KVM_PREFIX))$(n))), \
	$(KVM_LOCALDIR)/))

strip-prefix = $(subst '',,$(subst "",,$(1)))


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
KVM_LINUX_NSSDIR ?= $(SYSCONFDIR)/ipsec.d
KVM_LINUX_SD_RESTART_TYPE ?= no
KVM_LINUX_USE_EFENCE ?= true
KVM_LINUX_USE_LABELED_IPSEC ?= true
KVM_LINUX_USE_SECCOMP ?= true

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
	$(call KVM-MAKEFLAG, KVM_USE_CISCO_SPLIT) \
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
VIRT_SOURCEDIR ?= --filesystem=target=source,type=mount,accessmode=squash,source=$(KVM_$($*)_SOURCEDIR)
VIRT_TESTINGDIR ?= --filesystem=target=testing,type=mount,accessmode=squash,source=$(KVM_$($*)_TESTINGDIR)

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
KVM_PLATFORM += alpine
KVM_PLATFORM += debian
KVM_PLATFORM += fedora
KVM_PLATFORM += freebsd
KVM_PLATFORM += linux
KVM_PLATFORM += netbsd
KVM_PLATFORM += openbsd

# this is what is enabled
KVM_OS += $(if $(KVM_ALPINE),  alpine)
KVM_OS += $(if $(KVM_DEBIAN),  debian)
KVM_OS += $(if $(KVM_FEDORA),  fedora)
KVM_OS += $(if $(KVM_FREEBSD), freebsd)
KVM_OS += $(if $(KVM_LINUX),   linux)
KVM_OS += $(if $(KVM_NETBSD),  netbsd)
KVM_OS += $(if $(KVM_OPENBSD), openbsd)

# fed into virt-install --os-variant; linux is fedora!
KVM_ALPINE_OS_VARIANT  ?= $(shell osinfo-query os | awk '/alpinelinux[1-9]/ {print $$1}' | sort -V | tail -1)
KVM_DEBIAN_OS_VARIANT  ?= $(shell osinfo-query os | awk '/debian[1-9]/ {print $$1}' | sort -V | tail -1)
KVM_FEDORA_OS_VARIANT  ?= $(shell osinfo-query os | awk '/fedora[1-9]/ {print $$1}' | sort -V | tail -1)
KVM_FREEBSD_OS_VARIANT ?= $(shell osinfo-query os | awk '/freebsd[1-9]/ {print $$1}' | sort -V | tail -1)
KVM_LINUX_OS_VARIANT   ?= $(shell osinfo-query os | awk '/fedora[1-9]/ {print $$1}' | sort -V | tail -1)
KVM_NETBSD_OS_VARIANT  ?= $(shell osinfo-query os | awk '/netbsd[1-9]/ {print $$1}' | sort -V | tail -1)
KVM_OPENBSD_OS_VARIANT ?= $(shell osinfo-query os | awk '/openbsd[1-9]/ {print $$1}' | sort -V | tail -1)

#
# Hosts and Domains
#
# These make variables roughly follow the naming convention:
#
#  KVM_*_HOST_NAME KVM_*_HOST_NAMES
#
#      the root names without any additions
#
#  KVM_*_DOMAIN_NAME KVM_*_DOMAIN_NAME
#
#      the host names with domain specific prefixes added; this is
#      what is fed to KVM but note ...
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
KVM_OS_TEST_HOST_NAMES = e w n

define domains

KVM_$($(strip $1))_BASE_HOST_NAME    = $(strip $1)-base
KVM_$($(strip $1))_UPGRADE_HOST_NAME = $(strip $1)-upgrade
KVM_$($(strip $1))_BUILD_HOST_NAME   = $(strip $1)
KVM_$($(strip $1))_HOST_NAME         = $(strip $1)

KVM_$($(strip $1))_BASE_DOMAIN_NAME    = $$(addprefix $$(KVM_PREFIX), $$(KVM_$($(strip $1))_BASE_HOST_NAME))
KVM_$($(strip $1))_UPGRADE_DOMAIN_NAME = $$(addprefix $$(KVM_PREFIX), $$(KVM_$($(strip $1))_UPGRADE_HOST_NAME))
KVM_$($(strip $1))_BUILD_DOMAIN_NAME   = $$(addprefix $$(KVM_PREFIX), $$(KVM_$($(strip $1))_BUILD_HOST_NAME))
KVM_$($(strip $1))_DOMAIN_NAME         = $$(addprefix $$(KVM_PREFIX), $$(KVM_$($(strip $1))_HOST_NAME))

KVM_$($(strip $1))_BASE_DOMAIN    = $$(addprefix $$(KVM_POOLDIR)/, $$(KVM_$($(strip $1))_BASE_DOMAIN_NAME))
KVM_$($(strip $1))_UPGRADE_DOMAIN = $$(addprefix $$(KVM_POOLDIR)/, $$(KVM_$($(strip $1))_UPGRADE_DOMAIN_NAME))
KVM_$($(strip $1))_BUILD_DOMAIN   = $$(addprefix $$(KVM_POOLDIR)/, $$(KVM_$($(strip $1))_BUILD_DOMAIN_NAME))
KVM_$($(strip $1))_DOMAIN         = $$(addprefix $$(KVM_POOLDIR)/, $$(KVM_$($(strip $1))_DOMAIN_NAME))

KVM_$($(strip $1))_TEST_HOST_NAMES  ?= $$(addprefix $1, $$(KVM_OS_TEST_HOST_NAMES))
KVM_$($(strip $1))_TEST_DOMAINS      = $$(foreach prefix, $$(KVM_TEST_PREFIXES), $$(addprefix $$(prefix), $$(KVM_$($(strip $1))_TEST_HOST_NAMES)))

KVM_$($(strip $1))_DOMAINS += $$(KVM_$($(strip $1))_BASE_DOMAIN)
KVM_$($(strip $1))_DOMAINS += $$(KVM_$($(strip $1))_BUILD_DOMAIN)
KVM_$($(strip $1))_DOMAINS += $$(KVM_$($(strip $1))_UPGRADE_DOMAIN)
KVM_$($(strip $1))_DOMAINS += $$(KVM_$($(strip $1))_DOMAIN)
KVM_$($(strip $1))_DOMAINS += $$(KVM_$($(strip $1))_TEST_DOMAINS)

endef

$(foreach platform, $(KVM_PLATFORM), \
	$(eval $(call domains, $(platform))))

KVM_BASE_HOST_NAMES   = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_BASE_HOST_NAME))
KVM_BASE_DOMAIN_NAMES = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_BASE_DOMAIN_NAME))
KVM_BASE_DOMAINS      = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_BASE_DOMAIN))

KVM_UPGRADE_HOST_NAMES   = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_UPGRADE_HOST_NAME))
KVM_UPGRADE_DOMAIN_NAMES = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_UPGRADE_DOMAIN_NAME))
KVM_UPGRADE_DOMAINS      = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_UPGRADE_DOMAIN))

KVM_BUILD_HOST_NAMES   = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_BUILD_HOST_NAME))
KVM_BUILD_DOMAIN_NAMES = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_BUILD_DOMAIN_NAME))
KVM_BUILD_DOMAINS      = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_BUILD_DOMAIN))

KVM_TEST_HOST_NAMES   = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_TEST_HOST_NAMES))
KVM_TEST_DOMAINS      = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_TEST_DOMAINS))

KVM_HOST_NAMES += $(KVM_BASE_HOST_NAMES)
KVM_HOST_NAMES += $(KVM_UPGRADE_HOST_NAMES)
KVM_HOST_NAMES += $(KVM_BUILD_HOST_NAMES)
KVM_HOST_NAMES += $(KVM_TEST_HOST_NAMES)

KVM_DOMAIN_NAMES += $(KVM_BASE_DOMAIN_NAMES)
KVM_DOMAIN_NAMES += $(KVM_UPGRADE_DOMAIN_NAMES)
KVM_DOMAIN_NAMES += $(KVM_BUILD_DOMAIN_NAMES)
KVM_DOMAIN_NAMES += $(notdir $(KVM_TEST_DOMAINS))

KVM_DOMAINS += $(KVM_BASE_DOMAINS)
KVM_DOMAINS += $(KVM_UPGRADE_DOMAINS)
KVM_DOMAINS += $(KVM_BUILD_DOMAINS)
KVM_DOMAINS += $(KVM_TEST_DOMAINS)

define kvm-os-dir
KVM_$($(strip $(1)))_SOURCEDIR ?= $$(KVM_SOURCEDIR)
KVM_$($(strip $(1)))_TESTINGDIR ?= $$(KVM_TESTINGDIR)

endef
$(foreach platform, $(KVM_PLATFORM), $(eval $(call kvm-os-dir, $(platform))))

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

KVM_POOLDIR_PREFIX = $(KVM_POOLDIR)/$(KVM_PREFIX)

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

KVM_FRESH_BOOT_FILE = $(KVM_POOLDIR_PREFIX)boot.ok
$(KVM_FRESH_BOOT_FILE): $(firstword $(wildcard /var/run/rc.log /var/log/boot.log))
$(KVM_FRESH_BOOT_FILE): | $(KVM_POOLDIR)
	touch $@

#
# Check that there is enough entoropy for running the domains.
#
# Only do this once per boot.
#

KVM_HOST_ENTROPY_FILE ?= /proc/sys/kernel/random/entropy_avail
KVM_HOST_ENTROPY_OK = $(KVM_POOLDIR_PREFIX)entropy.ok
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
KVM_HOST_QEMUDIR_OK = $(KVM_POOLDIR_PREFIX)qemudir.ok
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

KVM_HOST_NFS_OK = $(KVM_POOLDIR_PREFIX)nfs.ok
$(KVM_HOST_NFS_OK): nfs.sh
$(KVM_HOST_NFS_OK): $(KVM_FRESH_BOOT_FILE)
$(KVM_HOST_NFS_OK): | $(KVM_POOLDIR)
	sh nfs.sh $(KVM_BENCHDIR) $(KVM_POOLDIR) $(KVM_SOURCEDIR) $(KVM_TESTINGDIR)
	touch $@

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

$(KVM_POOLDIR):
	$(info $(kvm-pooldir-info))
	false

ifneq ($(KVM_POOLDIR),$(KVM_LOCALDIR))
$(KVM_LOCALDIR):
	: not -p
	mkdir $(KVM_LOCALDIR)
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

KVM_TEST_STATUS += good
KVM_TEST_STATUS += $(KVM_OS)
KVM_RUN_POST_MORTEM ?=

STRIPPED_KVM_TEST_STATUS = $(subst $(sp),|,$(sort $(KVM_TEST_STATUS)))

KVM_TEST_NAME ?=
STRIPPED_KVM_TEST_NAME = $(subst $(sp),|,$(sort $(KVM_TEST_NAME)))

kvm-test kvm-check kvm-retest kvm-recheck: \
kvm-%: $(KVM_HOST_OK) kvm-keys-ok
	: $@
	: shutdown all the build domains, kvmrunner shuts down the test domains
	$(foreach domain, $(KVM_BUILD_DOMAINS), $(call shutdown-os-domain, $(domain)))
	@$(MAKE) -C $(top_srcdir) --no-print-directory WEB_REPODIR=$(WEB_REPODIR) web-test-prep
	: KVM_TESTS="$(STRIPPED_KVM_TESTS)"
	$(KVMRUNNER) \
		$(if $(KVM_PIDFILE), --pid-file "$(KVM_PIDFILE)") \
		$(foreach prefix,$(KVM_TEST_PREFIXES), --prefix '$(notdir $(prefix))') \
		$(if $(KVM_WORKERS), --workers $(KVM_WORKERS)) \
		$(if $(KVM_TESTINGDIR), --testing-directory $(KVM_TESTINGDIR)) \
		$(if $(WEB_ENABLED), --publish-hash $(WEB_HASH)) \
		$(if $(WEB_ENABLED), --publish-results $(WEB_RESULTSDIR)) \
		$(if $(WEB_ENABLED), --publish-status $(WEB_SUMMARYDIR)/status.json) \
		$(if $(STRIPPED_KVM_TEST_STATUS), --test-status '$(STRIPPED_KVM_TEST_STATUS)') \
		$(if $(STRIPPED_KVM_TEST_NAME), --test-name '$(STRIPPED_KVM_TEST_NAME)') \
		$(if $(KVM_SNAPSHOTDIR), --snapshot-directory $(KVM_SNAPSHOTDIR)) \
		$(if $(filter kvm-re%, $@), --skip passed) \
		$(if $(filter true, $(KVM_RUN_POST_MORTEM)), --run-post-mortem, \
		$(if $(filter false, $(KVM_RUN_POST_MORTEM)), --no-run-post-mortem)) \
		$(KVMRUNNER_FLAGS) \
		$(KVM_TEST_FLAGS) \
		$(STRIPPED_KVM_TESTS)
	@$(MAKE) -C $(top_srcdir) --no-print-directory WEB_REPODIR=$(WEB_REPODIR) web-test-post

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
#
# "dist_certs.py" can't create a directory called "certs/" on a 9p
# mounted file system (OSError: [Errno 13] Permission denied:
# 'certs/').  In fact, "mkdir xxx/ certs/" half fails (only xxx/ is
# created) so it might even be a problem with the mkdir call!  Get
# around this by first creating the certs in /tmp on the guest, and
# then copying back using a tar file.
#
# "dist_certs.py" always writes its certificates to $(dirname $0).
# Get around this by running a copy of dist_certs.py placed in /tmp.

# file to mark keys are up-to-date
KVM_KEYS = $(KVM_TESTINGDIR)/x509/keys/up-to-date
KVM_KEYS_EXPIRATION_DAY = 7
KVM_KEYS_EXPIRED = find $(KVM_TESTINGDIR)/x509/*/ -type f -mtime +$(KVM_KEYS_EXPIRATION_DAY) -ls
KVM_KEYS_DOMAIN = $(addprefix $(KVM_PREFIX), linux)

.PHONY: kvm-keys
kvm-keys:
	: invoke phony target to shut things down and delete old keys
	$(MAKE) kvm-shutdown
	$(MAKE) kvm-clean-keys
	$(MAKE) $(KVM_KEYS)

$(KVM_KEYS): $(KVM_TESTINGDIR)/x509/dist_certs.py
$(KVM_KEYS): $(KVM_TESTINGDIR)/x509/openssl.cnf
$(KVM_KEYS): $(KVM_TESTINGDIR)/x509/strongswan-ec-gen.sh
$(KVM_KEYS): $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/generate-dnssec.sh
$(KVM_KEYS): | $(KVM_POOLDIR)/$(KVM_KEYS_DOMAIN)
$(KVM_KEYS): | $(KVM_HOST_OK)
	:
	: disable FIPS
	:
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) rm -f /etc/system-fips
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) guestbin/fipsoff
	:
	: Copy the scripts to the empty /tmp/x509 directory
	:
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) rm -rf /tmp/x509
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) mkdir /tmp/x509
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) cp -f x509/dist_certs.py /tmp/x509
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) cp -f x509/openssl.cnf /tmp/x509
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) cp -f x509/strongswan-ec-gen.sh /tmp/x509
	:
	: run key scripts in /tmp/x509
	:
	$(KVMSH) --chdir /tmp/x509 $(KVM_KEYS_DOMAIN) ./dist_certs.py
	$(KVMSH) --chdir /tmp/x509 $(KVM_KEYS_DOMAIN) ./strongswan-ec-gen.sh
	:
	: copy the certs from guest to host in a tar ball to avoid 9fs bug
	:
	rm -f $(KVM_POOLDIR_PREFIX)kvm-keys.tar
	$(KVMSH) --chdir /tmp/x509 $(KVM_KEYS_DOMAIN) tar cf kvm-keys.tar '*/' nss-pw
	$(KVMSH) --chdir /tmp/x509 $(KVM_KEYS_DOMAIN) cp kvm-keys.tar /pool/$(KVM_PREFIX)kvm-keys.tar
	cd $(KVM_TESTINGDIR)/x509 && tar xf $(KVM_POOLDIR_PREFIX)kvm-keys.tar
	rm -f $(KVM_POOLDIR_PREFIX)kvm-keys.tar
	:
	: Also regenerate the DNSSEC keys
	:
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) ./baseconfigs/all/etc/bind/generate-dnssec.sh
	:
	: All done.
	:
	$(KVMSH) --shutdown $(KVM_KEYS_DOMAIN)
	touch $@

.PHONY: kvm-clean-keys kvm-keys-clean
kvm-clean-keys kvm-keys-clean:
	: careful output mixed with repo files
	rm -rf $(KVM_TESTINGDIR)/x509/*/
	rm -f $(KVM_TESTINGDIR)/x509/nss-pw
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/signed/*.signed
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/keys/*.key
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/keys/*.private
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/dsset/dsset-*
	rm -f $(KVM_POOLDIR_PREFIX)kvm-keys.tar

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
# Because the gateway is created directly from net/swandefault and
# that file contains hardwired IP addresses, only one is possible.
#
# XXX: Why?  Perhaps it is so that SSHing into the VMs is possible,
# but with lots of VMs what address gets assigned stops being
# predictable.
#
# To avoid the problem where the host has no "default" KVM network
# (there's a strong rumour that libreswan's main testing machine has
# this problem) define a dedicated swandefault gateway.

KVM_GATEWAY_NAME ?= swandefault
KVM_GATEWAY_ADDRESS ?= 192.168.234.1

KVM_GATEWAY = $(KVM_POOLDIR)/$(KVM_GATEWAY_NAME)

$(KVM_GATEWAY): | net/$(KVM_GATEWAY_NAME)
$(KVM_GATEWAY): | $(KVM_POOLDIR)
	./kvm-uninstall-network.sh $@
	$(VIRSH) net-define net/$(KVM_GATEWAY_NAME)
	$(VIRSH) net-autostart $(KVM_GATEWAY_NAME)
	$(VIRSH) net-start $(KVM_GATEWAY_NAME)
	touch $@

#
# Test networks.
#

KVM_TEST_NETWORK_NAMES = $(notdir $(wildcard net/192_*))
KVM_TEST_NETWORKS = \
	$(foreach test_prefix, $(KVM_TEST_PREFIXES), \
		$(foreach test_network, $(KVM_TEST_NETWORK_NAMES), \
			$(test_prefix)$(test_network)))

# <prefix><network>; if <prefix> is blank call it swan<network>*
KVM_BRIDGE_NAME = $(strip $(if $(patsubst 192_%,,$*), \
					$*, \
					swan$(subst _,,$(patsubst %192_,,$*))))

$(KVM_TEST_NETWORKS): \
$(KVM_LOCALDIR)/%: $(KVM_FRESH_BOOT_FILE) | $(KVM_LOCALDIR)
	: @=$@
	: *=$*
	./kvm-uninstall-network.sh $@
	rm -f '$@.tmp'
	echo "<network ipv6='yes'>" 					>> '$@.tmp'
	echo "  <name>$*</name>"					>> '$@.tmp'
	echo "  <bridge name='$(KVM_BRIDGE_NAME)'"			>> '$@.tmp'
	echo "          stp='on' delay='0'/>"				>> '$@.tmp'
	$(if $(patsubst 192_%,, $*), \
	echo "  <!--" 							>> '$@.tmp')
	echo "  <ip address='$(subst _,.,$(patsubst %192_, 192_, $*)).253'/>" >> '$@.tmp'
	$(if $(patsubst 192_%,, $*), \
	echo "    -->" 							>> '$@.tmp')
	echo "</network>"						>> '$@.tmp'
	: create a transient network
	: - immediately started
	: - deleted on reboot
	$(VIRSH) net-create $@.tmp
	mv $@.tmp $@

.PHONY: kvm-install-test-networks kvm-install-gateway
kvm-install-gateway: $(KVM_GATEWAY)
kvm-install-test-networks: $(KVM_TEST_NETWORKS)

.PHONY: kvm-uninstall-test-networks
kvm-uninstall-test-networks:
	./kvm-uninstall-network.sh $(KVM_TEST_NETWORKS)
.PHONY: kvm-uninstall-gateway
kvm-uninstall-gateway:
	./kvm-uninstall-network.sh $(KVM_GATEWAY)

##
##
## Build the base domains
##
##

KVM_BASE_CPUS = 1
KVM_BASE_MEMORY = 2048

.PHONY: kvm-base
kvm-base: $(patsubst %, kvm-base-%, $(KVM_OS))

$(patsubst %, kvm-base-%, $(KVM_PLATFORM)): \
kvm-base-%:
	: $@
	rm -f $(KVM_POOLDIR_PREFIX)$(*)-base
	rm -f $(KVM_POOLDIR_PREFIX)$(*)-base.*
	$(MAKE) $(KVM_POOLDIR_PREFIX)$(*)-base

$(patsubst %, $(KVM_POOLDIR_PREFIX)%-base, $(KVM_PLATFORM)): \
$(KVM_POOLDIR_PREFIX)%-base: \
		| \
		./kvm-install-base.py \
		$(KVM_POOLDIR) \
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
			--os-variant=$(KVM_$($*)_OS_VARIANT) \
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

KVM_ALPINE_VERSION ?= v3.19
KVM_ALPINE_RELEASE ?= 3.19.1
KVM_ALPINE_MACHINE ?= x86

KVM_ALPINE_URL ?= https://dl-cdn.alpinelinux.org/alpine/$(KVM_ALPINE_VERSION)/releases/$(KVM_ALPINE_MACHINE)

KVM_ALPINE_ISO ?= $(KVM_POOLDIR)/alpine-standard-$(KVM_ALPINE_RELEASE)-$(KVM_ALPINE_MACHINE).iso
KVM_ALPINE_ISO_HASH = SHA256
KVM_ALPINE_ISO_CKSUM ?= 6e6f363c56880e137a3bc142884e650376c187bf416b75dcdb67cb848508931b
KVM_ALPINE_ISO_URL ?= $(KVM_ALPINE_URL)/$(notdir $(KVM_ALPINE_ISO))

$(KVM_ALPINE_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_ALPINE_ISO_URL) $(KVM_ALPINE_ISO_HASH) $(KVM_ALPINE_ISO_CKSUM)

KVM_ALPINE_VIRT_INSTALL_FLAGS = \
	--cdrom=$(KVM_ALPINE_ISO)

$(KVM_ALPINE_DOMAIN)-base: $(KVM_ALPINE_ISO)


#
# Debian
#

KVM_DEBIAN_RELEASE ?= 12.2.0
KVM_DEBIAN_BUILD ?= 1

# https://cdimage.debian.org/debian-cd/current/amd64/iso-dvd
KVM_DEBIAN_URL ?= https://cdimage.debian.org/mirror/cdimage/archive/$(KVM_DEBIAN_RELEASE)/amd64/iso-dvd

KVM_DEBIAN_ISO = $(KVM_POOLDIR)/debian-$(KVM_DEBIAN_RELEASE)-amd64-DVD-$(KVM_DEBIAN_BUILD).iso
KVM_DEBIAN_ISO_HASH = SHA256
KVM_DEBIAN_ISO_CKSUM = d969b315de093bc065b4f12ab0dd3f5601b52d67a0c622627c899f1d35834b82
KVM_DEBIAN_ISO_URL ?= $(KVM_DEBIAN_URL)/$(notdir $(KVM_DEBIAN_ISO))

$(KVM_DEBIAN_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_DEBIAN_ISO_URL) $(KVM_DEBIAN_ISO_HASH) $(KVM_DEBIAN_ISO_CKSUM)

$(KVM_DEBIAN_DOMAIN)-base.iso: $(KVM_DEBIAN_ISO)
$(KVM_DEBIAN_DOMAIN)-base.iso: | debian/base.sh
	cp $(KVM_DEBIAN_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		debian/base.sh \
		> $(KVM_DEBIAN_DOMAIN)-base.sh
	growisofs -M $@.tmp -l -R \
		-input-charset utf-8 \
		-graft-points \
		/base.sh=$(KVM_DEBIAN_DOMAIN)-base.sh
	mv $@.tmp $@

$(KVM_DEBIAN_DOMAIN)-base: $(KVM_DEBIAN_DOMAIN)-base.iso

KVM_DEBIAN_VIRT_INSTALL_FLAGS = \
	--location=$(KVM_DEBIAN_DOMAIN)-base.iso \
	--initrd-inject=debian/preseed.cfg \
	--extra-args="console=ttyS0,115200 net.ifnames=0 biosdevname=0"


#
# Fedora
#
# - since kickstart is used this is pretty straight forward
#
# For instance: Fedora-Server-dvd-x86_64-36-1.5.iso

KVM_FEDORA_RELEASE ?= 40
KVM_FEDORA_BUILD ?= 1.14

KVM_FEDORA_URL ?= https://download.fedoraproject.org/pub/fedora/linux/releases/$(KVM_FEDORA_RELEASE)/Server/x86_64/iso

KVM_FEDORA_ISO ?= $(KVM_POOLDIR)/Fedora-Server-dvd-x86_64-$(KVM_FEDORA_RELEASE)-$(KVM_FEDORA_BUILD).iso
KVM_FEDORA_ISO_HASH = SHA256
KVM_FEDORA_ISO_CKSUM ?= 32d9ab1798fc8106a0b06e873bdcd83a3efea8412c9401dfe4097347ed0cfc65
KVM_FEDORA_ISO_URL ?= $(KVM_FEDORA_URL)/$(notdir $(KVM_FEDORA_ISO))

KVM_FEDORA_KICKSTART_FILE ?= fedora/base.ks

$(KVM_FEDORA_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_FEDORA_ISO_URL) $(KVM_FEDORA_ISO_HASH) $(KVM_FEDORA_ISO_CKSUM)

KVM_FEDORA_VIRT_INSTALL_FLAGS = \
	--location=$(KVM_FEDORA_ISO) \
	--initrd-inject=$(KVM_FEDORA_DOMAIN)-base.ks \
	--extra-args="inst.ks=file:/$(notdir $(KVM_FEDORA_DOMAIN)-base.ks) console=ttyS0,115200 net.ifnames=0 biosdevname=0 inst.notmux"

$(KVM_FEDORA_DOMAIN)-base: $(KVM_FEDORA_ISO)
$(KVM_FEDORA_DOMAIN)-base: | $(KVM_FEDORA_KICKSTART_FILE)
$(KVM_FEDORA_DOMAIN)-base: | $(KVM_FEDORA_DOMAIN)-base.ks

$(KVM_FEDORA_DOMAIN)-base.ks: | $(KVM_FEDORA_KICKSTART_FILE)
	$(KVM_TRANSMOGRIFY) \
		$(KVM_FEDORA_KICKSTART_FILE) \
		> $@.tmp
	mv $@.tmp $@

#
# FreeBSD
#
# - modifies the install CD
#
# - uses DISK 1, and not DVD 1, as the former does not contain
#   packages; they will be downloaded later
#

KVM_FREEBSD_RELEASE ?= 14.1

KVM_FREEBSD_URL ?= https://download.freebsd.org/ftp/releases/ISO-IMAGES/$(KVM_FREEBSD_RELEASE)

KVM_FREEBSD_ISO ?= $(KVM_POOLDIR)/FreeBSD-$(KVM_FREEBSD_RELEASE)-RELEASE-amd64-disc1.iso
KVM_FREEBSD_ISO_HASH ?= SHA256
KVM_FREEBSD_ISO_CKSUM ?= 5321791bd502c3714850e79743f5a1aedfeb26f37eeed7cb8eb3616d0aebf86b
KVM_FREEBSD_ISO_URL ?= $(KVM_FREEBSD_URL)/$(notdir $(KVM_FREEBSD_ISO))

$(KVM_FREEBSD_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_FREEBSD_ISO_URL) $(KVM_FREEBSD_ISO_HASH) $(KVM_FREEBSD_ISO_CKSUM)

KVM_FREEBSD_VIRT_INSTALL_FLAGS = \
       --cdrom=$(KVM_FREEBSD_DOMAIN)-base.iso

$(KVM_FREEBSD_DOMAIN)-base: $(KVM_FREEBSD_DOMAIN)-base.iso

$(KVM_FREEBSD_DOMAIN)-base.iso: $(KVM_FREEBSD_ISO)
$(KVM_FREEBSD_DOMAIN)-base.iso: | freebsd/loader.conf
$(KVM_FREEBSD_DOMAIN)-base.iso: | freebsd/base.conf
	cp $(KVM_FREEBSD_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		freebsd/base.conf \
		> $(KVM_FREEBSD_DOMAIN)-base.conf
	growisofs -M $@.tmp -l -R \
		-input-charset utf-8 \
		-graft-points \
		/boot/loader.conf=freebsd/loader.conf \
		/etc/installerconfig=$(KVM_FREEBSD_DOMAIN)-base.conf
	mv $@.tmp $@


#
# Linux
#
# - since kickstart is used this is pretty straight forward
#
# For instance: Fedora-Server-dvd-x86_64-36-1.5.iso

KVM_LINUX_RELEASE ?= 40
KVM_LINUX_BUILD ?= 1.14

KVM_LINUX_URL ?= https://download.fedoraproject.org/pub/fedora/linux/releases/$(KVM_FEDORA_RELEASE)/Server/x86_64/iso

KVM_LINUX_ISO ?= $(KVM_POOLDIR)/Fedora-Server-dvd-x86_64-$(KVM_LINUX_RELEASE)-$(KVM_LINUX_BUILD).iso
KVM_LINUX_ISO_HASH ?= SHA256
KVM_LINUX_ISO_CKSUM ?= 32d9ab1798fc8106a0b06e873bdcd83a3efea8412c9401dfe4097347ed0cfc65
KVM_LINUX_ISO_URL ?= $(KVM_LINUX_URL)/$(notdir $(KVM_LINUX_ISO))

KVM_LINUX_KICKSTART_FILE ?= linux/base.ks

ifneq ($(KVM_LINUX_ISO),$(KVM_FEDORA_ISO))
$(KVM_LINUX_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_LINUX_ISO_URL) $(KVM_LINUX_ISO_HASH) $(KVM_LINUX_ISO_CKSUM)
endif

KVM_LINUX_VIRT_INSTALL_FLAGS = \
	--location=$(KVM_LINUX_ISO) \
	--initrd-inject=$(KVM_LINUX_DOMAIN)-base.ks \
	--extra-args="inst.ks=file:/$(notdir $(KVM_LINUX_DOMAIN)-base.ks) console=ttyS0,115200 net.ifnames=0 biosdevname=0 inst.notmux"

$(KVM_LINUX_DOMAIN)-base: $(KVM_LINUX_ISO)
$(KVM_LINUX_DOMAIN)-base: | $(KVM_LINUX_KICKSTART_FILE)
$(KVM_LINUX_DOMAIN)-base: | $(KVM_LINUX_DOMAIN)-base.ks

$(KVM_LINUX_DOMAIN)-base.ks: | $(KVM_LINUX_KICKSTART_FILE)
	$(KVM_TRANSMOGRIFY) \
		$(KVM_LINUX_KICKSTART_FILE) \
		> $@.tmp
	mv $@.tmp $@


#
# NetBSD
#
# - needs a second serial console boot iso
#

KVM_NETBSD_MACHINE = amd64
KVM_NETBSD_RELEASE ?= NetBSD-10.0
KVM_NETBSD_URL ?= https://cdn.netbsd.org/pub/NetBSD/$(KVM_NETBSD_RELEASE)

KVM_NETBSD_INSTALL_ISO ?= $(KVM_POOLDIR)/$(KVM_NETBSD_RELEASE)-$(KVM_NETBSD_MACHINE).iso
KVM_NETBSD_INSTALL_ISO_HASH = SHA512
KVM_NETBSD_INSTALL_ISO_CKSUM ?= c28620e3e8be9081ad421701a3eec3535cd88e96c1a3e732cb34523c1838fe51b78d87e35fa40db6c11b1788cfeb0badd7da1548e3f956c80bf7db38121747c0

KVM_NETBSD_INSTALL_ISO_URL ?= $(KVM_NETBSD_URL)/images/$(notdir $(KVM_NETBSD_INSTALL_ISO))

# give downloaded ISO a unique name
KVM_NETBSD_BOOT_ISO ?= $(KVM_POOLDIR)/$(KVM_NETBSD_RELEASE)-$(KVM_NETBSD_MACHINE)-boot-com.iso
KVM_NETBSD_BOOT_ISO_HASH = SHA512
KVM_NETBSD_BOOT_ISO_CKSUM ?= a9f7525bb3ca2574e80b3ef658a56c5549958ff923012c7731bd33482d277bcf93c1dc27aaf32454f38d9961ffa40a042dfb0a20757aada5b7dbe11343e2e51f

KVM_NETBSD_BOOT_ISO_URL ?= $(KVM_NETBSD_URL)/$(KVM_NETBSD_MACHINE)/installation/cdrom/boot-com.iso

$(KVM_NETBSD_INSTALL_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_NETBSD_INSTALL_ISO_URL) $(KVM_NETBSD_INSTALL_ISO_HASH) $(KVM_NETBSD_INSTALL_ISO_CKSUM)
$(KVM_NETBSD_BOOT_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_NETBSD_BOOT_ISO_URL) $(KVM_NETBSD_BOOT_ISO_HASH) $(KVM_NETBSD_BOOT_ISO_CKSUM)

KVM_NETBSD_VIRT_INSTALL_FLAGS = \
	--cdrom=$(KVM_NETBSD_BOOT_ISO) \
	--disk=path=$(KVM_NETBSD_DOMAIN)-base.iso,readonly=on,device=cdrom

$(KVM_NETBSD_DOMAIN)-base: $(KVM_NETBSD_BOOT_ISO)
$(KVM_NETBSD_DOMAIN)-base: $(KVM_NETBSD_DOMAIN)-base.iso

$(KVM_NETBSD_DOMAIN)-base.iso: $(KVM_NETBSD_INSTALL_ISO)
$(KVM_NETBSD_DOMAIN)-base.iso: | netbsd/base.sh
	cp $(KVM_NETBSD_INSTALL_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		netbsd/base.sh \
		> $(KVM_NETBSD_DOMAIN)-base.sh
	: this mangles file/directory names
	growisofs -M $@.tmp -l \
		-input-charset utf-8 \
		-graft-points \
		/base.sh=$(KVM_NETBSD_DOMAIN)-base.sh
	mv $@.tmp $@


#
# OpenBSD
#
# - the downloaded ISO needs mangling
# - sources are in separate tarballs
#

# Give the OpenBSD ISO a meaningful name.

KVM_OPENBSD_ISO_RELEASE ?= 7.6

KVM_OPENBSD_URL ?= https://cdn.openbsd.org/pub/OpenBSD/$(KVM_OPENBSD_ISO_RELEASE)/amd64/

# not openbsd... as gets deleted by rm openbsd.*
KVM_OPENBSD_ISO = $(KVM_POOLDIR)/OpenBSD-$(KVM_OPENBSD_ISO_RELEASE)-install.iso
KVM_OPENBSD_ISO_HASH ?= SHA256
KVM_OPENBSD_ISO_CKSUM ?= 60cba8cb391b50bba8fa10fc768bd0529636f5345d82133c93e22c798d8e5269
# note: strip "."; upstream ISO name omits it
KVM_OPENBSD_ISO_URL ?= $(KVM_OPENBSD_URL)/install$(subst .,,$(KVM_OPENBSD_ISO_RELEASE)).iso

$(KVM_OPENBSD_ISO): | $(KVM_POOLDIR)
	$(KVM_GET) $(KVM_OPENBSD_ISO_URL) $(KVM_OPENBSD_ISO_HASH) $(KVM_OPENBSD_ISO_CKSUM)

KVM_OPENBSD_VIRT_INSTALL_FLAGS = \
	--disk path=$(KVM_OPENBSD_DOMAIN)-base.iso,readonly=on,device=cdrom,target.bus=sata \
	--install bootdev=cdrom

$(KVM_OPENBSD_DOMAIN)-base: $(KVM_OPENBSD_DOMAIN)-base.iso

$(KVM_OPENBSD_DOMAIN)-base.iso: $(KVM_OPENBSD_ISO)
$(KVM_OPENBSD_DOMAIN)-base.iso: | openbsd/base.conf
$(KVM_OPENBSD_DOMAIN)-base.iso: | openbsd/boot.conf
$(KVM_OPENBSD_DOMAIN)-base.iso: | openbsd/base.sh
$(KVM_OPENBSD_DOMAIN)-base.iso: | openbsd/base.disk
	cp $(KVM_OPENBSD_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		openbsd/base.sh \
		> $(KVM_OPENBSD_DOMAIN)-base.sh
	: boot.conf sets up a serial console
	: base.conf configures the installer
	: base.sh gets run by base.py after boot
	growisofs -M $@.tmp -l -R \
		-input-charset utf-8 \
		-graft-points \
		/base.conf=openbsd/base.conf \
		/etc/boot.conf=openbsd/boot.conf \
		/base.sh=$(KVM_OPENBSD_DOMAIN)-base.sh \
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

KVM_UPGRADE_CPUS = 1
KVM_UPGRADE_MEMORY = 2048

.PHONY: kvm-upgrade
kvm-upgrade: $(patsubst %, kvm-upgrade-%, $(KVM_OS))

$(patsubst %, kvm-upgrade-%, $(KVM_PLATFORM)): \
kvm-upgrade-%:
	: $@
	rm -f $(KVM_POOLDIR_PREFIX)$(*)-upgrade
	rm -f $(KVM_POOLDIR_PREFIX)$(*)-upgrade.*
	$(MAKE) $(KVM_POOLDIR_PREFIX)$(*)-upgrade

$(patsubst %, $(KVM_POOLDIR_PREFIX)%-upgrade, $(KVM_PLATFORM)): \
$(KVM_POOLDIR_PREFIX)%-upgrade: \
		$(KVM_POOLDIR_PREFIX)%-base \
		| \
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
		--os-variant=$(KVM_$($*)_OS_VARIANT) \
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

.PHONY: kvm-transmogrify
kvm-transmogrify: $(patsubst %, kvm-transmogrify-%, $(KVM_OS))

$(patsubst %, kvm-transmogrify-%, $(KVM_PLATFORM)): \
kvm-transmogrify-%:
	: $@
	rm -f $(KVM_POOLDIR_PREFIX)$(*)
	rm -f $(KVM_POOLDIR_PREFIX)$(*).*
	$(MAKE) $(KVM_POOLDIR_PREFIX)$(*)

KVM_BUILD_CPUS = $(KVM_WORKERS)
KVM_BUILD_MEMORY = $(shell expr 2048 + \( $(KVM_BUILD_CPUS) - 1 \) \* 256 )

$(patsubst %, $(KVM_POOLDIR_PREFIX)%, $(KVM_PLATFORM)): \
$(KVM_POOLDIR_PREFIX)%: \
		$(KVM_POOLDIR_PREFIX)%-upgrade \
		| \
		%/transmogrify.sh \
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
		--os-variant=$(KVM_$($*)_OS_VARIANT) \
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
		-e 's;@@SOURCEDIR@@;$(KVM_$($*)_SOURCEDIR);' \
		-e 's;@@TESTINGDIR@@;$(KVM_$($*)_TESTINGDIR);' \
		$*/transmogrify.sh \
		> $@.transmogrify.sh
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
KVM_INSTALL_PLATFORM += $(filter-out fedora, $(KVM_PLATFORM))
ifneq ($(KVM_INSTALL_RPM),true)
KVM_INSTALL_PLATFORM += fedora
endif

.PHONY: kvm-build
kvm-build: $(foreach os, $(KVM_OS), kvm-make-install-base-$(os))

$(patsubst %, kvm-make-install-base-%, $(KVM_INSTALL_PLATFORM)): \
kvm-make-install-base-%: $(KVM_POOLDIR_PREFIX)%
	: $@ $<
	$(KVMSH) $(KVMSH_FLAGS) \
		--chdir /source \
		$(notdir $<) \
		-- \
		ls \> /dev/null \&\& \
		time gmake install-base $(KVM_MAKEFLAGS) $(KVM_$($*)_MAKEFLAGS) \&\& \
		sync \&\& sync \&\& sync

$(patsubst %, kvm-make-install-all-%, $(KVM_INSTALL_PLATFORM)): \
kvm-make-install-all-%: $(KVM_POOLDIR_PREFIX)%
	: $@ $<
	$(KVMSH) $(KVMSH_FLAGS) \
		--chdir /source \
		$(notdir $<) \
		-- \
		ls \> /dev/null \&\& \
		time gmake install $(KVM_MAKEFLAGS) $(KVM_$($*)_MAKEFLAGS) \&\& \
		sync \&\& sync \&\& sync

$(patsubst %, kvm-install-%, $(KVM_PLATFORM)): \
kvm-install-%:
	: $@
	./kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	$(MAKE) kvm-make-install-base-$*
	$(KVMSH) --shutdown $(KVM_PREFIX)$*
	$(MAKE) $(KVM_$($*)_TEST_DOMAINS)

$(patsubst %, kvm-install-base-%, $(KVM_PLATFORM)): \
kvm-install-base-%:
	: $@
	./kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	$(MAKE) kvm-make-install-base-$*
	$(KVMSH) --shutdown $(KVM_PREFIX)$*
	$(MAKE) $(KVM_$($*)_TEST_DOMAINS)

$(patsubst %, kvm-install-all-%, $(KVM_PLATFORM)): \
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

.PRECIOUS: $(KVM_TEST_DOMAINS)

define define-test-domain
  $(addprefix $(1), $(2)): \
		$(KVM_POOLDIR_PREFIX)$(strip $(3)) \
		| \
		$$(addprefix $(1), $$(KVM_TEST_NETWORK_NAMES)) \
		vm/$(strip $(4)).xml
	: define-test-domain
	:  *=$$*
	:  @=$$@
	:  test_prefix=$(1)
	:  domain=$(2)
	:  platform=$(3)
	:  host=$(4)
	./kvm-uninstall-domain.sh $$@
	$$(QEMU_IMG) create -f qcow2 -F qcow2 -b $(KVM_POOLDIR_PREFIX)$(strip $(3)).qcow2 $$@.qcow2
	$$(KVM_TRANSMOGRIFY) \
		-e 's;@@DOMAIN@@;$$(notdir $$@);' \
		-e 's;@@SOURCEDIR@@;$$(KVM_$($(strip $(3)))_SOURCEDIR);' \
		-e 's;@@TESTINGDIR@@;$$(KVM_$($(strip $(3)))_TESTINGDIR);' \
		-e "s;@@TEST_PREFIX@@;$(notdir $(1));" \
		vm/$(strip $(4)).xml \
		> '$$@.tmp'
	$$(VIRSH) define $$@.tmp
	mv $$@.tmp $$@
endef

# Generate rules for all combinations, including those not enabled.
# Need to pass platform|host and platform and host as, per below,
# linux domains don't get the linux prefix.

$(foreach prefix, $(KVM_TEST_PREFIXES), \
	$(foreach platform, $(KVM_PLATFORM), \
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

$(patsubst %, kvm-shutdown-%, $(KVM_PLATFORM)): \
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
kvm-uninstall: $(foreach os, $(KVM_OS), kvm-uninstall-$(os))

$(patsubst %, kvm-uninstall-%, $(KVM_PLATFORM)): \
kvm-uninstall-%:
	: $@=$*
	./kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	./kvm-uninstall-domain.sh $(KVM_$($*)_BUILD_DOMAIN)

.PHONY: kvm-downgrade

kvm-downgrade: kvm-clean
kvm-downgrade: $(foreach os, $(KVM_OS), kvm-downgrade-$(os))

$(patsubst %, kvm-downgrade-%, $(KVM_PLATFORM)): \
kvm-downgrade-%: kvm-uninstall-%
	: $@=$*
	./kvm-uninstall-domain.sh $(KVM_$($*)_UPGRADE_DOMAIN)

.PHONY: kvm-purge

kvm-purge: kvm-clean
kvm-purge: $(foreach os, $(KVM_OS), kvm-purge-$(os))
	rm -f $(KVM_HOST_OK)

$(patsubst %, kvm-purge-%, $(KVM_PLATFORM)): \
kvm-purge-%: kvm-downgrade-%
	: $@=$*
	./kvm-uninstall-domain.sh $(KVM_$($*)_BASE_DOMAIN)

.PHONY: kvm-demolish

kvm-demolish: kvm-uninstall-gateway
kvm-demolish: $(foreach os, $(KVM_OS), kvm-demolish-$(os))

$(patsubst %, kvm-demolish-%, $(KVM_PLATFORM)): \
kvm-demolish-%: kvm-purge-%
	: $@=$*


#
# Create an RPM for the test domains
#

.PHONY: kvm-rpm
kvm-rpm: $(KVM_POOLDIR_PREFIX)fedora
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
kvm-fedora-install: $(KVM_POOLDIR_PREFIX)fedora
	rm -fr rpmbuild/*RPMS
	$(MAKE) kvm-rpm
	$(KVMSH) $(KVMSH_FLAGS) --chdir . $(notdir $<) 'rpm -aq | grep libreswan && rpm -e $$(rpm -aq | grep libreswan) || true'
	$(KVMSH) $(KVMSH_FLAGS) --chdir . $(notdir $<) 'rpm -i /source/rpmbuild/RPMS/x86_64/libreswan*rpm'
	$(KVMSH) $(KVMSH_FLAGS) --chdir . $(notdir $<) 'restorecon /usr/local/sbin /usr/local/libexec/ipsec -Rv'
endif

#
# kvmsh-HOST
#
# Map this onto the first domain group.  Logging into the other
# domains can be done by invoking kvmsh.py directly.
#

$(patsubst %, kvmsh-%, $(filter-out $(KVM_DOMAIN_NAMES), $(KVM_HOST_NAMES))): \
kvmsh-%: kvmsh-$(KVM_PREFIX)%

$(patsubst %, kvmsh-%, $(KVM_BASE_DOMAIN_NAMES)) : \
kvmsh-%: $(KVM_POOLDIR)/% | $(KVM_HOST_OK)
	$(KVMSH) $(KVMSH_FLAGS) $* $(KVMSH_COMMAND)

$(patsubst %, kvmsh-%, $(KVM_UPGRADE_DOMAIN_NAMES)) : \
kvmsh-%: $(KVM_POOLDIR)/% | $(KVM_HOST_OK)
	$(KVMSH) $(KVMSH_FLAGS) $* $(KVMSH_COMMAND)

$(patsubst %, kvmsh-%, $(KVM_BUILD_DOMAIN_NAMES)) : \
kvmsh-%: $(KVM_POOLDIR)/% | $(KVM_HOST_OK)
	$(KVMSH) $(KVMSH_FLAGS) $* $(KVMSH_COMMAND)

$(patsubst %, kvmsh-%, $(notdir $(KVM_TEST_DOMAINS))) : \
kvmsh-%: $(KVM_LOCALDIR)/% | $(KVM_HOST_OK)
	$(KVMSH) $(KVMSH_FLAGS) $* $(KVMSH_COMMAND)


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

$(call kvm-var-value,KVM_SOURCEDIR)

 $(foreach platform,$(KVM_PLATFORM),$(call kvm-var-value,KVM_$($(platform))_SOURCEDIR)$(crlf))

$(call kvm-var-value,KVM_TESTINGDIR)

 $(foreach platform,$(KVM_PLATFORM),$(call kvm-var-value,KVM_$($(platform))_TESTINGDIR)$(crlf))

$(call kvm-var-value,KVM_WORKERS)

$(call kvm-var-value,KVM_PREFIX)
$(call kvm-var-value,KVM_PREFIX)
$(call kvm-var-value,KVM_TEST_PREFIXES)
$(call kvm-var-value,KVM_POOLDIR_PREFIX)

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
$(call kvm-var-value,KVM_PLATFORM)

$(call kvm-var-value,KVM_MAKEFLAGS)

 $(foreach platform,$(KVM_PLATFORM),$(call kvm-var-value,KVM_$($(platform))_MAKEFLAGS)$(crlf))

 $(foreach platform,$(KVM_PLATFORM),$(call kvm-var-value,KVM_$($(platform))_OS_VARIANT)$(crlf))

$(call kvm-var-value,KVM_BASE_HOST_NAMES)

 $(foreach platform,$(KVM_PLATFORM),$(call kvm-var-value,KVM_$($(platform))_BASE_HOST_NAME)$(crlf))

$(call kvm-var-value,KVM_UPGRADE_HOST_NAMES)

 $(foreach platform,$(KVM_PLATFORM),$(call kvm-var-value,KVM_$($(platform))_UPGRADE_HOST_NAME)$(crlf))

$(call kvm-var-value,KVM_BUILD_HOST_NAMES)

 $(foreach platform,$(KVM_PLATFORM),$(call kvm-var-value,KVM_$($(platform))_BUILD_HOST_NAME)$(crlf))

$(call kvm-var-value,KVM_TEST_HOST_NAMES)
$(call kvm-var-value,KVM_OS_TEST_HOST_NAMES)

 $(foreach platform,$(KVM_PLATFORM),$(call kvm-var-value,KVM_$($(platform))_TEST_HOST_NAMES)$(crlf))

$(call kvm-var-value,KVM_HOST_NAMES)

$(call kvm-var-value,KVM_TEST_DOMAINS)

 $(foreach platform,$(KVM_PLATFORM),$(call kvm-var-value,KVM_$($(platform))_TEST_DOMAINS)$(crlf))

$(call kvm-var-value,KVM_BASE_DOMAIN_NAMES)
$(call kvm-var-value,KVM_UPGRADE_DOMAIN_NAMES)
$(call kvm-var-value,KVM_BUILD_DOMAIN_NAMES)

$(call kvm-var-value,KVM_DOMAIN_NAMES)

$(call kvm-var-value,KVM_BASE_DOMAINS)
$(call kvm-var-value,KVM_UPGRADE_DOMAINS)
$(call kvm-var-value,KVM_BUILD_DOMAINS)
$(call kvm-var-value,KVM_TEST_DOMAINS)

$(call kvm-var-value,KVM_DOMAINS)

 $(foreach platform,$(KVM_PLATFORM),$(call kvm-var-value,KVM_$($(platform))_DOMAINS)$(crlf))

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
  $(foreach install,$(KVM_TEST_HOST_NAMES),$(call strip-prefix,$(prefix))$(install)) \
  \
  $(crlf)$(sp)$(sp)$(sp)$(sp)|$(sp)$(sp)|$(sp$)$(sp)$(sp) networks: \
  $(foreach network, $(KVM_TEST_SUBNETS),$(call strip-prefix,$(prefix))$(network)) \
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

    kvmsh-HOST ($(filter-out build, $(KVM_TEST_HOST_NAMES)))
        - use 'virsh console' to login to the given domain
	- for HOST login to the first domain vis:
          $(addprefix $(KVM_PREFIX), HOST)
        - if necessary, create and boot the host
    $(addprefix kvmsh-, $(notdir $(KVM_TEST_DOMAINS)))
        - login to the specific domain
        - if necessary, create and boot the domain

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
