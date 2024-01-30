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
# The guest operating system.
#

include testing/libvirt/fedora/kvm.mk

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
KVM_WGET ?= wget --progress=dot:giga --continue

# While KVM_PREFIX might be empty, KVM_PREFIXES is never empty.
KVM_PREFIX ?=
KVM_PREFIXES ?= $(if $(KVM_PREFIX), $(KVM_PREFIX), '')
KVM_WORKERS ?= 1
#KVM_WORKERS ?= $(shell awk 'BEGIN { c=1 } /cpu cores/ { c=$$4 } END { if (c>1) print c/2; }' /proc/cpuinfo)
#KVM_PYTHON ?= PYTHONPATH=/home/python/pexpect:/home/python/ptyprocess /home/python/v3.8/bin/python3
KVM_PIDFILE ?= kvmrunner.pid
# Current user's UID; and GID used by QEMU
KVM_UID ?= $(shell id -u)
KVM_GID ?= $(shell stat --format=%g $(KVM_HOST_QEMUDIR))

KVM_TRANSMOGRIFY = \
	sed \
	-e 's;@@GATEWAY@@;$(KVM_GATEWAY_ADDRESS);' \
	-e 's;@@BENCHDIR@@;$(KVM_BENCHDIR);' \
	-e 's;@@LOCALDIR@@;$(KVM_LOCALDIR);' \
	-e 's;@@POOLDIR@@;$(KVM_POOLDIR);' \
	-e 's;@@SOURCEDIR@@;$(KVM_SOURCEDIR);' \
	-e 's;@@TESTINGDIR@@;$(KVM_TESTINGDIR);' \
	-e 's;@@USER@@;$(KVM_UID);' \
	-e 's;@@GROUP@@;$(KVM_GID);' \
	-e 's;@@PREFIX@@;$(KVM_FIRST_PREFIX);'

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
#   KVM_FEDORA_ALL_ALGS
#   KVM_ALL_ALGS
#
# In KVM-MAKEFLAG, the macro $(KVM_$($*)_$(strip $(1))) expands to
# $(KVM_<OS>_<FLAG>) and $(KVM_$(strip $(1))) expands to
# $(KVM_<FLAG>).

# On Fedora, overide linux defaults
KVM_FEDORA_NSSDIR ?= $(SYSCONFDIR)/ipsec.d
KVM_FEDORA_SD_RESTART_TYPE ?= no
KVM_FEDORA_USE_EFENCE ?= true
KVM_FEDORA_USE_LABELED_IPSEC ?= true
KVM_FEDORA_USE_SECCOMP ?= true

# from <FLAG> return KVM_<OS>_<FLAG> or KVM_<FLAG>
kvm-flag = \
	$(firstword \
		$(if $(KVM_$($*)_$(strip $(1))), KVM_$($*)_$(strip $(1))) \
		$(if $(KVM_$(strip $(1))),       KVM_$(strip $(1))))

kvm-flag-name = $(call kvm-flag, $(patsubst KVM_%, %, $(1)))
kvm-flag-value = $($(call kvm-flag, $(patsubst KVM_%, %, $(1))))

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
#
# XXX: Ignore KVM_PREFIXES, it is probably going away.

VIRT_INSTALL ?= sudo virt-install
VIRT_CPU ?= --cpu=host-passthrough
VIRT_DISK_SIZE_GB ?= 10
VIRT_RND ?= --rng=type=random,device=/dev/random
VIRT_SECURITY ?= --security=type=static,model=dac,label='$(KVM_UID):$(KVM_GID)',relabel=yes
VIRT_GATEWAY ?= --network=network:$(KVM_GATEWAY_NAME),model=virtio
VIRT_BENCHDIR ?= --filesystem=target=bench,type=mount,accessmode=squash,source=$(KVM_BENCHDIR)
VIRT_POOLDIR ?= --filesystem=target=pool,type=mount,accessmode=squash,source=$(KVM_POOLDIR)
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
KVM_FEDORA ?= true
KVM_FREEBSD ?=
KVM_NETBSD ?=
KVM_OPENBSD ?=

# so that $($*) converts % to upper case
alpine = ALPINE
debian = DEBIAN
fedora = FEDORA
freebsd = FREEBSD
netbsd = NETBSD
openbsd = OPENBSD

# this is what works
KVM_PLATFORM += alpine
KVM_PLATFORM += debian
KVM_PLATFORM += fedora
KVM_PLATFORM += freebsd
KVM_PLATFORM += netbsd
KVM_PLATFORM += openbsd

# this is what is enabled
KVM_OS += $(if $(KVM_ALPINE),  alpine)
KVM_OS += $(if $(KVM_DEBIAN),  debian)
KVM_OS += $(if $(KVM_FEDORA),  fedora)
KVM_OS += $(if $(KVM_FREEBSD), freebsd)
KVM_OS += $(if $(KVM_NETBSD),  netbsd)
KVM_OS += $(if $(KVM_OPENBSD), openbsd)

# fed into virt-install --os-variant
KVM_ALPINE_OS_VARIANT ?= $(shell osinfo-query os | awk '/alpinelinux[1-9]/ {print $$1}' | sort -V | tail -1)
KVM_DEBIAN_OS_VARIANT ?= $(shell osinfo-query os | awk '/debian[1-9]/ {print $$1}' | sort -V | tail -1)
KVM_FEDORA_OS_VARIANT ?= $(shell osinfo-query os | awk '/fedora[1-9]/ {print $$1}' | sort -V | tail -1)
KVM_FREEBSD_OS_VARIANT ?= $(shell osinfo-query os | awk '/freebsd[1-9]/ {print $$1}' | sort -V | tail -1)
KVM_NETBSD_OS_VARIANT ?= $(shell osinfo-query os | awk '/netbsd[1-9]/ {print $$1}' | sort -V | tail -1)
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
#      what is fed to libvirt but note ...
#
#  KVM_*_DOMAIN KVM_*_DOMAINS
#
#      the path/domain-name that is used as the make target
#
#      Note: make rules use $(notdir KVM_*_DOMAIN), $(notdir $@), and
#      $* (matching % in pattern rules) to get the domain name from
#      the target

strip-prefix = $(subst '',,$(subst "",,$(1)))
# for-each-kvm-prefix = how?
add-kvm-prefixes = \
	$(foreach prefix, $(KVM_PREFIXES), \
		$(addprefix $(call strip-prefix,$(prefix)),$(1)))
KVM_FIRST_PREFIX = $(call strip-prefix,$(firstword $(KVM_PREFIXES)))

KVM_OS_HOST_NAMES = e w n

# expand anything using $1 (such as make variable names and values)
# immediately, but delay everything else by using $$.

define domains

KVM_$($(strip $1))_BASE_HOST_NAME    = $(strip $1)-base
KVM_$($(strip $1))_UPGRADE_HOST_NAME = $(strip $1)-upgrade
KVM_$($(strip $1))_BUILD_HOST_NAME   = $(strip $1)
KVM_$($(strip $1))_HOST_NAME         = $(strip $1)

KVM_$($(strip $1))_BASE_DOMAIN_NAME    = $$(addprefix $$(KVM_FIRST_PREFIX), $$(KVM_$($(strip $1))_BASE_HOST_NAME))
KVM_$($(strip $1))_UPGRADE_DOMAIN_NAME = $$(addprefix $$(KVM_FIRST_PREFIX), $$(KVM_$($(strip $1))_UPGRADE_HOST_NAME))
KVM_$($(strip $1))_BUILD_DOMAIN_NAME   = $$(addprefix $$(KVM_FIRST_PREFIX), $$(KVM_$($(strip $1))_BUILD_HOST_NAME))
KVM_$($(strip $1))_DOMAIN_NAME         = $$(addprefix $$(KVM_FIRST_PREFIX), $$(KVM_$($(strip $1))_HOST_NAME))

KVM_$($(strip $1))_BASE_DOMAIN    = $$(addprefix $$(KVM_POOLDIR)/, $$(KVM_$($(strip $1))_BASE_DOMAIN_NAME))
KVM_$($(strip $1))_UPGRADE_DOMAIN = $$(addprefix $$(KVM_POOLDIR)/, $$(KVM_$($(strip $1))_UPGRADE_DOMAIN_NAME))
KVM_$($(strip $1))_BUILD_DOMAIN   = $$(addprefix $$(KVM_POOLDIR)/, $$(KVM_$($(strip $1))_BUILD_DOMAIN_NAME))
KVM_$($(strip $1))_DOMAIN         = $$(addprefix $$(KVM_POOLDIR)/, $$(KVM_$($(strip $1))_DOMAIN_NAME))

KVM_$($(strip $1))_TEST_HOST_NAMES   = $$(addprefix $1, $$(KVM_OS_HOST_NAMES))
KVM_$($(strip $1))_TEST_DOMAIN_NAMES = $$(call add-kvm-prefixes, $$(KVM_$($(strip $1))_TEST_HOST_NAMES))
KVM_$($(strip $1))_TEST_DOMAINS      = $$(addprefix $$(KVM_LOCALDIR)/, $$(KVM_$($(strip $1))_TEST_DOMAIN_NAMES))

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
KVM_TEST_DOMAIN_NAMES = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_TEST_DOMAIN_NAMES))
KVM_TEST_DOMAINS      = $(foreach platform, $(KVM_PLATFORM), $(KVM_$($(platform))_TEST_DOMAINS))

KVM_FEDORA_HOST_NAMES = east west north road nic
KVM_FEDORA_TEST_HOST_NAMES += $(KVM_FEDORA_HOST_NAMES)
#KVM_FEDORA_TEST_DOMAIN_NAMES += $(call add-kvm-prefixes, $(KVM_FEDORA_HOST_NAMES))
#KVM_FEDORA_TEST_DOMAINS += $(addprefix $(KVM_LOCALDIR)/, $(KVM_FEDORA_TEST_DOMAIN_NAMES))

KVM_HOST_NAMES += $(KVM_BASE_HOST_NAMES)
KVM_HOST_NAMES += $(KVM_UPGRADE_HOST_NAMES)
KVM_HOST_NAMES += $(KVM_BUILD_HOST_NAMES)
KVM_HOST_NAMES += $(KVM_TEST_HOST_NAMES)

KVM_DOMAIN_NAMES += $(KVM_BASE_DOMAIN_NAMES)
KVM_DOMAIN_NAMES += $(KVM_UPGRADE_DOMAIN_NAMES)
KVM_DOMAIN_NAMES += $(KVM_BUILD_DOMAIN_NAMES)
KVM_DOMAIN_NAMES += $(KVM_TEST_DOMAIN_NAMES)

KVM_DOMAINS += $(KVM_BASE_DOMAINS)
KVM_DOMAINS += $(KVM_UPGRADE_DOMAINS)
KVM_DOMAINS += $(KVM_BUILD_DOMAINS)
KVM_DOMAINS += $(KVM_TEST_DOMAINS)

#
# Domains
#
# Generate local names using prefixes
#

KVM_POOLDIR_PREFIX = $(KVM_POOLDIR)/$(KVM_FIRST_PREFIX)
KVM_LOCALDIR_PREFIXES = \
	$(call strip-prefix, \
		$(foreach prefix, $(KVM_PREFIXES), \
			$(addprefix $(KVM_LOCALDIR)/, $(prefix))))
add-kvm-localdir-prefixes = \
	$(foreach prefix, $(KVM_LOCALDIR_PREFIXES), \
		$(patsubst %, $(prefix)%, $(1)))

#
# Other utilities and directories
#

QEMU_IMG ?= sudo qemu-img
KVMSH ?= $(KVM_PYTHON) testing/utils/kvmsh.py
KVMRUNNER ?= $(KVM_PYTHON) testing/utils/kvmrunner.py
KVMRESULTS ?= $(KVM_PYTHON) testing/utils/kvmresults.py
KVMTEST ?= $(KVM_PYTHON) testing/utils/kvmtest.py

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
$(KVM_HOST_NFS_OK): testing/libvirt/nfs.sh
$(KVM_HOST_NFS_OK): $(KVM_FRESH_BOOT_FILE)
$(KVM_HOST_NFS_OK): | $(KVM_POOLDIR)
	sh testing/libvirt/nfs.sh $(KVM_BENCHDIR) $(KVM_POOLDIR) $(KVM_SOURCEDIR) $(KVM_TESTINGDIR)
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

.PHONY:
web-pages-disabled:
	@echo
	@echo Web-pages disabled.
	@echo
	@echo To enable web pages create the directory: $(LSW_WEBDIR)
	@echo To convert this result into a web page run: make web-page
	@echo

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
KVM_TEST_STATUS += $(if $(KVM_FREEBSD),freebsd)
KVM_TEST_STATUS += $(if $(KVM_NETBSD),netbsd)
KVM_TEST_STATUS += $(if $(KVM_OPENBSD),openbsd)
KVM_RUN_POST_MORTEM ?=

STRIPPED_KVM_TEST_STATUS = $(subst $(sp),|,$(sort $(KVM_TEST_STATUS)))

KVM_TEST_NAME ?=
STRIPPED_KVM_TEST_NAME = $(subst $(sp),|,$(sort $(KVM_TEST_NAME)))

kvm-test kvm-check kvm-retest kvm-recheck: \
kvm-%: $(KVM_HOST_OK) kvm-keys-ok
	: $@
	: shutdown all the build domains, kvmrunner shuts down the test domains
	$(foreach domain, $(KVM_BUILD_DOMAINS), $(call shutdown-os-domain, $(domain)))
	@$(MAKE) $(if $(WEB_ENABLED), web-test-prep, -s web-pages-disabled)
	: KVM_TESTS="$(STRIPPED_KVM_TESTS)"
	$(KVMRUNNER) \
		$(if $(KVM_PIDFILE), --pid-file "$(KVM_PIDFILE)") \
		$(foreach prefix,$(KVM_PREFIXES), --prefix $(prefix)) \
		$(if $(KVM_WORKERS), --workers $(KVM_WORKERS)) \
		$(if $(KVM_TESTINGDIR), --testing-directory $(KVM_TESTINGDIR)) \
		$(if $(WEB_ENABLED), --publish-hash $(WEB_HASH)) \
		$(if $(WEB_ENABLED), --publish-results $(WEB_RESULTSDIR)) \
		$(if $(WEB_ENABLED), --publish-status $(WEB_SUMMARYDIR)/status.json) \
		$(if $(STRIPPED_KVM_TEST_STATUS), --test-status '$(STRIPPED_KVM_TEST_STATUS)') \
		$(if $(STRIPPED_KVM_TEST_NAME), --test-name '$(STRIPPED_KVM_TEST_NAME)') \
		$(if $(KVM_SNAPSHOTDIR), --snapshot-directory $(KVM_SNAPSHOTDIR)) \
		$(if $(filter kvm-re%, $@), --skip passed) \
		$(if $(KVM_RUN_POST_MORTEM), --run-post-mortem) \
		$(KVMRUNNER_FLAGS) \
		$(KVM_TEST_FLAGS) \
		$(STRIPPED_KVM_TESTS)
	@$(MAKE) $(if $(WEB_ENABLED), web-test-post, -s web-pages-disabled)

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
KVM_KEYS_DOMAIN = $(addprefix $(KVM_FIRST_PREFIX), fedora)

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
	$(KVMSH) --chdir /tmp/x509 $(KVM_KEYS_DOMAIN) cp kvm-keys.tar /pool/$(KVM_FIRST_PREFIX)kvm-keys.tar
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
# Build a pool of networks from scratch
#

# This defines the primitives, the public rules are defined near the
# end.

define create-kvm-network
	:
        : create-kvm-network file=$(strip $(1))
	:
	$(VIRSH) net-define $(1)
	$(VIRSH) net-autostart $(basename $(notdir $(1)))
	$(VIRSH) net-start $(basename $(notdir $(1)))
endef


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
# Because the gateway is created directly from libvirt/swandefault and
# that file contains hardwired IP addresses, but only one is possible.
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

$(KVM_GATEWAY): | testing/libvirt/net/$(KVM_GATEWAY_NAME)
$(KVM_GATEWAY): | $(KVM_POOLDIR)
	./testing/libvirt/kvm-uninstall-network.sh $@
	$(call create-kvm-network, testing/libvirt/net/$(KVM_GATEWAY_NAME))
	touch $@

#
# Test networks.
#

KVM_TEST_NETWORK_NAMES = $(notdir $(wildcard testing/libvirt/net/192_*))
KVM_TEST_NETWORKS = $(call add-kvm-localdir-prefixes, $(KVM_TEST_NETWORK_NAMES))

.PRECIOUS: $(KVM_TEST_NETWORKS)

# <prefix><network>; if <prefix> is blank call it swan<network>*
KVM_BRIDGE_NAME = $(strip $(if $(patsubst 192_%,,$*), \
					$*, \
					swan$(subst _,,$(patsubst %192_,,$*))))

$(KVM_TEST_NETWORKS): \
$(KVM_LOCALDIR)/%: | $(KVM_LOCALDIR)
	: $@
	./testing/libvirt/kvm-uninstall-network.sh $@
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
	$(call create-kvm-network, $@.tmp)
	mv $@.tmp $@

.PHONY: kvm-install-test-networks kvm-install-gateway
kvm-install-gateway: $(KVM_GATEWAY)
kvm-install-test-networks: $(KVM_TEST_NETWORKS)

.PHONY: kvm-uninstall-test-networks
kvm-uninstall-test-networks:
	./testing/libvirt/kvm-uninstall-network.sh $(KVM_TEST_NETWORKS)
.PHONY: kvm-uninstall-gateway
kvm-uninstall-gateway:
	./testing/libvirt/kvm-uninstall-network.sh $(KVM_GATEWAY)

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
		testing/libvirt/kvm-install-base.py \
		$(KVM_POOLDIR) \
		$(KVM_HOST_OK) \
		$(KVM_GATEWAY)
	: @=$@ *=$*
	: clean up old domains
	./testing/libvirt/kvm-uninstall-domain.sh $@
	: use script to drive build of new domain
	$(KVM_PYTHON) testing/libvirt/kvm-install-base.py \
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
	! $(KVMSH) $(notdir $@) -- false
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
	: Delaying their creation hopefully makes it harder to accidently
	: access the wrong files.
	:
	$(KVMSH) $(notdir $@) -- test ! -d /source -a ! -d /testing
	:
	: Everything seems to be working, shut down.
	:
	$(KVMSH) --shutdown $(notdir $@)
	touch $@


.PHONY: kvm-iso

#
# Alpine
#

KVM_ALPINE_ISO_URL ?= https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-standard-3.18.0-x86_64.iso
KVM_ALPINE_ISO = $(KVM_POOLDIR)/$(notdir $(KVM_ALPINE_ISO_URL))
kvm-iso: $(KVM_ALPINE_ISO)
$(KVM_ALPINE_ISO): | $(KVM_POOLDIR)
	$(KVM_WGET) --output-document $@.tmp -- $(KVM_ALPINE_ISO_URL)
	touch $@.tmp # wget preserves dates
	mv $@.tmp $@

KVM_ALPINE_VIRT_INSTALL_FLAGS = \
	--cdrom=$(KVM_ALPINE_ISO)

$(KVM_ALPINE_DOMAIN)-base: $(KVM_ALPINE_ISO)


#
# Debian
#
# Track a slightly older DVD; current keeps moving.

KVM_DEBIAN_RELEASE ?= 12.2.0
# https://cdimage.debian.org/debian-cd/current/amd64/iso-dvd
KVM_DEBIAN_URL ?= https://cdimage.debian.org/mirror/cdimage/archive/$(KVM_DEBIAN_RELEASE)/amd64/iso-dvd
KVM_DEBIAN_ISO_URL ?= $(KVM_DEBIAN_URL)/debian-$(KVM_DEBIAN_RELEASE)-amd64-DVD-1.iso
KVM_DEBIAN_ISO = $(KVM_POOLDIR)/$(notdir $(KVM_DEBIAN_ISO_URL))
kvm-iso: $(KVM_DEBIAN_ISO)
$(KVM_DEBIAN_ISO): | $(KVM_POOLDIR)
	$(KVM_WGET) --output-document $@.tmp -- $(KVM_DEBIAN_ISO_URL)
	touch $@.tmp # wget preserves dates
	mv $@.tmp $@

$(KVM_DEBIAN_DOMAIN)-base.iso: $(KVM_DEBIAN_ISO)
$(KVM_DEBIAN_DOMAIN)-base.iso: | testing/libvirt/debian/base.sh
	cp $(KVM_DEBIAN_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		testing/libvirt/debian/base.sh \
		> $(KVM_DEBIAN_DOMAIN)-base.sh
	growisofs -M $@.tmp -l -R \
		-input-charset utf-8 \
		-graft-points \
		/base.sh=$(KVM_DEBIAN_DOMAIN)-base.sh
	mv $@.tmp $@

$(KVM_DEBIAN_DOMAIN)-base: $(KVM_DEBIAN_DOMAIN)-base.iso

KVM_DEBIAN_VIRT_INSTALL_FLAGS = \
	--location=$(KVM_DEBIAN_DOMAIN)-base.iso \
	--initrd-inject=testing/libvirt/debian/preseed.cfg \
	--extra-args="console=ttyS0,115200 net.ifnames=0 biosdevname=0"


#
# Fedora
#
# - since kickstart is used this is pretty straight forward
#
# For instance: Fedora-Server-dvd-x86_64-36-1.5.iso

KVM_FEDORA_RELEASE ?= 39
KVM_FEDORA_BUILD ?= 1.5
KVM_FEDORA_ISO_URL ?= https://download.fedoraproject.org/pub/fedora/linux/releases/$(KVM_FEDORA_RELEASE)/Server/x86_64/iso/Fedora-Server-dvd-x86_64-$(KVM_FEDORA_RELEASE)-$(KVM_FEDORA_BUILD).iso
KVM_FEDORA_KICKSTART_FILE ?= testing/libvirt/fedora/base.ks
KVM_FEDORA_ISO = $(KVM_POOLDIR)/$(notdir $(KVM_FEDORA_ISO_URL))
kvm-iso: $(KVM_FEDORA_ISO)
$(KVM_FEDORA_ISO): | $(KVM_POOLDIR)
	$(KVM_WGET) --output-document $@.tmp -- $(KVM_FEDORA_ISO_URL)
	touch $@.tmp # wget preserves dates
	mv $@.tmp $@

KVM_FEDORA_VIRT_INSTALL_FLAGS = \
	--location=$(KVM_FEDORA_ISO) \
	--initrd-inject=$(KVM_FEDORA_DOMAIN)-base.ks \
	--extra-args="inst.ks=file:/$(notdir $(KVM_FEDORA_DOMAIN)-base.ks) console=ttyS0,115200 net.ifnames=0 biosdevname=0"

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

KVM_FREEBSD_ISO_SHA256 ?= 52a1420db86802cfab8bafa36eccaa78c8b65b59673cbdf690e4b57f9d80f01f
KVM_FREEBSD_ISO_URL ?= https://download.freebsd.org/ftp/releases/ISO-IMAGES/13.2/FreeBSD-13.2-RELEASE-amd64-disc1.iso
KVM_FREEBSD_ISO ?= $(KVM_POOLDIR)/$(notdir $(KVM_FREEBSD_ISO_URL))

kvm-iso: $(KVM_FREEBSD_ISO)
# For FreeBSD, download the compressed ISO
$(KVM_FREEBSD_ISO).xz: | $(KVM_POOLDIR)
	$(KVM_WGET) --output-document $@.tmp -- $(KVM_FREEBSD_ISO_URL).xz
	touch $@.tmp # wget preserves dates
	mv $@.tmp $@
$(KVM_FREEBSD_ISO): | $(KVM_FREEBSD_ISO).xz
	echo 'SHA256 ($@.xz) = $(KVM_FREEBSD_ISO_SHA256)' | cksum -c
	xz --uncompress --keep $@.xz

KVM_FREEBSD_VIRT_INSTALL_FLAGS = \
       --cdrom=$(KVM_FREEBSD_DOMAIN)-base.iso

$(KVM_FREEBSD_DOMAIN)-base: $(KVM_FREEBSD_DOMAIN)-base.iso

$(KVM_FREEBSD_DOMAIN)-base.iso: $(KVM_FREEBSD_ISO)
$(KVM_FREEBSD_DOMAIN)-base.iso: | testing/libvirt/freebsd/loader.conf
$(KVM_FREEBSD_DOMAIN)-base.iso: | testing/libvirt/freebsd/base.conf
	cp $(KVM_FREEBSD_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		testing/libvirt/freebsd/base.conf \
		> $(KVM_FREEBSD_DOMAIN)-base.conf
	growisofs -M $@.tmp -l -R \
		-input-charset utf-8 \
		-graft-points \
		/boot/loader.conf=testing/libvirt/freebsd/loader.conf \
		/etc/installerconfig=$(KVM_FREEBSD_DOMAIN)-base.conf
	mv $@.tmp $@


#
# NetBSD
#
# - needs a second serial console boot iso
#
KVM_NETBSD_MACHINE = amd64
KVM_NETBSD_URL_PREFIX ?= https://nycdn.netbsd.org/pub/NetBSD-daily/netbsd-10/latest/

KVM_NETBSD_INSTALL_ISO ?= $(KVM_POOLDIR)/NetBSD-10.0_RC2-$(KVM_NETBSD_MACHINE).iso
KVM_NETBSD_INSTALL_ISO_URL ?= $(KVM_NETBSD_URL_PREFIX)/images/$(notdir $(KVM_NETBSD_INSTALL_ISO))
KVM_NETBSD_INSTALL_ISO_SHA512 ?= 71ddc1e7dc83deefff6a540669ed43f5d9d4a694d2ab2ac836d5f05fcf6887a211ddae089b07bfc3ae0bb3c47dfc0385f40201083791b6cdc2cd730bc9059897

# i.e., replace .is with -boot.iso; boot-com.iso isn't unique
KVM_NETBSD_BOOT_ISO ?= $(basename $(KVM_NETBSD_INSTALL_ISO))-boot.iso
KVM_NETBSD_BOOT_ISO_URL ?= $(KVM_NETBSD_URL_PREFIX)/$(KVM_NETBSD_MACHINE)/installation/cdrom/boot-com.iso
KVM_NETBSD_BOOT_ISO_SHA512 ?= 7451b61cddb69e3d88fe132d4148f5498f8a1847c180f160b0f60057b5e99993f756cd2adf63e5ccd5f5a17884a451f0073db26fde79d110f43d8606d0c4a35b

kvm-iso: $(KVM_NETBSD_BOOT_ISO)
kvm-iso: $(KVM_NETBSD_INSTALL_ISO)
$(KVM_NETBSD_INSTALL_ISO): | $(KVM_POOLDIR)
	$(KVM_WGET) --output-document $@.tmp -- $(KVM_NETBSD_INSTALL_ISO_URL)
	echo 'SHA512 ($@.tmp) = $(KVM_NETBSD_INSTALL_ISO_SHA512)' | cksum -c
	touch $@.tmp # wget preserves dates
	mv $@.tmp $@
$(KVM_NETBSD_BOOT_ISO): | $(KVM_POOLDIR)
	$(KVM_WGET) --output-document $@.tmp -- $(KVM_NETBSD_BOOT_ISO_URL)
	echo 'SHA512 ($@.tmp) = $(KVM_NETBSD_BOOT_ISO_SHA512)' | cksum -c
	touch $@.tmp # wget preserves dates
	mv $@.tmp $@

KVM_NETBSD_VIRT_INSTALL_FLAGS = \
	--cdrom=$(KVM_NETBSD_BOOT_ISO) \
	--disk=path=$(KVM_NETBSD_DOMAIN)-base.iso,readonly=on,device=cdrom

$(KVM_NETBSD_DOMAIN)-base: $(KVM_NETBSD_BOOT_ISO)
$(KVM_NETBSD_DOMAIN)-base: $(KVM_NETBSD_DOMAIN)-base.iso

$(KVM_NETBSD_DOMAIN)-base.iso: $(KVM_NETBSD_INSTALL_ISO)
$(KVM_NETBSD_DOMAIN)-base.iso: | testing/libvirt/netbsd/base.sh
	cp $(KVM_NETBSD_INSTALL_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		testing/libvirt/netbsd/base.sh \
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

KVM_OPENBSD_ISO_RELEASE ?= 7.4
KVM_OPENBSD_ISO_URL_BASE ?= https://cdn.openbsd.org/pub/OpenBSD/$(KVM_OPENBSD_ISO_RELEASE)
KVM_OPENBSD_ISO_URL ?= $(KVM_OPENBSD_ISO_URL_BASE)/amd64/install$(subst .,,$(KVM_OPENBSD_ISO_RELEASE)).iso
KVM_OPENBSD_ISO_SHA256 ?= a1001736ed9fe2307965b5fcdb426ae11f9b80d26eb21e404a705144a0a224a0
# not openbsd... as gets deleted by rm openbsd.*
KVM_OPENBSD_ISO = $(KVM_POOLDIR)/OpenBSD-$(KVM_OPENBSD_ISO_RELEASE)-install.iso

kvm-iso: $(KVM_OPENBSD_ISO)
$(KVM_OPENBSD_ISO): | $(KVM_POOLDIR)
	$(KVM_WGET) --output-document $@.tmp -- $(KVM_OPENBSD_ISO_URL)
	touch $@.tmp # wget preserves dates
	echo 'SHA256 ($@.tmp) = $(KVM_OPENBSD_ISO_SHA256)' | cksum -c
	mv $@.tmp $@

KVM_OPENBSD_VIRT_INSTALL_FLAGS = \
	--disk path=$(KVM_OPENBSD_DOMAIN)-base.iso,readonly=on,device=cdrom,target.bus=sata \
	--install bootdev=cdrom

$(KVM_OPENBSD_DOMAIN)-base: $(KVM_OPENBSD_DOMAIN)-base.iso

kvm-iso: $(KVM_OPENBSD_DOMAIN)-base.iso
$(KVM_OPENBSD_DOMAIN)-base.iso: $(KVM_OPENBSD_ISO)
$(KVM_OPENBSD_DOMAIN)-base.iso: | testing/libvirt/openbsd/base.conf
$(KVM_OPENBSD_DOMAIN)-base.iso: | testing/libvirt/openbsd/boot.conf
$(KVM_OPENBSD_DOMAIN)-base.iso: | testing/libvirt/openbsd/base.sh
$(KVM_OPENBSD_DOMAIN)-base.iso: | testing/libvirt/openbsd/base.disk
	cp $(KVM_OPENBSD_ISO) $@.tmp
	$(KVM_TRANSMOGRIFY) \
		testing/libvirt/openbsd/base.sh \
		> $(KVM_OPENBSD_DOMAIN)-base.sh
	: boot.conf sets up a serial console
	: base.conf configures the installer
	: base.sh gets run by base.py after boot
	growisofs -M $@.tmp -l -R \
		-input-charset utf-8 \
		-graft-points \
		/base.conf=testing/libvirt/openbsd/base.conf \
		/etc/boot.conf=testing/libvirt/openbsd/boot.conf \
		/base.sh=$(KVM_OPENBSD_DOMAIN)-base.sh \
		/base.disk=testing/libvirt/openbsd/base.disk
	mv $@.tmp $@

##
## Upgrade the base domain: create a clone, install any missing
## packages and upgrade any packages that are out-of-date.
##
## While the script is running only /pool and /bench (pointing into
## this repo) are accessible (/source and /testing which may point
## elsewhere are not accessable, see above and below).
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
		testing/libvirt/%/upgrade.sh \
		$(KVM_HOST_OK)
	: @=$@ *=$*
	./testing/libvirt/kvm-uninstall-domain.sh $@
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
		testing/libvirt/$*/upgrade.sh \
		> $@.sh
	$(KVMSH) $(notdir $@) -- \
		/bin/sh -x /pool/$(notdir $@).sh $(KVM_$($*)_UPGRADE_FLAGS)
	: only shutdown after upgrade succeeds
	$(KVMSH) --shutdown $(notdir $@)
	touch $@

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
		testing/libvirt/%/transmogrify.sh \
		$(KVM_HOST_OK)
	: @=$@ *=$*
	./testing/libvirt/kvm-uninstall-domain.sh $@
	$(QEMU_IMG) create -f qcow2 -F qcow2 -b $<.qcow2 $@.qcow2
	: fedora runs chcon TESTINGDIR
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
		testing/libvirt/$*/transmogrify.sh \
		> $@.transmogrify.sh
	$(KVMSH) $(notdir $@) -- \
		/bin/sh -x /pool/$(notdir $@).transmogrify.sh $(KVM_$($*)_TRANSMOGRIFY_FLAGS)
	: only shutdown after transmogrify succeeds
	$(KVMSH) --shutdown $(notdir $@)
	touch $@

KVM_FEDORA_TRANSMOGRIFY_FILES += $(wildcard testing/libvirt/fedora/network/*.network)
KVM_FREEBSD_TRANSMOGRIFY_FILES += testing/libvirt/freebsd/rc.conf
KVM_NETBSD_TRANSMOGRIFY_FILES += testing/libvirt/netbsd/rc.local
KVM_OPENBSD_TRANSMOGRIFY_FILES += testing/libvirt/openbsd/rc.local


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
		'ls > /dev/null' \; \
		'time gmake install-base $(KVM_MAKEFLAGS) $(KVM_$($*)_MAKEFLAGS)'

$(patsubst %, kvm-make-install-all-%, $(KVM_INSTALL_PLATFORM)): \
kvm-make-install-all-%: $(KVM_POOLDIR_PREFIX)%
	: $@ $<
	$(KVMSH) $(KVMSH_FLAGS) \
		--chdir /source \
		$(notdir $<) \
		-- \
		'ls > /dev/null' \; \
		'time gmake install $(KVM_MAKEFLAGS) $(KVM_$($*)_MAKEFLAGS)'

$(patsubst %, kvm-install-%, $(KVM_PLATFORM)): \
kvm-install-%:
	: $@
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	$(MAKE) kvm-make-install-base-$*
	$(KVMSH) --shutdown $(KVM_FIRST_PREFIX)$*
	$(MAKE) $(KVM_$($*)_TEST_DOMAINS)

$(patsubst %, kvm-install-base-%, $(KVM_PLATFORM)): \
kvm-install-base-%:
	: $@
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	$(MAKE) kvm-make-install-base-$*
	$(KVMSH) --shutdown $(KVM_FIRST_PREFIX)$*
	$(MAKE) $(KVM_$($*)_TEST_DOMAINS)

$(patsubst %, kvm-install-all-%, $(KVM_PLATFORM)): \
kvm-install-all-%:
	: $@
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	$(MAKE) kvm-make-install-all-$*
	$(KVMSH) --shutdown $(KVM_FIRST_PREFIX)$*
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
  $(strip $(1))$(strip $(2))$(strip $(3)): $(KVM_POOLDIR_PREFIX)$(strip $(2)) | \
		$$(addprefix $(1), $$(KVM_TEST_NETWORK_NAMES)) \
		testing/libvirt/vm/$(strip $(3)).xml
	: @=$$@
	: install-kvm-test-domain prefix=$(strip $(1)) platform=$(strip $(2)) host=$(strip $(3))
	./testing/libvirt/kvm-uninstall-domain.sh $$@
	$$(QEMU_IMG) create -f qcow2 -F qcow2 -b $(KVM_POOLDIR_PREFIX)$(strip $(2)).qcow2 $$@.qcow2
	$$(KVM_TRANSMOGRIFY) \
		-e 's;@@DOMAIN@@;$$(notdir $$@);' \
		-e "s;network='192_;network='$(addprefix $(notdir $(1)), 192_);" \
		testing/libvirt/vm/$(strip $(3)).xml \
		> '$$@.tmp'
	$$(VIRSH) define $$@.tmp
	mv $$@.tmp $$@
endef

# generate rules for all combinations, including those not enabled
$(foreach prefix, $(KVM_LOCALDIR_PREFIXES), \
	$(foreach platform, $(KVM_PLATFORM), \
		$(foreach host, $(KVM_OS_HOST_NAMES), \
			$(eval $(call define-test-domain, \
				$(prefix), \
				$(platform), \
				$(host))))))

define define-fedora-domain
  $(addprefix $(1), $(2)): $(3) | \
		$$(addprefix $(1), $$(KVM_TEST_NETWORK_NAMES)) \
		testing/libvirt/vm/$(strip $(2)).xml
	: @=$$@
	: install-kvm-test-domain prefix=$(strip $(1)) host=$(strip $(2)) template=$(strip $(3))
	./testing/libvirt/kvm-uninstall-domain.sh $$@
	$$(QEMU_IMG) create -f qcow2 -F qcow2 -b $(strip $(3)).qcow2 $$@.qcow2
	$$(KVM_TRANSMOGRIFY) \
		-e 's;@@DOMAIN@@;$$(notdir $$@);' \
		-e "s;network='192_;network='$(addprefix $(notdir $(1)), 192_);" \
		testing/libvirt/vm/$(strip $(2)).xml \
		> '$$@.tmp'
	$$(VIRSH) define $$@.tmp
	mv $$@.tmp $$@
endef

# generate rules for all combinations, including those not enabled
$(foreach prefix, $(KVM_LOCALDIR_PREFIXES), \
	$(foreach host, $(KVM_FEDORA_HOST_NAMES), \
		$(eval $(call define-fedora-domain, \
			$(prefix), \
			$(host), \
			$(KVM_POOLDIR_PREFIX)fedora))))


#
# Get rid of (almost) everything
#
# After running the operation, kvm-install will:
#
# kvm-uninstall:            transmogrify,              install
# kvm-clean-keys:                                keys, install
# kvm-clean:                transmogrify, build, keys, install
# kvm-purge:       upgrade, transmogrify, build, keys, install
#
# For kvm-uninstall, instead of trying to uninstall libreswan from the
# build domain, delete both the clones and the build domain and
# $(KVM_KEYS_DOMAIN) the install domains were cloned from.  This way,
# in addition to giving kvm-install a 100% fresh start (no dependence
# on 'make uninstall') the next test run also gets entirely new
# domains.

.PHONY: kvm-shutdown
$(patsubst %, kvm-shutdown-%, $(KVM_DOMAIN_NAMES)): \
kvm-shutdown-%:
	: $@
	$(KVMSH) --shutdown $*
kvm-shutdown: $(patsubst %, kvm-shutdown-%, $(KVM_DOMAIN_NAMES))

.PHONY: kvm-uninstall
kvm-uninstall: kvm-uninstall-test-networks
kvm-uninstall: kvm-uninstall-test-domains
kvm-uninstall: kvm-uninstall-build-domains

.PHONY: kvm-uninstall-test-domains
kvm-uninstall-test-domains:
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_TEST_DOMAINS)
.PHONY: kvm-uninstall-test-domains
kvm-uninstall-build-domains:
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_BUILD_DOMAINS)
.PHONY: kvm-uninstall-upgrade-domains
kvm-uninstall-upgrade-domains:
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_UPGRADE_DOMAINS)
.PHONY: kvm-uninstall-base-domains
kvm-uninstall-base-domains:
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_BASE_DOMAINS)

.PHONY: kvm-clean
kvm-clean: kvm-uninstall
kvm-clean: kvm-clean-keys
kvm-clean: kvm-clean-check
	rm -rf OBJ.kvm.*

.PHONY: kvm-purge
kvm-purge: kvm-clean
kvm-purge: kvm-downgrade
	rm -f $(KVM_HOST_OK)

$(patsubst %, kvm-purge-%, $(KVM_PLATFORM)): \
kvm-purge-%: kvm-clean kvm-downgrade-%

$(patsubst %, kvm-uninstall-%, $(KVM_PLATFORM)): \
kvm-uninstall-%:
	: $@
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_$($*)_BUILD_DOMAIN)

.PHONY: kvm-downgrade
kvm-downgrade: $(foreach os, $(KVM_OS), kvm-downgrade-$(os))

$(patsubst %, kvm-downgrade-%, $(KVM_PLATFORM)): \
kvm-downgrade-%:
	: $@
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_$($*)_TEST_DOMAINS)
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_$($*)_BUILD_DOMAIN)
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_$($*)_UPGRADE_DOMAIN)

.PHONY: kvm-demolish
kvm-demolish: kvm-uninstall-gateway
kvm-demolish: $(foreach os, $(KVM_OS), kvm-demolish-$(os))

$(patsubst %, kvm-demolish-%, $(KVM_PLATFORM)): \
kvm-demolish-%: kvm-downgrade-%
	./testing/libvirt/kvm-uninstall-domain.sh $(KVM_$($*)_BASE_DOMAIN)


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
kvmsh-%: kvmsh-$(KVM_FIRST_PREFIX)%

$(patsubst %, kvmsh-%, $(KVM_BASE_DOMAIN_NAMES)) : \
kvmsh-%: $(KVM_POOLDIR)/% | $(KVM_HOST_OK)
	$(KVMSH) $(KVMSH_FLAGS) $* $(KVMSH_COMMAND)

$(patsubst %, kvmsh-%, $(KVM_UPGRADE_DOMAIN_NAMES)) : \
kvmsh-%: $(KVM_POOLDIR)/% | $(KVM_HOST_OK)
	$(KVMSH) $(KVMSH_FLAGS) $* $(KVMSH_COMMAND)

$(patsubst %, kvmsh-%, $(KVM_BUILD_DOMAIN_NAMES)) : \
kvmsh-%: $(KVM_POOLDIR)/% | $(KVM_HOST_OK)
	$(KVMSH) $(KVMSH_FLAGS) $* $(KVMSH_COMMAND)

$(patsubst %, kvmsh-%, $(KVM_TEST_DOMAIN_NAMES)) : \
kvmsh-%: $(KVM_LOCALDIR)/% | $(KVM_HOST_OK)
	$(KVMSH) $(KVMSH_FLAGS) $* $(KVMSH_COMMAND)
