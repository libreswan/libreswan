# KVM make targets, for Libreswan
#
# Copyright (C) 2015-2017 Andrew Cagney
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

# Note: GNU Make doesn't let you combine pattern targets (e.x.,
# kvm-install-%: kvm-reboot-%) with .PHONY.  Consequently, so that
# patterns can be used, any targets with dependencies are not marked
# as .PHONY.  Sigh!

# Note: for pattern targets, the value of % can be found in the make
# variable '$*'.  It is used to extract the DOMAIN from targets like
# kvm-install-DOMAIN.


KVM_SOURCEDIR ?= $(abs_top_srcdir)
KVM_TESTINGDIR ?= $(abs_top_srcdir)/testing
# An educated guess ...
KVM_POOLDIR ?= $(abspath $(abs_top_srcdir)/../pool)
KVM_BASEDIR ?= $(KVM_POOLDIR)
KVM_LOCALDIR ?= $(KVM_POOLDIR)
# While KVM_PREFIX might be empty, KVM_PREFIXES is never empty.
KVM_PREFIX ?=
KVM_PREFIXES ?= $(if $(KVM_PREFIX), $(KVM_PREFIX), '')
KVM_WORKERS ?= 1
KVM_USER ?= $(shell id -u)
KVM_GROUP ?= $(shell id -g qemu)

#
# Generate local names using prefixes
#

strip-prefix = $(subst '',,$(subst "",,$(1)))
KVM_FIRST_PREFIX = $(call strip-prefix,$(firstword $(KVM_PREFIXES)))
add-all-domain-prefixes = \
	$(foreach prefix, $(KVM_PREFIXES), \
		$(addprefix $(call strip-prefix,$(prefix)),$(1)))


# To avoid the problem where the host has no "default" KVM network
# (there's a rumour that libreswan's main testing machine has this
# problem) define a dedicated swandefault gateway.

KVM_BASE_GATEWAY ?= swandefault
KVM_LOCAL_GATEWAY = $(KVM_BASE_GATEWAY)

# The alternative is qemu:///session and it doesn't require root.
# However, it has never been used, and the python tools all assume
# qemu://system. Finally, it comes with a warning: QEMU usermode
# session is not the virt-manager default.  It is likely that any
# pre-existing QEMU/KVM guests will not be available.  Networking
# options are very limited.

KVM_CONNECTION ?= qemu:///system

VIRSH = sudo virsh --connect $(KVM_CONNECTION)

VIRT_INSTALL = sudo virt-install --connect $(KVM_CONNECTION)

VIRT_RND ?= --rng type=random,device=/dev/random
VIRT_SECURITY ?= --security type=static,model=dac,label='$(KVM_USER):$(KVM_GROUP)',relabel=yes
VIRT_BASE_GATEWAY ?= --network=network:$(KVM_BASE_GATEWAY),model=virtio
VIRT_LOCAL_GATEWAY ?= --network=network:$(KVM_LOCAL_GATEWAY),model=virtio
VIRT_SOURCEDIR ?= --filesystem type=mount,accessmode=squash,source=$(KVM_SOURCEDIR),target=swansource
VIRT_TESTINGDIR ?= --filesystem type=mount,accessmode=squash,source=$(KVM_TESTINGDIR),target=testing

# The KVM's operating system.
KVM_OS ?= fedora22

#
# Hosts
#

KVM_BASE_HOST = swan$(KVM_OS)base

KVM_CLONE_HOST ?= clone
KVM_BUILD_HOST ?= $(firstword $(KVM_INSTALL_HOSTS))

KVM_TEST_HOSTS = $(notdir $(wildcard testing/libvirt/vm/*[a-z]))
KVM_BASIC_HOSTS = nic
KVM_INSTALL_HOSTS = $(filter-out $(KVM_BASIC_HOSTS), $(KVM_TEST_HOSTS))

KVM_LOCAL_HOSTS = $(sort $(KVM_CLONE_HOST) $(KVM_BUILD_HOST) $(KVM_TEST_HOSTS))

KVM_HOSTS = $(KVM_BASE_HOST) $(KVM_LOCAL_HOSTS)

#
# Domains
#

KVM_BASE_DOMAIN = $(KVM_BASE_HOST)

KVM_CLONE_DOMAIN = $(addprefix $(KVM_FIRST_PREFIX), $(KVM_CLONE_HOST))
KVM_BUILD_DOMAIN = $(addprefix $(KVM_FIRST_PREFIX), $(KVM_BUILD_HOST))

KVM_BASIC_DOMAINS = $(call add-all-domain-prefixes, $(KVM_BASIC_HOSTS))
KVM_INSTALL_DOMAINS = $(call add-all-domain-prefixes, $(KVM_INSTALL_HOSTS))
KVM_TEST_DOMAINS = $(call add-all-domain-prefixes, $(KVM_TEST_HOSTS))

KVM_LOCAL_DOMAINS = $(sort $(KVM_CLONE_DOMAIN) $(KVM_BUILD_DOMAIN) $(KVM_TEST_DOMAINS))

KVM_DOMAINS = $(KVM_BASE_DOMAIN) $(KVM_LOCAL_DOMAINS)

#
# what needs to be copied?
#

# A non-empty KVM_BUILD_COPIES indicates a separate build domain.

KVM_CLONE_COPIES =
KVM_BUILD_COPIES =

KVM_CLONE_COPIES += $(KVM_BASIC_DOMAINS)
ifneq ($(filter $(KVM_BUILD_DOMAIN),$(KVM_INSTALL_DOMAINS)),)
# build is an install domain
KVM_CLONE_COPIES += $(KVM_INSTALL_DOMAINS)
else
# separate build
KVM_CLONE_COPIES += $(KVM_BUILD_DOMAIN)
KVM_BUILD_COPIES += $(KVM_INSTALL_DOMAINS)
endif


#
# Other utilities and directories
#

KVMSH ?= $(abs_top_srcdir)/testing/utils/kvmsh.py
KVMRUNNER ?= $(abs_top_srcdir)/testing/utils/kvmrunner.py

KVM_OBJDIR = OBJ.kvm

RPM_VERSION = $(shell make showrpmversion)
RPM_PREFIX  = libreswan-$(RPM_VERSION)
RPM_BUILD_CLEAN ?= --rmsource --rmspec --clean

# file to mark keys are up-to-date
KVM_KEYS = testing/x509/keys/up-to-date


#
# For when HOST!=DOMAIN, generate maps from the host rule to the
# domain rule.
#

define kvm-HOST-DOMAIN
  #(info kvm-HOST-DOMAIN prefix=$(1) host=$(2) suffix=$(3))
  .PHONY: $(1)$(2)$(3)
  $(1)$(2)$(3): $(1)$$(addprefix $$(KVM_FIRST_PREFIX),$(2))$(3)
endef


#
# Check that things are correctly configured for creating the KVM
# domains
#

KVM_ENTROPY_FILE ?= /proc/sys/kernel/random/entropy_avail
define check-kvm-entropy
	test ! -r $(KVM_ENTROPY_FILE) || test $(shell cat $(KVM_ENTROPY_FILE)) -gt 100 || $(MAKE) broken-kvm-entropy
endef
.PHONY: check-kvm-entropy broken-kvm-entropy
check-kvm-entropy:
	$(call check-kvm-entropy)
broken-kvm-entropy:
	:
	:  According to $(KVM_ENTROPY_FILE) your computer do not seem to have much entropy.
	:
	:  Check the wiki for hints on how to fix this.
	:
	false


KVM_QEMUDIR ?= /var/lib/libvirt/qemu
define check-kvm-qemu-directory
	test -w $(KVM_QEMUDIR) || $(MAKE) broken-kvm-qemu-directory
endef
.PHONY: check-kvm-qemu-directory broken-kvm-qemu-directory
check-kvm-qemu-directory:
	$(call check-kvm-qemu-directory)
broken-kvm-qemu-directory:
	:
	:  The directory:
	:
	:      $(KVM_QEMUDIR)
	:
	:  is not writeable.  This will break virsh which is
	:  used to manipulate the domains.
	:
	false


.PHONY: check-kvm-clonedir check-kvm-basedir
check-kvm-clonedir check-kvm-basedir: | $(KVM_LOCALDIR) $(KVM_BASEDIR)
ifeq ($(KVM_BASEDIR),$(KVM_LOCALDIR))
  $(KVM_LOCALDIR):
else
  $(KVM_BASEDIR) $(KVM_LOCALDIR):
endif
	:
	:  The directory:
	:
	:       "$@"
	:
	:  used to store domain disk images and other files, does not exist.
	:
	:  Three make variables determine the directory or directories used to store
	:  domain disk images and files:
	:
	:      KVM_POOLDIR=$(KVM_POOLDIR)
	:                  - the default location to store domain disk images and files
	:                  - the default is ../pool
	:
	:      KVM_LOCALDIR=$(KVM_LOCALDIR)
	:                  - used for store the cloned test domain disk images and files
	:                  - the default is KVM_POOLDIR
	:
	:      KVM_BASEDIR=$(KVM_BASEDIR)
	:                  - used for store the base domain disk image and files
	:                  - the default is KVM_POOLDIR
	:
	:  Either create the above directory or adjust its location by setting
	:  one or more of the above make variables in the file:
	:
	:      Makefile.inc.local
	:
	false


#
# [re]run the testsuite.
#
# If the testsuite is being run a second time (for instance,
# re-started or re-run) what should happen: run all tests regardless;
# just run tests that have never been started; run tests that haven't
# yet passed?  Since each alternative has merit, let the user decide
# by providing both kvm-test and kvm-retest.

KVM_TESTS ?= testing/pluto

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
# - depends on kvm-keys and not $(KVM_KEYS) so that the check that the
#   keys are up-to-date is run.
#
# - need local domains shutdown as, otherwise, test domains can refuse
#   to boot because the domain they were cloned from is still running.

define kvm-test
.PHONY: $(1)
$(1): kvm-keys kvm-shutdown-local-domains web-test-prep
	$$(if $$(WEB_SUMMARYDIR),,@$(MAKE) -s web-pages-disabled)
	: kvm-test target=$(1) param=$(2)
	$$(call check-kvm-qemu-directory)
	$$(call check-kvm-entropy)
	: KVM_TESTS=$(STRIPPED_KVM_TESTS)
	$$(KVMRUNNER) \
		$$(foreach prefix,$$(KVM_PREFIXES), --prefix $$(prefix)) \
		$$(if $$(KVM_WORKERS), --workers $$(KVM_WORKERS)) \
		$$(if $$(WEB_RESULTSDIR), --publish-results $$(WEB_RESULTSDIR)) \
		$$(if $$(WEB_SUMMARYDIR), --publish-status $$(WEB_SUMMARYDIR)/status.json) \
		$(2) $$(KVM_TEST_FLAGS) $$(STRIPPED_KVM_TESTS)
	$$(if $$(WEB_SUMMARYDIR),,@$(MAKE) -s web-pages-disabled)
endef

# "test" and "check" just runs the entire testsuite.
$(eval $(call kvm-test,kvm-check kvm-test, --test-status "good"))

# "retest" and "recheck" re-run the testsuite updating things that
# didn't pass.
$(eval $(call kvm-test,kvm-retest kvm-recheck, --test-status "good" --skip passed))

# clean up; accept pretty much everything
KVM_TEST_CLEAN_TARGETS = \
	clean-kvm-check kvm-clean-check kvm-check-clean \
	clean-kvm-test kvm-clean-test kvm-test-clean \
	clean-kvm-tests kvm-clean-tests kvm-tests-clean
.PHONY: $(KVM_TEST_CLEAN_TARGETS)
$(KVM_TEST_CLEAN_TARGETS):
	find $(STRIPPED_KVM_TESTS) -name OUTPUT -type d -prune -print0 | xargs -0 -r rm -r


#
# Build the KVM keys using the KVM.
#

KVM_KEYS_SCRIPT = ./testing/x509/kvm-keys.sh
KVM_KEYS_EXPIRATION_DAY = 7
KVM_KEYS_EXPIRED = find testing/x509/*/ -mtime +$(KVM_KEYS_EXPIRATION_DAY)

.PHONY: kvm-keys
kvm-keys: $(KVM_KEYS)
	$(MAKE) --no-print-directory kvm-keys-up-to-date

# For moment don't force keys to be re-built.
.PHONY: kvm-keys-up-to-date
kvm-keys-up-to-date:
	@if test $$($(KVM_KEYS_EXPIRED) | wc -l) -gt 0 ; then \
		echo "The following keys are more than $(KVM_KEYS_EXPIRATION_DAY) days old:" ; \
		$(KVM_KEYS_EXPIRED) | sed -e 's/^/  /' ; \
		echo "run 'make kvm-keys-clean kvm-keys' to force an update" ; \
		exit 1 ; \
	fi

# XXX:
#
# Can't yet force the domain's creation.  This target may have been
# invoked by testing/pluto/Makefile which relies on old domain
# configurations.
#
# Make certain everything is shutdown.  Can't depend on the phony
# target kvm-shutdown-local-domains as that triggers an unconditional
# rebuild.  Instead invoke that rule inline.

$(KVM_KEYS): testing/x509/dist_certs.py $(KVM_KEYS_SCRIPT) # | $(KVM_LOCALDIR)/$(KVM_BUILD_DOMAIN).xml
	$(call check-kvm-domain,$(KVM_BUILD_DOMAIN))
	$(call check-kvm-entropy)
	$(call check-kvm-qemu-directory)
	: invoke phony target to shut things down
	$(MAKE) kvm-shutdown-local-domains
	$(MAKE) kvm-keys-clean
	$(KVM_KEYS_SCRIPT) $(KVM_BUILD_DOMAIN) testing/x509
	: Also regenerate the DNSSEC keys -- uses host
	$(top_srcdir)/testing/baseconfigs/all/etc/bind/generate-dnssec.sh
	$(KVMSH) --shutdown $(KVM_BUILD_DOMAIN)
	touch $(KVM_KEYS)

KVM_KEYS_CLEAN_TARGETS = clean-kvm-keys kvm-clean-keys kvm-keys-clean
.PHONY: $(KVM_KEYS_CLEAN_TARGETS)
$(KVM_KEYS_CLEAN_TARGETS):
	rm -rf testing/x509/*/
	rm -f testing/x509/nss-pw
	rm -f testing/baseconfigs/all/etc/bind/signed/*.signed
	rm -f testing/baseconfigs/all/etc/bind/keys/*.key
	rm -f testing/baseconfigs/all/etc/bind/keys/*.private
	rm -f testing/baseconfigs/all/etc/bind/dsset/dsset-*


#
# Create an RPM for the test domains
#

.PHONY: kvm-rpm
kvm-rpm:
	@echo building rpm for libreswan testing
	mkdir -p ~/rpmbuild/SPECS/
	sed  "s/@IPSECBASEVERSION@/$(RPM_VERSION)/g" packaging/fedora/libreswan-testing.spec.in \
		> ~/rpmbuild/SPECS/libreswan-testing.spec
	mkdir -p ~/rpmbuild/SOURCES
	git archive --format=tar --prefix=$(RPM_PREFIX)/ \
		-o ~/rpmbuild/SOURCES/$(RPM_PREFIX).tar HEAD
	if [ -a Makefile.inc.local ] ; then \
		tar --transform "s|^|$(RPM_PREFIX)/|" -rf ~/rpmbuild/SOURCES/$(RPM_PREFIX).tar Makefile.inc.local ; \
	fi;
	gzip -f ~/rpmbuild/SOURCES/$(RPM_PREFIX).tar
	rpmbuild -ba $(RPM_BUILD_CLEAN) ~/rpmbuild/SPECS/libreswan-testing.spec


#
# Build a pool of networks from scratch
#

# This defines the primitives, the public rules are defined near the
# end.

define create-kvm-network
        : create-kvm-network network=$(1) file=$(2)
	$(VIRSH) net-define '$(2)'
	$(VIRSH) net-autostart '$(1)'
	$(VIRSH) net-start '$(1)'
endef

define destroy-kvm-network
        : destroy-kvm-network network=$(1)
	if $(VIRSH) net-info '$(1)' 2>/dev/null | grep 'Active:.*yes' > /dev/null ; then \
		$(VIRSH) net-destroy '$(1)' ; \
	fi
	if $(VIRSH) net-info '$(1)' >/dev/null 2>&1 ; then \
		$(VIRSH) net-undefine '$(1)' ; \
	fi
endef

#
# Base network.
#

KVM_BASE_GATEWAY_FILE = $(KVM_BASEDIR)/$(KVM_BASE_GATEWAY).xml
.PHONY: install-kvm-network-$(KVM_BASE_GATEWAY)
install-kvm-network-$(KVM_BASE_GATEWAY): $(KVM_BASE_GATEWAY_FILE)
$(KVM_BASE_GATEWAY_FILE): | testing/libvirt/net/$(KVM_BASE_GATEWAY) $(KVM_BASEDIR)
	$(call destroy-kvm-network,$(KVM_BASE_GATEWAY))
	cp testing/libvirt/net/$(KVM_BASE_GATEWAY) $@.tmp
	$(call create-kvm-network,$(KVM_BASE_GATEWAY),$@.tmp)
	mv $@.tmp $@

.PHONY: uninstall-kvm-network-$(KVM_BASE_GATEWAY)
uninstall-kvm-network-$(KVM_BASE_GATEWAY):
	rm -f $(KVM_BASE_GATEWAY_FILE)
	$(call destroy-kvm-network,$(KVM_BASE_GATEWAY))

# zap dependent domains

uninstall-kvm-network-$(KVM_BASE_GATEWAY): uninstall-kvm-domain-$(KVM_BASE_DOMAIN)
uninstall-kvm-network-$(KVM_BASE_GATEWAY): uninstall-kvm-domain-$(KVM_CLONE_DOMAIN)
ifneq ($(KVM_BUILD_COPIES),)
uninstall-kvm-network-$(KVM_BASE_GATEWAY): uninstall-kvm-domain-$(KVM_BUILD_DOMAIN)
endif

#
# Test networks.
#

KVM_TEST_SUBNETS = \
	$(notdir $(wildcard testing/libvirt/net/192*))

KVM_TEST_NETWORKS = \
	$(foreach prefix, $(KVM_PREFIXES), \
		$(addprefix $(call strip-prefix,$(prefix)), $(KVM_TEST_SUBNETS)))

define install-kvm-test-network
  #(info prefix=$(1) network=$(2))
  .PHONY: install-kvm-network-$(1)$(2)
  install-kvm-network-$(1)$(2): $$(KVM_LOCALDIR)/$(1)$(2).xml
  .PRECIOUS: $$(KVM_LOCALDIR)/$(1)$(2).xml
  $$(KVM_LOCALDIR)/$(1)$(2).xml: | $$(KVM_LOCALDIR)
	: install-kvm-test-network prefix=$(1) network=$(2)
	$$(call destroy-kvm-network,$(1)$(2))
	rm -f '$$@.tmp'
	echo "<network ipv6='yes'>"					>> '$$@.tmp'
	echo "  <name>$(1)$(2)</name>"					>> '$$@.tmp'
  ifeq ($(1),)
	echo "  <bridge name='swan$(subst _,,$(patsubst 192_%,%,$(2)))' stp='on' delay='0'/>"		>> '$$@.tmp'
  else
	echo "  <bridge name='$(1)$(2)' stp='on' delay='0'/>"		>> '$$@.tmp'
  endif
  ifeq ($(1),)
	echo "  <ip address='$(subst _,.,$(2)).253'/>"				>> '$$@.tmp'
  else
	echo "  <!-- <ip address='$(subst _,.,$(2)).253'> -->"			>> '$$@.tmp'
  endif
	echo "</network>"						>> '$$@.tmp'
	$$(call create-kvm-network,$(1)$(2),$$@.tmp)
	mv $$@.tmp $$@
endef

$(foreach prefix, $(KVM_PREFIXES), \
	$(foreach subnet, $(KVM_TEST_SUBNETS), \
		$(eval $(call install-kvm-test-network,$(call strip-prefix,$(prefix)),$(subnet)))))

define uninstall-kvm-test-network
  #(info  uninstall-kvm-test-network prefix=$(1) network=$(2))
  .PHONY: uninstall-kvm-network-$(1)$(2)
  uninstall-kvm-network-$(1)$(2):
	: uninstall-kvm-test-network prefix=$(1) network=$(2)
	rm -f $$(KVM_LOCALDIR)/$(1)$(2).xml
	$$(call destroy-kvm-network,$(1)$(2))
  # zap dependent domains
  uninstall-kvm-network-$(1)$(2): $$(addprefix uninstall-kvm-domain-, $$(addprefix $(1), $$(KVM_TEST_HOSTS)))
endef

$(foreach prefix, $(KVM_PREFIXES), \
	$(foreach subnet, $(KVM_TEST_SUBNETS), \
		$(eval $(call uninstall-kvm-test-network,$(call strip-prefix,$(prefix)),$(subnet)))))


#
# Upgrade domains
#

define upgrade-kvm-domain
	: upgrade-kvm-domain domain=$(1)
	$(if $(KVM_PACKAGES), \
		$(KVMSH) $(1) $(KVM_PACKAGE_INSTALL) $(KVM_PACKAGES))
	$(if $(KVM_INSTALL_RPM_LIST), \
		$(KVMSH) $(1) $(KVM_INSTALL_RPM_LIST))
	$(if $(KVM_DEBUGINFO), \
		$(KVMSH) $(1) $(KVM_DEBUGINFO_INSTALL) $(KVM_DEBUGINFO))
	$(KVMSH) --shutdown $(1)
endef

.PHONY: kvm-upgrade-base-domain
kvm-upgrade-base-domain: $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks
	$(call upgrade-kvm-domain, $(KVM_BASE_DOMAIN))

# need to both delete any dependent domains and/or build the clone
# domain.

.PHONY: kvm-upgrade kvm-upgrade-local-domains
kvm-upgrade: kvm-upgrade-local-domains
kvm-upgrade-local-domains: $(KVM_LOCALDIR)/$(KVM_CLONE_DOMAIN).xml
kvm-upgrade-local-domains: $(addprefix uninstall-kvm-domain-, $(KVM_CLONE_COPIES))
kvm-upgrade-local-domains:
	$(call upgrade-kvm-domain, $(KVM_CLONE_DOMAIN))
	$(MAKE) kvm-install-local-domains


#
# Build KVM domains from scratch
#

# XXX: Once KVM_OS gets re-named to include the release, this hack can
# be deleted.
include testing/libvirt/$(KVM_OS).mk

ifeq ($(KVM_OS_VARIANT),)
$(error KVM_OS_VARIANT not defined)
endif
ifeq ($(KVM_ISO_URL),)
$(error KVM_ISO_URL not defined)
endif
ifeq ($(KVM_KICKSTART_FILE),)
$(error KVM_KICKSTART_FILE not defined)
endif

KVM_ISO = $(KVM_BASEDIR)/$(notdir $(KVM_ISO_URL))

.PHONY: kvm-iso
kvm-iso: $(KVM_ISO)
$(KVM_ISO): | $(KVM_BASEDIR)
	cd $(KVM_BASEDIR) && wget $(KVM_ISO_URL)

define check-kvm-domain
	: check-kvm-domain domain=$(1)
	if $(VIRSH) dominfo '$(1)' >/dev/null ; then : ; else \
		echo "" ; \
		echo "  ERROR: the domain $(1) seems to be missing; run 'make kvm-install'" ; \
		echo "" ; \
		exit 1 ; \
	fi
endef

define create-kvm-domain
	: create-kvm-domain domain=$(1)
	$(VIRT_INSTALL) \
		--name $(1) \
		--os-variant $(KVM_OS_VARIANT) \
		--vcpus=1 \
		--memory 512 \
		--nographics \
		--disk cache=writeback,path=$(KVM_LOCALDIR)/$(1).qcow2 \
		$(VIRT_LOCAL_GATEWAY) \
		$(VIRT_RND) \
		$(VIRT_SECURITY) \
		$(VIRT_SOURCEDIR) \
		$(VIRT_TESTINGDIR) \
		--import \
		--noautoconsole \
		--noreboot
	: Fixing up eth0, must be a better way ...
	$(KVMSH) --shutdown $(1) \
		sed -i -e '"s/HWADDR=.*/HWADDR=\"$$(cat /sys/class/net/e[n-t][h-s]?/address)\"/"' \
			/etc/sysconfig/network-scripts/ifcfg-eth0 \; \
		service network restart \; \
		ip address show scope global
endef

define destroy-kvm-domain
	: destroy-kvm-domain domain=$(1)
	if $(VIRSH) domstate $(1) 2>/dev/null | grep running > /dev/null ; then \
		$(VIRSH) destroy $(1) ; \
	fi
	if $(VIRSH) dominfo $(1) >/dev/null 2>&1 ; then \
		$(VIRSH) undefine $(1) ; \
	fi
endef

define shadow-kvm-disk
	: shadow-kvm-disk to=$(1) from-domain=$(2)
	: shutdown from and fix any disk modes - logging into from messes that up
	$(KVMSH) --shutdown $(2)
	test -r $(KVM_LOCALDIR)/$(2).qcow2 || sudo chgrp $(KVM_GROUP) $(KVM_LOCALDIR)/$(2).qcow2
	test -r $(KVM_LOCALDIR)/$(2).qcow2 || sudo chmod g+r          $(KVM_LOCALDIR)/$(2).qcow2
	: create a shadow - from is used as a backing store
	rm -f $(1)
	qemu-img create -f qcow2 \
		-b $(KVM_LOCALDIR)/$(2).qcow2 \
		$(1)
endef


#
# Create the base domain and (as a side effect) the disk image.
#

# To avoid unintended re-builds triggered by things like a git branch
# switch, this target is order-only dependent on its sources.

# This rule's target is the .ks file - moved into place right at the
# very end.  That way the problem of a virt-install crash leaving the
# disk-image in an incomplete state is avoided.

.PRECIOUS: $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks
$(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks: | $(KVM_ISO) $(KVM_KICKSTART_FILE) $(KVM_BASE_GATEWAY_FILE) $(KVM_BASEDIR)
	$(call check-kvm-qemu-directory)
	$(call destroy-kvm-domain,$(KVM_BASE_DOMAIN))
	: delete any old disk and let virt-install create the image
	rm -f '$(basename $@).qcow2'
	: Confirm that there is a tty - else virt-install fails mysteriously
	tty
	: XXX: Passing $(VIRT_SECURITY) to virt-install causes it to panic
	$(VIRT_INSTALL) \
		--name=$(KVM_BASE_DOMAIN) \
		--os-variant $(KVM_OS_VARIANT) \
		--vcpus=1 \
		--memory 1024 \
		--nographics \
		--disk size=8,cache=writeback,path=$(basename $@).qcow2 \
		$(VIRT_BASE_GATEWAY) \
		$(VIRT_RND) \
		--location=$(KVM_ISO) \
		--initrd-inject=$(KVM_KICKSTART_FILE) \
		--extra-args="swanname=$(KVM_BASE_DOMAIN) ks=file:/$(notdir $(KVM_KICKSTART_FILE)) console=tty0 console=ttyS0,115200" \
		--noreboot
	: the reboot message from virt-install can be ignored
	$(call upgrade-kvm-domain, $(KVM_BASE_DOMAIN))
	cp $(KVM_KICKSTART_FILE) $@
.PHONY: install-kvm-domain-$(KVM_BASE_DOMAIN)
install-kvm-domain-$(KVM_BASE_DOMAIN): $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks

#
# Create the local disk images
#

.PRECIOUS: $(foreach domain, $(KVM_LOCAL_DOMAINS), $(KVM_LOCALDIR)/$(domain).qcow2)

# Create the "clone" disk from the base .ks file (really the base
# disk).

$(KVM_LOCALDIR)/$(KVM_CLONE_DOMAIN).qcow2: | $(KVM_LOCALDIR)
	$(call check-kvm-qemu-directory)
	: create the base domain if needed
	$(MAKE) kvm-install-base-domain
	$(KVMSH) --shutdown $(KVM_BASE_DOMAIN)
	test -r $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).qcow2 || sudo chgrp $(KVM_GROUP) $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).qcow2
	test -r $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).qcow2 || sudo chmod g+r          $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).qcow2
	: create a full copy
	rm -f $@
	qemu-img convert \
		-p -O qcow2 \
		$(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).qcow2 \
		$@.tmp
	mv $@.tmp $@

# Create the basic disk images from clone

KVM_CLONE_DISK_COPIES = $(addsuffix .qcow2, $(addprefix $(KVM_LOCALDIR)/, $(KVM_CLONE_COPIES)))
$(KVM_CLONE_DISK_COPIES): | $(KVM_LOCALDIR)/$(KVM_CLONE_DOMAIN).qcow2
	: copy-clone-disk $@
	$(call check-kvm-qemu-directory)
	$(call shadow-kvm-disk,$@.tmp,$(KVM_CLONE_DOMAIN))
	mv $@.tmp $@

ifneq ($(KVM_BUILD_COPIES),)
KVM_BUILD_DISK_COPIES = $(addsuffix .qcow2, $(addprefix $(KVM_LOCALDIR)/, $(KVM_BUILD_COPIES)))
$(KVM_BUILD_DISK_COPIES): | $(KVM_LOCALDIR)/$(KVM_BUILD_DOMAIN).qcow2
	: copy-build-disk $@
	$(call check-kvm-qemu-directory)
	$(call shadow-kvm-disk,$@.tmp,$(KVM_BUILD_DOMAIN))
	mv $@.tmp $@
endif

#
# Create the local domains
#

# Since running a domain will likely modify its .qcow2 disk image
# (changing MTIME), the domain's disk isn't a good indicator that a
# domain needs updating.  Instead use the .xml file to indicate that a
# domain has been created.

.PRECIOUS: $(foreach domain, $(KVM_LOCAL_DOMAINS), $(KVM_LOCALDIR)/$(domain).xml)

# Create the "clone" domain from the base domain.

$(KVM_LOCALDIR)/$(KVM_CLONE_DOMAIN).xml: \
		| \
		$(KVM_LOCALDIR)/$(KVM_CLONE_DOMAIN).qcow2 \
		$(KVM_BASE_GATEWAY_FILE) \
		$(KVM_LOCALDIR)
	$(call check-kvm-qemu-directory)
	$(call destroy-kvm-domain,$(KVM_CLONE_DOMAIN))
	$(call create-kvm-domain,$(KVM_CLONE_DOMAIN))
	$(VIRSH) dumpxml $(KVM_CLONE_DOMAIN) > $@.tmp
	mv $@.tmp $@
.PHONY: install-kvm-domain-$(KVM_CLONE_DOMAIN)
install-kvm-domain-$(KVM_CLONE_DOMAIN): $(KVM_LOCALDIR)/$(KVM_CLONE_DOMAIN).xml

# Create the "build" domain (if unique)

ifneq ($(KVM_BUILD_COPIES),)
$(KVM_LOCALDIR)/$(KVM_BUILD_DOMAIN).xml: | $(KVM_BASE_NETWORK_FILE) $(KVM_LOCALDIR)/$(KVM_BUILD_DOMAIN).qcow2
	: build-domain $@
	$(call check-kvm-qemu-directory)
	$(call destroy-kvm-domain,$(KVM_BUILD_DOMAIN))
	$(call create-kvm-domain,$(KVM_BUILD_DOMAIN),$@.tmp)
	$(VIRSH) dumpxml $(KVM_BUILD_DOMAIN) > $@.tmp
	mv $@.tmp $@
.PHONY: install-kvm-domain-$(KVM_BUILD_DOMAIN)
install-kvm-domain-$(KVM_BUILD_DOMAIN): $(KVM_LOCALDIR)/$(KVM_BUILD_DOMAIN).xml
endif

#
# Create the test domains
#

define install-kvm-test-domain
  #(info install-kvm-test-domain prefix=$(1) host=$(2) domain=$(1)$(2))
  .PHONY: install-kvm-domain-$(1)$(2)
  install-kvm-domain-$(1)$(2): $$(KVM_LOCALDIR)/$(1)$(2).xml
  $$(KVM_LOCALDIR)/$(1)$(2).xml: \
		| \
		$$(foreach subnet,$$(KVM_TEST_SUBNETS), $$(KVM_LOCALDIR)/$(1)$$(subnet).xml) \
		testing/libvirt/vm/$(2) \
		$(KVM_LOCALDIR)/$(1)$(2).qcow2
	: install-kvm-test-domain prefix=$(1) host=$(2)
	$$(call check-kvm-qemu-directory)
	$$(call destroy-kvm-domain,$(1)$(2))
	sed \
		-e "s:@@NAME@@:$(1)$(2):" \
		-e "s:@@TESTINGDIR@@:$$(KVM_TESTINGDIR):" \
		-e "s:@@SOURCEDIR@@:$$(KVM_SOURCEDIR):" \
		-e "s:@@POOLSPACE@@:$$(KVM_LOCALDIR):" \
		-e "s:@@USER@@:$$(KVM_USER):" \
		-e "s:@@GROUP@@:$$(KVM_GROUP):" \
		-e "s:network='192_:network='$(1)192_:" \
		< 'testing/libvirt/vm/$(2)' \
		> '$$@.tmp'
	$$(VIRSH) define $$@.tmp
	$$(if $$(KVM_F26_HACK),$$(KVM_F26_HACK))
	mv $$@.tmp $$@
endef

$(foreach prefix, $(KVM_PREFIXES), \
	$(foreach host,$(KVM_TEST_HOSTS), \
		$(eval $(call install-kvm-test-domain,$(call strip-prefix,$(prefix)),$(host)))))


#
# Rules to uninstall individual domains
#

define uninstall-kvm-domain-DOMAIN
  #(info uninstall-kvm-domain-DOMAIN domain=$(1) dir=$(2))
  .PHONY: uninstall-kvm-domain-$(1)
  uninstall-kvm-domain-$(1):
	: uninstall-kvm-domain domain=$(1) dir=$(2)
	$$(call destroy-kvm-domain,$(1))
	rm -f $(2)/$(1).xml
	rm -f $(2)/$(1).ks
	rm -f $(2)/$(1).qcow2
	rm -f $(2)/$(1).img
endef

$(foreach domain, $(KVM_BASE_DOMAIN), \
	$(eval $(call uninstall-kvm-domain-DOMAIN,$(domain),$(KVM_BASEDIR))))
$(foreach domain, $(KVM_LOCAL_DOMAINS), \
	$(eval $(call uninstall-kvm-domain-DOMAIN,$(domain),$(KVM_LOCALDIR))))

# Direct dependencies.  This is so that a primitive like
# uninstall-kvm-domain-clone isn't run until all its dependencies,
# such as uninstall-kvm-domain-build, have been run.  Using
# kvm-uninstall-* rules leads to indirect dependencies and
# out-of-order distruction.

$(addprefix uninstall-kvm-domain-, $(KVM_CLONE_DOMAIN)): \
	$(addprefix uninstall-kvm-domain-, $(KVM_CLONE_COPIES))
ifneq ($(KVM_BUILD_COPIES),)
$(addprefix uninstall-kvm-domain-, $(KVM_BUILD_DOMAIN)): \
	$(addprefix uninstall-kvm-domain-, $(KVM_BUILD_COPIES))
endif

#
# Generic kvm-* rules, point at the *-kvm-* primitives defined
# elsewhere.
#

define kvm-hosts-domains
  #(info kvm-host-domains rule=$(1)

  .PHONY: kvm-$(1)-base-domain
  kvm-$(1)-base-domain: $$(addprefix $(1)-kvm-domain-, $$(KVM_BASE_DOMAIN))

  .PHONY: kvm-$(1)-clone-domain
  kvm-$(1)-clone-domain: $$(addprefix $(1)-kvm-domain-, $$(KVM_CLONE_DOMAIN))

  .PHONY: kvm-$(1)-build-domain
  kvm-$(1)-build-domain: $$(addprefix $(1)-kvm-domain-, $$(KVM_BUILD_DOMAIN))

  .PHONY: kvm-$(1)-basic-domains
  kvm-$(1)-basic-domains: $$(addprefix $(1)-kvm-domain-, $$(KVM_BASIC_DOMAINS))

  .PHONY: kvm-$(1)-install-domains
  kvm-$(1)-install-domains: $$(addprefix $(1)-kvm-domain-, $$(KVM_INSTALL_DOMAINS))

  .PHONY: kvm-$(1)-test-domains
  kvm-$(1)-test-domains: $$(addprefix $(1)-kvm-domain-, $$(KVM_TEST_DOMAINS))

  .PHONY: kvm-$(1)-local-domains
  kvm-$(1)-local-domains: $$(addprefix $(1)-kvm-domain-, $$(KVM_LOCAL_DOMAINS))

endef

$(eval $(call kvm-hosts-domains,install))

$(eval $(call kvm-hosts-domains,uninstall))

$(eval $(call kvm-hosts-domains,shutdown))


.PHONY: kvm-install-base-network
kvm-install-base-network: $(addprefix install-kvm-network-, $(KVM_BASE_GATEWAY))

.PHONY: kvm-install-test-networks
kvm-install-test-networks: $(addprefix install-kvm-network-,$(KVM_TEST_NETWORKS))

.PHONY: kvm-install-local-networks
kvm-install-local-networks: kvm-install-test-networks

.PHONY: kvm-uninstall-test-networks
kvm-uninstall-test-networks: $(addprefix uninstall-kvm-network-, $(KVM_TEST_NETWORKS))

.PHONY: kvm-uninstall-base-network
kvm-uninstall-base-network: $(addprefix uninstall-kvm-network-, $(KVM_BASE_GATEWAY))

.PHONY: kvm-uninstall-local-networks
kvm-uninstall-local-networks:  kvm-uninstall-test-networks

#
# Get rid of (almost) everything
#
# XXX: don't depend on targets that trigger a KVM build.

.PHONY: kvm-purge
kvm-purge: kvm-clean kvm-test-clean kvm-keys-clean kvm-uninstall-test-networks kvm-uninstall-local-domains

.PHONY: kvm-demolish
kvm-demolish: kvm-purge kvm-uninstall-base-network kvm-uninstall-base-domain

.PHONY: kvm-clean clean-kvm
kvm-clean clean-kvm: kvm-shutdown-local-domains kvm-clean-keys kvm-clean-tests
	: 'make kvm-DOMAIN-make-clean' to invoke clean on a DOMAIN
	rm -rf $(KVM_OBJDIR)


#
# Build targets
#
# Map the documented targets, and their aliases, onto
# internal/canonical targets.

#
# kvm-build and kvm-HOST|DOMAIN-build
#
# To avoid "make base" and "make module" running in parallel on the
# build machine (stepping on each others toes), this uses two explicit
# commands (each invokes make on the domain) to ensre that "make base"
# and "make modules" are serialized.
#
# Shutdown the domains before building.  The build domain won't boot
# when its clones are running.

define kvm-DOMAIN-build
  #(info kvm-DOMAIN-build domain=$(1))
  .PHONY: kvm-$(1)-build
  kvm-$(1)-build: kvm-shutdown-local-domains | $$(KVM_LOCALDIR)/$(1).xml
	: kvm-DOMAIN-build domain=$(1)
	$(call check-kvm-qemu-directory)
	$$(KVMSH) $$(KVMSH_FLAGS) --chdir . $(1) 'export OBJDIR=$$(KVM_OBJDIR) ; make OBJDIR=$$(KVM_OBJDIR) base'
	$$(KVMSH) $$(KVMSH_FLAGS) --chdir . $(1) 'export OBJDIR=$$(KVM_OBJDIR) ; make OBJDIR=$$(KVM_OBJDIR) module'
	: install will run $$(KVMSH) --shutdown $(1)
endef

# this includes $(KVM_CLONE_DOMAIN)
$(foreach domain, $(KVM_LOCAL_DOMAINS), \
	$(eval $(call kvm-DOMAIN-build,$(domain))))
$(foreach host, $(filter-out $(KVM_DOMAINS), $(KVM_LOCAL_HOSTS)), \
	$(eval $(call kvm-HOST-DOMAIN,kvm-,$(host),-build)))

.PHONY: kvm-build
kvm-build: kvm-$(KVM_BUILD_DOMAIN)-build


# kvm-install and kvm-HOST|DOMAIN-install
#
# "kvm-DOMAIN-install" can't start until the common
# kvm-$(KVM_BUILD_DOMAIN)-build has completed.
#
# After installing shut down the domain.  Otherwise, when KVM_PREFIX
# is large, the idle domains consume huge amounts of memory.
#
# When KVM_PREFIX is large, "make kvm-install" is dominated by the
# below target.  It should be possible to instead create one domain
# with everything installed and then clone it.

define kvm-DOMAIN-install
  #(info kvm-DOMAIN-install domain=$(1))
  .PHONY: kvm-$(1)-install
  kvm-$(1)-install: kvm-shutdown-local-domains kvm-$$(KVM_BUILD_DOMAIN)-build | $$(KVM_LOCALDIR)/$(1).xml
	: kvm-DOMAIN-install domain=$(1)
	$(call check-kvm-qemu-directory)
	$$(KVMSH) $$(KVMSH_FLAGS) --chdir . $(1) 'export OBJDIR=$$(KVM_OBJDIR) ; ./testing/guestbin/swan-install OBJDIR=$$(KVM_OBJDIR)'
	$$(KVMSH) --shutdown $(1)
endef

# this includes $(KVM_CLONE_DOMAIN)
$(foreach domain, $(KVM_LOCAL_DOMAINS), \
	$(eval $(call kvm-DOMAIN-install,$(domain))))
$(foreach host, $(filter-out $(KVM_DOMAINS), $(KVM_LOCAL_HOSTS)), \
	$(eval $(call kvm-HOST-DOMAIN,kvm-,$(host),-install)))

# By default, install where needed.
.PHONY: kvm-install-all
kvm-all-install: $(foreach domain, $(KVM_INSTALL_DOMAINS), kvm-$(domain)-install)

# This is trying to work-around even more broken F26 hosts where the
# build hangs.
#
# - tried OBJDIR=/var/tmp but things still hang so using $(KVM_OBJDIR)
#   for how; pointing KVM_OBJDIR=/var/tmp/KVM.OBJ is still a speed up
#
# - best way to recover from a hang is to uninstall the build domain
#   (should this always do that?)

define kvm-DOMAIN-hive
  #(info kvm-DOMAIN-hive domain=$(1))
  .PHONY: kvm-$(1)-hive
  kvm-$(1)-hive: kvm-$$(KVM_BUILD_DOMAIN)-install uninstall-kvm-domain-$(1)
	$(MAKE) install-kvm-domain-$(1)
endef

$(foreach domain, $(KVM_INSTALL_DOMAINS), \
	$(eval $(call kvm-DOMAIN-hive,$(domain))))
$(foreach host, $(filter-out $(KVM_DOMAINS), $(KVM_INSTALL_HOSTS)), \
	$(eval $(call kvm-HOST-DOMAIN,kvm-,$(host),-hive)))

.PHONY: kvm-install-hive
kvm-hive-install: $(foreach domain, $(KVM_INSTALL_DOMAINS), kvm-$(domain)-hive)

# If BUILD is defined, assume the HIVE install should be used.
.PHONY: kvm-install
ifneq ($(KVM_BUILD_COPIES),)
kvm-install: kvm-hive-install
else
kvm-install: kvm-all-install
endif

# Since the install domains list isn't exhaustive (for instance, nic
# is missing), add an explicit dependency on all the domains so that
# they still get created.
kvm-install: | $(foreach domain,$(KVM_TEST_DOMAINS),$(KVM_LOCALDIR)/$(domain).xml)

#
# kvm-uninstall
#
# Rather than just removing libreswan from the all the test (install)
# domains, this removes the test and build domains completely.  This
# way, in addition to giving kvm-install a 100% fresh start (no
# depdenence on 'make uninstall'), any broken test domains (including
# NIC) are rebuilt.  For instance:
#
#     - a domain hanging because of KVM breakage
#
#     - a domain (including the basic domain NIC) having a wrong
#       directory mount point
#
# Think of this as the make target to use when trying to dig ones way
# out of a hole.

.PHONY: kvm-uninstall
kvm-uninstall: $(addprefix uninstall-kvm-domain-, $(KVM_INSTALL_DOMAINS))
kvm-uninstall: $(addprefix uninstall-kvm-domain-, $(KVM_BASIC_DOMAINS))
ifneq ($(KVM_BUILD_COPIES),)
kvm-uninstall: $(addprefix uninstall-kvm-domain-, $(KVM_BUILD_DOMAIN))
endif


#
# kvmsh-HOST
#
# Map this onto the first domain group.  Logging into the other
# domains can be done by invoking kvmsh.py directly.
#

define kvmsh-DOMAIN
  #(info kvmsh-DOMAIN domain=$(1) file=$(2))
  .PHONY: kvmsh-$(1)
  kvmsh-$(1): | $(2)
	: kvmsh-DOMAIN domain=$(1) file=$(2)
	$(call check-kvm-qemu-directory)
	$$(KVMSH) $$(KVMSH_FLAGS) $(1) $(KVMSH_COMMAND)
endef

$(foreach domain,  $(KVM_BASE_DOMAIN), \
	$(eval $(call kvmsh-DOMAIN,$(domain),$$(KVM_BASEDIR)/$$(KVM_BASE_DOMAIN).ks)))

$(foreach domain,  $(KVM_LOCAL_DOMAINS), \
	$(eval $(call kvmsh-DOMAIN,$(domain),$$(KVM_LOCALDIR)/$(domain).xml)))

$(foreach host, $(filter-out $(KVM_DOMAINS), $(KVM_HOSTS)), \
	$(eval $(call kvm-HOST-DOMAIN,kvmsh-,$(host))))

.PHONY: kvmsh-base
kvmsh-base: kvmsh-$(KVM_BASE_DOMAIN)

ifeq ($(KVM_BUILD_COPIES),)
.PHONY: kvmsh-build
kvmsh-build: kvmsh-$(KVM_BUILD_DOMAIN)
endif


#
# Shutdown domains and hosts.
#

# Generate rules to shut down all the domains (kvm-shutdown) and
# individual domains (kvm-shutdown-domain).
#
# Don't require the domains to exist.

define shutdown-kvm-domain
  #(info shutdown-kvm-domain domain=$(1))
  .PHONY: shutdown-kvm-domain-$(1)
  shutdown-kvm-domain-$(1):
	: shutdown-kvm-domain domain=$(1)
	echo ; \
	if $(VIRSH) dominfo $(1) > /dev/null 2>&1 ; then \
		$(KVMSH) --shutdown $(1) || exit 1 ; \
	else \
		echo Domain $(1) does not exist ; \
	fi ; \
	echo
endef

$(foreach domain, $(KVM_DOMAINS), \
	$(eval $(call shutdown-kvm-domain,$(domain))))

.PHONY: kvm-shutdown
kvm-shutdown: $(addprefix shutdown-kvm-domain-,$(KVM_DOMAINS))

.PHONY: kvm-shutdown-install-domains
kvm-shutdown-install-domains: $(addprefix shutdown-kvm-domain-,$(KVM_INSTALL_DOMAINS))

.PHONY: kvm-shutdown-test-domains
kvm-shutdown-test-domains: $(addprefix shutdown-kvm-domain-,$(KVM_TEST_DOMAINS))

.PHONY: kvm-shutdown-local-domains
kvm-shutdown-local-domains: $(addprefix shutdown-kvm-domain-,$(KVM_LOCAL_DOMAINS))

#
# Some hints
#
# Only what is listed in here is "supported"
#

empty =
comma = ,
sp = $(empty) $(empty)
# the first blank line is ignored
define crlf


endef

define kvm-var-value
$(1)=$(value $(1)) [$($(1))]
endef

define kvm-config

Configuration:

  kvm configuration:

    $(call kvm-var-value,KVM_SOURCEDIR)
    $(call kvm-var-value,KVM_TESTINGDIR)
    $(call kvm-var-value,KVM_PREFIXES)
    $(call kvm-var-value,KVM_WORKERS)
    $(call kvm-var-value,KVM_USER)
    $(call kvm-var-value,KVM_GROUP)
    $(call kvm-var-value,KVM_CONNECTION)

  Directories:

    By default all the VMs are stored in the directory:

      $(call kvm-var-value,KVM_POOLDIR)$(if $(wildcard $(KVM_POOLDIR)),, [MISSING])

    This can be tuned, with the VMs split across two directories:

      $(call kvm-var-value,KVM_BASEDIR)$(if $(wildcard $(KVM_BASEDIR)),, [MISSING])

          for storing the shared base (master) VM; should be
          relatively permenant storage

      $(call kvm-var-value,KVM_LOCALDIR)$(if $(wildcard $(KVM_LOCALDIR)),, [MISSING])

          for storing the VMs dedicated to this build tree; can be
          temporary storage (if you feel lucky you can try pointing
          this at /tmp)

  Networks:

    Two types of networks are used.

    First there is the shared NATting gateway.  It is used by the base
    (master) domain along with any local domains when internet access
    is required:

      $(call kvm-var-value,KVM_BASE_GATEWAY)
      $(call kvm-var-value,KVM_LOCAL_GATEWAY)

    Second there are the local test networks used to interconnect the
    test domains.  Using $$(KVM_PREFIXES), test group is assigned
    their own set of networks:

      $(call kvm-var-value,KVM_TEST_SUBNETS)
      $(call kvm-var-value,KVM_TEST_NETWORKS)

  base domain:

    The (per OS) base domain is used as a shared starting point for
    creating all the other domains.

    Once created the base domain is rarely modified or rebuilt:

    - the process is slow and not 100% reliable

    - the image is shared between build trees

    (instead the clone domain, below, is best suited for trialing new
    packages and domain modifications).

    $(call kvm-var-value,KVM_OS)
    $(call kvm-var-value,KVM_KICKSTART_FILE)
    $(call kvm-var-value,KVM_BASE_HOST)
    $(call kvm-var-value,KVM_BASE_DOMAIN)
    $(call kvm-var-value,KVM_BASE_GATEWAY)
    $(call kvm-var-value,KVM_BASEDIR)

  clone domain:

    The clone domain, made unique to the build tree by KVM_PREFIXES,
    is used as the local starting point for all test domains.

    Since it is not shared across build trees, and has access to the
    real world (via the default network) it is easy to modify or
    rebuild.  For instance, experimental packages can be installed on
    the clone domain (and then the test domains rebuilt) without
    affecting other build trees.

    $(call kvm-var-value,KVM_CLONE_HOST)
    $(call kvm-var-value,KVM_CLONE_DOMAIN)
    $(call kvm-var-value,KVM_LOCAL_GATEWAY)
    $(call kvm-var-value,KVM_LOCALDIR)

  test domains:

    Groups of test domains, made unique to the build tree by
    KVM_PREFIXES, are used to run the tests in parallel.

    Separate build directories should use different KVM_PREFIXES (the
    variable is set in Makefile.inc.local
$(foreach prefix,$(KVM_PREFIXES),$(crlf)\
$(sp) $(sp)test group: $(call strip-prefix,$(prefix))$(crlf) \
$(sp) $(sp) $(sp)domains: $(addprefix $(call strip-prefix,$(prefix)),$(KVM_TEST_HOSTS))$(crlf) \
$(sp) $(sp) $(sp)networks: $(addprefix $(call strip-prefix,$(prefix)),$(KVM_TEST_SUBNETS))$(crlf) \
$(sp) $(sp) $(sp)directory: $(KVM_LOCALDIR))

endef

define kvm-help

Domains and networks:

  These directly manipulate the underling domains and networks and are
  not not generally recommended.  For the most part kvm-install and
  kvm-unsintall are sufficient.

  Domains:

    kvm-install-test-domains
        - create the test domains required by this directory
        - if needed, create dependencies such as the build and base
          domain, and test and base networks
    kvm-install-build-domain
        - create the build domain required by this directory
        - if needed, create dependencies such as the and base
          domain, and test and base networks
    kvm-install-local-domains
        - create all the domains required by this directory
        - if needed, create dependencies such as the base domain and
          networks
    kvm-install-base-domain
        - create the base domain
        - if needed, create the prerequisite base network

    kvm-uninstall-test-domains
        - destroy the test domains required by this directory
	- do not destroy any build or base domains
    kvm-uninstall-build-domains
        - destroy the build domain required by this directory
	- do not destroy any base domains
    kvm-uninstall-local-domains
        - destroy the domains local to this directory
    kvm-uninstall-base-domain
        - destroy the base domain
        - also destroy the derived clone domain and test domains

  Networks:

    kvm-install-local-networks
        - create the networks required by this directory
    kvm-install-base-network
        - create the NATting base network shared by base and clone
          domains

    kvm-uninstall-local-networks
        - destroy all networks local to this directory
        - also destroy the local domains that depend on those networks
        - do not destroy the NATting base gateway
    kvm-uninstall-base-network
        - destroy the NATTing base network shared between base domains
        - also destroy the base and clone domains that use the base
          network

  Try to delete (almost) everything:

    kvm-purge
        - delete everything specific to this directory, i.e., clone
          domain, test domains, test networks, test results, and test
          build
    kvm-demolish
        - also delete the base domain and base network

Standard targets and operations:

  Upgrading domains:

    kvm-upgrade
    kvm-upgrade-local-domains
        - upgrade the local domains
          (do not modify the base domain)
    kvm-upgrade-base-domain
        - upgrade the base domain
          (do not modify the local domains)

  Accessing (loging into) domains:

    kvmsh-base
    kvmsh-clone
    kvmsh-build
    kvmsh-HOST ($(filter-out build, $(KVM_TEST_HOSTS)))
        - use 'virsh console' to login to the given domain
	- for HOST login to the first domain vis $(addprefix $(KVM_FIRST_PREFIX), HOST)
        - if necessary, create and boot the host
    $(addprefix kvmsh-, $(KVM_LOCAL_DOMAINS))
        - login to the specific domain
        - if necessary, create and boot the domain

  Creating and deleting domains:

    kvm-install-base-domain
    kvm-uninstall-base-domain
        - install/uninstall the $(KVM_OS) base domain
    kvm-install-local-domains
    kvm-uninstall-local-domains
        - install/uninstall this directories domains
        - if needed install the $(KVM_OS) base domain

  To build or delete the keys used when testing:

    kvm-keys          - uses the build domain
                        to create the test keys
    kvm-keys-clean    - delete the test keys
                        forcing them to be rebuilt

  To install (or update) libreswan across all domains:

    kvm-install       - set everything up ready for a test
                        run using kvm-check, that is:
                      - if needed, create domains and networks
                      - build or rebuild libreswan using the
                        domain $(KVM_BUILD_DOMAIN)
                      - install libreswan into the test
                        domains $(KVM_INSTALL_DOMAINS)

  To run the testsuite against libreswan installed on the test domains
  (see "make kvm-install" above):

    kvm-check         - run all GOOD tests against the
                        previously installed libreswan
    kvm-check KVM_TESTS=testing/pluto/basic-pluto-0[0-1]
                      - run test matching the pattern
    kvm-check KVM_TEST_FLAGS='--test-status "good|wip"'
                      - run both good and wip tests
    kvm-recheck       - like kvm-check but skip tests that
                        passed during the previous kvm-check
    kvm-check-clean   - delete the test OUTPUT/ directories

  To prepare for a fresh test run:

    kvm-shutdown      - shutdown all domains
    kvm-clean         - clean up the source tree
                        both the kvm build and keys are deleted
                        so that the next kvm-install kvm-test will
                        rebuild them (the test OUTPUT/ is not deleted)
    kvm-uninstall     - force a clean build and install by
                        deleting all the test domains and networks
    distclean         - scrubs the source tree

endef

.PHONY: kvm-help
kvm-help:
	$(info $(kvm-help))
	$(info For more details see "make kvm-config" and "make web-config")

.PHONY: kvm-config
kvm-config:
	$(info $(kvm-config))
