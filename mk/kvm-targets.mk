# KVM make targets, for Libreswan
#
# Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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
KVM_PREFIX ?= ''
KVM_WORKERS ?= 1
KVM_USER ?= $(shell id -u)
KVM_GROUP ?= $(shell id -g qemu)

# The alternative is qemu:///session and it doesn't require root.
# However, it has never been used, and the python tools all assume
# qemu://system. Finally, it comes with a warning: QEMU usermode
# session is not the virt-manager default.  It is likely that any
# pre-existing QEMU/KVM guests will not be available.  Networking
# options are very limited.
KVM_CONNECTION ?= qemu:///system
VIRSH = sudo virsh --connect $(KVM_CONNECTION)
VIRT_INSTALL = sudo virt-install --connect $(KVM_CONNECTION)

# The KVM's operating system.
KVM_OS ?= fedora

# Note:
#
# Need to better differientate between DOMAINs (what KVM calls test
# machines) and HOSTs (what the test framework calls the test
# machines).  This is a transition.

KVM_BASE_DOMAIN = swan$(KVM_OS)base

KVM_TEST_HOSTS = $(notdir $(wildcard testing/libvirt/vm/*[a-z]))
KVM_INSTALL_HOSTS = $(filter-out nic, $(KVM_TEST_HOSTS))

strip-prefix = $(subst '',,$(subst "",,$(1)))
first-prefix = $(call strip-prefix,$(firstword $(KVM_PREFIX)))

KVM_CLONE_HOST ?= clone
KVM_BUILD_HOST ?= $(firstword $(KVM_INSTALL_HOSTS))

KVM_CLONE_DOMAIN = $(addprefix $(call first-prefix), $(KVM_CLONE_HOST))
KVM_BUILD_DOMAIN = $(addprefix $(call first-prefix), $(KVM_BUILD_HOST))

KVM_INSTALL_DOMAINS = $(if $(KVM_PREFIX),$(foreach prefix,$(KVM_PREFIX),$(addprefix $(call strip-prefix,$(prefix)),$(KVM_INSTALL_HOSTS))),$(KVM_INSTALL_HOSTS))
KVM_TEST_DOMAINS = $(if $(KVM_PREFIX),$(foreach prefix,$(KVM_PREFIX),$(addprefix $(call strip-prefix,$(prefix)),$(KVM_TEST_HOSTS))),$(KVM_TEST_HOSTS))
KVM_DOMAINS = $(KVM_BASE_DOMAIN) $(KVM_CLONE_DOMAIN) $(KVM_TEST_DOMAINS)

KVMSH ?= $(abs_top_srcdir)/testing/utils/kvmsh.py
KVMRUNNER ?= $(abs_top_srcdir)/testing/utils/kvmrunner.py

KVM_OBJDIR = OBJ.kvm

# file to mark keys are up-to-date
KVM_KEYS = testing/x509/keys/up-to-date

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

.PHONY: check-kvm-pooldir check-kvm-basedir
check-kvm-pooldir check-kvm-basedir: | $(KVM_POOLDIR) $(KVM_BASEDIR)
ifeq ($(KVM_BASEDIR),$(KVM_POOLDIR))
  $(KVM_POOLDIR):
else
  $(KVM_BASEDIR) $(KVM_POOLDIR):
endif
	:
	:  The pool directory:
	:
	:       "$@"
	:
	:  used to store kvm disk images and other files, does not exist.
	:
	:  Two make variables determine the pool directory\'s location:
	:
	:      KVM_POOLDIR=$(KVM_POOLDIR)
	:                  - used for store test domain disk mages and files
	:
	:      KVM_BASEDIR=$(KVM_BASEDIR)
	:                  - used for store the base domain disk image and files
	:                  - by default it is set to KVM_POOLDIR
	:
	:  Either create the above directory or adjust its location by setting
	:  the above make variables in the file:
	:
	:      Makefile.inc.local
	:
	false


# [re]run the testsuite.
#
# If the testsuite is being run a second time (for instance,
# re-started or re-run) what should happen: run all tests regardless;
# just run tests that have never been started; run tests that haven't
# yet passed?  Since each alternative has merit, let the user decide.

KVM_TESTS ?= testing/pluto

# Given a make command like:
#
#     make kvm-test "KVM_TESTS=$(./testing/utils/kvmresults.py --quick testing/pluto | awk '/output-different/ { print $1 }' )"
#
# then KVM_TESTS ends up containing new lines, strip them out.
STRIPPED_KVM_TESTS = $(strip $(KVM_TESTS))

define kvm-test
	$(call check-kvm-qemu-directory)
	$(call check-kvm-entropy)
	: KVM_TESTS=$(STRIPPED_KVM_TESTS)
	$(KVMRUNNER) $(foreach prefix,$(KVM_PREFIX), --prefix $(prefix))$(if $$(KVM_WORKERS), --workers $(KVM_WORKERS)) $(1) $(KVM_TEST_FLAGS) $(STRIPPED_KVM_TESTS)
endef

# "test" and "check" just runs the entire testsuite.
.PHONY: kvm-check kvm-test
kvm-check kvm-test: $(KVM_KEYS)
	$(call kvm-test, --test-result "good")

# "retest" and "recheck" re-run the testsuite updating things that
# didn't pass.
.PHONY: kvm-retest kvm-recheck
kvm-retest kvm-recheck: $(KVM_KEYS)
	$(call kvm-test, --test-result "good" --skip-passed)

# clean up; accept pretty much everything
KVM_TEST_CLEAN_TARGETS = \
	clean-kvm-check kvm-clean-check kvm-check-clean \
	clean-kvm-test kvm-clean-test kvm-test-clean
.PHONY: $(KVM_TEST_CLEAN_TARGETS)
$(KVM_TEST_CLEAN_TARGETS):
	find $(STRIPPED_KVM_TESTS) -name OUTPUT -type d -prune -print0 | xargs -0 -r rm -r


# Build the keys/certificates using the KVM.
KVM_KEYS_SCRIPT = ./testing/x509/kvm-keys.sh
KVM_KEYS_EXPIRATION_DAY = 14
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
		echo "run 'make clean-kvm-keys kvm-keys' to force an update" ; \
		exit 1 ; \
	fi

# XXX:
#
# Can't yet force the domain's creation.  This target may have been
# invoked by testing/pluto/Makefile which relies on old domain
# configurations.

$(KVM_KEYS): testing/x509/dist_certs.py $(KVM_KEYS_SCRIPT) # | $(KVM_DOMAIN_$(KVM_BUILD_DOMAIN)_FILES)
	$(call check-kvm-domain,$(KVM_BUILD_DOMAIN))
	$(call check-kvm-entropy)
	$(call check-kvm-qemu-directory)
	$(MAKE) clean-kvm-keys
	$(KVM_KEYS_SCRIPT) $(KVM_BUILD_DOMAIN) testing/x509
	touch $(KVM_KEYS)

KVM_KEYS_CLEAN_TARGETS = clean-kvm-keys kvm-clean-keys kvm-keys-clean
.PHONY: $(KVM_KEYS_CLEAN_TARGETS)
$(KVM_KEYS_CLEAN_TARGETS):
	rm -rf testing/x509/*/ testing/x509/nss-pw


#
# Build a pool of networks from scratch
#

# Accumulate a list of all the files created when building the
# network.  Can use this as a dependency to force the networks to be
# built before the domains.

KVM_TEST_NETWORK_FILES=

.PHONY: install-kvm-test-networks uninstall-kvm-test-networks

# Generate install and uninstall rules for each network within the
# pool.

define install-kvm-network
	$(VIRSH) net-define '$(2).tmp'
	$(VIRSH) net-autostart '$(1)'
	$(VIRSH) net-start '$(1)'
	mv $(2).tmp $(2)
endef

define uninstall-kvm-network
	if $(VIRSH) net-info '$(1)' 2>/dev/null | grep 'Active:.*yes' > /dev/null ; then \
		$(VIRSH) net-destroy '$(1)' ; \
	fi
	if $(VIRSH) net-info '$(1)' >/dev/null 2>&1 ; then \
		$(VIRSH) net-undefine '$(1)' ; \
	fi
	rm -f $(2)
endef

define check-no-kvm-network
	if $(VIRSH) net-info '$(1)' 2>/dev/null ; then \
		echo '' ; \
		echo '        The network $(1) seems to already exist.' ; \
		echo '  ' ; \
		echo '  This is most likely because make was aborted part' ; \
		echo '  way through creating the network, however it could be' ; \
		echo '  because the network was created by some other means.' ; \
		echo '' ; \
		echo '  To continue the build, the existing network will first need to' ; \
		echo '  be deleted using:' ; \
		echo '' ; \
		echo '      make uninstall-kvm-network-$(1)' ; \
		echo '' ; \
		exit 1 ; \
	fi
endef

define kvm-test-network
  #(info prefix=$(1) network=$(2))

  KVM_TEST_NETWORK_FILES += $$(KVM_POOLDIR)/$(1)$(2).xml

  install-kvm-test-networks: install-kvm-network-$(1)$(2)
  .PHONY: install-kvm-network-$(1)$(2)
  install-kvm-network-$(1)$(2): $$(KVM_POOLDIR)/$(1)$(2).xml
  .PRECIOUS: $$(KVM_POOLDIR)/$(1)$(2).xml
  $$(KVM_POOLDIR)/$(1)$(2).xml:
	$(call check-no-kvm-network,$(1)$(2),$$@)
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
	$(call install-kvm-network,$(1)$(2),$$@)

  .PHONY: uninstall-kvm-network-$(1)$(2)
  uninstall-kvm-test-networks: uninstall-kvm-network-$(1)$(2)
  uninstall-kvm-network-$(1)$(2):
	$(call uninstall-kvm-network,$(1)$(2),$$(KVM_POOLDIR)/$(1)$(2).xml)

endef

KVM_TEST_NETWORKS = $(notdir $(wildcard testing/libvirt/net/192*))
ifeq ($(KVM_PREFIX),)
$(foreach network,$(KVM_TEST_NETWORKS),$(eval $(call kvm-test-network,,$(network))))
else
$(foreach prefix,$(KVM_PREFIX),$(foreach network,$(KVM_TEST_NETWORKS),$(eval $(call kvm-test-network,$(call strip-prefix,$(prefix)),$(network)))))
endif

# To avoid the problem where the host has no "default" KVM network
# (there's a rumour that libreswan's main testing machine has this
# problem) create a dedicated swandefault.

KVM_BASE_NETWORK = swandefault
KVM_BASE_NETWORK_FILE = $(KVM_BASEDIR)/$(KVM_BASE_NETWORK).xml
.PHONY: install-kvm-base-network install-kvm-network-$(KVM_BASE_NETWORK)
install-kvm-base-network: install-kvm-network-$(KVM_BASE_NETWORK)
install-kvm-network-$(KVM_BASE_NETWORK): $(KVM_BASE_NETWORK_FILE)
$(KVM_BASE_NETWORK_FILE): | testing/libvirt/net/$(KVM_BASE_NETWORK) $(KVM_POOLDIR)
	$(call check-no-kvm-network,$(KVM_BASE_NETWORK),$@)
	cp testing/libvirt/net/$(KVM_BASE_NETWORK) $@.tmp
	$(call install-kvm-network,$(KVM_BASE_NETWORK),$@)

.PHONY: uninstall-kvm-base-network uninstall-kvm-network-$(KVM_BASE_NETWORK)
uninstall-kvm-base-network: uninstall-kvm-network-$(KVM_BASE_NETWORK)
uninstall-kvm-network-$(KVM_BASE_NETWORK): | $(KVM_POOLDIR)
	$(call uninstall-kvm-network,$(KVM_BASE_NETWORK),$(KVM_BASE_NETWORK_FILE))


#
# Build KVM domains from scratch
#


# KVM_ISO_URL_$(KVM_OS) = ...
KVM_ISO_URL_fedora21 = http://fedora.bhs.mirrors.ovh.net/linux/releases/21/Server/x86_64/iso/Fedora-Server-DVD-x86_64-21.iso
KVM_ISO_URL_fedora22 = http://fedora.bhs.mirrors.ovh.net/linux/releases/22/Server/x86_64/iso/Fedora-Server-DVD-x86_64-22.iso
# XXX: Next time the ISO needs an update, set KVM_OS to that release
# and delete the below hack.
KVM_ISO_URL_fedora = $(KVM_ISO_URL_fedora22)
KVM_ISO_URL = $(KVM_ISO_URL_$(KVM_OS))
KVM_ISO = $(KVM_BASEDIR)/$(notdir $(KVM_ISO_URL))
.PHONY: kvm-iso
kvm-iso: $(KVM_ISO)
$(KVM_ISO): | $(KVM_BASEDIR)
	cd $(KVM_BASEDIR) && wget $(KVM_ISO_URL)

# XXX: Needed?
KVM_HVM = $(shell grep vmx /proc/cpuinfo > /dev/null && echo --hvm)

define check-no-kvm-domain
	if $(VIRSH) dominfo '$(1)' 2>/dev/null ; then \
		echo '' ; \
		echo '        The domain $(1) seems to already exist.' ; \
		echo '' ; \
		echo '  This is most likely because to make was aborted part' ; \
		echo '  way through creating the domain, however it could be' ; \
		echo '  because the domain was created by some other means.' ; \
		echo '' ; \
		echo '  To continue the build, the existing domain will first need to' ; \
		echo '  be deleted using:' ; \
		echo '' ; \
		echo '      make uninstall-kvm-domain-$(1)' ; \
		echo '' ; \
		exit 1; \
	fi
endef

define check-kvm-domain
	if $(VIRSH) dominfo '$(1)' >/dev/null ; then : ; else \
		echo "" ; \
		echo "  ERROR: the domain $(1) seems to be missing; run 'make kvm-install'" ; \
		echo "" ; \
		exit 1 ; \
	fi
endef

# XXX: Once KVM_OS gets re-named to include the release, this hack can
# be deleted.
ifeq ($(KVM_OS),fedora)
KVM_KICKSTART_FILE = testing/libvirt/fedora22base.ks
else
KVM_KICKSTART_FILE = testing/libvirt/$(KVM_OS)base.ks
endif
KVM_DEBUGINFO ?= true

# Create the base domain and, as a side effect, the disk image.
#
# To avoid unintended re-builds triggered by things like a git branch
# switch, this target is order-only dependent on its sources.
#
# This rule's target is the .ks file - created at the end.  That way
# the problem of a virt-install crash leaving the disk-image in an
# incomplete state is avoided.

$(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks: | $(KVM_ISO) $(KVM_KICKSTART_FILE) $(KVM_BASE_NETWORK_FILE) $(KVM_BASEDIR)
	$(call check-no-kvm-domain,$(KVM_BASE_DOMAIN))
	$(call check-kvm-qemu-directory)
	$(call check-kvm-entropy)
	rm -f '$(basename $@).qcow2'
	sed -e 's/^kvm_debuginfo=.*/kvm_debuginfo=$(KVM_DEBUGINFO)/' \
		< $(KVM_KICKSTART_FILE) > $@.tmp
	$(VIRT_INSTALL) \
		--network=network:$(KVM_BASE_NETWORK),model=virtio \
		--initrd-inject=$@.tmp \
		--extra-args="swanname=$(KVM_BASE_DOMAIN) ks=file:/$(notdir $@).tmp console=tty0 console=ttyS0,115200" \
		--name=$(KVM_BASE_DOMAIN) \
		--disk size=8,path='$(basename $@).qcow2' \
		--ram 1024 \
		--vcpus=1 \
		--check-cpu \
		--accelerate \
		--location=$(KVM_ISO) \
		--nographics \
		--noreboot \
		$(KVM_HVM)
	: ignore the message about starting the domain
	mv $@.tmp $@

# mostly for testing
.PHONY: install-kvm-base-domain
install-kvm-base-domain: | $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks

.PHONY: install-kvm-clones uninstall-kvm-clones
install-kvm-clones: install-kvm-test-domains
uninstall-kvm-clones: uninstall-kvm-clone-domain uninstall-kvm-test-networks

# Create the "clone" domain from the base domain.
KVM_DOMAIN_$(KVM_CLONE_DOMAIN)_FILES = $(KVM_POOLDIR)/$(KVM_CLONE_DOMAIN).xml
.PRECIOUS: $(KVM_DOMAIN_$(KVM_CLONE_DOMAIN)_FILES
$(KVM_POOLDIR)/$(KVM_CLONE_DOMAIN).xml: $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks | $(KVM_BASE_NETWORK_FILE) $(KVM_POOLDIR)
	$(call check-no-kvm-domain,$(KVM_CLONE_DOMAIN))
	$(call check-kvm-qemu-directory)
	$(call check-kvm-entropy)
	$(KVMSH) --shutdown $(KVM_BASE_DOMAIN)
	qemu-img create \
		-b $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).qcow2 \
		-f qcow2 $(KVM_POOLDIR)/$(KVM_CLONE_DOMAIN).qcow2
	$(VIRT_INSTALL) \
		--name $(KVM_CLONE_DOMAIN) \
		--network network:$(KVM_BASE_NETWORK),model=virtio \
		--memory 512 \
		--disk $(KVM_POOLDIR)/$(KVM_CLONE_DOMAIN).qcow2 \
		--filesystem type=mount,accessmode=squash,source=$(KVM_SOURCEDIR),target=swansource \
		--filesystem type=mount,accessmode=squash,source=$(KVM_TESTINGDIR),target=testing \
		--rng type=random,device=/dev/random \
		--security type=static,model=dac,label='$(KVM_USER):$(KVM_GROUP)',relabel=yes \
		--noreboot \
		--nographics \
		--noautoconsole \
		--import
	: Fixing up eth0, must be a better way ...
	$(KVMSH) --shutdown $(KVM_CLONE_DOMAIN) \
		sed -i -e '"s/HWADDR=.*/HWADDR=\"$$(cat /sys/class/net/eth0/address)\"/"' \
			/etc/sysconfig/network-scripts/ifcfg-eth0 \; \
		service network restart \; \
		ifconfig eth0
	$(VIRSH) dumpxml $(KVM_CLONE_DOMAIN) > $@.tmp
	mv $@.tmp $@
.PHONY: install-kvm-clone-domain
install-kvm-clone-domain install-kvm-domain-$(KVM_CLONE_DOMAIN): $(KVM_POOLDIR)/$(KVM_CLONE_DOMAIN).xml

# Install the $(KVM_TEST_DOMAINS) in $(KVM_POOLDIR)
#
# These are created as clones of $(KVM_CLONE_DOMAIN).
#
# Since running a domain will likely modify its .qcow2 disk image
# (changing MTIME), the domain's disk isn't a good indicator that a
# domain needs updating.  Instead use the .xml file to track the
# domain's creation time.

define install-kvm-test-domain
  #(info install-kvm-test-domain prefix=$(1) host=$(2) domain=$(1)$(2))

  KVM_DOMAIN_$(1)$(2)_FILES = $$(KVM_POOLDIR)/$(1)$(2).xml
  .PRECIOUS: $$(KVM_DOMAIN_$(1)$(2)_FILES)

  .PHONY: install-kvm-domain-$(1)$(2)
  install-kvm-domain-$(1)$(2): $$(KVM_POOLDIR)/$(1)$(2).xml
  $$(KVM_POOLDIR)/$(1)$(2).xml: | $(KVM_POOLDIR)/$(KVM_CLONE_DOMAIN).xml $(KVM_TEST_NETWORK_FILES) testing/libvirt/vm/$(2)
	$(call check-no-kvm-domain,$(1)$(2))
	$(call check-kvm-qemu-directory)
	$(call check-kvm-entropy)
	$(KVMSH) --shutdown $(KVM_CLONE_DOMAIN)
	rm -f '$$(KVM_POOLDIR)/$(1)$(2).qcow2'
	qemu-img create \
		-b $$(KVM_POOLDIR)/$$(KVM_CLONE_DOMAIN).qcow2 \
		-f qcow2 $$(KVM_POOLDIR)/$(1)$(2).qcow2
	sed \
		-e "s:@@NAME@@:$(1)$(2):" \
		-e "s:@@TESTINGDIR@@:$$(KVM_TESTINGDIR):" \
		-e "s:@@SOURCEDIR@@:$$(KVM_SOURCEDIR):" \
		-e "s:@@POOLSPACE@@:$$(KVM_POOLDIR):" \
		-e "s:@@USER@@:$$(KVM_USER):" \
		-e "s:@@GROUP@@:$$(KVM_GROUP):" \
		-e "s:network='192_:network='$(1)192_:" \
		< 'testing/libvirt/vm/$(2)' \
		> '$$@.tmp'
	$(VIRSH) define $$@.tmp
	mv $$@.tmp $$@
endef

$(foreach prefix,$(if $(KVM_PREFIX),$(KVM_PREFIX),''), \
	$(foreach host,$(KVM_TEST_HOSTS), \
		$(eval $(call install-kvm-test-domain,$(call strip-prefix,$(prefix)),$(host)))))

.PHONY: install-kvm-test-domains
install-kvm-test-domains: $(addprefix install-kvm-domain-,$(KVM_TEST_DOMAINS))


#
# Build targets
#

# Map the documented targets, and their aliases, onto
# internal/canonical targets.

.PHONY: kvm-clean clean-kvm
kvm-clean clean-kvm:
	: 'make kvm-DOMAIN-make-clean' to invoke clean on a DOMAIN
	rm -rf $(KVM_OBJDIR)


# kvm-build and kvm-build-DOMAIN
#
# To avoid "make base" and "make module" running in parallel on the
# build machine (stepping on each others toes), this uses two explicit
# commands (each invokes make on the domain) to ensre that "make base"
# and "make modules" are serialized.

define kvm-build-domain
  #(info kvm-build-domain domain=$(1))
  kvm-build-$(1): | $$(KVM_DOMAIN_$(1)_FILES)
	$(call check-kvm-qemu-directory)
	$$(KVMSH) $$(KVMSH_FLAGS) --chdir . $(1) 'export OBJDIR=$$(KVM_OBJDIR) ; make -j2 OBJDIR=$$(KVM_OBJDIR) base'
	$$(KVMSH) $$(KVMSH_FLAGS) --chdir . $(1) 'export OBJDIR=$$(KVM_OBJDIR) ; make -j2 OBJDIR=$$(KVM_OBJDIR) module'
endef

# this includes $(KVM_BASE_DOMAIN), oops
$(foreach domain, $(KVM_DOMAINS), \
	$(eval $(call kvm-build-domain,$(domain))))

.PHONY: kvm-build
kvm-build: kvm-build-$(KVM_BUILD_DOMAIN)


# kvm-install and kvm-install-DOMAIN
#
# "kvm-install-DOMAIN" can't start until the common
# kvm-build-$(KVM_BUILD_DOMAIN) has completed.
#
# After installing shut down the domain.  Otherwise, when KVM_PREFIX
# is large, the idle domains consume huge amounts of memory.
#
# When KVM_PREFIX is large, "make kvm-install" is dominated by the
# below target.  It should be possible to instead create one domain
# with everything installed and then clone it.

define kvm-install-domain
  .PHONY: kvm-install-$(1)
  kvm-install-$(1): kvm-build-$$(KVM_BUILD_DOMAIN) | $$(KVM_DOMAIN_$(1)_FILES)
	$(call check-kvm-qemu-directory)
	$$(KVMSH) $$(KVMSH_FLAGS) --chdir . --shutdown $(1) 'export OBJDIR=$$(KVM_OBJDIR) ; ./testing/guestbin/swan-install OBJDIR=$$(KVM_OBJDIR)'
endef

# this includes $(KVM_BASE_DOMAIN), oops
$(foreach domain, $(KVM_DOMAINS), \
	$(eval $(call kvm-install-domain,$(domain))))

.PHONY: kvm-install
kvm-install: $(addprefix kvm-install-,$(KVM_INSTALL_DOMAINS))
# Since the install domains list isn't exhaustive (for instance, nic
# is missing), add an explicit dependency on the missing domains so
# that they still get created.
kvm-install: | $(foreach domain, $(filter-out $(KVM_INSTALL_DOMAINS),$(KVM_TEST_DOMAINS)),$(KVM_DOMAIN_$(domain)_FILES))


# kvm-uninstall
#
# this is simple and brutal

.PHONY: kvm-uninstall
kvm-uninstall: uninstall-kvm-test-domains


# kvmsh-domain

define kvmsh-domain
  .PHONY: kvmsh-$(1)
  kvmsh-$(1): | $$(KVM_DOMAIN_$(1)_FILES)
	$(call check-kvm-qemu-directory)
	$$(KVMSH) $$(KVMSH_FLAGS) $(1)
endef
$(foreach domain, $(KVM_DOMAINS), \
	$(eval $(call kvmsh-domain,$(domain))))


# Generate rules to uninstall domains
#
# For convenience, provide domain groups.  When removing a group, also
# remove any dependencies.  Otherwise the dependent qcow2 files become
# corrupt.
#
# Should also do this for uninstall-kvm-domain-DOMAIN.

define uninstall-kvm-domain
  #(info uninstall-kvm-domain domain=$(1) dir=$(2))
  .PHONY: uninstall-kvm-domain-$(1)
  uninstall-kvm-domain-$(1):
	if $(VIRSH) domstate $(1) 2>/dev/null | grep running > /dev/null ; then \
		$(VIRSH) destroy $(1) ; \
	fi
	if $(VIRSH) dominfo $(1) >/dev/null 2>&1 ; then \
		$(VIRSH) undefine $(1) ; \
	fi
	rm -f $(2)/$(1).xml
	rm -f $(2)/$(1).ks
	rm -f $(2)/$(1).qcow2
	rm -f $(2)/$(1).img
endef

$(foreach domain, $(KVM_DOMAINS), \
	$(eval $(call uninstall-kvm-domain,$(domain),$(KVM_POOLDIR))))

.PHONY: uninstall-kvm-base-domain
uninstall-kvm-base-domain: $(addprefix uninstall-kvm-domain-,$(KVM_DOMAINS))

.PHONY: uninstall-kvm-clone-domain
uninstall-kvm-clone-domain: $(addprefix uninstall-kvm-domain-,$(KVM_TEST_DOMAINS) $(KVM_CLONE_DOMAIN))

.PHONY: uninstall-kvm-test-domains
uninstall-kvm-test-domains: $(addprefix uninstall-kvm-domain-,$(KVM_TEST_DOMAINS))


# Generate rules to shut down all the domains (kvm-shutdown) and
# individual domains (kvm-shutdown-DOMAIN).
#
# Don't require the domains to exist.

define kvm-shutdown
  #(info kvm-shutdown domain=$(1))
  .PHONY: kvm-shutdown-$(1)
  kvm-shutdown-$(1):
	echo ; \
	if $(VIRSH) dominfo $(1) > /dev/null 2>&1 ; then \
		$(KVMSH) --shutdown $(1) || exit 1 ; \
	else \
		echo Domain $(1) does not exist ; \
	fi ; \
	echo
endef

$(foreach domain, $(KVM_DOMAINS), \
	$(eval $(call kvm-shutdown,$(domain))))

.PHONY: kvm-shutdown
kvm-shutdown: $(addprefix kvm-shutdown-,$(KVM_DOMAINS))


# Some hints
#
# Only what is listed in here is "supported"

.PHONY: kvm-help
kvm-help:
	@echo ''
	@echo ' To set up the test domains and then install or update libreswan:'
	@echo ''
	@echo '   kvm-install           - create the test networks:'
	@echo '                             $(KVM_TEST_NETWORKS)'
	@echo '                         - using $(KVM_BASE_DOMAIN) clone the test domains:'
	@echo '                             $(KVM_TEST_DOMAINS)'
	@echo '                         - build or rebuild libreswan using the domain:'
	@echo '                             $(KVM_BUILD_DOMAIN)'
	@echo '                         - install libreswan into the domains:'
	@echo '                             $(KVM_INSTALL_DOMAINS)'
	@echo ''
	@echo ' To run the testsuite against libreswan installed on the test domains:'
	@echo ''
	@echo '   kvm-check             - run all GOOD tests against the previously installed libreswan'
	@echo '   kvm-check KVM_TESTS=testing/pluto/basic-pluto-0[0-1]'
	@echo '                         - run the tests testing/pluto/basic-pluto-0[0-1]'
	@echo '   kvm-recheck           - like kvm-check but skip tests that passed during the last kvm-check'
	@echo ''
	@echo ' To prepare for a fresh test run:'
	@echo ''
	@echo '   kvm-test-clean        - force a clean test run by deleting test results in OUTPUT (else saved in BACKUP/)'
	@echo '   kvm-clean             - force a clean build by deleting the KVM build in $(KVM_OBJDIR)'
	@echo '   kvm-uninstall         - force a clean install by deleting all the test domains and networks'
	@echo ''
	@echo ' To explicitly wind back to just the bare base domain:'
	@echo ' (use this if you modify the base domain and need to re-clone)'
	@echo ''
	@echo '   install-kvm-clones    - a.k.a. install-kvm-test-domains'
	@echo '   uninstall-kvm-clones  - remove anything except the bare base domain'
	@echo ''
	@echo ' To explicitly create and delete domains use the following sequence:'
	@echo ' (kvm-install and kvm-uninstall do this automatically)'
	@echo ''
	@echo '   install-kvm-base-network    - create the base network:'
	@echo '                                   $(KVM_BASE_NETWORK)'
	@echo '   install-kvm-base-domain     - create the base domain:'
	@echo '                                   $(KVM_BASE_DOMAIN)'
	@echo '   install-kvm-test-networks   - create the test networks:'
	@echo '   install-kvm-test-domains    - create the test domains:'
	@echo ''
	@echo '   uninstall-kvm-base-domain   - delete the base domain and all its dependencies'
	@echo '   uninstall-kvm-test-networks - delete the test networks'
	@echo '   uninstall-kvm-base-network  - delete the base network'
	@echo ''
	@echo ' Also:'
	@echo ''
	@echo '   kvm-keys                - use $(KVM_BUILD_DOMAIN) to create the test keys'
	@echo '   kvm-shutdown            - shutdown all domains'
	@echo '   kvmsh-DOMAIN            - open console on DOMAIN'
	@echo ''
