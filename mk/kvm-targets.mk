# KVM make targets, for Libreswan
#
# Copyright (C) 2015-2017 Andrew Cagney <cagney@gnu.org>
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
KVM_CLONEDIR ?= $(KVM_POOLDIR)
# While KVM_PREFIX might be empty, KVM_PREFIXES is never empty.
KVM_PREFIX ?=
KVM_PREFIXES ?= $(if $(KVM_PREFIX), $(KVM_PREFIX), '')
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

VIRT_RND ?= --rng type=random,device=/dev/random
VIRT_SECURITY ?= --security type=static,model=dac,label='$(KVM_USER):$(KVM_GROUP)',relabel=yes
VIRT_BASE_NETWORK ?= --network=network:$(KVM_DEFAULT_NETWORK),model=virtio
VIRT_SOURCEDIR ?= --filesystem type=mount,accessmode=squash,source=$(KVM_SOURCEDIR),target=swansource
VIRT_TESTINGDIR ?= --filesystem type=mount,accessmode=squash,source=$(KVM_TESTINGDIR),target=testing

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
first-prefix = $(call strip-prefix,$(firstword $(KVM_PREFIXES)))

KVM_CLONE_HOST ?= clone
KVM_BUILD_HOST ?= $(firstword $(KVM_INSTALL_HOSTS))

KVM_CLONE_DOMAIN = $(addprefix $(call first-prefix), $(KVM_CLONE_HOST))
KVM_BUILD_DOMAIN = $(addprefix $(call first-prefix), $(KVM_BUILD_HOST))

KVM_INSTALL_DOMAINS = $(foreach prefix, $(KVM_PREFIXES), \
	$(addprefix $(call strip-prefix,$(prefix)),$(KVM_INSTALL_HOSTS)))
KVM_TEST_DOMAINS = $(foreach prefix, $(KVM_PREFIXES), \
	$(addprefix $(call strip-prefix,$(prefix)),$(KVM_TEST_HOSTS)))
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


.PHONY: check-kvm-clonedir check-kvm-basedir
check-kvm-clonedir check-kvm-basedir: | $(KVM_CLONEDIR) $(KVM_BASEDIR)
ifeq ($(KVM_BASEDIR),$(KVM_CLONEDIR))
  $(KVM_CLONEDIR):
else
  $(KVM_BASEDIR) $(KVM_CLONEDIR):
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
	:      KVM_CLONEDIR=$(KVM_CLONEDIR)
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
	: kvm-test param=$(1)
	$(call check-kvm-qemu-directory)
	$(call check-kvm-entropy)
	: KVM_TESTS=$(STRIPPED_KVM_TESTS)
	$(KVMRUNNER) $(foreach prefix,$(KVM_PREFIXES), --prefix $(prefix))$(if $$(KVM_WORKERS), --workers $(KVM_WORKERS)) $(1) $(KVM_TEST_FLAGS) $(STRIPPED_KVM_TESTS)
endef

# "test" and "check" just runs the entire testsuite.
.PHONY: kvm-check kvm-test
kvm-check kvm-test: $(KVM_KEYS)
	$(call kvm-test, --test-status "good")

# "retest" and "recheck" re-run the testsuite updating things that
# didn't pass.
.PHONY: kvm-retest kvm-recheck
kvm-retest kvm-recheck: $(KVM_KEYS)
	$(call kvm-test, --test-status "good" --skip passed)

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

.PHONY: install-kvm-test-networks uninstall-kvm-test-networks

# Generate install and uninstall rules for each network within the
# pool.

define install-kvm-network
        : install-kvm-network network=$(1) file=$(2)
	$(VIRSH) net-define '$(2).tmp'
	$(VIRSH) net-autostart '$(1)'
	$(VIRSH) net-start '$(1)'
	mv $(2).tmp $(2)
endef

define uninstall-kvm-network
        : uninstall-kvm-network network=$(1) file=$(2)
	if $(VIRSH) net-info '$(1)' 2>/dev/null | grep 'Active:.*yes' > /dev/null ; then \
		$(VIRSH) net-destroy '$(1)' ; \
	fi
	if $(VIRSH) net-info '$(1)' >/dev/null 2>&1 ; then \
		$(VIRSH) net-undefine '$(1)' ; \
	fi
	rm -f $(2)
endef

define check-no-kvm-network
        : uninstall-kvm-network network=$(1)
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

define install-kvm-test-network
  #(info prefix=$(1) network=$(2))

  install-kvm-test-networks: install-kvm-network-$(1)$(2)
  .PHONY: install-kvm-network-$(1)$(2)
  install-kvm-network-$(1)$(2): $$(KVM_CLONEDIR)/$(1)$(2).xml
  .PRECIOUS: $$(KVM_CLONEDIR)/$(1)$(2).xml
  $$(KVM_CLONEDIR)/$(1)$(2).xml:
	: install-kvm-test-network prefix=$(1) network=$(2)
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
endef

define uninstall-kvm-test-network
  #(info prefix=$(1) network=$(2))

  .PHONY: uninstall-kvm-network-$(1)$(2)
  uninstall-kvm-test-networks: uninstall-kvm-network-$(1)$(2)
  uninstall-kvm-network-$(1)$(2):
	: uninstall-kvm-test-network prefix=$(1) network=$(2)
	$(call uninstall-kvm-network,$(1)$(2),$$(KVM_CLONEDIR)/$(1)$(2).xml)
endef

KVM_TEST_NETWORKS = $(notdir $(wildcard testing/libvirt/net/192*))
$(foreach prefix, $(KVM_PREFIXES), \
	$(foreach network, $(KVM_TEST_NETWORKS), \
		$(eval $(call install-kvm-test-network,$(call strip-prefix,$(prefix)),$(network)))))
$(foreach prefix, $(KVM_PREFIXES), \
	$(foreach network, $(KVM_TEST_NETWORKS), \
		$(eval $(call uninstall-kvm-test-network,$(call strip-prefix,$(prefix)),$(network)))))

# To avoid the problem where the host has no "default" KVM network
# (there's a rumour that libreswan's main testing machine has this
# problem) create a dedicated swandefault.

KVM_DEFAULT_NETWORK ?= swandefault
KVM_DEFAULT_NETWORK_FILE = $(KVM_BASEDIR)/$(KVM_DEFAULT_NETWORK).xml
.PHONY: install-kvm-default-network install-kvm-network-$(KVM_DEFAULT_NETWORK)
install-kvm-default-network: install-kvm-network-$(KVM_DEFAULT_NETWORK)
install-kvm-network-$(KVM_DEFAULT_NETWORK): $(KVM_DEFAULT_NETWORK_FILE)
$(KVM_DEFAULT_NETWORK_FILE): | testing/libvirt/net/$(KVM_DEFAULT_NETWORK) $(KVM_BASEDIR)
	$(call check-no-kvm-network,$(KVM_DEFAULT_NETWORK),$@)
	cp testing/libvirt/net/$(KVM_DEFAULT_NETWORK) $@.tmp
	$(call install-kvm-network,$(KVM_DEFAULT_NETWORK),$@)

.PHONY: uninstall-kvm-default-network uninstall-kvm-network-$(KVM_DEFAULT_NETWORK)
uninstall-kvm-default-network: uninstall-kvm-network-$(KVM_DEFAULT_NETWORK)
uninstall-kvm-network-$(KVM_DEFAULT_NETWORK): | $(KVM_BASEDIR)
	$(call uninstall-kvm-network,$(KVM_DEFAULT_NETWORK),$(KVM_DEFAULT_NETWORK_FILE))


#
# Build KVM domains from scratch
#


# KVM_ISO_URL_$(KVM_OS) = ...
KVM_ISO_URL_fedora21 = http://fedora.bhs.mirrors.ovh.net/linux/releases/21/Server/x86_64/iso/Fedora-Server-DVD-x86_64-21.iso
KVM_ISO_URL_fedora22 = http://fedora.bhs.mirrors.ovh.net/linux/releases/22/Server/x86_64/iso/Fedora-Server-DVD-x86_64-22.iso
KVM_ISO_URL_fedora25 = http://fedora.bhs.mirrors.ovh.net/linux/releases/25/Server/x86_64/iso/Fedora-Server-dvd-x86_64-25-1.3.iso
# XXX: Next time the ISO needs an update, set KVM_OS to that release
# and delete the below hack.
KVM_ISO_URL_fedora = $(KVM_ISO_URL_fedora22)
KVM_ISO_URL = $(KVM_ISO_URL_$(KVM_OS))
KVM_ISO = $(KVM_BASEDIR)/$(notdir $(KVM_ISO_URL))
.PHONY: kvm-iso
kvm-iso: $(KVM_ISO)
$(KVM_ISO): | $(KVM_BASEDIR)
	cd $(KVM_BASEDIR) && wget $(KVM_ISO_URL)

define check-no-kvm-domain
	: check-no-kvm-domain domain=$(1)
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
	: check-kvm-domain domain=$(1)
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
KVM_KICKSTART_FILE = testing/libvirt/fedora22.ks
else
KVM_KICKSTART_FILE = testing/libvirt/$(KVM_OS).ks
endif
KVM_DEBUGINFO ?= true

ifeq ($(KVM_OS),fedora25)
	# fedora 25 hack. run swan-transmogrify to initialze Network interscace
	# It does not seems to run the first time when called from /etc/rc.d/rc.local
	# This slows down installation. If you 7 prefixes it could cost 40 min:)
	KVM_F25_HACK=$(KVMSH) --shutdown $(1)$(2) '/testing/guestbin/swan-transmogrify'
else
	KVM_F25_HACK=
endif


# Create the base domain and, as a side effect, the disk image.
#
# To avoid unintended re-builds triggered by things like a git branch
# switch, this target is order-only dependent on its sources.
#
# This rule's target is the .ks file - moved into place right at the
# very end.  That way the problem of a virt-install crash leaving the
# disk-image in an incomplete state is avoided.

KVM_DOMAIN_$(KVM_BASE_DOMAIN)_FILES = $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks
$(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks: | $(KVM_ISO) $(KVM_KICKSTART_FILE) $(KVM_DEFAULT_NETWORK_FILE) $(KVM_BASEDIR)
	$(call check-no-kvm-domain,$(KVM_BASE_DOMAIN))
	$(call check-kvm-qemu-directory)
	$(call check-kvm-entropy)
	: delete any old disk and let virt-install create the image
	rm -f '$(basename $@).qcow2'
	sed -e 's/^kvm_debuginfo=.*/kvm_debuginfo=$(KVM_DEBUGINFO)/' \
		< $(KVM_KICKSTART_FILE) > $@.tmp
	: XXX: Passing $(VIRT_SECURITY) to virt-install causes it to panic
	$(VIRT_INSTALL) \
		--name=$(KVM_BASE_DOMAIN) \
		--vcpus=1 \
		--memory 1024 \
		--nographics \
		--disk size=8,cache=writeback,path=$(basename $@).qcow2 \
		$(VIRT_BASE_NETWORK) \
		$(VIRT_RND) \
		--location=$(KVM_ISO) \
		--initrd-inject=$@.tmp \
		--extra-args="swanname=$(KVM_BASE_DOMAIN) ks=file:/$(notdir $@).tmp console=tty0 console=ttyS0,115200" \
		--noreboot
	: make certain that the image is accessable
	test -r $(basename $@).qcow2 || sudo chgrp $(KVM_GROUP) $(basename $@).qcow2
	test -r $(basename $@).qcow2 || sudo chmod g+r $(basename $@).qcow2
	mv $@.tmp $@
	: the reboot message from virt-install can be ignored
.PHONY: install-kvm-domain-$(KVM_BASE_DOMAIN)
install-kvm-domain-$(KVM_BASE_DOMAIN): $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks

# mostly for testing
.PHONY: install-kvm-base-domain
install-kvm-base-domain: | $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks

# Create the "clone" domain from the base domain.
KVM_DOMAIN_$(KVM_CLONE_DOMAIN)_FILES = $(KVM_CLONEDIR)/$(KVM_CLONE_DOMAIN).xml
.PRECIOUS: $(KVM_DOMAIN_$(KVM_CLONE_DOMAIN)_FILES)
$(KVM_CLONEDIR)/$(KVM_CLONE_DOMAIN).xml: $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks | $(KVM_DEFAULT_NETWORK_FILE) $(KVM_CLONEDIR)
	$(call check-no-kvm-domain,$(KVM_CLONE_DOMAIN))
	$(call check-kvm-qemu-directory)
	$(call check-kvm-entropy)
	$(KVMSH) --shutdown $(KVM_BASE_DOMAIN)
	qemu-img convert -p -O qcow2 \
		$(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).qcow2 \
		$(KVM_POOLDIR)/$(KVM_CLONE_DOMAIN).qcow2
	$(VIRT_INSTALL) \
		--name $(KVM_CLONE_DOMAIN) \
		--vcpus=1 \
		--memory 512 \
		--nographics \
		--disk cache=writeback,path=$(KVM_CLONEDIR)/$(KVM_CLONE_DOMAIN).qcow2 \
		$(VIRT_BASE_NETWORK) \
		$(VIRT_RND) \
		$(VIRT_SECURITY) \
		$(VIRT_SOURCEDIR) \
		$(VIRT_TESTINGDIR) \
		--import \
		--noautoconsole \
		--noreboot
	: Fixing up eth0, must be a better way ...in F25 This works after a reboot.
	$(KVMSH) --shutdown $(KVM_CLONE_DOMAIN) \
		sed -i -e '"s/HWADDR=.*/HWADDR=\"$$(cat /sys/class/net/e[n-t][h-s]?/address)\"/"' \
			/etc/sysconfig/network-scripts/ifcfg-eth0 \; \
		service network restart \; \
		ip address show scope global
	$(VIRSH) dumpxml $(KVM_CLONE_DOMAIN) > $@.tmp
	mv $@.tmp $@
.PHONY: install-kvm-domain-$(KVM_CLONE_DOMAIN)
install-kvm-domain-$(KVM_CLONE_DOMAIN): $(KVM_CLONEDIR)/$(KVM_CLONE_DOMAIN).xml
# mostly for testing
.PHONY: install-kvm-clone-domain
install-kvm-clone-domain: $(KVM_CLONEDIR)/$(KVM_CLONE_DOMAIN).xml

# Install the $(KVM_TEST_DOMAINS) in $(KVM_CLONEDIR)
#
# These are created as clones of $(KVM_CLONE_DOMAIN).
#
# Since running a domain will likely modify its .qcow2 disk image
# (changing MTIME), the domain's disk isn't a good indicator that a
# domain needs updating.  Instead use the .xml file to track the
# domain's creation time.

define install-kvm-test-domain
  #(info install-kvm-test-domain prefix=$(1) host=$(2) domain=$(1)$(2))

  KVM_DOMAIN_$(1)$(2)_FILES = $$(KVM_CLONEDIR)/$(1)$(2).xml
  .PRECIOUS: $$(KVM_DOMAIN_$(1)$(2)_FILES)

  .PHONY: install-kvm-domain-$(1)$(2)
  install-kvm-domain-$(1)$(2): $$(KVM_CLONEDIR)/$(1)$(2).xml
  $$(KVM_CLONEDIR)/$(1)$(2).xml: \
		| \
		$$(KVM_CLONEDIR)/$$(KVM_CLONE_DOMAIN).xml \
		$$(foreach network,$$(KVM_TEST_NETWORKS), $$(KVM_CLONEDIR)/$(1)$$(network).xml) \
		testing/libvirt/vm/$(2)
	: install-kvm-test-domain prefix=$(1) host=$(2)
	$(call check-no-kvm-domain,$(1)$(2))
	$(call check-kvm-qemu-directory)
	$(call check-kvm-entropy)
	$(KVMSH) --shutdown $(KVM_CLONE_DOMAIN)
	rm -f '$$(KVM_CLONEDIR)/$(1)$(2).qcow2'
	qemu-img create \
		-b $$(KVM_CLONEDIR)/$$(KVM_CLONE_DOMAIN).qcow2 \
		-f qcow2 $$(KVM_CLONEDIR)/$(1)$(2).qcow2
	sed \
		-e "s:@@NAME@@:$(1)$(2):" \
		-e "s:@@TESTINGDIR@@:$$(KVM_TESTINGDIR):" \
		-e "s:@@SOURCEDIR@@:$$(KVM_SOURCEDIR):" \
		-e "s:@@POOLSPACE@@:$$(KVM_CLONEDIR):" \
		-e "s:@@USER@@:$$(KVM_USER):" \
		-e "s:@@GROUP@@:$$(KVM_GROUP):" \
		-e "s:network='192_:network='$(1)192_:" \
		< 'testing/libvirt/vm/$(2)' \
		> '$$@.tmp'
	$(VIRSH) define $$@.tmp
	$(KVM_F25_HACK)
	mv $$@.tmp $$@
endef

$(foreach prefix, $(KVM_PREFIXES), \
	$(foreach host,$(KVM_TEST_HOSTS), \
		$(eval $(call install-kvm-test-domain,$(call strip-prefix,$(prefix)),$(host)))))

.PHONY: install-kvm-test-domains
install-kvm-test-domains: $(addprefix install-kvm-domain-,$(KVM_TEST_DOMAINS))


#
# Rules to uninstall individual domains
#
# Note that these low-level rules do not uninstall the networks.
#

define uninstall-kvm-domain
  #(info uninstall-kvm-domain domain=$(1) dir=$(2))
  .PHONY: uninstall-kvm-domain-$(1)
  uninstall-kvm-domain-$(1):
	: uninstall-kvm-domain domain=$(1) dir=$(2)
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

$(foreach domain, $(KVM_BASE_DOMAIN), \
	$(eval $(call uninstall-kvm-domain,$(domain),$(KVM_POOLDIR))))
$(foreach domain, $(KVM_CLONE_DOMAIN) $(KVM_TEST_DOMAINS), \
	$(eval $(call uninstall-kvm-domain,$(domain),$(KVM_CLONEDIR))))


#
# Generic kvm-install-* and kvm-uninstall-* rules, point at the
# install-kvm-* and uninstall-kvm-* versions.
#

.PHONY: kvm-install-base-domain
kvm-install-base-domain: $(addprefix install-kvm-domain-,$(KVM_BASE_DOMAIN))

.PHONY: kvm-install-clone-domain
kvm-install-clone-domain: $(addprefix install-kvm-domain-,$(KVM_CLONE_DOMAIN))

.PHONY: kvm-install-test-domains
kvm-install-test-domains: $(addprefix install-kvm-domain-,$(KVM_TEST_DOMAINS))

.PHONY: kvm-uninstall-base-domain
kvm-uninstall-base-domain: kvm-uninstall-clone-domain $(addprefix uninstall-kvm-domain-,$(KVM_BASE_DOMAIN))

.PHONY: kvm-uninstall-clone-domain
kvm-uninstall-clone-domain: kvm-uninstall-test-domains $(addprefix uninstall-kvm-domain-,$(KVM_CLONE_DOMAIN))

.PHONY: kvm-uninstall-test-domains
kvm-uninstall-test-domains: $(addprefix uninstall-kvm-domain-,$(KVM_TEST_DOMAINS))


#
# Build targets
#

# Map the documented targets, and their aliases, onto
# internal/canonical targets.

.PHONY: kvm-clean clean-kvm
kvm-clean clean-kvm: kvm-shutdown
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
	: kvm-build-domain domain=$(1)
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
	: kvm-install-domain domain=$(1)
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

# kvm-uninstall et.al.
#
# these are simple and brutal

.PHONY: kvm-uninstall
kvm-uninstall: uninstall-kvm-test-domains uninstall-kvm-test-networks

.PHONY: kvm-uninstall-clones
kvm-uninstall-clones: uninstall-kvm-clone-domain uninstall-kvm-test-networks

# This does not uninstall-kvm-default-network as that is shared between
# base domains.
.PHONY: kvm-uninstall-base
kvm-uninstall-base: uninstall-kvm-base-domain uninstall-kvm-test-networks


#
# kvmsh-HOST
#
# Map this onto the first-prefix domain group.  Logging into the other
# domains can be done by invoking kvmsh.py directly.
#

define kvmsh
  #(info host=$(1) domain=$(2))
  .PHONY: kvmsh-$(1)
  kvmsh-$(1): | $$(KVM_DOMAIN_$(2)_FILES)
	: kvmsh-host host=$(1)
	$(call check-kvm-qemu-directory)
	$$(KVMSH) $$(KVMSH_FLAGS) $(2)
endef
$(foreach host, $(KVM_TEST_HOSTS), \
	$(eval $(call kvmsh,$(host),$(call first-prefix)$(host))))
$(eval $(call kvmsh,build,$(KVM_BUILD_DOMAIN)))
$(eval $(call kvmsh,clone,$(KVM_CLONE_DOMAIN)))
$(eval $(call kvmsh,base,$(KVM_BASE_DOMAIN)))


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
	: kvm-shutdown domain=$(1)
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


#
# Hack to push test results onto a remote machine.
#

KVM_GITSTAMP ?= $(shell id --name --user)-$(shell make showversion)

.PHONY: kvm-publish
kvm-publish:
	: is KVM_PUBLISHDIR valid
	test -n "$(KVM_PUBLISHDIR)"
	: generate and copy over the results
	./testing/web/rsync-tests.sh . $(KVM_PUBLISHDIR)/$(KVM_GITSTAMP)
	./testing/web/rsync-results.sh . $(KVM_PUBLISHDIR)/$(KVM_GITSTAMP)
	./testing/web/build-results.sh . testing/pluto $(KVM_PUBLISHDIR)/$(KVM_GITSTAMP)

# Some hints
#
# Only what is listed in here is "supported"

empty =
comma = ,

.PHONY: kvm-help
kvm-help:
	@echo ''
	@echo ' Configuration:'
	@echo ''
	@echo '   make variables:'
	@echo ''
	@: $(foreach variable, KVM_SOURCEDIR KVM_TESTINGDIR KVM_POOLDIR KVM_BASEDIR \
			       KVM_CLONEDIR KVM_PREFIXES KVM_WORKERS KVM_USER KVM_GROUP \
			       KVM_CONNECTION KVM_PUBLISHDIR, \
		; echo '     $(variable)=$(value $(variable)) ($($(variable)))' \
	)
	@echo ''
	@echo '   default network:'
	@echo ''
	@echo '     The default network, used by the base and clone domains,'
	@echo '     provides a NATed gateway to the real world.'
	@echo ''
	@echo '     network: $(KVM_DEFAULT_NETWORK)'
	@echo ''
	@echo '   base domain:'
	@echo ''
	@echo '     The (per OS) base domain is used as a shared starting'
	@echo '     point for creating all the other domains.'
	@echo ''
	@echo '     Once created the base domain is rarely modified or'
	@echo '     rebuilt:'
	@echo ''
	@echo '     - the process is slow and not 100% reliable'
	@echo ''
	@echo '     - the image is shared between build trees'
	@echo ''
	@echo '     (instead the clone domain, below, is best suited for'
	@echo '     trialing new packages and domain modifications).'
	@echo ''
	@echo '     os: $(KVM_OS)'
	@echo '     domain: $(KVM_BASE_DOMAIN)'
	@echo '     network: $(KVM_DEFAULT_NETWORK)'
	@echo '     directory: $(KVM_BASEDIR)'
	@echo ''
	@echo '   clone domain:'
	@echo ''
	@echo '     The clone domain, made unique to the build tree by'
	@echo '     KVM_PREFIXES, is used as the local starting point for all'
	@echo '     test domains.'
	@echo ''
	@echo '     Since it is not shared across build trees, and has access'
	@echo '     to the real world (via the default network) it is easy to'
	@echo '     modify or rebuild.  For instance, experimental packages'
	@echo '     can be installed on the clone domain (and then the'
	@echo '     test domains rebuilt) without affecting other build trees.'
	@echo ''
	@echo '     domain: $(KVM_CLONE_DOMAIN)'
	@echo '     network: $(KVM_DEFAULT_NETWORK)'
	@echo '     directory: $(KVM_CLONEDIR)'
	@echo ''
	@echo '   test domains'
	@echo ''
	@echo '     Groups of test domains, made unique to the build tree by'
	@echo '     KVM_PREFIXES, are used to run the tests in parallel.'
	@echo ''
	@echo '     Separate build directories should use different'
	@echo '     KVM_PREFIXES (the variable is set in Makefile.inc.local'
	@: $(foreach prefix, $(KVM_PREFIXES), \
		; echo '' \
		; echo '     test group: $(call strip-prefix,$(prefix))' \
		; echo '' \
		; echo '       domains: $(addprefix $(call strip-prefix,$(prefix)),$(KVM_TEST_HOSTS))' \
		; echo '       networks: $(addprefix $(call strip-prefix,$(prefix)),$(KVM_TEST_NETWORKS))' \
		; echo '       directory: $(KVM_CLONEDIR)' \
		)
	@echo ''
	@echo ' Low-level make targets:'
	@echo ''
	@echo '   These directly manipulate the underling domains and'
	@echo '   networks and are not not generally recommended.'
	@echo '   For the most part kvm-install and kvm-unsintall are'
	@echo '   sufficient.'
	@echo ''
	@echo '   Their names and behaviour also have a habit of changing'
	@echo '   over time:'
	@echo ''
	@echo '   Creating domains:'
	@echo ''
	@echo '     kvm-install-test-domains   - create the test domains'
	@echo '                                  from the clone domain'
	@echo '                                  disk image'
	@echo '                                - if needed, create the'
	@echo '                                  prerequisite clone domain,'
	@echo '                                  test networks, base domain,'
	@echo '                                  and default network'
	@echo ''
	@echo '     kvm-install-clone-domain   - create the clone domain'
	@echo '                                  from the base domain disk'
	@echo '                                  image'
	@echo '                                - if needed, create the'
	@echo '                                  prerequisite base domain'
	@echo '                                  and default network'
	@echo ''
	@echo '     kvm-install-base-domain    - create the base domain'
	@echo '                                - if needed, create the'
	@echo '                                  prerequisite default'
	@echo '                                  network'
	@echo ''
	@echo '   Destroying domains:'
	@echo ''
	@echo '     kvm-uninstall-test-domains - destroy the test domains'
	@echo ''
	@echo '     kvm-uninstall-clone-domain - destroy the clone domain,'
	@echo '                                - also destroy the derived'
	@echo '                                  test domains'
	@echo ''
	@echo '     kvm-uninstall-base-domain  - destroy the base domain'
	@echo '                                - also destroy the derived'
	@echo '                                  clone domain and test domains'
	@echo ''
	@echo '   Create/destroy the default NAT network $(KVM_DEFAULT_NETWORK):'
	@echo ''
	@echo '     install-kvm-default-network    - create the default NAT'
	@echo '                                      network shared between'
	@echo '                                      base domains'
	@echo '     uninstall-kvm-default-network  - destroy the default NAT'
	@echo '                                      network shared between'
	@echo '                                      base domains'
	@echo ''
	@echo ' Additional rules:'
	@echo ''
	@echo '   kvm-keys          - use the build domain ($(KVM_BUILD_DOMAIN))'
	@echo '                       to create the test keys'
	@echo '   kvm-shutdown      - shutdown all domains'
	@echo '   kvmsh-{$(subst $(empty) $(empty),$(comma),base clone build $(KVM_TEST_HOSTS))}'
	@echo '                     - log into the domain using kvmsh.py'
	@echo '                     - for test domains log into $(call first-prefix)HOST'
	@echo '   kvm-publish       - use rsync to publish test results'
	@echo '                       to KVM_PUBLISHDIR=$(KVM_PUBLISHDIR)'
	@echo ''
	@echo ' RECOMMENDED:'
	@echo ''
	@echo ' To set up all the necessary domains and networks and then'
	@echo ' install or update libreswan:'
	@echo ''
	@echo '   kvm-install       - set everything up ready for a test'
	@echo '                       run using kvm-check, that is:'
	@echo '                       + if needed, create domains and networks'
	@echo '                       + build or rebuild libreswan using the'
	@echo '                         domain $(KVM_BUILD_DOMAIN)'
	@echo '                       + install libreswan into the test'
	@echo '                         domains $(KVM_INSTALL_DOMAINS)'
	@echo ''
	@echo ' To run the testsuite against libreswan installed on the test'
	@echo ' domains:'
	@echo ''
	@echo '   kvm-check         - run all GOOD tests against the'
	@echo '                       previously installed libreswan'
	@echo '   kvm-check KVM_TESTS=testing/pluto/basic-pluto-0[0-1]'
	@echo '                     - run the individual tests:'
	@echo '                         testing/pluto/basic-pluto-00'
	@echo '                         testing/pluto/basic-pluto-01'
	@echo '   kvm-recheck       - like kvm-check but skip tests that'
	@echo '                       passed during the last kvm-check'
	@echo ''
	@echo ' To prepare for a fresh test run:'
	@echo ''
	@echo '   kvm-test-clean    - force a clean test run by deleting'
	@echo '                       test results in OUTPUT (else saved in'
	@echo '                       BACKUP/)'
	@echo '   kvm-clean         - force a clean build by deleting the'
	@echo '                       KVM build in $(KVM_OBJDIR)'
	@echo '   kvm-uninstall     - force a clean install by deleting all'
	@echo '                       the test domains and networks'
	@echo '   distclean         - scrubs the source tree'
	@echo ''
