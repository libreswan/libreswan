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
# KVM_POOLDIR ?= /home/build/pool
KVM_BASEDIR ?= $(KVM_POOLDIR)

# The KVM's operating system.
KVM_OS ?= fedora

KVM_BASE_DOMAIN = swan$(KVM_OS)base
KVM_TEST_DOMAINS = $(notdir $(wildcard testing/libvirt/vm/*[a-z]))
KVM_INSTALL_DOMAINS = $(filter-out nic, $(KVM_TEST_DOMAINS))
KVM_DOMAINS = $(KVM_TEST_DOMAINS) $(KVM_BASE_DOMAIN)
KVM_QEMUDIR = /var/lib/libvirt/qemu

KVMSH_COMMAND ?= $(abs_top_srcdir)/testing/utils/kvmsh.py
KVMSH ?= $(KVMSH_COMMAND)
KVM_WORKERS ?= 1
KVMRUNNER_COMMAND ?= $(abs_top_srcdir)/testing/utils/kvmrunner.py
KVMRUNNER ?= $(KVMRUNNER_COMMAND)$(foreach pool,$(KVM_POOL), --prefix $(pool))$(if $(KVM_WORKERS), --workers $(KVM_WORKERS))

KVM_OBJDIR = OBJ.kvm

# file to mark keys are up-to-date
KVM_KEYS = testing/x509/keys/up-to-date

#
# Check that things are correctly configured for creating the KVM
# domains
#

KVM_CONFIG =

ifeq ($(shell test -w $(KVM_QEMUDIR) && echo ok),)
KVM_CONFIG += kvm-config-broken-qemu
endif
.PHONY: kvm-config-broken-qemu
kvm-config-broken-qemu:
	@echo ''
	@echo 'The directory:'
	@echo ''
	@echo '    $(KVM_QEMUDIR)'
	@echo ''
	@echo 'is not writeable.  This will break virsh which is'
	@echo 'used to manipulate the domains.'
	@echo ''
	@exit 1

ifeq ($(wildcard $(KVM_POOLDIR)),)
KVM_CONFIG += kvm-config-missing-pooldir
endif
.PHONY: kvm-config-missing-pooldir
kvm-config-missing-pooldir:
	@echo ''
	@echo 'The directory "$(KVM_POOLDIR)", specified by KVM_POOLDIR, does not exist.'
	@echo ''
	@echo 'The make variable KVM_POOLDIR specifies the directory to store the test domain and network files.'
	@echo ''
	@echo 'Either:'
	@echo '    - create the directory "$(KVM_POOLDIR)"'
	@echo 'or:'
	@echo '    - set KVM_POOLDIR in Makefile.inc.local'
	@echo ''
	@exit 1

ifeq ($(wildcard $(KVM_BASEDIR)),)
KVM_CONFIG += kvm-config-missing-basedir
endif
.PHONY: kvm-config-missing-basedir
kvm-config-missing-basedir:
	@echo ''
	@echo 'The directory '$(KVM_BASEDIR)', specified by KVM_BASEDIR, does not exist'
	@echo ''
	@echo 'The make variable KVM_BASEDIR specifies the directory to store the base domain configuration files.'
	@echo ''
	@echo 'KVM_BASEDIR defaults to KVM_POOLDIR ($(KVM_POOLDIR)).'
	@exit 1


# Invoke KVMSH in the curret directory with $(1).
define kvmsh
	: KVM_OBJDIR: '$(KVM_OBJDIR)'
	test -w $(KVM_QEMUDIR) || $(MAKE) --no-print-directory kvm-config-broken-qemu
	$(KVMSH) --output ++compile-log.txt --chdir . $(1)
endef

# [re]run the testsuite.
#
# If the testsuite is being run a second time (for instance,
# re-started or re-run) what should happen: run all tests regardless;
# just run tests that have never been started; run tests that haven't
# yet passed?  Since each alternative has merit, let the user decide.

KVM_TESTS = testing/pluto

# Given a make command like:
#
#     make kvm-test "KVM_TESTS=$(./testing/utils/kvmresults.py --quick testing/pluto | awk '/output-different/ { print $1 }' )"
#
# then KVM_TESTS ends up containing new lines, strip them out.
STRIPPED_KVM_TESTS = $(strip $(KVM_TESTS))

# "check" runs any test that has not yet passed (that is: failed,
# incomplete, and not started).  This is probably the safest option.
.PHONY: kvm-check kvm-check-good kvm-check-all
kvm-check: kvm-check-good
kvm-check-good: $(KVM_KEYS)
	: KVM_TESTS = $(STRIPPED_KVM_TESTS)
	$(KVMRUNNER) --retry  1 --test-result "good"     $(STRIPPED_KVM_TESTS)
kvm-check-all: $(KVM_KEYS)
	: KVM_TESTS = $(STRIPPED_KVM_TESTS)
	$(KVMRUNNER) --retry  1 --test-result "good|wip" $(STRIPPED_KVM_TESTS)

# "test" runs tests regardless.  It is best used with the KVM_TESTS
# varible.
.PHONY: kvm-test-good kvm-test-all
kvm-test: kvm-test-good
kvm-test: $(KVM_KEYS)
	: KVM_TESTS = $(STRIPPED_KVM_TESTS)
	$(KVMRUNNER) --retry -1 --test-result "good"     $(STRIPPED_KVM_TESTS)
kvm-test-all: $(KVM_KEYS)
	: KVM_TESTS = $(STRIPPED_KVM_TESTS)
	$(KVMRUNNER) --retry -1 --test-result "good|wip" $(STRIPPED_KVM_TESTS)

# clean up; accept pretty much everything
KVM_TEST_CLEAN_TARGETS = \
	clean-kvm-check kvm-clean-check kvm-check-clean \
	clean-kvm-test kvm-clean-test kvm-test-clean
.PHONY: $(KVM_TEST_CLEAN_TARGETS)
$(KVM_TEST_CLEAN_TARGETS):
	rm -rf $(KVM_TESTS)/*/OUTPUT*


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

$(KVM_KEYS): testing/x509/dist_certs.py $(KVM_KEYS_SCRIPT)
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

# The offical network targets.
.PHONY: install-kvm-networks uninstall-kvm-networks

# Mainly for consistency
.PHONY: install-kvm-test-networks uninstall-kvm-test-networks
install-kvm-networks: install-kvm-test-networks
uninstall-kvm-networks: uninstall-kvm-test-networks

# Generate install and uninstall rules for each network within the
# pool.

define install-kvm-network
	sudo virsh net-define '$(2).tmp'
	sudo virsh net-autostart '$(1)'
	sudo virsh net-start '$(1)'
	mv $(2).tmp $(2)
endef

define uninstall-kvm-network
	if sudo virsh net-info '$(1)' 2>/dev/null | grep 'Active:.*yes' > /dev/null ; then \
		sudo virsh net-destroy '$(1)' ; \
	fi
	if sudo virsh net-info '$(1)' >/dev/null 2>&1 ; then \
		sudo virsh net-undefine '$(1)' ; \
	fi
	rm -f $(2)
endef

define check-no-kvm-network
	if sudo virsh net-info '$(1)' 2>/dev/null ; then \
		echo 'The network $(1) seems to already exist.  Either clean it up with:' ; \
		echo '' ; \
		echo '    make uninstall-kvm-network-$(1)' ; \
		echo '' ; \
		echo 'Or skip creating the network with:' ; \
		echo '' ; \
		echo '    touch $(2)' ; \
		echo '' ; \
		exit 1 ; \
	fi
endef

define kvm-test-network
  #(info pool=$(1) network=$(2))

  KVM_TEST_NETWORK_FILES += $$(KVM_POOLDIR)/$(1)$(2).xml

  .PHONY: install-kvm-network-$(1)$(2)
  install-kvm-test-networks install-kvm-network-$(1)$(2): $$(KVM_POOLDIR)/$(1)$(2).xml
  .PRECIOUS: $$(KVM_POOLDIR)/$(1)$(2).xml
  $$(KVM_POOLDIR)/$(1)$(2).xml:
	$(call check-no-kvm-network,$(1)$(2),$$@)
	rm -f '$$@.tmp'
	echo "<network ipv6='yes'>"					>> '$$@.tmp'
	echo "  <name>$(1)$(2)</name>"					>> '$$@.tmp'
	echo "  <bridge name='$(1)$(2)' stp='on' delay='0'/>"		>> '$$@.tmp'
	case "$(1)$(2)" in \
		192_0_* ) echo '  <ip address="$(2).127"/>' ;; \
		192_* )   echo '  <ip address="$(2).253"/>' ;; \
	esac | sed -e 's/_/./g'						>> '$$@.tmp'
	echo "</network>"						>> '$$@.tmp'
	$(call install-kvm-network,$(1)$(2),$$@)

  .PHONY: uninstall-kvm-network-$(1)$(2)
  uninstall-kvm-test-networks: uninstall-kvm-network-$(1)$(2)
  uninstall-kvm-network-$(1)$(2):
	$(call uninstall-kvm-network,$(1)$(2),$$(KVM_POOLDIR)/$(1)$(2).xml)

endef

KVM_TEST_NETWORKS = $(notdir $(wildcard testing/libvirt/net/192*))
ifdef KVM_POOL
$(foreach pool,$(KVM_POOL),$(foreach network,$(KVM_TEST_NETWORKS),$(eval $(call kvm-test-network,$(pool),$(network)))))
else
$(foreach network,$(KVM_TEST_NETWORKS),$(eval $(call kvm-test-network,,$(network))))
endif

# To avoid the problem where the host has no "default" KVM network
# (there's a rumour that libreswan's main testing machine has this
# problem) create a dedicated swandefault.

KVM_BASE_NETWORK = swandefault
KVM_BASE_NETWORK_FILE = $(KVM_BASEDIR)/$(KVM_BASE_NETWORK).xml
.PHONY: install-kvm-base-network install-kvm-network-$(KVM_BASE_NETWORK)
install-kvm-base-network install-kvm-network-$(KVM_BASE_NETWORK): $(KVM_BASE_NETWORK_FILE)
$(KVM_BASE_NETWORK_FILE): $(KVM_CONFIG) | testing/libvirt/net/$(KVM_BASE_NETWORK)
	$(call check-no-kvm-network,$(KVM_BASE_NETWORK),$@)
	cp testing/libvirt/net/$(KVM_BASE_NETWORK) $@.tmp
	$(call install-kvm-network,$(KVM_BASE_NETWORK),$@)

.PHONY: uninstall-kvm-base-network uninstall-kvm-network-$(KVM_BASE_NETWORK)
uninstall-kvm-base-network uninstall-kvm-network-$(KVM_BASE_NETWORK): $(KVM_CONFIG)
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
$(KVM_ISO):
	cd $(KVM_BASEDIR) && wget $(KVM_ISO_URL)

# XXX: Needed?
KVM_HVM = $(shell grep vmx /proc/cpuinfo > /dev/null && echo --hvm)

# Build the base domain's disk image in $(KVM_BASEDIR).
#
# Use a pattern rule so that GNU make knows that two things are built.
#
# This rule uses order-only dependencies so that unintended re-builds,
# triggered says by switching git branches say, do not occure.
#
# This rule uses the .ks file as main target.  Should the target fail
# the .img file may be in an incomplete state.

define install-kvm-domain
	sudo virsh define $(2).tmp
	mv $(2).tmp $(2)
endef

define uninstall-kvm-domain
	if sudo virsh domstate '$(1)' 2>/dev/null | grep running > /dev/null ; then \
		sudo virsh destroy '$(1)' ; \
	fi
	if sudo virsh dominfo '$(1)' >/dev/null 2>&1 ; then \
		sudo virsh undefine '$(1)' --remove-all-storage ; \
	fi
	rm -f $(2).xml
	rm -f $(2).ks
	rm -f $(2).qcow2
	rm -f $(2).img
endef

define check-no-kvm-domain
	if sudo virsh dominfo '$(1)' 2>/dev/null ; then \
		echo 'The domain $(1) seems to already exist.  Either clean it up with:' ; \
		echo '' ; \
		echo '    make uninstall-kvm-domain-$(1)' ; \
		echo '' ; \
		echo 'Or skip creating the domain with:' ; \
		echo '' ; \
		echo '    touch $(2)' ; \
		echo '' ; \
		exit 1; \
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

$(KVM_BASEDIR)/%.ks $(KVM_BASEDIR)/%.img: $(KVM_CONFIG) | $(KVM_ISO) $(KVM_KICKSTART_FILE) $(KVM_BASE_NETWORK_FILE)
	$(call check-no-kvm-domain,$*,$(KVM_BASEDIR)/$*.ks)
	rm -f '$(KVM_BASEDIR)/$*.img'
	fallocate -l 8G '$(KVM_BASEDIR)/$*.img'
	sed -e 's/^kvm_debuginfo=.*/kvm_debuginfo=$(KVM_DEBUGINFO)/' \
		< $(KVM_KICKSTART_FILE) > $(KVM_BASEDIR)/$*.tmp.ks
	sudo virt-install \
		--connect=qemu:///system \
		--network=network:$(KVM_BASE_NETWORK),model=virtio \
		--initrd-inject=$(KVM_BASEDIR)/$*.tmp.ks \
		--extra-args="swanname=$(KVM_BASE_DOMAIN) ks=file:/$*.tmp.ks console=tty0 console=ttyS0,115200" \
		--name=$(KVM_BASE_DOMAIN) \
		--disk path='$(KVM_BASEDIR)/$*.img' \
		--ram 1024 \
		--vcpus=1 \
		--check-cpu \
		--accelerate \
		--location=$(KVM_ISO) \
		--nographics \
		--noreboot \
		$(KVM_HVM)
	cp $(KVM_BASEDIR)/$*.tmp.ks $(KVM_BASEDIR)/$*.ks

# mostly for testing
.PHONY: install-kvm-base-domain uninstall-kvm-base-domain
install-kvm-base-domain: $(KVM_CONFIG) | $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks
uninstall-kvm-base-domain uninstall-kvm-domain-$(KVM_BASE_DOMAIN): $(KVM_CONFIG)
	$(call uninstall-kvm-domain,$(KVM_BASE_DOMAIN),$(KVM_BASEDIR)/$(KVM_BASE_DOMAIN))

# Create the base domain's .qcow2 disk image (ready for cloning) in
# $(KVM_BASEDIR).
#
# The base domain's .img file is an order-only dependency.  This
# prevents things like rebooting the domain triggering an unexpected
# update.
#
# The base domain's kickstart file is an order-only dependency.  This
# prevents things like switching branches triggering an unexpected
# update.
#
# XXX: There is a bug where the install sometimes leaves the disk
# image in a state where the clone result is corrupt.  Since one
# symptom seems to be a kernel barf involving qemu-img, look for that
# in dmesg.

$(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).qcow2:  $(KVM_CONFIG) | $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).ks $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).img
	: clone
	rm -f $@.tmp
	sudo qemu-img convert -O qcow2 '$(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).img' $@.tmp
	: try to track down an apparent corruption
	if dmesg | grep qemu-img ; then \
		: qemu-img caused a kernel panic, time to reboot ; \
		exit 1 ; \
	fi
	: finished
	mv $@.tmp $@

# Create the test domains in $(KVM_POOLDIR)
#
# Since running a domain will likely modify its .qcow2 disk image
# (changing MTIME), the domain's disk isn't a good indicator that a
# domain needs updating.  Instead use the .xml file to track the
# domain's creation time.

KVM_TEST_DOMAIN_FILES =

# The offical targets
.PHONY: install-kvm-domains uninstall-kvm-domains

# for consistency
.PHONY: install-kvm-test-domains uninstall-kvm-test-domains
install-kvm-domains: install-kvm-test-domains
uninstall-kvm-domains: uninstall-kvm-test-domains

define kvm-test-domain
  #(info pool=$(1) network=$(2))

  KVM_DOMAIN_$(1)$(2)_FILES = $$(KVM_POOLDIR)/$(1)$(2).xml
  KVM_TEST_DOMAIN_FILES += $$(KVM_DOMAIN_$(1)$(2)_FILES)

  .PHONY: install-kvm-domain-$(1)$(2)
  install-kvm-test-domains install-kvm-domain-$(1)$(2): $$(KVM_POOLDIR)/$(1)$(2).xml
  $$(KVM_POOLDIR)/$(1)$(2).xml: $(KVM_CONFIG) $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).qcow2 | $(KVM_TEST_NETWORK_FILES) testing/libvirt/vm/$(2)
	$(call check-no-kvm-domain,$(1)$(2),$$@)
	rm -f '$$(KVM_POOLDIR)/$(1)$(2).qcow2'
	qemu-img create -F qcow2 -f qcow2 -b '$$(KVM_BASEDIR)/$$(KVM_BASE_DOMAIN).qcow2' '$$(KVM_POOLDIR)/$(1)$(2).qcow2'
	sed \
		-e "s:@@NAME@@:$(1)$(2):" \
		-e "s:@@TESTINGDIR@@:$$(KVM_TESTINGDIR):" \
		-e "s:@@SOURCEDIR@@:$$(KVM_SOURCEDIR):" \
		-e "s:@@POOLSPACE@@:$$(KVM_POOLDIR):" \
		-e "s:@@USER@@:$$$$(id -u):" \
		-e "s:@@GROUP@@:$$$$(id -g qemu):" \
		-e "s:network='192_:network='$(1)192_:" \
		< 'testing/libvirt/vm/$(2)' \
		> '$$@.tmp'
	$(call install-kvm-domain,$(1)$(2),$$@)

  .PHONY: uninstall-kvm-domain-$(1)$(2)
  uninstall-kvm-test-domains: uninstall-kvm-domain-$(1)$(2)
  uninstall-kvm-domain-$(1)$(2): $(KVM_CONFIG)
	$(call uninstall-kvm-domain,$(1)$(2),$(KVM_POOLDIR)/$(1)$(2))
endef

ifdef KVM_POOL
$(foreach pool,$(KVM_POOL),$(foreach domain,$(KVM_TEST_DOMAINS),$(eval $(call kvm-test-domain,$(pool),$(domain)))))
else
$(foreach domain,$(KVM_TEST_DOMAINS),$(eval $(call kvm-test-domain,,$(domain))))
endif

uninstall-kvm-domains:
	@echo ''
	@echo 'NOTE:'
	@echo ''
	@echo '      Neither the base (master) domain nor its cloned disk have been deleted'
	@echo ''
	@echo 'To force a rebuild of the test domains using the real base domain disk type:'
	@echo ''
	@echo '     rm -f $(KVM_BASEDIR)/$(KVM_BASE_DOMAIN).qcow2'
	@echo '     make install-kvm-domains'
	@echo ''
	@echo 'To force a complete rebuild of all domains including base type:'
	@echo ''
	@echo '     make uninstall-kvm-domains uninstall-kvm-base-domain'
	@echo '     make install-kvm-domains'
	@echo ''
	@echo 'Rationale: since the creation of the base domain and its cloned disk is'
	@echo 'both unreliable and slow, and typically not needed, an explict rule is provided'
	@echo ''


#
# Build targets
#

# Select the build domain; the choice is arbitrary; most likely it is "east".
KVM_BUILD_DOMAIN = $(firstword $(KVM_POOL))$(firstword $(KVM_INSTALL_DOMAINS))

# Map the documented targets, and their aliases, onto
# internal/canonical targets.

.PHONY: kvm-clean clean-kvm
kvm-clean clean-kvm:
	: 'make kvm-DOMAIN-make-clean' to invoke clean on a DOMAIN
	rm -rf $(KVM_OBJDIR)
.PHONY: kvm-distclean distclean-kvm
kvm-distclean distclean-kvm: kvm-$(KVM_BUILD_DOMAIN)-make-distclean

# kvm-build is special.  To avoid "make base" and "make module"
# running in parallel on the build machine (stepping on each others
# toes), this uses sub-makes to explicitly serialize "base" and
# "modules" targets.
.PHONY: kvm-build build-kvm
kvm-build build-kvm:
	$(MAKE) kvm-$(KVM_BUILD_DOMAIN)-make-base
	$(MAKE) kvm-$(KVM_BUILD_DOMAIN)-make-module

# A catch all to run "make %" on the build domain; for instance "make
# kvm-make-manpages'.
kvm-make-%: kvm-$(KVM_BUILD_DOMAIN)-make-% ; @:

# "kvm-install" is a little wierd.  It needs to be run on most VMs,
# and it needs to use the swan-install script.
#
# To ensure that all test domains are created, include an explict
# dependency on all the test domain files.  "nic" which doesn't get
# pluto installed, would otherwise not be created.
#
# For a parallel kvm-install, avoid multiple domains simultaneously
# re-building libreswan by first explicitly running a build on
# $(KVM_BUILD_DOMAIN).
.PHONY: kvm-install kvm-shutdown
kvm-install: kvm-build | $(KVM_TEST_DOMAIN_FILES)

define build_rules
  #(info pool=$(1) domain=$(2))

  # Run "make <anything>" on the specified domain
  kvm-$(1)$(2)-make-%: | $$(KVM_DOMAIN_$(1)$(2)_FILES)
	$(call kvmsh,$(1)$(2) 'export OBJDIR=$$(KVM_OBJDIR) ; make -j2 OBJDIR=$$(KVM_OBJDIR) "$$(strip $$*)"')

  # "kvm-install" is a little wierd.  It needs to be run on most VMs,
  # and it needs to use the swan-install script.
  kvm-install: kvm-$(1)$(2)-install
  .PHONY: kvm-$(1)$(2)-install
  kvm-$(1)$(2)-install: kvm-build | $$(KVM_DOMAIN_$(1)$(2)_FILES)
	$(call kvmsh,$(1)$(2) 'export OBJDIR=$(KVM_OBJDIR) ; ./testing/guestbin/swan-install OBJDIR=$(KVM_OBJDIR)')

  kvm-shutdown: kvm-$(1)$(2)-shutdown
  .PHONY: kvm-$(1)$(2)-shutdown
  kvm-$(1)$(2)-shutdown: | $$(KVM_DOMAIN_$(1)$(2)_FILES)
	$(call kvmsh,--shutdown $(1)$(2))

  .PHONY: kvmsh-$(1)$(2)
  kvmsh-$(1)$(2): | $$(KVM_DOMAIN_$(1)$(2)_FILES)
	$(call kvmsh,$(1)$(2))
  kvmsh-$(1)$(2)-%: | $$(KVM_DOMAIN_$(1)$(2)_FILES)
	$(call kvmsh,$(1)$(2) $*)

endef

# Catch all to map 'kvmsh-east pwd' onto a kvmsh command.  Should
# kvmsh-east map onto kvmsh-pooleast?  Probably not.
kvmsh-%:
	$(call kvmsh,$*)

ifdef KVM_POOL
$(foreach pool,$(KVM_POOL),$(foreach domain,$(KVM_INSTALL_DOMAINS),$(eval $(call build_rules,$(pool),$(domain)))))
else
$(foreach domain,$(KVM_INSTALL_DOMAINS),$(eval $(call build_rules,,$(domain))))
endif


.PHONY: kvm-help
kvm-help:
	@echo ''
	@echo 'For more help see mk/README.md but here are some hints'
	@echo ''
	@echo '  To create the test domains:'
	@echo '    make install-kvm-networks install-kvm-domains'
	@echo '  where:'
	@echo '    install-kvm-networks       - installs the test networks'
	@echo '    install-kvm-domains        - installs the test domains'
	@echo ''
	@echo '  To run tests, either:'
	@echo '    make check UPDATE=1'
	@echo '  Or (you can cherry-pick steps):'
	@echo '    make kvm-clean kvm-install kvm-test-clean kvm-test kvm-check'
	@echo '  Where:'
	@echo '    kvm-clean                  - delete $(KVM_OBJDIR)'
	@echo '    kvm-install                - update/install libreswan into the test domains'
	@echo '    kvm-test-clean             - delete any previous test results'
	@echo '    kvm-test                   - run all "good" tests'
	@echo '                                 add KVM_TESTS=testing/pluto/... for individual tests'
	@echo '    kvm-check                  - re-run any tests that failed during kvm-test'
	@echo ''
	@echo '  To rebuild the test domains:'
	@echo '    make uninstall-kvm-domains install-kvm-domains'
	@echo '  Where:'
	@echo '    uninstall-kvm-domains      - delete the test domains (base remains)'
	@echo '    install-kvm-domains        - update/install the test domains'
	@echo ''
	@echo '  To login to a domain:'
	@echo '    make kvmsh-DOMAIN          - for instance kvmsh-east'
	@echo '  And to run something on a domain:'
	@echo '    make kvmsh-"DOMAIN CMD"    - for instance kvmsh-"east pwd"'
	@echo ''
	@echo '  Also:'
	@echo '    kvm-check-clean            - alias for kvm-test-clean'
	@echo '    kvm-keys                   - use the KVM to create the test keys'
	@echo '    uninstall-kvm-base-domain  - delete the base domain used to create the test domains'
	@echo '    uninstall-kvm-networks     - delete the test networks'
	@echo ''
