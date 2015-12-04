# KVM make targets, for Libreswan
#
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

# XXX: GNU Make doesn't let you combine pattern targets (e.x.,
# kvm-install-%: kvm-reboot-%) with .PHONY.  Consequently, so that
# patterns can be used, any targets with dependencies are not marked
# as .PHONY.  Sigh!

# XXX: For compatibility
abs_top_srcdir ?= $(abspath ${LIBRESWANSRCDIR})

KVM_OS = fedora
KVM_POOL = /home/build/pool
KVM_BASE_DOMAIN = swan$(KVM_OS)base
KVM_TEST_DOMAINS = $(notdir $(wildcard testing/libvirt/vm/*[a-z]))
KVM_BUILD_DOMAIN = east
KVM_MODULE_DOMAIN = west
KVM_INSTALL_DOMAINS = $(filter-out nic, $(KVM_TEST_DOMAINS))
KVM_DOMAINS = $(KVM_TEST_DOMAINS) $(KVM_BASE_DOMAIN)

KVMSH_COMMAND ?= $(abs_top_srcdir)/testing/utils/kvmsh.py
KVMTEST_COMMAND ?= $(abs_top_srcdir)/testing/utils/kvmtest.py
KVMRUNNER_COMMAND ?= $(abs_top_srcdir)/testing/utils/kvmrunner.py

KVM_OBJDIR = OBJ.kvm

# file to mark keys are up-to-date
KVM_KEYS = testing/x509/keys/up-to-date

# Uses "$@" to determine the current make target's indented host.
# Assumes the target looks like xxx-yyy-HOST, defaults to 'east' (the
# choice is arbitrary).
KVM_DOMAIN = $(firstword $(filter $(KVM_DOMAINS),$(lastword $(subst -, ,$@))) $(KVM_BUILD_DOMAIN))

# Run "make $(1)" on $(2).
define kvm-make
	: KVM_OBJDIR: '$(KVM_OBJDIR)'
	$(KVMSH_COMMAND) \
		--output ++compile-log.txt \
		--chdir . \
		'$(strip $(2))' \
		'export OBJDIR=$(KVM_OBJDIR) ; make OBJDIR=$(KVM_OBJDIR) "$(strip $(1))"'
endef

# Standard make targets; just mirror the local target names.  Most
# things get run on "east", but module gets run on west!

KVM_BUILD_TARGETS = kvm-all kvm-base kvm-clean kvm-manpages kvm-clean-base kvm-clean-manpages kvm-distclean
.PHONY: $(KVM_BUILD_TARGETS)
$(KVM_BUILD_TARGETS):
	$(call kvm-make, $(patsubst kvm-%,%,$@), $(KVM_BUILD_DOMAIN))
.PHONY: kvm-module
kvm-module:
	$(call kvm-make, module, $(KVM_MODULE_DOMAIN))


# "install" is a little wierd.  It needs to be run on all VMs, and it
# needs to use the swan-install script.  Also, to avoid parallel
# builds getting in the way, this uses sub-makes to explicitly
# serialize things.
KVM_INSTALL_TARGETS = $(patsubst %,kvm-install-%,$(KVM_INSTALL_DOMAINS))
PHONY: kvm-install $(KVM_INSTALL_TARGETS)
$(KVM_INSTALL_TARGETS):
	: KVM_DOMAIN: '$(KVM_DOMAIN)'
	: KVM_OBJDIR: '$(KVM_OBJDIR)'
	$(KVMSH_COMMAND) --chdir . '$(KVM_DOMAIN)' 'export OBJDIR=$(KVM_OBJDIR) ; ./testing/guestbin/swan-install OBJDIR=$(KVM_OBJDIR)'
kvm-install: kvm-base kvm-module
	$(MAKE) --no-print-directory $(KVM_INSTALL_TARGETS)


# Some useful kvm wide commands.
KVM_SHUTDOWN_TARGETS = $(patsubst %,kvm-shutdown-%,$(KVM_DOMAINS))
.PHONY: kvm-shutdown $(KVM_SHUTDOWN_TARGETS)
$(KVM_SHUTDOWN_TARGETS):
	: KVM_DOMAIN: '$(KVM_DOMAIN)'
	$(KVMSH_COMMAND) --shutdown '$(KVM_DOMAIN)'
kvm-shutdown: $(KVM_SHUTDOWN_TARGETS)


# [re]run the testsuite.
#
# If the testsuite is being run a second time (for instance,
# re-started or re-run) what should happen: run all tests regardless;
# just run tests that have never been started; run tests that haven't
# yet passed?  Since each alternative has merit, let the user decide.

KVM_TESTS = testing/pluto

# "check" runs any test that has not yet passed (that is: failed,
# incomplete, and not started).  This is probably the safest option.
.PHONY: kvm-check kvm-check-good kvm-check-all
kvm-check: kvm-check-good
kvm-check-good: $(KVM_KEYS)
	: KVM_TESTS = $(KVM_TESTS)
	$(KVMRUNNER_COMMAND) --retry 1 --test-result "good"     $(KVM_TESTS)
kvm-check-all: $(KVM_KEYS)
	: KVM_TESTS = $(KVM_TESTS)
	$(KVMRUNNER_COMMAND) --retry 1 --test-result "good|wip" $(KVM_TESTS)

# "test" runs tests regardless.  It is best used with the KVM_TESTS
# varible.
.PHONY: kvm-test-good kvm-test-all
kvm-test: kvm-test-good
kvm-test: $(KVM_KEYS)
	: KVM_TESTS = $(KVM_TESTS)
	$(KVMRUNNER_COMMAND) --retry -1 --test-result "good"     $(KVM_TESTS)
kvm-test-all: $(KVM_KEYS)
	: KVM_TESTS = $(KVM_TESTS)
	$(KVMRUNNER_COMMAND) --retry -1 --test-result "good|wip" $(KVM_TESTS)

# clean up
.PHONY: kvm-clean-check clean-kvm-check kvm-clean-test clean-kvm-test
kvm-clean-check clean-kvm-check kvm-clean-test clean-kvm-test:
	rm -rf $(KVM_TESTS)/*/OUTPUT*


# Hide a make call
SHOWVERSION = $(MAKE) showversion

# Detect either a new or updated install or test.
#
# The file kvm-checksum.new is left as a marker for $(NEWRUN).
#
# The checksums for both the installed tree (on east) and the source
# tree are recorded.  Presumably if either changes then it is a new
# run.  The /etc directory is excluded as the tests play havoc with
# its contents.
.PHONY: kvm-checksum
kvm-checksum:
	$(SHOWVERSION) | tee kvm-checksum.new
	$(KVMSH_COMMAND) --output ++kvm-checksum.new --chdir . east \
		'make list-base | grep '^/' | grep -v '^/etc' | xargs md5sum'
	if test -r kvm-checksum && cmp kvm-checksum.new kvm-checksum ; then \
		echo "Checksum file unchanged" ; \
		rm kvm-checksum.new ; \
	else \
		echo "Checksum file CHANGED" ; \
		cp kvm-checksum.new kvm-checksum ; \
	fi

# Build the keys/certificates using the KVM.
KVM_KEYS_SCRIPT = ./testing/x509/kvm-keys.sh
KVM_KEYS_EXPIRATION_DAY = 14
KVM_KEYS_EXPIRED = find testing/x509/*/ -mtime +$(KVM_KEYS_EXPIRATION_DAY)
.PHONY: kvm-keys clean-kvm-keys kvm-clean-keys

kvm-keys: $(KVM_KEYS)
	$(MAKE) --no-print-directory kvm-keys-up-to-date

# For moment don't force keys to be re-built.
.PHONY: kvm-keys-up-to-date
kvm-keys-up-to-date:
	@if test $$($(KVM_KEYS_EXPIRED) | wc -l) -gt 0 ; then \
		echo "The following keys are more than $(KVM_KEYS_EXPIRATION_DAY) days old:" ; \
		$(KVM_KEYS_EXPIRED) | sed -e 's/^/  /' ; \
		echo "run 'make kvm-clean-keys kvm-keys' to force an update" ; \
		exit 1 ; \
	fi

$(KVM_KEYS): testing/x509/dist_certs.py $(KVM_KEYS_SCRIPT)
	: always remove old keys - create xxx/ so */ always works
	mkdir -p testing/x509/xxx/ && rm -r testing/x509/*/
	$(KVM_KEYS_SCRIPT) east testing/x509
	touch $(KVM_KEYS)

kvm-clean-keys clean-kvm-keys:
	rm -rf testing/x509/*/

#
# Build KVM domains from scratch
#

# Where to get the install image.
KVM_ISO_URL_fedora = http://fedora.bhs.mirrors.ovh.net/linux/releases/21/Server/x86_64/iso/Fedora-Server-DVD-x86_64-21.iso
KVM_ISO_URL = $(value KVM_ISO_URL_$(KVM_OS))
KVM_ISO = $(notdir $(KVM_ISO_URL))
$(KVM_ISO):
	wget $(KVM_ISO_URL)

# XXX: Needed?
KVM_HVM = $(shell grep vmx /proc/cpuinfo > /dev/null && echo --hvm)

# Build the base disk image.  Don't use the .img as the marker as
# re-booting the domain touches it making a potentially circular
# dependency.
KVM_BASE_DOMAIN_IMAGE = $(KVM_POOL)/$(KVM_BASE_DOMAIN).img
$(KVM_POOL)/$(KVM_BASE_DOMAIN).xml: $(KVM_ISO) testing/libvirt/$(KVM_OS)base.ks
	-@$(MAKE) --no-print-directory kvm-destroy-$(KVM_BASE_DOMAIN)
	-@$(MAKE) --no-print-directory kvm-undefine-$(KVM_BASE_DOMAIN)
	rm -f $(KVM_BASE_DOMAIN_IMAGE)
	fallocate -l 8G '$(KVM_BASE_DOMAIN_IMAGE)'
	sudo virt-install \
		--connect=qemu:///system \
		--network=network:swandefault,model=virtio \
		--initrd-inject=testing/libvirt/$(KVM_OS)base.ks \
		--extra-args="swanname=$(KVM_BASE_DOMAIN) ks=file:/$(KVM_OS)base.ks console=tty0 console=ttyS0,115200" \
		--name=$(KVM_BASE_DOMAIN) \
		--disk path='$(KVM_BASE_DOMAIN_IMAGE)' \
		--ram 1024 \
		--vcpus=1 \
		--check-cpu \
		--accelerate \
		--location=$(KVM_ISO) \
		--nographics \
		--noreboot \
		$(KVM_HVM)
	touch $@
# XXX: fsck the disk and shutdown base before cloning it?
#
# XXX: If someone boots $(KVM_BASE_DOMAIN) then the .img file will be
# modified causing everything to rebuild.
KVM_BASE_DOMAIN_DISK = $(KVM_POOL)/$(KVM_BASE_DOMAIN).qcow2
$(KVM_BASE_DOMAIN_DISK): $(KVM_POOL)/$(KVM_BASE_DOMAIN).xml
	: $(KVMSH_COMMAND) --hostname swanbase --shutdown $(KVM_BASE_DOMAIN) 'touch /forcefsck'
	: $(KVMSH_COMMAND) --hostname swanbase --shutdown $(KVM_BASE_DOMAIN) 'true'
	rm -f $(KVM_BASE_DOMAIN_DISK)
	sudo qemu-img convert -O qcow2 '$(KVM_BASE_DOMAIN_IMAGE)' '$(KVM_BASE_DOMAIN_DISK)'
# Mainly for debugging
.PHONY: kvm-base-domain
kvm-base-domain: $(KVM_BASE_DOMAIN_DISK)

# Since running a domain will likely modify its disk (changing MTIME),
# the domain's disk isn't a good indicator that a domain needs
# updating.  Instead use a scratch file to track the domain's creation
# time.
$(KVM_POOL)/%.xml: $(KVM_BASE_DOMAIN_DISK) testing/libvirt/vm/%
	-@$(MAKE) --no-print-directory kvm-destroy-$*
	-@$(MAKE) --no-print-directory kvm-undefine-$*
	rm -f '$(KVM_POOL)/$*.qcow2'
	sudo qemu-img create -F qcow2 -f qcow2 -b '$(KVM_BASE_DOMAIN_DISK)' '$(KVM_POOL)/$*.qcow2'
	sed \
		-e "s:@@TESTINGDIR@@:$(abs_top_srcdir)/testing:" \
		-e "s:@@SOURCEDIR@@:$(abspath $(abs_top_srcdir)/..):" \
		-e "s:@@POOLSPACE@@:$(KVM_POOL):" \
		-e "s:@@USER@@:$$(id -u):" \
		-e "s:@@GROUP@@:$$(id -g qemu):" \
		testing/libvirt/vm/$* \
		> '$@.tmp'
	sudo virsh define '$@.tmp'
	mv '$@.tmp' '$@'

# XXX: Should destroy and undefine be merged?
KVM_DESTROY_TARGETS = $(patsubst %,kvm-destroy-%,$(KVM_DOMAINS))
.PHONY: kvm-destroy-domains $(KVM_DESTROY_TARGETS)
$(KVM_DESTROY_TARGETS):
	: KVM_DOMAIN: '$(KVM_DOMAIN)'
	sudo virsh destroy $(KVM_DOMAIN)
kvm-destroy-domains: $(KVM_DESTROY_TARGETS)

KVM_UNDEFINE_TARGETS = $(patsubst %,kvm-undefine-%,$(KVM_DOMAINS))
.PHONY: kvm-undefine $(KVM_UNDEFINE_TARGETS)
# XXX: --remove-all-storage doesn't work when the disk was created
# outside of the domain.
$(KVM_UNDEFINE_TARGETS):
	: KVM_DOMAIN: '$(KVM_DOMAIN)'
	sudo virsh undefine $(KVM_DOMAIN) --remove-all-storage
kvm-undefine-domains: $(KVM_UNDEFINE_TARGETS)

.PHONY: 
kvm-clean-domains:
	$(MAKE) $(KVM_DESTROY_TARGETS)
	$(MAKE) $(KVM_UNDEFINE_TARGETS)

KVM_DOMAIN_TARGETS = $(patsubst %,kvm-domain-%,$(KVM_DOMAINS))
.PHONY: $(KVM_TEST_DOMAIN_TARGETS)
$(KVM_DOMAIN_TARGETS):
	@$(MAKE) --no-print-directory $(KVM_POOL)/$(KVM_DOMAIN).xml
.PHONY: kvm-domains
kvm-domains: $(patsubst %,$(KVM_POOL)/%.xml,$(KVM_DOMAINS))
