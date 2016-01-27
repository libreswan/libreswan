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

KVM_OS ?= fedora
KVM_POOL ?= /home/build/pool
KVM_SOURCEDIR ?= $(abspath $(abs_top_srcdir)/..)
KVM_TESTINGDIR ?= $(abs_top_srcdir)/testing

KVM_BASE_DOMAIN = swan$(KVM_OS)base
KVM_TEST_DOMAINS = $(notdir $(wildcard testing/libvirt/vm/*[a-z]))
KVM_BUILD_DOMAIN = east
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

# Hack to map common typos on to real kvm-clean* targets
clean-kvm-%: kvm-clean-% ; @:
kvm-%-clean: kvm-clean-% ; @:
.PHONY: clean-kvm distclean-kvm
clean-kvm: kvm-clean
distclean-kvm: kvm-distclean

# Run "make $(1)" on $(2).
define kvm-make
	: KVM_OBJDIR: '$(KVM_OBJDIR)'
	$(KVMSH_COMMAND) \
		--output ++compile-log.txt \
		--chdir . \
		'$(strip $(2))' \
		'export OBJDIR=$(KVM_OBJDIR) ; make OBJDIR=$(KVM_OBJDIR) "$(strip $(1))"'
endef

# Standard make targets; just mirror the local target names.
# Everything is run on $(KVM_BUILD_DOMAIN).
KVM_BUILD_TARGETS = kvm-all kvm-base kvm-clean-base kvm-manpages kvm-clean-manpages kvm-module kvm-clean kvm-distclean
.PHONY: $(KVM_BUILD_TARGETS)
$(KVM_BUILD_TARGETS):
	$(call kvm-make, $(patsubst kvm-%,%,$@), $(KVM_BUILD_DOMAIN))


# "install" is a little wierd.  It needs to be run on all VMs, and it
# needs to use the swan-install script.  Also, to avoid parallel
# builds getting in the way, this uses sub-makes to explicitly
# serialize building "base" and "modules".
KVM_INSTALL_TARGETS = $(patsubst %,kvm-install-%,$(KVM_INSTALL_DOMAINS))
.PHONY: kvm-install kvm-build $(KVM_INSTALL_TARGETS)
$(KVM_INSTALL_TARGETS): kvm-build
	: KVM_DOMAIN: '$(KVM_DOMAIN)'
	: KVM_OBJDIR: '$(KVM_OBJDIR)'
	$(KVMSH_COMMAND) --chdir . '$(KVM_DOMAIN)' 'export OBJDIR=$(KVM_OBJDIR) ; ./testing/guestbin/swan-install OBJDIR=$(KVM_OBJDIR)'
kvm-install: $(KVM_INSTALL_TARGETS)
kvm-build:
	$(MAKE) --no-print-directory kvm-base
	$(MAKE) --no-print-directory kvm-module


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
.PHONY: clean-kvm-check clean-kvm-test
clean-kvm-check clean-kvm-test:
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
.PHONY: kvm-keys clean-kvm-keys

kvm-keys: $(KVM_KEYS)
	$(MAKE) --no-print-directory kvm-keys-up-to-date

# For moment don't force keys to be re-built.
.PHONY: kvm-keys-up-to-date clean-kvm-keys
kvm-keys-up-to-date:
	@if test $$($(KVM_KEYS_EXPIRED) | wc -l) -gt 0 ; then \
		echo "The following keys are more than $(KVM_KEYS_EXPIRATION_DAY) days old:" ; \
		$(KVM_KEYS_EXPIRED) | sed -e 's/^/  /' ; \
		echo "run 'make clean-kvm-keys kvm-keys' to force an update" ; \
		exit 1 ; \
	fi

$(KVM_KEYS): testing/x509/dist_certs.py $(KVM_KEYS_SCRIPT)
	$(MAKE) clean-kvm-keys
	$(KVM_KEYS_SCRIPT) east testing/x509
	touch $(KVM_KEYS)

clean-kvm-keys:
	rm -rf testing/x509/*/ testing/x509/nss-pw


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

$(KVM_POOL):
	@echo ''
	@echo '    The directory $(KVM_POOL) does not exist'
	@echo '    Either create $(KVM_POOL) or set the KVM_POOL make variable in Makefile.inc.local'
	@echo ''
	@exit 1

# Build the base domain's disk image.
#
# Use a pattern rule so that GNU make knows that two things are built.
#
# This rule uses order-only dependencies so that unintended re-builds,
# triggered says by switching git branches say, do not occure.
#
# This rule uses the .ks file as main target.  Should the target fail
# the .img file may be in an incomplete state.

# XXX: Could run the kickstart file through SED before using it.

$(KVM_POOL)/%.ks $(KVM_POOL)/%.img: | $(KVM_ISO) testing/libvirt/$(KVM_OS)base.ks $(KVM_POOL)
	@$(MAKE) uninstall-kvm-domain-$(KVM_BASE_DOMAIN)
	rm -f '$(KVM_POOL)/$*.img'
	fallocate -l 8G '$(KVM_POOL)/$*.img'
	sudo virt-install \
		--connect=qemu:///system \
		--network=network:default,model=virtio \
		--initrd-inject=testing/libvirt/$(KVM_OS)base.ks \
		--extra-args="swanname=$(KVM_BASE_DOMAIN) ks=file:/$(KVM_OS)base.ks console=tty0 console=ttyS0,115200" \
		--name=$(KVM_BASE_DOMAIN) \
		--disk path='$(KVM_POOL)/$*.img' \
		--ram 1024 \
		--vcpus=1 \
		--check-cpu \
		--accelerate \
		--location=$(KVM_ISO) \
		--nographics \
		--noreboot \
		$(KVM_HVM)
	cp testing/libvirt/$(KVM_OS)base.ks $(KVM_POOL)/$*.ks

# mostly for testing
.PHONY: install-kvm-base-domain uninstall-kvm-base-domain
install-kvm-base-domain: $(KVM_POOL)/$(KVM_BASE_DOMAIN).ks
uninstall-kvm-base-domain: uninstall-kvm-domain-$(KVM_BASE_DOMAIN)

# Create the base domain's .qcow2 disk image (ready for cloning)
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

$(KVM_POOL)/$(KVM_BASE_DOMAIN).qcow2: | $(KVM_POOL)/$(KVM_BASE_DOMAIN).ks $(KVM_POOL)/$(KVM_BASE_DOMAIN).img
	: clone
	rm -f $@.tmp
	sudo qemu-img convert -O qcow2 '$(KVM_POOL)/$(KVM_BASE_DOMAIN).img' $@.tmp
	: try to track down an apparent corruption
	if dmesg | grep qemu-img ; then \
		: qemu-img caused a kernel panic, time to reboot ; \
		exit 1 ; \
	fi
	: finished
	mv $@.tmp $@

# Create the test domains
#
# Use a pattern rule so that GNU make knows that both the .xml and the
# .qcow2 files are created.
#
# Since running a domain will likely modify its .qcow2 disk image
# (changing MTIME), the domain's disk isn't a good indicator that a
# domain needs updating.  Instead use the .xml file to track the
# domain's creation time.

.PHONY: install-kvm-domains install-kvm-test-domains
install-kvm-domains: install-kvm-test-domains install-kvm-base-domain
install-kvm-test-domains: $(patsubst %,install-kvm-domain-%,$(KVM_TEST_DOMAINS))
install-kvm-domain-%: $(KVM_POOL)/%.xml | $(KVM_POOL)/%.qcow2 ; @:
.PRECIOUS: $(patsubst %,$(KVM_POOL)/%.qcow2,$(KVM_TEST_DOMAINS))
.PRECIOUS: $(patsubst %,$(KVM_POOL)/%.xml,$(KVM_TEST_DOMAINS))
$(KVM_POOL)/%.xml $(KVM_POOL)/%.qcow2: $(KVM_POOL)/$(KVM_BASE_DOMAIN).qcow2 testing/libvirt/vm/%
	@$(MAKE) --no-print-directory uninstall-kvm-domain-$*
	rm -f '$(KVM_POOL)/$*.qcow2'
	sudo qemu-img create -F qcow2 -f qcow2 -b '$(KVM_POOL)/$(KVM_BASE_DOMAIN).qcow2' '$(KVM_POOL)/$*.qcow2'
	sed \
		-e "s:@@TESTINGDIR@@:$(KVM_TESTINGDIR):" \
		-e "s:@@SOURCEDIR@@:$(KVM_SOURCEDIR):" \
		-e "s:@@POOLSPACE@@:$(KVM_POOL):" \
		-e "s:@@USER@@:$$(id -u):" \
		-e "s:@@GROUP@@:$$(id -g qemu):" \
		'testing/libvirt/vm/$*' \
		> '$(KVM_POOL)/$*.tmp'
	sudo virsh define '$(KVM_POOL)/$*.tmp'
	mv '$(KVM_POOL)/$*.tmp' '$(KVM_POOL)/$*.xml'

# some useful aliases
kvm-domains: install-kvm-domains ; @:
kvm-domain-%: install-kvm-domain-% ; @:

.PHONY: uninstall-kvm-domains uninstall-kvm-test-domains
uninstall-kvm-test-domains: $(patsubst %,uninstall-kvm-domain-%,$(KVM_TEST_DOMAINS))
	: Force the shared qcow file to be rebuilt
	rm -f $(KVM_POOL)/$(KVM_BASE_DOMAIN).qcow2
uninstall-kvm-domains: uninstall-kvm-test-domains uninstall-kvm-base-domain
uninstall-kvm-domain-%: | $(KVM_POOL)
	if sudo virsh domstate '$*' 2>/dev/null | grep running > /dev/null ; then \
		sudo virsh destroy '$*' ; \
	fi
	if sudo virsh domstate '$*' > /dev/null 2>&1 ; then \
		sudo virsh undefine '$*' --remove-all-storage ; \
	fi
	rm -f $(KVM_POOL)/$*.xml   $(KVM_POOL)/$*.ks
	rm -f $(KVM_POOL)/$*.qcow2 $(KVM_POOL)/$*.img

# Some useful aliases
kvm-clean-domains: uninstall-kvm-domains ; @:
kvm-clean-domain-%: uninstall-kvm-domain-% ; @:

#
# Build networks from scratch
#
# XXX: This deletes each network before creating it; should it?

KVM_NETDIR = testing/libvirt/net
.PHONY: install-kvm-networks
install-kvm-networks: $(patsubst $(KVM_NETDIR)/%,install-kvm-network-%,$(wildcard $(KVM_NETDIR)/*))
install-kvm-network-%: uninstall-kvm-network-%
	sudo virsh net-define $(KVM_NETDIR)/$*
	sudo virsh net-autostart $*
	sudo virsh net-start $*
.PHONY: uninstall-kvm-networks
uninstall-kvm-networks: $(patsubst $(KVM_NETDIR)/%,uninstall-kvm-network-%,$(wildcard $(KVM_NETDIR)/*))
uninstall-kvm-network-%:
	if sudo virsh net-info $* 2>/dev/null | grep 'Active:.*yes' > /dev/null ; then \
		sudo virsh net-destroy $* ; \
	fi
	if sudo virsh net-info $* >/dev/null 2>&1 ; then \
		sudo virsh net-undefine $* ; \
	fi
# Some useful aliases
kvm-networks: install-kvm-networks ; @:
kvm-network-%: install-kvm-network-% ; @:
kvm-clean-networks: uninstall-kvm-networks ; @:
kvm-clean-network-%: uninstall-kvm-network-% ; @:
