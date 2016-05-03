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


# XXX: For compatibility
abs_top_srcdir ?= $(abspath ${LIBRESWANSRCDIR})

# KVM_SOURCEDIR ?= $(abspath $(abs_top_srcdir)/..)
# KVM_TESTINGDIR ?= $(abs_top_srcdir)/testing
# KVM_POOLDIR ?= /home/build/pool
KVM_TEST_DOMAIN_POOLDIR ?= $(KVM_POOLDIR)

KVM_OS ?= fedora

KVM_BASE_DOMAIN = swan$(KVM_OS)base
KVM_TEST_DOMAINS = $(notdir $(wildcard testing/libvirt/vm/*[a-z]))
KVM_BUILD_DOMAIN = east
KVM_INSTALL_DOMAINS = $(filter-out nic, $(KVM_TEST_DOMAINS))
KVM_DOMAINS = $(KVM_TEST_DOMAINS) $(KVM_BASE_DOMAIN)
KVM_QEMUDIR = /var/lib/libvirt/qemu

KVMSH_COMMAND ?= $(abs_top_srcdir)/testing/utils/kvmsh.py
KVMSH ?= $(KVMSH_COMMAND)
KVMRUNNER_COMMAND ?= $(abs_top_srcdir)/testing/utils/kvmrunner.py
KVMRUNNER ?= $(KVMRUNNER_COMMAND)

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

ifeq ($(and $(KVM_SOURCEDIR),$(KVM_TESTINGDIR)),)
KVM_CONFIG += kvm-config-broken-mounts
endif
.PHONY: kvm-config-broken-mounts
kvm-config-broken-mounts:
	@echo ''
	@echo 'Invalid kvm mount points'
	@echo ''
	@echo 'Before creating the test domains, the following make variables'
	@echo 'need to be defined (these make variables are only used when'
	@echo 'creating the domains and specify extra domain mount points):'
	@echo ''
	@echo '    KVM_SOURCEDIR:  directory to mount on /source'
	@echo '    KVM_TESTINGDIR: directory to mount on /testing'
	@echo ''
	@echo 'For a traditional test domain configuration, with a single'
	@echo 'libreswan source directory mounted under /source, add the'
	@echo 'following to Makefile.inc.local:'
	@echo ''
	@echo '    KVM_SOURCEDIR = $$(abs_top_srcdir)'
	@echo '    KVM_TESTINGDIR = $$(abs_top_srcdir)/testing'
	@echo ''
	@echo 'Alternatively, if you have multiple libreswan source'
	@echo 'directories and would like their common parent directory to'
	@echo 'be mounted under /source then add the following to'
	@echo 'Makefile.inc.local:'
	@echo ''
	@echo '    KVM_SOURCEDIR = $$(abspath $$(abs_top_srcdir)/..)'
	@echo '    KVM_TESTINGDIR = $$(abs_top_srcdir)/testing'
	@echo ''
	@exit 1

ifeq ($(and $(KVM_POOLDIR),$(wildcard $(KVM_POOLDIR))),)
KVM_CONFIG += kvm-config-broken-pooldir
endif
.PHONY: kvm-config-broken-pooldir
kvm-config-broken-pooldir:
	@echo ''
	@echo 'Invalid kvm pool directory.'
	@echo ''
	@echo 'Check that the make variable:'
	@echo ''
	@echo '    KVM_POOLDIR - pool directory for both test and base domains'
	@echo ''
	@echo 'is defined in Makefile.inc.local, and that the directory
	@echo '($(KVM_POOLDIR)) exists.'
	@echo ''
	@echo 'For instance, to store all domain disks in /home/build/pool, add:'
	@echo ''
	@echo '    KVM_POOLDIR=/home/build/pool'
	@echo ''
	@echo 'to Makefile.inc.local.
	@exit 1

ifeq ($(and $(KVM_TEST_DOMAIN_POOLDIR),$(wildcard $(KVM_TEST_DOMAIN_POOLDIR))),)
KVM_CONFIG += kvm-config-broken-test-domain-pooldir
endif
.PHONY: kvm-config-broken-test-domain-pooldir
kvm-config-broken-test-domain-pooldir:
	@echo ''
	@echo 'Invalid kvm test domain pool directory.'
	@echo ''
	@echo 'Check that one of the following is defined in Makefile.inc.local:'
	@echo ''
	@echo '    KVM_POOLDIR - common pool directory for both test and base domains'
	@echo '    KVM_TEST_DOMAIN_POOLDIR - base domain pool directory (defaults to KVM_POOLDIR)'
	@echo ''
	@echo 'and that the corresponding directory ($(KVM_TEST_DOMAIN_POOLDIR)) exists.'
	@echo ''
	@echo 'For instance, to store all domain disks in /home/build/pool, add'
	@echo ''
	@echo '    KVM_POOLDIR=/home/build/pool'
	@echo ''
	@echo 'to Makefile.inc.local.  Alternatively, if you feel lucky, try specifying:'
	@echo ''
	@echo '    KVM_TEST_DOMAIN_POOLDIR=/tmp'
	@echo ''
	@exit 1


# Hack to map common typos on to real kvm-clean* targets
clean-kvm-%: kvm-clean-% ; @:
kvm-%-clean: kvm-clean-% ; @:
.PHONY: clean-kvm distclean-kvm
clean-kvm: kvm-clean
distclean-kvm: kvm-distclean

# Invoke KVMSH in curret directory with argument list $(1)
define kvmsh
	: KVM_OBJDIR: '$(KVM_OBJDIR)'
	test -w $(KVM_QEMUDIR) || $(MAKE) --no-print-directory kvm-config-broken-qemu
	$(KVMSH) \
		--output ++compile-log.txt \
		--chdir . \
		$(1)
endef

# Run "make $(1)" on $(2)"; yea, host argument should be first :-)
define kvm-make
	$(call kvmsh, $(2) \
		'export OBJDIR=$(KVM_OBJDIR) ; make -j2 OBJDIR=$(KVM_OBJDIR) "$(strip $(1))"')
endef

# Standard make targets; just mirror the local target names.
# Everything is run on $(KVM_BUILD_DOMAIN).
KVM_BUILD_TARGETS = kvm-all kvm-base kvm-clean-base kvm-manpages kvm-clean-manpages kvm-module kvm-clean kvm-distclean
.PHONY: $(KVM_BUILD_TARGETS)
$(KVM_BUILD_TARGETS):
	$(call kvm-make, $(patsubst kvm-%,%,$@), $(KVM_BUILD_DOMAIN))


# "install" is a little wierd.  It needs to be run on all VMs, and it
# needs to use the swan-install script.
.PHONY: kvm-install
kvm-install: $(patsubst %,kvm-install-%,$(KVM_INSTALL_DOMAINS))
kvm-install-%: kvm-build
	$(call kvmsh, $* \
		'export OBJDIR=$(KVM_OBJDIR) ; ./testing/guestbin/swan-install OBJDIR=$(KVM_OBJDIR)')

# To avoid parallel "make base" and "make module" builds stepping on
# each others toes, this uses sub-makes to explicitly serialize "base"
# and "modules" targets.
.PHONY: kvm-build
kvm-build:
	$(MAKE) --no-print-directory kvm-base
	$(MAKE) --no-print-directory kvm-module


# Some useful kvm wide commands.
.PHONY: kvm-shutdown
kvm-shutdown: $(patsubst %,kvm-shutdown-%,$(KVM_DOMAINS))
kvm-shutdown-%:
	$(call kvmsh, --shutdown $*)


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

# clean up
.PHONY: kvm-clean-check kvm-clean-test
kvm-clean-check kvm-clean-test:
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
	$(call kvmsh, $(KVM_BUILD_DOMAIN) \
		'make list-base | grep '^/' | grep -v '^/etc' | xargs md5sum')
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

# Build the base domain's disk image in $(KVM_POOLDIR).
#
# Use a pattern rule so that GNU make knows that two things are built.
#
# This rule uses order-only dependencies so that unintended re-builds,
# triggered says by switching git branches say, do not occure.
#
# This rule uses the .ks file as main target.  Should the target fail
# the .img file may be in an incomplete state.

# XXX: Could run the kickstart file through SED before using it.

$(KVM_POOLDIR)/%.ks $(KVM_POOLDIR)/%.img: $(KVM_CONFIG) | $(KVM_ISO) testing/libvirt/$(KVM_OS)base.ks
	@$(MAKE) uninstall-kvm-domain-$(KVM_BASE_DOMAIN)
	rm -f '$(KVM_POOLDIR)/$*.img'
	fallocate -l 8G '$(KVM_POOLDIR)/$*.img'
	sudo virt-install \
		--connect=qemu:///system \
		--network=network:default,model=virtio \
		--initrd-inject=testing/libvirt/$(KVM_OS)base.ks \
		--extra-args="swanname=$(KVM_BASE_DOMAIN) ks=file:/$(KVM_OS)base.ks console=tty0 console=ttyS0,115200" \
		--name=$(KVM_BASE_DOMAIN) \
		--disk path='$(KVM_POOLDIR)/$*.img' \
		--ram 1024 \
		--vcpus=1 \
		--check-cpu \
		--accelerate \
		--location=$(KVM_ISO) \
		--nographics \
		--noreboot \
		$(KVM_HVM)
	cp testing/libvirt/$(KVM_OS)base.ks $(KVM_POOLDIR)/$*.ks

# mostly for testing
.PHONY: install-kvm-base-domain uninstall-kvm-base-domain
install-kvm-base-domain: $(KVM_CONFIG) | $(KVM_POOLDIR)/$(KVM_BASE_DOMAIN).ks
uninstall-kvm-base-domain:  $(KVM_CONFIG) undefine-kvm-domain-$(KVM_BASE_DOMAIN)
	rm -f $(KVM_POOLDIR)/$*.xml
	rm -f $(KVM_POOLDIR)/$*.ks
	rm -f $(KVM_POOLDIR)/$*.qcow2
	rm -f $(KVM_POOLDIR)/$*.img

# Create the base domain's .qcow2 disk image (ready for cloning) in
# $(KVM_POOLDIR).
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

$(KVM_POOLDIR)/$(KVM_BASE_DOMAIN).qcow2:  $(KVM_CONFIG) | $(KVM_POOLDIR)/$(KVM_BASE_DOMAIN).ks $(KVM_POOLDIR)/$(KVM_BASE_DOMAIN).img
	: clone
	rm -f $@.tmp
	sudo qemu-img convert -O qcow2 '$(KVM_POOLDIR)/$(KVM_BASE_DOMAIN).img' $@.tmp
	: try to track down an apparent corruption
	if dmesg | grep qemu-img ; then \
		: qemu-img caused a kernel panic, time to reboot ; \
		exit 1 ; \
	fi
	: finished
	mv $@.tmp $@

# Create the test domains in $(KVM_TEST_DOMAIN_POOLDIR)
#
# Use a pattern rule so that GNU make knows that both the .xml and the
# .qcow2 files are created.
#
# Since running a domain will likely modify its .qcow2 disk image
# (changing MTIME), the domain's disk isn't a good indicator that a
# domain needs updating.  Instead use the .xml file to track the
# domain's creation time.

kvm-test-domain-files = \
	$(KVM_TEST_DOMAIN_POOLDIR)/$(1).qcow2 \
	$(KVM_TEST_DOMAIN_POOLDIR)/$(1).xml
# multiple domains, multiple config files, terrible english
KVM_TEST_DOMAINS_FILES = \
	$(foreach domain, $(KVM_TEST_DOMAINS), \
		$(call kvm-test-domain-files,$(domain)))

.PHONY: install-kvm-domains install-kvm-test-domains

install-kvm-domains: install-kvm-test-domains install-kvm-base-domain
install-kvm-test-domains: $(patsubst %,install-kvm-domain-%,$(KVM_TEST_DOMAINS))
install-kvm-domain-%:  $(KVM_CONFIG) $(call kvm-test-domain-files,%) ; @:
.PRECIOUS: $(KVM_TEST_DOMAINS_FILES)
$(call kvm-test-domain-files,%): $(KVM_CONFIG) $(KVM_POOLDIR)/$(KVM_BASE_DOMAIN).qcow2 | testing/libvirt/vm/%
	@$(MAKE) --no-print-directory uninstall-kvm-domain-$*
	rm -f '$(KVM_TEST_DOMAIN_POOLDIR)/$*.qcow2'
	qemu-img create -F qcow2 -f qcow2 -b '$(KVM_POOLDIR)/$(KVM_BASE_DOMAIN).qcow2' '$(KVM_TEST_DOMAIN_POOLDIR)/$*.qcow2'
	sed \
		-e "s:@@TESTINGDIR@@:$(KVM_TESTINGDIR):" \
		-e "s:@@SOURCEDIR@@:$(KVM_SOURCEDIR):" \
		-e "s:@@POOLSPACE@@:$(KVM_TEST_DOMAIN_POOLDIR):" \
		-e "s:@@USER@@:$$(id -u):" \
		-e "s:@@GROUP@@:$$(id -g qemu):" \
		'testing/libvirt/vm/$*' \
		> '$(KVM_TEST_DOMAIN_POOLDIR)/$*.tmp'
	sudo virsh define '$(KVM_TEST_DOMAIN_POOLDIR)/$*.tmp'
	mv '$(KVM_TEST_DOMAIN_POOLDIR)/$*.tmp' '$(KVM_TEST_DOMAIN_POOLDIR)/$*.xml'

.PHONY: uninstall-kvm-domains uninstall-kvm-test-domains
uninstall-kvm-domains: uninstall-kvm-test-domains uninstall-kvm-base-domain
uninstall-kvm-test-domains: $(patsubst %,uninstall-kvm-domain-%,$(KVM_TEST_DOMAINS))
	: To rebuild the test domains from the current base domain disk type:
	:
	:     rm -f $(KVM_POOLDIR)/$(KVM_BASE_DOMAIN).qcow2
	:
	: This is not done by default as the operation is unreliable and slow.
uninstall-kvm-domain-%: $(KVM_CONFIG) undefine-kvm-domain-%
	rm -f $(KVM_TEST_DOMAIN_POOLDIR)/$*.xml
	rm -f $(KVM_TEST_DOMAIN_POOLDIR)/$*.ks
	rm -f $(KVM_TEST_DOMAIN_POOLDIR)/$*.qcow2
undefine-kvm-domain-%: destroy-kvm-domain-%
	if sudo virsh domstate '$*' > /dev/null 2>&1 ; then \
		sudo virsh undefine '$*' --remove-all-storage ; \
	fi
destroy-kvm-domain-%:
	if sudo virsh domstate '$*' 2>/dev/null | grep running > /dev/null ; then \
		sudo virsh destroy '$*' ; \
	fi


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
