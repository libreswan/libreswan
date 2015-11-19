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

KVMSH_COMMAND ?= $(abs_top_srcdir)/testing/utils/kvmsh.py
KVMTEST_COMMAND ?= $(abs_top_srcdir)/testing/utils/kvmtest.py
KVMRUNNER_COMMAND ?= $(abs_top_srcdir)/testing/utils/kvmrunner.py

KVM_OBJDIR = OBJ.kvm
KVM_HOSTS = east west road north

# file to mark keys are up-to-date
KVM_KEYS = testing/x509/keys/up-to-date

# Uses "$@" to determine the current make target's indented host.
# Assumes the target looks like xxx-yyy-HOST, defaults to 'east' (the
# choice is arbitrary).
KVM_HOST = $(firstword $(filter $(KVM_HOSTS),$(lastword $(subst -, ,$@))) east)

# Run "make $(1)" on $(KVM_HOST); see $(KVM_HOST) above for how the
# host is identified.
define kvm-make
	: KVM_HOST: '$(KVM_HOST)'
	: KVM_OBJDIR: '$(KVM_OBJDIR)'
	$(KVMSH_COMMAND) \
		--output ++compile-log.txt \
		--chdir . \
		'$(KVM_HOST)' \
		'export OBJDIR=$(KVM_OBJDIR) ; make OBJDIR=$(KVM_OBJDIR) $(1)'
endef

# Standard targets; just mirror the local target names.

KVM_MAKE_TARGETS = kvm-all kvm-base kvm-module kvm-clean kvm-manpages kvm-clean-base kvm-clean-manpages kvm-distclean
.PHONY: $(KVM_MAKE_TARGETS)
$(KVM_MAKE_TARGETS):
	$(call kvm-make, $(patsubst kvm-%,%,$@))

# "install" is a little wierd.  It needs to be run on all VMs, and it
# needs to use the swan-install script.  Also, to avoid parallel
# builds getting in the way, this uses sub-makes to explicitly
# serialize things.
KVM_INSTALL_TARGETS = $(patsubst %,kvm-install-%,$(KVM_HOSTS))
PHONY: kvm-install $(KVM_INSTALL_TARGETS)
$(KVM_INSTALL_TARGETS):
	: KVM_HOST: '$(KVM_HOST)'
	: KVM_OBJDIR: '$(KVM_OBJDIR)'
	$(KVMSH_COMMAND) --chdir . '$(KVM_HOST)' 'export OBJDIR=$(KVM_OBJDIR) ; ./testing/guestbin/swan-install OBJDIR=$(KVM_OBJDIR)'
kvm-install:
	$(MAKE) --no-print-directory kvm-base
	$(MAKE) --no-print-directory kvm-module
	$(MAKE) --no-print-directory $(KVM_INSTALL_TARGETS)


# Some useful kvm wide commands.
KVM_SHUTDOWN_TARGETS = $(patsubst %,kvm-shutdown-%,$(KVM_HOSTS))
.PHONY: kvm-shutdown $(KVM_SHUTDOWN_TARGETS)
$(KVM_SHUTDOWN_TARGETS):
	: KVM_HOST: '$(KVM_HOST)'
	$(KVMSH_COMMAND) --shutdown '$(KVM_HOST)'
kvm-shutdown: $(KVM_SHUTDOWN_TARGETS)


# [re]run the testsuite.
#
# If the testsuite is being run a second time (for instance,
# re-started or re-run) what should happen: run all tests regardless;
# just run tests that have never been started; run tests that haven't
# yet passed?  Since each alternative has merit, let the user decide.

KVM_TESTS = testing/pluto

# "check" runs any test that has not yet passed (for instance, failed,
# incomplete and not started).  This is probably the safest option.
.PHONY: kvm-check kvm-check-good kvm-check-all
kvm-check: kvm-check-good
kvm-check-good: $(KVM_KEYS)
	: KVM_TESTS = $(KVM_TESTS)
	$(KVMRUNNER_COMMAND) --retry 1 --test-result "good"     $(KVM_TESTS)
kvm-check-all: $(KVM_KEYS)
	: KVM_TESTS = $(KVM_TESTS)
	$(KVMRUNNER_COMMAND) --retry 1 --test-result "good|wip" $(KVM_TESTS)

# "test" runs tests that have not been started.  This unfortunately
# means that an incomplete test isn't re-tried.
.PHONY: kvm-test-good kvm-test-all
kvm-test: kvm-test-good
kvm-test: $(KVM_KEYS)
	: KVM_TESTS = $(KVM_TESTS)
	$(KVMRUNNER_COMMAND) --retry 0 --test-result "good"     $(KVM_TESTS)
kvm-test-all: $(KVM_KEYS)
	: KVM_TESTS = $(KVM_TESTS)
	$(KVMRUNNER_COMMAND) --retry 0 --test-result "good|wip" $(KVM_TESTS)

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
