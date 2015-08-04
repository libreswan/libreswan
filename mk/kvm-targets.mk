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


# Run the testsuite.
#
# The problem is that it is never really clear, when re-running tests,
# what the intent of a user really is.  For instance, should running
# check twice be incremental, and if so, what exactly does incremental
# mean?
#
# For the moment provide the rules below, each with subtlely different
# behaviour and names.

# "check" only runs tests that have never been started (it skips
# failed and crashed tests).
.PHONY: kvm-check kvm-check-good kvm-check-all
kvm-check: kvm-check-good
kvm-check-good: testing/x509/keys/mainca.key
	$(KVMRUNNER_COMMAND) --retry 0 --test-result "good"     testing/pluto
kvm-check-all: testing/x509/keys/mainca.key
	$(KVMRUNNER_COMMAND) --retry 0 --test-result "good|wip" testing/pluto
# "recheck" re-runs any test that didn't pass.
.PHONY: kvm-recheck-good kvm-recheck-all
kvm-recheck: kvm-recheck-good
kvm-recheck: testing/x509/keys/mainca.key
	$(KVMRUNNER_COMMAND) --retry 1 --test-result "good"     testing/pluto
kvm-recheck-all: testing/x509/keys/mainca.key
	$(KVMRUNNER_COMMAND) --retry 1 --test-result "good|wip" testing/pluto
# clean up
.PHONY: kvm-clean-check
kvm-clean-check:
	rm -rf testing/pluto/*/OUTPUT*


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

# Re-build the keys/certificates.
#
# Strangely, dist_certs.py can't create a directory called "certs/" on
# a 9p mounted file system (OSError: [Errno 13] Permission denied:
# 'certs/').  Get around it by first creating the certs in /tmp and
# then copying them over.
#
# By copying "dist_certs.py" to /tmp the need to compute the remote
# path to the local dist_certs.py is avoided (do not assume it is
# under /testing).  Better might be for dist_certs.py to take an
# output directory argument.
kvm-keys testing/x509/keys/mainca.key: testing/x509/dist_certs.py
	$(KVMSH_COMMAND) --chdir .         east 'rm -f /etc/system-fips'
	$(KVMSH_COMMAND) --chdir .         east './testing/guestbin/fipsoff'
	$(KVMSH_COMMAND) --chdir .         east 'rm -rf /tmp/x509'
	$(KVMSH_COMMAND) --chdir .         east 'mkdir /tmp/x509'
	$(KVMSH_COMMAND) --chdir .         east 'cp -f testing/x509/dist_certs.py /tmp'
	$(KVMSH_COMMAND) --chdir /tmp/x509 east '../dist_certs.py'
	rm -f testing/x509/x509.tar
	$(KVMSH_COMMAND) --chdir .         east '( cd /tmp && tar cf - x509 ) > testing/x509.tar'
	cd testing && tar xpvf x509.tar
	rm testing/x509.tar
.PHONY: kvm-keys
