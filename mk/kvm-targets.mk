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

KVM_RUN ?= $(abs_top_srcdir)/testing/utils/runkvm.py
KVM_MOUNTS ?= $(abs_top_srcdir)/testing/utils/kvmmounts.sh

KVM_HOSTS = east west road north

# NOTE: Use this from make rules only.  Determines the KVM path to
# $(abs_top_srcdir).  If broken, override using Makefile.inc.local
KVM_HOST = $(lastword $(subst -, ,$@))
KVM_MOUNT ?= $(shell $(KVM_MOUNTS) $(KVM_HOST) swansource)
KVM_SUBMOUNT ?= $(subst $(KVM_MOUNT),,$(abs_top_srcdir))
KVM_SOURCEDIR ?= /source/$(patsubst /%,%,$(KVM_SUBMOUNT))

KVM_TEST_TARGETS = $(patsubst %,kvm-test-%,$(KVM_HOSTS))
.PHONY: $(KVM_TEST_TARGETS)
$(KVM_TEST_TARGETS):
	: host: $(KVM_HOST)
	: mount for $(KVM_HOST): $(KVM_MOUNT)
	: submount for $(KVM_HOST): $(KVM_SUBMOUNT)
	: sourcedir for $(KVM_HOST): $(KVM_SOURCEDIR)
	: hosts: $(KVM_HOSTS)
	: targets: $(KVM_TEST_TARGETS)

KVM_RUN_TARGETS = $(patsubst %,kvm-run-%,$(KVM_HOSTS))
.PHONY: $(KVM_RUN_TARGETS)
$(KVM_RUN_TARGETS):
	test '$(RUN)' != ""
	$(KVM_RUN) --sourcedir $(KVM_SOURCEDIR) --hostname $(KVM_HOST) --run '$(RUN)'

KVM_REBOOT_TARGETS = $(patsubst %,kvm-reboot-%,$(KVM_HOSTS))
.PHONY: $(KVM_REBOOT_TARGETS)
$(KVM_REBOOT_TARGETS):
	$(KVM_RUN) --sourcedir $(KVM_SOURCEDIR) --hostname $(KVM_HOST) --reboot

KVM_COMPILE_TARGETS = $(patsubst %,kvm-compile-%,$(KVM_HOSTS))
#.PHONY: $(KVM_COMPILE_TARGETS)
#$(KVM_COMPILE_TARGETS):
kvm-compile-%: kvm-reboot-%
	$(KVM_RUN) --sourcedir $(KVM_SOURCEDIR) --hostname $(KVM_HOST) --compile

KVM_INSTALL_TARGETS = $(patsubst %,kvm-install-%,$(KVM_HOSTS))
#.PHONY: $(KVM_INSTALL_TARGETS)
#$(KVM_INSTALL_TARGETS):
kvm-install-%: kvm-reboot-%
	$(KVM_RUN) --sourcedir $(KVM_SOURCEDIR) --hostname $(KVM_HOST) --install

.PHONY: kvm-update
kvm-update: kvm-compile-east | $(KVM_INSTALL_TARGETS)
