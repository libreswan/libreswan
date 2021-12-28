# KVM make targets, for Libreswan
#
# Copyright (C) 2015-2021 Andrew Cagney
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
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
# variable '$*' (why not $%!?!?!, because that was used for archives).
# It is used to extract the DOMAIN from targets like
# kvm-install-DOMAIN.

empty =
comma = ,
sp = $(empty) $(empty)
# the first blank line is ignored
define crlf


endef

#
# The guest operating system.
#
# Pull in all its defaults so that they override everything below.

include testing/libvirt/fedora/fedora.mk
include testing/libvirt/netbsd/netbsd.mk
include testing/libvirt/openbsd/openbsd67.mk

#
# where things live and what gets created
#

# can be a separate directories
KVM_SOURCEDIR ?= $(abs_top_srcdir)
KVM_TESTINGDIR ?= $(abs_top_srcdir)/testing

# An educated guess ...
KVM_POOLDIR ?= $(abspath $(abs_top_srcdir)/../pool)
KVM_LOCALDIR ?= $(KVM_POOLDIR)
# While KVM_PREFIX might be empty, KVM_PREFIXES is never empty.
KVM_PREFIX ?=
KVM_PREFIXES ?= $(if $(KVM_PREFIX), $(KVM_PREFIX), '')
KVM_WORKERS ?= 1
#KVM_WORKERS ?= $(shell awk 'BEGIN { c=1 } /cpu cores/ { c=$$4 } END { if (c>1) print c/2; }' /proc/cpuinfo)
KVM_GROUP ?= qemu
#KVM_PYTHON ?= PYTHONPATH=/home/python/pexpect:/home/python/ptyprocess /home/python/v3.8/bin/python3
KVM_PIDFILE ?= kvmrunner.pid
KVM_UID ?= $(shell id -u)
KVM_GID ?= $(shell id -g $(KVM_GROUP))

# The alternative is qemu:///session and it doesn't require root.
# However, it has never been used, and the python tools all assume
# qemu://system. Finally, it comes with a warning: QEMU usermode
# session is not the virt-manager default.  It is likely that any
# pre-existing QEMU/KVM guests will not be available.  Networking
# options are very limited.

KVM_CONNECTION ?= qemu:///system

VIRSH = sudo virsh --connect=$(KVM_CONNECTION)


#
# Makeflags passed to the KVM build
#

# Should these live in the OS.mk file?
KVM_USE_EFENCE ?= true
KVM_USE_NSS_IPSEC_PROFILE ?= true
KVM_USE_NSS_KDF ?= true
KVM_ALL_ALGS ?= false
KVM_USE_SECCOMP ?= true
KVM_USE_LABELED_IPSEC ?= true
KVM_SD_RESTART_TYPE ?= no
KVM_USE_FIPSCHECK ?= false
KVM_FINALNSSDIR ?= $(FINALCONFDIR)/ipsec.d
KVM_FEDORA_NSS_CFLAGS ?=
KVM_FEDORA_NSS_LDFLAGS ?=

KVM_MAKEFLAGS ?= -j$(shell expr $(KVM_WORKERS) + 1)
KVM_FEDORA_MAKEFLAGS = \
	USE_EFENCE=$(KVM_USE_EFENCE) \
	ALL_ALGS=$(KVM_ALL_ALGS) \
	USE_SECCOMP=$(KVM_USE_SECCOMP) \
	USE_LABELED_IPSEC=$(KVM_USE_LABELED_IPSEC) \
	USE_NSS_IPSEC_PROFILE=$(KVM_USE_NSS_IPSEC_PROFILE) \
	SD_RESTART_TYPE=$(KVM_SD_RESTART_TYPE) \
	USE_NSS_KDF=$(KVM_USE_NSS_KDF) \
	FINALNSSDIR=$(KVM_FINALNSSDIR) \
	USE_FIPSCHECK=$(KVM_USE_FIPSCHECK) \
	$(if $(KVM_FEDORA_NSS_CFLAGS),NSS_CFLAGS="$(KVM_FEDORA_NSS_CFLAGS)") \
	$(if $(KVM_FEDORA_NSS_LDFLAGS),NSS_LDFLAGS="$(KVM_FEDORA_NSS_LDFLAGS)") \
	$(NULL)

#
# Generate local names using prefixes
#

strip-prefix = $(subst '',,$(subst "",,$(1)))
# for-each-kvm-prefix = how?
add-kvm-prefixes = \
	$(foreach prefix, $(KVM_PREFIXES), \
		$(addprefix $(call strip-prefix,$(prefix)),$(1)))
KVM_FIRST_PREFIX = $(call strip-prefix,$(firstword $(KVM_PREFIXES)))

# targets for dumping the above
.PHONY: print-kvm-prefixes
print-kvm-prefixes: ; @echo "$(KVM_PREFIXES)"


# Fine-tune the BASE and BUILD machines.
#
# BASE is kept small.
#
# BUILD is more complex:
#
# CPUs: so as to not over allocate host cores, stick with
# $(KVM_WORKERS) (default 1). The heuristic is to set $(KVM_WORKERS)
# to #cores/2 - as it seems that a [booting] machine ties up two
# cores.
#
# Memory: a test typically requires two 512mb VMs. With $(KVM_WORKERS)
# that makes at least $(KVM_WORKERS)*2*512mb of ram being used by
# tests VMs.  Boost build's memory by that amount.
#
# XXX: Ignore KVM_PREFIXES, it is probably going away.

VIRT_INSTALL ?= sudo virt-install
VIRT_CPU ?= --cpu=host-passthrough
VIRT_DISK_SIZE_GB ?=8
VIRT_RND ?= --rng=type=random,device=/dev/random
VIRT_SECURITY ?= --security=type=static,model=dac,label='$(KVM_UID):$(KVM_GID)',relabel=yes
VIRT_GATEWAY ?= --network=network:$(KVM_GATEWAY),model=virtio
VIRT_POOLDIR ?= --filesystem=target=pool,type=mount,accessmode=squash,source=$(KVM_POOLDIR)
VIRT_SOURCEDIR ?= --filesystem=target=source,type=mount,accessmode=squash,source=$(KVM_SOURCEDIR)
VIRT_TESTINGDIR ?= --filesystem=target=testing,type=mount,accessmode=squash,source=$(KVM_TESTINGDIR)

VIRT_INSTALL_FLAGS = \
	--connect=$(KVM_CONNECTION) \
	--check=path_in_use=off \
	--graphics=none \
	--virt-type=kvm \
	--noreboot \
	--console=pty,target_type=serial \
	--vcpus=$(KVM_WORKERS) \
	--memory=$(shell expr 1024 + $(KVM_WORKERS) \* 2 \* 512) \
	$(VIRT_CPUS) \
	$(VIRT_CPU) \
	$(VIRT_GATEWAY) \
	$(VIRT_RND) \
	$(VIRT_SECURITY) \
	$(VIRT_POOLDIR)

#
# Hosts
#

KVM_DEBIAN_HOSTS =
KVM_FEDORA_HOSTS = east west north road nic
KVM_NETBSD_HOSTS =
KVM_OPENBSD_HOSTS = openbsde openbsdw

KVM_TEST_HOSTS = $(foreach platform, $(KVM_PLATFORMS), $(KVM_$($(platform))_HOSTS))
KVM_BUILD_HOSTS = $(foreach platform, $(KVM_PLATFORMS), $(foreach variant, base upgrade build, $(platform)-$(variant)))

KVM_HOSTS = $(KVM_TEST_HOSTS) $(KVM_BUILD_HOSTS)

#
# Domains
#

# so that $($*) conversts % to upper case
fedora = FEDORA
debian = DEBIAN
netbsd = NETBSD
openbsd = OPENBSD

#KVM_PLATFORMS += debian
KVM_PLATFORMS += fedora
KVM_PLATFORMS += netbsd
KVM_PLATFORMS += openbsd

KVM_POOLDIR_PREFIX = $(KVM_POOLDIR)/$(KVM_FIRST_PREFIX)
KVM_LOCALDIR_PREFIXES = \
	$(call strip-prefix, \
		$(foreach prefix, $(KVM_PREFIXES), \
			$(addprefix $(KVM_LOCALDIR)/, $(prefix))))
add-kvm-localdir-prefixes = \
	$(foreach prefix, $(KVM_LOCALDIR_PREFIXES), \
		$(patsubst %, $(prefix)%, $(1)))

# full path
KVM_DEBIAN_CLONES = $(call add-kvm-localdir-prefixes, $(KVM_DEBIAN_HOSTS))
KVM_FEDORA_CLONES = $(call add-kvm-localdir-prefixes, $(KVM_FEDORA_HOSTS))
KVM_OPENBSD_CLONES = $(call add-kvm-localdir-prefixes, $(KVM_OPENBSD_HOSTS))
KVM_NETBSD_CLONES = $(call add-kvm-localdir-prefixes, $(KVM_NETBSD_HOSTS))

KVM_TEST_DOMAINS = $(call add-kvm-prefixes, $(KVM_TEST_HOSTS))

KVM_LOCAL_DOMAINS = $(sort $(KVM_TEST_DOMAINS))

KVM_DOMAINS =  $(sort $(KVM_LOCAL_DOMAINS) $(XXX_WHAT_ABOUT_NEW_DOMAINS))

#
# Other utilities and directories
#

KVMSH ?= $(KVM_PYTHON) testing/utils/kvmsh.py
KVMRUNNER ?= $(KVM_PYTHON) testing/utils/kvmrunner.py
KVMRESULTS ?= $(KVM_PYTHON) testing/utils/kvmresults.py
KVMTEST ?= $(KVM_PYTHON) testing/utils/kvmtest.py

RPM_VERSION = $(shell make --no-print-directory showrpmversion)
RPM_PREFIX  = libreswan-$(RPM_VERSION)
RPM_BUILD_CLEAN ?= --rmsource --rmspec --clean


#
# Detect a fresh boot of the host machine.  Use this as a dependency
# for actions that should only be run once after each boot.
#
# The first time $(MAKE) is run after a boot, this file is touched,
# any further rules leave the file alone.
#

KVM_FRESH_BOOT_FILE = $(KVM_POOLDIR_PREFIX).boot.ok
$(KVM_FRESH_BOOT_FILE): $(firstword $(wildcard /var/run/rc.log /var/log/boot.log)) | $(KVM_LOCALDIR)
	touch $@

#
# Check that there is enough entoropy for running the domains.
#
# Only do this once per boot.
#

KVM_ENTROPY_FILE ?= /proc/sys/kernel/random/entropy_avail

$(KVM_POOLDIR_PREFIX).entropy.ok: $(KVM_FRESH_BOOT_FILE) | $(KVM_LOCALDIR)
	@if test ! -r $(KVM_ENTROPY_FILE); then				\
		echo no entropy to check ;				\
	elif test $$(cat $(KVM_ENTROPY_FILE)) -gt 100 ; then		\
		echo lots of entropy ;					\
	else								\
		echo ;							\
		echo  According to:					\
		echo ;							\
		echo      $(KVM_ENTROPY_FILE) ;				\
		echo ;							\
		echo  your computer does not have much entropy ;	\
		echo ;							\
		echo  Check the wiki for hints on how to fix this. ;	\
		echo ;							\
		false ;							\
	fi
	touch $@

KVM_HOST_OK += $(KVM_POOLDIR_PREFIX).entropy.ok

#
# Check that the QEMUDIR is writeable by us.
#
# (assumes that the machine is rebooted after a qemu update)
#


KVM_QEMUDIR ?= /var/lib/libvirt/qemu

$(KVM_POOLDIR_PREFIX).qemudir.ok: $(KVM_FRESH_BOOT_FILE) | $(KVM_LOCALDIR)
	@if ! test -w $(KVM_QEMUDIR) ; then				\
		echo ;							\
		echo "  The directory:" ;				\
		echo ;							\
		echo "     $(shell ls -ld $(KVM_QEMUDIR))" ;		\
		echo ;							\
		echo "  is not writeable." ;				\
		echo ;							\
		echo "  This will break virsh which is"	;		\
		echo "  used to manipulate the domains." ;		\
		echo ;							\
		false ;							\
	fi
	touch $@

KVM_HOST_OK += $(KVM_POOLDIR_PREFIX).qemudir.ok

#
# ensure that NFS is running and everything is exported
#

$(KVM_POOLDIR_PREFIX).nfs.ok: testing/libvirt/nfs.sh $(KVM_FRESH_BOOT_FILE) | $(KVM_LOCALDIR)
	sh testing/libvirt/nfs.sh $(KVM_POOLDIR) $(KVM_SOURCEDIR) $(KVM_TESTINGDIR)
	touch $@

KVM_HOST_OK += $(KVM_POOLDIR_PREFIX).nfs.ok

#
# Don't create $(KVM_POOLDIR) - let the user do that as it lives
# outside of the current directory tree.
#
# However, do create $(KVM_LOCALDIR) (but not using -p) if it is
# unique and doesn't exist - convention seems to be to point it at
# /tmp/pool which needs to be re-created every time the host is
# rebooted.
#
# Defining a macro and the printing it using $(info) is easier than
# a bunch of echo's or :s.
#

define kvm-pooldir-info

  The directory:

      "$(KVM_POOLDIR)"

  specified by KVM_POOLDIR and used to store the base domain disk
  and other files, does not exist.

  Either create the directory or adjust its location by setting
  KVM_POOLDIR in the file:

      Makefile.inc.local

endef

$(KVM_POOLDIR):
	$(info $(kvm-pooldir-info))
	false

ifneq ($(KVM_POOLDIR),$(KVM_LOCALDIR))
$(KVM_LOCALDIR):
	: not -p
	mkdir $(KVM_LOCALDIR)
endif


#
# [re]run the testsuite.
#
# If the testsuite is being run a second time (for instance,
# re-started or re-run) what should happen: run all tests regardless;
# just run tests that have never been started; run tests that haven't
# yet passed?  Since each alternative has merit, let the user decide
# by providing both kvm-test and kvm-retest.

KVM_TESTS ?= $(KVM_TESTINGDIR)/pluto

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
# - depends on kvm-keys-ok and not kvm-keys or $(KVM_KEYS) so that the
#   check that the keys are up-to-date is run.
#
# - need local domains shutdown as, otherwise, test domains can refuse
#   to boot because the domain they were cloned from is still running.

define kvm-test
.PHONY: $(1)
$(1): $(KVM_HOST_OK) kvm-keys-ok kvm-shutdown
	@$(MAKE) $$(if $$(WEB_ENABLED), web-test-prep, -s web-pages-disabled)
	: kvm-test target=$(1) param=$(2)
	: KVM_TESTS=$(STRIPPED_KVM_TESTS)
	$$(KVMRUNNER) \
		$(if $(KVM_PIDFILE), --pid-file "$(KVM_PIDFILE)") \
		$$(foreach prefix,$$(KVM_PREFIXES), --prefix $$(prefix)) \
		$$(if $$(KVM_WORKERS), --workers $$(KVM_WORKERS)) \
		$$(if $$(WEB_ENABLED), \
			--publish-hash $$(WEB_HASH) \
			--publish-results $$(WEB_RESULTSDIR) \
			--publish-status $$(WEB_SUMMARYDIR)/status.json) \
		$(2) $$(KVMRUNNER_FLAGS) $$(KVM_TEST_FLAGS) $$(STRIPPED_KVM_TESTS)
	@$(MAKE) $$(if $$(WEB_ENABLED), web-test-post, -s web-pages-disabled)
endef

# XXX: $(file < "x") tries to open '"x"' !!!
.PHONY: kvm-kill
kvm-kill:
	test -s "$(KVM_PIDFILE)" && kill $(file < $(KVM_PIDFILE))
.PHONY: kvm-status
kvm-status:
	test -s "$(KVM_PIDFILE)" && ps $(file < $(KVM_PIDFILE))

# "test" and "check" just runs the entire testsuite.
$(eval $(call kvm-test,kvm-check kvm-test, --test-status "good"))

# "retest" and "recheck" re-run the testsuite updating things that
# didn't pass.
$(eval $(call kvm-test,kvm-retest kvm-recheck, --test-status "good" --skip passed))

# clean up; accept pretty much everything
KVM_TEST_CLEAN_TARGETS = kvm-clean-check kvm-check-clean kvm-clean-test kvm-test-clean
.PHONY: $(KVM_TEST_CLEAN_TARGETS)
$(KVM_TEST_CLEAN_TARGETS):
	find $(STRIPPED_KVM_TESTS) -name OUTPUT -type d -prune -print0 | xargs -0 -r rm -r

.PHONY: kvm-results
kvm-results:
	$(KVMRESULTS) $(KVMRESULTS_FLAGS) $(KVM_TEST_FLAGS) $(STRIPPED_KVM_TESTS) $(if $(KVM_BASELINE),--baseline $(KVM_BASELINE))
.PHONY: kvm-diffs
kvm-diffs:
	$(KVMRESULTS) $(KVMRESULTS_FLAGS) $(KVM_TEST_FLAGS) $(STRIPPED_KVM_TESTS) $(if $(KVM_BASELINE),--baseline $(KVM_BASELINE)) --print diffs

#
# Build the KVM keys using the KVM.
#
# XXX:
#
# Can't yet force the domain's creation.  This target may have been
# invoked by testing/pluto/Makefile which relies on old domain
# configurations.
#
# Make certain everything is shutdown.  Can't directly depend on the
# phony target kvm-shutdown as that triggers an unconditional rebuild.
# Instead invoke that rule inline.
#
# "dist_certs.py" can't create a directory called "certs/" on a 9p
# mounted file system (OSError: [Errno 13] Permission denied:
# 'certs/').  In fact, "mkdir xxx/ certs/" half fails (only xxx/ is
# created) so it might even be a problem with the mkdir call!  Get
# around this by first creating the certs in /tmp on the guest, and
# then copying back using a tar file.
#
# "dist_certs.py" always writes its certificates to $(dirname $0).
# Get around this by running a copy of dist_certs.py placed in /tmp.

# file to mark keys are up-to-date
KVM_KEYS = $(KVM_TESTINGDIR)/x509/keys/up-to-date
KVM_KEYS_EXPIRATION_DAY = 7
KVM_KEYS_EXPIRED = find testing/x509/*/ -type f -mtime +$(KVM_KEYS_EXPIRATION_DAY) -ls
KVM_KEYS_DOMAIN = $(addprefix $(KVM_FIRST_PREFIX), fedora)

.PHONY: kvm-keys
kvm-keys:
	: invoke phony target to shut things down and delete old keys
	$(MAKE) kvm-shutdown
	$(MAKE) kvm-clean-keys
	$(MAKE) $(KVM_KEYS)

$(KVM_KEYS):	$(KVM_TESTINGDIR)/x509/dist_certs.py \
		$(KVM_TESTINGDIR)/x509/openssl.cnf \
		$(KVM_TESTINGDIR)/x509/strongswan-ec-gen.sh \
		$(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/generate-dnssec.sh \
		| \
		$(KVM_POOLDIR)/$(KVM_KEYS_DOMAIN) \
		$(KVM_HOST_OK)
	:
	: disable FIPS
	:
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) rm -f /etc/system-fips
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) guestbin/fipsoff
	:
	: Copy the scripts to the empty /tmp/x509 directory
	:
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) rm -rf /tmp/x509
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) mkdir /tmp/x509
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) cp -f x509/dist_certs.py /tmp/x509
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) cp -f x509/openssl.cnf /tmp/x509
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) cp -f x509/strongswan-ec-gen.sh /tmp/x509
	:
	: run key scripts in /tmp/x509
	:
	$(KVMSH) --chdir /tmp/x509 $(KVM_KEYS_DOMAIN) ./dist_certs.py
	$(KVMSH) --chdir /tmp/x509 $(KVM_KEYS_DOMAIN) ./strongswan-ec-gen.sh
	:
	: copy the certs from guest to host in a tar ball to avoid 9fs bug
	:
	rm -f $(KVM_POOLDIR_PREFIX)kvm-keys.tar
	$(KVMSH) --chdir /tmp/x509 $(KVM_KEYS_DOMAIN) tar cf kvm-keys.tar '*/' nss-pw
	$(KVMSH) --chdir /tmp/x509 $(KVM_KEYS_DOMAIN) cp kvm-keys.tar /pool/$(KVM_FIRST_PREFIX)kvm-keys.tar
	cd $(KVM_TESTINGDIR)/x509 && tar xf $(KVM_POOLDIR_PREFIX)kvm-keys.tar
	rm -f $(KVM_POOLDIR_PREFIX)kvm-keys.tar
	:
	: Also regenerate the DNSSEC keys
	:
	$(KVMSH) --chdir /testing $(KVM_KEYS_DOMAIN) ./baseconfigs/all/etc/bind/generate-dnssec.sh
	:
	: All done.
	:
	$(KVMSH) --shutdown $(KVM_KEYS_DOMAIN)
	touch $@

.PHONY: kvm-clean-keys kvm-keys-clean
kvm-clean-keys kvm-keys-clean:
	: careful output mixed with repo files
	rm -rf $(KVM_TESTINGDIR)/x509/*/
	rm -f $(KVM_TESTINGDIR)/x509/nss-pw
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/signed/*.signed
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/keys/*.key
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/keys/*.private
	rm -f $(KVM_TESTINGDIR)/baseconfigs/all/etc/bind/dsset/dsset-*
	rm -f $(KVM_POOLDIR_PREFIX)kvm-keys.tar

# For moment don't force keys to be re-built.
.PHONY: kvm-keys-ok
kvm-keys-ok:
	@if test ! -r $(KVM_KEYS); then							\
		echo "" ;								\
		echo "The KVM keys are missing; was 'make kvm-install' run?" ;		\
		echo "" ;								\
		exit 1 ;								\
	elif test $$($(KVM_KEYS_EXPIRED) | wc -l) -gt 0 ; then				\
		echo "" ;								\
		echo "The following KVM keys are too old:" ;				\
		$(KVM_KEYS_EXPIRED) ;							\
		echo "run 'make kvm-keys-clean kvm-keys' to force an update" ;		\
		echo "" ;								\
		exit 1 ;								\
	fi

#
# Build a pool of networks from scratch
#

# This defines the primitives, the public rules are defined near the
# end.

define create-kvm-network
	:
        : create-kvm-network file=$(strip $(1))
	:
	$(VIRSH) net-define $(1)
	$(VIRSH) net-autostart $(basename $(notdir $(1)))
	$(VIRSH) net-start $(basename $(notdir $(1)))
endef

define destroy-kvm-network
	: destroy-kvm-network network=$(strip $(1))
	if $(VIRSH) net-info '$(basename $(notdir $(1)))' 2>/dev/null | grep 'Active:.*yes' > /dev/null ; then \
		$(VIRSH) net-destroy '$(basename $(notdir $(1)))' ; \
	fi
	if $(VIRSH) net-info '$(basename $(notdir $(1)))' >/dev/null 2>&1 ; then \
		$(VIRSH) net-undefine '$(basename $(notdir $(1)))' ; \
	fi
	rm -f $(1)
endef


#
# The Gateway
#
# Because the gateway is created directly from libvirt/swandefault and
# that file contains hardwired IP addresses, but only one is possible.
#
# XXX: Why?  Perhaps it is so that SSHing into the VMs is possible,
# but with lots of VMs what address gets assigned stops being
# predictable.

# To avoid the problem where the host has no "default" KVM network
# (there's a rumour that libreswan's main testing machine has this
# problem) define a dedicated swandefault gateway.

KVM_GATEWAY ?= swandefault
KVM_GATEWAY_ADDRESS ?= 192.168.234.1

KVM_GATEWAY_FILE = $(KVM_POOLDIR)/$(KVM_GATEWAY).gw

$(KVM_POOLDIR)/$(KVM_GATEWAY).gw: | testing/libvirt/net/$(KVM_GATEWAY) $(KVM_POOLDIR)
	$(call destroy-kvm-network, $@)
	$(call create-kvm-network, testing/libvirt/net/$(KVM_GATEWAY))
	touch $@

#
# Test networks.
#
# Since networks survive across reboots and don't use any disk, they
# are stored in $(KVM_POOLDIR) and not $(KVM_LOCALDIR).
#

KVM_TEST_SUBNETS = $(notdir $(wildcard testing/libvirt/net/192_*))
KVM_TEST_NETWORKS = $(addsuffix .net, $(call add-kvm-localdir-prefixes, $(KVM_TEST_SUBNETS)))

.PRECIOUS: $(KVM_TEST_NETWORKS)

# <prefix><network>.net; if <prefix> is blank call it swan<network>*
KVM_BRIDGE_NAME = $(strip $(if $(patsubst 192_%,,$*), \
			$*, \
			swan$(subst _,,$(patsubst %192_,,$*))))

$(KVM_LOCALDIR)/%.net: | $(KVM_LOCALDIR)
	$(call destroy-kvm-network, $@)
	rm -f '$@.tmp'
	echo "<network ipv6='yes'>" 					>> '$@.tmp'
	echo "  <name>$*</name>"					>> '$@.tmp'
	echo "  <bridge name='$(KVM_BRIDGE_NAME)'" >> '$@.tmp'
	echo "          stp='on' delay='0'/>"				>> '$@.tmp'
	$(if $(patsubst 192_%,, $*), \
	echo "  <!--" 							>> '$@.tmp')
	echo "  <ip address='$(subst _,.,$(patsubst %192_, 192_, $*)).253'/>" >> '$@.tmp'
	$(if $(patsubst 192_%,, $*), \
	echo "    -->" 							>> '$@.tmp')
	echo "</network>"						>> '$@.tmp'
	: rename .net.tmp to .tmp
	mv $@.tmp $(basename $@).tmp
	$(call create-kvm-network, $(basename $@).tmp)
	mv $(basename $@).tmp $@

.PHONY: kvm-networks kvm-gateway
kvm-gateway: $(KVM_GATEWAY_FILE)
kvm-networks: $(KVM_TEST_NETWORKS)
.PHONY: kvm-purge-networks kvm-purge-gateway
kvm-purge-networks:
	$(foreach network, $(KVM_TEST_NETWORKS), \
		$(call destroy-kvm-network, $(network)))
kvm-purge-gateway:
	$(call destroy-kvm-network, $(KVM_GATEWAY_FILE)


##
##
## Download all required ISOs
##
##

# NetBSD requires a serial boot ISO (boot-com.iso) and an install ISO
# (NetBSD-*.iso).
#
# Try to give the OpenBSD and NetBSD ISOs meaningful names.
#
# Note: Remember, $(basename) is counter intuitive - unlike UNIX
# basename it doesn't strip the directory.

.PHONY: kvm-iso

KVM_LINUX_ISO = $(KVM_POOLDIR)/$(notdir $(KVM_LINUX_ISO_URL))
kvm-iso: $(KVM_LINUX_ISO)
$(KVM_LINUX_ISO): | $(KVM_POOLDIR)
	wget --output-document $@.tmp --no-clobber -- $(KVM_LINUX_ISO_URL)
	mv $@.tmp $@

KVM_FEDORA_ISO = $(KVM_POOLDIR)/$(notdir $(KVM_FEDORA_ISO_URL))
kvm-iso: $(KVM_FEDORA_ISO)
$(KVM_FEDORA_ISO): | $(KVM_POOLDIR)
	wget --output-document $@.tmp --no-clobber -- $(KVM_FEDORA_ISO_URL)
	mv $@.tmp $@

KVM_OPENBSD_ISO = $(KVM_POOLDIR)/OpenBSD-$(notdir $(KVM_OPENBSD_ISO_URL))
kvm-iso: $(KVM_OPENBSD_ISO)
$(KVM_OPENBSD_ISO): | $(KVM_POOLDIR)
	wget --output-document $@.tmp --no-clobber -- $(KVM_OPENBSD_ISO_URL)
	mv $@.tmp $@

KVM_NETBSD_INSTALL_ISO ?= $(KVM_POOLDIR)/$(notdir $(KVM_NETBSD_INSTALL_ISO_URL))
KVM_NETBSD_BOOT_ISO ?= $(basename $(KVM_NETBSD_INSTALL_ISO))-boot.iso
kvm-iso: $(KVM_NETBSD_BOOT_ISO) $(KVM_NETBSD_INSTALL_ISO)
$(KVM_NETBSD_INSTALL_ISO): | $(KVM_POOLDIR)
	wget --output-document $@.tmp --no-clobber -- $(KVM_NETBSD_INSTALL_ISO_URL)
	mv $@.tmp $@
$(KVM_NETBSD_BOOT_ISO): | $(KVM_POOLDIR)
	wget --output-document $@.tmp --no-clobber -- $(KVM_NETBSD_BOOT_ISO_URL)
	mv $@.tmp $@

##
##
## Utilities
##
##

define undefine-os-domain
	: undefine-os-domain
	:    path=$(strip $(1))
	:    domain=$(notdir $(1))
	case "$$($(VIRSH) domstate $(notdir $(1)))" in \
	"running" ) $(VIRSH) destroy $(notdir $(1)) ; $(VIRSH) undefine $(notdir $(1)) ;; \
	"shut off" ) $(VIRSH) undefine $(notdir $(1)) ;; \
	"" ) ;; \
	esac
	rm -f $(1)
	rm -f $(1).*
endef

define clone-os-disk
	: clone-os-disk
	:    in=$(strip $(1))
	:    out=$(strip $(2))
	sudo qemu-img create -f qcow2 -F qcow2 -b $(1) $(2)
endef

##
##
## Build the base domains
##
##

.PHONY: kvm-base
kvm-base: $(patsubst %, $(KVM_POOLDIR_PREFIX)%-base, $(KVM_PLATFORMS))

$(patsubst %, kvm-%-base, $(KVM_PLATFORMS)): \
kvm-%-base:
	rm -f $(KVM_POOLDIR_PREFIX)$(*)-base
	rm -f $(KVM_POOLDIR_PREFIX)$(*)-base.*
	$(MAKE) $(KVM_POOLDIR_PREFIX)$(*)-base

$(patsubst %, $(KVM_POOLDIR_PREFIX)%-base, $(KVM_PLATFORMS)): \
$(KVM_POOLDIR_PREFIX)%-base: | \
		testing/libvirt/%/base.py \
		$(KVM_POOLDIR) \
		$(KVM_HOST_OK) \
		$(KVM_GATEWAY_FILE)
	: clean up old domains
	$(call undefine-os-domain, $@)
	: use script to drive build of new domain
	DOMAIN=$(notdir $@) \
	GATEWAY=$(KVM_GATEWAY_ADDRESS) \
	POOLDIR=$(KVM_POOLDIR) \
	$(KVM_PYTHON) testing/libvirt/$*/base.py \
		$(VIRT_INSTALL) \
			$(VIRT_INSTALL_FLAGS) \
			--name=$(notdir $@) \
			--os-variant=$(KVM_$($*)_VIRT_INSTALL_OS_VARIANT) \
			--disk=path=$@.qcow2,size=$(VIRT_DISK_SIZE_GB),bus=virtio,format=qcow2 \
			$(KVM_$($*)_VIRT_INSTALL_FLAGS)
	: things are working: true is true and false is !true
	$(KVMSH) $(notdir $@) -- true
	! $(KVMSH) $(notdir $@) -- false
	$(KVMSH) --shutdown $(notdir $@)
	touch $@

# Fedora

KVM_FEDORA_BASE_DOMAIN = $(KVM_POOLDIR_PREFIX)fedora-base
KVM_FEDORA_VIRT_INSTALL_OS_VARIANT ?= fedora30
KVM_FEDORA_VIRT_INSTALL_FLAGS = \
	--location=$(KVM_FEDORA_ISO) \
	--initrd-inject=$(KVM_FEDORA_KICKSTART_FILE) \
	--extra-args="inst.ks=file:/$(notdir $(KVM_FEDORA_KICKSTART_FILE)) console=ttyS0,115200 net.ifnames=0 biosdevname=0"

$(KVM_FEDORA_BASE_DOMAIN): | $(KVM_FEDORA_ISO) $(KVM_FEDORA_KICKSTART_FILE)

# NetBSD

KVM_NETBSD_BASE_DOMAIN = $(KVM_POOLDIR_PREFIX)netbsd-base
KVM_NETBSD_VIRT_INSTALL_OS_VARIANT ?= netbsd8.0
KVM_NETBSD_VIRT_INSTALL_FLAGS = \
	--cdrom=$(KVM_NETBSD_BOOT_ISO) \
	--disk=path=$(KVM_NETBSD_INSTALL_ISO),readonly=on,device=cdrom

$(KVM_NETBSD_BASE_DOMAIN): | $(KVM_NETBSD_INSTALL_ISO) $(KVM_NETBSD_BOOT_ISO)

# OpenBSD needs to mangle the ISO

KVM_OPENBSD_BASE_DOMAIN = $(KVM_POOLDIR_PREFIX)openbsd-base
KVM_OPENBSD_VIRT_INSTALL_OS_VARIANT ?= openbsd6.5
KVM_OPENBSD_INSTALL_ISO = $(KVM_POOLDIR_PREFIX)openbsd.iso
KVM_OPENBSD_VIRT_INSTALL_FLAGS = --cdrom=$(KVM_OPENBSD_INSTALL_ISO)

$(KVM_OPENBSD_BASE_DOMAIN): | $(KVM_OPENBSD_INSTALL_ISO)

$(KVM_OPENBSD_INSTALL_ISO): $(KVM_OPENBSD_ISO) testing/libvirt/openbsd/install.conf testing/libvirt/openbsd/boot.conf
	cp $(KVM_OPENBSD_ISO) $@.tmp
	growisofs -M $@.tmp -l -R -input-charset utf-8 \
		-graft-points \
		/install.conf="testing/libvirt/openbsd/install.conf" \
		/etc/boot.conf="testing/libvirt/openbsd/boot.conf"
	mv $@.tmp $@

##
## Create and update the base domain, installing missing packages.
##
## Repeated kvm-$(OS)-upgrade calls upgrade (not fresh install) the
## domain.  Use kvm-$(OS)-downgrade to force this.
##
## At this point only /pool is accessible (/source and /testing are
## not, see below).

$(patsubst %, kvm-%-downgrade, $(KVM_PLATFORMS)): \
kvm-%-downgrade:
	rm -f $(KVM_POOLDIR_PREFIX)$(*)-upgrade
	rm -f $(KVM_POOLDIR_PREFIX)$(*)-upgrade.*

.PHONY: kvm-downgrade
kvm-downgrade: $(patsubst %, kvm-%-downgrade, $(KVM_PLATFORMS))

$(patsubst %, kvm-%-upgrade, $(KVM_PLATFORMS)): \
kvm-%-upgrade:
	rm -f $(KVM_POOLDIR_PREFIX)$(*)-upgrade  # not .*
	$(MAKE) $(KVM_POOLDIR_PREFIX)$(*)-upgrade

.PHONY: kvm-upgrade
kvm-upgrade: $(patsubst %, kvm-%-upgrade, $(KVM_PLATFORMS))

$(patsubst %, $(KVM_POOLDIR_PREFIX)%-upgrade.vm, $(KVM_PLATFORMS)): \
$(KVM_POOLDIR_PREFIX)%-upgrade.vm: $(KVM_POOLDIR_PREFIX)%-base \
		testing/libvirt/%/install.sh \
		| $(KVM_HOST_OK)
	: creating domain ...-upgrade, not -upgrade.vm, hence basename
	$(call undefine-os-domain, $(basename $@))
	$(call clone-os-disk, $<.qcow2, $(basename $@).qcow2)
	$(VIRT_INSTALL) \
		$(VIRT_INSTALL_FLAGS) \
		--name=$(notdir $(basename $@)) \
		--os-variant=$(KVM_$($*)_VIRT_INSTALL_OS_VARIANT) \
		--disk=cache=writeback,path=$(basename $@).qcow2 \
		--import \
		--noautoconsole
	: install $(notdir $(basename $@)) using install.sh from $(srcdir) and not $(KVM_SOURCEDIR)
	cp testing/libvirt/$*/install.sh $(KVM_POOLDIR)/$(notdir $(basename $@)).install.sh
	$(KVMSH) $(notdir $(basename $@)) -- /pool/$(notdir $(basename $@)).install.sh $(KVM_$($*)_INSTALL_FLAGS)
	: only shutdown when install works
	$(KVMSH) --shutdown $(basename $(notdir $@))
	touch $@

$(patsubst %, $(KVM_POOLDIR_PREFIX)%-upgrade, $(KVM_PLATFORMS)): \
$(KVM_POOLDIR_PREFIX)%-upgrade: $(KVM_POOLDIR_PREFIX)%-upgrade.vm \
		testing/libvirt/%/upgrade.sh \
		| $(KVM_HOST_OK)
	: upgrade $($*) using upgrade.sh from $(srcdir) and not $(KVM_SOURCEDIR)
	cp testing/libvirt/$*/upgrade.sh $(KVM_POOLDIR)/$(notdir $(basename $@)).upgrade.sh
	$(KVMSH) $(notdir $@) -- /pool/$(notdir $(basename $@)).upgrade.sh $(KVM_$($*)_UPGRADE_FLAGS)
	: only shutdown when upgrade works
	$(KVMSH) --shutdown $(notdir $@)
	touch $@

##
## Create the platform domain by transmogrifying the updated domain.
##
## This also makes /source $(KVM_SOURCEDIR) and /testing
## $(KVM_TESTINGDIR) available to the VM.  Setting these during
## transmogrify means changing them only requires a re-transmogrify
## and not a full domain rebuild.

.PHONY: kvm-transmogrify
kvm-transmogrify: $(patsubst %, kvm-%-transmogrify, $(KVM_PLATFORMS))

$(patsubst %, kvm-%-transmogrify, $(KVM_PLATFORMS)): \
kvm-%-transmogrify:
	rm -f $(KVM_POOLDIR_PREFIX)$(*)
	rm -f $(KVM_POOLDIR_PREFIX)$(*).*
	$(MAKE) $(KVM_POOLDIR_PREFIX)$(*)

$(patsubst %, $(KVM_POOLDIR_PREFIX)%, $(KVM_PLATFORMS)): \
$(KVM_POOLDIR_PREFIX)%: $(KVM_POOLDIR_PREFIX)%-upgrade \
		| \
		testing/libvirt/%/transmogrify.sh \
		$(KVM_HOST_OK)
	$(call undefine-os-domain, $@)
	$(call clone-os-disk, $<.qcow2, $@.qcow2)
	$(VIRT_INSTALL) \
		$(VIRT_INSTALL_FLAGS) \
		$(VIRT_SOURCEDIR) \
		$(VIRT_TESTINGDIR) \
		--name=$(notdir $@) \
		--os-variant=$(KVM_$($*)_VIRT_INSTALL_OS_VARIANT) \
		--disk=cache=writeback,path=$@.qcow2 \
		--import \
		--noautoconsole
	: transmogrify $($*) using transmogrify.sh from srcdir=$(srcdir) and not KVM_SOURCEDIR=$(KVM_SOURCEDIR)
	cp testing/libvirt/$*/transmogrify.sh $(KVM_POOLDIR)/$(notdir $(basename $@)).transmogrify.sh
	$(KVMSH) $(notdir $@) -- \
		GATEWAY=$(KVM_GATEWAY_ADDRESS) \
		POOLDIR=$(KVM_POOLDIR) \
		SOURCEDIR=$(KVM_SOURCEDIR) \
		TESTINGDIR=$(KVM_TESTINGDIR) \
		/pool/$(notdir $(basename $@)).transmogrify.sh
	: shutdown needed after transmogrify but only shutdown when transmogrify works
	$(KVMSH) --shutdown $(notdir $@)
	touch $@

##
## Install libreswan into the build.
##

$(patsubst %, kvm-%-install, $(KVM_PLATFORMS)): \
kvm-%-install: $(KVM_POOLDIR_PREFIX)%
	$(KVMSH) $(KVMSH_FLAGS) \
		--chdir /source \
		$(notdir $<) \
		-- \
		gmake install-base $(KVM_MAKEFLAGS) $(KVM_$($*)_MAKEFLAGS)
	$(KVMSH) --shutdown $(notdir $<)


#
# Create the local domains
#

# Since running a domain will likely modify its .qcow2 disk image
# (changing MTIME), the domain's disk isn't a good indicator that a
# domain needs updating.  Instead use the domain-name to indicate that
# a domain has been created.

.PRECIOUS: $(foreach domain, $(KVM_LOCAL_DOMAINS), $(KVM_LOCALDIR)/$(domain))

define define-clone-domain
  $(addprefix $(1), $(2)): $(3) | \
		$$(foreach subnet, $$(KVM_TEST_SUBNETS), \
			$(addprefix $(1), $$(subnet).net)) \
		testing/libvirt/vm/$(strip $(2)).xml
	: install-kvm-test-domain prefix=$(strip $(1)) host=$(strip $(2)) template=$(strip $(3))
	$$(call undefine-os-domain, $$@)
	$(call clone-os-disk, $(addprefix $(3), .qcow2), $$@.qcow2)
	sed \
		-e "s:@@NAME@@:$$(notdir $$@):" \
		-e "s:@@TESTINGDIR@@:$$(KVM_TESTINGDIR):" \
		-e "s:@@SOURCEDIR@@:$$(KVM_SOURCEDIR):" \
		-e "s:@@POOLDIR@@:$$(KVM_POOLDIR):" \
		-e "s:@@LOCALDIR@@:$$(KVM_LOCALDIR):" \
		-e "s:@@USER@@:$$(KVM_UID):" \
		-e "s:@@GROUP@@:$$(KVM_GID):" \
		-e "s:network='192_:network='$(addprefix $(notdir $(1)), 192_):" \
		< testing/libvirt/vm/$(strip $(2)).xml \
		> '$$@.tmp'
	$$(VIRSH) define $$@.tmp
	mv $$@.tmp $$@
endef

$(foreach prefix, $(KVM_LOCALDIR_PREFIXES), \
	$(foreach platform, $(KVM_PLATFORMS), \
		$(foreach host, $(KVM_$($(platform))_HOSTS), \
			$(eval $(call define-clone-domain, \
				$(prefix), \
				$(host), \
				$(KVM_POOLDIR_PREFIX)$(platform))))))


#
# Get rid of (almost) everything
#
# After running the operation, kvm-install will:
#
# kvm-uninstall:            transmogrify,              install
# kvm-clean-keys:                                keys, install
# kvm-clean:                transmogrify, build, keys, install
# kvm-purge:       upgrade, transmogrify, build, keys, install
#
# For kvm-uninstall, instead of trying to uninstall libreswan from the
# build domain, delete both the clones and the build domain and
# $(KVM_KEYS_DOMAIN) the install domains were cloned from.  This way,
# in addition to giving kvm-install a 100% fresh start (no dependence
# on 'make uninstall') the next test run also gets entirely new
# domains.

define shutdown-os-domain
	$(KVMSH) --shutdown $(notdir $(1))

endef

.PHONY: kvm-shutdown
kvm-shutdown:
	$(foreach platform, $(KVM_PLATFORMS), \
		$(foreach clone, $(KVM_$($(platform))_CLONES), \
			$(call shutdown-os-domain, $(clone))))
	$(foreach platform, $(KVM_PLATFORMS), \
		$(foreach variant, base upgrade build, \
			$(call shutdown-os-domain, $(KVM_POOLDIR_PREFIX)$(platform)-$(variant))))

.PHONY: kvm-uninstall kvm-clean-install
kvm-uninstall kvm-clean-install:
	$(foreach platform, $(KVM_PLATFORMS), $(foreach clone, $(KVM_$($(platform))_CLONES), $(call undefine-os-domain, $(clone))))
	$(foreach platform, $(KVM_PLATFORMS), $(call undefine-os-domain, $(KVM_POOLDIR_PREFIX)$(platform)))
	$(call undefine-os-domain, $(KVM_LOCALDIR)/$(KVM_KEYS_DOMAIN))

.PHONY: kvm-clean
kvm-clean: kvm-clean-install
kvm-clean: kvm-clean-keys
kvm-clean: kvm-clean-check
kvm-clean:
	rm -rf $(patsubst %, OBJ.*.%/, $(KVM_PLATFORMS))
	rm -rf OBJ.*.swanbase

.PHONY: kvm-purge
kvm-purge: kvm-clean
kvm-purge: kvm-purge-networks
kvm-purge:
	$(foreach platform, $(KVM_PLATFORMS), $(call undefine-os-domain, $(KVM_POOLDIR_PREFIX)$(platform)-upgrade))
	: legacy
	$(foreach platform, $(KVM_PLATFORMS), $(call undefine-os-domain, $(KVM_POOLDIR_PREFIX)$(platform)-build))
	rm -f $(KVM_HOST_OK)

.PHONY: kvm-demolish
kvm-demolish: kvm-purge
kvm-demolish:
	$(foreach platform, $(KVM_PLATFORMS), $(call undefine-os-domain, $(KVM_POOLDIR_PREFIX)$(platform)-base))

#
# Create an RPM for the test domains
#

.PHONY: kvm-rpm
kvm-rpm: $(KVM_POOLDIR_PREFIX)fedora
	@echo building rpm for libreswan testing
	mkdir -p rpmbuild/SPECS/
	: NOTE: testing/packaging/// and NOT packaging/...
	sed -e "s/@IPSECBASEVERSION@/$(RPM_VERSION)/g" \
		-e "s/^Version:.*/Version: $(RPM_VERSION)/g" \
		-e "s/@INITSYSTEM@/$(INITSYSTEM)/g" \
		testing/packaging/fedora/libreswan-testing.spec \
		> rpmbuild/SPECS/libreswan-testing.spec
	mkdir -p rpmbuild/SOURCES
	git archive \
		--format=tar \
		--prefix=$(RPM_PREFIX)/ \
		-o rpmbuild/SOURCES/$(RPM_PREFIX).tar \
		HEAD
	: add Makefile.in.local?
	if [ -a Makefile.inc.local ] ; then \
		tar --transform "s|^|$(RPM_PREFIX)/|" \
			-rf rpmbuild/SOURCES/$(RPM_PREFIX).tar \
			Makefile.inc.local ; \
	fi
	gzip -f rpmbuild/SOURCES/$(RPM_PREFIX).tar
	$(KVMSH) --chdir /source $(notdir $<) -- \
		rpmbuild -D_topdir\\ /source/rpmbuild \
			-ba $(RPM_BUILD_CLEAN) \
			rpmbuild/SPECS/libreswan-testing.spec

.PHONY: kvm-rpm-install
kvm-rpm-install: $(KVM_POOLDIR_PREFIX)fedora
	rm -fr rpmbuild/*RPMS
	$(MAKE) kvm-rpm
	$(KVMSH) $(KVMSH_FLAGS) --chdir . $(notdir $<) 'rpm -aq | grep libreswan && rpm -e $$(rpm -aq | grep libreswan) || true'
	$(KVMSH) $(KVMSH_FLAGS) --chdir . $(notdir $<) 'rpm -i /source/rpmbuild/RPMS/x86_64/libreswan*rpm'
	$(KVMSH) $(KVMSH_FLAGS) --chdir . $(notdir $<) 'restorecon /usr/local/sbin /usr/local/libexec/ipsec -Rv'
	$(KVMSH) --shutdown $(KVM_KEYS_DOMAIN)

#
# kvm-install target
#
# First delete all of the build domain's clones.  The build domain
# won't boot when its clones are running.
#
# So that all the INSTALL domains are deleted before the build domain
# is booted, this is done using a series of sub-makes (without this,
# things barf because the build domain things its disk is in use).

.PHONY: kvm-install
kvm-install: | $(KVM_OPENBSD_CLONES)
	$(foreach clone, $(KVM_FEDORA_CLONES), $(call undefine-os-domain, $(clone)))
ifeq ($(KVM_INSTALL_RPM), true)
	$(MAKE) kvm-rpm-install
else
	$(MAKE) kvm-fedora-install
endif
	$(MAKE) $(KVM_KEYS)
	$(MAKE) $(KVM_FEDORA_CLONES)

.PHONY: kvm-bisect
kvm-bisect:
	: 125 is git bisect magic for 'skip'
	$(MAKE) kvm-install || exit 125
	$(MAKE) kvm-test kvm-diffs $(if $(KVM_TESTS),KVM_TESTS="$(KVM_TESTS)")

#
# kvmsh-HOST
#
# Map this onto the first domain group.  Logging into the other
# domains can be done by invoking kvmsh.py directly.
#

define kvm-HOST-DOMAIN
  #(info kvm-HOST-DOMAIN rule-prefix=$(1) host=$(2)
  .PHONY: $$(addprefix $(1), $(2))
  $$(addprefix $(1), $(2)): \
		$$(addprefix $(1), $$(addprefix $$(KVM_FIRST_PREFIX), $(2)))
endef

$(foreach host, $(filter-out $(KVM_DOMAINS), $(KVM_HOSTS)), \
	$(eval $(call kvm-HOST-DOMAIN, kvmsh-, $(host))))

# the base domain only requires the raw image; not upgraded

define kvmsh-DOMAIN
  #(info kvmsh-DOMAIN domain=$(1) make-target=$(2))
  .PHONY: kvmsh-$(1)
  kvmsh-$(strip $(1)): $(2) | $(KVM_HOST_OK)
	: kvmsh-DOMAIN domain=$(1) make-target=$(2)
	$$(KVMSH) $$(KVMSH_FLAGS) $(1) $(KVMSH_COMMAND)
endef

$(foreach domain, $(KVM_LOCAL_DOMAINS), \
	$(eval $(call kvmsh-DOMAIN,$(domain),$$(KVM_LOCALDIR)/$(domain))))

$(foreach variant, base upgrade build, \
	$(foreach platform, $(KVM_PLATFORMS), \
		$(eval $(call kvmsh-DOMAIN, \
			$(KVM_FIRST_PREFIX)$(platform)-$(variant), \
			$(KVM_POOLDIR_PREFIX)$(platform)-$(variant)))))

.PHONY: kvmsh-base
kvmsh-base: kvmsh-$(KVM_FIRST_PREFIX)fedora-base

.PHONY: kvmsh-build
kvmsh-build: kvmsh-$(KVM_FIRST_PREFIX)fedora


#
# Some hints
#
# Only what is listed in here is "supported"
#

define kvm-var-value
$(1)=$($(1)) [$(value $(1))]
endef

define kvm-value
$($(1)) [$(value $(1))]
endef

define kvm-var
$($(1)) [$$($(1))]
endef

define kvm-config

Configuration:

  Makefile variables:

    $(call kvm-var-value,KVM_SOURCEDIR)
    $(call kvm-var-value,KVM_TESTINGDIR)

    $(call kvm-var-value,KVM_POOLDIR)
	directory for storing the shared base VM;
	should be relatively permanent storage
    $(call kvm-var-value,KVM_LOCALDIR)
	directory for storing the VMs local to this build tree;
	can be temporary storage (for instance /tmp)

    $(call kvm-var-value,KVM_WORKERS)

    $(call kvm-var-value,KVM_PREFIX)
    $(call kvm-var-value,KVM_FIRST_PREFIX)
    $(call kvm-var-value,KVM_PREFIXES)
    $(call kvm-var-value,KVM_POOLDIR_PREFIX)
    $(call kvm-var-value,KVM_LOCALDIR_PREFIXES)

    $(call kvm-var-value,KVM_GROUP)
    $(call kvm-var-value,KVM_PIDFILE)
    $(call kvm-var-value,KVM_UID)
    $(call kvm-var-value,KVM_GID)
    $(call kvm-var-value,KVM_CONNECTION)
    $(call kvm-var-value,KVM_VIRSH)
	the shared NATting gateway;
	used by the base domain along with any local domains
	when internet access is required

    $(call kvm-var-value,KVM_KEYS_DOMAIN)

    $(call kvm-var-value,KVM_DEBIAN_MAKEFLAGS)
    $(call kvm-var-value,KVM_FEDORA_MAKEFLAGS)
    $(call kvm-var-value,KVM_NETBSD_MAKEFLAGS)
    $(call kvm-var-value,KVM_OPENBSD_MAKEFLAGS)

    $(call kvm-var-value,KVM_DEBIAN_HOSTS)
    $(call kvm-var-value,KVM_FEDORA_HOSTS)
    $(call kvm-var-value,KVM_NETBSD_HOSTS)
    $(call kvm-var-value,KVM_OPENBSD_HOSTS)

    $(call kvm-var-value,KVM_DEBIAN_CLONES)
    $(call kvm-var-value,KVM_FEDORA_CLONES)
    $(call kvm-var-value,KVM_NETBSD_CLONES)
    $(call kvm-var-value,KVM_OPENBSD_CLONES)

    $(call kvm-var-value,KVM_GATEWAY)
    $(call kvm-var-value,KVM_GATEWAY_FILE)
    $(call kvm-var-value,KVM_TEST_SUBNETS)
    $(call kvm-var-value,KVM_TEST_NETWORKS)

    $(call kvm-var-value,KVM_TEST_HOSTS)
    $(call kvm-var-value,KVM_TEST_DOMAINS)

 KVM Domains:

    $(KVM_BASE_DOMAIN)
    | gateway: $(KVM_GATEWAY)
    | directory: $(KVM_POOLDIR)
    |
    +- $(KVM_KEYS_DOMAIN)
    |  | gateway: $(KVM_GATEWAY)
    |  | directory: $(KVM_POOLDIR)
    |  |  \
$(foreach prefix,$(KVM_PREFIXES), \
  \
  $(crlf)$(sp)$(sp)$(sp)$(sp)|$(sp)$(sp)| test group $(prefix) \
  $(crlf)$(sp)$(sp)$(sp)$(sp)|$(sp) +-- \
  $(foreach install,$(KVM_FEDORA_HOSTS),$(call strip-prefix,$(prefix))$(install)) \
  \
  $(crlf)$(sp)$(sp)$(sp)$(sp)|$(sp)$(sp)|$(sp$)$(sp)$(sp) networks: \
  $(foreach network, $(KVM_TEST_SUBNETS),$(call strip-prefix,$(prefix))$(network)) \
  \
  $(crlf)$(sp)$(sp)$(sp)$(sp)|$(sp)$(sp)| \
)
endef

define kvm-help

Manually building and modifying the base domain and network:

  Normally kvm-install et.al, below, are sufficient.  However ....

  The first step in setting up the test environment is creating the
  base domain.  The make targets below can be used to step through the
  process of constructing the base domain.  At anytime kvmsh-base can
  be used to log into that domain.

    kvmsh-base

      log into the base domain (if necessary, kickstart it); this will
      not trigger an upgrade or transmogrify

    kvm-downgrade

      revert everything back to the kickstarted base domain; no extra
      packages will have been upgraded and no transmogrification will
      have been performed

      if the base domain doesn't exist it will be created

    kvm-upgrade

      perform an incremental install/upgrade any packages needed by
      libreswan; to force a complete re-install of all packages, first
      kvm-downgrade

      to keep kickstart (which is something of a black box) as simple
      as possible, and to make re-running / debugging the upgrade
      process easier, this step is not embedded in kickstart.

    kvm-transmogrify

      install all the configuration files so that the domain will
      automatically transmogrify from the base domain to a test domain
      during boot

  also:

    kvm-install-gateway
    kvm-uninstall-gateway

      just create the base domain's gateway

      note that uninstalling the gateway also uninstalls the base
      domain (since it depends on the gateway)

Running 'git bisect' to find a regression:

  First find or create test (don't commit it) that detects the
  regression.  If the test is new don't commit it - this way the test
  sticks around as commits are checked out.

  Next, as per normal, establish the bounds of the bisect:

    git bisect start
    git bisect good ...
    git bisect bad ...

  Finally use the kvm-bisect and KVM_TESTS to build and run each
  commit:

    git bisect run make kvm-bisect KVM_TESTS=test/that/changed

  The kvm-bisect target is roughly equivalent to:

    make kvm-install || exit 125
    make kvm-test KVM_TESTS=...
    make kvm-diffs KVM_TESTS=...

  where <<exit 125>> is git magic for result unknown; and (unlike
  kvm-test) kvm-diffs exits with a non-zero status code when things
  fail.

Standard targets and operations:

  Delete the installed KVMs and networks so that the next kvm-install
  will create new versions:

    kvm-uninstall: force clean test and build domains
        - delete test domains
        - delete test build
    kvm-purge:
        - delete test domains
	- delete test build
        - delete test results
        - delete test networks
    kvm-demolish: wipe out a directory
        - also delete the base domain

  Manipulating and accessing (logging into) domains:

    kvmsh-build
    kvmsh-HOST ($(filter-out build, $(KVM_TEST_HOSTS)))
        - use 'virsh console' to login to the given domain
	- for HOST login to the first domain vis:
          $(addprefix $(KVM_FIRST_PREFIX), HOST)
        - if necessary, create and boot the host
    $(addprefix kvmsh-, $(KVM_LOCAL_DOMAINS))
        - login to the specific domain
        - if necessary, create and boot the domain

    kvm-shutdown
        - shutdown all domains

  To build or delete the keys used when testing:

    kvm-keys (kvm-clean-keys)
        - use the local build domain to create the test keys

  To set things up for a test run:

    kvm-install:

      build / install (or update) everything needed for a test run

    kvm-uninstall:

      uninstall libreswan from the the test domains (cheats by
      deleting the build and test domains); doesn't touch the build
      directory or test results

    kvm-clean:

      cleans the directory of the build, test results, and test
      domains ready for a new run

  To run the testsuite against libreswan installed on the test domains
  (see "make kvm-install" above):

    kvm-check         - run all GOOD tests against the
                        previously installed libreswan
    kvm-check KVM_TESTS+=testing/pluto/basic-pluto-0[0-1]
                      - run test matching the pattern
    kvm-check KVM_TEST_FLAGS='--test-status "good|wip"'
                      - run both good and wip tests
    kvm-recheck       - like kvm-check but skip tests that
                        passed during the previous kvm-check
    kvm-check-clean   - delete the test OUTPUT/ directories

    distclean         - scrubs the source tree (but don't touch the KVMS)

    kvm-status        - prints PS for the currently running tests
    kvm-kill          - kill the currently running tests

  To analyze test results:

    kvm-results       - list the tests and their results
                        compare against KVM_BASELINE when defined
    kvm-diffs         - list the tests and their differences
                        compare against KVM_BASELINE when defined

endef

.PHONY: kvm-help
kvm-help:
	$(info $(kvm-help))
	$(info For more details see "make kvm-config" and "make web-config")

.PHONY: kvm-config
kvm-config:
	$(info $(kvm-config))
