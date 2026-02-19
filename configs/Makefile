# Makefile for miscellaneous programs
#
# Copyright (C) 2002-2006  Michael Richardson	<mcr@xelerance.com>
# Copyright (C) 2025 Andrew Cagney
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

include ../mk/dirs.mk
include $(top_srcdir)/mk/config.mk

# the man page source is generated
MANPAGES += ipsec.conf.5
MANPAGES += ipsec.secrets.5

XMLTO_SEARCHPATH = $(abs_srcdir):$(abs_top_srcdir)/mk

# different mode
ipsec.secrets.INSTFLAGS = -m 0600

CONFFILES += ipsec.conf
CONFFILES += ipsec.secrets

LOGROTATEDFILE += libreswan

CONFDSUBDIR = policies
CONFDSUBDIRFILES = clear clear-or-private private-or-clear private block portexcludes.conf

local-base: $(CONFFILES) $(CONFDSUBDIRFILES) $(LOGROTATEDFILE)

local-clean-base:
	rm -f $(builddir)/*

# For each group of files; first copy to the examples directory and
# then, optionally, install into /etc (but only when
# INSTALL_CONFIGS=true, and only when not already present).

local-install-base: $(CONFFILES) $(CONFDSUBDIRFILES) $(LOGROTATEDFILE)
	@: CONFDDIR - EXAMPLECONFDIR not EXAMPLECONFDDIR and sample suffix
	@set -eu ; $(call install-directory, $(DESTDIR)$(EXAMPLE_IPSEC_SYSCONFDIR))
	@set -eu ; $(call install-file, $(INSTCONFFLAGS) $(ipsec.conf.INSTFLAGS),    $(builddir)/ipsec.conf,    $(DESTDIR)$(EXAMPLE_IPSEC_SYSCONFDIR)/$(notdir $(IPSEC_CONF))-sample)
	@set -eu ; $(call install-file, $(INSTCONFFLAGS) $(ipsec.secrets.INSTFLAGS), $(builddir)/ipsec.secrets, $(DESTDIR)$(EXAMPLE_IPSEC_SYSCONFDIR)/$(notdir $(IPSEC_SECRETS))-sample)
ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(DESTDIR)$(IPSEC_CONFDDIR), 0700)
	@set -eu ; $(call install-missing-file, $(INSTCONFFLAGS) $(ipsec.conf.INSTFLAGS),    $(builddir)/ipsec.conf,    $(DESTDIR)$(IPSEC_CONF))
	@set -eu ; $(call install-missing-file, $(INSTCONFFLAGS) $(ipsec.secrets.INSTFLAGS), $(builddir)/ipsec.secrets, $(DESTDIR)$(IPSEC_SECRETS))
endif
	@: CONFDSUBDIR
	@set -eu ; $(call install-directory, $(DESTDIR)$(EXAMPLE_IPSEC_CONFDDIR), 0700)
	@set -eu ; $(call install-directory, $(DESTDIR)$(EXAMPLE_IPSEC_CONFDDIR)/$(CONFDSUBDIR), 0700)
	@set -eu ; $(foreach file, $(CONFDSUBDIRFILES), \
		$(call install-file, $(INSTCONFFLAGS), \
			$(builddir)/$(file), $(DESTDIR)$(EXAMPLE_IPSEC_CONFDDIR)/$(CONFDSUBDIR)/$(file)) ; \
	)
ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(DESTDIR)$(IPSEC_CONFDDIR)/$(CONFDSUBDIR), 0700)
	@set -eu ; $(foreach file, $(CONFDSUBDIRFILES), \
		$(call install-missing-file, $(INSTCONFFLAGS), \
			$(DESTDIR)$(EXAMPLE_IPSEC_CONFDDIR)/$(CONFDSUBDIR)/$(file), $(DESTDIR)$(IPSEC_CONFDDIR)/$(CONFDSUBDIR)/$(file)) ; \
	)
endif
	@: LOGROTATED
	@set -eu ; $(call install-directory, $(DESTDIR)$(EXAMPLE_LOGROTATEDDIR))
	@set -eu ; $(call install-file, $(INSTCONFFLAGS), \
		$(builddir)/$(LOGROTATEDFILE), $(DESTDIR)$(EXAMPLE_LOGROTATEDDIR)/$(LOGROTATEDFILE))
ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(DESTDIR)$(LOGROTATEDDIR))
	@set -eu ; $(call install-missing-file, $(INSTCONFFLAGS), \
		$(builddir)/$(LOGROTATEDFILE), $(DESTDIR)$(LOGROTATEDDIR)/$(LOGROTATEDFILE))
endif
	@: NSSDIR install
ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(DESTDIR)$(NSSDIR), 0700)
endif
ifeq ($(USE_AUTHPAM),true)
	@: PAM
	@set -eu ; $(call install-directory, $(DESTDIR)$(EXAMPLE_PAMCONFDIR))
	@set -eu ; $(call install-file, $(INSTCONFFLAGS), \
			pam.d/pluto, $(DESTDIR)$(EXAMPLE_PAMCONFDIR)/pluto)
 ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(DESTDIR)$(PAMCONFDIR))
	@set -eu ; $(call install-missing-file, $(INSTCONFFLAGS), \
			$(DESTDIR)$(EXAMPLE_PAMCONFDIR)/pluto, $(DESTDIR)$(PAMCONFDIR)/pluto)
 endif
endif
	@: $(SELINUX)
ifeq ($(INSTALL_CONFIGS),true)
	@if test -z "$(DESTDIR)" -a -x /usr/sbin/selinuxenabled -a $(DESTDIR)$(SBINDIR) != "$(DESTDIR)/usr/sbin" ; then \
	if /usr/sbin/selinuxenabled ; then  \
		echo -e "\n************************** WARNING ***********************************" ; \
		echo "SElinux is present on this system and the prefix path is not /usr." ; \
		echo "This can cause software failures if selinux is running in Enforcing mode"; \
		echo -e "unless selinux policies are updated manually to allow this.\n" ; \
		echo "The following commands fix a common issue of /usr/local/ being mislabeled"; \
		echo "    sudo restorecon /usr/local/sbin -Rv"; \
		echo "    sudo restorecon /usr/local/libexec/ipsec -Rv"; \
		if test -x /usr/sbin/getenforce ; then \
			echo -e "\nSElinux is currently running in `/usr/sbin/getenforce` mode" ; \
		fi ; \
		echo -e "**********************************************************************\n" ; \
	fi \
	fi
endif

list-local-base:
	@set -eu ; $(foreach file, $(CONFFILES), \
		echo $(DESTDIR)$(SYSCONFDIR)/$(file) ; \
	)
	@set -eu ; $(foreach file, $(CONFFILES), \
		echo $(DESTDIR)$(EXAMPLE_IPSEC_SYSCONFDIR)/$(file)-sample ; \
	)
	@set -eu ; $(foreach file, $(CONFDSUBDIRFILES), \
		echo $(DESTDIR)$(IPSEC_CONFDDIR)/$(CONFDSUBDIR)/$${file} ; \
	)

# Custom rules for ipsec.conf.5; manpages.mk should be updated to
# mimic this behaviour.

D_IPSEC_CONF_XML = $(srcdir)/d.ipsec.conf/*/*.xml
D_IPSEC_CONF_EXAMPLE = $(srcdir)/d.ipsec.conf/*.example

$(builddir)/ipsec.conf.5.man: $(srcdir)/ipsec.conf.5.xml
$(builddir)/ipsec.conf.5.man: $(D_IPSEC_CONF_XML)
$(builddir)/ipsec.conf.5.man: $(D_IPSEC_CONF_EXAMPLE)
$(builddir)/ipsec.conf.5.man: $(builddir)/ipsec.conf.5.ok

$(builddir)/ipsec.conf.5.ok: $(D_IPSEC_CONF_XML)
	: do all d.ipsec.conf/*.xml files appear in ipsec.conf.5.xml?
	for x in $(D_IPSEC_CONF_XML) ; do \
		d=$$(basename $$(dirname $${x})) ; \
		b=$$(basename $${x} .xml) ; \
		f=d.ipsec.conf/$${d}/$${b}.xml ; \
		e=$${d}.$${b} ; \
		if ! grep '"'$${f}'"' ipsec.conf.5.xml > /dev/null ; then \
			echo include 'ENTITY ... "'$${f}'"' missing ; \
			exit 1 ; \
		fi ; \
		if ! grep '&'$${e}';' ipsec.conf.5.xml > /dev/null ; then \
			echo use '&'$${e}';' missing ; \
			exit 1 ; \
		fi ; \
		if ! grep "id='$${d}.$${b}'" $${x} > /dev/null ; then \
			echo anchor "id='$${d}.$${b}'" missing ; \
			exit 1 ; \
		fi ; \
	done
	touch $@

$(top_builddir)/html/ipsec.conf.5.html: $(srcdir)/d.ipsec.conf/*/*.xml

include $(top_srcdir)/mk/targets.mk
include $(top_srcdir)/mk/rules.mk
include $(top_srcdir)/mk/manpages.mk
include $(top_srcdir)/mk/install.mk
