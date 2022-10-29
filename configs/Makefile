# Makefile for miscellaneous programs
# Copyright (C) 2002-2006  Michael Richardson	<mcr@xelerance.com>
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

# the man page source is generated
MANPAGES += ipsec.conf.5
MANPAGES += ipsec.secrets.5

# different mode
ipsec.secrets.INSTFLAGS = -m 0600

CONFFILES += ipsec.conf
CONFFILES += ipsec.secrets

LOGROTATEDCONFFILES += libreswan

CONFDSUBDIR = policies
CONFDSUBDIRFILES = clear clear-or-private private-or-clear private block portexcludes.conf

ifndef top_srcdir
include ../mk/dirs.mk
endif
include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/targets.mk
include $(top_srcdir)/mk/rules.mk
include $(top_srcdir)/mk/manpages.mk
include $(top_srcdir)/mk/install.mk

local-base: $(CONFFILES) $(CONFDSUBDIRFILES) $(LOGROTATEDCONFFILES)

local-clean-base:
	rm -f $(foreach file, $(CONFFILES) $(CONFDSUBDIRFILES) $(LOGROTATEDCONFFILES), $(builddir)/$(file))

# For each group of files; first copy to the examples directory and
# then, optionally, install the examples copy into /etc (but only when
# INSTALL_CONFIGS=true, and only when not already present).

local-install-base: $(CONFFILES) $(CONFDSUBDIRFILES) $(LOGROTATEDCONFFILES)
	@: CONFDDIR - EXAMPLECONFDIR not EXAMPLECONFDDIR and sample suffix
	@set -eu ; $(call install-directory, $(EXAMPLECONFDIR))
	@set -eu ; $(call install-file, $(INSTCONFFLAGS) $(ipsec.conf.INSTFLAGS),    $(builddir)/ipsec.conf,    $(DESTDIR)$(FINALEXAMPLECONFDIR)/$(notdir $(IPSEC_CONF))-sample)
	@set -eu ; $(call install-file, $(INSTCONFFLAGS) $(ipsec.secrets.INSTFLAGS), $(builddir)/ipsec.secrets, $(DESTDIR)$(FINALEXAMPLECONFDIR)/$(notdir $(IPSEC_SECRETS))-sample)
ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(CONFDDIR), 0700)
	@set -eu ; $(call install-missing-file, $(INSTCONFFLAGS) $(ipsec.conf.INSTFLAGS),    $(DESTDIR)$(EXAMPLECONFDIR)/$(notdir $(IPSEC_CONF))-sample,         $(DESTDIR)$(IPSEC_CONF))
	@set -eu ; $(call install-missing-file, $(INSTCONFFLAGS) $(ipsec.secrets.INSTFLAGS), $(DESTDIR)$(FINALEXAMPLECONFDIR)/$(notdir $(IPSEC_SECRETS))-sample, $(DESTDIR)$(IPSEC_SECRETS))
endif
	@: CONFDSUBDIR
	@set -eu ; $(call install-directory, $(EXAMPLECONFDDIR), 0700)
	@set -eu ; $(call install-directory, $(EXAMPLECONFDDIR)/$(CONFDSUBDIR), 0700)
	@set -eu ; $(foreach file, $(CONFDSUBDIRFILES), \
		$(call install-file, $(INSTCONFFLAGS), \
			$(builddir)/$(file), $(EXAMPLECONFDDIR)/$(CONFDSUBDIR)/$(file)) ; \
	)
ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(CONFDDIR)/$(CONFDSUBDIR), 0700)
	@set -eu ; $(foreach file, $(CONFDSUBDIRFILES), \
		$(call install-missing-file, $(INSTCONFFLAGS), \
			$(EXAMPLECONFDDIR)/$(CONFDSUBDIR)/$(file), $(CONFDDIR)/$(CONFDSUBDIR)/$(file)) ; \
	)
endif
	@: LOGROTATED
	@set -eu ; $(call install-directory, $(EXAMPLELOGROTATEDDIR))
	@set -eu ; $(foreach file, $(LOGROTATEDCONFFILES), \
		$(call install-file, $(INSTCONFFLAGS), \
			$(builddir)/$(file), $(EXAMPLELOGROTATEDDIR)/$(file)) ; \
	)
ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(LOGROTATEDDIR))
	@set -eu ; $(foreach file, $(LOGROTATEDCONFFILES), \
		$(call install-missing-file, $(INSTCONFFLAGS), \
			$(EXAMPLELOGROTATEDDIR)/$(file), $(LOGROTATEDDIR)/$(file)) ; \
	)
endif
	@: NSSDIR install
ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(DESTDIR)$(NSSDIR), 0700)
endif
ifeq ($(USE_AUTHPAM),true)
	@: PAM
	@set -eu ; $(call install-directory, $(EXAMPLEPAMCONFDIR))
	@set -eu ; $(call install-file, $(INSTCONFFLAGS), \
			pam.d/pluto, $(EXAMPLEPAMCONFDIR)/pluto)
 ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(PAMCONFDIR))
	@set -eu ; $(call install-missing-file, $(INSTCONFFLAGS), \
			$(EXAMPLEPAMCONFDIR)/pluto, $(PAMCONFDIR)/pluto)
 endif
endif
	@: $(SELINUX)
ifeq ($(INSTALL_CONFIGS),true)
	@if test -z "$(DESTDIR)" -a -x /usr/sbin/selinuxenabled -a $(SBINDIR) != "$(DESTDIR)/usr/sbin" ; then \
	if /usr/sbin/selinuxenabled ; then  \
		echo -e "\n************************** WARNING ***********************************" ; \
		echo "SElinux is present on this system and the prefix path is not /usr." ; \
		echo "This can cause software failures if selinux is running in Enforcing mode"; \
		echo -e "unless selinux policies are updated manually to allow this.\n" ; \
		echo "The following commands fix a common issue of /usr/local/ being mislabeled"; \
		echo "    restorecon /usr/local/sbin -Rv"; \
		echo "    restorecon /usr/local/libexec/ipsec -Rv"; \
		if test -x /usr/sbin/getenforce ; then \
			echo -e "\nSElinux is currently running in `/usr/sbin/getenforce` mode" ; \
		fi ; \
		echo -e "**********************************************************************\n" ; \
	fi \
	fi
endif

list-local-base:
	@set -eu ; $(foreach file, $(CONFFILES), \
		echo $(CONFDIR)/$(file) ; \
	)
	@set -eu ; $(foreach file, $(CONFFILES), \
		echo $(EXAMPLECONFDIR)/$(file)-sample ; \
	)
	@set -eu ; $(foreach file, $(CONFDSUBDIRFILES), \
		echo $(CONFDDIR)/$(CONFDSUBDIR)/$${file} ; \
	)

# Since man page is generated, override the default rule for
# generating $(buildir)/$(MANPAGE).tmp from $(MANPAGE).xml

xmlsources = d.ipsec.conf/order.txt

$(builddir)/ipsec.conf.5.tmp: d.ipsec.conf/*.xml $(xmlsources) | $(builddir)
	missing=$$(find d.ipsec.conf -name '*.xml' | sort - $(xmlsources) | uniq -u) ; \
	if test "$${missing}" != ""; then	\
		echo "$${missing}" ;		\
		exit 1 ;			\
	fi
	cat $(xmlsources) | xargs cat | $(TRANSFORM_VARIABLES) > $@.tmp
	mv $@.tmp $@
