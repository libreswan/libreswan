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
	@if test ! -d $(CONFDDIR) ; then \
		mkdir -p $(CONFDDIR) ; \
		chmod 0700 $(CONFDDIR) ; \
	fi
	@if test ! -d $(CONFDDIR)/$(CONFDSUBDIR) ; then \
		mkdir -p $(CONFDDIR)/$(CONFDSUBDIR) ; \
		chmod 0700 $(CONFDDIR)/$(CONFDSUBDIR) ; \
	fi
	@set -eu ; $(foreach file, $(CONFFILES), \
		src=$(builddir)/$(file) ; \
		dst=$(CONFDIR)/$(file) ; \
		if [ ! -f $${dst} ]; then \
			echo $${src} '->' $${dst} ; \
			mkdir -p $(CONFDIR) ; \
			$(INSTALL) $(INSTCONFFLAGS) $($(file).INSTFLAGS) $${src} $${dst} ; \
		fi ; \
	)
	@set -eu ; $(foreach file, $(CONFFILES), \
		src=$(builddir)/$(file) ; \
		dst=$(EXAMPLECONFDIR)/$(file)-sample ; \
		echo $${src} '->' $${dst} ; \
		mkdir -p $(EXAMPLECONFDIR) ; \
		$(INSTALL) $(INSTCONFFLAGS) $${src} $${dst} ; \
	)
	@set -eu ; $(foreach file, $(CONFDSUBDIRFILES), \
		src=$(builddir)/$(file) ; \
		dst=$(CONFDDIR)/$(CONFDSUBDIR)/$(file) ; \
		if [ ! -f $${dst} ]; then \
			echo $${src} '->' $${dst} ; \
			$(INSTALL) $(INSTCONFFLAGS) $${src} $${dst} ; \
		fi ; \
	)
	@: LOGROTATED
	@set -eu ; $(call install-directory, $(EXAMPLELOGROTATEDDIR))
	@set -eu ; $(foreach file, $(LOGROTATEDCONFFILES), \
		$(call install-file, $(builddir)/$(file), $(EXAMPLELOGROTATEDDIR)/$(file)) ; \
	)
ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(LOGROTATEDDIR))
	@set -eu ; $(foreach file, $(LOGROTATEDCONFFILES), \
		$(call install-missing-file, $(EXAMPLELOGROTATEDDIR)/$(file), $(LOGROTATEDDIR)/$(file)) ; \
	)
endif
	@if test ! -d $(NSSDIR) ; then \
		mkdir -p $(NSSDIR) ; \
		chmod 0700 $(NSSDIR) ; \
	fi
ifeq ($(USE_AUTHPAM),true)
	@: PAM
	@set -eu ; $(call install-directory, $(EXAMPLEPAMCONFDIR))
	@set -eu ; $(call install-file, pam.d/pluto, $(EXAMPLEPAMCONFDIR)/pluto)
 ifeq ($(INSTALL_CONFIGS),true)
	@set -eu ; $(call install-directory, $(PAMCONFDIR))
	@set -eu ; $(call install-missing-file, $(EXAMPLEPAMCONFDIR)/pluto, $(PAMCONFDIR)/pluto)
 endif
endif
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
