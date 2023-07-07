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

LOGROTATEDFILE += libreswan

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

local-base: $(CONFFILES) $(CONFDSUBDIRFILES) $(LOGROTATEDFILE)

local-clean-base:
	rm -f $(foreach file, $(CONFFILES) $(CONFDSUBDIRFILES) $(LOGROTATEDFILE), $(builddir)/$(file))

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
		echo $(DESTDIR)$(SYSCONFDIR)/$(file) ; \
	)
	@set -eu ; $(foreach file, $(CONFFILES), \
		echo $(DESTDIR)$(EXAMPLE_IPSEC_SYSCONFDIR)/$(file)-sample ; \
	)
	@set -eu ; $(foreach file, $(CONFDSUBDIRFILES), \
		echo $(DESTDIR)$(IPSEC_CONFDDIR)/$(CONFDSUBDIR)/$${file} ; \
	)

XMLSOURCES += d.ipsec.conf/head.xml
XMLSOURCES += d.ipsec.conf/connsections.xml
XMLSOURCES += d.ipsec.conf/exampleleftright.xml
XMLSOURCES += d.ipsec.conf/conngeneral.xml
XMLSOURCES += d.ipsec.conf/keyexchange.xml
XMLSOURCES += d.ipsec.conf/hostaddrfamily.xml
XMLSOURCES += d.ipsec.conf/clientaddrfamily.xml
XMLSOURCES += d.ipsec.conf/type.xml
XMLSOURCES += d.ipsec.conf/left.xml
XMLSOURCES += d.ipsec.conf/leftsubnet.xml
XMLSOURCES += d.ipsec.conf/leftsubnets.xml
XMLSOURCES += d.ipsec.conf/leftvti.xml
XMLSOURCES += d.ipsec.conf/leftaddresspool.xml
XMLSOURCES += d.ipsec.conf/leftprotoport.xml
XMLSOURCES += d.ipsec.conf/leftnexthop.xml
XMLSOURCES += d.ipsec.conf/leftsourceip.xml
XMLSOURCES += d.ipsec.conf/leftupdown.xml
XMLSOURCES += d.ipsec.conf/leftcat.xml
XMLSOURCES += d.ipsec.conf/leftfirewall.xml
XMLSOURCES += d.ipsec.conf/conngeneralend.xml
XMLSOURCES += d.ipsec.conf/connauto.xml
XMLSOURCES += d.ipsec.conf/auto.xml
XMLSOURCES += d.ipsec.conf/authby.xml
XMLSOURCES += d.ipsec.conf/ike.xml
XMLSOURCES += d.ipsec.conf/phase2.xml
XMLSOURCES += d.ipsec.conf/phase2alg.xml
XMLSOURCES += d.ipsec.conf/sha2-truncbug.xml
XMLSOURCES += d.ipsec.conf/ms-dh-downgrade.xml
XMLSOURCES += d.ipsec.conf/dns-match-id.xml
XMLSOURCES += d.ipsec.conf/require-id-on-certificate.xml
XMLSOURCES += d.ipsec.conf/ppk.xml
XMLSOURCES += d.ipsec.conf/ppk-ids.xml
XMLSOURCES += d.ipsec.conf/nat-ikev1-method.xml
XMLSOURCES += d.ipsec.conf/esp.xml
XMLSOURCES += d.ipsec.conf/ah.xml
XMLSOURCES += d.ipsec.conf/fragmentation.xml
XMLSOURCES += d.ipsec.conf/ikepad.xml
XMLSOURCES += d.ipsec.conf/ikev2.xml
XMLSOURCES += d.ipsec.conf/mobike.xml
XMLSOURCES += d.ipsec.conf/intermediate.xml
XMLSOURCES += d.ipsec.conf/esn.xml
XMLSOURCES += d.ipsec.conf/decap-dscp.xml
XMLSOURCES += d.ipsec.conf/nopmtudisc.xml
XMLSOURCES += d.ipsec.conf/narrowing.xml
XMLSOURCES += d.ipsec.conf/sareftrack.xml
XMLSOURCES += d.ipsec.conf/nic-offload.xml
XMLSOURCES += d.ipsec.conf/leftid.xml
XMLSOURCES += d.ipsec.conf/leftrsasigkey.xml
XMLSOURCES += d.ipsec.conf/leftcert.xml
XMLSOURCES += d.ipsec.conf/leftckaid.xml
XMLSOURCES += d.ipsec.conf/leftauth.xml
XMLSOURCES += d.ipsec.conf/leftautheap.xml
XMLSOURCES += d.ipsec.conf/leftca.xml
XMLSOURCES += d.ipsec.conf/leftikeport.xml
XMLSOURCES += d.ipsec.conf/leftsendcert.xml
XMLSOURCES += d.ipsec.conf/leftxauthserver.xml
XMLSOURCES += d.ipsec.conf/leftxauthclient.xml
XMLSOURCES += d.ipsec.conf/leftusername.xml
XMLSOURCES += d.ipsec.conf/leftmodecfgserver.xml
XMLSOURCES += d.ipsec.conf/leftmodecfgclient.xml
XMLSOURCES += d.ipsec.conf/xauthby.xml
XMLSOURCES += d.ipsec.conf/xauthfail.xml
XMLSOURCES += d.ipsec.conf/pam-authorize.xml
XMLSOURCES += d.ipsec.conf/modecfgpull.xml
XMLSOURCES += d.ipsec.conf/modecfgoptions.xml
XMLSOURCES += d.ipsec.conf/remote-peer-type.xml
XMLSOURCES += d.ipsec.conf/nm-configured.xml
XMLSOURCES += d.ipsec.conf/encapsulation.xml
XMLSOURCES += d.ipsec.conf/enable-tcp.xml
XMLSOURCES += d.ipsec.conf/tcp-remoteport.xml
XMLSOURCES += d.ipsec.conf/nat-keepalive.xml
XMLSOURCES += d.ipsec.conf/initial-contact.xml
XMLSOURCES += d.ipsec.conf/cisco-unity.xml
XMLSOURCES += d.ipsec.conf/ignore-peer-dns.xml
XMLSOURCES += d.ipsec.conf/redirect.xml
XMLSOURCES += d.ipsec.conf/fake-strongswan.xml
XMLSOURCES += d.ipsec.conf/send-vendorid.xml
XMLSOURCES += d.ipsec.conf/overlapip.xml
XMLSOURCES += d.ipsec.conf/reqid.xml
XMLSOURCES += d.ipsec.conf/dpddelay.xml
XMLSOURCES += d.ipsec.conf/ikev1-dpdtimeout.xml
XMLSOURCES += d.ipsec.conf/pfs.xml
XMLSOURCES += d.ipsec.conf/pfsgroup.xml
XMLSOURCES += d.ipsec.conf/aggressive.xml
XMLSOURCES += d.ipsec.conf/salifetime.xml
XMLSOURCES += d.ipsec.conf/ipsec-max-bytes.xml
XMLSOURCES += d.ipsec.conf/ipsec-max-packets.xml
XMLSOURCES += d.ipsec.conf/replay-window.xml
XMLSOURCES += d.ipsec.conf/rekey.xml
XMLSOURCES += d.ipsec.conf/rekeymargin.xml
XMLSOURCES += d.ipsec.conf/rekeyfuzz.xml
XMLSOURCES += d.ipsec.conf/ikelifetime.xml
XMLSOURCES += d.ipsec.conf/retransmit-timeout.xml
XMLSOURCES += d.ipsec.conf/retransmit-interval.xml
XMLSOURCES += d.ipsec.conf/compress.xml
XMLSOURCES += d.ipsec.conf/metric.xml
XMLSOURCES += d.ipsec.conf/mtu.xml
XMLSOURCES += d.ipsec.conf/tfc.xml
XMLSOURCES += d.ipsec.conf/nflog.xml
XMLSOURCES += d.ipsec.conf/mark.xml
XMLSOURCES += d.ipsec.conf/vti.xml
XMLSOURCES += d.ipsec.conf/ipsec-interface.xml
XMLSOURCES += d.ipsec.conf/priority.xml
XMLSOURCES += d.ipsec.conf/sendca.xml
XMLSOURCES += d.ipsec.conf/labeled-ipsec.xml
XMLSOURCES += d.ipsec.conf/policy-label.xml
XMLSOURCES += d.ipsec.conf/failureshunt.xml
XMLSOURCES += d.ipsec.conf/negotiationshunt.xml
XMLSOURCES += d.ipsec.conf/connautoend.xml
XMLSOURCES += d.ipsec.conf/configsections.xml
XMLSOURCES += d.ipsec.conf/protostack.xml
XMLSOURCES += d.ipsec.conf/listen.xml
XMLSOURCES += d.ipsec.conf/ike-socket.xml
XMLSOURCES += d.ipsec.conf/listen-udp.xml
XMLSOURCES += d.ipsec.conf/listen-tcp.xml
XMLSOURCES += d.ipsec.conf/nflog-all.xml
XMLSOURCES += d.ipsec.conf/keep-alive.xml
XMLSOURCES += d.ipsec.conf/virtual-private.xml
XMLSOURCES += d.ipsec.conf/myvendorid.xml
XMLSOURCES += d.ipsec.conf/nhelpers.xml
XMLSOURCES += d.ipsec.conf/seedbits.xml
XMLSOURCES += d.ipsec.conf/ikev1-secctx-attr-type.xml
XMLSOURCES += d.ipsec.conf/ikev1-policy.xml
XMLSOURCES += d.ipsec.conf/crlcheckinterval.xml
XMLSOURCES += d.ipsec.conf/crl-strict.xml
XMLSOURCES += d.ipsec.conf/curl-iface.xml
XMLSOURCES += d.ipsec.conf/curl-timeout.xml
XMLSOURCES += d.ipsec.conf/ocsp-global.xml
XMLSOURCES += d.ipsec.conf/syslog.xml
XMLSOURCES += d.ipsec.conf/plutodebug.xml
XMLSOURCES += d.ipsec.conf/uniqueids.xml
XMLSOURCES += d.ipsec.conf/logfile.xml
XMLSOURCES += d.ipsec.conf/logappend.xml
XMLSOURCES += d.ipsec.conf/logip.xml
XMLSOURCES += d.ipsec.conf/audit-log.xml
XMLSOURCES += d.ipsec.conf/logtime.xml
XMLSOURCES += d.ipsec.conf/ddos-mode.xml
XMLSOURCES += d.ipsec.conf/ddos-ike-threshold.xml
XMLSOURCES += d.ipsec.conf/global-redirect.xml
XMLSOURCES += d.ipsec.conf/max-halfopen-ike.xml
XMLSOURCES += d.ipsec.conf/shuntlifetime.xml
XMLSOURCES += d.ipsec.conf/xfrmlifetime.xml
XMLSOURCES += d.ipsec.conf/dumpdir.xml
XMLSOURCES += d.ipsec.conf/statsbin.xml
XMLSOURCES += d.ipsec.conf/ipsecdir.xml
XMLSOURCES += d.ipsec.conf/nssdir.xml
XMLSOURCES += d.ipsec.conf/secretsfile.xml
XMLSOURCES += d.ipsec.conf/seccomp.xml
XMLSOURCES += d.ipsec.conf/dnssec.xml
XMLSOURCES += d.ipsec.conf/configsectionsend.xml
XMLSOURCES += d.ipsec.conf/oe_conns.xml
XMLSOURCES += d.ipsec.conf/tail.xml

# Since man page is generated, override the default rule for
# generating $(buildir)/$(MANPAGE).tmp from $(MANPAGE).xml

$(builddir)/ipsec.conf.5.tmp: $(XMLSOURCES) | $(builddir)
	missing="$(filter-out $(XMLSOURCES), $(wildcard d.ipsec.conf/*.xml))" ; \
	if test "$${missing}" ; then \
		echo "$${missing}" ;		\
		exit 1 ;			\
	fi
	cat $(XMLSOURCES) | $(TRANSFORM_VARIABLES) > $@.tmp
	mv $@.tmp $@
