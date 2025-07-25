%global _hardened_build 1
# These are rpm macros and are 0 or 1
%global with_efence 0
%global with_development 0
%global with_cavstests 1
# minimum version for support for rhbz#1651314
%global nss_version 3.44.0-8
%global unbound_version 1.6.6
# Libreswan config options. With these settings, libreswan
# does not require its own FIPS validation. Only the system
# and NSS needs to be FIPS validated.
%global libreswan_config \\\
    LIBEXECDIR=%{_libexecdir}/ipsec \\\
    MANDIR=%{_mandir} \\\
    NSSDIR=%{_sysconfdir}/ipsec.d \\\
    INITSYSTEM=systemd \\\
    NSS_HAS_IPSEC_PROFILE=true \\\
    PREFIX=%{_prefix} \\\
    SHELL_BINARY=%{_bindir}/sh \\\
    USE_AUTHPAM=true \\\
    USE_DNSSEC=true \\\
    USE_LABELED_IPSEC=true \\\
    USE_LDAP=true \\\
    USE_LIBCAP_NG=true \\\
    USE_LIBCURL=true \\\
    USE_LINUX_AUDIT=true \\\
    USE_NSS_KDF=true \\\
    USE_SECCOMP=true \\\
%{nil}

#global prever rc2

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
# version is generated in the release script
Version: 5.3
Release: %{?prever:0.}1%{?prever:.%{prever}}%{?dist}
License: GPL-2.0-or-later
Url: https://libreswan.org/
Source0: https://download.libreswan.org/%{?prever:with_development/}%{name}-%{version}%{?prever}.tar.gz
%if 0%{with_cavstests}
Source1: https://download.libreswan.org/cavs/ikev1_dsa.fax.bz2
Source2: https://download.libreswan.org/cavs/ikev1_psk.fax.bz2
Source3: https://download.libreswan.org/cavs/ikev2.fax.bz2
%endif
BuildRequires: audit-libs-devel
BuildRequires: bison
BuildRequires: curl-devel
BuildRequires: flex
BuildRequires: gcc
BuildRequires: hostname
BuildRequires: ldns-devel
BuildRequires: libcap-ng-devel
BuildRequires: libevent-devel
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
BuildRequires: make
BuildRequires: nspr-devel
BuildRequires: nss-devel >= %{nss_version}
BuildRequires: nss-tools
BuildRequires: openldap-devel
BuildRequires: pam-devel
BuildRequires: pkgconfig
BuildRequires: redhat-rpm-config
BuildRequires: systemd-rpm-macros
BuildRequires: unbound-devel >= %{unbound_version}
BuildRequires: xmlto
%if 0%{with_efence}
BuildRequires: ElectricFence
%endif
Requires: coreutils
Requires: iproute >= 2.6.8
Requires: nss >= %{nss_version}
Requires: nss-softokn
Requires: nss-tools
Requires: procps-ng
Requires: unbound-libs >= %{unbound_version}
Suggests: logrotate
%{?systemd_requires}

%description
Libreswan is a free implementation of IKE/IPsec for Linux.  IPsec is
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Libreswan.

Libreswan also supports IKEv2 (RFC7296) and Secure Labeling

Libreswan is based on Openswan-2.6.38 which in turn is based on FreeS/WAN-2.04

%prep
%setup -q -n libreswan-%{version}%{?prever}

# enable crypto-policies support
sed -i "s:#[ ]*include \(.*\)\(/crypto-policies/back-ends/libreswan.config\)$:include \1\2:" configs/ipsec.conf.in


%build
make %{?_smp_mflags} \
%if 0%{with_development}
    OPTIMIZE_CFLAGS="%{?_hardened_cflags}" \
%else
    OPTIMIZE_CFLAGS="%{optflags}" \
%endif
%if 0%{with_efence}
    USE_EFENCE=true \
%endif
    USERLINK="%{?__global_ldflags}" \
    %{libreswan_config} \
    programs
FS=$(pwd)

%install
make \
  DESTDIR=%{buildroot} \
  %{libreswan_config} \
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan
rm -rf %{buildroot}%{_libexecdir}/ipsec/*check

install -d -m 0755 %{buildroot}%{_rundir}/pluto
install -d %{buildroot}%{_sbindir}

install -d %{buildroot}%{_sysctldir}
install -m 0644 packaging/rhel/libreswan-sysctl.conf \
  %{buildroot}%{_sysctldir}/50-libreswan.conf

echo "include %{_sysconfdir}/ipsec.d/*.secrets" \
     > %{buildroot}%{_sysconfdir}/ipsec.secrets
rm -fr %{buildroot}%{_sysconfdir}/rc.d/rc*

%if 0%{with_cavstests}
%check
# There is an elaborate upstream testing infrastructure which we do not
# run here - it takes hours and uses kvm
# We only run the CAVS tests.
cp %{SOURCE1} %{SOURCE2} %{SOURCE3} .
bunzip2 *.fax.bz2

: starting CAVS test for IKEv2
%{buildroot}%{_libexecdir}/ipsec/cavp -v2 ikev2.fax | \
    diff -u ikev2.fax - > /dev/null
: starting CAVS test for IKEv1 RSASIG
%{buildroot}%{_libexecdir}/ipsec/cavp -v1dsa ikev1_dsa.fax | \
    diff -u ikev1_dsa.fax - > /dev/null
: starting CAVS test for IKEv1 PSK
%{buildroot}%{_libexecdir}/ipsec/cavp -v1psk ikev1_psk.fax | \
    diff -u ikev1_psk.fax - > /dev/null
: CAVS tests passed

%{buildroot}%{_libexecdir}/ipsec/algparse -tp || { echo prooposal test failed; exit 1; }
%{buildroot}%{_libexecdir}/ipsec/algparse -ta || { echo algorithm test failed; exit 1; }

# self test for pluto daemon - this also shows which algorithms it allows in FIPS mode
tmpdir=$(mktemp -d /tmp/libreswan-XXXXX)
certutil -N -d sql:$tmpdir --empty-password
%{buildroot}%{_libexecdir}/ipsec/pluto --selftest --nssdir $tmpdir --rundir $tmpdir
: pluto self-test passed - verify FIPS algorithms allowed is still compliant with NIST

%endif

%post
%systemd_post ipsec.service
%sysctl_apply 50-libreswan.conf

%preun
%systemd_preun ipsec.service

%postun
%systemd_postun_with_restart ipsec.service

%files
%license COPYING LICENSE
%doc CHANGES CREDITS README*
%doc docs/*.* docs/examples
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ipsec.secrets
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/policies
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%attr(0644,root,root) %config(noreplace) %{_sysctldir}/50-libreswan.conf
%attr(0755,root,root) %dir %{_rundir}/pluto
%attr(0644,root,root) %{_tmpfilesdir}/libreswan.conf
%attr(0644,root,root) %{_unitdir}/ipsec.service
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/pam.d/pluto
%config(noreplace) %{_sysconfdir}/logrotate.d/libreswan
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%attr(0644,root,root) %doc %{_mandir}/*/*

%changelog
* Thu Jul  3 2025 Team Libreswan <team@libreswan.org> - 5.3-1
- Automated build from release tar ball
