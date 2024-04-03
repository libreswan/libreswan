# These are rpm macros and are 0 or 1
%global _hardened_build 1
%global with_efence 0
%global with_development 0
%global with_cavstests 1
# There is no new enough unbound on rhel7
%global with_dnssec 0
%global nss_version 3.79-4
# Libreswan config options
%global libreswan_config \\\
    FINALLIBEXECDIR=%{_libexecdir}/ipsec \\\
    FINALMANDIR=%{_mandir} \\\
    FINALNSSDIR=%{_sysconfdir}/ipsec.d \\\
    INITSYSTEM=systemd \\\
    PREFIX=%{_prefix} \\\
    PYTHON_BINARY=%{__python2} \\\
    SHELL_BINARY=/bin/sh \\\
    USE_AUTHPAM=true \\\
    USE_DNSSEC=%{USE_DNSSEC} \\\
    USE_FIPSCHECK=false \\\
    USE_LABELED_IPSEC=true \\\
    USE_LDAP=true \\\
    USE_LIBCAP_NG=true \\\
    USE_LIBCURL=true \\\
    USE_NM=true \\\
    USE_NSS_IPSEC_PROFILE=true \\\
    USE_NSS_KDF=true \\\
    USE_SECCOMP=true \\\
    USE_XFRM_INTERFACE_IFLA_HEADER=true \\\
%{nil}

#global prever rc1

Name: libreswan
Summary: Internet Key Exchange (IKEv1 and IKEv2) implementation for IPsec
Version: 4.14
Release: %{?prever:0.}1%{?prever:.%{prever}}%{?dist}
License: GPLv2
Url: https://libreswan.org/
Source0: https://download.libreswan.org/%{?prever:development/}%{name}-%{version}%{?prever}.tar.gz
%if 0%{with_cavstests}
Source10: https://download.libreswan.org/cavs/ikev1_dsa.fax.bz2
Source11: https://download.libreswan.org/cavs/ikev1_psk.fax.bz2
Source12: https://download.libreswan.org/cavs/ikev2.fax.bz2
%endif

BuildRequires: gcc make
BuildRequires: audit-libs-devel
BuildRequires: bison
BuildRequires: curl-devel
BuildRequires: flex
BuildRequires: hostname
BuildRequires: libcap-ng-devel
BuildRequires: libevent-devel
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
BuildRequires: nspr-devel
BuildRequires: nss-devel >= %{nss_version}
BuildRequires: nss-tools
BuildRequires: openldap-devel
BuildRequires: pam-devel
BuildRequires: pkgconfig
BuildRequires: redhat-rpm-config
BuildRequires: systemd
BuildRequires: xmlto
%if 0%{with_efence}
BuildRequires: ElectricFence
%endif
%if 0%{with_dnssec}
BuildRequires: ldns-devel
BuildRequires: unbound-devel >= 1.6.0
Requires: unbound-libs >= 1.6.0
%global USE_DNSSEC true
%else
%global USE_DNSSEC false
%endif
Requires: coreutils
Requires: iproute
Requires: logrotate
Requires: nss >= %{nss_version}
Requires: nss-softokn
Requires: nss-tools
%{?systemd_requires}

Conflicts: openswan < %{version}-%{release}
Obsoletes: openswan < %{version}-%{release}
Provides: openswan = %{version}-%{release}
Provides: openswan-doc = %{version}-%{release}



%description
Libreswan is a free implementation of IPsec & IKE for Linux.  IPsec is
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
    WERROR_CFLAGS="-Werror -Wno-error=address -Wno-missing-braces -Wno-missing-field-initializers" \
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

echo "include /etc/ipsec.d/*.secrets" \
    > %{buildroot}%{_sysconfdir}/ipsec.secrets


%if 0%{with_cavstests}
%check
# There is an elaborate upstream testing infrastructure which we do not
# run here.
# We only run the CAVS tests here.
cp %{SOURCE10} %{SOURCE11} %{SOURCE12} .
bunzip2 *.fax.bz2

# work around for older xen based machines
export NSS_DISABLE_HW_GCM=1

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

# Some of these tests will show ERROR for negative testing - it will exit on real errors
%{buildroot}%{_libexecdir}/ipsec/algparse -tp || { echo prooposal test failed; exit 1; }
%{buildroot}%{_libexecdir}/ipsec/algparse -ta || { echo algorithm test failed; exit 1; }
: Algorithm parser tests passed

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
%license LICENSE COPYING
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
%doc %{_mandir}/*/*

%changelog
* Mon Mar 11 2024 Team Libreswan <team@libreswan.org> - 4.14-1
- Automated build from release tar ball
