%global _hardened_build 1
# These are rpm macros and are 0 or 1
%global with_efence 1
%global with_development 1
%global nss_version 3.41
%global unbound_version 1.6.6
%global with_cavstests 0
%global _exec_prefix %{_prefix}/local
%global initsystem @INITSYSTEM@
%global optflags -g
# Libreswan config options
%global libreswan_config \\\
    FINALDOCDIR=%{_pkgdocdir} \\\
    FINALEXAMPLECONFDIR=%{_pkgdocdir} \\\
    FINALINITDDIR=%{_initddir} \\\
    FINALLIBEXECDIR=%{_libexecdir}/ipsec \\\
    FINALMANDIR=%{_mandir} \\\
    FINALRUNDIR=%{_rundir}/pluto \\\
    INITSYSTEM=%{initsystem} \\\
    IPSECVERSION=%{IPSECVERSION} \\\
    PREFIX=%{_exec_prefix} \\\
    PYTHON_BINARY=%{__python3} \\\
    SHELL_BINARY=%{_prefix}/bin/sh \\\
    USE_NSS_IPSEC_PROFILE=true \\\
%{nil}

%{nil}

#global prever rc1

%global rel %{?prever:0.}1%{?prever:.%{prever}}
# for pluto --version
%global IPSECVERSION %{version}-%{rel}

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
# version is replaced in make target
Version: 3.30
Release: %{rel}%{?dist}
License: GPLv2
Url: https://libreswan.org/
Source0: https://download.libreswan.org/%{?prever:development/}%{name}-%{version}%{?prever}.tar.gz
%if 0%{with_cavstests}
Source1: https://download.libreswan.org/cavs/ikev1_dsa.fax.bz2
Source2: https://download.libreswan.org/cavs/ikev1_psk.fax.bz2
Source3: https://download.libreswan.org/cavs/ikev2.fax.bz2
%endif
BuildRequires: gcc make
BuildRequires: bison
BuildRequires: flex
BuildRequires: pkgconfig
BuildRequires: systemd-devel

Conflicts: openswan < %{version}-%{release}
Obsoletes: openswan < %{version}-%{release}
Provides: openswan = %{version}-%{release}
Provides: openswan-doc = %{version}-%{release}

BuildRequires: pkgconfig hostname
BuildRequires: nss-devel >= 3.16.1
BuildRequires: nspr-devel
BuildRequires: pam-devel
BuildRequires: libevent-devel
BuildRequires: unbound-devel >= 1.5.0-1
BuildRequires: ldns-devel
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
Buildrequires: audit-libs-devel
BuildRequires: libcap-ng-devel
BuildRequires: openldap-devel
BuildRequires: curl-devel
%if 0%{with_efence}
BuildRequires: ElectricFence
%endif
BuildRequires: xmlto

Requires: nss-tools
Requires: nss-softokn
Requires: iproute >= 2.6.8

%description
Libreswan testing RPM for debugging and testrun only, without -O2.

This package contains the daemons and userland tools for setting up Libreswan.

%prep
%setup -q -n libreswan-%{version}%{?prever}
sed -i "s:#[ ]*include \(.*\)\(/crypto-policies/back-ends/libreswan.config\)$:include \1\2:" programs/configs/ipsec.conf.in

%build
make %{?_smp_mflags} \
    OPTIMIZE_CFLAGS="%{optflags}" \
%if 0%{with_efence}
    USE_EFENCE=true \
%endif
    %{libreswan_config} \
    programs
FS=$(pwd)

# Add generation of HMAC checksums of the final stripped binaries
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
%{nil}

%install
make \
    DESTDIR=%{buildroot} \
    %{libreswan_config} \
    install
FS=$(pwd)
# Work around for FINALEXAMPLECONFDIR not working properly
rm -rf %{buildroot}%{_prefix}/share/doc

install -d -m 0700 %{buildroot}%{_rundir}/pluto
# used when setting --perpeerlog without --perpeerlogbase
install -d -m 0700 %{buildroot}%{_localstatedir}/log/pluto/peer
install -d %{buildroot}%{_sbindir}

install -d %{buildroot}%{_sysconfdir}/sysctl.d
install -m 0644 packaging/fedora/libreswan-sysctl.conf \
    %{buildroot}%{_sysconfdir}/sysctl.d/50-libreswan.conf

echo "include %{_sysconfdir}/ipsec.d/*.secrets" \
    > %{buildroot}%{_sysconfdir}/ipsec.secrets
rm -fr %{buildroot}%{_sysconfdir}/rc.d/rc*

%if 0%{with_cavstests}
%check
# There is an elaborate upstream testing infrastructure which we do not
# run here - it takes hours and uses kvm
# We only run the CAVS tests.
# cp %{SOURCE1} %{SOURCE2} %{SOURCE3} .
# bunzip2 *.fax.bz2

# work around for older xen based machines
export NSS_DISABLE_HW_GCM=1

: starting CAVS test for IKEv2
%{buildroot}%{_libexecdir}/ipsec/cavp -v2 ikev2.fax | \
    diff -u ikev2.fax - > /dev/null
: starting CAVS test for IKEv1 RSASIG
%{buildroot}%{_libexecdir}/ipsec/cavp -v1sig ikev1_dsa.fax | \
    diff -u ikev1_dsa.fax - > /dev/null
: starting CAVS test for IKEv1 PSK
%{buildroot}%{_libexecdir}/ipsec/cavp -v1psk ikev1_psk.fax | \
    diff -u ikev1_psk.fax - > /dev/null
: CAVS tests passed
%endif

%if "%{initsystem}" == "systemd"
%post
%systemd_post ipsec.service

%preun
%systemd_preun ipsec.service

%postun
%systemd_postun_with_restart ipsec.service
%endif

%files
%doc CHANGES COPYING CREDITS README* LICENSE
%doc docs/*.* docs/examples
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ipsec.secrets
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/policies
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysctl.d/50-libreswan.conf
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto/peer
%attr(0700,root,root) %dir %{_rundir}/pluto
%if "%{initsystem}" == "systemd"
%attr(0644,root,root) %{_tmpfilesdir}/libreswan.conf
%attr(0644,root,root) %{_unitdir}/ipsec.service
%endif
%if "%{initsystem}" == "docker" || "%{initsystem}" == "sysvinit"
%attr(0755,root,root) %{_initddir}/ipsec
%config(noreplace) %{_sysconfdir}/sysconfig/pluto
%endif
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/pam.d/pluto
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%{_mandir}/*/*

%changelog
* Wed Aug  9 2017 Team Libreswan <team@libreswan.org> - @IPSECBASEVERSION@
- Automated build for testing from git tree.
- All compile time options are set in Makefile.inc.local not here.
