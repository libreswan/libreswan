# These are rpm macros and are 0 or 1
%global _hardened_build 1
%global with_efence 0
%global with_development 0
%global with_cavstests 1
# There is no new enough unbound on rhel7
%global with_dnssec 0
# Libreswan config options
%global libreswan_config \\\
    FINALLIBEXECDIR=%{_libexecdir}/ipsec \\\
    FINALMANDIR=%{_mandir} \\\
    INC_RCDEFAULT=%{_initrddir} \\\
    INC_USRLOCAL=%{_prefix} \\\
    INITSYSTEM=systemd \\\
    USE_DNSSEC=%{USE_DNSSEC} \\\
    USE_FIPSCHECK=true \\\
    USE_LABELED_IPSEC=true \\\
    USE_LDAP=true \\\
    USE_LIBCAP_NG=true \\\
    USE_LIBCURL=true \\\
    USE_NM=true \\\
    USE_SECCOMP=true \\\
    USE_XAUTHPAM=true \\\
%{nil}
#global prever rc1

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
Version: 3.27
Release: %{?prever:0.}1%{?prever:.%{prever}}%{?dist}
License: GPLv2
Url: https://libreswan.org/
Source0: https://download.libreswan.org/%{?prever:development/}%{name}-%{version}%{?prever}.tar.gz
%if 0%{with_cavstests}
Source10: https://download.libreswan.org/cavs/ikev1_dsa.fax.bz2
Source11: https://download.libreswan.org/cavs/ikev1_psk.fax.bz2
Source12: https://download.libreswan.org/cavs/ikev2.fax.bz2
%endif
BuildRequires: bison flex redhat-rpm-config pkgconfig
BuildRequires: systemd
Requires(post): coreutils bash systemd
Requires(preun): systemd
Requires(postun): systemd
Requires: iproute

Conflicts: openswan < %{version}-%{release}
Obsoletes: openswan < %{version}-%{release}
Provides: openswan = %{version}-%{release}
Provides: openswan-doc = %{version}-%{release}

BuildRequires: pkgconfig hostname
BuildRequires: nss-devel >= 3.16.2
BuildRequires: nspr-devel
BuildRequires: pam-devel
BuildRequires: libevent-devel
%if 0%{with_dnssec}
BuildRequires: ldns-devel
BuildRequires: unbound-devel >= 1.6.0
Requires: unbound-libs >= 1.6.0
%global USE_DNSSEC true
%else
%global USE_DNSSEC false
%endif
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
BuildRequires: fipscheck-devel
Requires: fipscheck%{_isa}
Buildrequires: audit-libs-devel
BuildRequires: systemd-devel
BuildRequires: libcap-ng-devel
BuildRequires: curl-devel
BuildRequires: openldap-devel
%if 0%{with_efence}
BuildRequires: ElectricFence
%endif
BuildRequires: xmlto

Requires: nss-tools
Requires: nss-softokn

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
%if 0%{with_efence}
%define efence "-lefence"
%endif

#796683: -fno-strict-aliasing
make %{?_smp_mflags} \
%if 0%{with_development}
    USERCOMPILE="-g -DGCC_LINT %(echo %{optflags} | sed -e s/-O[0-9]*/ /) %{?efence} -fPIE -pie -fno-strict-aliasing -Wformat-nonliteral -Wformat-security" \
%else
    USERCOMPILE="-g -DGCC_LINT %{optflags} %{?efence} -fPIE -pie -fno-strict-aliasing -Wformat-nonliteral -Wformat-security" \
%endif
    USERLINK="-g -pie -Wl,-z,relro,-z,now %{?efence}" \
    %{libreswan_config} \
    programs
FS=$(pwd)

# Add generation of HMAC checksums of the final stripped binaries
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    fipshmac -d %{buildroot}%{_libdir}/fipscheck %{buildroot}%{_libexecdir}/ipsec/pluto
%{nil}

%install
make \
    DESTDIR=%{buildroot} \
    %{libreswan_config} \
    install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan

install -d -m 0755 %{buildroot}%{_rundir}/pluto
# used when setting --perpeerlog without --perpeerlogbase
install -d -m 0700 %{buildroot}%{_localstatedir}/log/pluto/peer
install -d %{buildroot}%{_sbindir}

install -d %{buildroot}%{_sysconfdir}/sysctl.d
install -m 0644 packaging/rhel/libreswan-sysctl.conf \
    %{buildroot}%{_sysconfdir}/sysctl.d/50-libreswan.conf

install -d %{buildroot}%{_tmpfilesdir}
install -m 0644 packaging/rhel/libreswan-tmpfiles.conf  \
    %{buildroot}%{_tmpfilesdir}/libreswan.conf

mkdir -p %{buildroot}%{_libdir}/fipscheck
install -d %{buildroot}%{_sysconfdir}/prelink.conf.d/
install -m644 packaging/rhel/libreswan-prelink.conf \
    %{buildroot}%{_sysconfdir}/prelink.conf.d/libreswan-fips.conf

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
%endif

%post
%systemd_post ipsec.service
prelink -u %{_libexecdir}/ipsec/* 2>/dev/null || :

%preun
%systemd_preun ipsec.service

%postun
%systemd_postun_with_restart ipsec.service

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
%attr(0755,root,root) %dir %{_rundir}/pluto
%attr(0644,root,root) %{_tmpfilesdir}/libreswan.conf
%attr(0644,root,root) %{_unitdir}/ipsec.service
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/pam.d/pluto
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%doc %{_mandir}/*/*
%{_libdir}/fipscheck/pluto.hmac
# We own the directory so we don't have to require prelink
%dir %{_sysconfdir}/prelink.conf.d/
%{_sysconfdir}/prelink.conf.d/libreswan-fips.conf

%changelog
* Sun Oct 07 2018 Team Libreswan <team@libreswan.org> - 3.27-1
- Automated build from release tar ball
