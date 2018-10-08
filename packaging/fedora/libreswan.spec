%global _hardened_build 1
# These are rpm macros and are 0 or 1
%global with_efence 0
%global with_development 0
%global with_cavstests 1
# Libreswan config options
%global libreswan_config \\\
    FINALLIBEXECDIR=%{_libexecdir}/ipsec \\\
    FINALMANDIR=%{_mandir} \\\
    FIPSPRODUCTCHECK=%{_sysconfdir}/system-fips \\\
    INC_RCDEFAULT=%{_initrddir} \\\
    INC_USRLOCAL=%{_prefix} \\\
    INITSYSTEM=systemd \\\
    NSS_REQ_AVA_COPY=false \\\
    USE_DNSSEC=true \\\
    USE_FIPSCHECK=true \\\
    USE_LABELED_IPSEC=true \\\
    USE_LDAP=true \\\
    USE_LIBCAP_NG=true \\\
    USE_LIBCURL=true \\\
    USE_LINUX_AUDIT=true \\\
    USE_NM=true \\\
    USE_SECCOMP=true \\\
    USE_XAUTHPAM=true \\\
%{nil}

#global prever rc1

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
# version is generated in the release script
Version: 3.27
Release: %{?prever:0.}1%{?prever:.%{prever}}%{?dist}
License: GPLv2
Url: https://libreswan.org/
Source0: https://download.libreswan.org/%{?prever:development/}%{name}-%{version}%{?prever}.tar.gz
%if 0%{with_cavstests}
Source1: https://download.libreswan.org/cavs/ikev1_dsa.fax.bz2
Source2: https://download.libreswan.org/cavs/ikev1_psk.fax.bz2
Source3: https://download.libreswan.org/cavs/ikev2.fax.bz2
%endif
Requires(post): bash coreutils systemd
Requires(preun): systemd
Requires(postun): systemd

Conflicts: openswan < %{version}-%{release}
Obsoletes: openswan < %{version}-%{release}
Provides: openswan = %{version}-%{release}
Provides: openswan-doc = %{version}-%{release}

BuildRequires: pkgconfig hostname
BuildRequires: bison flex
BuildRequires: systemd-devel
BuildRequires: nss-devel >= 3.16.1
BuildRequires: nspr-devel
BuildRequires: pam-devel
BuildRequires: libevent-devel
BuildRequires: unbound-devel >= 1.6.0-6
BuildRequires: ldns-devel
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
BuildRequires: fipscheck-devel
Requires: fipscheck%{_isa}
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
Requires: unbound-libs >= 1.6.6

%description
Libreswan is a free implementation of IPsec & IKE for Linux.  IPsec is
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Libreswan. To build KLIPS, see the kmod-libreswan.spec file.

Libreswan also supports IKEv2 (RFC7296) and Secure Labeling

Libreswan is based on Openswan-2.6.38 which in turn is based on FreeS/WAN-2.04

%prep
%setup -q -n libreswan-%{version}%{?prever}
# Fedora should really figure this versioning out itself, not burden upstream
sed -i "s:/usr/bin/python:/usr/bin/python3:" programs/verify/verify.in
sed -i "s:/usr/bin/python:/usr/bin/python3:" programs/show/show.in
sed -i "s:/usr/bin/python:/usr/bin/python3:" testing/cert_verify/usage_test
sed -i "s:/usr/bin/python:/usr/bin/python3:" testing/pluto/ikev1-01-fuzzer/cve-2015-3204.py
sed -i "s:/usr/bin/python:/usr/bin/python3:" testing/pluto/ikev2-15-fuzzer/send_bad_packets.py
sed -i "s:/usr/bin/python:/usr/bin/python3:" testing/x509/dist_certs.py
# enable crypto-policies support
sed -i "s:#[ ]*include \(.*\)\(/crypto-policies/back-ends/libreswan.config\)$:include \1\2:" programs/configs/ipsec.conf.in

%build
%if 0%{with_efence}
%global efence "-lefence"
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
    fipshmac -d %{buildroot}%{_libdir}/fipscheck %{buildroot}%{_libexecdir}/ipsec/pluto \
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
install -m 0644 packaging/fedora/libreswan-sysctl.conf \
    %{buildroot}%{_sysconfdir}/sysctl.d/50-libreswan.conf

install -d %{buildroot}%{_tmpfilesdir}
install -m 0644 packaging/fedora/libreswan-tmpfiles.conf  \
    %{buildroot}%{_tmpfilesdir}/libreswan.conf

mkdir -p %{buildroot}%{_libdir}/fipscheck

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

%changelog
* Sun Oct 07 2018 Team Libreswan <team@libreswan.org> - 3.27-1
- Automated build from release tar ball
