%global USE_FIPSCHECK true
%global USE_LIBCAP_NG true
%global USE_LABELED_IPSEC true
%global USE_CRL_FETCHING true
%global USE_DNSSEC true
%global USE_NM true
%global USE_LINUX_AUDIT true

%global _hardened_build 1

%global fipscheck_version 1.4.1
%global buildefence 0
%global development 0

#global prever rc1

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
# version is generated in the release script
Version: IPSECBASEVERSION
Release: %{?prever:0.}1%{?prever:.%{prever}}%{?dist}
%define hmac_suffix .%{version}-%{release}.hmac

License: GPLv2
Url: https://www.libreswan.org/
Source: https://download.libreswan.org/%{name}-%{version}%{?prever}.tar.gz
Group: System Environment/Daemons
BuildRequires: gmp-devel bison flex redhat-rpm-config pkgconfig
BuildRequires: systemd systemd-units
Requires(post): coreutils bash systemd
Requires(preun): systemd
Requires(postun): systemd

Conflicts: openswan < %{version}-%{release}
Obsoletes: openswan < %{version}-%{release}
Provides: openswan = %{version}-%{release}

BuildRequires: pkgconfig hostname
BuildRequires: nss-devel >= 3.12.6-2, nspr-devel
BuildRequires: pam-devel
%if %{USE_DNSSEC}
BuildRequires: unbound-devel
%endif
%if %{USE_FIPSCHECK}
BuildRequires: fipscheck-devel >= %{fipscheck_version}
# we need fipshmac
Requires: fipscheck%{_isa} >= %{fipscheck_version}
%endif
%if %{USE_LINUX_AUDIT}
Buildrequires: audit-libs-devel
%endif

%if %{USE_LIBCAP_NG}
BuildRequires: libcap-ng-devel
%endif
%if %{USE_CRL_FETCHING}
BuildRequires: openldap-devel curl-devel
%endif
%if %{buildefence}
BuildRequires: ElectricFence
%endif
# Only needed if xml man pages are modified and need regeneration
# BuildRequires: xmlto

Requires: nss-tools, nss-softokn
Requires: iproute >= 2.6.8

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

Libreswan also supports IKEv2 (RFC4309) and Secure Labeling

Libreswan is based on Openswan-2.6.38 which in turn is based on FreeS/WAN-2.04

%if %{USE_FIPSCHECK}
%package fips
Summary: FIPS 140-2 HMAC files and prelink blacklist configuration
Group: System Environment/Daemons
Requires: %{name}%{_isa} = %{version}-%{release}
Requires: fipscheck-lib%{_isa} >= %{fipscheck_version}
# NSS: Technically, we need to Requires: nss-softokn-fips but nss-softokn
#      already requires the -fips sub-package (to allow firefox to go into
#      fips mode on non-fips machines with no -fips packages)

%description fips
FIPS 140-2 module for Openswan that contains HMAC files and the blacklist
configuration for prelink.
%endif

 
%prep
%setup -q -n libreswan-%{version}%{?prever}

%build
%if %{buildefence}
 %define efence "-lefence"
%endif

#796683: -fno-strict-aliasing
%{__make} \
%if %{development}
   USERCOMPILE="-g -DGCC_LINT %(echo %{optflags} | sed -e s/-O[0-9]*/ /) %{?efence} -fPIE -pie -fno-strict-aliasing -Wformat-nonliteral -Wformat-security" \
%else
  USERCOMPILE="-g -DGCC_LINT %{optflags} %{?efence} -fPIE -pie -fno-strict-aliasing -Wformat-nonliteral -Wformat-security" \
%endif
  USERLINK="-g -pie -Wl,-z,relro,-z,now %{?efence}" \
  INITSYSTEM=systemd \
  USE_DYNAMICDNS="true" \
  USE_NM=%{USE_NM} \
  USE_XAUTHPAM=true \
  USE_FIPSCHECK="%{USE_FIPSCHECK}" \
  FIPSHMACSUFFIX=%{hmac_suffix} \
  USE_LIBCAP_NG="%{USE_LIBCAP_NG}" \
  USE_LABELED_IPSEC="%{USE_LABELED_IPSEC}" \
%if %{USE_CRL_FETCHING}
  USE_LDAP=true \
  USE_LIBCURL=true \
%endif
  USE_DNSSEC="%{USE_DNSSEC}" \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libexecdir}/ipsec \
  FINALLIBEXECDIR=%{_libexecdir}/ipsec \
  MANTREE=%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  programs
FS=$(pwd)

%if %{USE_FIPSCHECK}
# Add generation of HMAC checksums of the final stripped binaries
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
  fipshmac -d %{buildroot}%{_libdir}/fipscheck -s %{hmac_suffix} %{buildroot}%{_sbindir}/ipsec \
  fipshmac -d %{buildroot}%{_libdir}/fipscheck -s %{hmac_suffix} ` ls %{buildroot}%{_libexecdir}/ipsec/* ` \
%{nil}
%endif

%install
rm -rf ${RPM_BUILD_ROOT}
%{__make} \
  DESTDIR=%{buildroot} \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libexecdir}/ipsec \
  FINALLIBEXECDIR=%{_libexecdir}/ipsec \
  MANTREE=%{buildroot}%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  INSTMANFLAGS="-m 644" \
  INITSYSTEM=systemd \
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan

install -d -m 0755 %{buildroot}%{_localstatedir}/run/pluto
# used when setting --perpeerlog without --perpeerlogbase 
install -d -m 0700 %{buildroot}%{_localstatedir}/log/pluto/peer
install -d %{buildroot}%{_sbindir}
%if %{USE_FIPSCHECK}
install -d -m 0700 %{buildroot}/%{_sysconfdir}/prelink.conf.d/
install -m644 packaging/fedora/libreswan-prelink.conf %{buildroot}/%{_sysconfdir}/prelink.conf.d/libreswan-fips.conf
%endif


%if %{USE_FIPSCHECK}
mkdir -p %{buildroot}%{_libdir}/fipscheck
%endif

echo "include /etc/ipsec.d/*.secrets" > %{buildroot}%{_sysconfdir}/ipsec.secrets
rm -fr %{buildroot}/etc/rc.d/rc*

%files 
%doc BUGS CHANGES COPYING CREDITS README LICENSE
%doc docs/*.*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/pluto
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ipsec.secrets
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/cacerts
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/crls
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/policies
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto/peer
%attr(0755,root,root) %dir %{_localstatedir}/run/pluto
%attr(0644,root,root) %{_unitdir}/ipsec.service
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/pam.d/pluto
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%attr(0644,root,root) %doc %{_mandir}/*/*

%if %{USE_FIPSCHECK}
%files fips
%{_sysconfdir}/prelink.conf.d/libreswan-fips.conf
%{_libdir}/fipscheck/*.hmac

%post fips
prelink -u %{_libexecdir}/ipsec/* 2>/dev/null || :
%endif

%preun
%systemd_preun ipsec.service

%postun
%systemd_postun_with_restart ipsec.service

%post 
%systemd_post ipsec.service

%changelog
* Tue Jan 01 2013 Team Libreswan <team@libreswan.org> - IPSECBASEVERSION-1
- Automated build from release tar ball
