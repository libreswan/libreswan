%global USE_FIPSCHECK true
%global USE_LIBCAP_NG true
%global USE_LABELED_IPSEC true
%global USE_CRL_FETCHING true
%global USE_DNSSEC true
%global USE_NM true
%global USE_LINUX_AUDIT true

%global fipscheck_version 1.2.0-7
%global buildefence 0
%global development 0
%global cavstests 1

#global prever rc1

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
Version: 3.18
Release: %{?prever:0.}1%{?prever:.%{prever}}%{?dist}
License: GPLv2
Url: https://libreswan.org/
Source0: https://download.libreswan.org/%{?prever:development/}%{name}-%{version}%{?prever}.tar.gz
%if %{cavstests}
Source10: https://download.libreswan.org/cavs/ikev1_dsa.fax.bz2
Source11: https://download.libreswan.org/cavs/ikev1_psk.fax.bz2
Source12: https://download.libreswan.org/cavs/ikev2.fax.bz2
%endif
Group: System Environment/Daemons
BuildRequires: bison flex redhat-rpm-config pkgconfig
Requires(post): coreutils bash
Requires(preun): initscripts chkconfig
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service

Conflicts: openswan < %{version}-%{release}
Obsoletes: openswan < %{version}-%{release}
Provides: openswan = %{version}-%{release}
Provides: openswan-doc = %{version}-%{release}

BuildRequires: pkgconfig net-tools
BuildRequires: nss-devel >= 3.16.1, nspr-devel
BuildRequires: pam-devel
BuildRequires: libevent2-devel
%if %{USE_DNSSEC}
BuildRequires: unbound-devel
%endif
%if %{USE_LABELED_IPSEC}
BuildRequires: libselinux-devel
%endif
%if %{USE_FIPSCHECK}
# we need fipshmac
BuildRequires: fipscheck-devel >= %{fipscheck_version}
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
BuildRequires: xmlto

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

%prep
%setup -q -n libreswan-%{version}%{?prever}

%build
%if %{buildefence}
%global efence "-lefence"
%endif

#796683: -fno-strict-aliasing
make %{?_smp_mflags} \
%if %{development}
    USERCOMPILE="-g -DGCC_LINT %(echo %{optflags} | sed -e s/-O[0-9]*/ /) %{?efence} -fPIE -pie -fno-strict-aliasing -Wformat-nonliteral -Wformat-security" \
%else
    USERCOMPILE="-g -DGCC_LINT %{optflags} %{?efence} -fPIE -pie -fno-strict-aliasing -Wformat-nonliteral -Wformat-security" \
    WERROR_CFLAGS= \
%endif
    INITSYSTEM=sysvinit \
    USERLINK="-g -pie -Wl,-z,relro,-z,now %{?efence}" \
    USE_NM=%{USE_NM} \
    USE_XAUTHPAM=true \
    USE_FIPSCHECK=%{USE_FIPSCHECK} \
    FIPSPRODUCTCHECK="%{_sysconfdir}/system-fips" \
    USE_LIBCAP_NG=%{USE_LIBCAP_NG} \
    USE_LABELED_IPSEC=%{USE_LABELED_IPSEC} \
    USE_LDAP=%{USE_CRL_FETCHING} \
    USE_LIBCURL=%{USE_CRL_FETCHING} \
    USE_DNSSEC=%{USE_DNSSEC} \
    INC_USRLOCAL=%{_prefix} \
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
    fipshmac %{buildroot}%{_libexecdir}/ipsec/pluto \
%{nil}
%endif

%install
make \
    DESTDIR=%{buildroot} \
    INITSYSTEM=sysvinit \
    INC_USRLOCAL=%{_prefix} \
    FINALLIBEXECDIR=%{_libexecdir}/ipsec \
    MANTREE=%{buildroot}%{_mandir} \
    INC_RCDEFAULT=%{_initrddir} \
    INSTMANFLAGS="-m 644" \
    install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan

install -d -m 0700 %{buildroot}%{_localstatedir}/run/pluto
# used when setting --perpeerlog without --perpeerlogbase
install -d -m 0700 %{buildroot}%{_localstatedir}/log/pluto/peer
install -d %{buildroot}%{_sbindir}
# replace with rhel[56] specific version
install -m 0755 initsystems/sysvinit/init.rhel %{buildroot}%{_initrddir}/ipsec

echo "include %{_sysconfdir}/ipsec.d/*.secrets" > %{buildroot}%{_sysconfdir}/ipsec.secrets
rm -fr %{buildroot}%{_sysconfdir}/rc.d/rc*

%if %{USE_FIPSCHECK}
install -d %{buildroot}%{_sysconfdir}/prelink.conf.d/
install -m644 packaging/fedora/libreswan-prelink.conf %{buildroot}%{_sysconfdir}/prelink.conf.d/libreswan-fips.conf
%endif

%if %{cavstests}
# cavs testing
cp -a OBJ.linux.*/programs/pluto/cavp %{buildroot}%{_libexecdir}/ipsec

%endif

%if %{cavstests}
%check
# There is an elaborate upstream testing infrastructure which we do not
# run here.
# We only run the CAVS tests here.
cp %{SOURCE10} %{SOURCE11} %{SOURCE12} .
bunzip2 *.fax.bz2

# work around for older xen based machines
export NSS_DISABLE_HW_GCM=1

: starting CAVS test for IKEv2
OBJ.linux.*/programs/pluto/cavp -v2 ikev2.fax | \
    diff -u ikev2.fax - > /dev/null
: starting CAVS test for IKEv1 RSASIG
OBJ.linux.*/programs/pluto/cavp -v1sig ikev1_dsa.fax | \
    diff -u ikev1_dsa.fax - > /dev/null
: starting CAVS test for IKEv1 PSK
OBJ.linux.*/programs/pluto/cavp -v1psk ikev1_psk.fax | \
    diff -u ikev1_psk.fax - > /dev/null
: CAVS tests passed
%endif

%post
/sbin/chkconfig --add ipsec || :
%if %{USE_FIPSCHECK}
prelink -u %{_libexecdir}/ipsec/* 2>/dev/null || :
%endif

%preun
if [ $1 -eq 0 ]; then
    /sbin/service ipsec stop > /dev/null 2>&1 || :
    /sbin/chkconfig --del ipsec
fi

%postun
if [ $1 -ge 1 ] ; then
     /sbin/service ipsec condrestart 2>&1 >/dev/null || :
fi

%files
%doc CHANGES COPYING CREDITS README* LICENSE
%doc docs/*.* docs/examples
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ipsec.secrets
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/pluto
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/v6neighbor-hole.conf
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/policies
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto/peer
%attr(0700,root,root) %dir %{_localstatedir}/run/pluto
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/pam.d/pluto
%{_sbindir}/ipsec
%attr(0755,root,root) %dir %{_libexecdir}/ipsec
%{_libexecdir}/ipsec/*
%attr(0644,root,root) %{_mandir}/*/*.gz
%{_initrddir}/ipsec

%if %{USE_FIPSCHECK}
%{_libexecdir}/ipsec/.pluto.hmac

# We own the directory so we don't have to require prelink
%attr(0755,root,root) %dir %{_sysconfdir}/prelink.conf.d/
%{_sysconfdir}/prelink.conf.d/libreswan-fips.conf
%endif

%changelog
* Wed Jul 27 2016 Team Libreswan <team@libreswan.org> - 3.18-1
- Automated build from release tar ball
