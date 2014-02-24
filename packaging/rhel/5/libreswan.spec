%define USE_FIPSCHECK true
%define USE_LABELED_IPSEC true
%define USE_CRL_FETCHING true
%define USE_DNSSEC true
%define USE_NM true
%define USE_LINUX_AUDIT true
# Eanble for OCF, requires <crypto/cryptodev.h> See ocf-linux.sourceforge.net
%define USE_OCF 0
# Not available for RHEL5
%define USE_LIBCAP_NG 0

%define fipscheck_version 1.2.0-1
%define buildefence 0
%define development 0

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
# version is generated in the release script
Version: IPSECBASEVERSION

# The default kernel version to build for is the latest of
# the installed binary kernel
# This can be overridden by "--define 'kversion x.x.x-y.y.y'"
%define defkv %(rpm -q kernel kernel-lt kernel-debug| grep -v "not installed" | sed -e "s/kernel-debug-//" -e  "s/kernel-//" -e "s/\.[^.]*$//"  | sort | tail -1 )
%{!?kversion: %{expand: %%define kversion %defkv}}
%define krelver %(echo %{kversion} | tr -s '-' '_')
# Libreswan -pre/-rc nomenclature has to co-exist with hyphen paranoia
%define srcpkgver %(echo %{version} | tr -s '_' '-')

Release: 1%{?dist}
License: GPLv2
Url: https://www.libreswan.org/
Source: %{name}-%{srcpkgver}.tar.gz
Group: System Environment/Daemons
BuildRequires: gmp-devel bison flex redhat-rpm-config pkgconfig
Requires(post): coreutils bash
Requires(preun): initscripts chkconfig
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: pkgconfig net-tools
BuildRequires: nss-devel >= 3.12.6-2, nspr-devel
BuildRequires: pam-devel
%if %{USE_DNSSEC}
BuildRequires: unbound-devel
%endif
%if %{USE_FIPSCHECK}
BuildRequires: fipscheck-devel >= %{fipscheck_version}
# we need fipshmac
Requires: fipscheck >= %{fipscheck_version}
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

Requires: nss-tools
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
%setup -q -n libreswan-%{srcpkgver}

%build
%if %{buildefence}
 %define efence "-lefence"
%endif

#796683: -fno-strict-aliasing
%{__make} \
%if %{development}
   USERCOMPILE="-g -DGCC_LINT %(echo %{optflags} | sed -e s/-O[0-9]*/ /) %{?efence} -fPIE -pie -fno-strict-aliasing" \
%else
  USERCOMPILE="-g -DGCC_LINT %{optflags} %{?efence} -fPIE -pie -fno-strict-aliasing" \
%endif
  INITSYSTEM=sysvinit \
  USERLINK="-g -pie %{?efence}" \
  USE_NM=%{USE_NM} \
  USE_XAUTHPAM=true \
  USE_FIPSCHECK=%{USE_FIPSCHECK} \
  USE_LIBCAP_NG=%{USE_LIBCAP_NG} \
%if %{USE_OCF}
  USE_OCF=true \
%endif
  USE_LABELED_IPSEC=%{USE_LABELED_IPSEC} \
  USE_LDAP=%{USE_CRL_FETCHING} \
  USE_LIBCURL=%{USE_CRL_FETCHING} \
  USE_DNSSEC=%{USE_DNSSEC} \
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
  fipshmac %{buildroot}%{_sbindir}/ipsec \
  fipshmac %{buildroot}%{_libexecdir}/ipsec/* \
%{nil}
%endif

%install
rm -rf %{buildroot}
%{__make} \
  DESTDIR=%{buildroot} \
  INITSYSTEM=sysvinit \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libexecdir}/ipsec \
  FINALLIBEXECDIR=%{_libexecdir}/ipsec \
  MANTREE=%{buildroot}%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  INSTMANFLAGS="-m 644" \
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan

install -d -m 0755 %{buildroot}%{_localstatedir}/run/pluto
# used when setting --perpeerlog without --perpeerlogbase 
install -d -m 0700 %{buildroot}%{_localstatedir}/log/pluto/peer
install -d %{buildroot}%{_sbindir}

echo "include /etc/ipsec.d/*.secrets" > %{buildroot}%{_sysconfdir}/ipsec.secrets
rm -fr %{buildroot}/etc/rc.d/rc*

%files 
%doc CHANGES COPYING CREDITS README* LICENSE
%doc docs/*.* docs/examples
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ipsec.secrets
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/pluto
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/cacerts
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/crls
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/policies
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto/peer
%attr(0755,root,root) %dir %{_localstatedir}/run/pluto
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/pam.d/pluto
%{_initrddir}/ipsec
%{_libexecdir}/ipsec
%{_sbindir}/ipsec
%attr(0644,root,root) %{_mandir}/*/*.gz

%if %{USE_FIPSCHECK}
%{_sbindir}/.ipsec.hmac
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

%post 
/sbin/chkconfig --add ipsec || :
if [ ! -f %{_sysconfdir}/ipsec.d/cert8.db ] ; then
    TEMPFILE=$(/bin/mktemp %{_sysconfdir}/ipsec.d/nsspw.XXXXXXX)
    [ $? -gt 0 ] && TEMPFILE=%{_sysconfdir}/ipsec.d/nsspw.$$
    echo > ${TEMPFILE}
    certutil -N -f ${TEMPFILE} -d %{_sysconfdir}/ipsec.d
    restorecon %{_sysconfdir}/ipsec.d/*db 2>/dev/null || :
    rm -f ${TEMPFILE}
fi

%changelog
* Tue Jan 01 2013 Team Libreswan <team@libreswan.org> - 3.1-1
- Automated build from release tar ball

