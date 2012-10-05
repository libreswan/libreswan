%global USE_FIPSCHECK true
%global USE_LIBCAP_NG true
%global USE_NM true
%global USE_XAUTHPAM true
%global fipscheck_version 1.3.0
%global USE_CRL_FECTCHING true
%global USE_DNSSEC true
%global buildklips 0
%global buildefence 0
%global development 0

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
# version is generated in the release script
Version: IPSECBASEVERSION

# The default kernel version to build for is the latest of
# the installed binary kernel
# This can be overridden by "--define 'kversion x.x.x-y.y.y'"
%define defkv %(rpm -q kernel kernel-smp| grep -v "not installed" | sed "s/kernel-smp-\\\(.\*\\\)$/\\1smp/"| sed "s/kernel-//"| sort | tail -1)
%{!?kversion: %{expand: %%define kversion %defkv}}
%define krelver %(echo %{kversion} | tr -s '-' '_')

# Libreswan -pre/-rc nomenclature has to co-exist with hyphen paranoia
%define srcpkgver %(echo %{version} | tr -s '_' '-')
%define ourrelease 1

Release: %{ourrelease}%{?dist}
License: GPLv2
Url: http://www.libreswan.org/
Source: %{name}-%{srcpkgver}.tar.gz
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: gmp-devel bison flex redhat-rpm-config
BuildRequires: pkgconfig
BuildRequires: nss-devel >= 3.12.6-2, nspr-devel
%if %{USE_XAUTHPAM}
BuildRequires: pam-devel
%endif
%if %{USE_DNSSEC}
BuildRequires: unbound-devel
%endif
%if %{USE_FIPSCHECK}
BuildRequires: fipscheck-devel >= %{fipscheck_version}
Requires: fipscheck%{_isa} >= %{fipscheck_version}
%endif
%if %{USE_LIBCAP_NG}
BuildRequires: libcap-ng-devel
%endif
%if %{USE_CRL_FECTCHING}
BuildRequires: openldap-devel curl-devel
Requires: curl openldap
%endif
%if %{buildefence}
BuildRequires: ElectricFence
%endif
# Only needed if xml man pages are modified and need regeneration
# BuildRequires: xmlto

Provides: ipsec-userland = %{version}-%{release}

Requires: nss-tools, nss-softokn
Requires: iproute >= 2.6.8
Requires(post): coreutils bash
Requires(preun): initscripts chkconfig
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service

%description
Libreswan is a free implementation of IPsec & IKE for Linux.  IPsec is 
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and 
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Libreswan. It optionally also builds the Libreswan KLIPS IPsec stack that
is an alternative for the NETKEY/XFRM IPsec stack that exists in the
default Linux kernel.

Libreswan 2.6.x also supports IKEv2 (RFC4309)

Libreswan is based on Openswan which in turn is based on FreeS/WAN

%if %{buildklips}
%package klips
Summary: Libreswan kernel module
Group:  System Environment/Kernel
Release: %{krelver}_%{ourrelease}
Requires: kernel = %{kversion}, %{name}-%{version}

%description klips
This package contains only the ipsec module for the RedHat/Fedora series of
kernels.
%endif

%prep
%setup -q -n libreswan-%{srcpkgver}

%build
%if %{buildefence}
 %define efence "-lefence"
%endif

#796683: -fno-strict-aliasing
%{__make} \
%if %{development}
   USERCOMPILE="-g -DGCC_LINT `pkg-config --cflags nss` %(echo %{optflags} | sed -e s/-O[0-9]*/ /) %{?efence} -fPIE -pie -fno-strict-aliasing" \
%else
  USERCOMPILE="-g -DGCC_LINT `pkg-config --cflags nss` %{optflags} %{?efence} -fPIE -pie -fno-strict-aliasing" \
%endif
  USERLINK="-g -pie %{?efence}" \
  HAVE_THREADS="true" \
  USE_FIPSCHECK="%{USE_FIPSCHECK}" \
  USE_LIBCAP_NG="%{USE_LIBCAP_NG}" \
  USE_DYNAMICDNS="true" \
  USE_DNSSEC="%{USE_DNSSEC}" \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libdir}/ipsec \
  MANTREE=%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  USE_NM=%{USE_NM} \
%if %{USE_CRL_FECTCHING}
  USE_LIBCURL=true \
%endif
%if %{USE_XAUTHPAM}
  USE_XAUTHPAM=true \
%endif
  programs
FS=$(pwd)

%if %{USE_FIPSCHECK}
# Add generation of HMAC checksums of the final stripped binaries
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
  fipshmac -d $RPM_BUILD_ROOT%{_libdir}/fipscheck $RPM_BUILD_ROOT%{_libexecdir}/ipsec/* \
  fipshmac -d $RPM_BUILD_ROOT%{_libdir}/fipscheck $RPM_BUILD_ROOT%{_sbindir}/ipsec \
%{nil}
%endif

%if %{buildklips}
mkdir -p BUILD.%{_target_cpu}

cd packaging/fedora
# rpm doesn't know we're compiling kernel code. optflags will give us -m64
%{__make} -C $FS MOD26BUILDDIR=$FS/BUILD.%{_target_cpu} \
    LIBRESWANSRCDIR=$FS \
    KLIPSCOMPILE="%{optflags}" \
    KERNELSRC=/lib/modules/%{kversion}/build \
    ARCH=%{_arch} \
    MODULE_DEF_INCLUDE=$FS/packaging/fedora/config-%{_target_cpu}.h \
    MODULE_EXTRA_INCLUDE=$FS/packaging/fedora/extra_%{krelver}.h \
    include module
%endif

%install
rm -rf ${RPM_BUILD_ROOT}
%{__make} \
  DESTDIR=%{buildroot} \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libdir}/ipsec \
  MANTREE=%{buildroot}%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  INSTMANFLAGS="-m 644" \
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan
rm -f %{buildroot}/%{_initrddir}/setup
rm -rf %{buildroot}/etc/ipsec.d/examples
#find %{buildroot}%{_mandir}  -type f | xargs chmod a-x

install -d -m 0700 %{buildroot}%{_localstatedir}/run/pluto
# used when setting --perpeerlog without --perpeerlogbase 
install -d -m 0700 %{buildroot}%{_localstatedir}/log/pluto/peer
install -d %{buildroot}%{_sbindir}

%if %{USE_FIPSCHECK}
mkdir -p $RPM_BUILD_ROOT%{_libdir}/fipscheck
%endif

%if %{buildklips}
mkdir -p %{buildroot}/lib/modules/%{kversion}/kernel/net/ipsec
for i in $FS/BUILD.%{_target_cpu}/ipsec.ko  $FS/modobj/ipsec.o
do
  if [ -f $i ]
  then
    cp $i %{buildroot}/lib/modules/%{kversion}/kernel/net/ipsec 
  fi
done
%endif

echo "include /etc/ipsec.d/*.secrets" > $RPM_BUILD_ROOT%{_sysconfdir}/ipsec.secrets
rm -fr $RPM_BUILD_ROOT/etc/rc.d/rc*

%clean
rm -rf ${RPM_BUILD_ROOT}

%files 
%defattr(-,root,root)
%doc BUGS CHANGES COPYING CREDITS README LICENSE
%doc OBJ.linux.*/programs/examples/*.conf
%doc docs/*.*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ipsec.secrets
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto/peer
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%ghost %attr(0700,root,root) %dir %{_localstatedir}/run/pluto
%{_initrddir}/ipsec
%{_libdir}/ipsec
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%attr(0644,root,root) %doc %{_mandir}/*/*

%if %{USE_FIPSCHECK}
%{_libdir}/fipscheck/*.hmac
%endif

%if %{buildklips}
%files klips
%defattr (-,root,root)
/lib/modules/%{kversion}/kernel/net/ipsec
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

%if %{buildklips}
%postun klips
/sbin/depmod -ae %{kversion}
%post klips
/sbin/depmod -ae %{kversion}
%endif

%post 
/sbin/chkconfig --add ipsec || :

%changelog
* Wed Sep 05 2012 Paul Wouters <paul@libreswan.org> - 0.9.9-1
- Merged in Avesh' spec file for fedora

