Summary: Libreswan IPsec implementation
Name: libreswan
#Version: IPSECBASEVERSION
Version: 2.6.33rc1
# Build KLIPS kernel module?
%{!?buildklips: %{expand: %%define buildklips 0}}
%{!?buildxen: %{expand: %%define buildxen 0}}
%{!?buildefence: %{expand: %%define buildefence 0}}
%{!?development: %{expand: %%define development 0}}
# nss build
%{!?buildnss: %{expand: %%define buildnss 0}}

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
License: GPLv2, some BSD
Url: http://www.libreswan.org/
Source: libreswan-%{srcpkgver}.tar.gz
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Summary: Libreswan - An IPsec and IKE implementation
Group: System Environment/Daemons
BuildRequires: gmp-devel bison flex bind-devel redhat-rpm-config xmlto
%if %{buildnss}
BuildRequires: nss-devel >= 3.12.6-2, nspr-devel fipscheck-devel, libcap-ng-devel
Requires: nss-tools
%endif
%if %{buildefence}
BuildRequires: ElectricFence
%endif
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
#sed -i 's/-Werror/#-Werror/' lib/libdns/Makefile
#sed -i 's/-Werror/#-Werror/' lib/libisc/Makefile
#sed -i 's/-Werror/#-Werror/' lib/liblwres/Makefile

%build
%if %{buildefence}
 %define efence "-lefence"
%endif

%{__make} \
%if %{development}
   USERCOMPILE="-g %(echo %{optflags} | sed -e s/-O[0-9]*/ /) %{?efence} -fPIE -pie" \
%else
  USERCOMPILE="-g %{optflags} %{?efence} -fPIE -pie" \
%endif
  USERLINK="-g -pie %{?efence}" \
  HAVE_THREADS="true" \
%if %{buildnss}
  USE_LIBNSS="true" \
  USE_FIPSCHECK="true" \
  USE_LIBCAP_NG="true" \
%endif
  USE_DYNAMICDNS="true" \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libdir}/ipsec \
  MANTREE=%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  programs
FS=$(pwd)

%if %{buildklips}
mkdir -p BUILD.%{_target_cpu}

cd packaging/fedora
# rpm doesn't know we're compiling kernel code. optflags will give us -m64
%{__make} -C $FS MOD26BUILDDIR=$FS/BUILD.%{_target_cpu} \
    LIBRESWANSRCDIR=$FS \
    KLIPSCOMPILE="%{optflags}" \
    KERNELSRC=/lib/modules/%{kversion}/build \
%if %{buildxen}
    ARCH=xen \
%else
    ARCH=%{_arch} \
%endif
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
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan
rm -rf %{buildroot}/%{_initrddir}/setup
rm -rf %{buildroot}/etc/ipsec.d/examples
find %{buildroot}%{_mandir}  -type f | xargs chmod a-x

install -d -m 0700 %{buildroot}%{_localstatedir}/run/pluto
# used when setting --perpeerlog without --perpeerlogbase 
install -d -m 0700 %{buildroot}%{_localstatedir}/log/pluto/peer
install -d %{buildroot}%{_sbindir}

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

%clean
rm -rf ${RPM_BUILD_ROOT}

%files 
%defattr(-,root,root)
%doc BUGS CHANGES COPYING CREDITS README LICENSE
%doc OBJ.linux.*/programs/examples/*.conf
%if %{buildnss}
%doc doc/README.nss
%endif
#%doc doc/manpage.d/*
# /usr/share/doc/libreswan/*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto/peer
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%ghost %attr(0700,root,root) %dir %{_localstatedir}/run/pluto
%{_initrddir}/ipsec
%{_libdir}/ipsec
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%doc %{_mandir}/*/*

%if %{buildklips}
%files klips
%defattr (-,root,root)
/lib/modules/%{kversion}/kernel/net/ipsec
%endif

%preun
if [ $1 -eq 0 ]; then
        /sbin/service ipsec stop > /dev/null 2>&1
        /sbin/chkconfig --del ipsec
fi

%postun
if [ $1 -ge 1 ] ; then
 /sbin/service ipsec condrestart 2>&1 >/dev/null
fi

%if %{buildklips}
%postun klips
/sbin/depmod -ae %{kversion}
%post klips
/sbin/depmod -ae %{kversion}
%endif

%post 
/sbin/chkconfig --add ipsec

%changelog
