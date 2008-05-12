# norootforbuild
# usedforbuild    aaa_base acl attr audit-libs autoconf automake bash binutils bzip2 coreutils cpio cpp cpp42 cracklib curl-ca-bundle cvs diffutils file filesystem fillup findutils fltk fontconfig fontconfig-devel freetype2 freetype2-devel gawk gcc gcc42 gdbm gettext gettext-devel glibc glibc-devel glibc-locale gmp gmp-devel grep groff gzip htmldoc info insserv less libacl libattr libbz2-1 libbz2-devel libcurl-devel libcurl4 libdb-4_5 libexpat-devel libexpat1 libgcc42 libgomp42 libidn libidn-devel libjpeg libjpeg-devel libltdl-3 libmudflap42 libopenssl-devel libopenssl0_9_8 libpcap libpcap-devel libpng libreadline5 libstdc++42 libtool libuuid1 libvolume_id libxcrypt libzio linux-kernel-headers lynx m4 make man mktemp ncurses net-tools netcfg openssl-certs pam pam-modules patch perl perl-base permissions pkg-config popt rpm sed sysvinit tar texinfo timezone util-linux xli xorg-x11-devel xorg-x11-fonts-devel xorg-x11-libICE xorg-x11-libICE-devel xorg-x11-libSM xorg-x11-libSM-devel xorg-x11-libX11 xorg-x11-libX11-devel xorg-x11-libXau xorg-x11-libXau-devel xorg-x11-libXdmcp xorg-x11-libXdmcp-devel xorg-x11-libXext xorg-x11-libXext-devel xorg-x11-libXfixes xorg-x11-libXfixes-devel xorg-x11-libXmu xorg-x11-libXmu-devel xorg-x11-libXp xorg-x11-libXp-devel xorg-x11-libXpm xorg-x11-libXpm-devel xorg-x11-libXprintUtil xorg-x11-libXprintUtil-devel xorg-x11-libXrender xorg-x11-libXrender-devel xorg-x11-libXt xorg-x11-libXt-devel xorg-x11-libXv xorg-x11-libXv-devel xorg-x11-libfontenc xorg-x11-libfontenc-devel xorg-x11-libs xorg-x11-libxcb xorg-x11-libxcb-devel xorg-x11-libxkbfile xorg-x11-libxkbfile-devel xorg-x11-proto-devel xorg-x11-util-devel xorg-x11-xtrans-devel zlib zlib-devel


Summary: Openswan IPSEC implementation
Name: openswan
Version: 2.5.50s
# Build KLIPS kernel module?
%{!?buildklips: %{expand: %%define buildklips 0}}
%{!?buildxen: %{expand: %%define buildxen 0}}

# The default kernel version to build for is the latest of
# the installed binary kernel
# This can be overridden by "--define 'kversion x.x.x-y.y.y'"
%define defkv %(rpm -q kernel kernel-smp| grep -v "not installed" | sed "s/kernel-smp-\\\(.\*\\\)$/\\1smp/"| sed "s/kernel-//"| sort | tail -1)
%{!?kversion: %{expand: %%define kversion %defkv}}
%define krelver %(echo %{kversion} | tr -s '-' '_')

# Openswan -pre/-rc nomenclature has to co-exist with hyphen paranoia
%define srcpkgver %(echo %{version} | tr -s '_' '-')
%define ourrelease 1
Release: %{ourrelease}
License: GPLv2
Url: http://www.openswan.org/
Source: openswan-%{srcpkgver}.tar.gz
Group: Productivity/Networking/Security
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Summary: Openswan - An IPsec and IKE implementation
Provides: pluto klips ipsec VPN freeswan
Obsoletes: freeswan
PreReq: gmp %insserv_prereq %fillup_prereq perl
BuildRequires: gmp-devel bison flex bind-devel 
Requires: iproute2 >= 2.6.8
AutoReqProv:    on
Source10:       openswan.README.SUSE

Source31:       sysconfig.network.scripts.openswan
Source32:       sysconfig.network.scripts.openswan-functions
Source33:       openswan.ip-up
Prefix:         /usr

%description
Openswan is a free implementation of IPSEC & IKE for Linux.  IPSEC is 
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and 
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Openswan on a freeswan enabled kernel. It optionally also builds the
Openswan KLIPS IPsec stack that is an alternative for the NETKEY/XFRM
IPsec stack that exists in the default Linux kernel.

%if %{buildklips}
%package klips
Summary: Openswan kernel module
Group:  System Environment/Kernel
Release: %{krelver}_%{ourrelease}
Requires: kernel = %{kversion}, %{name}-%{version}
%endif

%if %{buildklips}
%description klips
This package contains only the ipsec module for the RedHat/Fedora series of
kernels.
%endif

%prep
%setup -q -n openswan-%{srcpkgver}
sed -i 's/-Werror/#-Werror/' lib/libdns/Makefile
sed -i 's/-Werror/#-Werror/' lib/libisc/Makefile
sed -i 's/-Werror/#-Werror/' lib/liblwres/Makefile

%build
%{__make} \
  USERCOMPILE='-g $(RPM_OPT_FLAGS) ' \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libdir}/ipsec \
  FINALBINDIR=%{_libexecdir}/ipsec \
  MANTREE=%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  INC_RCDIRS='/etc/init.d /etc/rc.d/init.d /etc/rc.d /sbin/init.d' \
  INC_DOCDIR=share/doc/packages \
  programs
FS=$(pwd)
%if %{buildklips}
mkdir -p BUILD.%{_target_cpu}

cd packaging/suse
# rpm doesn't know we're compiling kernel code. optflags will give us -m64
%{__make} -C $FS MOD26BUILDDIR=$FS/BUILD.%{_target_cpu} \
    OPENSWANSRCDIR=$FS \
    KLIPSCOMPILE="%{optflags}" \
    KERNELSRC=/lib/modules/%{kversion}/build \
%if %{buildxen}
    ARCH=xen \
%else
    ARCH=%{_arch} \
%endif
    MODULE_DEF_INCLUDE=$FS/packaging/redhat/config-%{_target_cpu}.h \
    MODULE_EXTRA_INCLUDE=$FS/packaging/redhat/extra_%{krelver}.h \
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
rm -rf %{buildroot}/usr/share/doc/openswan
#this needs to be fixed in 'make install'
rm -rf %{buildroot}/etc/rc.d/rc?.d/*ipsec
rm -rf %{buildroot}/%{_initrddir}/setup
rm -rf %{buildroot}/etc/ipsec.d/examples
find %{buildroot}%{_mandir}  -type f | xargs chmod a-x
install -d -m 0700 %{buildroot}%{_localstatedir}/run/pluto
install -d %{buildroot}%{_sbindir}
#suse specific
ln -sf /etc/init.d/ipsec ${RPM_BUILD_ROOT}%{prefix}/sbin/rcipsec
touch $RPM_BUILD_ROOT/etc/ipsec.secrets
install -d -m 755 %{buildroot}/etc/sysconfig/network/{scripts,if-up.d,if-down.d}
install -m 755 packaging/suse/sysconfig.network.scripts.openswan %{buildroot}/etc/sysconfig/network/scripts/freeswan
install -m 644 packaging/suse/sysconfig.network.scripts.openswan-functions %{buildroot}/etc/sysconfig/network/scripts/freeswan-functions
ln -s ../scripts/freeswan %{buildroot}/etc/sysconfig/network/if-up.d/freeswan
ln -s ../scripts/freeswan %{buildroot}/etc/sysconfig/network/if-down.d/freeswan
# ip-up script (#39048)
install -d -m 755 %{buildroot}/etc/ppp/ip-{up,down}.d
install -m 755 packaging/suse/openswan.ip-up %{buildroot}/etc/ppp/ip-up.d/freeswan
ln -s ../ip-up.d/freeswan %{buildroot}/etc/ppp/ip-down.d/freeswan
rm -f %{buildroot}/etc/rc?.d/[KS]*ipsec

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
#%doc doc/manpage.d/*
# /usr/share/doc/openswan/*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%{_localstatedir}/run/pluto
%{_initrddir}/ipsec
%{_libdir}/ipsec
%{_sbindir}/rcipsec
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%doc %{_mandir}/*/*
%config /etc/init.d/ipsec
/etc/sysconfig/network/scripts/*
/etc/sysconfig/network/if-up.d/freeswan
/etc/sysconfig/network/if-down.d/freeswan
/etc/ppp/ip-up.d/freeswan
/etc/ppp/ip-down.d/freeswan
%dir %attr(700,root,root) /etc/ipsec.d/private

%if %{buildklips}
%files klips
%defattr (-,root,root)
/lib/modules/%{kversion}/kernel/net/ipsec
%endif

%preun
%{stop_on_removal ipsec}
# Some people expect to not loose their secrets even after multiple rpm -e.
if test -s etc/ipsec.secrets.rpmsave; then
  cp -p --backup=numbered etc/ipsec.secrets.rpmsave etc/ipsec.secrets.rpmsave.old
fi
exit 0

%postun
%{restart_on_update ipsec}
%{insserv_cleanup}

%if %{buildklips}
%postun klips
/sbin/depmod -ae %{kversion}
%post klips
/sbin/depmod -ae %{kversion}
%endif

%post 
%{fillup_and_insserv ipsec}
# don't create host keys on install - might be no entropy!
# openswan automatically does it on 'start' if no ipsec.secrets is found

%changelog
* Fri Apr 18 2008 Paul Wouters <paul@xelerance.com> - 2.5.sony-1
- Incororated Suse initscripts and some SPEC semantics from mt@suse.de

* Thu Dec 20 2007 Paul Wouters <paul@xelerance.com> - 2.6.01-1
- Work around for warnings in BIND related code
- Remove bogus file /etc/init.d/setup at install
- Cleaned up spec file

* Mon Oct 10 2005 Paul Wouters <paul@xelerance.com>
- Updated for klips on xen 
- added ldconfig for post klips to obtain ipsec module dependancies
- Run 'make include' since on FC4 kernel source does not have the links yet.

* Wed Jan  5 2005 Paul Wouters <paul@xelerance.com>
- Updated for x86_64 and klips on 2.6

* Sun Sep  5 2004 Paul Wouters <paul@xelerance.com>
- Updated for openswan

* Fri Aug 22 2003 Sam Sgro <sam@freeswan.org>
- Juggling release/source package names to allow for 
  -pre/-rc releases to build.

* Thu Aug 14 2003 Sam Sgro <sam@freeswan.org>
- Reverting back to pre-x.509 version, cosmetic changes.

* Tue May 20 2003 Charlie Brady <charlieb@e-smith.com> 2.0.0-x509_1.3.2_2es
- Add "Obsoletes: freeswan" to userland RPM.

* Fri May 16 2003 Charlie Brady <charlieb@e-smith.com> 2.0.0-x509_1.3.2_1es
- Add version 1.3.2 of the x509 patch.
- Add missing /usr/libexec/ipsec dir and files.
- Minor tidy up of spec file.

* Thu May 15 2003 Charlie Brady <charlieb@e-smith.com> 2.0.0-1es
- Based on work by Paul Lahaie of Steamballoon, Michael
  Richardson of freeS/WAN team and Tuomo Soini <tis@foobar.fi>.
- Build freeswan RPMs from a single source RPM, for RedHat, but
  should work on any RPM based system.
