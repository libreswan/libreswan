# Define the kmod package name here.
%define kmod_name libreswan

# If kversion isn't defined on the rpmbuild line, define it here.
%{!?kversion: %define kversion 3.0.68-3.ocf.nopl-%{_target_cpu}}

#% define with_ocf 1
%if %{with_ocf}
%define ocf _ocf
%endif

Name:    %{kmod_name}-kmod
Version: IPSECBASEVERSION
Release: 1%{?dist}%{ocf}
Group:   System Environment/Kernel
License: GPLv2
Summary: %{kmod_name} kernel module
URL:     https://libreswan.org/

# so spec can be used on rhel5 and newer
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: redhat-rpm-config
ExclusiveArch: i686 x86_64

# Sources.
Source0:  %{kmod_name}-%{version}.tar.gz

# Magic hidden here.
%{expand:%(sh /usr/lib/rpm/redhat/kmodtool rpmtemplate %{kmod_name} %{kversion} "")}

# Disable the building of the debug package(s).
%define debug_package %{nil}

%description
This package provides the %{kmod_name} kernel module(s).
It is built to depend upon the specific ABI provided by a range of releases
of the same variant of the Linux kernel and not on any one specific build.

%prep
%setup -q -n %{kmod_name}-%{version}
echo "override %{kmod_name} * weak-updates/%{kmod_name}" > kmod-%{kmod_name}.conf

%build
%if %{with_ocf}
%{__make} KERNELSRC=%{_usrsrc}/kernels/%{kversion} %{?_smp_mflags} MODULE_DEF_INCLUDE=`pwd`/packaging/ocf/config-all.h MODULE_DEFCONFIG=`pwd`/packaging/ocf/defconfig module
%else
%{__make} KERNELSRC=%{_usrsrc}/kernels/%{kversion} %{?_smp_mflags} module
%endif


%install
rm -rf %{buildroot}
export INSTALL_MOD_PATH=%{buildroot}
export INSTALL_MOD_DIR=/lib/modules/%{kversion}/extra/%{kmod_name}

%{__install} -d %{buildroot}/$INSTALL_MOD_DIR
%{__install} modobj/ipsec.ko %{buildroot}/$INSTALL_MOD_DIR

%{__install} -d %{buildroot}%{_sysconfdir}/depmod.d/
%{__install} kmod-%{kmod_name}.conf %{buildroot}%{_sysconfdir}/depmod.d/
%{__install} -d %{buildroot}%{_defaultdocdir}/kmod-%{kmod_name}-%{version}/
%{__install} LICENSE %{buildroot}%{_defaultdocdir}/kmod-%{kmod_name}-%{version}/
# Set the module(s) to be executable, so that they will be stripped when packaged.
find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;
# Remove the unrequired files.
%{__rm} -f %{buildroot}/lib/modules/%{kversion}/modules.*

%files
/lib/modules/%{kversion}/extra/%{kmod_name}/ipsec.ko
%{_sysconfdir}/depmod.d/kmod-%{kmod_name}.conf
%{_defaultdocdir}/kmod-%{kmod_name}-%{version}/LICENSE

%clean
%{__rm} -rf %{buildroot}

%changelog
* Mon Mar 11 2013 Paul Wouters <pwouters@redhat.com> - IPSECBASEVERSION
- Customized for libreswan KLIPS kernel module

* Fri Jan 28 2011 Alan Bartlett <ajb@elrepo.org> - 0.5-6
- Updated the spec file to the current ELRepo Project standards.

* Sat Dec 04 2010 Alan Bartlett <ajb@elrepo.org> - 0.5-5
- Updated the packageing to the current ELRepo Project standards.

* Mon Nov 15 2010 Alan Bartlett <ajb@elrepo.org> - 0.5-4
- Adjusted the kmodtool file.

* Sun Nov 14 2010 Alan Bartlett <ajb@elrepo.org> - 0.5-3
- Adjust & verify both the kmodtool file and this spec file.

* Sun Nov 14 2010 Philip J Perry <phil@elrepo.org> - 0.5-2
- Bump release to test updates

* Sat Nov 13 2010 Philip J Perry <phil@elrepo.org> - 0.5-1
- Update for RHEL6 GA release.

* Thu Apr 29 2010 Philip J Perry <phil@elrepo.org> - 0.5-0.1
- Update to latest release.
- Update kmodtool and SPEC file.

* Thu Apr 29 2010 Philip J Perry <phil@elrepo.org> - 0.0-0.1
- Initial el6 build of the kmod package.
