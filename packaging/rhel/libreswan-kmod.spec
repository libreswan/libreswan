# Define the kmod package name here.
%define kmod_name libreswan

# If kversion isn't defined on the rpmbuild line, define it here.
%{!?kversion: %define kversion 2.6.32-358.0.1.el6.%{_target_cpu}}

Name:    %{kmod_name}-kmod
Version: IPSECBASEVERSION
Release: 1%{?dist}
Group:   System Environment/Kernel
License: GPLv2
Summary: %{kmod_name} kernel module(s)
URL:     http://www.kernel.org/

BuildRequires: redhat-rpm-config
ExclusiveArch: i686 x86_64

# Sources.
Source0:  %{kmod_name}-%{version}.tar.gz
Source10: kmodtool-%{kmod_name}-el6.sh

# Magic hidden here.
%{expand:%(sh %{SOURCE10} rpmtemplate %{kmod_name} %{kversion} "")}

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
KSRC=%{_usrsrc}/kernels/%{kversion}
#%{__make} -C "${KSRC}" %{?_smp_mflags} modules M=$PWD
%{__make} %{?_smp_mflags} module #M=$PWD

%install
export INSTALL_MOD_PATH=%{buildroot}
export INSTALL_MOD_DIR=extra/%{kmod_name}
#KSRC=%{_usrsrc}/kernels/%{kversion}
#%{__make} -C "${KSRC}" modules_install M=$PWD
%{__make} OSMOD_DESTDIR=${INSTALL_MOD_DIR} module_install #M=$PWD
%{__install} -d %{buildroot}%{_sysconfdir}/depmod.d/
%{__install} kmod-%{kmod_name}.conf %{buildroot}%{_sysconfdir}/depmod.d/
%{__install} -d %{buildroot}%{_defaultdocdir}/kmod-%{kmod_name}-%{version}/
%{__install} LICENSE %{buildroot}%{_defaultdocdir}/kmod-%{kmod_name}-%{version}/
# Set the module(s) to be executable, so that they will be stripped when packaged.
find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;
# Remove the unrequired files.
%{__rm} -f %{buildroot}/lib/modules/%{kversion}/modules.*

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
