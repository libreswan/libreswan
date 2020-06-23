%global _hardened_build 1
# These are rpm macros and are 0 or 1
%global with_efence 0
%global with_development 0
%global with_cavstests 1
# minimum version for support for rhbz#1651314
%global nss_version 3.39.0-1.4
%global unbound_version 1.6.6
# Libreswan config options
%global libreswan_config \\\
    FINALLIBEXECDIR=%{_libexecdir}/ipsec \\\
    FINALMANDIR=%{_mandir} \\\
    FIPSPRODUCTCHECK=%{_sysconfdir}/system-fips \\\
    PREFIX=%{_prefix} \\\
    INITSYSTEM=systemd \\\
    NSS_REQ_AVA_COPY=false \\\
    NSS_HAS_IPSEC_PROFILE=true \\\
    PYTHON_BINARY=%{__python3} \\\
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
    USE_NSS_KDF=true \\\
%{nil}

#global prever rc1

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
# version is generated in the release script
Version: IPSECBASEVERSION
Release: %{?prever:0.}1%{?prever:.%{prever}}%{?dist}
License: GPLv2
Url: https://libreswan.org/
Source0: https://download.libreswan.org/%{?prever:with_development/}%{name}-%{version}%{?prever}.tar.gz
%if 0%{with_cavstests}
Source1: https://download.libreswan.org/cavs/ikev1_dsa.fax.bz2
Source2: https://download.libreswan.org/cavs/ikev1_psk.fax.bz2
Source3: https://download.libreswan.org/cavs/ikev2.fax.bz2
%endif
BuildRequires: audit-libs-devel
BuildRequires: bison
BuildRequires: curl-devel
BuildRequires: fipscheck-devel
BuildRequires: flex
BuildRequires: gcc make
BuildRequires: ldns-devel
BuildRequires: libcap-ng-devel
BuildRequires: libevent-devel
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
BuildRequires: nspr-devel
BuildRequires: nss-devel >= %{nss_version}
BuildRequires: nss-tools
BuildRequires: openldap-devel
BuildRequires: pam-devel
BuildRequires: pkgconfig
BuildRequires: hostname
BuildRequires: redhat-rpm-config
BuildRequires: systemd-devel
BuildRequires: unbound-devel >= %{unbound_version}
BuildRequires: xmlto
%if 0%{with_efence}
BuildRequires: ElectricFence
%endif
Requires: fipscheck%{_isa}
Requires: iproute >= 2.6.8
Requires: nss >= %{nss_version}
Requires: nss-softokn
Requires: nss-tools
Requires: unbound-libs >= %{unbound_version}
Requires(post): bash
Requires(post): coreutils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Libreswan is a free implementation of IKE/IPsec for Linux.  IPsec is
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

# replace unsupported KLIPS README
echo "KLIPS is not supported with RHEL8" > README.KLIPS

# linking to freebl is not needed
sed -i "s/-lfreebl //" mk/config.mk

# enable crypto-policies support
sed -i "s:#[ ]*include \(.*\)\(/crypto-policies/back-ends/libreswan.config\)$:include \1\2:" programs/configs/ipsec.conf.in


%build
make %{?_smp_mflags} \
%if 0%{with_development}
    OPTIMIZE_CFLAGS="%{?_hardened_cflags}" \
%else
    OPTIMIZE_CFLAGS="%{optflags}" \
%endif
%if 0%{with_efence}
    USE_EFENCE=true \
%endif
    WERROR_CFLAGS="-Werror -Wno-missing-field-initializers" \
    USERLINK="%{?__global_ldflags}" \
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
rm -rf %{buildroot}%{_libexecdir}/ipsec/*check

install -d -m 0755 %{buildroot}%{_rundir}/pluto
# used when setting --perpeerlog without --perpeerlogbase
install -d -m 0700 %{buildroot}%{_localstatedir}/log/pluto/peer
install -d %{buildroot}%{_sbindir}

install -d %{buildroot}%{_sysconfdir}/sysctl.d
install -m 0644 packaging/fedora/libreswan-sysctl.conf \
  %{buildroot}%{_sysconfdir}/sysctl.d/50-libreswan.conf

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

%{buildroot}%{_libexecdir}/ipsec/algparse -tp || { echo prooposal test failed; exit 1; }
%{buildroot}%{_libexecdir}/ipsec/algparse -ta || { echo algorithm test failed; exit 1; }

# self test for pluto daemon - this also shows which algorithms it allows in FIPS mode
tmpdir=$(mktemp -d /tmp/libreswan-XXXXX)
certutil -N -d sql:$tmpdir --empty-password
%{buildroot}%{_libexecdir}/ipsec/pluto --selftest --nssdir $tmpdir --rundir $tmpdir
: pluto self-test passed - verify FIPS algorithms allowed is still compliant with NIST

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
%attr(0644,root,root) %doc %{_mandir}/*/*
%{_libdir}/fipscheck/pluto.hmac

%changelog
* Sun Oct  7 2018 Team Libreswan <team@libreswan.org> - IPSECBASEVERSION-1
- Automated build from release tar ball
