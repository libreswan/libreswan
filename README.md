# Libreswan
The Libreswan Project   https://libreswan.org/

Libreswan is an Internet Key Exchange (IKE) implementation for Linux.
It supports IKEv1 and IKEv2 and has support for most of the extensions
(RFC + IETF drafts) related to IPsec, including IKEv2, X.509 Digital
Certificates, NAT Traversal, and many others.  Libreswan uses the native
Linux IPsec stack (NETKEY/XFRM) per default.

Libreswan was forked from Openswan 2.6.38, which was forked from
FreeS/WAN 2.04. See the CREDITS files for contributor acknowledgments.

It can be downloaded from:

    https://download.libreswan.org/

A Git repository is available at:

    https://github.com/libreswan/libreswan/

## License
The bulk of libreswan is licensed under the GNU General Public License
version 2; see the LICENSE and CREDIT.* files. Some smaller parts have
a different license.

## Requirements
Recent Linux distributions based on kernel 2.x, 3.x or 4.x
are supported platforms. Libreswan has been ported to
Win2k/BSD/OSX in the past as well.

Most distributions have native packaged support for Libreswan. Libreswan is
available for RHEL, Fedora, Ubuntu, Debian, Arch, OpenWrt and more.

Unless a source-based build is truly needed,  it is often best to use
the pre-built version of the distribution you are using.

There are a few packages required for Libreswan to compile from source:

For Debian/Ubuntu

	apt-get install libnss3-dev libnspr4-dev pkg-config libpam-dev \
		libcap-ng-dev libcap-ng-utils libselinux-dev \
		libcurl3-nss-dev flex bison gcc make libldns-dev \
		libunbound-dev libnss3-tools libevent-dev xmlto \
		libsystemd-dev

	(there is no fipscheck library for these, set USE_FIPSCHECK=false)
	(unbound is build without event api, set USE_DNSSEC=false)

For Fedora/RHEL8/CentOS8/RHEL7/CentOS7

	yum install audit-libs-devel bison curl-devel fipscheck-devel flex \
		gcc ldns-devel libcap-ng-devel libevent-devel \
		libseccomp-devel libselinux-devel make nspr-devel nss-devel \
		pam-devel pkgconfig systemd-devel unbound-devel xmlto

For RHEL6/CentOS6

	yum install audit-libs-devel bison curl-devel fipscheck-devel flex \
		gcc libcap-ng-devel libevent2-devel libseccomp-devel \
		libselinux-devel make nspr-devel nss-devel pam-devel \
		pkgconfig systemd-devel xmlto

       (unbound is too old to build dnssec support, set USE_DNSSEC=false)

Runtime requirements (usually already present on the system)

	nss, iproute2, iptables, sed, awk, bash, cut, procps-ng, which

	(note: the Busybox version of "ip" does not support 'ip xfrm', so
	       ensure you enable the iproute(2) package for busybox)

	Python is used for "ipsec verify", which helps debugging problems
	python-ipaddress is used for "ipsec show", which shows tunnels


## Building for RPM based systems
See packaging/ for an up to date spec file for your distribution. For example,
to build for CentOS8, use: rpmbuild -ba packaging/centos/8/libreswan.spec

## Building for DEB based systems
The packaging/debian directly is used to build deb files. Simply issue the
command: make deb

## Compiling the userland and IKE daemon manually in /usr/local

    make programs
    sudo make install

If you want to build without creating and installing manual pages, run:

    make base
    sudo make install-base

Note: The ipsec-tools package or setkey is not needed. Instead the iproute2
packakge (>= 2.6.8) is required. Run `ipsec verify` to determine if your
system misses any of the requirements. This will also tell you if any of
the kernel sysctl values needs changing.

## Starting Libreswan
The install will detect the init system used (systemd, upstart, sysvinit,
openrc) and should integrate with the linux distribution. The service
name is called "ipsec".  For example, on RHEL8, one would use:

    systemctl enable ipsec.service
    systemctl start ipsec.service

If unsure of the specific init system used on the system, the "ipsec"
command can also be used to start or stop the ipsec service. This
command will auto-detect the init system and invoke it:

    ipsec start
    ipsec stop

## Status
For a connection status overview, use: ipsec trafficstatus
For a brief status overview, use: ipsec briefstatus
For a machine readable global status, use: ipsec globalstatus

## Configuration
Most of the libreswan configuration is stored in /etc/ipsec.conf and
/etc/ipsec.secrets. Include files may be present in /etc/ipsec.d/
See the respective man pages for more information.

## NSS initialisation
Libreswan uses NSS to store private keys and X.509 certificates. The NSS
database should have been initialised by the package installer. If not,
the NSS database can be initialised using:

    ipsec initnss

PKCS#12 certificates (.p12 files) can be imported using:

    ipsec import /path/to/your.p12

See README.NSS and `certutil --help` for more details on using NSS and
migrating from the old Openswan `/etc/ipsec.d/` directories to using NSS.

## Upgrading
If you are upgrading from FreeS/WAN 1.x or Openswan 2.x to Libreswan 3.x,
you might need to adjust your config files, although great care has been
put into making the configuration files full backwards compatible. See
also: https://libreswan.org/wiki/HOWTO:_openswan_to_libreswan_migration

See 'man ipsec.conf' for the list of options to find any new features.

You can run `make install` on top of your old version - it will not
overwrite your your `/etc/ipsec.*` configuration files. The default install
target installs in `/usr/local`. Ensure you do not install libreswan twice,
one from a distribution package in /usr and once manually in /usr/local.

## Support

Mailing lists:

    https://lists.libreswan.org/ is home of all our the mailing lists

Wiki:

    https://libreswan.org is home to the Libreswan wiki.  it contains
    documentation, interop guides and other useful information.

IRC:

    Libreswan developers and users can be found on IRC, on #swan
    irc.freenode.net.

## Bugs
Bugs can be reported on the mailing list or using our bug tracking system,
at https://bugs.libreswan.org/

## Security Information
All security issues found that require public disclosure will
receive proper CVE tracking numbers (see https://www.mitre.org/) and
will be co-ordinated via the vendor-sec / oss-security lists. A
complete list of known security vulnerabilities is available at:

https://libreswan.org/security/

## Development
Those interested in the development, patches, and beta releases of
Libreswan can join the development mailing list "swan-dev" or talk to the
development team on IRC in #swan on irc.freenode.net

For those who want to track things a bit more closely, the
swan-commits@lists.libreswan.org mailing list will mail all the commit
messages when they happen. This list is quite busy during active
development periods.

## Documentation
The most up to date documentation consists of the man pages that come
with the software. Further documentation can be found at https://libreswan.org/
and the wiki at https://libreswan.org/wiki/

## KLIPS IPsec stack
The KLIPS IPsec stack has been removed. Please use the netlink/XFRM stack.
If you wish to have network interfaces like KLIPS had, please use the XFRMi
interfaces via the ipsec-interface= keyword.
