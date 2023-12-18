# Libreswan

The Libreswan Project   https://libreswan.org/

Libreswan is an Internet Key Exchange (IKE) implementation for Linux,
FreeBSD, NetBSD and OpenBSD.  It supports IKEv1 and IKEv2 and has
support for most of the extensions (RFC + IETF drafts) related to
IPsec, including IKEv2, X.509 Digital Certificates, NAT Traversal, and
many others.

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

Most distributions have native packaged support for Libreswan.
Libreswan is available for the Linux distributions RHEL, Fedora,
CentOS, Ubuntu, Debian, Arch, Apline, OpenWrt as well as FreeBSD
(ports) and NetBSD (pkgsrc/wip).

Unless a source-based build is truly needed,  it is often best to use
the pre-built version of the distribution you are using.

There are a few packages required for Libreswan to compile from source:

For Debian/Ubuntu

   apt-get install net-tools make build-essential libnss3-dev \
     pkg-config libevent-dev libunbound-dev bison \
     flex libsystemd-dev libcurl4-nss-dev \
     libpam0g-dev libcap-ng-dev libldns-dev xmlto

For Fedora/CentOS-Stream/RHEL/AlmaLinux/RockyLinux etc.

   dnf install audit-libs-devel bison curl-devel flex \
     gcc ldns-devel libcap-ng-devel libevent-devel \
     libseccomp-devel libselinux-devel make nspr-devel nss-devel \
     pam-devel pkgconfig systemd-devel unbound-devel xmlto

Alpine Linux:

   aph add mandoc mandoc-doc apk-tools-doc bison \
     bison-doc bsd-compat-headers coreutils coreutils-doc curl-dev \
     curl-doc flex flex-doc gcc gcc-doc git git-doc gmp-dev gmp-doc \
     ldns-dev ldns-doc libcap-ng-dev libcap-ng-doc libevent-dev \
     linux-pam-dev linux-pam-doc make make-doc musl-dev nspr-dev \
     nss-dev nss-tools pkgconfig sed sed-doc unbound-doc unbound-dev \
     xmlto xmlto-doc

FreeBSD:

   pkg install gmake git pkgconf nss libevent unbound bison \
     flex ldns xmlto gcc

NetBSD:

   pkgin install git gmake nss unbound bison flex ldns xmlto pkgconf

OpenBSD:

   pkg_add gmake nss libevent libunbound bison libldns xmlto curl git llvm%16

## Building for RPM based systems

Install requirements for rpm package building:

   dnf install rpm-build rpmdevtools

The packaging/ directory is used to find the proper spce file for your
distribution. Simply issue the command:

   make rpm

You can also pick a specific spec file. For example, to build for CentOS8,
use:

   rpmbuild -ba packaging/centos/8/libreswan.spec

## Building for DEB based systems

The packaging/debian directory is used to build deb files. Simply issue the
command:

    make deb

## Compiling the userland and IKE daemon manually in /usr/local

    make
    sudo make install

If you want to build without creating and installing manual pages, run:

    make base
    sudo make install-base

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
If you are upgrading from FreeS/WAN 1.x, Openswan 2.x or older Libreswan
versions to Libreswan 4.x, you might need to adjust your config files,
although great care has been put into making the configuration files full
backwards compatible. See also:
https://libreswan.org/wiki/HOWTO:_openswan_to_libreswan_migration

See 'man ipsec.conf' for the list of options to find any new features.

You can run `make install` on top of your old version - it will not
overwrite your your `/etc/ipsec.*` configuration files. The default install
target installs in `/usr/local`. Ensure you do not install libreswan twice,
one from a distribution package in /usr and once manually in /usr/local.

Note that for rpm based systems, the NSS directory changed from /etc/ipsec.d
to /var/lib/ipsec/nss/

## Support

Mailing lists:

    https://lists.libreswan.org/ is home of all our the mailing lists

Wiki:

    https://libreswan.org is home to the Libreswan wiki.  it contains
    documentation, interop guides and other useful information.

IRC:

    Libreswan developers and users can be found on IRC, on #libreswan
    irc.libera.chat

## Bugs
Bugs can be reported on the mailing list or using our bug tracking system,
at https://github.com/libreswan/libreswan/issues

## Security Information
All security issues found that require public disclosure will
receive proper CVE tracking numbers (see https://www.mitre.org/) and
will be co-ordinated via the vendor-sec / oss-security lists. A
complete list of known security vulnerabilities is available at:

https://libreswan.org/security/

## Development
Those interested in the development, patches, and beta releases of
Libreswan can join the development mailing list "swan-dev" or talk to the
development team on IRC in #swan on irc.libera.chat

For those who want to track things a bit more closely, the
swan-commits@lists.libreswan.org mailing list will mail all the commit
messages when they happen. This list is quite busy during active
development periods.

## Documentation
The most up to date documentation consists of the man pages that come
with the software. Further documentation can be found at https://libreswan.org/
and the wiki at https://libreswan.org/wiki/

## KLIPS IPsec stack
The KLIPS IPsec stack has been removed. Please use the XFRM stack.
If you wish to have network interfaces like KLIPS had, please use the XFRMi
interfaces via the ipsec-interface= keyword, or use the less capable VTI
interface support.
