# Libreswan
The Libreswan Project   https://libreswan.org/

Libreswan is an IPsec implementation for Linux. It has support for most
of the extensions (RFC + IETF drafts) related to IPsec, including
IKEv2, X.509 Digital Certificates, NAT Traversal, and many others.
Libreswan uses the native Linux IPsec stack (NETKEY/XFRM) per default.
For more information about the alternative Libreswan kernel IPsec stack,
see README.KLIPS.

Libreswan was forked from Openswan 2.6.38, which was forked from
FreeS/WAN 2.04. See the CREDITS files for contributor acknowledgments.

It can be downloaded from various locations:

    https://download.libreswan.org/
    ftp://ftp.libreswan.org/

A Git repository is available at:

    https://github.com/libreswan/libreswan/

## License
The bulk of libreswan is licensed under the GNU General Public License
version 2; see the LICENSE and CREDIT.* files. Some smaller parts have
a different license.

## Requirements
A recent Linux distribution based on either kernel 2.4.x, 2.6.x or 3.x
are the currently supported platforms. Libreswan has been ported to
Win2k/BSD/OSX as well.

Most distributions have native packaged support for Libreswan. Libreswan is
available for RHEL, Fedora, Ubuntu, Debian, Arch, OpenWrt and more.

Unless a source-based build is truly needed,  it is often best to use
the pre-built version of the distribution you are using.

There are a few packages required for Libreswan to compile from source:

For Debian/Ubuntu

	apt-get install libnss3-dev libnspr4-dev pkg-config libpam-dev \
		libcap-ng-dev libcap-ng-utils libselinux-dev \
		libcurl3-nss-dev flex bison gcc make \
		libunbound-dev libnss3-tools libevent-dev xmlto

	(there is no fipscheck library for these, set USE_FIPSCHECK=false)

For Fedora/RHEL/CentOS

	yum install nss-devel nspr-devel pkgconfig pam-devel \
		libcap-ng-devel libselinux-devel \
		curl-devel flex bison gcc make \
		fipscheck-devel unbound-devel libevent-devel xmlto

(note: for rhel6/centos6 use libevent2-devel)

For Fedora/RHEL7/CentOS7 with systemd:

	yum install audit-libs-devel systemd-devel

Runtime requirements (usually already present on the system)

	nss, iproute2, iptables, sed, awk, bash, cut, procps-ng, which

	(note: the Busybox version of "ip" does not support 'ip xfrm', so
	       ensure you enable the iproute(2) package for busybox)

	Python is used for "ipsec verify", which helps debugging problems

## Compiling the userland and IKE daemon

    make programs
    sudo make install

Note: The ipsec-tools package or setkey is not needed. Instead the iproute2
pacakge (>= 2.6.8) is required. Run `ipsec verify` to determine if your
system misses any of the requirements. This will also tell you if any of
the kernel sysctl values needs changing.

## Starting Libreswan
The install will detect the init system used (systemd, upstart, sysvinit,
openrc) and should integrate with the linux distribution. The service
name is called "ipsec".  For example, on RHEL7, one would use:

    systemctl enable ipsec.service
    systemctl start ipsec.service

If unsure, the "ipsec" command can also be used to start or stop the ipsec
service:

    ipsec setup start
    ipsec setup stop

## Configuration
Most of the libreswan configuration is stored in /etc/ipsec.conf and
/etc/ipsec.secrets.  See their respective man pages for more information.

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
put into making the configuration files full backwards compatible.

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
receive proper CVE tracking numbers (see http://mitre.org/) and
will be co-ordinated via the vendor-sec / oss-security lists. A
complete list of known security vulnerabilities is available at:

https://libreswan.org/security/

## Development
Those interested in the development, patches, and beta releases of
Libreswan can join the development mailing list "swan-dev" or talk to the
development team on IRC in #swan on irc.freenode.net

For those who want to track things a bit more closely, the
swan-commits@lists.libreswan.org mailinglist will mail all the commit
messages when they happen. This list is quite busy during active
development periods.

## Documentation
The most up to date documentation consists of the man pages that come
with the software. Further documentation can be found at https://libreswan.org/
and the wiki at https://libreswan.org/wiki/

