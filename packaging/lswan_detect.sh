#!/bin/sh

# some distro's don't add the sbin directories to the path
PATH=$PATH:/sbin:/usr/sbin

# hopefully this will be very cross platform. Standards people!!

return_initsystem() {
# try to detect the running init system, perhaps more then one can be installed?

if test -z "`uname -o |grep inux`"
then
	echo "non-linux init system not supported yet"
	return
fi

# works for systemd, not upstart
if test "`cat /proc/1/comm`" = "systemd"
then
	echo "systemd"
	return
fi

if test -f /lib/systemd/systemd -a -d /var/run/systemd
then
	echo "systemd"
	return
fi

if test -f /sbin/initctl -o -f /usr/sbin/initctl 
then
	if test -n "`initctl version| grep upstart`"
	then
		echo "upstart"
		return
	fi
fi

# really, most have this, it is probably a backwards compatiblity or realy sysv
if test -d /etc/init.d
then
	echo "sysvinit"
	return
fi

echo "unknown"
}

return_distro() {

if test -z "`uname -o |grep inux`"
then
	# non-Linux, so this will be BSD, OSX or cygwin/Windows
	echo "non-linux building not auto-detected yet"
	return
fi

if test -f /etc/redhat-release
then
	VER="`grep 'Fedora release'  /etc/redhat-release | awk '{ print $3;}'`"
	if test -n "$VER"
	then
		echo "fedora/$VER"
		return
	fi
	VER="`grep 'Red Hat Enterprise'  /etc/redhat-release | awk '{ print $7;}'`"
	if test -n "$VER"
	then
		echo "rhel/$VER"
		return
	fi
	VER="`grep CentOS /etc/redhat-release | awk '{ print $3;}'`"
	if test -n "$VER"
	then
		echo "centos/$VER"
		return
	fi
fi

# Check ubuntu before debian, as it also has /etc/debian_version
if test -f /etc/lsb-release
then
	. /etc/lsb-release
	if test "$DISTRIB_ID" = "Ubuntu"
	then
		echo "ubuntu/$DISTRIB_RELEASE"
		return
	fi
fi

if test -f /etc/debian_version
then
	VER="`cat /etc/debian_version | sed 's/^\([0-9]\.[0-9]\).*$/\1/'`"
	echo "debian/$VER"
	return
fi

if test -f /etc/arch-release
then
	# Arch Linux has no version, rolling release only
	echo "archlinux"
	return
fi

if test -f /etc/SuSE-release
then
	VER="`grep openSUSE /etc/SuSE-release | awk '{ print $2}'`"
	echo "opensuse/$VER"
	return
fi

echo "unknown please email dev@libreswan.org with:"
uname -a
exit 1

}

case "$1" in
help|--help|-h|'')
	echo "Usage: distro | init"
	echo "distro will detect the distribution (eg fedora/18)"
	echo "init will detect the init system used (systemd, upstart, sysv)"
	exit 1
	;;
distro|--distro)
	return_distro
	;;

init|--init|initsystem|--initsystem)
	return_initsystem
	;;
esac
