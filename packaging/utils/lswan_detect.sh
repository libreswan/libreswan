#!/bin/sh

#
#  We use sh here so this might run correctly on ANY unix host.
# hopefully this will be very cross platform. Standards people!!

#
#  Some distro's don't add the sbin directories to the normal users PATH
PATH=${PATH}:/sbin:/usr/sbin


return_initsystem() {
    # try to detect the running init system, perhaps more then one can
    # be installed?
    if [ -z "$(uname -o 2> /dev/null | grep inux)" ]; then
	echo "Error: This init system is not yet supported." >&2
	return 89
    fi

    #  works for systemd, not upstart?
    if [ -e /proc/1/comm  ]; then
	if [ "$(cat /proc/1/comm)" = "systemd" ]; then
	    echo "systemd"
	    return
	fi
    fi

    if [ -f /lib/systemd/systemd -a -d /var/run/systemd ]; then
	echo "systemd"
	return
    fi

    if [ -f /sbin/start ]; then
	# override for rhel/centos to use sysvinit
	if [ -e /etc/redhat-release ]; then
	    echo "sysvinit"
	else
	    echo "upstart"
	fi
	return
    fi

    if [ -f /sbin/rc-service -o -f /usr/sbin/rc-service ]; then
	echo "openrc"
	return
    fi


    # really, most have this, it is probably a backwards compatibility or
    # really sysvinit - we have no other known targets at this point anyway
    if [ -d /etc/init.d -o -d /etc/rc.d ]; then
	echo "sysvinit"
	return
    fi

    echo "unknown init system, please email swan-dev@lists.libreswan.org with: $(uname -a)" >&2
    echo "unknown"
    exit 1
}

return_distro() {
    # try to detect the distro
    if [ -z "$(uname -o 2> /dev/null | grep inux)" ]; then
	# non-Linux, so this will be BSD, OSX or cygwin/Windows
	echo "Error: This system is not supported yet." >&2
	return 88
    fi

    if [ -f /etc/redhat-release ]; then
	VER="$(grep 'Fedora release'  /etc/redhat-release | awk '{print $3;}')"
	if [ -n "${VER}" ]; then
	    echo "fedora/${VER}"
	    return
	fi
	VER="$(grep 'Red Hat Enterprise'  /etc/redhat-release | awk '{print $7;}')"
	if [ -n "${VER}" ]; then
	    echo "rhel/${VER}"
	    return
	fi
	VER="$(grep CentOS /etc/redhat-release | awk '{ print $3;}')"
	if [ -n "${VER}" ]; then
	    echo "centos/${VER}"
	    return
	fi
	VER="$(grep 'Foobar Linux'  /etc/redhat-release | awk '{print $4;}')"
	if [ -n "${VER}" ]; then
	    echo "foobar/${VER}"
	    return
	fi
	if [ -n "$(grep enterprise-release /etc/redhat-release)" ]; then
	    echo "The unbreakable broke - Oracle is welcome to submit patches" >&2
	    return 90
	fi
    fi

    #  Test for OpenSuSE:
    if [ -f /etc/SuSE-brand ]; then
	if [ "$(head -1 /etc/SuSE-brand | tr '[:upper:]' '[:lower:]')" = "opensuse" ]; then
	    echo "opensuse/$(grep VERSION /etc/SuSE-brand | awk '{print $3;}')"
	    return
	fi
    fi

    #  Test for SuSE/SLES:
    if [ -f /etc/SuSE-release ]; then
	if grep -i suse /etc/SuSE-release > /dev/null 2>&1; then
	    VER="$(grep VERSION /etc/SuSE-release | awk '{print $3;}')"
	    PAT="$(grep PATCHLEVEL /etc/SuSE-release | awk '{print $3;}')"
	    echo "suse/${VER}.${PAT}"
	fi
	return
    fi

    # Check ubuntu before debian, as it also has /etc/debian_version
    if [ -f /etc/lsb-release ]; then
	. /etc/lsb-release
	if [ "${DISTRIB_ID}" = "Ubuntu" ]; then
	    echo "ubuntu/${DISTRIB_RELEASE}"
	    return
	fi
    fi

    if [ -f /etc/debian_version ]; then
	VER="$(cat /etc/debian_version | sed 's/^\([0-9]\.[0-9]\).*$/\1/')"
	echo "debian/${VER}"
	return
    fi

    if [ -f /etc/arch-release ]; then
	# Arch Linux has no version, rolling release only
	echo "archlinux"
	return
    fi

    if [ -f /etc/alpine-release ]; then
	VER="$(cat /etc/alpine-release | sed 's/^\([0-9]\.[0-9]\).*$/\1/')"
	echo "alpine/${VER}"
	return
    fi

    if [ -f /etc/gentoo-release ]; then
	VER="$(cat /etc/gentoo-release | awk '{print $NF;}')"
	echo "gentoo/${VER}"
	return
    fi

    if [ -f /etc/slackware-version ]; then
	VER="`cat /etc/slackware-version | awk '{print $2}'`"
	echo "slackware/$VER"
	return
    fi

    echo "unknown distribution, please email swan-dev@lists.libreswan.org with: $(uname -a)"  >&2
    echo "unknown"
    exit 1
}

case "$1" in
    distro|--distro)
	return_distro
	;;
    init|--init|initsystem|--initsystem)
	return_initsystem
	;;
    *)
	echo "Usage: $0 <distro|init>"
	echo "    distro  will detect the distribution (eg fedora/18, ubuntu/12.10, etc.)"
	echo "    init    will detect the init system used (systemd, upstart, sysvinit)"
	echo " "
	echo " output is currently a single line used by make/scripts for configuration and"
	echo " installation of distribtion and init-system specific files"
	echo
	exit 1
	;;
esac
