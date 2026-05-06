#!/sbin/openrc-run

# Copyright (c) Natanael Copa
# Copyright (c) 2025 Andrew Cagney
# This code is licensed under BSD-2-Clause

description="Sets the hostname of the machine."

depend() {
	keyword -prefix -lxc -docker
}

start()
{

    hostname=alpine # default
    . /etc/rc.hostname

    ebegin "Setting hostname ${hostname}"
    hostname ${hostname}
    eend $?

    cp /dev/null /etc/network/interfaces.new
    cat <<EOF >> /etc/network/interfaces.new
auto lo
iface lo
      inet
      loopback
iface eth${dhcp_ethN}
      inet
      dhcp
EOF
    if test "${ipv4_eth0}" ; then
	cat <<EOF >> /etc/network/interfaces.new
auto eth0
iface eth0
      address ${ipv4_eth0}
      address ${ipv6_eth0}
EOF
    fi
    if test "${ipv4_eth1}" ; then
	cat <<EOF >> /etc/network/interfaces.new
auto eth1
iface eth1
      address ${ipv4_eth1}
      address ${ipv6_eth1}
EOF
    fi
    if test "${ipv4_eth2}" ; then
	cat <<EOF >> /etc/network/interfaces.new
auto eth2
iface eth2
      address ${ipv4_eth2}
      address ${ipv6_eth2}
EOF
    fi

    cp /dev/null /etc/route.conf
    if test "${ipv4_gw}" ; then
	cat <<EOF >> /etc/route.conf
net default gw ${ipv4_gw}
EOF
    fi
    if test "${ipv6_gw}" ; then
	cat <<EOF >> /etc/route.conf
net default gw ${ipv6_gw}
EOF
    fi

    mv /etc/network/interfaces.new /etc/network/interfaces
}
