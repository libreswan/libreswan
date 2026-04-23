# NIC runs DNS

nic# ../../guestbin/dnssec.sh
nic# unbound-control local_data right.libreswan.org 3600 IN A 192.1.2.23

# EAST is the first responder

east# /testing/guestbin/prep.sh
east# echo "192.1.2.23 right.libreswan.org" >> /etc/hosts
east# ../../guestbin/mount-bind.sh /etc/hosts /etc/hosts
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec add named

# WEST is the second responder

west# /testing/guestbin/prep.sh
west# echo "192.1.2.45 right.libreswan.org" >> /etc/hosts
west# ../../guestbin/mount-bind.sh /etc/hosts /etc/hosts
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec add named

# ROAD is the initiator

road# /testing/guestbin/prep.sh

# need to disable ipv6 and activate auto-interface
road# cp resolv.conf /etc
road# cp west-unbound.conf /etc/unbound/unbound.conf
road# unbound-control-setup > /dev/null 2>&1

# use modified service file that skips ICANN root key checks
road# cat /lib/systemd/system/unbound.service | grep -v ExecStartPre > /etc/systemd/system/unbound.service
road# systemctl daemon-reload
road# systemctl start unbound.service

road# dig +short         right.libreswan.org @192.1.3.254
road# dig +dnssec +short right.libreswan.org @192.1.3.254

# bring up road-west

road# ipsec start
road# ../../guestbin/wait-until-pluto-started

road# ipsec add named
road# ipsec up named

# On NIC redirect DNS to WEST

nic# unbound-control local_data right.libreswan.org 3600 IN A 192.1.2.45

road# dig +short         right.libreswan.org @192.1.3.254
road# dig +dnssec +short right.libreswan.org @192.1.3.254

# kill existing

east# ipsec stop

# first revival attempt is to east, second is to west (new DNS)

road# ../../guestbin/wait-for-pluto.sh --match '#2: connection is supposed to remain up'
road# ../../guestbin/wait-for-pluto.sh --match '#3: initiating IKEv2 connection'
road# ../../guestbin/wait-for-pluto.sh --match '#3: deleting IKE SA'
road# ../../guestbin/wait-for-pluto.sh --match '#4: initiating IKEv2 connection'
road# ../../guestbin/wait-for-pluto.sh --match '#4: initiator established IKE SA'
road# ../../guestbin/wait-for-pluto.sh --match '#5: initiator established Child SA'

final# ipsec _kernel state
final# ipsec _kernel policy
