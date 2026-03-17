# east is the first responder

east# /testing/guestbin/prep.sh
east# echo "192.1.2.23 right.libreswan.org" >> /etc/hosts
east# ../../guestbin/mount-bind.sh /etc/hosts /etc/hosts
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec add named

# west is the second responder

west# /testing/guestbin/prep.sh
west# echo "192.1.2.45 right.libreswan.org" >> /etc/hosts
west# ../../guestbin/mount-bind.sh /etc/hosts /etc/hosts
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec add named

# road is the initiator

road# /testing/guestbin/prep.sh
road# ../../guestbin/mount-bind.sh /etc/hosts /etc/hosts
road# echo "192.1.2.23 right.libreswan.org" >> /etc/hosts # EAST
road# ipsec start
road# ../../guestbin/wait-until-pluto-started

# bring up road-west

road# ipsec add named
road# ipsec up named

# redirect DNS to WEST

road# cp /etc/hosts /tmp/west.hosts
road# sed -e '/right.libreswan.org/ s/.*/192.1.2.45 right.libreswan.org/' /tmp/west.hosts > /etc/hosts # WEST

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
