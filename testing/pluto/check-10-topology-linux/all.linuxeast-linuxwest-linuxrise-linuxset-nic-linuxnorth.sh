nic# : make certain NIC is running

east# ifconfig eth0 | grep -e 'inet ' -e 'inet6 .*2001:'
east# ifconfig eth1 | grep -e 'inet ' -e 'inet6 .*2001:'

west# ifconfig eth0 | grep -e 'inet ' -e 'inet6 .*2001:'
west# ifconfig eth1 | grep -e 'inet ' -e 'inet6 .*2001:'

rise# ifconfig eth0 | grep -e 'inet ' -e 'inet6 .*2001:'
rise# ifconfig eth1 | grep -e 'inet ' -e 'inet6 .*2001:'

set# ifconfig eth0 | grep -e 'inet ' -e 'inet6 .*2001:'
set# ifconfig eth1 | grep -e 'inet ' -e 'inet6 .*2001:'

north# ifconfig eth0 | grep -e 'inet ' -e 'inet6 .*2001:'
north# ifconfig eth1 | grep -e 'inet ' -e 'inet6 .*2001:'
# east to west_internet4 nic_internet4 north_nicnet4 rise_eastnet4
east# ../../guestbin/ping-once.sh --up 192.1.2.45 # west_internet4
east# ../../guestbin/ping-once.sh --up 192.1.2.254 # nic_internet4
east# ../../guestbin/ping-once.sh --up 192.1.3.33 # north_nicnet4
east# ../../guestbin/ping-once.sh --up 192.0.2.12 # rise_eastnet4
# west to east_internet4 nic_internet4 north_nicnet4 set_westnet4
west# ../../guestbin/ping-once.sh --up 192.1.2.23 # east_internet4
west# ../../guestbin/ping-once.sh --up 192.1.2.254 # nic_internet4
west# ../../guestbin/ping-once.sh --up 192.1.3.33 # north_nicnet4
west# ../../guestbin/ping-once.sh --up 192.0.1.15 # set_westnet4
# rise to east_eastnet4 set_darknet4
rise# ../../guestbin/ping-once.sh --up 192.0.2.254 # east_eastnet4
rise# ../../guestbin/ping-once.sh --up 198.18.1.15 # set_darknet4
# set to west_westnet4 rise_darknet4
set# ../../guestbin/ping-once.sh --up 192.0.1.254 # west_westnet4
set# ../../guestbin/ping-once.sh --up 198.18.1.12 # rise_darknet4
# north to north_northnet4 nic_nicnet4 nic_internet4 east_internet4 west_internet4
north# ../../guestbin/ping-once.sh --up 192.0.3.254 # north_northnet4
north# ../../guestbin/ping-once.sh --up 192.1.3.254 # nic_nicnet4
north# ../../guestbin/ping-once.sh --up 192.1.2.254 # nic_internet4
north# ../../guestbin/ping-once.sh --up 192.1.2.23 # east_internet4
north# ../../guestbin/ping-once.sh --up 192.1.2.45 # west_internet4
