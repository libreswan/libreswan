nic# : make certain NIC is running

east# ifconfig vtnet0 | grep -e 'inet ' -e 'inet6 .*2001:'
east# ifconfig vtnet1 | grep -e 'inet ' -e 'inet6 .*2001:'

west# ifconfig vtnet0 | grep -e 'inet ' -e 'inet6 .*2001:'
west# ifconfig vtnet1 | grep -e 'inet ' -e 'inet6 .*2001:'

rise# ifconfig vtnet0 | grep -e 'inet ' -e 'inet6 .*2001:'
rise# ifconfig vtnet1 | grep -e 'inet ' -e 'inet6 .*2001:'

set# ifconfig vtnet0 | grep -e 'inet ' -e 'inet6 .*2001:'
set# ifconfig vtnet1 | grep -e 'inet ' -e 'inet6 .*2001:'

north# ifconfig vtnet0 | grep -e 'inet ' -e 'inet6 .*2001:'
north# ifconfig vtnet1 | grep -e 'inet ' -e 'inet6 .*2001:'
# east to west_pubnet nic_pubnet north_nicnet rise_eastnet
east# ../../guestbin/ping-once.sh --up 192.1.2.45 # west_pubnet
east# ../../guestbin/ping-once.sh --up 192.1.2.254 # nic_pubnet
east# ../../guestbin/ping-once.sh --up 192.1.3.33 # north_nicnet
east# ../../guestbin/ping-once.sh --up 192.0.2.12 # rise_eastnet
# west to east_pubnet nic_pubnet north_nicnet set_westnet
west# ../../guestbin/ping-once.sh --up 192.1.2.23 # east_pubnet
west# ../../guestbin/ping-once.sh --up 192.1.2.254 # nic_pubnet
west# ../../guestbin/ping-once.sh --up 192.1.3.33 # north_nicnet
west# ../../guestbin/ping-once.sh --up 192.0.1.15 # set_westnet
# rise to east_eastnet set_sunnet
rise# ../../guestbin/ping-once.sh --up 192.0.2.254 # east_eastnet
rise# ../../guestbin/ping-once.sh --up 198.18.1.15 # set_sunnet
# set to west_westnet rise_sunnet
set# ../../guestbin/ping-once.sh --up 192.0.1.254 # west_westnet
set# ../../guestbin/ping-once.sh --up 198.18.1.12 # rise_sunnet
# north to north_northnet nic_nicnet nic_pubnet east_pubnet west_pubnet
north# ../../guestbin/ping-once.sh --up 192.0.3.254 # north_northnet
north# ../../guestbin/ping-once.sh --up 192.1.3.254 # nic_nicnet
north# ../../guestbin/ping-once.sh --up 192.1.2.254 # nic_pubnet
north# ../../guestbin/ping-once.sh --up 192.1.2.23 # east_pubnet
north# ../../guestbin/ping-once.sh --up 192.1.2.45 # west_pubnet

rise# ../../guestbin/prep.sh
rise# ipsec initnss
rise# ipsec start
rise# ../../guestbin/wait-until-pluto-started
rise# ipsec add rise-set

set# ../../guestbin/prep.sh
set# ipsec initnss
set# ipsec start
set# ../../guestbin/wait-until-pluto-started
set# ipsec add rise-set
rise# ipsec up rise-set
