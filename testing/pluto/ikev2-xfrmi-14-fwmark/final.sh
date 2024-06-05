ipsec whack --trafficstatus
# this will succeed on west and north and error on east
hostname | grep west > /dev/null && ../../guestbin/ip.sh -s link show dev gre1
hostname | grep north > /dev/null && ../../guestbin/ip.sh -s link show dev gre1
