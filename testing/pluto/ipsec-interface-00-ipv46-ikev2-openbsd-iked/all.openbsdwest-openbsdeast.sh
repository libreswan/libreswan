# east 01-openbsdeast-add-interface.sh

east# prep.sh

east# ifconfig sec1 create
east# ifconfig sec1 up
east# ../../guestbin/tcpdump.sh --start -i sec1
east# ifconfig sec1 inet     198.18.23.23/32     198.18.45.45
east# ifconfig sec1 inet6 2001:db8:23::23/128 2001:db8:45::45

east# ifconfig sec1
east# ipsec _kernel state
east# ipsec _kernel policy

# west 02-openbsdwest-add-interface.sh

west# prep.sh

west# ifconfig sec1 create
west# ifconfig sec1 up
west# ../../guestbin/tcpdump.sh --start -i sec1
west# ifconfig sec1 inet     198.18.45.45/32     198.18.23.23
west# ifconfig sec1 inet6 2001:db8:45::45/128 2001:db8:23::23

west# ifconfig sec1
west# ipsec _kernel state
west# ipsec _kernel policy

# east 03-openbsdeast-add-state.sh

east# ../../guestbin/iked.sh start

# west 04-openbsdwest-add-state.sh

west# ../../guestbin/iked.sh start

west# sleep 10 # give IKE a chance :-/

# east 05-openbsdeast-ping.sh

east# ../../guestbin/ping-once.sh --up    198.18.45.45
east# ../../guestbin/ping-once.sh --up 2001:db8:45::45

east# sleep 5
east# ../../guestbin/tcpdump.sh --stop -i sec1

# west 06-openbsdwest-ping.sh

west# ../../guestbin/ping-once.sh --up    198.18.23.23
west# ../../guestbin/ping-once.sh --up 2001:db8:23::23

west# sleep 5
west# ../../guestbin/tcpdump.sh --stop -i sec1
