# east 01-openbsdeast-add-interface.sh

east# ../../guestbin/prep.sh
east# 
east# ifconfig sec1 create
east# ifconfig sec1 inet 198.18.23.23/24 198.18.45.45
east# ifconfig sec1 up
east# 
east# ifconfig sec1
east# ipsec _kernel state
east# ipsec _kernel policy

# west 02-openbsdwest-add-interface.sh

west# ../../guestbin/prep.sh
west# 
west# ifconfig sec1 create
west# ifconfig sec1 inet 198.18.45.45/24 198.18.23.23
west# ifconfig sec1 up
west# 
west# ifconfig sec1
west# ipsec _kernel state
west# ipsec _kernel policy

# east 03-openbsdeast-add-state.sh

east# ../../guestbin/iked.sh start

# west 04-openbsdwest-add-state.sh

west# ../../guestbin/iked.sh start
west# 
west# sleep 10 # give IKE a chance :-/

# east 05-openbsdeast-ping.sh

east# ../../guestbin/ping-once.sh --up -I 198.18.23.23 198.18.45.45
east# 
east# ipsec _kernel state
east# ipsec _kernel policy

# west 06-openbsdwest-ping.sh

west# ../../guestbin/ping-once.sh --up -I 198.18.45.45 198.18.23.23
west# 
west# ipsec _kernel state
west# ipsec _kernel policy

# final final.sh

final# ../../guestbin/iked.sh stop
final# ifconfig sec1 destroy

