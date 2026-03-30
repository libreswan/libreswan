# set 01-fedoraset-add-interface.sh

set# ../../guestbin/prep.sh
set# 
set# ../../guestbin/ip.sh link add dev ipsec1 type xfrm dev eth0 if_id 0x1
set# ../../guestbin/ip.sh addr add 198.18.15.15/24 dev ipsec1
set# ../../guestbin/ip.sh link set ipsec1 up
set# 
set# ../../guestbin/ip.sh addr show ipsec1
set# ../../guestbin/ip.sh link show ipsec1
set# ipsec _kernel policy
set# 
set# ip -4 route add 198.18.12.0/24 dev ipsec1

# rise 02-fedorarise-add-interface.sh

rise# ../../guestbin/prep.sh
rise# 
rise# ../../guestbin/ip.sh link add dev ipsec1 type xfrm dev eth0 if_id 1
rise# ../../guestbin/ip.sh addr add 198.18.12.12/24 dev ipsec1
rise# ../../guestbin/ip.sh link set ipsec1 up
rise# 
rise# ../../guestbin/ip.sh addr show ipsec1
rise# ../../guestbin/ip.sh link show ipsec1
rise# ipsec _kernel policy
rise# 
rise# ip -4 route add 198.18.15.0/24 dev ipsec1

# set 03-fedoraset-ipsec-add.sh

set# ipsec start
set# ../../guestbin/wait-until-pluto-started
set# 
set# ipsec add rise-set

# rise 04-fedorarise-ipsec-up.sh

rise# ipsec start
rise# ../../guestbin/wait-until-pluto-started
rise# 
rise# ipsec add rise-set
rise# ipsec up rise-set

# set 05-fedoraset-ping.sh

set# ../../guestbin/ping-once.sh --up -I 198.18.15.15 198.18.12.12
set# 
set# ipsec _kernel state
set# ipsec _kernel policy

# rise 06-fedorarise-ping.sh

rise# ../../guestbin/ping-once.sh --up -I 198.18.12.12 198.18.15.15
rise# 
rise# ipsec _kernel state
rise# ipsec _kernel policy

# final final.sh

final# #../../guestbin/ip.sh xfrm state flush
final# #../../guestbin/ip.sh link delete ipsec1

