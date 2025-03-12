/testing/guestbin/swan-prep

# build the IPsec interface device
../../guestbin/ip.sh link add dev ipsec9 type xfrm if_id 0x1
../../guestbin/ip.sh addr add 192.0.1.251/24 dev ipsec9
../../guestbin/ip.sh link show ipsec9 type xfrm
../../guestbin/ip.sh addr show ipsec9

# move it into the name space
../../guestbin/ip.sh netns add ns
../../guestbin/ip.sh link set ipsec9 netns ns
../../guestbin/ip.sh -n ns link show ipsec9 type xfrm
../../guestbin/ip.sh -n ns addr show ipsec9

# add the address and mark it up
../../guestbin/ip.sh -n ns addr add 192.0.1.251/24 dev ipsec9
../../guestbin/ip.sh -n ns link set ipsec9 up
../../guestbin/ip.sh -n ns link show ipsec9
../../guestbin/ip.sh -n ns addr show ipsec9
../../guestbin/ip.sh -n ns -4 route add 192.0.2.0/24 dev ipsec9

# ../../guestbin/ip.sh monitor all all-nsid &
../../guestbin/ip.sh -n ns link show ipsec9

# move it into a namespace

ipsec start
../../guestbin/wait-until-pluto-started
 
