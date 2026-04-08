# east 01-fedoraeast-add-interface.sh

east# ../../guestbin/prep.sh
east# 
east# ../../guestbin/ip.sh link add dev ipsec1 type xfrm dev eth1 if_id 0x1
east# ../../guestbin/ip.sh addr add 198.18.23.23/24 dev ipsec1
east# ../../guestbin/ip.sh link set ipsec1 up
east# 
east# ../../guestbin/ip.sh addr show ipsec1
east# ../../guestbin/ip.sh link show ipsec1
east# ipsec _kernel policy
east# 
east# ip -4 route add 198.18.45.0/24 dev ipsec1

# west 02-fedorawest-add-interface.sh

west# ../../guestbin/prep.sh
west# 
west# ../../guestbin/ip.sh link add dev ipsec1 type xfrm dev eth1 if_id 1
west# ../../guestbin/ip.sh addr add 198.18.45.45/24 dev ipsec1
west# ../../guestbin/ip.sh link set ipsec1 up
west# 
west# ../../guestbin/ip.sh addr show ipsec1
west# ../../guestbin/ip.sh link show ipsec1
west# ipsec _kernel policy
west# 
west# ip -4 route add 198.18.23.0/24 dev ipsec1

# east 03-fedoraeast-add-state.sh

east# ../../guestbin/ip.sh xfrm state add src 192.1.2.45 dst 192.1.2.23 proto esp spi 4523 reqid 4523 if_id 0x1 mode tunnel enc 'cbc(aes)' '45-----Key----23' auth 'hmac(sha1)' '45------Hash------23'
east# ../../guestbin/ip.sh xfrm state add src 192.1.2.23 dst 192.1.2.45 proto esp spi 2345 reqid 2345 if_id 0x1 mode tunnel enc 'cbc(aes)' '23-----Key----45' auth 'hmac(sha1)' '23------Hash------45'
east# 
east# # ignore forward policy
east# #../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir fwd tmpl src 192.1.2.45 dst 192.1.2.23 proto esp reqid 4523 mode tunnel
east# ../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir in  tmpl src 192.1.2.45 dst 192.1.2.23 proto esp reqid 4523 mode tunnel
east# ../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir out tmpl src 192.1.2.23 dst 192.1.2.45 proto esp reqid 2345 mode tunnel
east# 
east# ipsec _kernel state
east# ipsec _kernel policy

# west 04-fedorawest-add-state.sh

west# ../../guestbin/ip.sh xfrm state add src 192.1.2.45 dst 192.1.2.23 proto esp spi 4523 reqid 4523 if_id 1 mode tunnel enc 'cbc(aes)' '45-----Key----23' auth 'hmac(sha1)' '45------Hash------23'
west# ../../guestbin/ip.sh xfrm state add src 192.1.2.23 dst 192.1.2.45 proto esp spi 2345 reqid 2345 if_id 1 mode tunnel enc 'cbc(aes)' '23-----Key----45' auth 'hmac(sha1)' '23------Hash------45'
west# 
west# # ignore forward policy
west# ../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 1 dir out tmpl src 192.1.2.45 dst 192.1.2.23 proto esp reqid 4523 mode tunnel
west# ../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 1 dir in  tmpl src 192.1.2.23 dst 192.1.2.45 proto esp reqid 2345 mode tunnel
west# #../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 1 dir fwd tmpl src 192.1.2.23 dst 192.1.2.45 proto esp reqid 2345 mode tunnel
west# 
west# ipsec _kernel state
west# ipsec _kernel policy

# east 05-fedoraeast-ping.sh

east# ../../guestbin/ping-once.sh --up -I 198.18.23.23 198.18.45.45
east# 
east# ipsec _kernel state
east# ipsec _kernel policy

# west 06-fedorawest-ping.sh

west# ../../guestbin/ping-once.sh --up -I 198.18.45.45 198.18.23.23
west# 
west# ipsec _kernel state
west# ipsec _kernel policy

# final final.sh

final# #../../guestbin/ip.sh xfrm state flush
final# #../../guestbin/ip.sh link delete ipsec1

