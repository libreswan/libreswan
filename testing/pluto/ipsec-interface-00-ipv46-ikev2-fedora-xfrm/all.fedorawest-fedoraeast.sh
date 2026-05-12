# east 01-fedoraeast-add-interface.sh

east# prep.sh

east# ip.sh link add dev ipsec1 type xfrm dev eth1 if_id 0x1
east# ip.sh addr add 198.18.23.23/24 dev ipsec1
east# ip.sh addr add 2001:db8:23::23/64 dev ipsec1
east# ip.sh link set ipsec1 up

east# ip-route.sh -4 add   198.18.45.0/24 dev ipsec1 src    198.18.23.23
east# ip-route.sh -6 add 2001:db8:45::/64 dev ipsec1 src 2001:db8:23::23

# west 02-fedorawest-add-interface.sh

west# prep.sh

west# ip.sh link add dev ipsec1 type xfrm dev eth1 if_id 1
west# ip.sh addr add 198.18.45.45/24 dev ipsec1
west# ip.sh addr add 2001:db8:45::45/64 dev ipsec1
west# ip.sh link set ipsec1 up

west# ip-route.sh -4 add   198.18.23.0/24 dev ipsec1 src    198.18.45.45
west# ip-route.sh -6 add 2001:db8:23::/64 dev ipsec1 src 2001:db8:45::45

# east 03-fedoraeast-add-state.sh

east# ip.sh xfrm state add src 192.1.2.45 dst 192.1.2.23 proto esp spi 4523 reqid 4523 if_id 0x1 flag af-unspec dir  in mode tunnel enc 'cbc(aes)' '45-----Key----23' auth 'hmac(sha1)' '45------Hash------23'
east# ip.sh xfrm state add src 192.1.2.23 dst 192.1.2.45 proto esp spi 2345 reqid 2345 if_id 0x1 flag af-unspec dir out mode tunnel enc 'cbc(aes)' '23-----Key----45' auth 'hmac(sha1)' '23------Hash------45'
east#
east# # ignore forward policy
east# #ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir fwd tmpl src 192.1.2.45 dst 192.1.2.23 proto esp reqid 4523 mode tunnel
east# ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir in  tmpl src 192.1.2.45 dst 192.1.2.23 proto esp reqid 4523 mode tunnel
east# ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir out tmpl src 192.1.2.23 dst 192.1.2.45 proto esp reqid 2345 mode tunnel
east#
east# ip.sh xfrm policy add src ::/0 dst ::/0 if_id 0x1 dir in  tmpl src 192.1.2.45 dst 192.1.2.23 proto esp reqid 4523 mode tunnel
east# ip.sh xfrm policy add src ::/0 dst ::/0 if_id 0x1 dir out tmpl src 192.1.2.23 dst 192.1.2.45 proto esp reqid 2345 mode tunnel
east#
east# ipsec _kernel state
east# ipsec _kernel policy

# west 04-fedorawest-add-state.sh

west# ip.sh xfrm state add src 192.1.2.45 dst 192.1.2.23 proto esp spi 4523 reqid 4523 if_id 1 flag af-unspec dir out mode tunnel enc 'cbc(aes)' '45-----Key----23' auth 'hmac(sha1)' '45------Hash------23'
west# ip.sh xfrm state add src 192.1.2.23 dst 192.1.2.45 proto esp spi 2345 reqid 2345 if_id 1 flag af-unspec dir  in mode tunnel enc 'cbc(aes)' '23-----Key----45' auth 'hmac(sha1)' '23------Hash------45'
west#
west# # ignore forward policy
west# #ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 1 dir fwd tmpl src 192.1.2.23 dst 192.1.2.45 proto esp reqid 2345 mode tunnel
west# ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 1 dir out tmpl src 192.1.2.45 dst 192.1.2.23 proto esp reqid 4523 mode tunnel
west# ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 1 dir in  tmpl src 192.1.2.23 dst 192.1.2.45 proto esp reqid 2345 mode tunnel
west#
west# ip.sh xfrm policy add src ::/0 dst ::/0 if_id 1 dir out tmpl src 192.1.2.45 dst 192.1.2.23 proto esp reqid 4523 mode tunnel
west# ip.sh xfrm policy add src ::/0 dst ::/0 if_id 1 dir in  tmpl src 192.1.2.23 dst 192.1.2.45 proto esp reqid 2345 mode tunnel
west#
west# ipsec _kernel state
west# ipsec _kernel policy

# east 05-fedoraeast-ping.sh

east# ping-once.sh --up    198.18.45.45
east# ping-once.sh --up 2001:db8:45::45
east#
east# ipsec _kernel state

# west 06-fedorawest-ping.sh

west# ping-once.sh --up    198.18.23.23
west# ping-once.sh --up 2001:db8:23::23
west#
west# ipsec _kernel state
