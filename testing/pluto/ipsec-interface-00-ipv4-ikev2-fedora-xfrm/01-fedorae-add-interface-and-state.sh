../../guestbin/prep.sh

../../guestbin/ip.sh link add dev ipsec1 type xfrm dev eth1 if_id 0x1
../../guestbin/ip.sh addr add 192.0.23.1/24 dev ipsec1
../../guestbin/ip.sh link set ipsec1 up

../../guestbin/ip.sh addr show ipsec1
../../guestbin/ip.sh link show ipsec1
../../guestbin/ipsec-kernel-policy.sh

../../guestbin/ip.sh xfrm state add src 192.1.2.45 dst 192.1.2.23 proto esp spi 4523 reqid 4523 if_id 0x1 mode tunnel enc 'cbc(aes)' '45-----Key----23' auth 'hmac(sha1)' '45------Hash------23'
../../guestbin/ip.sh xfrm state add src 192.1.2.23 dst 192.1.2.45 proto esp spi 2345 reqid 2345 if_id 0x1 mode tunnel enc 'cbc(aes)' '23-----Key----45' auth 'hmac(sha1)' '23------Hash------45'

# ignore forward policy
#../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir fwd tmpl src 192.1.2.45 dst 192.1.2.23 proto esp reqid 4523 mode tunnel
../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir in  tmpl src 192.1.2.45 dst 192.1.2.23 proto esp reqid 4523 mode tunnel
../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir out tmpl src 192.1.2.23 dst 192.1.2.45 proto esp reqid 2345 mode tunnel

../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

echo added
