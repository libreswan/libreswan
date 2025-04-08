../../guestbin/ip.sh xfrm state add src 198.18.1.12 dst 198.18.1.15 proto esp spi 4523 reqid 4523 if_id 0x1 mode tunnel enc 'cbc(aes)' '45-----Key----23' auth 'hmac(sha1)' '45------Hash------23'
../../guestbin/ip.sh xfrm state add src 198.18.1.15 dst 198.18.1.12 proto esp spi 2345 reqid 2345 if_id 0x1 mode tunnel enc 'cbc(aes)' '23-----Key----45' auth 'hmac(sha1)' '23------Hash------45'

# ignore forward policy
#../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir fwd tmpl src 198.18.1.12 dst 198.18.1.15 proto esp reqid 4523 mode tunnel
../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir in  tmpl src 198.18.1.12 dst 198.18.1.15 proto esp reqid 4523 mode tunnel
../../guestbin/ip.sh xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 if_id 0x1 dir out tmpl src 198.18.1.15 dst 198.18.1.12 proto esp reqid 2345 mode tunnel

ipsec _kernel state
ipsec _kernel policy
