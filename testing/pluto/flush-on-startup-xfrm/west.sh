../../guestbin/swan-prep --46 --nokeys

# https://www.sobyte.net/post/2022-10/ipsec-ip-xfrm/
# add a policy + state
ID=1000
KEY=0x1234567890123456789012345678901234567890

ip xfrm state add src 1.1.1.1 dst 2.2.2.2 proto esp spi $ID reqid $ID mode tunnel aead 'rfc4106(gcm(aes))' $KEY 128
ip xfrm state add src 2.2.2.2 dst 1.1.1.1 proto esp spi $ID reqid $ID mode tunnel aead 'rfc4106(gcm(aes))' $KEY 128

ip xfrm policy add src 10.0.1.0/24 dst 10.0.2.0/24 dir out tmpl src 1.1.1.1 dst 2.2.2.2 proto esp reqid $ID mode tunnel
ip xfrm policy add src 10.0.2.0/24 dst 10.0.1.0/24 dir fwd tmpl src 2.2.2.2 dst 1.1.1.1 proto esp reqid $ID mode tunnel
ip xfrm policy add src 10.0.2.0/24 dst 10.0.1.0/24 dir in tmpl src 2.2.2.2 dst 1.1.1.1 proto esp reqid $ID mode tunnel

ipsec _kernel state
ipsec _kernel policy

# start pluto
ipsec pluto --config /etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started

# check policy/state gone
ipsec _kernel state
ipsec _kernel policy
