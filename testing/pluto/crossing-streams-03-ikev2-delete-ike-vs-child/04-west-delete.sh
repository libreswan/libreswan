# stop all traffic, will be drip feeding

ipsec whack --impair block_inbound
ipsec whack --impair block_outbound

# initiate delete; but block it

ipsec whack --delete-child --name east-west --asynchronous
../../guestbin/wait-for-outbound.sh 1

# now do same on east
