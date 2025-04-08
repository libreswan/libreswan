# check policy installed
ipsec _kernel policy

# initiate a connection
../../guestbin/ping-once.sh --forget -I 192.0.3.254 192.0.2.254
../../guestbin/wait-for-pluto.sh '^".*#1: sent IKE_SA_INIT request'
ipsec _kernel policy

# wait for it to fail
../../guestbin/wait-for-pluto.sh ' second timeout exceeded after '
ipsec _kernel policy

# let larval state expire
../../guestbin/wait-for.sh --no-match 'spi 0x00000000' -- ipsec _kernel state
