../../guestbin/prep.sh

left=192.1.2.45
right=192.1.2.23
leftsubnet=192.0.1.0/24
rightsubnet=192.0.2.0/24

../../guestbin/start-racoon.sh

# create a partial state on east, don't hold the hack for retransmit
racoonctl establish-sa -w isakmp inet ${left} ${right}

echo "spdadd ${leftsubnet}[any] ${rightsubnet}[any] any -P out ipsec esp/tunnel/${left}-${right}/require;" | setkey -c
echo "spdadd ${rightsubnet}[any] ${leftsubnet}[any] any -P in  ipsec esp/tunnel/${right}-${left}/require;" | setkey -c
racoonctl establish-sa -w esp inet ${leftsubnet}/255 ${rightsubnet}/255 any

ipsec _kernel state
ipsec _kernel policy

../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
