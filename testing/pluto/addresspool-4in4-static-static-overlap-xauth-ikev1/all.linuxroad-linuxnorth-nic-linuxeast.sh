# nic nicinit.sh

nic# iptables -t nat -F
nic# iptables -F
nic# echo initdone
nic# : ==== end ====

# east eastinit.sh

east# /testing/guestbin/swan-prep --nokeys
east# echo "xnorth:xOzlFlqtwJIu2:east-any:192.0.2.101" > /etc/ipsec.d/passwd
east# echo "xroad:xOzlFlqtwJIu2:east-any:192.0.2.101-192.0.2.200" >> /etc/ipsec.d/passwd

east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec whack --impair timeout_on_retransmit
east# ipsec add east-any
east# echo initdone

# north northinit.sh

north# /testing/guestbin/swan-prep --nokeys
north# ipsec start
north# ../../guestbin/wait-until-pluto-started
north# ../../guestbin/block-non-ipsec.sh
north# ipsec add north-east
north# echo initdone

# road roadinit.sh

road# /testing/guestbin/swan-prep --nokeys
road# ipsec start
road# ../../guestbin/wait-until-pluto-started
road# ../../guestbin/block-non-ipsec.sh
road# ipsec add road-east
road# echo initdone

# establish NORTH, assiging an IP

north# ipsec whack --xauthname xnorth --xauthpass use1pass --name north-east --initiate # sanitize-retransmits

east# ../../guestbin/wait-for-pluto.sh --match '#2: IPsec SA established tunnel mode'

north# ../../guestbin/ping-once.sh --up 192.0.2.254
north# ipsec trafficstatus
north# echo done

# road roadrun.sh

road# ipsec whack --impair revival
road# # expected to fail due to overlap of IP
road# ipsec whack --xauthname xroad --xauthpass use1pass --name road-east --initiate # sanitize-retransmits
road# echo done

# final final.sh

final# ipsec trafficstatus
