
ipsec whack --oppohere 192.1.2.23 --oppothere 192.0.1.3
ping -n -c 1 192.0.1.1

ipsec auto --status

# exchange groups private-or-clear and private
P=/tmp/etc/ipsec.d/policies
mv $P/private-or-clear $P/t
mv $P/private $P/private-or-clear
mv $P/t $P/private

ipsec auto --rereadgroups

ipsec auto --status

: ==== end ====
