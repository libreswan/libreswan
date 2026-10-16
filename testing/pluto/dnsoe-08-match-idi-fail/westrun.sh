ipsec whack --impair drop_inbound:2
ipsec up west-east
# again, this time east has the A record cached
ipsec up west-east
echo done
