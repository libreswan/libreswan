ipsec auto --add road-east
ipsec whack --impair delete-on-retransmit
ipsec auto --up road-east
echo "2. road connection add+up done"
