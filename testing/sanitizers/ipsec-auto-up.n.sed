# note this script need sed -n
# remove extra retransmits from the following ipsec commands
#
# ipsec auto --up road-east-psk
# ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --initiate --name westnet-eastnet-ipv4-psk-ikev1
# ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate
# ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.67

/^ ipsec auto --up [[:alnum:]-]*$/ b match
/^ ipsec whack --xauthname.*--initiate [[:alnum:]-]*$/ b match
/^ ipsec whack --xauthname.*--initiate$/ b match
/^ ipsec whack --oppohere.*[[:alnum:]-]*$/ b match

b end

:match
 p

:noprint

 n

 /^\(\(east\|west\|road\|north\|nic\) #\)$/ b end

 /retransmission; will wait/ b noprint

b match

:end

p
