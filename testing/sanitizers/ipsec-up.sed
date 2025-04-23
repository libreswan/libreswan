# note this script need sed -n
# remove extra retransmits from the following ipsec commands
#
# ipsec auto --up road-east-psk
# ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --initiate --name westnet-eastnet-ipv4-psk-ikev1
# ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate
# ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.67

/^ ipsec up / b match-ipsec-up
/^ ipsec auto --up [[:alnum:]-]*$/ b match-ipsec-up
/^ ipsec whack --xauthname.*--initiate [[:alnum:]-]*$/ b match-ipsec-up
/^ ipsec whack --xauthname.*--initiate$/ b match-ipsec-up
/^ ipsec whack --oppohere.*[[:alnum:]-]*$/ b match-ipsec-up

b end-ipsec-up

:drop-ipsec-up

  # append line into PATTERN space; strip out current line
  N
  s/^.*\n//
  b match-ipsec-up

:next-ipsec-up

  # replace PATTERN space with next line (printing current)

  n

:match-ipsec-up

  /^[a-z][a-z]* #$/ b end-ipsec-up

  /retransmission; will wait/ b drop-ipsec-up

b next-ipsec-up

:end-ipsec-up
