ipsec auto --up west-east
# state # 1,2,3,4
ipsec status | grep STATE_
ipsec whack --rekey-ipsec --name west-east/1x0
ipsec whack --rekey-ipsec --name west-east/2x0
ipsec whack --rekey-ipsec --name west-east/3x0
sleep 35
# state # should be 1,5,6,7 only in STATE_V2_IPSEC_I, anything else would be sign of regression
ipsec status | grep STATE_
# this is complex grep line susceptible to change in log lines.
# until we find better one. Once it is fixed these logs will not there
# lets look at it later
grep -E  "Message ID:|emit IKEv2 Delete Payload|exchange type:|**emit ISAKMP Message|**parse ISAKMP Message" /tmp/pluto.log
echo done
