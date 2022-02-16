ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# Message ID 0+1 used to establish Child SA
# probe=1s; so 8 problems is 8s which is more than east's 5s probe timer
# 8+1 == 9
../../guestbin/wait-for.sh --match 'received message response 9' -- sed -n -e '/Message ID/ s/ (.*/ (...)/p' /tmp/pluto.log
# check other end sent no probes
../../guestbin/wait-for.sh --no-match 'received message request 0' -- sed -n -e '/Message ID/ s/ (.*/ (...)/p' /tmp/pluto.log
