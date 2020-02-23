ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
route -n
# ping skipped because strongswan does not properly handle proxyarp per default, and the
# reply packet is lost
echo done
