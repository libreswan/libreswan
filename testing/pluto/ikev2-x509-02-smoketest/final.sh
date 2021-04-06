# confirm all verifications used the NSS IPsec profile and not TLS client/server profile
grep profile /tmp/pluto.log  | grep -v Starting
