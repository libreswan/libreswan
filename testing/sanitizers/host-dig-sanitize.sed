s/\(;; WHEN: ... ... .. ..:..:.. ....\)/;; WHEN: DATE/
s/\(;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: \).*/\112345/
s/\(.*.	604800	IN	NS	\).*\(.uml.freeswan.org.\)/\1NSSERVER/
s/\(.*.	604800	IN	NS	\).*\(.root-servers.net.\)/\1NSSERVER/
s/\(;; Query time: \).*\( msec\)/\125\2/
s/\(; <<>> DiG \).*\(<<>> .*\)/\1VERSION\2/
s/\(;; MSG SIZE  rcvd: \).*/\1SIZE/

