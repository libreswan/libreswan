# 002 "road-eastnet-nonat" #2: route-client output: Error: Peer netns reference is invalid.
/.*Error: Peer netns reference is invalid.$/d
s/Error: Peer netns reference is invalid.//
s/brd ff:ff:ff:ff:ff:ff link-netnsid 0/brd ff:ff:ff:ff:ff:ff/
s/qdisc noqueue state UNKNOWN group default.*$/state UNKNOWN/
s/qdisc noqueue state UNKNOWN mode DEFAULT group default.*/state UNKNOWN/
s/qdisc noqueue state DOWN group default qlen 1000/state DOWN/
s/qdisc noqueue state UP group default qlen [0-9]*/state UP/
s/qdisc noqueue state UP group default/state UP/
s/qdisc fq_codel state UP group default/state UP/
s/noop state DOWN mode DEFAULT group default/state DOWN/
s/noqueue state DOWN group default qlen [0-9]*/state DOWN/
s/qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000/state UNKNOWN/
#s/ brd 192.1.3.255 scope /scope /
s/ brd [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\} scope/ scope/
s/^\(default .*\) metric 1024 pref medium/\1/g
/^::1 dev lo proto kernel metric 256 pref medium/d
/nsenter --mount/d
