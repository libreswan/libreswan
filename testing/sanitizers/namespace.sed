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
