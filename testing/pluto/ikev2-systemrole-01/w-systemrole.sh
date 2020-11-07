#!/bin/sh
#
rm -rf OUTPUT/west
mkdir -p OUTPUT/west/ipsec.d/
#
# System Role code to pull data from inventory and create configs files goes here
# Below is simple reference example
#
# Instead of pushing configs to the host's /etc/ipsec.d like the real System Role,
# this pushes to OUTPUT/west/ipsec.d/ and the host will include it as if in /etc/ipsec.d
cat << EOM > OUTPUT/west/ipsec.d/west-east.conf
conn west-east
	left=192.1.2.45
	leftid=@west
	right=192.1.2.23
	rightid=@east
	auto=ondemand
	authby=secret
EOM
cat << EOM > OUTPUT/west/ipsec.d/west-east.secrets
@east @west : PSK "SuperSecretAndRandom"
EOM

# Normally files are pushed onto host. in this case we generated them at the right spot.
