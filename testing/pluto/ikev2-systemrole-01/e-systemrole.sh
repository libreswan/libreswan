#!/bin/sh
#
rm -rf OUTPUT/east
mkdir -p OUTPUT/east/ipsec.d/
#
# System Role code to pull data from inventory and create configs files goes here
# Below is simple reference example using hardcoded information.
#
# Instead of pushing configs to the host's /etc/ipsec.d like the real System Role,
# this pushes to OUTPUT/east/ipsec.d/ and the host will include it as if in /etc/ipsec.d
cat << EOM > OUTPUT/east/ipsec.d/east-west.conf
conn east-west
	left=192.1.2.23
	leftid=@east
	right=192.1.2.45
	rightid=@west
	auto=ondemand
	authby=secret
EOM
cat << EOM > OUTPUT/east/ipsec.d/east-west.secrets
@west @east : PSK "SuperSecretAndRandom"
EOM

# Normally files are pushed onto host. in this case we generated them at the right spot.
